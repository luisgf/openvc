"""
tests/test_ebsi_error_body_bound.py — the DECODED size of an error answer's body (#350).

``EbsiHttpClient._read_problem_type`` (#321) reads a non-200 body for its RFC 9457 ``type``
and stops at ``MAX_ERROR_BODY_BYTES`` (16 KiB), but it read with ``iter_bytes`` and checked the
cap after appending a chunk, and ``iter_bytes`` yields a chunk httpx has already inflated: one
260 935-byte ``gzip`` body that inflates to 256 MiB, served as a 403, a 404 or a 503, peaked at
557 MiB before the 16 KiB check ran (the same class as #335 on the 200 path, which #348 fixed
there). The read now goes through the bounded decoder of the 200 path: the raw stream, one
``gzip`` or ``deflate`` coding, ``zlib`` asked for at most the room left plus one byte.

What did not change, and is pinned here against the measurements taken on ``main`` at 3bd9e59:
the STATUS decides the exception class (403 ``HttpError``, 404 ``HttpNotFound``, a retried 503
``HttpTransientExhausted``) and an answer the reader cannot use gives ``problem_type=None``;
the one exception is a stream that does not decode, which is ``MalformedRegistryResponse``, not
retried (#248). A truncated stream, bytes after its end and a raw ``deflate`` stream were read
before and are read now, so that a retried 5xx stays retried. The two things that did change
are marked ``delta-`` below: a ``gzip, gzip`` list and an unknown coding no longer give a
``type`` (httpx decoded the first twice and ignored the second). Their class is the same for
a body that was fine, and is the STATUS's for a body that was corrupt (it is no longer
decoded, so no longer ``MalformedRegistryResponse``): section 3 pins that too, and the same
for a corrupt stream that is refused for its size before its trailer is reached.

The clients are built through the REAL constructor with ``httpx.Client`` patched to inject a
``MockTransport`` (as test_ebsi_get_json_bounds.py does). A body is a stream the reader pulls
raw, as a socket's would be: ``httpx.Response(content=)`` would be decoded when it is built.
Self-contained: ``tests/`` is not a package. Dates are not used.
"""
from __future__ import annotations

import datetime
import gzip
import http.server
import json
import random
import ssl
import threading
import tracemalloc
import zlib
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

httpx = pytest.importorskip("httpx")

from openvc.errors import OpenvcError  # noqa: E402
from openvc_ebsi import http as H  # noqa: E402
from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402

NODE = "api-pilot.ebsi.eu"
NODE_URL = f"https://{NODE}/x"
PROBLEM = "application/problem+json"
CAP = H.MAX_ERROR_BODY_BYTES
FAST = H.RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)

STATUSES = [403, 404, 503]
CLASS = {403: H.HttpError, 404: H.HttpNotFound, 503: H.HttpTransientExhausted}
ATTEMPTS = {403: 1, 404: 1, 503: 3}              # a 503 is retried to the policy's budget

DOC = b'{"type": "urn:ebsi:problems:x"}'
TYPE = "urn:ebsi:problems:x"


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

class Wire(httpx.SyncByteStream):
    """A response body that counts how many chunks the reader pulled. (``closed`` is kept for
    the harness only: the request loop closes every response, read or not, so it proves nothing;
    that a connection is dropped is shown against a real socket, section 7.)"""

    def __init__(self, chunks):
        self.chunks = chunks
        self.pulled = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.pulled += 1
            yield chunk

    def close(self):
        self.closed = True


class Server:
    """A MockTransport handler: every request is answered with *status* and a FRESH body (a
    stream cannot be read twice), cut into *step*-byte chunks when *step* is given, or exactly
    the list *chunks* when that is."""

    def __init__(self, status, wire, coding=None, *, step=None, chunks=None,
                 content_type=PROBLEM):
        self.status, self.wire, self.coding = status, wire, coding
        self.step, self.chunks, self.content_type = step, chunks, content_type
        self.streams = []

    def __call__(self, request):
        wire, step = self.wire, self.step
        if self.chunks is not None:
            chunks = list(self.chunks)
        else:
            chunks = ([wire] if step is None
                      else [wire[i:i + step] for i in range(0, len(wire), step)])
        stream = Wire(chunks)
        self.streams.append(stream)
        headers = {}
        if self.content_type is not None:
            headers["content-type"] = self.content_type
        if self.coding is not None:
            headers["content-encoding"] = self.coding
        return httpx.Response(self.status, headers=headers, stream=stream)

    @property
    def n(self):
        return len(self.streams)


@pytest.fixture
def build(monkeypatch):
    """``build(handler, **kw)``: a client from the real constructor, with the transport injected
    into the ``httpx.Client`` it creates. Every inner client is closed."""
    real = httpx.Client
    created = []

    def make(handler, **kwargs):
        def patched(**kw):
            inner = real(transport=httpx.MockTransport(handler), **kw)
            created.append(inner)
            return inner
        monkeypatch.setattr(httpx, "Client", patched)
        try:
            kwargs.setdefault("retry", FAST)
            return H.EbsiHttpClient(allowed_hosts={NODE}, **kwargs)
        finally:
            monkeypatch.setattr(httpx, "Client", real)

    yield make
    for inner in created:
        inner.close()


def bare_client(handler, **kwargs):
    """A client over *handler* that costs little to build (no certificate store), for the
    property tests that make one per example."""
    client = H.EbsiHttpClient(allowed_hosts={NODE}, verify_tls=False, retry=FAST, **kwargs)
    client._client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def expect(cls, fn, *args, **kwargs):
    """Call ``fn`` and require EXACTLY ``cls`` (not a subclass), so a test cannot pass on an
    earlier or a different failure."""
    with pytest.raises(OpenvcError) as info:
        fn(*args, **kwargs)
    assert type(info.value) is cls, (
        f"expected {cls.__name__}, got {type(info.value).__name__}: {info.value}")
    return info.value


def peak_mib(fn):
    """Run ``fn`` and return (outcome, peak traced allocation in MiB)."""
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    tracemalloc.reset_peak()
    try:
        try:
            outcome = fn()
        except OpenvcError as exc:
            outcome = exc
        return outcome, tracemalloc.get_traced_memory()[1] / 2**20
    finally:
        if not was_tracing:
            tracemalloc.stop()


def raw_deflate(data):
    """A deflate stream without the zlib wrapper (some servers send it for ``deflate``)."""
    packer = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return packer.compress(data) + packer.flush()


_CODECS = {"gzip": gzip.compress, "deflate": zlib.compress, "raw-deflate": raw_deflate}
_BOMBS = {}


def pack(kind, plain):
    """*plain* as the wire bytes of *kind*, and the Content-Encoding to announce for it."""
    coding = "gzip" if kind == "gzip" else "deflate"
    return coding, _CODECS[kind](plain)


def bomb(kind, size):
    """*size* bytes of zeros as wire bytes of *kind* (cached: 256 MiB takes about a second)."""
    if (kind, size) not in _BOMBS:
        compress = {"gzip": lambda b: gzip.compress(b, 9), "deflate": lambda b: zlib.compress(b, 9),
                    "raw-deflate": raw_deflate}[kind]
        _BOMBS[kind, size] = compress(b"0" * size)
    return _BOMBS[kind, size]


def problem_of_size(n, typ=TYPE):
    """A Problem Details object of exactly *n* bytes (the padding is JSON whitespace)."""
    head = json.dumps({"type": typ}).encode()
    assert len(head) <= n
    body = head + b" " * (n - len(head))
    assert len(body) == n
    return body


# --------------------------------------------------------------------------- #
# 1. A decompression bomb as an error answer costs what its cap costs
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("status", STATUSES)
@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_the_256_mib_bomb_of_the_issue_is_refused_at_a_peak_far_below_its_size(
        build, kind, status):
    """260 KB on the wire, 256 MiB inflated: 557 MiB peak on ``main`` for every status. This
    one is also over the cap on the wire (the wire check refuses it before ``zlib`` runs), the
    next tests are the ones that reach ``zlib``."""
    wire = bomb(kind, 2**28)
    assert len(wire) > CAP
    server = Server(status, wire, "gzip" if kind == "gzip" else "deflate")
    client = build(server)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is CLASS[status], outcome
    assert outcome.status == status and outcome.problem_type is None
    assert server.n == ATTEMPTS[status]
    assert all(s.pulled == 1 for s in server.streams)
    assert peak < 1, f"peak allocation {peak:.0f} MiB: the error body was inflated"


@pytest.mark.parametrize("step", [None, 1024], ids=["one-chunk", "1-KiB-chunks"])
@pytest.mark.parametrize("status", STATUSES)
@pytest.mark.parametrize("kind", ["gzip", "deflate", "raw-deflate"])
def test_a_bomb_under_the_wire_cap_is_refused_inside_zlib_before_it_is_allocated(
        build, kind, status, step):
    """8 MiB of zeros in about 8 KB: under the wire cap, so ``zlib`` runs and is asked for at
    most the room left plus one byte. On ``main`` the same bytes peaked at 21 MiB in one chunk
    and 2.4 MiB in 1 KiB chunks (httpx inflates each chunk whole), 0.1 MiB here."""
    wire = bomb(kind, 2**23)
    assert len(wire) < CAP
    coding = "gzip" if kind == "gzip" else "deflate"
    server = Server(status, wire, coding, step=step)
    client = build(server)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is CLASS[status], outcome
    assert outcome.status == status and outcome.problem_type is None
    assert server.n == ATTEMPTS[status]
    # stopped at the first chunk, whose inflation is already past the cap: the rest of the wire
    # was not pulled (``closed`` would say nothing: the request loop closes every response)
    assert all(s.pulled == 1 for s in server.streams)
    assert peak < 1, f"peak allocation {peak:.1f} MiB: the decoded size was not capped in zlib"


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_valid_type_in_front_of_a_bomb_is_not_read_from_the_part_that_fits(build, kind):
    """The cap is on the answer, not on a prefix of it: a body that inflates past it has no
    ``type`` even when its first bytes are a perfectly good one (as on ``main``)."""
    plain = b'{"type": "urn:ok", "pad": "' + b"a" * 2**23 + b'"}'
    coding, wire = pack(kind, plain)
    assert len(wire) < CAP
    exc = expect(H.HttpNotFound, build(Server(404, wire, coding)).get_json, NODE_URL)
    assert exc.problem_type is None


def test_a_retried_503_does_not_accumulate_what_each_attempt_refused(build):
    """Six attempts, each one a bomb: the peak over the whole call is one attempt's, not their
    sum, and every response was left unread past the first chunk."""
    wire = bomb("gzip", 2**23)
    server = Server(503, wire, "gzip")
    client = build(server, retry=H.RetryPolicy(attempts=6, backoff_base_s=0.0, backoff_max_s=0.0))
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is H.HttpTransientExhausted and outcome.status == 503
    assert outcome.problem_type is None
    assert server.n == 6 and all(s.pulled == 1 for s in server.streams)
    assert peak < 1


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_bomb_does_not_stop_a_later_answer_from_being_read(build, kind):
    """The refusal is per response: after a bomb the same client reads a small coded Problem
    Details body and a 200, and nothing was cached from either error."""
    coding, small = pack(kind, DOC)
    answers = iter([
        lambda r: httpx.Response(503, headers={"content-encoding": coding},
                                 stream=Wire([bomb(kind, 2**23)])),
        lambda r: httpx.Response(404, headers={"content-type": PROBLEM, "content-encoding": coding},
                                 stream=Wire([small])),
        lambda r: httpx.Response(200, stream=httpx.ByteStream(b'{"ok": 1}')),
    ])
    client = build(lambda request: next(answers)(request), retry=H.RetryPolicy(
        attempts=1, backoff_base_s=0.0, backoff_max_s=0.0))
    assert expect(H.HttpTransientExhausted, client.get_json, NODE_URL).problem_type is None
    assert expect(H.HttpNotFound, client.get_json, NODE_URL).problem_type == TYPE
    assert client.get_json(NODE_URL) == {"ok": 1}


# --------------------------------------------------------------------------- #
# 2. The boundary: the cap is on the decoded body, and it is inclusive
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("step", [None, 1, 7, 4096])
@pytest.mark.parametrize("kind", ["gzip", "deflate", "raw-deflate"])
def test_a_decoded_body_at_the_cap_gives_its_type_and_one_byte_more_does_not(build, kind, step):
    if kind == "raw-deflate" and step == 1:
        pytest.skip("a one-byte first chunk is not told from a zlib header, as in httpx")
    coding, at = pack(kind, problem_of_size(CAP))
    _, over = pack(kind, problem_of_size(CAP + 1))
    assert len(at) < CAP and len(over) < CAP
    ok = expect(H.HttpNotFound, build(Server(404, at, coding, step=step)).get_json, NODE_URL)
    assert ok.problem_type == TYPE
    no = expect(H.HttpNotFound, build(Server(404, over, coding, step=step)).get_json, NODE_URL)
    assert no.problem_type is None


def test_a_stored_gzip_whose_wire_is_past_the_cap_is_past_the_cap():
    """The wire is bounded by the cap too, so a body that is LARGER on the wire than the cap
    is refused whatever it decodes to (stored blocks add 5 bytes each and the gzip frame
    18). Pinned as the one place the wire bound differs from main's decoded-only one; a real
    Problem Details answer is 150 to 190 bytes."""
    stored = gzip.compress(problem_of_size(CAP), 0)
    assert len(stored) > CAP
    client = bare_client(Server(404, stored, "gzip"))
    assert expect(H.HttpNotFound, client.get_json, NODE_URL).problem_type is None
    small = gzip.compress(problem_of_size(1024), 0)
    assert len(small) < CAP
    client = bare_client(Server(404, small, "gzip"))
    assert expect(H.HttpNotFound, client.get_json, NODE_URL).problem_type == TYPE


def test_a_coded_wire_of_exactly_the_cap_is_read_and_one_byte_more_is_refused(build):
    """The wire bound is ``wire > cap``, like the decoded one: a body of exactly the cap on the
    wire still gives its ``type``. A stored gzip adds 23 bytes to what it carries."""
    overhead = len(gzip.compress(b"", 0))
    at = gzip.compress(problem_of_size(CAP - overhead), 0)
    over = gzip.compress(problem_of_size(CAP - overhead + 1), 0)
    assert (len(at), len(over)) == (CAP, CAP + 1)
    assert expect(H.HttpNotFound, build(Server(404, at, "gzip")).get_json,
                  NODE_URL).problem_type == TYPE
    assert expect(H.HttpNotFound, build(Server(404, over, "gzip")).get_json,
                  NODE_URL).problem_type is None


def test_an_uncoded_body_at_the_cap_gives_its_type_and_one_byte_more_does_not(build):
    ok = expect(H.HttpNotFound, build(Server(404, problem_of_size(CAP))).get_json, NODE_URL)
    assert ok.problem_type == TYPE
    no = expect(H.HttpNotFound, build(Server(404, problem_of_size(CAP + 1))).get_json, NODE_URL)
    assert no.problem_type is None


def test_an_uncoded_body_is_not_appended_once_it_is_past_the_cap(build):
    """The check is before the append now: a 10 MiB chunk of a plain body costs no copy."""
    server = Server(400, b"a" * (10 * 2**20))
    client = build(server)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is H.HttpError and outcome.problem_type is None
    assert peak < 1


# --------------------------------------------------------------------------- #
# 3. What the status decides, and what a body that does not decode still is (#248)
# --------------------------------------------------------------------------- #

MALFORMED = object()
GZ = gzip.compress(DOC)

#   id, Content-Encoding, wire bytes, expected: MALFORMED, a type, or None
CONTRACT = [
    pytest.param("gzip", GZ, TYPE, id="gzip"),
    pytest.param("deflate", zlib.compress(DOC), TYPE, id="zlib-deflate"),
    pytest.param("deflate", raw_deflate(DOC), TYPE, id="raw-deflate"),
    pytest.param("GZIP", GZ, TYPE, id="upper-case-GZIP"),
    pytest.param(" gzip ", GZ, TYPE, id="spaced-gzip"),
    pytest.param("Deflate ", raw_deflate(DOC), TYPE, id="raw-deflate-odd-case-and-space"),
    pytest.param("identity", DOC, TYPE, id="identity"),
    pytest.param("gzip", GZ[:-8], TYPE, id="truncated-before-the-trailer"),
    pytest.param("gzip", GZ[:10], None, id="truncated-to-the-header"),
    pytest.param("gzip", b"", None, id="empty-under-gzip"),
    pytest.param("gzip", GZ + b"JUNK", TYPE, id="trailing-garbage"),
    pytest.param("gzip", GZ + gzip.compress(b'{"type": "urn:second"}'), TYPE,
                 id="second-gzip-member"),
    pytest.param("x-gzip", GZ, None, id="x-gzip"),
    pytest.param("br", b"\x00\x01\x02", None, id="br"),
    pytest.param("gzip", DOC, MALFORMED, id="not-gzip-under-gzip"),
    pytest.param("deflate", b"\xff\xfe\xfd garbage", MALFORMED, id="garbage-under-deflate"),
    pytest.param("gzip", GZ[:-8] + b"\x00" * 8, MALFORMED, id="bad-trailer-crc"),
    pytest.param("gzip", raw_deflate(DOC), MALFORMED, id="raw-deflate-is-for-deflate-only"),
    # the two changes (main read a type from both: it decoded the first twice and ignored the
    # second); the class is the same for a body that was not corrupt
    pytest.param("gzip, gzip", gzip.compress(GZ), None, id="delta-double-coding"),
    pytest.param("zzz", DOC, None, id="delta-unknown-coding-over-a-plain-body"),
]


@pytest.mark.parametrize("step", [None, 7], ids=["one-chunk", "7-byte-chunks"])
@pytest.mark.parametrize("status", STATUSES)
@pytest.mark.parametrize("coding,wire,expected", CONTRACT)
def test_the_status_decides_the_class_and_only_a_corrupt_stream_replaces_it(
        build, coding, wire, expected, status, step):
    server = Server(status, wire, coding, step=step)
    client = build(server)
    if expected is MALFORMED:
        exc = expect(MalformedRegistryResponse, client.get_json, NODE_URL)
        assert isinstance(exc.__cause__, httpx.DecodingError)
        assert isinstance(exc.__cause__.__cause__, zlib.error)
        assert server.n == 1                  # a body that does not decode is not retried
        return
    exc = expect(CLASS[status], client.get_json, NODE_URL)
    assert exc.status == status and exc.problem_type == expected
    assert server.n == ATTEMPTS[status]


def test_the_raw_deflate_retry_is_for_the_first_chunk_only(build):
    """httpx retried a raw stream when the FIRST chunk was not zlib. A zlib header in the first
    chunk (it decodes to nothing) and a raw stream after it is a stream that does not decode."""
    first = zlib.compress(b"A" * 50, 9)[:5]
    server = Server(503, b"", "deflate", chunks=[first, raw_deflate(DOC)])
    exc = expect(MalformedRegistryResponse, build(server).get_json, NODE_URL)
    assert isinstance(exc.__cause__, httpx.DecodingError) and server.n == 1


_BAD_CRC = gzip.compress(b'{"type": "urn:x", "pad": "' + b"a" * 40000 + b'"}', 9)
_BAD_CRC = _BAD_CRC[:-8] + b"\x00" * 8                  # ~100 bytes on the wire, 40 KB inflated
_RANDOM = random.Random(350).randbytes(CAP - 14)         # decodes under the cap, wire over it
_WIRE_OVER = gzip.compress(_RANDOM, 6)[:-8] + b"\x00" * 8

#   id, Content-Encoding, wire bytes, step
CORRUPT_BUT_NOT_DECODED = [
    pytest.param("gzip, gzip", DOC, None, id="double-coding-over-a-body-that-is-not-gzip"),
    pytest.param("gzip, deflate", b"\xff\xfe\xfd garbage", None, id="two-codings-over-garbage"),
    pytest.param("gzip", _BAD_CRC, None, id="bad-crc-past-the-decoded-cap-one-chunk"),
    pytest.param("gzip", _BAD_CRC, 50, id="bad-crc-past-the-decoded-cap-50-byte-chunks"),
    pytest.param("gzip", _WIRE_OVER, None, id="bad-crc-under-the-decoded-cap-over-the-wire-cap"),
    pytest.param("gzip", _WIRE_OVER, 4096, id="bad-crc-over-the-wire-cap-4-KiB-chunks"),
]


@pytest.mark.parametrize("status", STATUSES)
@pytest.mark.parametrize("coding,wire,step", CORRUPT_BUT_NOT_DECODED)
def test_a_corrupt_body_that_is_not_decoded_or_is_refused_first_is_the_statuss_class(
        build, coding, wire, step, status):
    """The one place a class DOES change against ``main`` (pinned, not hidden): a corrupt body
    that the reader never gets to decode (a coding it does not read) or refuses for its size
    before the damage is reached (a bad CRC trailer after more than the cap, or behind a wire
    over it) was ``MalformedRegistryResponse``, not retried, on ``main`` when it arrived whole
    (and the status's class when the trailer arrived in a later chunk: it depended on the
    chunking). It is the status's class now, whatever the chunking: more retries and fail-over,
    bounded by the attempt budget, and nothing accepted that was refused."""
    if wire is _WIRE_OVER:
        assert len(wire) > CAP
    server = Server(status, wire, coding, step=step)
    exc = expect(CLASS[status], build(server).get_json, NODE_URL)
    assert exc.status == status and exc.problem_type is None
    assert server.n == ATTEMPTS[status]


def test_a_stream_that_goes_bad_after_a_good_first_chunk_is_malformed_not_retried(build):
    wire = gzip.compress(problem_of_size(CAP // 2))
    # the 10-byte gzip header decodes to nothing, the next chunk is an invalid block type
    server = Server(503, wire[:10] + b"\xff" * 20, "gzip", step=10)
    exc = expect(MalformedRegistryResponse, build(server).get_json, NODE_URL)
    assert isinstance(exc.__cause__, httpx.DecodingError) and server.n == 1


@pytest.mark.parametrize("status", STATUSES)
@pytest.mark.parametrize("coding", ["gzip, gzip", "gzip, deflate", "br", "zstd", "compress",
                                    "x-gzip", "zzz", "gzip,", ",gzip", "gzip\x00"])
def test_a_coding_the_client_does_not_decode_is_never_an_encoding_error_on_an_error_answer(
        build, coding, status):
    """``HttpUnexpectedEncoding`` is the 200 path's class (it carries status 200): the 200
    reader raises it for these, and it must never replace a 403, a 404 or a retried 503."""
    server = Server(status, GZ, coding)
    exc = expect(CLASS[status], build(server).get_json, NODE_URL)
    assert exc.status == status and exc.problem_type is None
    assert server.n == ATTEMPTS[status]
    assert all(s.pulled == 0 for s in server.streams)                # not even read


def test_a_double_coded_bomb_is_not_read_at_all(build):
    """``gzip, gzip`` was decoded twice by httpx, the second pass over the first's whole
    output; it is not decoded now, so its expansion costs nothing."""
    inner = bomb("gzip", 2**23)
    wire = gzip.compress(inner)
    server = Server(403, wire, "gzip, gzip")
    client = build(server)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is H.HttpError and outcome.problem_type is None
    assert peak < 1 and server.streams[0].pulled == 0


@pytest.mark.parametrize("content_type", ["text/html", "application/json", None])
@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_coded_body_under_another_media_type_gives_no_type(build, kind, content_type):
    coding, wire = pack(kind, DOC)
    exc = expect(H.HttpError, build(Server(403, wire, coding, content_type=content_type)).get_json,
                 NODE_URL)
    assert exc.problem_type is None


@pytest.mark.parametrize("status", STATUSES)
@pytest.mark.parametrize("kind", ["gzip", "deflate", "raw-deflate"])
def test_a_small_coded_problem_details_body_still_gives_its_type(build, kind, status):
    coding, wire = pack(kind, json.dumps(
        {"type": "urn:ebsi:problems:identifier-not-found", "title": "t",
         "status": status}).encode())
    server = Server(status, wire, coding)
    exc = expect(CLASS[status], build(server).get_json, NODE_URL)
    assert exc.problem_type == "urn:ebsi:problems:identifier-not-found"
    assert server.n == ATTEMPTS[status]
    assert all(s.pulled == 1 for s in server.streams)               # read to its end


@pytest.mark.parametrize("coding", ["gzip", "deflate"])
def test_a_small_coded_body_is_read_to_the_end_so_the_connection_can_be_reused(build, coding):
    _, wire = pack(coding, DOC)
    server = Server(403, wire, coding, step=3)
    expect(H.HttpError, build(server).get_json, NODE_URL)
    assert server.streams[0].pulled == len(server.streams[0].chunks) > 1


def test_a_body_a_transport_double_has_already_decoded_is_read_without_stream_consumed(build):
    """``httpx.Response(content=...)`` is decoded when it is built, so there is nothing for
    ``iter_raw`` to give (it would raise ``StreamConsumed``); no socket hands one over, and
    the answers the older tests build are of this kind."""
    def handler(request):
        return httpx.Response(404, content=gzip.compress(DOC), headers={
            "content-type": PROBLEM, "content-encoding": "gzip"})
    assert expect(H.HttpNotFound, build(handler).get_json, NODE_URL).problem_type == TYPE


def test_a_bomb_a_transport_double_has_already_decoded_is_still_capped(build):
    """The same double over a bomb: httpx inflated it when the double was built (the double's
    own cost, outside the client), and what the client reads of it is capped."""
    plain = b'{"type": "urn:ok", "pad": "' + b"a" * 2**21 + b'"}'

    def handler(request):
        return httpx.Response(404, content=gzip.compress(plain), headers={
            "content-type": PROBLEM, "content-encoding": "gzip"})
    assert expect(H.HttpNotFound, build(handler).get_json, NODE_URL).problem_type is None


# --------------------------------------------------------------------------- #
# 4. The deadline and the transport still bound the read
# --------------------------------------------------------------------------- #

class TickTime:
    """Stands in for the ``time`` module of openvc_ebsi.http: every reading is 100 s later."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        self.now += 100.0
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.mark.parametrize("coding", ["gzip", "deflate"])
def test_a_dripping_coded_error_body_is_given_up_at_the_deadline(build, monkeypatch, coding):
    _, wire = pack(coding, problem_of_size(1024))
    server = Server(403, wire, coding, step=1)                    # one byte at a time
    client = build(server, timeout_s=10.0)
    monkeypatch.setattr(H, "time", TickTime())
    exc = expect(H.HttpError, client.get_json, NODE_URL)
    assert exc.status == 403 and exc.problem_type is None
    assert server.streams[0].pulled == 1


#: A gzip member header followed by empty stored deflate blocks: it decodes to NOTHING, however
#: long it is. ``iter_bytes`` yielded no chunk for it, so on ``main`` the loop body that held the
#: cap and the deadline never ran: 4 MiB of it was drained under a 16 KiB cap, and 5 001 chunks
#: were pulled past a deadline that had expired at the first.
EMPTY_BLOCKS = gzip.compress(b"")[:10] + b"\x00\x00\x00\xff\xff" * (4 * 2**20 // 5)


@pytest.mark.parametrize("status", [403, 503])
@pytest.mark.parametrize("step", [4095, 65536])
def test_a_coded_body_that_decodes_to_nothing_is_still_bounded_by_the_wire_cap(
        build, status, step):
    server = Server(status, EMPTY_BLOCKS, "gzip", step=step)
    exc = expect(CLASS[status], build(server).get_json, NODE_URL)
    assert exc.status == status and exc.problem_type is None
    assert server.n == ATTEMPTS[status]
    for stream in server.streams:                    # the cap, plus the chunk that crossed it
        assert stream.pulled <= CAP // step + 2 < len(stream.chunks)


def test_a_coded_body_that_decodes_to_nothing_is_still_bounded_by_the_deadline(
        build, monkeypatch):
    server = Server(403, EMPTY_BLOCKS[:20_000], "gzip", step=5)       # 4 000 chunks of 5 bytes
    client = build(server, timeout_s=10.0)
    monkeypatch.setattr(H, "time", TickTime())
    exc = expect(H.HttpError, client.get_json, NODE_URL)
    assert exc.status == 403 and exc.problem_type is None
    assert server.streams[0].pulled == 1


def test_a_read_error_in_the_middle_of_a_coded_body_is_retried_like_any_transport_error(build):
    class Dies(httpx.SyncByteStream):
        def __iter__(self):
            yield GZ[:5]
            raise httpx.ReadError("connection reset")

    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503, headers={"content-type": PROBLEM, "content-encoding": "gzip"},
                              stream=Dies())
    exc = expect(H.HttpTransientExhausted, build(handler).get_json, NODE_URL)
    assert exc.status is None and calls["n"] == 3         # the transport failure, not a status


# --------------------------------------------------------------------------- #
# 5. The 200 path and everything around the read are untouched
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_200_coded_body_still_goes_through_the_200_reader(build, kind):
    coding, wire = pack(kind, b'{"ok": 1}')
    client = build(Server(200, wire, coding, content_type="application/json"))
    assert client.get_json(NODE_URL) == {"ok": 1}


@pytest.mark.parametrize("coding", ["gzip, gzip", "br", "x-gzip"])
def test_a_200_under_a_coding_the_client_does_not_decode_is_still_an_encoding_error(build, coding):
    exc = expect(H.HttpUnexpectedEncoding, build(Server(200, GZ, coding)).get_json, NODE_URL)
    assert exc.status == 200


def test_a_200_bomb_is_still_http_error_200_at_a_small_peak(build):
    wire = bomb("gzip", 2**23)
    client = build(Server(200, wire, "gzip", content_type="application/json"),
                   max_response_bytes=1 << 20)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is H.HttpError and outcome.status == 200 and peak < 16


def test_get_bytes_and_probe_still_never_read_an_error_body(build):
    server = Server(403, bomb("gzip", 2**23), "gzip")
    client = build(server)
    assert expect(H.HttpError, client.get_bytes, NODE_URL).problem_type is None
    assert client.probe(NODE_URL).status == 403
    assert all(s.pulled == 0 for s in server.streams)


def test_an_error_answer_is_never_cached(build):
    coding, wire = pack("gzip", DOC)
    server = Server(404, wire, coding)
    client = build(server)
    for _ in range(2):
        expect(H.HttpNotFound, client.get_json, NODE_URL)
    assert server.n == 2


# --------------------------------------------------------------------------- #
# 6. Properties
# --------------------------------------------------------------------------- #

_TYPES = st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7e),
                 min_size=1, max_size=40)


@settings(max_examples=150, deadline=None)
@given(typ=_TYPES, pad=st.integers(0, CAP + 2000), edge=st.one_of(st.none(), st.integers(-3, 3)),
       kind=st.sampled_from(sorted(_CODECS)), step=st.sampled_from([None, 8, 64, 1000]),
       status=st.sampled_from(STATUSES))
def test_property_the_bounded_read_agrees_with_an_unbounded_decode_up_to_the_cap(
        typ, pad, edge, kind, step, status):
    """For any Problem Details object, whatever the coding, the chunking and the status: the
    type read is the one an unbounded decode finds when the decoded body fits the cap, and
    ``None`` when it does not; the class is the status's. *edge* puts the body within three
    bytes of the cap, either side of it."""
    if edge is not None:
        pad = max(0, CAP - len(json.dumps({"type": typ, "pad": ""})) + edge)
    plain = json.dumps({"type": typ, "pad": "x" * pad}).encode()
    coding, wire = pack(kind, plain)
    client = bare_client(Server(status, wire, coding, step=step))
    exc = expect(CLASS[status], client.get_json, NODE_URL)
    expected = H._problem_type(PROBLEM, plain) if len(plain) <= CAP else None
    assert exc.problem_type == expected
    assert (exc.problem_type == typ) == (len(plain) <= CAP)


_CODINGS = ["gzip", "deflate", "identity", "br", "gzip, gzip", "x-gzip", "", "zzz", "GZIP"]
_ALLOWED = (H.HttpError, H.HttpNotFound, H.HttpTransientExhausted, MalformedRegistryResponse)


@settings(max_examples=250, deadline=None)
@given(wire=st.binary(max_size=4096), coding=st.sampled_from(_CODINGS),
       status=st.sampled_from(STATUSES), step=st.sampled_from([None, 1, 5, 100]),
       content_type=st.sampled_from([PROBLEM, "text/html", None]))
def test_fuzz_arbitrary_bytes_under_any_coding_give_only_the_typed_errors(
        wire, coding, status, step, content_type):
    """Arbitrary wire bytes under any Content-Encoding raise a class of the error family and
    never a bare ``zlib`` or httpx exception; a ``type`` is short visible ASCII or ``None``."""
    server = Server(status, wire, coding or None, step=step, content_type=content_type)
    with pytest.raises(OpenvcError) as info:
        bare_client(server).get_json(NODE_URL)
    assert isinstance(info.value, _ALLOWED), type(info.value)
    if not isinstance(info.value, MalformedRegistryResponse):
        assert type(info.value) is CLASS[status]
        pt = info.value.problem_type
        assert pt is None or (1 <= len(pt) <= 256 and pt.isascii() and pt.isprintable()
                              and " " not in pt)


@settings(max_examples=120, deadline=None)
@given(plain=st.builds(lambda unit, times: unit * times, st.binary(max_size=300),
                       st.integers(0, 200)),
       kind=st.sampled_from(sorted(_CODECS)), step=st.sampled_from([None, 17, 4096]))
def test_fuzz_any_compressed_body_is_read_within_its_cap_or_refused(plain, kind, step):
    """Any decoded body, compressible or not: no exception outside the family, and a body past
    the cap never gives a type."""
    coding, wire = pack(kind, plain)
    with pytest.raises(OpenvcError) as info:
        bare_client(Server(404, wire, coding, step=step)).get_json(NODE_URL)
    assert isinstance(info.value, (H.HttpNotFound, MalformedRegistryResponse))
    if len(plain) > CAP:
        assert getattr(info.value, "problem_type", None) is None


# --------------------------------------------------------------------------- #
# 7. A dropped connection is not observable through a mock: a real socket
# --------------------------------------------------------------------------- #

_SOCKET_ROUTES = {
    # path: (Content-Encoding, wire bytes)
    "/small-gzip": ("gzip", GZ),
    "/small-deflate": ("deflate", zlib.compress(DOC)),
    "/small-raw-deflate": ("deflate", raw_deflate(DOC)),
    "/bomb-8-mib": ("gzip", bomb("gzip", 2**23)),
    "/bomb-256-mib": ("gzip", bomb("gzip", 2**28)),
    "/empty-blocks": ("gzip", EMPTY_BLOCKS),
    "/double-coded": ("gzip, gzip", gzip.compress(GZ)),
}


class _TlsServer:
    """A throwaway HTTPS server on 127.0.0.1 that answers every route of ``_SOCKET_ROUTES`` with
    a 403 ``application/problem+json`` under its coding, and counts the connections it accepts
    (a client that drops a connection has to open another one for its next request)."""

    def __init__(self, tmp_path: Path) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .sign(key, hashes.SHA256()))
        certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.connections = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                outer.connections += 1
                super().setup()

            def log_message(self, *args):
                pass

            def do_GET(self):
                coding, wire = _SOCKET_ROUTES[self.path]
                self.send_response(403)
                self.send_header("Content-Type", PROBLEM)
                self.send_header("Content-Encoding", coding)
                self.send_header("Content-Length", str(len(wire)))
                self.end_headers()
                try:
                    self.wfile.write(wire)
                except OSError:                       # the client dropped the connection
                    self.close_connection = True

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certfile), str(keyfile))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.mark.parametrize("path,reused", [
    pytest.param("/small-gzip", True, id="small-gzip-is-read-to-the-end"),
    pytest.param("/small-deflate", True, id="small-deflate-is-read-to-the-end"),
    pytest.param("/small-raw-deflate", True, id="small-raw-deflate-is-read-to-the-end"),
    pytest.param("/bomb-8-mib", False, id="bomb-8-mib-drops-the-connection"),
    pytest.param("/bomb-256-mib", False, id="bomb-256-mib-drops-the-connection"),
    pytest.param("/empty-blocks", False, id="empty-blocks-drop-the-connection"),
    pytest.param("/double-coded", False, id="a-coding-not-read-drops-the-connection"),
])
def test_a_coded_error_body_keeps_the_connection_only_when_it_was_read_to_the_end(
        tmp_path, monkeypatch, path, reused):
    """The mock streams cannot tell a dropped connection from a drained one, and ``closed`` is
    always true there. Over a real TLS socket: after a body that was read to its end the next
    request reuses the connection; after a bomb, a body past the wire cap or a coding that is
    not read it opens another one. (``empty-blocks`` is the one ``main`` drained and reused.)"""
    # the origin guard admits port 443 only (#318) and this server listens on an ephemeral one;
    # the guard is not what this test is about (tests/test_ebsi_guard_origin.py pins it)
    monkeypatch.setattr(H.EbsiHttpClient, "_guard_host", lambda self, url: None)
    with _TlsServer(tmp_path) as server:
        client = H.EbsiHttpClient(allowed_hosts={"127.0.0.1"}, verify_tls=False, retry=FAST,
                                  timeout_s=10.0)
        url = f"https://127.0.0.1:{server.port}{path}"
        try:
            for _ in range(2):
                exc = expect(H.HttpError, client.get_json, url)
                assert exc.status == 403
                assert exc.problem_type == (TYPE if path.startswith("/small") else None)
            assert server.connections == (1 if reused else 2)
        finally:
            client.close()
