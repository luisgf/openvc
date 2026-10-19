"""
tests/test_ebsi_get_json_bounds.py — what a hostile or misbehaving allow-listed host can make
``EbsiHttpClient.get_json`` cost (#335, and the request-path rows (a) and (b) of #324).

Two bounds, both on the request path every registry read goes through:

1. **The decoded size of a 200 body.** ``get_json`` used to read with ``iter_bytes`` and check
   its cap after appending, but ``iter_bytes`` yields a chunk that is already inflated, so one
   small ``gzip`` chunk could allocate the expansion ratio times itself before the cap fired
   (260 934 bytes of gzip became 256 MiB in one chunk, a 557 MiB peak). ``get_json`` now reads
   through the reader ``get_bytes`` has: the wire is read raw, one ``gzip`` or ``deflate``
   coding is decoded with ``zlib`` asked for at most the room left, and any other coding is
   ``HttpUnexpectedEncoding``.
2. **How long a ``Retry-After`` can make the client sleep, and what a hostile value does to
   the parser.** The sleep was ``max(backoff, Retry-After)`` with no ceiling, and the value
   was read with ``str.isdigit`` + ``float``: 400 digits became ``inf`` and ``time.sleep``
   raised a bare ``OverflowError``; ``"²"`` passed ``isdigit`` and ``float`` raised a bare
   ``ValueError``. Every sleep is now ``min(max(backoff, Retry-After),
   RetryPolicy.retry_after_max_s)`` (default: ``backoff_max_s``), and the value is delta-seconds
   only as a short run of ASCII digits, an HTTP-date, or ignored.

The clients are built through the REAL constructor with ``httpx.Client`` patched to inject a
``MockTransport`` (as test_ebsi_http_bytes.py does), so the default headers are the shipped
ones. A body is a stream the reader pulls raw, as a socket's would be. New names are reached as
``H.<name>`` at call time, so that a run of this file against the previous release fails test
by test (the controls still pass) instead of failing to collect. The tests that need a new
``RetryPolicy`` field build the policy inside the test for the same reason.
"""
from __future__ import annotations

import gzip
import math
import tracemalloc
import zlib
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

httpx = pytest.importorskip("httpx")

from openvc import __version__  # noqa: E402
from openvc.errors import OpenvcError  # noqa: E402
from openvc_ebsi import http as H  # noqa: E402
from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402

NODE = "api-pilot.ebsi.eu"
NODE_URL = f"https://{NODE}/x"


def default_ceiling_policy(attempts=3):
    """Zero backoff, so a retry sleeps exactly what the policy's ceiling lets a Retry-After ask
    for. The ceiling is the default one (``backoff_max_s``): 5 s here."""
    return H.RetryPolicy(attempts=attempts, backoff_base_s=0.0, backoff_max_s=5.0)


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

class Chunks(httpx.SyncByteStream):
    """A response body that counts how many chunks the reader pulled from it."""

    def __init__(self, chunks):
        self._chunks = chunks
        self.pulled = 0

    def __iter__(self):
        for chunk in self._chunks:
            self.pulled += 1
            yield chunk


def R(status=200, content=b"", headers=None, stream=None):
    """A response as a socket delivers it: a body the reader pulls (``httpx.Response(content=)``
    would decode it eagerly)."""
    return httpx.Response(
        status, headers=headers,
        stream=stream if stream is not None else httpx.ByteStream(content))


def reply(status=200, content=b"", headers=None):
    """A step that builds a fresh response per request, so a body can be read more than once."""
    return lambda request: R(status, content, headers)


class Script:
    """A MockTransport handler: records every request and plays its steps in turn (the last
    one repeats). A step is an exception to raise or a callable that builds the response."""

    def __init__(self, *steps):
        self.steps = steps
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        step = self.steps[min(len(self.requests) - 1, len(self.steps) - 1)]
        if isinstance(step, Exception):
            raise step
        return step(request)

    @property
    def n(self):
        return len(self.requests)


class FakeTime:
    """Stands in for the ``time`` module of openvc_ebsi.http: a sleep advances the clock."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


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
            return H.EbsiHttpClient(allowed_hosts={NODE}, **kwargs)
        finally:
            monkeypatch.setattr(httpx, "Client", real)

    yield make
    for inner in created:
        inner.close()


@pytest.fixture
def fake_time(monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)
    return fake


def expect(cls, fn, *args, **kwargs):
    """Call ``fn`` and require EXACTLY ``cls`` (not a subclass), so a test cannot pass on an
    earlier or a different failure."""
    with pytest.raises(OpenvcError) as info:
        fn(*args, **kwargs)
    assert type(info.value) is cls, (
        f"expected {cls.__name__}, got {type(info.value).__name__}: {info.value}")
    return info.value


def bare_client(handler, **kwargs):
    """A client over *handler* that costs little to build (no certificate store), for the
    property tests that make one per example. Built by the real constructor, then its pooled
    ``httpx.Client`` is swapped for a mock one."""
    client = H.EbsiHttpClient(allowed_hosts={NODE}, verify_tls=False, **kwargs)
    client._client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


_BOMBS = {}


def bomb(kind):
    """256 MiB of zeros compressed to ~260 KB (cached: it takes about a second to make)."""
    if kind not in _BOMBS:
        compress = gzip.compress if kind == "gzip" else zlib.compress
        _BOMBS[kind] = compress(b"0" * 2**28, 9)
    return _BOMBS[kind]


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


def encoded(kind, plain):
    return gzip.compress(plain) if kind == "gzip" else zlib.compress(plain)


def json_of_size(n):
    """A JSON object of exactly *n* bytes."""
    body = b'{"a":"' + b"x" * (n - 8) + b'"}'
    assert len(body) == n
    return body


# --------------------------------------------------------------------------- #
# 1. A decoded chunk is never larger than the cap
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_decompression_bomb_in_one_chunk_is_refused_before_it_is_allocated(build, kind):
    wire = bomb(kind)
    assert len(wire) < 300_000                        # 260 KB on the wire, 256 MiB inflated
    stream = Chunks([wire])
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind}, stream=stream))
    client = build(script, max_response_bytes=1 << 20)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is H.HttpError and outcome.status == 200, outcome
    assert "exceeds" in str(outcome)
    assert script.n == 1                              # terminal, not retried
    # About 2 MiB with the bounded reader, 557 MiB before it (the inflated chunk, then a copy).
    assert peak < 16, f"peak allocation {peak:.0f} MiB: the decoded size was not capped in zlib"


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_decompression_bomb_split_over_many_raw_chunks_is_refused_early(build, kind):
    wire = bomb(kind)
    pieces = [wire[i:i + 1024] for i in range(0, len(wire), 1024)]
    stream = Chunks(pieces)
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind}, stream=stream))
    client = build(script, max_response_bytes=1 << 20)
    outcome, peak = peak_mib(lambda: client.get_json(NODE_URL))
    assert type(outcome) is H.HttpError and outcome.status == 200, outcome
    assert peak < 16
    assert stream.pulled < len(pieces) // 10          # stopped long before the end of the wire


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_decoded_size_at_the_cap_passes_and_one_over_fails(build, kind):
    plain = json_of_size(2048)
    wire = encoded(kind, plain)
    headers = {"Content-Encoding": kind}
    ok = build(Script(reply(200, wire, headers)), max_response_bytes=len(plain))
    assert ok.get_json(NODE_URL)["a"] == "x" * 2040
    over = build(Script(reply(200, wire, headers)), max_response_bytes=len(plain) - 1)
    exc = expect(H.HttpError, over.get_json, NODE_URL)
    assert exc.status == 200 and "exceeds" in str(exc)


def test_an_uncoded_body_at_the_cap_passes_and_one_over_fails(build):
    plain = json_of_size(2048)
    ok = build(Script(reply(200, plain)), max_response_bytes=len(plain))
    assert len(ok.get_json(NODE_URL)["a"]) == 2040
    over = build(Script(reply(200, plain)), max_response_bytes=len(plain) - 1)
    exc = expect(H.HttpError, over.get_json, NODE_URL)
    assert exc.status == 200 and "exceeds" in str(exc)


def test_an_uncoded_body_is_refused_before_a_chunk_past_the_cap_is_appended(build):
    chunks = Chunks(iter([b"x" * 65536] * 3200))      # 200 MiB on offer, cap 1 KiB
    script = Script(lambda req: R(200, stream=chunks))
    exc = expect(H.HttpError, build(script, max_response_bytes=1024).get_json, NODE_URL)
    assert exc.status == 200 and chunks.pulled == 1 and script.n == 1


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_declared_length_over_the_cap_is_refused_before_the_body_is_read(build, kind):
    chunks = Chunks([encoded(kind, b'{"a": 1}')])
    script = Script(lambda req: R(200, stream=chunks, headers={
        "Content-Encoding": kind, "Content-Length": "999999999"}))
    exc = expect(H.HttpError, build(script, max_response_bytes=1 << 20).get_json, NODE_URL)
    assert exc.status == 200 and chunks.pulled == 0


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_well_formed_compressed_answer_is_still_returned(build, kind):
    doc = {"id": "did:ebsi:z", "keys": [1, 2, 3], "name": "ü€ ☃"}
    plain = (b'{"id": "did:ebsi:z", "keys": [1, 2, 3], "name": "' +
             "ü€ ☃".encode() + b'"}')
    script = Script(reply(200, encoded(kind, plain), {"Content-Encoding": kind}))
    assert build(script).get_json(NODE_URL) == doc
    assert script.n == 1


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
@pytest.mark.parametrize("step", [1, 7, 4096])
def test_a_compressed_answer_split_into_tiny_chunks_decodes_identically(build, kind, step):
    wire = encoded(kind, json_of_size(5000))
    pieces = [wire[i:i + step] for i in range(0, len(wire), step)]
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind},
                                  stream=Chunks(pieces)))
    assert len(build(script).get_json(NODE_URL)["a"]) == 4992


@pytest.mark.parametrize("coding", [None, "identity", "Identity", ""])
def test_an_uncoded_answer_is_returned(build, coding):
    headers = {} if coding is None else {"Content-Encoding": coding}
    script = Script(reply(200, b'{"ok": 1}', headers))
    assert build(script).get_json(NODE_URL) == {"ok": 1}


def test_a_body_the_transport_has_already_read_is_still_served():
    """``httpx.Response(json=...)`` is read eagerly and its stream marked consumed (what most
    test doubles in this repository return). With no coding there is nothing to inflate, so the
    reader uses ``iter_bytes`` and serves it; a raw read of it would be ``StreamConsumed``."""
    client = bare_client(lambda req: httpx.Response(200, json={"ok": True}))
    try:
        assert client.get_json(NODE_URL) == {"ok": True}
    finally:
        client.close()


@pytest.mark.parametrize("label,compress", [("gzip", gzip.compress), ("deflate", zlib.compress)])
def test_a_coded_body_the_transport_has_already_read_is_still_served(label, compress):
    """``httpx.Response(content=<gzip bytes>, headers={"Content-Encoding": "gzip"})`` is decoded
    and read when it is built, so a raw read of it is ``StreamConsumed`` (not an ``OpenvcError``
    and not what ``get_json`` served before this change). The decoded content is what is left to
    read; no socket hands over such a response."""
    client = bare_client(lambda req: httpx.Response(
        200, content=compress(b'{"ok": 1}'), headers={"Content-Encoding": label}))
    try:
        assert client.get_json(NODE_URL) == {"ok": 1}
        assert client.get_bytes(NODE_URL).body == b'{"ok": 1}'
    finally:
        client.close()


def test_the_cap_holds_on_a_coded_body_the_transport_has_already_read():
    big = b'{"k": "' + b"a" * 400 + b'"}'
    client = bare_client(
        lambda req: httpx.Response(
            200, content=gzip.compress(big), headers={"Content-Encoding": "gzip"}),
        max_response_bytes=100, retry=H.RetryPolicy(attempts=1))
    try:
        exc = expect(H.HttpError, client.get_json, NODE_URL)
        assert exc.status == 200 and "exceeds 100 bytes" in str(exc)
    finally:
        client.close()


@pytest.mark.parametrize("coding", ["br", "zstd", "x-gzip", "compress", "gzip, gzip", "gzip, br",
                                    "identity, gzip", "deflate, gzip", "gzip,deflate", "gzipp",
                                    "\x00", "gzip;q=1"])
def test_an_encoding_other_than_one_gzip_or_deflate_is_unexpected(build, coding):
    body = Chunks([b'{"ok": 1}'])
    script = Script(lambda req: R(200, headers=[(b"content-encoding", coding.encode())],
                                  stream=body))
    exc = expect(H.HttpUnexpectedEncoding, build(script).get_json, NODE_URL)
    assert exc.status == 200 and script.n == 1        # terminal, not retried
    assert body.pulled == 0                           # refused before the body is read


GARBAGE = b"this is not a compressed stream"
GOOD = b'{"ok": 1}'


@pytest.mark.parametrize("label,wire", [
    pytest.param("gzip", GARBAGE, id="gzip-garbage"),
    pytest.param("deflate", GARBAGE, id="deflate-garbage"),
    pytest.param("gzip", zlib.compress(GOOD), id="zlib-labelled-gzip"),
    pytest.param("deflate", gzip.compress(GOOD), id="gzip-labelled-deflate"),
    # the whole document arrives, the trailer (CRC and length / Adler-32) does not: httpx
    # handed such a body over as complete
    pytest.param("gzip", gzip.compress(GOOD)[:-5], id="gzip-truncated-trailer"),
    pytest.param("deflate", zlib.compress(GOOD)[:-3], id="deflate-truncated-trailer"),
    # a stream cut short whose decoded prefix is itself a document: httpx returned
    # {"ok": 1} for this one
    pytest.param("gzip", gzip.compress(GOOD * 50)[:20], id="gzip-truncated-body"),
    pytest.param("gzip", b"", id="gzip-empty"),
])
def test_a_compressed_body_that_does_not_decode_is_malformed_and_not_retried(build, label, wire):
    script = Script(reply(200, wire, {"Content-Encoding": label}))
    exc = expect(MalformedRegistryResponse, build(script).get_json, NODE_URL)
    assert script.n == 1
    assert "https://" in str(exc) and len(str(exc)) < 200     # bounded, names the URL


def test_a_raw_deflate_stream_is_malformed_where_httpx_used_to_accept_it(build):
    """``deflate`` here is the zlib format (``zlib.compress``), as on the ``get_bytes`` path.
    httpx fell back to a raw stream (no zlib header) when the first attempt failed; that
    tolerance is not kept, because the reader decodes with ``zlib`` itself."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    wire = compressor.compress(GOOD) + compressor.flush()
    script = Script(reply(200, wire, {"Content-Encoding": "deflate"}))
    expect(MalformedRegistryResponse, build(script).get_json, NODE_URL)
    assert script.n == 1


def test_a_corrupt_stream_chains_the_zlib_error_that_caused_it(build):
    script = Script(reply(200, GARBAGE, {"Content-Encoding": "gzip"}))
    exc = expect(MalformedRegistryResponse, build(script).get_json, NODE_URL)
    assert isinstance(exc.__cause__, zlib.error)


@pytest.mark.parametrize("label,wire", [
    pytest.param("gzip", gzip.compress(GOOD) + b"x", id="gzip-trailing-byte"),
    pytest.param("gzip", gzip.compress(GOOD) + gzip.compress(GOOD), id="gzip-two-members"),
    pytest.param("deflate", zlib.compress(GOOD) + b"junk", id="deflate-trailing-bytes"),
])
def test_bytes_after_the_end_of_a_compressed_stream_are_malformed_not_dropped(
        build, label, wire):
    script = Script(reply(200, wire, {"Content-Encoding": label}))
    expect(MalformedRegistryResponse, build(script).get_json, NODE_URL)
    assert script.n == 1


def test_get_json_asks_for_the_codings_it_decodes_and_get_bytes_for_none(build):
    script = Script(reply(200, b'{"ok": 1}'))
    client = build(script)
    client.get_json(NODE_URL)
    client.get_bytes(f"https://{NODE}/y")
    assert script.requests[0].headers["accept-encoding"] == "gzip, deflate"
    assert script.requests[1].headers["accept-encoding"] == "identity"
    assert script.requests[0].headers["user-agent"] == f"openvc-core/{__version__}"


def test_the_deadline_still_bounds_a_slow_body(build, fake_time):
    def slow():
        yield b'{"a":'
        fake_time.now += 11.0                         # past timeout_s (10 s), between chunks
        yield b' 1}'
    script = Script(lambda req: R(200, stream=Chunks(slow())))
    exc = expect(H.HttpError, build(script).get_json, NODE_URL)
    assert "deadline" in str(exc) and script.n == 1


def test_a_gzipped_answer_is_cached_like_any_other(build):
    script = Script(reply(200, gzip.compress(b'{"ok": 1}'), {"Content-Encoding": "gzip"}))
    client = build(script)
    assert client.get_json(NODE_URL) == {"ok": 1}
    assert client.get_json(NODE_URL) == {"ok": 1}
    assert script.n == 1


@settings(max_examples=300, deadline=None)
@given(wire=st.binary(max_size=300), label=st.sampled_from(["gzip", "deflate"]),
       cap=st.integers(0, 400))
def test_fuzz_arbitrary_bytes_under_a_coding_give_a_document_or_a_typed_error(wire, label, cap):
    client = bare_client(lambda req: R(200, wire, {"Content-Encoding": label}),
                         max_response_bytes=cap, retry=H.RetryPolicy(attempts=1))
    try:
        got = client.get_json(NODE_URL)
    except OpenvcError as exc:
        assert type(exc) in (H.HttpError, MalformedRegistryResponse), exc
    else:
        assert isinstance(got, dict)
    finally:
        client.close()


@settings(max_examples=200, deadline=None)
@given(coding=st.binary(max_size=24))
def test_fuzz_content_encoding_values_give_a_document_or_a_typed_error(coding):
    client = bare_client(lambda req: R(200, b'{"ok": 1}', [(b"content-encoding", coding)]),
                         retry=H.RetryPolicy(attempts=1))
    try:
        got = client.get_json(NODE_URL)
    except OpenvcError as exc:
        assert type(exc) in (H.HttpUnexpectedEncoding, MalformedRegistryResponse), exc
    else:
        assert got == {"ok": 1}                       # no coding, or identity
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# 2. Retry-After: the parser
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value,expected", [
    pytest.param("0", 0.0, id="zero"),
    pytest.param("2", 2.0, id="small"),
    pytest.param("120", 120.0, id="two-minutes"),
    pytest.param("86400", 86400.0, id="a-day"),
    pytest.param("007", 7.0, id="leading-zeros"),
    pytest.param("999999999", 999999999.0, id="nine-digits-is-the-longest"),
    pytest.param(" 5 ", 5.0, id="spaces-around"),
    pytest.param("\t7\t", 7.0, id="tabs-around"),
])
def test_delta_seconds_is_a_short_run_of_ascii_digits(value, expected):
    assert H._parse_retry_after(value) == expected


@pytest.mark.parametrize("value", [
    pytest.param("9999999999", id="ten-digits"),
    pytest.param("99999999999", id="eleven-digits"),
    pytest.param("9" * 400, id="four-hundred-digits"),
    pytest.param("9" * 5000, id="past-the-int-str-conversion-limit"),
    pytest.param("0" * 400, id="four-hundred-zeros"),
    pytest.param("²", id="superscript-two"),
    pytest.param("٣", id="arabic-indic-three"),
    pytest.param("١٢٣", id="arabic-indic-123"),
    pytest.param("５", id="fullwidth-five"),
    pytest.param("5 ", id="no-break-space"),
    pytest.param(" 5", id="em-space"),
    pytest.param("nan", id="nan"),
    pytest.param("NaN", id="NaN"),
    pytest.param("inf", id="inf"),
    pytest.param("-inf", id="minus-inf"),
    pytest.param("-1", id="negative"),
    pytest.param("+5", id="plus-sign"),
    pytest.param("1e400", id="exponent"),
    pytest.param("1.5", id="fraction"),
    pytest.param("5 6", id="two-numbers"),
    pytest.param("5, 7", id="two-headers-joined"),
    pytest.param("0x10", id="hex"),
    pytest.param("5\n", id="newline"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="blank"),
    pytest.param(None, id="absent"),
    pytest.param("not-a-date", id="words"),
    pytest.param("\x00", id="nul"),
    # Longer than any HTTP-date form, so not one. The stdlib date parser ignores the trailing
    # text and reads this as a date (CPython 3.10 to 3.15, measured), so only the length bound
    # turns it into None.
    pytest.param("Sun, 06 Nov 1994 08:49:37 GMT" + "x" * 100, id="date-then-junk"),
])
def test_anything_that_is_not_ascii_digits_or_a_date_is_ignored(value):
    assert H._parse_retry_after(value) is None


def test_an_http_date_is_the_seconds_until_it():
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    secs = H._parse_retry_after(future)
    assert secs is not None and 0 < secs <= 31
    past = format_datetime(datetime.now(timezone.utc) - timedelta(seconds=30), usegmt=True)
    assert H._parse_retry_after(past) == 0.0          # never negative


@pytest.mark.parametrize("value", [
    "Sun, 06 Nov 1994 08:49:37 GMT",                  # IMF-fixdate
    "Sunday, 06-Nov-94 08:49:37 GMT",                 # RFC 850
    "Sun Nov  6 08:49:37 1994",                       # asctime
])
def test_the_three_http_date_forms_are_read(value):
    assert H._parse_retry_after(value) == 0.0         # long past


def test_a_date_far_in_the_future_is_a_finite_number_the_caller_clamps():
    value = format_datetime(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc), usegmt=True)
    secs = H._parse_retry_after(value)
    assert secs is not None and math.isfinite(secs) and secs > 1e11


@pytest.mark.parametrize("value", [
    "Mon, 01 Jan 2000 00:00:00 +99999999999999999999",
    "Mon, 01 Jan 2000 00:00:00 +9999",
    "Mon, 31 Feb 2000 00:00:00 GMT",
    "Mon, 01 Jan 2000 24:00:00 GMT",
    "01 Jan 99999999999 00:00:00 GMT",
    "Mon, 01 Jan 2000 00:00:00 +" + "9" * 5000,
    "Sun, 06 Nov 1994 08:49:37 GMT" + " " * 100_000,
    "١٢ Jan 2000",
])
def test_a_malformed_or_oversized_date_is_ignored_not_raised(value):
    secs = H._parse_retry_after(value)
    assert secs is None or (math.isfinite(secs) and secs >= 0)


@settings(max_examples=500, deadline=None)
@given(value=st.one_of(
    st.text(max_size=80),
    st.from_regex(r"\s*[0-9²٣]{0,14}\s*", fullmatch=True),
    st.from_regex(r"[A-Za-z]{3}, [0-9]{1,3} [A-Za-z]{3} [0-9]{1,6} [0-9:]{0,10} [A-Z+0-9-]{0,12}",
                  fullmatch=True)))
def test_fuzz_the_parser_gives_none_or_a_finite_non_negative_number(value):
    secs = H._parse_retry_after(value)
    assert secs is None or (isinstance(secs, float) and math.isfinite(secs) and secs >= 0.0)


@settings(max_examples=200, deadline=None)
@given(n=st.integers(0, 999_999_999))
def test_fuzz_a_short_run_of_digits_is_read_exactly(n):
    assert H._parse_retry_after(str(n)) == float(n)


# --------------------------------------------------------------------------- #
# 3. Retry-After: the sleep
# --------------------------------------------------------------------------- #

RETRIED_STATUSES = [429, 500, 502, 503, 504]


@pytest.mark.parametrize("status", RETRIED_STATUSES)
@pytest.mark.parametrize("header", ["86400", "999999999", "99999999999"])
def test_a_retry_after_above_the_ceiling_sleeps_the_ceiling_not_the_ask(
        build, fake_time, status, header):
    script = Script(reply(status, headers={"Retry-After": header}))
    client = build(script, retry=default_ceiling_policy())
    expect(H.HttpTransientExhausted, client.get_json, NODE_URL)
    assert script.n == 3
    # 86400 and 999999999 are read and cut to the ceiling; 99999999999 is ignored, and the
    # client keeps its own (zero) backoff. Neither is the time the server asked for.
    assert fake_time.sleeps and max(fake_time.sleeps) <= 5.0
    if header != "99999999999":
        assert fake_time.sleeps == [5.0, 5.0]


@pytest.mark.parametrize("status", [429, 503])
def test_a_retry_after_date_a_day_out_sleeps_the_ceiling(build, fake_time, status):
    tomorrow = format_datetime(datetime.now(timezone.utc) + timedelta(days=1), usegmt=True)
    script = Script(reply(status, headers={"Retry-After": tomorrow}))
    expect(H.HttpTransientExhausted, build(script, retry=default_ceiling_policy()).get_json,
           NODE_URL)
    assert fake_time.sleeps == [5.0, 5.0]


@pytest.mark.parametrize("status", [429, 503])
def test_a_retry_after_date_in_the_year_9999_cannot_reach_time_sleep(build, fake_time, status):
    far = format_datetime(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc), usegmt=True)
    script = Script(reply(status, headers={"Retry-After": far}))
    expect(H.HttpTransientExhausted, build(script, retry=default_ceiling_policy()).get_json,
           NODE_URL)
    assert fake_time.sleeps == [5.0, 5.0]


@pytest.mark.parametrize("raw", [
    pytest.param(b"99999999999", id="eleven-digits"),
    pytest.param(b"9" * 400, id="four-hundred-digits"),
    pytest.param(b"9" * 5000, id="five-thousand-digits"),
    pytest.param("²".encode(), id="superscript-two-as-utf-8"),
    pytest.param("١٢٣".encode(), id="arabic-indic-123-as-utf-8"),
    pytest.param(b"nan", id="nan"),
    pytest.param(b"inf", id="inf"),
    pytest.param(b"-1", id="negative"),
    pytest.param(b" 5 ", id="spaces"),
    pytest.param(b"", id="empty"),
    pytest.param(b"1e400", id="exponent"),
    pytest.param(b"\xff\xfe", id="invalid-utf-8"),
    pytest.param(b"Mon, 01 Jan 2000 00:00:00 +99999999999999999999", id="date-huge-offset"),
])
@pytest.mark.parametrize("status", [429, 503])
def test_a_hostile_retry_after_is_a_typed_outcome_never_a_bare_exception(
        build, fake_time, status, raw):
    script = Script(lambda req: R(status, headers=[(b"Retry-After", raw)]))
    expect(H.HttpTransientExhausted, build(script, retry=default_ceiling_policy()).get_json,
           NODE_URL)
    assert script.n == 3 and len(fake_time.sleeps) == 2
    assert all(math.isfinite(s) and 0.0 <= s <= 5.0 for s in fake_time.sleeps), fake_time.sleeps


@pytest.mark.parametrize("raw,expected", [
    pytest.param(b"0", [0.0, 0.0], id="zero"),
    pytest.param(b"2", [2.0, 2.0], id="two"),
    pytest.param(b" 3 ", [3.0, 3.0], id="spaced-three"),
    pytest.param(b"5", [5.0, 5.0], id="at-the-ceiling"),
    pytest.param(b"6", [5.0, 5.0], id="one-over-the-ceiling"),
])
def test_a_small_retry_after_is_still_honoured(build, fake_time, raw, expected):
    """The control: the bound is a ceiling, not a removal of Retry-After support."""
    script = Script(lambda req: R(429, headers=[(b"Retry-After", raw)]))
    expect(H.HttpTransientExhausted, build(script, retry=default_ceiling_policy()).get_json,
           NODE_URL)
    assert fake_time.sleeps == expected


def test_a_retry_after_that_recovers_returns_the_body_after_the_bounded_sleep(
        build, fake_time):
    script = Script(reply(503, headers={"Retry-After": "86400"}), reply(200, b'{"ok": 1}'))
    assert build(script, retry=default_ceiling_policy()).get_json(NODE_URL) == {"ok": 1}
    assert fake_time.sleeps == [5.0] and script.n == 2


def test_a_retry_after_below_the_backoff_does_not_shorten_it(build, fake_time, monkeypatch):
    monkeypatch.setattr(H.random, "uniform", lambda a, b: b)          # the backoff's top
    policy = H.RetryPolicy(attempts=2, backoff_base_s=4.0, backoff_max_s=4.0)
    script = Script(reply(503, headers={"Retry-After": "1"}))
    expect(H.HttpTransientExhausted, build(script, retry=policy).get_json, NODE_URL)
    assert fake_time.sleeps == [4.0]


def test_the_ceiling_bounds_a_transport_error_backoff_too(build, fake_time, monkeypatch):
    monkeypatch.setattr(H.random, "uniform", lambda a, b: b)
    policy = H.RetryPolicy(attempts=3, backoff_base_s=8.0, backoff_max_s=8.0,
                           retry_after_max_s=1.0)
    script = Script(httpx.ConnectError("refused"))
    expect(H.HttpTransientExhausted, build(script, retry=policy).get_json, NODE_URL)
    assert fake_time.sleeps == [1.0, 1.0]             # "every sleep", not only Retry-After's


def test_a_policy_ceiling_above_the_default_lets_a_longer_retry_after_through(
        build, fake_time):
    policy = H.RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=5.0,
                           retry_after_max_s=60.0)
    script = Script(reply(429, headers={"Retry-After": "45"}))
    expect(H.HttpTransientExhausted, build(script, retry=policy).get_json, NODE_URL)
    assert fake_time.sleeps == [45.0, 45.0]


def test_a_zero_ceiling_never_sleeps(build, fake_time):
    policy = H.RetryPolicy(attempts=3, backoff_base_s=1.0, backoff_max_s=1.0,
                           retry_after_max_s=0)
    script = Script(reply(429, headers={"Retry-After": "30"}))
    expect(H.HttpTransientExhausted, build(script, retry=policy).get_json, NODE_URL)
    assert fake_time.sleeps == [0.0, 0.0] and script.n == 3


def test_a_callers_budget_still_shortens_a_sleep_below_the_ceiling(build, fake_time):
    policy = H.RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0,
                           retry_after_max_s=60.0)
    script = Script(reply(503, headers={"Retry-After": "60"}))
    expect(H.HttpError, build(script, retry=policy).get_bytes, NODE_URL, deadline_s=2)
    assert fake_time.sleeps and sum(fake_time.sleeps) <= 2.0


def test_a_backoff_ceiling_above_a_day_cannot_reach_time_sleep(build, fake_time):
    """A policy whose own ceiling is absurd (a caller who meant "no limit") still never hands
    ``time.sleep`` more than a day, which it always takes: the date form is the one value that
    can ask for more than 9.2e9 s."""
    far = format_datetime(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc), usegmt=True)
    policy = H.RetryPolicy(attempts=2, backoff_base_s=0.0, backoff_max_s=1e12)
    assert policy.retry_after_max_s is None           # follows backoff_max_s, unvalidated
    script = Script(reply(503, headers={"Retry-After": far}))
    expect(H.HttpTransientExhausted, build(script, retry=policy).get_json, NODE_URL)
    assert fake_time.sleeps == [86400.0]


def test_the_last_attempt_does_not_sleep(build, fake_time):
    script = Script(reply(503, headers={"Retry-After": "3"}))
    expect(H.HttpTransientExhausted, build(script, retry=default_ceiling_policy(2)).get_json,
           NODE_URL)
    assert fake_time.sleeps == [3.0] and script.n == 2


@settings(max_examples=400, deadline=None)
@given(raw=st.one_of(
    st.binary(max_size=80),
    st.text(max_size=60).map(lambda t: t.encode()),
    st.from_regex(r"\s*[0-9]{0,14}\s*", fullmatch=True).map(lambda t: t.encode()),
    st.from_regex(r"[A-Za-z]{3}, [0-9]{1,3} [A-Za-z]{3} [0-9]{1,6} [0-9:]{0,10} [A-Z+0-9-]{0,12}",
                  fullmatch=True).map(lambda t: t.encode())))
def test_fuzz_the_sleep_for_any_retry_after_is_finite_and_within_the_ceiling(raw):
    ceiling = 3.0
    policy = H.RetryPolicy(attempts=2, backoff_base_s=0.0, backoff_max_s=ceiling)
    client = bare_client(lambda req: R(200), retry=policy)
    fake, real_time = FakeTime(), H.time
    H.time = fake
    try:
        client._sleep_before_retry(0, httpx.Response(429, headers=[(b"Retry-After", raw)]))
    finally:
        H.time = real_time
        client.close()
    assert len(fake.sleeps) == 1
    assert math.isfinite(fake.sleeps[0]) and 0.0 <= fake.sleeps[0] <= ceiling


@settings(max_examples=300, deadline=None)
@given(n=st.integers(0, 999_999_999), cap=st.floats(0, 600, allow_nan=False),
       # not a subnormal: `backoff / 2 + backoff / 2` is not `backoff` once `backoff / 2` underflows
       backoff=st.one_of(st.just(0.0), st.floats(1e-3, 600)))
def test_fuzz_the_sleep_is_min_of_max_of_backoff_and_retry_after_and_the_ceiling(n, cap, backoff):
    policy = H.RetryPolicy(attempts=2, backoff_base_s=backoff, backoff_max_s=backoff,
                           retry_after_max_s=cap)
    client = bare_client(lambda req: R(200), retry=policy)
    fake, real_time, real_uniform = FakeTime(), H.time, H.random.uniform
    H.time, H.random.uniform = fake, (lambda a, b: b)         # backoff = its ceiling, `backoff`
    try:
        client._sleep_before_retry(0, httpx.Response(
            429, headers=[(b"Retry-After", str(n).encode())]))
    finally:
        H.time, H.random.uniform = real_time, real_uniform
        client.close()
    assert fake.sleeps == [min(max(backoff, float(n)), cap)]


# --------------------------------------------------------------------------- #
# 4. The policy
# --------------------------------------------------------------------------- #

def test_the_ceiling_is_none_by_default_and_none_means_the_backoff_ceiling():
    assert H.RetryPolicy().retry_after_max_s is None
    assert H.RetryPolicy(retry_after_max_s=None) == H.RetryPolicy()


@pytest.mark.parametrize("backoff_max_s,asked,slept", [
    (5.0, "30", 5.0),
    (60.0, "45", 45.0),
    (60.0, "90", 60.0),
    (0.0, "30", 0.0),
])
def test_without_an_explicit_ceiling_a_retry_after_is_cut_at_backoff_max_s(
        build, fake_time, backoff_max_s, asked, slept):
    policy = H.RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=backoff_max_s)
    script = Script(reply(429, headers={"Retry-After": asked}))
    expect(H.HttpTransientExhausted, build(script, retry=policy).get_json, NODE_URL)
    assert fake_time.sleeps == [slept, slept]


def test_replace_of_backoff_max_s_moves_the_ceiling_with_it(build, fake_time, monkeypatch):
    """A policy derived with ``dataclasses.replace`` is the policy built directly: the ceiling
    is not copied at the old value, so it neither caps the backoff nor the ``Retry-After`` at
    the 5 s the original had."""
    import dataclasses
    monkeypatch.setattr(H.random, "uniform", lambda a, b: b)          # the backoff's top
    base = H.RetryPolicy(attempts=3, backoff_base_s=100.0)
    derived = dataclasses.replace(base, backoff_max_s=60.0)
    assert derived == H.RetryPolicy(attempts=3, backoff_base_s=100.0, backoff_max_s=60.0)
    script = Script(reply(503, headers={"Retry-After": "45"}))
    expect(H.HttpTransientExhausted, build(script, retry=derived).get_json, NODE_URL)
    assert fake_time.sleeps == [60.0, 60.0]           # the backoff at its new ceiling


@pytest.mark.parametrize("backoff_max_s", [1e6, -1.0, float("nan"), 1e300])
def test_replace_of_a_policy_with_an_odd_backoff_max_s_does_not_raise(backoff_max_s):
    """Nothing validated ``backoff_max_s`` before this change, so a policy that could be built
    and copied still can: only an explicit ``retry_after_max_s`` is checked."""
    import dataclasses
    odd = H.RetryPolicy(backoff_max_s=backoff_max_s)
    assert dataclasses.replace(odd, attempts=5).attempts == 5


def test_replace_keeps_an_explicit_ceiling_and_still_validates_one():
    import dataclasses
    kept = dataclasses.replace(H.RetryPolicy(retry_after_max_s=7.0), backoff_max_s=60.0)
    assert kept.retry_after_max_s == 7.0
    with pytest.raises(ValueError):
        dataclasses.replace(H.RetryPolicy(), retry_after_max_s=-1)


@pytest.mark.parametrize("ceiling", [0, 0.0, 1, 2.5, 30, 86400, 86400.0])
def test_an_explicit_ceiling_is_kept(ceiling):
    assert H.RetryPolicy(retry_after_max_s=ceiling).retry_after_max_s == ceiling


@pytest.mark.parametrize("bad", [
    True, False, "5", b"5", [5], -1, -0.5, float("nan"), float("inf"), float("-inf"),
    86400.5, 86401, 10**30, 10**400, 1e300, object()],
    ids=lambda v: f"{type(v).__name__}-{repr(v)[:12]}")
def test_a_ceiling_that_is_not_a_number_of_seconds_up_to_a_day_is_a_value_error(bad):
    with pytest.raises(ValueError) as info:
        H.RetryPolicy(retry_after_max_s=bad)
    assert "retry_after_max_s" in str(info.value) and len(str(info.value)) < 200


def test_a_policy_is_still_frozen_hashable_and_comparable():
    policy = H.RetryPolicy(attempts=2, retry_after_max_s=7.0)
    assert hash(policy) == hash(H.RetryPolicy(attempts=2, retry_after_max_s=7.0))
    with pytest.raises(AttributeError):
        policy.retry_after_max_s = 1.0                # type: ignore[misc]


def test_the_fields_that_existed_are_unchanged():
    p = H.RetryPolicy()
    assert (p.attempts, p.backoff_base_s, p.backoff_max_s) == (3, 0.25, 5.0)
    assert p.retry_statuses == frozenset({429, 500, 502, 503, 504})
    assert 0.0 <= p.backoff(0) <= p.backoff_max_s
