"""
tests/test_ebsi_http_bytes.py — the bytes GET and the tnl.ebsi.eu fetch helper (#320,
ADR-0009 D4).

``EbsiHttpClient.get_bytes`` returns a body verbatim (the Trusted Nodes List signatures cover
exact bytes, and two of the four files are binary), under the same host guard, redirects-off
and retry rules as ``get_json`` and with a size cap that holds on the DECODED size too.
``for_tnl`` / ``get_tnl_files`` fetch the four list documents from a client that allow-lists
``tnl.ebsi.eu`` alone. Nothing here verifies anything: that is the verifier's job (#319).

The clients are built through the REAL constructors with ``httpx.Client`` patched to inject a
``MockTransport``, so ``follow_redirects``, the default headers and the cookie policy are the
shipped ones (the older rows in test_ebsi_http.py replace ``_client`` wholesale, which would
hide a mutation of any of them).

A mocked response is built with ``R(...)``, whose body is a stream the reader pulls raw, as a
socket's would be. ``httpx.Response(content=...)`` decodes eagerly and marks its stream
consumed, which ``iter_raw`` (rightly) refuses: it is not what a transport delivers.

New names are reached as ``H.<name>`` at call time, never imported at the top, so that a run of
this file against the previous release fails test by test (the ``get_json`` controls still pass)
instead of failing to collect.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import socket
import threading
import time
import tracemalloc
import zlib
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

httpx = pytest.importorskip("httpx")

from openvc import __version__  # noqa: E402
from openvc.cache import TtlCache  # noqa: E402
from openvc.errors import OpenvcError  # noqa: E402
from openvc_ebsi import http as H  # noqa: E402
from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402

NODE = "api-pilot.ebsi.eu"
NODE_URL = f"https://{NODE}/x"
TNL = "tnl.ebsi.eu"
TNL_URL = f"https://{TNL}/tnl.json"
FIXTURE = Path(__file__).parent / "fixtures" / "ebsi" / "tnl_response_headers.json"

# Zero backoff so the retry-loop tests do not sleep.
FAST = H.RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)
ONCE = H.RetryPolicy(attempts=1)


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
    """A response as a socket delivers it (see the module docstring)."""
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

    @property
    def urls(self):
        return [str(r.url) for r in self.requests]


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
    """``build(handler, factory=None, **kw)``: a client from the real constructor, with the
    transport injected into the ``httpx.Client`` it creates. Every inner client is closed."""
    real = httpx.Client
    created = []

    def make(handler, factory=None, **kwargs):
        def patched(**kw):
            inner = real(transport=httpx.MockTransport(handler), **kw)
            created.append(inner)
            return inner
        monkeypatch.setattr(httpx, "Client", patched)
        try:
            factory = factory or (lambda **kw: H.EbsiHttpClient(allowed_hosts={NODE}, **kw))
            return factory(**kwargs)
        finally:
            monkeypatch.setattr(httpx, "Client", real)

    yield make
    for inner in created:
        inner.close()


def expect(cls, fn, *args, **kwargs):
    """Call ``fn`` and require EXACTLY ``cls`` (not a subclass), so a test cannot pass on an
    earlier or a different failure."""
    with pytest.raises(OpenvcError) as info:
        fn(*args, **kwargs)
    assert type(info.value) is cls, (
        f"expected {cls.__name__}, got {type(info.value).__name__}: {info.value}")
    return info.value


def tnl_client(build, handler, **kw):
    return build(handler, factory=H.for_tnl, **kw)


# A body with every byte value, a trailing newline, CRLFs, a NUL and a UTF-8 BOM: what a text
# decode, a strip or a newline normalisation would change.
NASTY = bytes(range(256)) + b"\r\n\r\n" + b"\x00" + b"\xef\xbb\xbf" + b"tail\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


_BOMBS = {}


def bomb(kind):
    """256 MiB of zeros compressed to ~260 KB (cached: it takes half a second to make)."""
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


# --------------------------------------------------------------------------- #
# 1. The host guard: both paths, the list host and the node hosts kept apart
# --------------------------------------------------------------------------- #

TNL_GUARD_URLS = [
    pytest.param("http://tnl.ebsi.eu/tnl.json", id="not-https"),
    pytest.param("https://api-pilot.ebsi.eu/x", id="pilot-node-host"),
    pytest.param("https://api.ebsi.iti.gr/v1/x", id="listed-node-host"),
    pytest.param("https://tnl.ebsi.eu.example/tnl.json", id="suffix-lookalike"),
    pytest.param("https://tnl.ebsi.eu@api.ebsi.iti.gr/", id="userinfo-lookalike"),
    pytest.param("https://tnl.ebsi.eu/x\ty", id="tab"),
    pytest.param("https://tnl.ebsi.eu/x/é", id="non-ascii"),
    pytest.param("https://tnl.ebsi.eu:99999/x", id="port-out-of-range"),
    pytest.param("https://[::1/x", id="broken-ipv6"),
]


@pytest.mark.parametrize("method", ["get_json", "get_bytes"])
@pytest.mark.parametrize("url", TNL_GUARD_URLS)
def test_tnl_client_refuses_any_other_host_before_any_request(build, method, url):
    script = Script(reply(200, b'{"ok": true}'))
    client = tnl_client(build, script, retry=FAST)
    expect(H.HttpForbiddenHost, getattr(client, method), url)
    assert script.n == 0


@pytest.mark.parametrize("method", ["get_json", "get_bytes"])
def test_node_client_refuses_the_list_host(build, method):
    script = Script(reply(200, b'{"ok": true}'))
    client = build(script, factory=lambda **kw: H.for_ebsi("legacy-pilot", **kw), retry=FAST)
    expect(H.HttpForbiddenHost, getattr(client, method), TNL_URL)
    assert script.n == 0


def test_for_tnl_allows_the_list_host_alone():
    with H.for_tnl() as client:
        assert client.allowed_hosts == frozenset({"tnl.ebsi.eu"})
        assert isinstance(client.allowed_hosts, frozenset)


def test_for_tnl_does_not_take_an_allow_list():
    with pytest.raises(TypeError):
        H.for_tnl(allowed_hosts={"tnl.ebsi.eu", "api.ebsi.iti.gr"})
    with pytest.raises(TypeError):
        H.for_tnl(allowed_hosts=set())


def test_allowed_hosts_is_a_read_only_view_of_the_guard(build):
    client = build(Script(reply(200, b"x")), retry=FAST)
    assert client.allowed_hosts == frozenset({NODE})
    with pytest.raises(AttributeError):
        client.allowed_hosts.add("evil.example")          # a frozenset has no add
    expect(H.HttpForbiddenHost, client.get_bytes, "https://evil.example/x")


@pytest.mark.parametrize("hosts", [
    pytest.param({NODE}, id="node-host"),
    pytest.param({"tnl.ebsi.eu", "api.ebsi.iti.gr"}, id="list-host-plus-a-node"),
    pytest.param({"tnl.ebsi.eu", "tnl.ebsi.eu.example"}, id="list-host-plus-a-lookalike"),
    pytest.param(set(), id="empty"),
])
def test_get_tnl_files_refuses_a_client_that_is_not_the_list_host_alone(build, hosts):
    script = Script(reply(200, b"x"))
    client = build(script, factory=lambda **kw: H.EbsiHttpClient(allowed_hosts=hosts, **kw))
    expect(H.HttpForbiddenHost, H.get_tnl_files, client)
    assert script.n == 0


def test_get_tnl_files_refuses_a_pilot_environment_client(build):
    script = Script(reply(200, b"x"))
    client = build(script, factory=lambda **kw: H.for_ebsi("legacy-pilot", **kw))
    expect(H.HttpForbiddenHost, H.get_tnl_files, client)
    assert script.n == 0


def test_get_tnl_files_refuses_an_object_that_is_not_a_client():
    expect(H.HttpForbiddenHost, H.get_tnl_files, object())


# --------------------------------------------------------------------------- #
# 2. Redirects are never followed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", [
    pytest.param("https://tnl.ebsi.eu/elsewhere", id="allow-listed-host"),
    pytest.param("https://10.0.0.1/secret", id="private-address"),
    pytest.param("http://127.0.0.1:8080/", id="loopback"),
])
def test_a_redirect_is_an_error_and_the_location_is_never_requested(build, code, location):
    body = Chunks([b"<html>moved</html>"])
    script = Script(lambda req: R(code, headers={"Location": location}, stream=body))
    client = tnl_client(build, script, retry=FAST)
    exc = expect(H.HttpError, client.get_bytes, TNL_URL)
    assert exc.status == code
    assert script.urls == [TNL_URL]                  # one request, the Location never asked for
    assert body.pulled == 0                          # and the body never read


# --------------------------------------------------------------------------- #
# 3. The size cap: wire bytes, Content-Length, max_bytes
# --------------------------------------------------------------------------- #

def test_wire_body_over_the_cap_is_refused_and_the_iterator_is_not_run_to_the_end(build):
    body = Chunks([b"x" * 100] * 1000)                # 100 000 bytes on the wire, cap 1 000
    script = Script(lambda req: R(200, stream=body))
    client = build(script, max_response_bytes=1000, retry=FAST)
    exc = expect(H.HttpError, client.get_bytes, NODE_URL)
    assert exc.status == 200 and script.n == 1       # a size refusal is terminal, not retried
    assert body.pulled == 11                          # ten chunks fit; the eleventh crosses


def test_body_exactly_at_the_cap_is_returned(build):
    client = build(Script(reply(200, b"x" * 1000)), max_response_bytes=1000)
    assert client.get_bytes(NODE_URL).body == b"x" * 1000


def test_content_length_over_the_cap_is_refused_before_any_body_is_read(build):
    body = Chunks([b"x" * 10])
    script = Script(lambda req: R(200, headers={"Content-Length": "5000"}, stream=body))
    client = build(script, max_response_bytes=1000, retry=FAST)
    exc = expect(H.HttpError, client.get_bytes, NODE_URL)
    assert exc.status == 200 and script.n == 1
    assert body.pulled == 0


@pytest.mark.parametrize("declared", ["9" * 30, "9" * 5000, "99999999999999999999", " 5000 "])
def test_an_enormous_or_padded_content_length_is_still_over_the_cap(build, declared):
    body = Chunks([b"x" * 10])
    script = Script(lambda req: R(200, headers={"Content-Length": declared}, stream=body))
    client = build(script, max_response_bytes=1000, retry=FAST)
    expect(H.HttpError, client.get_bytes, NODE_URL)
    assert body.pulled == 0


@pytest.mark.parametrize("declared", ["", "abc", "-5", "5.0", "1,2", "٣"])
def test_a_content_length_that_is_not_a_size_is_ignored_and_the_streamed_cap_applies(
        build, declared):
    header = [(b"content-length", declared.encode())]
    ok = Script(lambda req: R(200, b"x" * 10, header))
    assert build(ok, max_response_bytes=1000).get_bytes(NODE_URL).body == b"x" * 10
    big = Script(lambda req: R(200, headers=header, stream=Chunks([b"x" * 100] * 50)))
    expect(H.HttpError, build(big, max_response_bytes=1000).get_bytes, NODE_URL)


def test_max_bytes_can_lower_the_clients_cap_but_never_raise_it(build):
    lower = build(Script(reply(200, b"x" * 11)), max_response_bytes=1000)
    expect(H.HttpError, lower.get_bytes, NODE_URL, max_bytes=10)
    assert lower.get_bytes(NODE_URL, max_bytes=11).body == b"x" * 11

    higher = build(Script(reply(200, b"x" * 500)), max_response_bytes=100)
    expect(H.HttpError, higher.get_bytes, NODE_URL, max_bytes=100_000)


@pytest.mark.parametrize("bad", [-1, 1.5, float("nan"), "10", True, [1]])
def test_max_bytes_that_is_not_a_size_is_an_error_before_any_request(build, bad):
    script = Script(reply(200, b"x"))
    client = build(script)
    expect(H.HttpError, client.get_bytes, NODE_URL, max_bytes=bad)
    assert script.n == 0


def test_for_tnl_caps_a_response_at_64_kib_unless_told_otherwise(build):
    script = Script(reply(200, b"x" * (64 * 1024 + 1)))
    expect(H.HttpError, tnl_client(build, script).get_bytes, TNL_URL)
    ok = Script(reply(200, b"x" * (64 * 1024)))
    assert len(tnl_client(build, ok).get_bytes(TNL_URL).body) == 64 * 1024
    small = Script(reply(200, b"x" * 11))
    expect(H.HttpError, tnl_client(build, small, max_response_bytes=10).get_bytes, TNL_URL)


# --------------------------------------------------------------------------- #
# 4. Content-Encoding: identity, one gzip or deflate, nothing else; the decoded size is capped
# --------------------------------------------------------------------------- #

def _encoded(kind, plain):
    return gzip.compress(plain) if kind == "gzip" else zlib.compress(plain)


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_decompression_bomb_is_refused_inside_zlib_before_it_is_allocated(build, kind):
    wire = bomb(kind)
    assert len(wire) < 300_000                        # 260 KB on the wire, 256 MiB inflated
    stream = Chunks([wire])
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind}, stream=stream))
    client = build(script, max_response_bytes=1 << 20, retry=FAST)
    outcome, peak = peak_mib(lambda: client.get_bytes(NODE_URL))
    assert type(outcome) is H.HttpError and outcome.status == 200, outcome
    assert script.n == 1
    # Calibrated on first run: ~2 MiB, against the 557 MiB peak of get_json on the same bomb.
    assert peak < 16, f"peak allocation {peak:.0f} MiB: the decoded size was not capped in zlib"


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_a_decompression_bomb_split_over_many_raw_chunks_is_refused_early(build, kind):
    wire = bomb(kind)
    pieces = [wire[i:i + 1024] for i in range(0, len(wire), 1024)]
    stream = Chunks(pieces)
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind}, stream=stream))
    client = build(script, max_response_bytes=1 << 20, retry=FAST)
    outcome, peak = peak_mib(lambda: client.get_bytes(NODE_URL))
    assert type(outcome) is H.HttpError, outcome
    assert peak < 16
    assert stream.pulled < len(pieces) // 10          # stopped long before the end of the wire


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_decoded_size_at_the_cap_passes_and_one_over_fails(build, kind):
    plain = bytes(range(256)) * 4
    wire = _encoded(kind, plain)
    headers = {"Content-Encoding": kind}
    ok = build(Script(reply(200, wire, headers)), max_response_bytes=len(plain))
    assert ok.get_bytes(NODE_URL).body == plain
    over = build(Script(reply(200, wire, headers)), max_response_bytes=len(plain) - 1)
    expect(H.HttpError, over.get_bytes, NODE_URL)


@pytest.mark.parametrize("coding", ["br", "zstd", "x-gzip", "compress", "gzip, gzip", "gzip, br",
                                    "identity, gzip", "deflate, gzip", "gzip,deflate", "gzipp",
                                    "\x00", "gzip;q=1"])
def test_an_encoding_other_than_one_gzip_or_deflate_is_unexpected(build, coding):
    body = Chunks([b"anything"])
    script = Script(lambda req: R(200, headers=[(b"content-encoding", coding.encode())],
                                  stream=body))
    client = build(script, retry=FAST)
    exc = expect(H.HttpUnexpectedEncoding, client.get_bytes, NODE_URL)
    assert exc.status == 200 and script.n == 1        # terminal, not retried
    assert body.pulled == 0                           # refused before the body is read


@pytest.mark.parametrize("coding", ["GZIP", " gzip ", "Gzip"])
def test_content_encoding_is_compared_case_insensitively(build, coding):
    script = Script(reply(200, gzip.compress(NASTY), {"Content-Encoding": coding}))
    assert build(script).get_bytes(NODE_URL).body == NASTY


@pytest.mark.parametrize("coding", [None, "identity", "IDENTITY", ""])
def test_no_coding_and_identity_return_the_wire_bytes(build, coding):
    headers = {} if coding is None else {"Content-Encoding": coding}
    script = Script(reply(200, NASTY, headers))
    assert build(script).get_bytes(NODE_URL).body == NASTY


def _raw_deflate(plain):
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    return comp.compress(plain) + comp.flush()


GARBAGE = b"this is not a compressed stream"


@pytest.mark.parametrize("label,wire", [
    pytest.param("gzip", GARBAGE, id="gzip-garbage"),
    pytest.param("deflate", GARBAGE, id="deflate-garbage"),
    pytest.param("deflate", _raw_deflate(b"hello world" * 10), id="raw-deflate-labelled-deflate"),
    pytest.param("gzip", zlib.compress(b"hello"), id="zlib-labelled-gzip"),
    pytest.param("deflate", gzip.compress(b"hello"), id="gzip-labelled-deflate"),
])
def test_a_body_that_does_not_decode_is_malformed_with_the_zlib_error_as_cause(
        build, label, wire):
    script = Script(reply(200, wire, {"Content-Encoding": label}))
    exc = expect(MalformedRegistryResponse, build(script, retry=FAST).get_bytes, NODE_URL)
    assert isinstance(exc.__cause__, zlib.error)
    assert script.n == 1                              # not retried


@pytest.mark.parametrize("label,wire", [
    pytest.param("gzip", gzip.compress(b"hello world" * 50)[:-5], id="gzip-truncated-trailer"),
    pytest.param("gzip", gzip.compress(b"hello world" * 50)[:20], id="gzip-truncated-body"),
    pytest.param("gzip", b"", id="gzip-empty"),
    pytest.param("deflate", zlib.compress(b"hello world" * 50)[:-3], id="deflate-truncated"),
    pytest.param("deflate", b"", id="deflate-empty"),
    pytest.param("gzip", gzip.compress(b"hello") + b"x", id="gzip-trailing-byte"),
    pytest.param("gzip", gzip.compress(b"a") + gzip.compress(b"b"), id="gzip-two-members"),
    pytest.param("deflate", zlib.compress(b"hello") + b"x", id="deflate-trailing-byte"),
])
def test_a_truncated_or_over_long_stream_is_malformed_and_not_retried(build, label, wire):
    script = Script(reply(200, wire, {"Content-Encoding": label}))
    expect(MalformedRegistryResponse, build(script, retry=FAST).get_bytes, NODE_URL)
    assert script.n == 1


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
def test_bytes_after_the_end_of_the_stream_in_a_later_chunk_are_malformed(build, kind):
    wire = _encoded(kind, b"hello")
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind},
                                  stream=Chunks([wire, b"trailing"])))
    expect(MalformedRegistryResponse, build(script, retry=FAST).get_bytes, NODE_URL)
    assert script.n == 1


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
@pytest.mark.parametrize("step", [1, 7, 64])
def test_a_compressed_body_split_into_tiny_chunks_decodes_identically(build, kind, step):
    wire = _encoded(kind, NASTY * 3)
    pieces = [wire[i:i + step] for i in range(0, len(wire), step)]
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind},
                                  stream=Chunks(pieces)))
    got = build(script, max_response_bytes=len(NASTY) * 3).get_bytes(NODE_URL).body
    assert got == NASTY * 3


@pytest.mark.parametrize("kind", ["gzip", "deflate"])
@pytest.mark.parametrize("cap", [2**62, 2**63 - 1, 2**63, 2**64, 2**70, 10**30])
def test_a_client_cap_past_a_c_ssize_t_still_decodes_and_is_never_a_bare_overflow(
        build, kind, cap):
    # zlib takes `max_length` as a C ssize_t: handing it `room + 1` for a cap of 2**63 or more
    # raised OverflowError, outside the typed errors (the cap is operator config, not attacker
    # input, but nothing validates it at construction).
    wire = _encoded(kind, NASTY)
    script = Script(lambda req: R(200, headers={"Content-Encoding": kind},
                                  stream=Chunks([wire[:5], wire[5:]])))
    got = build(script, retry=ONCE, max_response_bytes=cap).get_bytes(NODE_URL).body
    assert got == NASTY


def test_max_bytes_past_a_c_ssize_t_cannot_raise_the_client_cap(build):
    wire = gzip.compress(b"x" * 100)
    script = Script(lambda req: R(200, headers={"Content-Encoding": "gzip"}, content=wire))
    exc = expect(H.HttpError, build(script, retry=ONCE, max_response_bytes=50).get_bytes,
                 NODE_URL, max_bytes=2**70)
    assert "once decoded" in str(exc)


# --------------------------------------------------------------------------- #
# 5. Deadlines
# --------------------------------------------------------------------------- #

def test_a_slow_body_past_the_read_deadline_is_an_error(build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)

    def slow():
        yield b"a"
        fake.now += 11.0                              # past timeout_s=10
        yield b"b"
    script = Script(lambda req: R(200, stream=Chunks(slow())))
    exc = expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL)
    assert script.n == 1 and "deadline" in str(exc)


def test_deadline_s_also_bounds_the_body_read(build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)

    def slow():
        yield b"a"
        fake.now += 5.0                               # inside timeout_s=10, past deadline_s=1
        yield b"b"
    script = Script(lambda req: R(200, stream=Chunks(slow())))
    expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL, deadline_s=1)
    fake.now = 1000.0
    ok = Script(lambda req: R(200, stream=Chunks(slow())))
    assert build(ok, retry=FAST).get_bytes(NODE_URL, deadline_s=60).body == b"ab"


def test_a_retry_after_sleep_is_clamped_to_the_budget_and_the_call_then_fails(
        build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)
    script = Script(reply(503, headers={"Retry-After": "86400"}))
    client = build(script, retry=FAST)
    exc = expect(H.HttpError, client.get_bytes, NODE_URL, deadline_s=2)
    assert "deadline" in str(exc)
    assert fake.sleeps and max(fake.sleeps) <= 2.0
    assert sum(fake.sleeps) <= 2.0
    assert script.n == 1                              # the budget was spent before a second try


def test_a_backoff_sleep_is_clamped_to_the_budget_too(build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)
    policy = H.RetryPolicy(attempts=5, backoff_base_s=8.0, backoff_max_s=8.0)
    script = Script(reply(500))
    expect(H.HttpError, build(script, retry=policy).get_bytes, NODE_URL, deadline_s=1)
    assert fake.sleeps and sum(fake.sleeps) <= 1.0


def test_get_json_is_given_no_overall_budget_so_its_sleeps_are_not_clamped(build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)
    script = Script(reply(503, headers={"Retry-After": "5"}))
    expect(H.HttpTransientExhausted, build(script, retry=FAST).get_json, NODE_URL)
    assert fake.sleeps == [5.0, 5.0] and script.n == 3


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True, "5", [1]])
def test_deadline_s_that_is_not_a_positive_finite_number_is_an_error_before_any_request(
        build, bad):
    script = Script(reply(200, b"x"))
    expect(H.HttpError, build(script).get_bytes, NODE_URL, deadline_s=bad)
    assert script.n == 0


@pytest.mark.parametrize("bad", [10**400, 10**30, 86401, 86400.5, 1e300, 1e308])
def test_deadline_s_above_a_day_or_too_large_to_be_a_float_is_an_http_error_not_an_overflow(
        build, bad):
    # `math.isfinite(10**400)` and `float(10**400)` raise OverflowError; a value that does
    # convert (1e300) would reach `time.sleep` through the clamp and overflow there.
    script = Script(reply(200, b"x"))
    exc = expect(H.HttpError, build(script).get_bytes, NODE_URL, deadline_s=bad)
    assert "deadline_s" in str(exc) and "86400" in str(exc)
    assert script.n == 0


@pytest.mark.parametrize("ok", [1, 0.001, 86400, 86400.0])
def test_deadline_s_up_to_a_day_is_taken(build, ok):
    assert build(Script(reply(200, b"x"))).get_bytes(NODE_URL, deadline_s=ok).body == b"x"


def test_a_day_long_budget_clamps_even_an_infinite_retry_after_to_a_sleepable_time(
        build, monkeypatch):
    # The reason for the ceiling: with the longest budget a sleep is still clamped to a value
    # `time.sleep` takes, whatever the server asks for (a 400-digit Retry-After parses to inf).
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)
    script = Script(reply(503, headers={"Retry-After": "9" * 400}))
    expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL, deadline_s=86400)
    assert fake.sleeps and max(fake.sleeps) <= 86400.0


def test_a_response_that_arrives_after_the_budget_is_refused_at_its_first_body_chunk(
        build, monkeypatch):
    # `deadline_s` does not interrupt the wait for the headers (see the real-socket row
    # below); what it guarantees is that nothing is accepted once the budget is spent.
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)

    def late(request):
        fake.now += 5.0                               # inside timeout_s=10, past deadline_s=1
        return R(200, b"ab")
    script = Script(late)
    exc = expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL, deadline_s=1)
    assert "deadline" in str(exc) and script.n == 1


def test_slow_response_headers_are_not_cut_by_deadline_s_but_the_late_body_is_refused():
    """The limit stated in the docs, pinned over a real loopback socket: the server sends the
    status line and then one header line every 0.1 s (each socket read is far inside
    ``timeout_s``), so ``deadline_s=0.2`` does not end the wait for the headers; the body read
    then refuses the late response. The wait is therefore at least the whole drip."""
    drip, lines = 0.1, 6
    srv = socket.create_server(("127.0.0.1", 0))
    srv.settimeout(15)
    port = srv.getsockname()[1]
    served = []

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(15)
            conn.recv(65536)
            served.append("request")
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            for i in range(lines):
                time.sleep(drip)
                conn.sendall(b"X-Pad-%d: y\r\n" % i)
            conn.sendall(b"Content-Length: 2\r\n\r\nab")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = H.EbsiHttpClient(allowed_hosts={"127.0.0.1"}, timeout_s=5.0, retry=ONCE)
    client._guard_host = lambda url: None             # https-only guard: this is plain loopback
    started = time.perf_counter()
    try:
        exc = expect(H.HttpError, client.get_bytes, f"http://127.0.0.1:{port}/x",
                     deadline_s=0.2)
        elapsed = time.perf_counter() - started
    finally:
        client.close()
        srv.close()
        thread.join(5)
    assert "read exceeded its deadline" in str(exc)
    assert served == ["request"]
    assert elapsed >= drip * lines * 0.9               # the headers were waited for, not cut


# --------------------------------------------------------------------------- #
# 6. Status handling
# --------------------------------------------------------------------------- #

def test_an_unsolicited_304_is_an_error(build):
    script = Script(reply(304, headers={"ETag": '"abc"'}))
    exc = expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL)
    assert exc.status == 304 and script.n == 1


def test_a_404_is_not_found_and_not_retried(build):
    script = Script(reply(404))
    expect(H.HttpNotFound, build(script, retry=FAST).get_bytes, NODE_URL)
    assert script.n == 1


@pytest.mark.parametrize("status", [403, 204, 206, 400, 401, 405, 410, 418, 451])
def test_any_other_status_is_a_plain_error_with_the_body_never_read(build, status):
    firewall = Chunks([b"<html><title>Web Application Firewall</title></html>"])
    script = Script(lambda req: R(status, stream=firewall))
    exc = expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL)
    assert exc.status == status and script.n == 1     # terminal, not retried
    assert firewall.pulled == 0                       # and an error body is never read


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_transient_statuses_are_retried_then_exhausted(build, status):
    script = Script(reply(status))
    expect(H.HttpTransientExhausted, build(script, retry=FAST).get_bytes, NODE_URL)
    assert script.n == FAST.attempts


def test_a_transient_status_then_success_returns_the_body(build):
    script = Script(reply(503), reply(200, b"ok"))
    assert build(script, retry=FAST).get_bytes(NODE_URL).body == b"ok"
    assert script.n == 2


def test_a_transport_error_is_retried_then_exhausted(build):
    script = Script(httpx.ConnectError("boom"))
    expect(H.HttpTransientExhausted, build(script, retry=FAST).get_bytes, NODE_URL)
    assert script.n == FAST.attempts
    again = Script(httpx.ConnectError("boom"), reply(200, b"ok"))
    assert build(again, retry=FAST).get_bytes(NODE_URL).body == b"ok"


def test_an_error_body_that_would_not_decode_is_never_decoded(build):
    # get_json drains an error body (and a corrupt one raised, #248); the bytes path never
    # reads it, so the status decides.
    bad404 = Script(reply(404, b"not gzip", {"Content-Encoding": "gzip"}))
    expect(H.HttpNotFound, build(bad404, retry=FAST).get_bytes, NODE_URL)
    bad500 = Script(lambda req: R(500, headers={"Content-Encoding": "gzip"},
                                  stream=Chunks([b"not gzip"])))
    expect(H.HttpTransientExhausted, build(bad500, retry=FAST).get_bytes, NODE_URL)


# --------------------------------------------------------------------------- #
# 7. ETag in, ETag out
# --------------------------------------------------------------------------- #

BAD_ETAGS = [
    pytest.param("", id="empty"),
    pytest.param("*", id="wildcard"),
    pytest.param('"a b"', id="space"),
    pytest.param('"a\rb"', id="cr"),
    pytest.param('"a\nb"', id="lf"),
    pytest.param('"a\tb"', id="tab"),
    pytest.param('"a\x00b"', id="nul"),
    pytest.param('"a\x7fb"', id="del"),
    pytest.param('"é"', id="non-ascii"),
    pytest.param('"\ud800"', id="lone-surrogate"),
    pytest.param("x" * 257, id="257-chars"),
    pytest.param('"abc"\n', id="trailing-newline"),
    pytest.param(5, id="int"),
    pytest.param(b'"abc"', id="bytes"),
    pytest.param(["abc"], id="list"),
]


@pytest.mark.parametrize("bad", BAD_ETAGS)
def test_a_supplied_etag_that_is_not_a_plausible_validator_is_refused_before_any_request(
        build, bad):
    script = Script(reply(304))
    expect(H.HttpError, build(script, retry=FAST).get_bytes, NODE_URL, etag=bad)
    assert script.n == 0


@pytest.mark.parametrize("etag", ['"abc"', 'W/"abc"', "x" * 256, "!", "~", "abc", '"a,b"'])
def test_a_supplied_etag_is_sent_verbatim_and_a_304_returns_it(build, etag):
    script = Script(reply(304, headers={"ETag": '"somethingelse"'}))
    got = build(script, retry=FAST).get_bytes(NODE_URL, etag=etag)
    assert script.requests[0].headers["if-none-match"] == etag
    assert got == H.BytesResponse(None, etag)         # the one sent, not the one on the 304
    assert got.not_modified is True and got.body is None


def test_if_none_match_is_absent_when_no_etag_was_given(build):
    script = Script(reply(200, b"x"))
    build(script).get_bytes(NODE_URL)
    assert "if-none-match" not in script.requests[0].headers


def test_a_200_to_a_conditional_request_returns_the_new_body_and_etag(build):
    script = Script(reply(200, b"fresh", {"ETag": 'W/"new"'}))
    got = build(script).get_bytes(NODE_URL, etag='"old"')
    assert got == H.BytesResponse(b"fresh", 'W/"new"') and got.not_modified is False


@pytest.mark.parametrize("received", [
    pytest.param("", id="empty"),
    pytest.param("*", id="wildcard"),
    pytest.param('"a b"', id="space"),
    pytest.param('"a",  "b"', id="two-validators-joined"),
    pytest.param("x" * 257, id="257-chars"),
])
def test_a_received_etag_that_is_not_plausible_is_dropped_and_the_body_kept(build, received):
    script = Script(reply(200, NASTY, {"ETag": received}))
    got = build(script).get_bytes(NODE_URL)
    assert got.etag is None and got.body == NASTY


def test_a_received_etag_with_non_ascii_bytes_is_dropped_and_the_body_kept(build):
    script = Script(lambda req: R(200, NASTY, headers=[(b"etag", b'"caf\xe9"')]))
    got = build(script).get_bytes(NODE_URL)
    assert got.etag is None and got.body == NASTY


def test_a_strong_and_a_weak_received_etag_are_kept_verbatim(build):
    for value in ('"abc"', 'W/"abc"', "x" * 256):
        script = Script(reply(200, b"x", {"ETag": value}))
        assert build(script).get_bytes(NODE_URL).etag == value


def test_no_etag_header_is_etag_none(build):
    got = build(Script(reply(200, b"x"))).get_bytes(NODE_URL)
    assert got.etag is None and got.body == b"x"


# --------------------------------------------------------------------------- #
# 8. Positives: byte-exact bodies, headers, no state
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("coding", [None, "identity", "gzip", "deflate"])
def test_the_body_comes_back_byte_for_byte(build, coding):
    headers = {} if coding is None else {"Content-Encoding": coding}
    wire = {"gzip": gzip.compress, "deflate": zlib.compress}.get(coding, lambda b: b)(NASTY)
    got = build(Script(reply(200, wire, headers))).get_bytes(NODE_URL).body
    assert type(got) is bytes
    assert sha(got) == sha(NASTY)


def test_an_empty_200_is_empty_bytes_and_judging_it_is_the_verifiers_job(build):
    got = build(Script(reply(200, b""))).get_bytes(NODE_URL)
    assert got.body == b"" and got.not_modified is False


def test_get_bytes_sends_its_own_accept_headers_and_the_clients_user_agent(build):
    script = Script(reply(200, b"x"))
    build(script).get_bytes(NODE_URL)
    sent = script.requests[0].headers
    assert sent["accept"] == "*/*"
    assert sent["accept-encoding"] == "identity"
    assert sent["user-agent"] == f"openvc-core/{__version__}"
    assert "cookie" not in sent and "authorization" not in sent


def test_get_json_keeps_its_own_default_headers(build):
    script = Script(reply(200, b'{"ok": 1}'))
    build(script).get_json(NODE_URL)
    sent = script.requests[0].headers
    assert sent["accept"] == "application/json, application/did+ld+json, */*;q=0.1"
    assert sent["user-agent"] == f"openvc-core/{__version__}"
    assert "if-none-match" not in sent


class _SpyCache(TtlCache):
    def __init__(self):
        super().__init__(ttl_s=300)
        self.touched = []

    def get(self, key):
        self.touched.append(("get", key))
        return super().get(key)

    def set(self, key, value):
        self.touched.append(("set", key))
        super().set(key, value)


def test_get_bytes_never_touches_the_cache_and_get_json_is_unaffected(build):
    cache = _SpyCache()
    script = Script(reply(200, b'{"a": 1}'))
    client = build(script, cache=cache, retry=FAST)
    assert client.get_bytes(NODE_URL).body == b'{"a": 1}'
    assert cache.touched == []                        # no read, no write
    assert client.get_json(NODE_URL) == {"a": 1}      # a real fetch, not a cached byte string
    assert script.n == 2
    assert cache.touched == [("get", NODE_URL), ("set", NODE_URL)]


def test_get_bytes_does_not_read_what_get_json_cached(build):
    script = Script(reply(200, b'{"a": 1}'))
    client = build(script, retry=FAST)
    assert client.get_json(NODE_URL) == {"a": 1}
    assert client.get_json(NODE_URL) == {"a": 1} and script.n == 1       # cached
    assert client.get_bytes(NODE_URL).body == b'{"a": 1}'
    assert script.n == 2                              # get_bytes asked the server


def test_get_json_still_refuses_a_forbidden_url_that_a_shared_cache_holds(build):
    # The guard runs before the cache lookup: `cache=` can be shared between clients with
    # different allow-lists, and a hit must not bypass the guard.
    cache = TtlCache(ttl_s=300)
    cache.set("https://evil.example/x", {"leak": True})
    script = Script(reply(200, b'{"ok": 1}'))
    expect(H.HttpForbiddenHost, build(script, cache=cache).get_json, "https://evil.example/x")
    assert script.n == 0


@pytest.mark.parametrize("method", ["get_json", "get_bytes"])
def test_the_real_constructor_does_not_follow_redirects(build, method):
    script = Script(reply(302, headers={"Location": f"https://{NODE}/other"}),
                    reply(200, b'{"ok": 1}'))
    expect(H.HttpError, getattr(build(script, retry=FAST), method), NODE_URL)
    assert script.urls == [NODE_URL]


# --------------------------------------------------------------------------- #
# 9. get_tnl_files
# --------------------------------------------------------------------------- #

LIST_FILES = ["trusted-keys.json", "trusted-keys.json.sig", "tnl.json", "tnl.json.sig"]


def _list_body(request):
    name = request.url.path.lstrip("/")
    return R(200, f"bytes of {name}\n".encode(), {"ETag": f'"etag-of-{name}"'})


def test_the_helper_fetches_the_four_files_in_order_and_nothing_else(build):
    script = Script(_list_body)
    got = H.get_tnl_files(tnl_client(build, script, retry=FAST))
    assert script.urls == [f"https://tnl.ebsi.eu/{n}" for n in LIST_FILES]
    assert not any("keylist-key" in u for u in script.urls)
    assert list(got) == LIST_FILES == list(H.TNL_FILES)
    for name in LIST_FILES:
        assert got[name] == H.BytesResponse(f"bytes of {name}\n".encode(), f'"etag-of-{name}"')


def test_the_helper_never_names_the_pinned_key():
    assert "keylist-key.asc" not in H.TNL_FILES
    assert all("asc" not in name for name in H.TNL_FILES)
    assert set(H.TNL_MAX_BYTES) == set(H.TNL_FILES)
    with pytest.raises(TypeError):
        H.TNL_MAX_BYTES["tnl.json"] = 10 ** 9         # the caps are not a mutable global


def test_each_request_carries_the_fixed_headers_and_no_credentials(build):
    script = Script(_list_body)
    H.get_tnl_files(tnl_client(build, script, retry=FAST))
    assert script.n == 4
    for request in script.requests:
        assert request.headers["accept"] == "*/*"
        assert request.headers["accept-encoding"] == "identity"
        assert request.headers["user-agent"] == f"openvc-core/{__version__}"
        assert "cookie" not in request.headers
        assert "authorization" not in request.headers
        assert "if-none-match" not in request.headers
        assert request.method == "GET"


def test_the_tnl_client_keeps_no_cookie(build):
    script = Script(reply(200, b"x", {"Set-Cookie": "SRV_ID=abc123; Path=/; Secure; HttpOnly"}))
    client = tnl_client(build, script, retry=FAST)
    H.get_tnl_files(client)
    assert script.n == 4
    assert all("cookie" not in r.headers for r in script.requests)
    assert len(client._client.cookies.jar) == 0       # nothing the server set was stored


def test_conditional_requests_per_file_and_a_304_maps_to_the_etag_that_was_sent(build):
    etags = {"tnl.json": '"v4"', "trusted-keys.json": 'W/"k1"'}

    def handler(request):
        name = request.url.path.lstrip("/")
        sent = request.headers.get("if-none-match")
        if sent is not None and sent == etags.get(name):
            return R(304, headers={"ETag": etags[name]})
        return _list_body(request)
    script = Script(handler)
    got = H.get_tnl_files(tnl_client(build, script, retry=FAST), etags=etags)
    assert got["tnl.json"] == H.BytesResponse(None, '"v4"')
    assert got["trusted-keys.json"] == H.BytesResponse(None, 'W/"k1"')
    assert got["tnl.json.sig"].body == b"bytes of tnl.json.sig\n"
    assert got["trusted-keys.json.sig"].not_modified is False
    sent = {r.url.path.lstrip("/"): r.headers.get("if-none-match") for r in script.requests}
    assert sent == {"trusted-keys.json": 'W/"k1"', "trusted-keys.json.sig": None,
                    "tnl.json": '"v4"', "tnl.json.sig": None}


@pytest.mark.parametrize("etags", [
    pytest.param({"keylist-key.asc": '"x"'}, id="the-pinned-key"),
    pytest.param({"tnl.jsn": '"x"'}, id="typo"),
    pytest.param({"TNL.JSON": '"x"'}, id="case"),
    pytest.param({"tnl.json": '"x"', "other": '"y"'}, id="one-good-one-unknown"),
    pytest.param({"tnl.json": "bad etag"}, id="invalid-value"),
    pytest.param({"tnl.json": 5}, id="non-str-value"),
    pytest.param({"tnl.json": '"x"', "tnl.json.sig": ""}, id="second-value-invalid"),
    pytest.param([("tnl.json", '"x"')], id="not-a-mapping"),
])
def test_bad_etags_are_refused_before_any_request(build, etags):
    script = Script(_list_body)
    expect(H.HttpError, H.get_tnl_files, tnl_client(build, script), etags=etags)
    assert script.n == 0


def test_the_helper_is_all_or_nothing_and_names_the_file(build):
    def handler(request):
        if request.url.path == "/trusted-keys.json.sig":
            return R(404)
        return _list_body(request)
    script = Script(handler)
    exc = expect(H.HttpNotFound, H.get_tnl_files, tnl_client(build, script, retry=FAST))
    assert "trusted-keys.json.sig" in str(exc)
    assert exc.url == "https://tnl.ebsi.eu/trusted-keys.json.sig"
    assert script.n == 2                              # the third file was never asked for


@pytest.mark.parametrize("status,cls", [
    (403, "HttpError"), (301, "HttpError"), (304, "HttpError"), (503, "HttpTransientExhausted")])
def test_a_failure_on_the_last_file_keeps_its_class_and_returns_nothing(build, status, cls):
    def handler(request):
        if request.url.path == "/tnl.json.sig":
            return R(status, headers={"Location": "https://evil.example/"})
        return _list_body(request)
    script = Script(handler)
    exc = expect(getattr(H, cls), H.get_tnl_files, tnl_client(build, script, retry=FAST))
    assert "tnl.json.sig" in str(exc)


def test_a_body_over_the_per_file_cap_is_refused_and_names_the_file(build):
    def handler(request):
        if request.url.path == "/tnl.json.sig":
            return R(200, b"x" * (4 * 1024 + 1))
        return _list_body(request)
    exc = expect(H.HttpError, H.get_tnl_files, tnl_client(build, Script(handler), retry=FAST))
    assert "tnl.json.sig" in str(exc) and exc.status == 200


def test_the_list_json_files_may_be_larger_than_the_signature_files(build):
    def handler(request):
        size = 64 * 1024 if request.url.path.endswith(".json") else 4 * 1024
        return R(200, b"x" * size)
    got = H.get_tnl_files(tnl_client(build, Script(handler), retry=FAST))
    assert {n: len(r.body) for n, r in got.items()} == {
        "trusted-keys.json": 65536, "trusted-keys.json.sig": 4096,
        "tnl.json": 65536, "tnl.json.sig": 4096}


def test_the_deadline_is_shared_by_the_four_requests(build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)

    def handler(request):
        fake.now += 4.0                               # each request takes four "seconds"
        return _list_body(request)
    script = Script(handler)
    exc = expect(H.HttpError, H.get_tnl_files, tnl_client(build, script, retry=FAST),
                 deadline_s=10)
    assert "deadline" in str(exc) and "tnl.json" in str(exc)
    assert script.n == 3                              # the fourth never started


def test_a_budget_spent_exactly_between_two_files_stops_before_the_next_request(
        build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)

    def handler(request):
        fake.now += 5.0                               # two requests spend the whole budget
        return _list_body(request)
    script = Script(handler)
    exc = expect(H.HttpError, H.get_tnl_files, tnl_client(build, script, retry=FAST),
                 deadline_s=10)
    assert "tnl.json" in str(exc) and "deadline" in str(exc)
    assert exc.url == "https://tnl.ebsi.eu/tnl.json"
    assert script.n == 2                              # the third was never sent


def test_a_slow_503_storm_cannot_outlast_the_helpers_deadline(build, monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(H, "time", fake)
    script = Script(reply(503, headers={"Retry-After": "86400"}))
    expect(H.HttpError, H.get_tnl_files, tnl_client(build, script, retry=FAST), deadline_s=5)
    assert fake.sleeps and sum(fake.sleeps) <= 5.0


@pytest.mark.parametrize(
    "bad", [0, -3, float("nan"), float("inf"), True, "30", 10**400, 86401, 1e300])
def test_the_helpers_deadline_must_be_positive_finite_and_at_most_a_day(build, bad):
    script = Script(_list_body)
    expect(H.HttpError, H.get_tnl_files, tnl_client(build, script), deadline_s=bad)
    assert script.n == 0


def test_without_a_client_the_helper_builds_a_tnl_client_and_closes_it(monkeypatch):
    real = httpx.Client
    made = []
    script = Script(_list_body)

    def patched(**kw):
        inner = real(transport=httpx.MockTransport(script), **kw)
        made.append(inner)
        return inner
    monkeypatch.setattr(httpx, "Client", patched)
    got = H.get_tnl_files()
    assert list(got) == LIST_FILES and script.n == 4
    assert len(made) == 1 and made[0].is_closed
    assert script.requests[0].headers["user-agent"] == f"openvc-core/{__version__}"


def test_the_helper_does_not_poll_or_persist(build):
    script = Script(_list_body)
    client = tnl_client(build, script, retry=FAST)
    H.get_tnl_files(client)
    assert script.n == 4                              # one round trip per file per call
    H.get_tnl_files(client)
    assert script.n == 8                              # nothing is cached between calls


# --------------------------------------------------------------------------- #
# 10. Replay of the recorded tnl.ebsi.eu headers (tests/fixtures/ebsi/tnl_response_headers.json)
# --------------------------------------------------------------------------- #

def _recorded():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_the_recording_settles_the_four_questions_of_the_issue():
    rec = _recorded()
    assert rec["recording"]["host"] == "tnl.ebsi.eu"
    assert rec["recording"]["requests"] == 8
    assert rec["recording"]["tls_verification"] is True
    assert rec["recording"]["redirects_followed"] is False
    assert rec["recording"]["request_headers"]["User-Agent"].startswith("openvc-core/")
    assert list(rec["unconditional"]) == LIST_FILES == list(rec["conditional"])
    for name in LIST_FILES:
        first, second = rec["unconditional"][name], rec["conditional"][name]
        # 1. the client's own User-Agent is served on all four
        assert first["status"] == 200
        # 2. Accept-Encoding: identity yields no Content-Encoding
        assert "content-encoding" not in first["headers"]
        # 3. every file has an ETag, and it is strong
        etag = first["headers"]["etag"]
        assert etag.startswith('"') and not etag.startswith("W/")
        # 4. If-None-Match with that ETag yields a 304, which carries no content
        assert second["status"] == 304
        assert second["headers"]["etag"] == etag
        assert second["body_length"] is None and "content-length" not in second["headers"]
        assert first["set_cookie_present"] is False


def test_the_recorded_header_sets_replay_through_the_helper(build):
    rec = _recorded()
    seen = []

    def handler(request):
        name = request.url.path.lstrip("/")
        conditional = request.headers.get("if-none-match")
        seen.append((name, conditional))
        first = rec["unconditional"][name]
        if conditional is not None:
            assert conditional == first["headers"]["etag"]
            second = rec["conditional"][name]
            return R(second["status"], headers=second["headers"])
        return R(first["status"], b"\x00" * first["body_length"], first["headers"])
    client = tnl_client(build, Script(handler), retry=FAST)

    first = H.get_tnl_files(client)
    assert {n: len(r.body) for n, r in first.items()} == {
        n: rec["unconditional"][n]["body_length"] for n in LIST_FILES}
    assert {n: r.etag for n, r in first.items()} == {
        n: rec["unconditional"][n]["headers"]["etag"] for n in LIST_FILES}

    second = H.get_tnl_files(client, etags={n: r.etag for n, r in first.items()})
    assert all(r.not_modified for r in second.values())
    assert {n: r.etag for n, r in second.items()} == {n: r.etag for n, r in first.items()}
    assert [c for _, c in seen[:4]] == [None] * 4 and all(c for _, c in seen[4:])


# --------------------------------------------------------------------------- #
# 11. Fuzzing (the bytes handed to zlib, and the header values, are attacker-influenced)
# --------------------------------------------------------------------------- #

_FUZZ = {}


def _fuzz_call(make_response, **kwargs):
    """get_bytes against one shared client (building a client per example would cost more
    than the example) whose next response is ``make_response()``."""
    if "client" not in _FUZZ:
        client = H.EbsiHttpClient(allowed_hosts={NODE}, retry=ONCE)
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(
            lambda req: _FUZZ["next"](req)))
        _FUZZ["client"] = client
        _FUZZ["sent"] = []
    _FUZZ["sent"].clear()

    def reply_once(request):
        _FUZZ["sent"].append(request)
        return make_response()
    _FUZZ["next"] = reply_once
    try:
        return _FUZZ["client"].get_bytes(NODE_URL, **kwargs)
    except OpenvcError as exc:
        return exc


def _oracle(label, wire, cap):
    """What a whole-buffer decode says: the plain bytes if the stream is complete, exact and
    within the cap (on the wire and decoded), else None."""
    if len(wire) > cap:
        return None
    d = zlib.decompressobj(31 if label == "gzip" else 15)
    try:
        out = d.decompress(wire)
    except zlib.error:
        return None
    if not d.eof or d.unused_data or len(out) > cap:
        return None
    return out


@settings(max_examples=300, deadline=None)
@given(wire=st.binary(max_size=300), label=st.sampled_from(["gzip", "deflate"]),
       cap=st.integers(0, 400))
def test_fuzz_arbitrary_bytes_under_a_coding_decode_exactly_or_fail_typed(wire, label, cap):
    got = _fuzz_call(lambda: R(200, wire, {"Content-Encoding": label}), max_bytes=cap)
    expected = _oracle(label, wire, cap)
    if expected is None:
        assert isinstance(got, OpenvcError), got
    else:
        assert got.body == expected


@settings(max_examples=300, deadline=None)
@given(plain=st.binary(max_size=1500), label=st.sampled_from(["gzip", "deflate"]),
       cap=st.integers(0, 1600), step=st.integers(1, 90),
       damage=st.sampled_from(["none", "truncate", "append", "flip"]),
       where=st.integers(0, 10_000), junk=st.binary(min_size=1, max_size=8))
def test_fuzz_valid_and_damaged_streams_in_any_chunking_match_a_whole_buffer_decode(
        plain, label, cap, step, damage, where, junk):
    wire = gzip.compress(plain) if label == "gzip" else zlib.compress(plain)
    if damage == "truncate":
        wire = wire[:where % (len(wire) + 1)]
    elif damage == "append":
        wire = wire + junk
    elif damage == "flip" and wire:
        i = where % len(wire)
        wire = wire[:i] + bytes([wire[i] ^ 0x5A]) + wire[i + 1:]
    pieces = [wire[i:i + step] for i in range(0, len(wire), step)]
    got = _fuzz_call(lambda: R(200, headers={"Content-Encoding": label}, stream=Chunks(pieces)),
                     max_bytes=cap)
    expected = _oracle(label, wire, cap)
    if expected is None:
        assert isinstance(got, OpenvcError), got
    else:
        assert got.body == expected


@settings(max_examples=300, deadline=None)
@given(coding=st.binary(max_size=24))
def test_fuzz_content_encoding_values_give_a_body_or_a_typed_error(coding):
    got = _fuzz_call(lambda: R(200, b"plain body", [(b"content-encoding", coding)]))
    if isinstance(got, OpenvcError):
        assert type(got) is H.HttpUnexpectedEncoding or type(got) is MalformedRegistryResponse
    else:
        assert got.body == b"plain body"                         # identity or empty


_PLAUSIBLE = re.compile(r"[\x21-\x7e]{1,256}")


@settings(max_examples=300, deadline=None)
@given(raw=st.binary(max_size=40))
def test_fuzz_a_received_etag_is_kept_only_if_plausible_and_never_costs_the_body(raw):
    got = _fuzz_call(lambda: R(200, NASTY, [(b"etag", raw)]))
    assert got.body == NASTY
    if got.etag is not None:
        assert _PLAUSIBLE.fullmatch(got.etag) and got.etag != "*"


_ETAG_TEXT = st.one_of(
    st.text(max_size=12),
    st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7e), max_size=300),
    st.text(alphabet=st.characters(exclude_categories=()), max_size=6),
)


@settings(max_examples=300, deadline=None)
@given(etag=st.one_of(_ETAG_TEXT, st.integers(), st.binary(max_size=8), st.floats()))
def test_fuzz_a_supplied_etag_is_an_http_error_or_sent_verbatim(etag):
    got = _fuzz_call(lambda: R(304), etag=etag)
    sent = _FUZZ["sent"]
    usable = isinstance(etag, str) and _PLAUSIBLE.fullmatch(etag) and etag != "*"
    if usable:
        assert got == H.BytesResponse(None, etag)
        assert sent[0].headers["if-none-match"] == etag
    else:
        assert type(got) is H.HttpError, got
        assert sent == []                                        # refused before any I/O
