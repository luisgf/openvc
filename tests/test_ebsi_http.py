"""
tests/test_ebsi_http.py — EBSI HTTP client resource limits (#103).

Offline (httpx.MockTransport) coverage for the response-size cap and the Retry-After
parsing added in the uniform-resource-limits pass. The wall-clock deadline shares the
same streamed read path; a drip test would be timing-flaky, so it is left to the read
loop's logic and the size-cap test here.
"""
from __future__ import annotations

import json
import zlib
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

httpx = pytest.importorskip("httpx")

import openvc_ebsi.http as ebsi_http  # noqa: E402
from openvc.errors import OpenvcError  # noqa: E402
from openvc_ebsi.errors import (  # noqa: E402
    MalformedRegistryResponse,
    NodeClientConfigError,
    NodeListExpired,
)
from openvc_ebsi.http import (  # noqa: E402
    EbsiHttpClient,
    HttpError,
    HttpForbiddenHost,
    HttpNotFound,
    HttpTransientExhausted,
    ProbeResponse,
    RetryPolicy,
    _parse_retry_after,
)

HOST = "api-pilot.ebsi.eu"
URL = f"https://{HOST}/x"

# Zero backoff so the retry-loop tests do not sleep.
FAST_RETRY = RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)


def _client(handler, **kwargs):
    c = EbsiHttpClient(allowed_hosts={HOST}, **kwargs)
    c._client = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def test_response_over_the_cap_fails_closed():
    big = b'{"a":"' + b"0" * 10_000 + b'"}'
    c = _client(lambda req: httpx.Response(200, content=big), max_response_bytes=1024)
    with pytest.raises(HttpError):
        c.get_json(URL)


def test_response_under_the_cap_is_returned():
    c = _client(lambda req: httpx.Response(200, json={"ok": True}), max_response_bytes=1024)
    assert c.get_json(URL) == {"ok": True}


def test_parse_retry_after_delta_seconds_and_http_date():
    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("not-a-date") is None
    # the HTTP-date form (RFC 9110 §10.2.3) is now honoured, not silently dropped
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30))
    secs = _parse_retry_after(future)
    assert secs is not None and 0 < secs <= 31
    past = format_datetime(datetime.now(timezone.utc) - timedelta(seconds=30))
    assert _parse_retry_after(past) == 0.0        # never negative


# --- retry / backoff (offline, via MockTransport) ------------------------------ #

def _sequence(*responses):
    """A handler that returns each response in turn (last one repeats)."""
    calls = {"n": 0}

    def handler(request):
        i = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        return responses[i]
    return handler, calls


def test_retries_a_transient_500_then_succeeds():
    handler, calls = _sequence(httpx.Response(500), httpx.Response(200, json={"ok": 1}))
    c = _client(handler, retry=FAST_RETRY)
    assert c.get_json(URL) == {"ok": 1}
    assert calls["n"] == 2                       # one retry after the 500


def test_persistent_5xx_exhausts_retries():
    handler, calls = _sequence(httpx.Response(503))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpTransientExhausted):
        c.get_json(URL)
    assert calls["n"] == FAST_RETRY.attempts      # tried the full budget


def test_404_maps_to_not_found_without_retry():
    handler, calls = _sequence(httpx.Response(404))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpNotFound):
        c.get_json(URL)
    assert calls["n"] == 1                        # 404 is terminal, not retried


def test_unexpected_status_is_typed_http_error():
    c = _client(lambda req: httpx.Response(403), retry=FAST_RETRY)
    with pytest.raises(HttpError):
        c.get_json(URL)


def test_retry_after_header_is_honoured_on_transient():
    # a 429 carrying Retry-After: 0 then a 200 — the delta-seconds path is exercised offline
    handler, _ = _sequence(
        httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json={"ok": 2}))
    c = _client(handler, retry=FAST_RETRY)
    assert c.get_json(URL) == {"ok": 2}


# --- a URL either parser cannot read (#246) -------------------------------------- #
# `_guard_host` checks a URL with urlparse; httpx fetches it. urlsplit drops a tab or
# newline and ignores other control characters, which httpx rejects with a bare
# `httpx.InvalidURL` (not a TransportError). Each shape is now refused by the guard
# itself — not left to the `InvalidURL` backstop — before any request.

UNREADABLE_URLS = [
    pytest.param(f"https://{HOST}/x\ty", id="tab"),
    pytest.param(f"https://{HOST}/x\x00y", id="nul"),
    pytest.param(f"https://{HOST}/x\x7fy", id="del"),
    pytest.param(f" https://{HOST}/x", id="leading-space"),
    pytest.param(f"https://{HOST}/x/é", id="non-ascii"),
    pytest.param("https://[::1/x", id="broken-ipv6"),
    pytest.param(f"https://{HOST}:99999/x", id="port-out-of-range"),  # httpx parses it
    pytest.param(f"https://{HOST}:abc/x", id="port-not-numeric"),
]


@pytest.mark.parametrize("bad", UNREADABLE_URLS)
def test_unreadable_url_is_refused_typed_before_any_request(bad):
    handler, calls = _sequence(httpx.Response(200, json={"ok": True}))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost) as exc_info:
        c.get_json(bad)
    assert not isinstance(exc_info.value.__cause__, httpx.InvalidURL)   # the guard, not httpx
    assert calls["n"] == 0                        # refused before the transport


def test_guard_refuses_non_ascii_before_urlparse(monkeypatch):
    # On CPython <= 3.12 urlparse NFKC-normalizes a non-ASCII netloc in quadratic time,
    # and nothing bounds a URL before the guard (a status-list URL via `extra_hosts`).
    from openvc_ebsi import _url

    def no_urlparse(url):
        raise AssertionError("urlparse reached")
    monkeypatch.setattr(_url, "urlparse", no_urlparse)   # the one reader, shared with the pin
    c = _client(lambda req: httpx.Response(200, json={}), retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost):
        c.get_json(f"https://{HOST}́/x")


def test_invalid_url_from_httpx_is_mapped_typed_and_not_retried():
    # The backstop: a URL urlparse accepts but httpx rejects. Over httpx's 64 KiB limit
    # passes `_guard_host`, so this exercises the `httpx.InvalidURL` mapping itself.
    handler, calls = _sequence(httpx.Response(200, json={"ok": True}))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost) as exc_info:
        c.get_json(f"https://{HOST}/" + "a" * 70_000)
    assert isinstance(exc_info.value.__cause__, httpx.InvalidURL)
    assert calls["n"] == 0


# --- a body httpx cannot decode (#248) -------------------------------------------- #
# httpx decompresses while streaming; a corrupt gzip/deflate body raised a bare
# `httpx.DecodingError` (not a TransportError) from the capped read or the error drain.

@pytest.mark.parametrize("status", [200, 404, 500])
@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_corrupt_compressed_body_is_typed_and_not_retried(status, encoding):
    handler, calls = _sequence(httpx.Response(
        status, headers={"Content-Encoding": encoding},
        stream=httpx.ByteStream(b"not compressed")))   # content= would decode eagerly
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(MalformedRegistryResponse) as exc_info:
        c.get_json(URL)
    # A 200 body is decoded by the bounded reader (zlib, #335); an error body still by httpx.
    expected = zlib.error if status == 200 else httpx.DecodingError
    assert isinstance(exc_info.value.__cause__, expected)
    assert calls["n"] == 1                        # terminal, not retried


# --- the same rows against get_bytes (#320) --------------------------------------- #
# `get_json` and `get_bytes` run one request loop (`_request`), so the guard, retry,
# not-found and typed-error behaviour above holds for both, with the same EXACT classes.
# A mocked 200 body is a stream, as a socket delivers it: `get_bytes` reads it raw, whereas
# `httpx.Response(content=...)` has already decoded it and marked the stream consumed.
# The bytes-only rows (decode bound, ETag, redirects, the tnl.ebsi.eu helper) are in
# test_ebsi_http_bytes.py.

READERS = ["get_json", "get_bytes"]


def _resp(status, body=b"", headers=None):
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


def _play(*steps):
    """A handler that plays each step in turn (the last repeats) and counts the requests.
    A step is an exception to raise or a function building the response."""
    calls = {"n": 0}

    def handler(request):
        step = steps[min(calls["n"], len(steps) - 1)]
        calls["n"] += 1
        if isinstance(step, Exception):
            raise step
        return step(request)
    return handler, calls


def _read(client, method, url):
    out = getattr(client, method)(url)
    return out if method == "get_json" else json.loads(out.body)


OK_BODY = json.dumps({"ok": 1}).encode()


def _ok(request):
    return _resp(200, OK_BODY)


@pytest.mark.parametrize("method", READERS)
@pytest.mark.parametrize("bad", UNREADABLE_URLS)
def test_parity_unreadable_url_is_refused_typed_before_any_request(method, bad):
    handler, calls = _play(_ok)
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost) as exc_info:
        getattr(c, method)(bad)
    assert type(exc_info.value) is HttpForbiddenHost
    assert not isinstance(exc_info.value.__cause__, httpx.InvalidURL)   # the guard, not httpx
    assert calls["n"] == 0


@pytest.mark.parametrize("method", READERS)
@pytest.mark.parametrize("url", [
    pytest.param("http://api-pilot.ebsi.eu/x", id="not-https"),
    pytest.param("https://api.ebsi.iti.gr/x", id="other-host"),
    pytest.param("https://api-pilot.ebsi.eu.example/x", id="suffix-lookalike"),
    pytest.param("https://api-pilot.ebsi.eu@api.ebsi.iti.gr/x", id="userinfo-lookalike"),
])
def test_parity_a_url_off_the_allow_list_is_refused_before_any_request(method, url):
    handler, calls = _play(_ok)
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost) as exc_info:
        getattr(c, method)(url)
    assert type(exc_info.value) is HttpForbiddenHost
    assert calls["n"] == 0


@pytest.mark.parametrize("method", READERS)
def test_parity_guard_refuses_non_ascii_before_urlparse(monkeypatch, method):
    from openvc_ebsi import _url

    def no_urlparse(url):
        raise AssertionError("urlparse reached")
    monkeypatch.setattr(_url, "urlparse", no_urlparse)   # the one reader, shared with the pin
    c = _client(_play(_ok)[0], retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost):
        getattr(c, method)(f"https://{HOST}́/x")


@pytest.mark.parametrize("method", READERS)
def test_parity_invalid_url_from_httpx_is_mapped_typed_and_not_retried(method):
    handler, calls = _play(_ok)
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpForbiddenHost) as exc_info:
        getattr(c, method)(f"https://{HOST}/" + "a" * 70_000)
    assert type(exc_info.value) is HttpForbiddenHost
    assert isinstance(exc_info.value.__cause__, httpx.InvalidURL)
    assert calls["n"] == 0


@pytest.mark.parametrize("method", READERS)
def test_parity_retries_a_transient_500_then_succeeds(method):
    handler, calls = _play(lambda r: _resp(500), _ok)
    c = _client(handler, retry=FAST_RETRY)
    assert _read(c, method, URL) == {"ok": 1}
    assert calls["n"] == 2


@pytest.mark.parametrize("method", READERS)
def test_parity_a_transport_error_is_retried(method):
    handler, calls = _play(httpx.ConnectError("boom"), _ok)
    c = _client(handler, retry=FAST_RETRY)
    assert _read(c, method, URL) == {"ok": 1}
    assert calls["n"] == 2


@pytest.mark.parametrize("status", [429, 500, 503])
@pytest.mark.parametrize("method", READERS)
def test_parity_persistent_transient_status_exhausts_retries(method, status):
    handler, calls = _play(lambda r: _resp(status))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpTransientExhausted) as exc_info:
        getattr(c, method)(URL)
    assert type(exc_info.value) is HttpTransientExhausted
    assert calls["n"] == FAST_RETRY.attempts


@pytest.mark.parametrize("method", READERS)
def test_parity_404_maps_to_not_found_without_retry(method):
    handler, calls = _play(lambda r: _resp(404))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpNotFound) as exc_info:
        getattr(c, method)(URL)
    assert type(exc_info.value) is HttpNotFound
    assert calls["n"] == 1


@pytest.mark.parametrize("status", [403, 304, 301, 204, 206])
@pytest.mark.parametrize("method", READERS)
def test_parity_unexpected_status_is_typed_http_error_and_not_retried(method, status):
    handler, calls = _play(lambda r: _resp(status))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(HttpError) as exc_info:
        getattr(c, method)(URL)
    assert type(exc_info.value) is HttpError
    assert exc_info.value.status == status
    assert calls["n"] == 1


@pytest.mark.parametrize("method", READERS)
def test_parity_retry_after_header_is_honoured_on_transient(method):
    handler, calls = _play(lambda r: _resp(429, headers={"Retry-After": "0"}), _ok)
    c = _client(handler, retry=FAST_RETRY)
    assert _read(c, method, URL) == {"ok": 1}
    assert calls["n"] == 2


@pytest.mark.parametrize("method", READERS)
def test_parity_response_over_the_cap_fails_closed(method):
    big = b'{"a":"' + b"0" * 10_000 + b'"}'
    handler, calls = _play(lambda r: _resp(200, big))
    c = _client(handler, max_response_bytes=1024, retry=FAST_RETRY)
    with pytest.raises(HttpError) as exc_info:
        getattr(c, method)(URL)
    assert type(exc_info.value) is HttpError
    assert exc_info.value.status == 200 and calls["n"] == 1


@pytest.mark.parametrize("method", READERS)
def test_parity_response_under_the_cap_is_returned(method):
    handler, _ = _play(_ok)
    c = _client(handler, max_response_bytes=1024)
    assert _read(c, method, URL) == {"ok": 1}


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
@pytest.mark.parametrize("method", READERS)
def test_parity_corrupt_compressed_200_is_typed_and_not_retried(method, encoding):
    handler, calls = _play(lambda r: _resp(
        200, b"not compressed", headers={"Content-Encoding": encoding}))
    c = _client(handler, retry=FAST_RETRY)
    with pytest.raises(MalformedRegistryResponse) as exc_info:
        getattr(c, method)(URL)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert exc_info.value.__cause__ is not None
    assert calls["n"] == 1


# --- the lifetime gate: valid_until + clock (#324, ADR-0009 D5) ----------------------- #
# A client built from a verified node list stops at the list's `expires`: `get_json`,
# `get_bytes` and `probe` raise NodeListExpired BEFORE the host guard, the cache and any socket,
# and again before every retry (a backoff sleep can cross the instant). The wall clock is
# injected; the cache keeps its own monotonic one. Without the pair nothing changes (every
# test above is that control).

UNTIL = datetime(2027, 1, 4, 13, 33, 18, tzinfo=timezone.utc)
TICK = timedelta(microseconds=1)
GATED = ["get_json", "get_bytes", "probe"]


class WallClock:
    def __init__(self, now):
        self.now = now
        self.reads = 0

    def __call__(self):
        self.reads += 1
        return self.now


class SleepyTime:
    """Stands in for the ``time`` module of openvc_ebsi.http: a sleep advances the wall clock."""

    def __init__(self, wall):
        self.now = 1000.0
        self.sleeps = []
        self.wall = wall

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        self.wall.now += timedelta(seconds=seconds)


def _gated(handler, wall, **kwargs):
    return _client(handler, valid_until=UNTIL, clock=wall, **kwargs)


def _call(client, method, url=URL):
    return getattr(client, method)(url)


def _exact(cls, fn, *args):
    with pytest.raises(OpenvcError) as info:
        fn(*args)
    assert type(info.value) is cls, f"expected {cls.__name__}, got {type(info.value).__name__}"
    return info.value


@pytest.mark.parametrize("kwargs", [
    pytest.param({"valid_until": UNTIL}, id="only-valid_until"),
    pytest.param({"clock": lambda: UNTIL}, id="only-clock"),
])
def test_valid_until_and_clock_go_together(kwargs):
    exc = _exact(NodeClientConfigError, lambda: EbsiHttpClient(allowed_hosts={HOST}, **kwargs))
    assert isinstance(exc, ValueError)


@pytest.mark.parametrize("valid_until", [
    "2027-01-04T13:33:18Z", 1798680000, 1798680000.0, UNTIL.date(), object(), [UNTIL]])
def test_valid_until_must_be_a_datetime(valid_until):
    _exact(NodeClientConfigError, lambda: EbsiHttpClient(
        allowed_hosts={HOST}, valid_until=valid_until, clock=lambda: UNTIL))


@pytest.mark.parametrize("clock", ["now", 5, UNTIL, [UNTIL]])
def test_the_clock_must_be_callable(clock):
    _exact(NodeClientConfigError, lambda: EbsiHttpClient(
        allowed_hosts={HOST}, valid_until=UNTIL, clock=clock))


@pytest.mark.parametrize("method", GATED)
@pytest.mark.parametrize("moment", [
    pytest.param(UNTIL, id="at-valid_until"),
    pytest.param(UNTIL + TICK, id="one-microsecond-after"),
    pytest.param(UNTIL + timedelta(days=4000), id="far-past"),
])
def test_at_or_after_valid_until_every_reader_raises_with_zero_requests(method, moment):
    handler, calls = _play(_ok)
    c = _gated(handler, WallClock(moment), retry=FAST_RETRY)
    exc = _exact(NodeListExpired, _call, c, method)
    assert UNTIL.isoformat() in str(exc)
    assert calls["n"] == 0


@pytest.mark.parametrize("method", GATED)
def test_one_microsecond_before_valid_until_the_reader_works(method):
    handler, calls = _play(_ok)
    c = _gated(handler, WallClock(UNTIL - TICK), retry=FAST_RETRY)
    _call(c, method)
    assert calls["n"] == 1


@pytest.mark.parametrize("method", GATED)
def test_the_gate_comes_before_the_host_guard(method):
    # an expired client names expiry, not the host: nothing about the URL is looked at first
    handler, calls = _play(_ok)
    c = _gated(handler, WallClock(UNTIL), retry=FAST_RETRY)
    _exact(NodeListExpired, _call, c, method, "https://api.ebsi.iti.gr/x")
    _exact(NodeListExpired, _call, c, method, "not a url")
    assert calls["n"] == 0


def test_a_cached_success_is_not_served_past_valid_until():
    handler, calls = _play(_ok)
    wall = WallClock(UNTIL - timedelta(seconds=5))
    c = _gated(handler, wall, retry=FAST_RETRY)
    assert c.get_json(URL) == {"ok": 1}
    assert c.get_json(URL) == {"ok": 1} and calls["n"] == 1        # served from the cache
    wall.now = UNTIL
    _exact(NodeListExpired, c.get_json, URL)
    assert calls["n"] == 1


@pytest.mark.parametrize("method", ["get_json", "get_bytes"])
def test_a_backoff_sleep_that_crosses_valid_until_stops_the_next_attempt(monkeypatch, method):
    wall = WallClock(UNTIL - timedelta(seconds=1))
    monkeypatch.setattr(ebsi_http, "time", SleepyTime(wall))
    handler, calls = _play(lambda r: _resp(503))
    c = _gated(handler, wall, retry=RetryPolicy(attempts=3, backoff_base_s=4.0,
                                                backoff_max_s=4.0))
    _exact(NodeListExpired, _call, c, method)
    assert calls["n"] == 1                       # the first attempt only; the second never left


def test_a_transport_failure_retry_that_crosses_valid_until_stops_too(monkeypatch):
    wall = WallClock(UNTIL - timedelta(seconds=1))
    monkeypatch.setattr(ebsi_http, "time", SleepyTime(wall))
    handler, calls = _play(httpx.ConnectError("refused"))
    c = _gated(handler, wall, retry=RetryPolicy(attempts=3, backoff_base_s=4.0,
                                                backoff_max_s=4.0))
    _exact(NodeListExpired, c.get_json, URL)
    assert calls["n"] == 1


def test_the_gate_reads_the_clock_for_every_attempt_not_once():
    wall = WallClock(UNTIL - timedelta(days=1))
    handler, calls = _play(lambda r: _resp(503))
    c = _gated(handler, wall, retry=FAST_RETRY)
    _exact(HttpTransientExhausted, c.get_json, URL)
    assert calls["n"] == 3 and wall.reads >= 3


class Boom(Exception):
    pass


BAD_CLOCKS = [
    pytest.param(lambda: None, id="None"),
    pytest.param(lambda: 1798680000, id="int"),
    pytest.param(lambda: 1798680000.5, id="float"),
    pytest.param(lambda: "2026-10-16T12:00:00Z", id="string"),
    pytest.param(lambda: UNTIL.date(), id="date"),
    pytest.param(lambda: (_ for _ in ()).throw(RuntimeError("boom")), id="raises"),
    pytest.param(lambda: (_ for _ in ()).throw(Boom()), id="raises-custom"),
]


@pytest.mark.parametrize("method", GATED)
@pytest.mark.parametrize("clock", BAD_CLOCKS)
def test_a_clock_that_returns_no_datetime_is_a_config_error_never_now(method, clock):
    handler, calls = _play(_ok)
    c = _client(handler, valid_until=UNTIL, clock=clock, retry=FAST_RETRY)
    _exact(NodeClientConfigError, _call, c, method)
    assert calls["n"] == 0


def test_a_naive_clock_is_read_as_utc():
    handler, calls = _play(_ok)
    wall = WallClock((UNTIL - TICK).replace(tzinfo=None))
    c = _gated(handler, wall, retry=FAST_RETRY)
    assert c.get_json(URL) == {"ok": 1}
    wall.now = UNTIL.replace(tzinfo=None)
    _exact(NodeListExpired, c.get_json, "https://api-pilot.ebsi.eu/y")
    assert calls["n"] == 1


def test_a_naive_valid_until_is_read_as_utc():
    handler, _ = _play(_ok)
    c = _client(handler, valid_until=UNTIL.replace(tzinfo=None), clock=WallClock(UNTIL),
                retry=FAST_RETRY)
    assert c.valid_until == UNTIL and c.valid_until.tzinfo is timezone.utc
    _exact(NodeListExpired, c.get_json, URL)


def test_a_clock_in_another_zone_is_compared_as_the_instant_it_is():
    tz = timezone(timedelta(hours=5))
    handler, _ = _play(_ok)
    inside = (UNTIL - TICK).astimezone(tz)
    c = _client(handler, valid_until=UNTIL, clock=lambda: inside, retry=FAST_RETRY)
    assert c.get_json(URL) == {"ok": 1}
    at = _client(handler, valid_until=UNTIL, clock=lambda: UNTIL.astimezone(tz),
                 retry=FAST_RETRY)
    _exact(NodeListExpired, at.get_json, URL)


class LyingInstant(datetime):
    """A datetime whose own methods lie: only its fields and ``tzinfo`` are true (#286)."""

    def utcoffset(self):
        return timedelta(hours=-12)

    def astimezone(self, tz=None):
        return datetime(1999, 1, 1, tzinfo=timezone.utc)

    def __ge__(self, other):
        return False

    def __lt__(self, other):
        return True


@pytest.mark.parametrize("delta,expired", [(-TICK, False), (timedelta(0), True)])
def test_a_datetime_subclass_cannot_change_the_reading(delta, expired):
    moment = UNTIL + delta
    lying = LyingInstant(moment.year, moment.month, moment.day, moment.hour, moment.minute,
                         moment.second, moment.microsecond, tzinfo=timezone.utc)
    handler, calls = _play(_ok)
    c = _gated(handler, WallClock(lying), retry=FAST_RETRY)
    if expired:
        _exact(NodeListExpired, c.get_json, URL)
        assert calls["n"] == 0
    else:
        assert c.get_json(URL) == {"ok": 1}


def test_without_the_pair_the_client_is_unbounded_and_reads_no_clock():
    handler, calls = _play(_ok)
    c = _client(handler, retry=FAST_RETRY)
    assert c.valid_until is None
    for method in GATED:
        _call(c, method)
    assert calls["n"] == 3


# --- probe: one attempt, every status returned, never cached (#324) ------------------- #

def test_probe_returns_the_status_and_the_body_of_a_200():
    handler, calls = _play(lambda r: _resp(200, b'{"health_global":1}'))
    c = _client(handler, retry=FAST_RETRY)
    assert c.probe(URL) == ProbeResponse(200, b'{"health_global":1}')
    assert calls["n"] == 1


@pytest.mark.parametrize("status", [201, 204, 301, 302, 304, 400, 403, 404, 429, 500, 503])
def test_probe_returns_every_other_status_without_its_body_and_without_a_retry(
        monkeypatch, status):
    slept = SleepyTime(WallClock(UNTIL))
    monkeypatch.setattr(ebsi_http, "time", slept)
    handler, calls = _play(lambda r: _resp(status, b"SECRET-BODY", {"Location": "/elsewhere"}))
    c = _client(handler, retry=RetryPolicy(attempts=5, backoff_base_s=1.0, backoff_max_s=1.0))
    assert c.probe(URL) == ProbeResponse(status, b"")
    assert calls["n"] == 1 and slept.sleeps == []


@pytest.mark.parametrize("exc", [
    httpx.ConnectError("refused"), httpx.ConnectTimeout("t"), httpx.ReadTimeout("t")])
def test_probe_does_not_retry_a_transport_failure_and_does_not_sleep(monkeypatch, exc):
    slept = SleepyTime(WallClock(UNTIL))
    monkeypatch.setattr(ebsi_http, "time", slept)
    handler, calls = _play(exc)
    c = _client(handler, retry=RetryPolicy(attempts=5, backoff_base_s=1.0, backoff_max_s=1.0))
    err = _exact(HttpTransientExhausted, c.probe, URL)
    assert err.status is None
    assert calls["n"] == 1 and slept.sleeps == []
    assert str(err).startswith("gave up after 1 attempts")


def test_probe_is_not_read_from_nor_written_to_the_cache():
    handler, calls = _play(lambda r: _resp(200, b'{"health_global":1}'))
    c = _client(handler, retry=FAST_RETRY)
    c._cache.set(URL, {"poison": True})
    assert c.probe(URL).body == b'{"health_global":1}'
    assert c._cache.get(URL) == {"poison": True}                 # untouched
    c._cache.clear()
    c.probe(URL)
    assert len(c._cache) == 0 and calls["n"] == 2


def test_probe_applies_the_host_guard_and_the_cap():
    handler, calls = _play(lambda r: _resp(200, b"x" * 5000))
    c = _client(handler, retry=FAST_RETRY, max_response_bytes=1024)
    _exact(HttpForbiddenHost, c.probe, "https://api.ebsi.iti.gr/x")
    assert calls["n"] == 0
    err = _exact(HttpError, c.probe, URL)                        # body past the client cap
    assert err.status == 200


def test_probe_never_follows_a_redirect():
    handler, calls = _play(lambda r: _resp(302, b"", {"Location": "https://attacker.example/"}),
                           lambda r: _resp(200, b'{"health_global":1}'))
    c = _client(handler, retry=FAST_RETRY)
    assert c.probe(URL) == ProbeResponse(302, b"")
    assert calls["n"] == 1


def test_probe_max_bytes_can_only_lower_the_clients_cap():
    handler, _ = _play(lambda r: _resp(200, b"x" * 200))
    c = _client(handler, retry=FAST_RETRY, max_response_bytes=1024)
    assert len(c.probe(URL).body) == 200
    err = _exact(HttpError, lambda: c.probe(URL, max_bytes=100))
    assert err.status == 200
    c2 = _client(handler, retry=FAST_RETRY, max_response_bytes=100)
    _exact(HttpError, lambda: c2.probe(URL, max_bytes=10**9))     # cannot raise the client's cap
    for bad in (-1, True, 1.5, "10", None):
        _exact(HttpError, lambda bad=bad: c.probe(URL, max_bytes=bad))


# --- HttpTransientExhausted.status (#324) ---------------------------------------------- #

@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_exhausted_retries_carry_the_last_status(status):
    handler, calls = _play(lambda r: _resp(status))
    c = _client(handler, retry=FAST_RETRY)
    err = _exact(HttpTransientExhausted, c.get_json, URL)
    assert err.status == status and calls["n"] == 3


@pytest.mark.parametrize("method", READERS)
def test_exhausted_retries_after_transport_errors_carry_no_status(method):
    handler, _ = _play(httpx.ConnectError("refused"))
    c = _client(handler, retry=FAST_RETRY)
    err = _exact(HttpTransientExhausted, getattr(c, method), URL)
    assert err.status is None


def test_the_status_is_the_last_attempts_not_the_first():
    handler, _ = _play(lambda r: _resp(503), httpx.ConnectError("refused"),
                       lambda r: _resp(429))
    c = _client(handler, retry=FAST_RETRY)
    assert _exact(HttpTransientExhausted, c.get_json, URL).status == 429
