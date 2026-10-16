"""
tests/test_ebsi_http.py — EBSI HTTP client resource limits (#103).

Offline (httpx.MockTransport) coverage for the response-size cap and the Retry-After
parsing added in the uniform-resource-limits pass. The wall-clock deadline shares the
same streamed read path; a drip test would be timing-flaky, so it is left to the read
loop's logic and the size-cap test here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

httpx = pytest.importorskip("httpx")

from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    EbsiHttpClient,
    HttpError,
    HttpForbiddenHost,
    HttpNotFound,
    HttpTransientExhausted,
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
    assert isinstance(exc_info.value.__cause__, httpx.DecodingError)
    assert calls["n"] == 1                        # terminal, not retried
