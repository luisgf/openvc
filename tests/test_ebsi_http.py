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

from openvc_ebsi.http import EbsiHttpClient, HttpError, _parse_retry_after  # noqa: E402

HOST = "api-pilot.ebsi.eu"
URL = f"https://{HOST}/x"


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
