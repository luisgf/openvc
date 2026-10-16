"""
tests/test_ebsi_http_cookies.py — the pooled EBSI client keeps no cookie jar (#317).

``EbsiHttpClient`` is a stateless GET reader whose only state is the TTL cache
(ADR-0001 D2). httpx's default cookie jar would store any ``Set-Cookie`` from an
allow-listed host and send it back, which pins a retry to the backend it is leaving,
lets a ``Domain=`` cookie cross to a sibling host, and is hidden state that lives as long
as the client (ADR-0009, "Where each design can be attacked", row "Cookie jar").

HARNESS TRAP. ``test_ebsi_http.py`` and friends assign ``client._client = httpx.Client(
transport=...)``, which replaces the constructor-built client and so discards the policy:
a cookie test written that way fails whatever the fix. Here the ``EbsiHttpClient`` is built
normally and the transport is injected by patching ``httpx.Client`` for the duration of the
constructor only; the keyword arguments it receives are recorded.

Offline and synthetic: the cookie is a stand-in ``SRV_ID`` (the name the two
``edelivery.lt`` hosts were seen to set in ADR-0009). The real ``Set-Cookie`` line (its
``Domain``, ``Path``, ``Secure`` ... attributes) was not recorded: that needs two live GETs
nobody has approved, and nothing here depends on it.
"""
from __future__ import annotations

import warnings
from collections.abc import Callable
from http.cookiejar import Cookie, CookieJar
from unittest import mock
from urllib.request import Request

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

httpx = pytest.importorskip("httpx")

from openvc import __version__  # noqa: E402
from openvc_ebsi import http as ebsi_http  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    EbsiHttpClient,
    HttpError,
    HttpNotFound,
    HttpTransientExhausted,
    RetryPolicy,
)

# Captured at import: patching ``httpx.Client`` and then reading it again would recurse.
_REAL_CLIENT = httpx.Client

PROD = "api.ebsi.edelivery.lt"
PREPROD = "api-preprod.ebsi.edelivery.lt"
HOSTS = {PROD, PREPROD}
URL_A = f"https://{PROD}/a"
URL_B = f"https://{PROD}/b"
URL_PREPROD = f"https://{PREPROD}/c"

# Zero backoff so the retry tests do not sleep.
FAST_RETRY = RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)

SET_COOKIE = "SRV_ID=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"
SET_COOKIE_DOMAIN = "SRV_ID=abc123; Path=/; Domain=ebsi.edelivery.lt"


class Rig:
    """A handler that records every request it sees and answers from a script."""

    def __init__(self, respond: Callable[[httpx.Request, int], httpx.Response]) -> None:
        self.respond = respond
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.respond(request, len(self.requests))

    @property
    def cookie_headers(self) -> list[str | None]:
        return [r.headers.get("cookie") for r in self.requests]


def _ok(
    set_cookie: str | bytes | None = SET_COOKIE,
) -> Callable[[httpx.Request, int], httpx.Response]:
    def respond(request: httpx.Request, n: int) -> httpx.Response:
        headers: list[tuple[bytes, bytes]] = []
        if set_cookie is not None:
            raw = set_cookie if isinstance(set_cookie, bytes) else set_cookie.encode("latin-1")
            headers.append((b"set-cookie", raw))
        return httpx.Response(200, headers=headers, json={"n": n})
    return respond


def build(rig: Rig, **kwargs) -> tuple[EbsiHttpClient, dict]:
    """The real constructor, with the transport injected and the kwargs recorded."""
    recorded: dict = {}

    def factory(**kw):
        recorded.update(kw)
        return _REAL_CLIENT(transport=httpx.MockTransport(rig), **kw)

    kwargs.setdefault("retry", FAST_RETRY)
    with mock.patch.object(httpx, "Client", factory):
        client = EbsiHttpClient(allowed_hosts=HOSTS, **kwargs)
    return client, recorded


def plain_client(rig: Rig, **kw) -> httpx.Client:
    return _REAL_CLIENT(transport=httpx.MockTransport(rig), **kw)


# --------------------------------------------------------------------------- #
# The controls first: they are what stops the negatives passing vacuously.
# --------------------------------------------------------------------------- #

def test_control_a_plain_httpx_client_sends_the_cookie_back():
    rig = Rig(_ok())
    with plain_client(rig) as c:
        for url in (URL_A, URL_B):
            with c.stream("GET", url) as resp:         # the call get_json makes
                resp.read()
    assert rig.cookie_headers == [None, "SRV_ID=abc123"]


def test_control_the_constructor_kwargs_without_cookies_send_it_too():
    """Strip only ``cookies`` from what the constructor passed: the cookie comes back, so
    the harness sees a leak when there is one, through the same ``stream`` path."""
    _, recorded = build(Rig(_ok()))
    rig = Rig(_ok())
    without = {k: v for k, v in recorded.items() if k != "cookies"}
    with plain_client(rig, **without) as c:
        for url in (URL_A, URL_B):
            with c.stream("GET", url) as resp:
                resp.read()
    assert rig.cookie_headers == [None, "SRV_ID=abc123"]


# --------------------------------------------------------------------------- #
# The client keeps no cookie
# --------------------------------------------------------------------------- #

def test_a_set_cookie_on_a_200_is_neither_stored_nor_sent_back():
    rig = Rig(_ok())
    client, _ = build(rig)
    with client:
        assert client.get_json(URL_A) == {"n": 1}
        assert client.get_json(URL_B) == {"n": 2}         # another URL: not the TTL cache
        # Both assertions: a policy whose ``set_ok`` is True fills the jar, and one that
        # only refuses to send is caught by the header (httpx copies the jar per request).
        assert len(client._client.cookies.jar) == 0
    assert rig.cookie_headers == [None, None]


def test_a_set_cookie_on_a_503_is_not_carried_by_the_retry():
    def respond(request, n):
        if n == 1:
            return httpx.Response(503, headers=[(b"set-cookie", SET_COOKIE.encode())])
        return httpx.Response(200, json={"n": n})

    rig = Rig(respond)
    client, _ = build(rig)
    with client:
        assert client.get_json(URL_A) == {"n": 2}
        assert len(client._client.cookies.jar) == 0
    assert len(rig.requests) == 2
    assert rig.cookie_headers == [None, None]


def test_a_domain_cookie_from_one_host_is_not_sent_to_a_sibling_host():
    rig = Rig(_ok(SET_COOKIE_DOMAIN))
    client, _ = build(rig)                       # both hosts allow-listed, as in a hand-built set
    with client:
        client.get_json(URL_A)
        client.get_json(URL_PREPROD)
    assert [r.url.host for r in rig.requests] == [PROD, PREPROD]
    assert rig.cookie_headers == [None, None]


def test_control_the_domain_cookie_does_cross_hosts_in_a_default_jar():
    rig = Rig(_ok(SET_COOKIE_DOMAIN))
    with plain_client(rig) as c:
        for url in (URL_A, URL_PREPROD):
            with c.stream("GET", url) as resp:
                resp.read()
    assert rig.cookie_headers == [None, "SRV_ID=abc123"]


@pytest.mark.parametrize("with_cookie", [False, True], ids=["no-cookie", "set-cookie"])
@pytest.mark.parametrize(
    "status, expected, requests",
    [
        (503, HttpTransientExhausted, 3),
        (404, HttpNotFound, 1),
        (403, HttpError, 1),
        (302, HttpError, 1),
    ],
    ids=["503-exhausted", "404", "403", "302-no-redirect"],
)
def test_error_classes_are_unchanged_with_and_without_a_set_cookie(
        status, expected, requests, with_cookie):
    def respond(request, n):
        headers = [(b"set-cookie", SET_COOKIE.encode())] if with_cookie else []
        if status == 302:
            headers.append((b"location", f"https://{PROD}/elsewhere".encode()))
        return httpx.Response(status, headers=headers)

    rig = Rig(respond)
    client, _ = build(rig)
    with client:
        with pytest.raises(HttpError) as info:
            client.get_json(URL_A)
    assert type(info.value) is expected
    assert info.value.status == (None if expected is HttpTransientExhausted else status)
    assert len(rig.requests) == requests                  # a 302 is not followed
    assert {r.url.path for r in rig.requests} == {"/a"}
    assert rig.cookie_headers == [None] * requests


def test_a_302_with_a_cookie_is_not_followed_and_the_target_gets_no_cookie():
    def respond(request, n):
        if request.url.path == "/a":
            return httpx.Response(302, headers=[(b"set-cookie", SET_COOKIE.encode()),
                                                (b"location", URL_B.encode())])
        return httpx.Response(200, json={"n": n})

    rig = Rig(respond)
    client, _ = build(rig)
    with client:
        with pytest.raises(HttpError):
            client.get_json(URL_A)
        assert client.get_json(URL_B) == {"n": 2}
    assert [r.url.path for r in rig.requests] == ["/a", "/b"]
    assert rig.cookie_headers == [None, None]


def test_even_with_redirects_on_the_constructor_jar_sends_nothing_on_the_hop():
    """The client never follows a redirect (``follow_redirects=False``), so this uses the
    very ``cookies`` object it hands httpx on a client that does: the jar, not the redirect
    policy, is what keeps the cookie off the second request."""
    def respond(request, n):
        if request.url.path == "/a":
            return httpx.Response(302, headers=[(b"set-cookie", SET_COOKIE.encode()),
                                                (b"location", URL_B.encode())])
        return httpx.Response(200, json={"n": n})

    _, recorded = build(Rig(respond))
    rig = Rig(respond)
    with plain_client(rig, **{**recorded, "follow_redirects": True}) as c:
        with c.stream("GET", URL_A) as resp:
            resp.read()
    assert [r.url.path for r in rig.requests] == ["/a", "/b"]
    assert rig.cookie_headers == [None, None]

    rig = Rig(respond)                                    # control: the same without the jar
    without = {k: v for k, v in recorded.items() if k != "cookies"}
    with plain_client(rig, **{**without, "follow_redirects": True}) as c:
        with c.stream("GET", URL_A) as resp:
            resp.read()
    assert rig.cookie_headers == [None, "SRV_ID=abc123"]


# --------------------------------------------------------------------------- #
# Hostile Set-Cookie values: the stdlib still parses them, then drops the cookie
# --------------------------------------------------------------------------- #

HOSTILE = [
    b"",
    b"=",
    b"SRV_ID=abc; Expires=not a date",
    b"SRV_ID=abc; Max-Age=xyz",
    b"SRV_ID=abc; Max-Age=" + b"9" * 5000,
    b"SRV_ID=\xe9",                                       # latin-1 byte
    b"SRV_ID=\xc3\xa9",                                   # UTF-8 bytes
    b"; ".join(b"a%d=b" % i for i in range(20_000)),      # 20 000 attributes
    b"SRV_ID=" + b"x" * 1_000_000,                        # 1 MB value
    b'SRV_ID="unbalanced',
    b"SRV_ID=abc; Domain=.",
    b"SRV_ID=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT",  # already expired
]


@pytest.mark.parametrize("value", HOSTILE, ids=[f"hostile-{i}" for i in range(len(HOSTILE))])
def test_hostile_set_cookie_values_neither_raise_nor_warn(value):
    rig = Rig(_ok(value))
    client, _ = build(rig)
    with client, warnings.catch_warnings():
        warnings.simplefilter("error")
        assert client.get_json(URL_A) == {"n": 1}
        assert client.get_json(URL_B) == {"n": 2}
        assert len(client._client.cookies.jar) == 0
    assert rig.cookie_headers == [None, None]


_COOKIE_BITS = st.one_of(
    st.sampled_from([
        b"SRV_ID=abc", b"SRV_ID=", b"=", b"Path=/", b"Domain=ebsi.edelivery.lt",
        b"Domain=.edelivery.lt", b"Secure", b"HttpOnly", b"SameSite=None", b"Max-Age=60",
        b"Max-Age=-1", b"Expires=Wed, 09 Jun 2037 10:18:14 GMT", b"Version=1", b"Port=443",
        b"Comment=x", b'x="a;b"',
    ]),
    st.binary(max_size=24),
)
# Arbitrary bytes (what a header can hold, as latin-1 text) and cookie-shaped lines, which
# are what actually reach the jar's store path when the policy is missing.
HEADER_VALUES = st.one_of(
    st.binary(max_size=512),
    st.lists(_COOKIE_BITS, max_size=10).map(b"; ".join),
)


@settings(max_examples=150, deadline=None)
@given(HEADER_VALUES)
def test_property_any_set_cookie_leaves_the_jar_empty_and_nothing_is_sent(value):
    rig = Rig(_ok(value))
    client, _ = build(rig)
    with client, warnings.catch_warnings():
        warnings.simplefilter("error")
        assert client.get_json(URL_A) == {"n": 1}
        assert client.get_json(URL_B) == {"n": 2}
        assert len(client._client.cookies.jar) == 0
    assert rig.cookie_headers == [None, None]


# --------------------------------------------------------------------------- #
# Nothing else changed
# --------------------------------------------------------------------------- #

def test_the_constructor_passes_the_old_kwargs_plus_a_bare_cookiejar():
    _, recorded = build(Rig(_ok()))
    assert set(recorded) == {"timeout", "verify", "follow_redirects", "headers", "cookies"}
    assert recorded["timeout"] == httpx.Timeout(10.0)
    assert recorded["verify"] is True
    assert recorded["follow_redirects"] is False
    assert recorded["headers"] == {
        "User-Agent": f"openvc-core/{__version__}",
        "Accept": "application/json, application/did+ld+json, */*;q=0.1",
    }
    # A bare CookieJar: httpx keeps only that as given (an httpx.Cookies, a dict or a list
    # is rebuilt with the default policy, which would silently lose ours).
    assert type(recorded["cookies"]) is CookieJar
    assert len(recorded["cookies"]) == 0


def test_the_other_constructor_options_still_pass_through():
    _, recorded = build(Rig(_ok()), verify_tls=False, timeout_s=3.5, user_agent="ua/1")
    assert recorded["verify"] is False
    assert recorded["timeout"] == httpx.Timeout(3.5)
    assert recorded["headers"]["User-Agent"] == "ua/1"
    assert recorded["follow_redirects"] is False


def test_request_headers_are_the_old_ones_apart_from_the_absent_cookie():
    rig = Rig(_ok())
    client, _ = build(rig)
    with client:
        client.get_json(URL_A)
        client.get_json(URL_B)
    first, second = rig.requests
    assert second.headers.multi_items() == first.headers.multi_items()
    assert first.headers["user-agent"] == f"openvc-core/{__version__}"
    assert first.headers["accept"] == "application/json, application/did+ld+json, */*;q=0.1"
    assert "cookie" not in first.headers and "cookie" not in second.headers
    assert set(first.headers) == {"host", "accept", "accept-encoding", "connection",
                                  "user-agent"}


def test_the_policy_refuses_in_all_four_directions():
    """``set_ok`` is the load-bearing one; the other three are defence in depth and are
    unreachable through httpx (it copies the jar into a default-policy one per request), so
    they are pinned directly."""
    policy = ebsi_http._NoCookiePolicy()
    cookie = Cookie(
        version=0, name="SRV_ID", value="abc", port=None, port_specified=False,
        domain=PROD, domain_specified=False, domain_initial_dot=False, path="/",
        path_specified=True, secure=False, expires=None, discard=True, comment=None,
        comment_url=None, rest={})
    request = Request(URL_A)
    assert policy.set_ok(cookie, request) is False
    assert policy.return_ok(cookie, request) is False
    assert policy.domain_return_ok(PROD, request) is False
    assert policy.path_return_ok("/", request) is False
    assert (policy.netscape, policy.rfc2965, policy.hide_cookie2) == (True, False, False)

    jar = CookieJar(policy=policy)
    jar.set_cookie(cookie)                                # bypasses set_ok on purpose
    jar.add_cookie_header(request)
    assert request.get_header("Cookie") is None
