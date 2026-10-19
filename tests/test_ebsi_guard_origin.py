"""
tests/test_ebsi_guard_origin.py — the EBSI client admits an ORIGIN, not a host name (#318).

``EbsiHttpClient._guard_host`` used to admit a URL when its scheme was ``https`` and its
host name was in ``allowed_hosts``. The port was never read, so every port of an allow-listed
host reached the socket (``:80``, ``:8443``, ``:9200``, and ``:0``), and a URL with userinfo
went out with a Basic ``Authorization`` header the caller never set. Only the TIR v5 adapter's
origin pin (``versioning._origin``, #172, #253) kept a registry walk off another port, and
only for three hops of one adapter.

The guard now admits ``https`` on a listed host at port 443 (ADR-0009 D1: the Trusted Nodes
List publishes bare ``https://host`` origins), and nothing else:

  * an absent port, an EMPTY port (``https://host:/x``) and ``:443`` / ``:0443`` / ``:00443``
    are 443; every other port is ``HttpForbiddenHost``, ``:0`` included (``port is None``, not
    truthiness, so ``:0`` does not fold into 443: the #253 trap);
  * a URL with userinfo, the empty forms ``https://@host/`` and ``https://:@host/`` included,
    is ``HttpForbiddenHost`` (an ``@`` in a path, query or fragment is not userinfo);
  * ``allowed_hosts`` stays a set of host NAMES, 443 implied, so every existing caller works;
  * the guard and the adapter pin read a URL through one reader (``openvc_ebsi._url``), and
    a parity test makes them agree: the guard admits a URL exactly when the pin says it is on
    ``https://api-pilot.ebsi.eu:443``, except the two documented gaps (userinfo: the guard
    refuses and the pin ignores it; over 8 KiB: the pin refuses and the guard has no cap).

Every refusal is asserted against the EXACT class (``type(exc) is HttpForbiddenHost``) and
against the message of the rule that should have fired, so a refusal by an earlier rule cannot
stand in for the one under test, and against a transport that records every request, so
"refused" means "nothing left the process". The helpers are self-contained (tests/ is not a
package: no cross-import). The reader's own tests import ``openvc_ebsi._url`` inside the test,
so the guard tests above them stay runnable against a tree that lacks the module.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import pytest

httpx = pytest.importorskip("httpx")

from hypothesis import example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from openvc.proof.vc_jwt import VcJwtProofSuite  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    EbsiHttpClient,
    HttpError,
    HttpForbiddenHost,
    for_ebsi,
)
from openvc_ebsi.versioning import DidEbsiResolver, TirV5, _on_origin, _origin  # noqa: E402

HOST = "api-pilot.ebsi.eu"
PILOT_BASE = f"https://{HOST}"
DID = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"


# --------------------------------------------------------------------------- #
# Harness (self-contained: tests/ is not a package)
# --------------------------------------------------------------------------- #

class Recorder:
    """A MockTransport handler that records every request and answers 200 ``{"ok": true}``."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json={"ok": True})


def _client(handler: Any, *, hosts: tuple[str, ...] = (HOST,)) -> EbsiHttpClient:
    """A client over ``handler``. Swapping ``_client`` wholesale is the harness the neighbouring
    suites use; the redirect tests below build the real client instead."""
    c = EbsiHttpClient(allowed_hosts=set(hosts))
    c._client = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def _admits(client: EbsiHttpClient, url: str) -> bool:
    """Whether ``_guard_host`` admits ``url``. Any exception but ``HttpForbiddenHost`` is a bug."""
    try:
        client._guard_host(url)
    except HttpForbiddenHost:
        return False
    return True


def _refused(client: EbsiHttpClient, url: str, match: str) -> None:
    """``url`` is ``HttpForbiddenHost`` (the exact class) from both the guard and ``get_json``,
    with ``match`` in the message and a cause that is not an ``httpx.InvalidURL``."""
    for call in (client._guard_host, client.get_json):
        with pytest.raises(HttpForbiddenHost, match=match) as exc_info:
            call(url)
        assert type(exc_info.value) is HttpForbiddenHost
        assert not isinstance(exc_info.value.__cause__, httpx.InvalidURL)   # the guard, not httpx


@pytest.fixture(scope="module")
def guard_client() -> Iterator[EbsiHttpClient]:
    """One real client for the tests that call ``_guard_host`` alone (no I/O)."""
    c = EbsiHttpClient(allowed_hosts={HOST})
    yield c
    c.close()


# --------------------------------------------------------------------------- #
# Another port of an allow-listed host: refused, before the cache and any I/O
# --------------------------------------------------------------------------- #

# The ports the issue lists, as they are spelt in a URL.
REFUSED_PORTS = [":0", ":00", ":80", ":444", ":4430", ":8443", ":9200", ":65535"]
# Each is tried on a lower-case host, an upper-case host, with a path and query, and bare.
SHAPES = [
    "https://{host}{port}/x",
    "https://{host}{port}",
    "https://{host}{port}/a/b?c=1&d=2",
    "HTTPS://{host}{port}/x",
]
HOSTS = [HOST, "API-PILOT.ebsi.eu", "Api-Pilot.EBSI.eu"]
REFUSED_PORT_URLS = [
    pytest.param(shape.format(host=host, port=port), int(port[1:]), id=f"{shape}-{host}-{port}")
    for port in REFUSED_PORTS for host in HOSTS for shape in SHAPES
]


@pytest.mark.parametrize("url,number", REFUSED_PORT_URLS)
def test_another_port_is_refused_before_any_request(url: str, number: int) -> None:
    rec = Recorder()
    c = _client(rec)
    _refused(c, url, match=rf"port {number} not allowed")
    assert rec.requests == []                  # nothing reached the transport


def test_a_cached_body_is_not_served_for_a_refused_port() -> None:
    # The guard runs before the cache lookup: an entry stored under a refused URL (a cache
    # shared with another client, or one pre-populated by hand) is not a way around it.
    rec = Recorder()
    c = _client(rec)
    c._cache.set(f"{PILOT_BASE}:8443/x", {"cached": True})
    with pytest.raises(HttpForbiddenHost, match="port 8443 not allowed"):
        c.get_json(f"{PILOT_BASE}:8443/x")
    assert rec.requests == []


@pytest.mark.parametrize("port", [":0", ":80", ":8443", ":65535"])
def test_the_port_rule_does_not_depend_on_how_the_host_is_listed(port: str) -> None:
    # A host listed with a trailing dot or in upper case: the same 443-only rule.
    rec = Recorder()
    c = _client(rec, hosts=("API-PILOT.ebsi.eu.",))
    _refused(c, f"https://{HOST}.{port}/x", match=r"port \d+ not allowed")
    assert rec.requests == []
    assert _admits(c, f"https://{HOST}./x")
    assert _admits(c, f"https://{HOST}.:443/x")


def test_extra_hosts_take_port_443_only() -> None:
    # `for_ebsi(extra_hosts=...)`: a status-list host is host NAME in, port 443 out.
    c = for_ebsi("legacy-pilot", extra_hosts={"status.example.org"})
    try:
        assert _admits(c, "https://status.example.org/list/1")
        assert _admits(c, "https://status.example.org:443/list/1")
        _refused(c, "https://status.example.org:8443/list/1", match="port 8443 not allowed")
        _refused(c, f"https://{HOST}:9200/x", match="port 9200 not allowed")
        assert _admits(c, f"https://{HOST}/x")
    finally:
        c.close()


@pytest.mark.parametrize("entry", [
    pytest.param(f"{HOST}:8443", id="host-port"),
    pytest.param(f"{HOST}:443", id="host-443"),
    pytest.param(f"https://{HOST}", id="origin-string"),
    pytest.param(f"https://{HOST}:443", id="origin-string-443"),
])
def test_an_allow_list_entry_that_spells_a_port_or_scheme_never_matches(entry: str) -> None:
    # Unchanged and still documented: `allowed_hosts` holds host NAMES. An origin string or a
    # `host:port` is not parsed (that is API work for 2.0, #74); it simply never matches.
    c = EbsiHttpClient(allowed_hosts={entry})
    try:
        for url in (f"https://{HOST}/x", f"https://{HOST}:443/x", f"https://{HOST}:8443/x"):
            _refused(c, url, match="host not in allow-list")
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# Userinfo: outside an origin, refused
# --------------------------------------------------------------------------- #

USERINFO_URLS = [
    pytest.param(f"https://u@{HOST}/x", id="user"),
    pytest.param(f"https://u:p@{HOST}/x", id="user-password"),
    pytest.param(f"https://@{HOST}/x", id="empty-user"),
    pytest.param(f"https://:@{HOST}/x", id="empty-user-empty-password"),
    pytest.param(f"https://:p@{HOST}/x", id="empty-user-password"),
    pytest.param(f"https://u@{HOST}:443/x", id="user-explicit-443"),
    pytest.param(f"https://u@{HOST}", id="user-no-path"),
    pytest.param(f"https://evil.example\\@{HOST}/x", id="backslash-in-userinfo"),
    pytest.param(f"https://u%40v@{HOST}/x", id="percent-escaped-at"),
    pytest.param(f"https://u@@{HOST}/x", id="two-ats"),
]


@pytest.mark.parametrize("url", USERINFO_URLS)
def test_userinfo_is_refused_before_any_request(url: str) -> None:
    rec = Recorder()
    c = _client(rec)
    _refused(c, url, match="carries userinfo")
    assert rec.requests == []


def test_the_userinfo_refusal_does_not_echo_the_userinfo() -> None:
    # The userinfo is caller- or registry-supplied; the refusal names the rule, not the secret.
    # Nothing the exception holds carries it: not the message, not `.url` (None here, where
    # every other refusal keeps the URL as given), not the args, repr or cause/context.
    c = EbsiHttpClient(allowed_hosts={HOST})
    try:
        for call in (c._guard_host, c.get_json):
            with pytest.raises(HttpForbiddenHost) as exc_info:
                call(f"https://zq9name:s3cretpass@{HOST}/x")
            exc = exc_info.value
            assert type(exc) is HttpForbiddenHost
            assert exc.url is None
            assert exc.args == ("URL rejected: carries userinfo",)
            assert exc.__cause__ is None and exc.__context__ is None
            held = "|".join((str(exc), repr(exc), repr(vars(exc)), repr(exc.args)))
            assert "s3cretpass" not in held
            assert "zq9name" not in held
    finally:
        c.close()


@pytest.mark.parametrize("url", USERINFO_URLS)
def test_the_userinfo_refusal_keeps_no_url(url: str) -> None:
    # `.url` is the one attribute that used to hold the credentials; every form is None.
    c = EbsiHttpClient(allowed_hosts={HOST})
    try:
        with pytest.raises(HttpForbiddenHost, match="carries userinfo") as exc_info:
            c._guard_host(url)
        assert type(exc_info.value) is HttpForbiddenHost
        assert exc_info.value.url is None
    finally:
        c.close()


def test_userinfo_was_sent_as_basic_auth_before_this_guard() -> None:
    # The reason for the rule, kept as a measured fact about httpx 0.28: given the URL, the
    # client puts the userinfo in an `Authorization: Basic` header. It is a transport-level
    # check with the guard bypassed, so it pins what the guard now stops.
    rec = Recorder()
    transport_client = httpx.Client(transport=httpx.MockTransport(rec))
    transport_client.get(f"https://u:p@{HOST}/x")
    assert rec.requests[0].headers["Authorization"] == "Basic dTpw"


@pytest.mark.parametrize("url", [
    pytest.param(f"https://{HOST}/a@b", id="at-in-path"),
    pytest.param(f"https://{HOST}/x?u=a@b", id="at-in-query"),
    pytest.param(f"https://{HOST}/x#@y", id="at-in-fragment"),
    pytest.param(f"https://{HOST}?@evil.example:8443/", id="at-in-query-after-bare-host"),
    pytest.param(f"https://{HOST}#@evil.example:8443/", id="at-in-fragment-after-bare-host"),
    pytest.param(f"https://{HOST}:443/x?cb=1&who=a@b.example", id="explicit-443-at-in-query"),
])
def test_an_at_sign_outside_the_authority_is_not_userinfo(url: str) -> None:
    rec = Recorder()
    c = _client(rec)
    assert c.get_json(url) == {"ok": True}
    assert len(rec.requests) == 1
    assert rec.requests[0].url.host == HOST and rec.requests[0].url.port is None


# --------------------------------------------------------------------------- #
# Controls: the forms that stay admitted, one request each, to the right place
# --------------------------------------------------------------------------- #

ADMITTED_URLS = [
    pytest.param(f"https://{HOST}/x", id="absent-port"),
    pytest.param(f"https://{HOST}", id="bare-origin"),
    pytest.param(f"https://{HOST}?q=1", id="bare-origin-query"),
    pytest.param(f"https://{HOST}:443/x", id="443"),
    pytest.param(f"https://{HOST}:0443/x", id="0443"),
    pytest.param(f"https://{HOST}:00443/x", id="00443"),
    pytest.param(f"https://{HOST}:/x", id="empty-port"),
    pytest.param(f"https://{HOST}:", id="empty-port-no-path"),
    pytest.param(f"HTTPS://{HOST.upper()}:443/x", id="upper-case-everything"),
    pytest.param("HtTpS://Api-Pilot.EBSI.eu/x", id="mixed-case"),
    pytest.param(f"https://{HOST}:443/a/b?c=1#frag", id="path-query-fragment"),
]


@pytest.mark.parametrize("url", ADMITTED_URLS)
def test_the_default_port_spellings_are_admitted_and_reach_port_443(url: str) -> None:
    rec = Recorder()
    c = _client(rec)
    assert c.get_json(url) == {"ok": True}
    assert len(rec.requests) == 1
    request = rec.requests[0]
    assert request.url.scheme == "https"
    assert request.url.host == HOST
    # httpx folds a lower-case-scheme 443 into "no port" and keeps `:443` after an upper-case
    # scheme (measured, 0.28.1); either way the connection goes to the https default port.
    assert request.url.port in (None, 443)


# The recorded pilot registry, served through the REAL client over a MockTransport. The
# fixtures carry no port, so with a `:443` base they also exercise the `:443`-equals-absent
# rule across the guard and the pin.
def _recorded_registry() -> dict[str, Any]:
    issuer = json.loads((FIXTURES / "tir_v5_issuer.json").read_text())
    attributes = json.loads((FIXTURES / "tir_v5_attributes.json").read_text())
    revisions = json.loads((FIXTURES / "tir_v5_revisions.json").read_text())
    didr = json.loads((FIXTURES / "didr_v5_identifiers.json").read_text())
    routes: dict[str, Any] = {
        f"{PILOT_BASE}/did-registry/v5/identifiers/{DID}": didr,
        f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{DID}": issuer,
        issuer["attributes"]: attributes,
    }
    for item in attributes["items"]:
        routes[item["href"]] = revisions[item["id"]]
    return routes


@pytest.mark.parametrize("base", [
    pytest.param(PILOT_BASE, id="base-default-port"),
    pytest.param(PILOT_BASE + ":443", id="base-explicit-443"),
])
def test_the_recorded_pilot_registry_resolves_end_to_end_through_the_real_client(base: str) -> None:
    routes = _recorded_registry()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        body = routes.get(str(request.url))
        return httpx.Response(200, json=body) if body is not None else httpx.Response(404, json={})

    client = _client(handler)
    try:
        resolver = DidEbsiResolver(
            client.get_json, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=base)
        assert resolver.resolve(DID).id == DID
        record = resolver.issuer_record(DID)
        assert record.has_attributes and len(record.accreditations) == 3
        assert len(seen) == 1 + 1 + 1 + 3          # DID, issuer, listing, 3 revision hrefs
        assert set(seen) <= set(routes)
    finally:
        client.close()


@pytest.mark.parametrize("base", [PILOT_BASE + ":8443", PILOT_BASE + ":9200", PILOT_BASE + ":0"])
def test_a_resolver_base_on_another_port_is_refused_at_the_first_fetch(base: str) -> None:
    # `base` is the listing's own origin, so the adapter pin passes every hop it builds from
    # it. The client is what refuses, at the first fetch, with nothing sent.
    rec = Recorder()
    client = _client(rec)
    try:
        resolver = DidEbsiResolver(
            client.get_json, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=base)
        with pytest.raises(HttpForbiddenHost, match=r"port \d+ not allowed") as exc_info:
            resolver.issuer_record(DID)
        assert type(exc_info.value) is HttpForbiddenHost
        with pytest.raises(HttpForbiddenHost, match=r"port \d+ not allowed") as exc_info:
            resolver.resolve(DID)
        assert type(exc_info.value) is HttpForbiddenHost
        assert rec.requests == []
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# What stays refused, with the message of the rule that refuses it
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url,match", [
    # scheme, including a downgrade on the right host and port
    pytest.param(f"http://{HOST}/x", "non-https", id="http"),
    pytest.param(f"http://{HOST}:443/x", "non-https", id="http-on-443"),
    pytest.param(f"HTTP://{HOST}:80/x", "non-https", id="http-80"),
    pytest.param(f"ftp://{HOST}/x", "non-https", id="ftp"),
    pytest.param(f"wss://{HOST}/x", "non-https", id="wss"),
    pytest.param(f"//{HOST}/x", "non-https", id="scheme-relative"),
    pytest.param(f"{HOST}/x", "non-https", id="no-scheme"),
    pytest.param("/trusted-issuers-registry/v5/issuers/x", "non-https", id="path-only"),
    # host
    pytest.param("https://evil.example/x", "host not in allow-list", id="other-host"),
    pytest.param("https://evil.example:443/x", "host not in allow-list", id="other-host-443"),
    pytest.param(f"https://{HOST}.evil.example/x", "host not in allow-list", id="suffix"),
    pytest.param(f"https://evil.{HOST}/x", "host not in allow-list", id="subdomain"),
    pytest.param(f"https://{HOST}./x", "host not in allow-list", id="trailing-dot"),
    pytest.param(f"https://{HOST}.:443/x", "host not in allow-list", id="trailing-dot-443"),
    pytest.param(f"https://{HOST}\\@evil.example/x", "host not in allow-list",
                 id="backslash-then-at-reads-evil-host"),
    pytest.param(f"https://{HOST}:443@evil.example/x", "host not in allow-list",
                 id="port-looking-userinfo-reads-evil-host"),
    pytest.param(f"https://{HOST}%2f@evil.example/x", "host not in allow-list",
                 id="percent-escaped-slash"),
    pytest.param("https:///x", "host not in allow-list", id="empty-host"),
    pytest.param(f"https:{HOST}/x", "host not in allow-list", id="no-slashes"),
    # IPv6 literals: a name that is not on the list, with or without a port
    pytest.param("https://[::1]/x", "host not in allow-list", id="ipv6-loopback"),
    pytest.param("https://[::1]:443/x", "host not in allow-list", id="ipv6-loopback-443"),
    pytest.param("https://[::1]:8443/x", "host not in allow-list", id="ipv6-loopback-8443"),
    pytest.param("https://[::ffff:127.0.0.1]/x", "host not in allow-list", id="ipv6-mapped"),
    pytest.param("https://[2001:db8::1]:8443/x", "host not in allow-list", id="ipv6-doc-8443"),
    # unreadable
    pytest.param(f"https://{HOST}:99999/x", "does not parse", id="port-out-of-range"),
    pytest.param(f"https://{HOST}:abc/x", "does not parse", id="port-not-numeric"),
    pytest.param(f"https://{HOST}:443:443/x", "does not parse", id="two-ports"),
    pytest.param("https://[::1/x", "does not parse", id="broken-ipv6"),
    pytest.param("https://::1/x", "does not parse", id="unbracketed-ipv6"),
    pytest.param(f"https://{HOST}:443\\x", "does not parse", id="backslash-after-port"),
    pytest.param(f"https://{HOST}/x\ty", "not visible ASCII", id="tab"),
    pytest.param(f"https://{HOST}/x y", "not visible ASCII", id="space"),
    pytest.param(f" https://{HOST}/x", "not visible ASCII", id="leading-space"),
    pytest.param(f"https://{HOST}/x\x00y", "not visible ASCII", id="nul"),
])
def test_what_the_guard_already_refused_still_is_with_its_own_message(url: str, match: str) -> None:
    rec = Recorder()
    c = _client(rec)
    _refused(c, url, match=match)
    assert rec.requests == []


def test_a_host_name_in_brackets_never_reaches_the_transport() -> None:
    # `[name]` is not an IPv6 literal. Whether `urlparse` rejects it depends on the
    # interpreter: where it does, the guard says "does not parse"; where it does not, it
    # reads the host `name`, the guard admits, and httpx raises `InvalidURL`, which
    # `get_json` maps to `HttpForbiddenHost`. Either way, that class and no request.
    rec = Recorder()
    c = _client(rec)
    with pytest.raises(HttpForbiddenHost) as exc_info:
        c.get_json(f"https://[{HOST}]/x")
    assert type(exc_info.value) is HttpForbiddenHost
    assert rec.requests == []


# --------------------------------------------------------------------------- #
# ASCII-only hosts: xn-- A-labels in, U-labels never converted (ascii-only-hosts policy)
# --------------------------------------------------------------------------- #

def test_an_a_label_host_is_admitted_when_listed_and_a_u_label_is_not_converted() -> None:
    rec = Recorder()
    c = _client(rec, hosts=("xn--bcher-kva.example",))
    assert c.get_json("https://xn--bcher-kva.example/x") == {"ok": True}
    assert c.get_json("https://XN--BCHER-KVA.example:443/x") == {"ok": True}
    assert len(rec.requests) == 2
    _refused(c, "https://xn--bcher-kva.example:8443/x", match="port 8443 not allowed")
    # The U-label spelling is refused as not ASCII, before `urlparse` and before any IDNA
    # conversion: it is never turned into the listed A-label.
    _refused(c, "https://bücher.example/x", match="not visible ASCII")
    assert len(rec.requests) == 2


@pytest.mark.parametrize("url", ["https:///x", "https://:443/x", f"https:{HOST}/x", "https://"])
def test_an_empty_allow_list_entry_never_admits_a_url_without_a_host(url: str) -> None:
    # The reader says "" for a URL that names no host; that must not match a "" entry.
    rec = Recorder()
    c = _client(rec, hosts=("",))
    _refused(c, url, match="host not in allow-list: None")
    assert rec.requests == []


def test_a_u_label_allow_list_entry_never_matches_its_a_label() -> None:
    rec = Recorder()
    c = _client(rec, hosts=("bücher.example",))
    _refused(c, "https://xn--bcher-kva.example/x", match="host not in allow-list")
    _refused(c, "https://bücher.example/x", match="not visible ASCII")
    assert rec.requests == []


@pytest.mark.parametrize("url", [
    pytest.param(f"https://{HOST}：8443/x", id="fullwidth-colon-port"),
    pytest.param(f"https://{HOST}／evil/x", id="fullwidth-solidus"),
    pytest.param(f"https://{HOST}‥/x", id="two-dot-leader"),
    pytest.param("https://api-pilot。ebsi。eu/x", id="ideographic-full-stop"),
    pytest.param(f"https://{HOST}/x/é", id="non-ascii-path"),
    pytest.param(f"https://{HOST}́/x", id="combining-acute"),
    pytest.param(f"https://{HOST}:٤٤٣/x", id="arabic-indic-443"),
    pytest.param(f"https://①{HOST}/x", id="circled-digit"),
])
def test_non_ascii_urls_are_refused_as_not_visible_ascii(url: str) -> None:
    rec = Recorder()
    c = _client(rec)
    _refused(c, url, match="not visible ASCII")
    assert rec.requests == []


# --------------------------------------------------------------------------- #
# IPv6 literals as listed hosts: the same 443-only rule
# --------------------------------------------------------------------------- #

def test_a_listed_ipv6_literal_is_admitted_on_443_only() -> None:
    rec = Recorder()
    c = _client(rec, hosts=("::1",))
    assert c.get_json("https://[::1]/x") == {"ok": True}
    assert c.get_json("https://[::1]:443/x") == {"ok": True}
    assert len(rec.requests) == 2
    for port in (":0", ":80", ":8443"):
        _refused(c, f"https://[::1]{port}/x", match=r"port \d+ not allowed")
    _refused(c, "https://[::2]/x", match="host not in allow-list")
    _refused(c, "https://u@[::1]/x", match="carries userinfo")
    assert len(rec.requests) == 2


# --------------------------------------------------------------------------- #
# Redirects stay off: the guard never sees a Location, so this is the defence
# --------------------------------------------------------------------------- #

def _real_client_over(monkeypatch: pytest.MonkeyPatch, handler: Any) -> EbsiHttpClient:
    """The client as ``__init__`` builds it (``follow_redirects=False`` and all), with only the
    transport replaced: ``httpx.Client`` is wrapped for the construction."""
    real = httpx.Client

    def build(*args: Any, **kwargs: Any) -> httpx.Client:
        return real(*args, transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(httpx, "Client", build)
    return EbsiHttpClient(allowed_hosts={HOST})


def test_the_production_client_does_not_follow_redirects() -> None:
    c = EbsiHttpClient(allowed_hosts={HOST})
    try:
        assert c._client.follow_redirects is False
    finally:
        c.close()


@pytest.mark.parametrize("status", [301, 302, 307, 308])
@pytest.mark.parametrize("location", [
    pytest.param(f"https://{HOST}:8443/x", id="same-host-other-port"),
    pytest.param("/elsewhere", id="relative"),
    pytest.param("//evil.example/x", id="scheme-relative"),
    pytest.param(f"http://{HOST}/x", id="scheme-downgrade"),
    pytest.param("https://evil.example/x", id="other-host"),
])
def test_a_redirect_is_a_failed_read_and_is_never_followed(
        monkeypatch: pytest.MonkeyPatch, status: int, location: str) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, headers={"Location": location})

    c = _real_client_over(monkeypatch, handler)
    try:
        with pytest.raises(HttpError, match=f"unexpected status {status}") as exc_info:
            c.get_json(f"https://{HOST}/x")
        assert type(exc_info.value) is HttpError and exc_info.value.status == status
        # the Location is never fetched
        assert [str(r.url) for r in requests] == [f"https://{HOST}/x"]
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# Parity: the guard and the adapter pin read a URL the same way
# --------------------------------------------------------------------------- #

PIN = _origin(PILOT_BASE)          # https://api-pilot.ebsi.eu:443

# (url, kind): kind "same" -> the guard admits exactly what the pin does;
# "userinfo" -> the pin ignores userinfo and the guard refuses it;
# "long" -> the pin caps a URL at 8 KiB and the guard has no cap (a documented gap).
PARITY_URLS = [
    # on the pin's origin
    *[(u, "same") for u in (
        f"https://{HOST}", f"https://{HOST}/x", f"https://{HOST}:443/x", f"https://{HOST}:0443/x",
        f"https://{HOST}:00443/x", f"https://{HOST}:/x", f"HTTPS://{HOST.upper()}:443/x",
        f"https://{HOST}/x?a=1#f", f"https://{HOST}?q", f"https://{HOST}/a@b",
    )],
    # off it: port
    *[(f"https://{HOST}{p}/x", "same") for p in (
        ":0", ":00", ":1", ":80", ":444", ":4430", ":8443", ":9200", ":65535", ":65536",
        ":99999", ":-1", ":+443", ":abc", ":4_43", ": 443", ":443:443",
    )],
    # off it: scheme, host
    *[(u, "same") for u in (
        f"http://{HOST}", f"http://{HOST}:443/x", f"ftp://{HOST}/x", f"//{HOST}/x", f"{HOST}/x",
        "https://api.ebsi.eu/x", "https://evil.example/x", f"https://{HOST}./x",
        f"https://{HOST}.evil.example/x", f"https://{HOST}\\@evil.example/x",
        f"https://{HOST}:443@evil.example/x", "https://[::1]/x", "https://[::1]:443/x",
        "https://[::1/x", f"https://[{HOST}]/x", "https:///x", f"https:{HOST}/x",
        f"https://{HOST}/x\ty", f"https://{HOST}/x y", f"https://{HOST}́/x",
        f"https://{HOST}：8443/x", f"https://bücher.example/{HOST}",
    )],
    # userinfo on the pin's origin: the guard refuses, the pin does not look
    *[(u, "userinfo") for u in (
        f"https://u@{HOST}/x", f"https://u:p@{HOST}/x", f"https://@{HOST}/x",
        f"https://:@{HOST}/x", f"https://u@{HOST}:443/x", f"https://evil.example\\@{HOST}/x",
    )],
    # userinfo off the origin: both refuse
    *[(u, "same") for u in (
        f"https://u@{HOST}:8443/x", "https://u@evil.example/x", f"http://u@{HOST}/x",
    )],
    # over 8 KiB
    (f"https://{HOST}/" + "a" * 9000, "long"),
]


@pytest.mark.parametrize("url,kind", [pytest.param(u, k, id=f"{k}-{i}")
                                      for i, (u, k) in enumerate(PARITY_URLS)])
def test_the_guard_admits_a_url_exactly_when_the_pin_says_it_is_on_the_origin(
        guard_client: EbsiHttpClient, url: str, kind: str) -> None:
    on_pin = _on_origin(url, PIN)
    admitted = _admits(guard_client, url)
    if kind == "same":
        assert admitted == on_pin, url
    elif kind == "userinfo":
        assert on_pin is True and admitted is False, url
    else:
        assert kind == "long"
        assert on_pin is False and admitted is True, url


def test_the_parity_table_has_both_outcomes_in_every_kind(guard_client: EbsiHttpClient) -> None:
    # Guard against a table that passes by agreeing on "refused" everywhere.
    same = [u for u, k in PARITY_URLS if k == "same"]
    assert sum(_admits(guard_client, u) for u in same) >= 8
    assert sum(not _admits(guard_client, u) for u in same) >= 30


# --------------------------------------------------------------------------- #
# Fuzz: whatever the guard admits, httpx would fetch from the listed host on 443
# --------------------------------------------------------------------------- #

# Authority-significant characters, digits, a tab, a space, a non-ASCII letter, and port words.
ATOMS = [":", "@", "[", "]", "/", "\\", "?", "#", "%", ".", "0", "4", "3", "8", "9", "\t", " ",
         "é", "+", "-", "_", "u", "443", "8443", "00", "%40", "%2f", "xn--", HOST,
         "evil.example", "::1", "٤"]
JUNK = st.lists(st.sampled_from(ATOMS), max_size=8).map("".join)
SCHEMES = st.sampled_from(["https", "https", "https", "HTTPS", "http"])
PORT_SPELLINGS = st.one_of(
    st.integers(0, 70000).map(str),
    st.integers(0, 70000).map(lambda n: str(n).zfill(7)),
    st.sampled_from(["", "+443", "-1", "0x1bb", "4_43", "443 ", " 443", "443.0", "٤٤٣",
                     "443\t", "\t443", "+8443", "-443", "00", "000443", "0443"]),
    st.text(alphabet="0123456789+-_ x", max_size=8),
)
TAILS = st.sampled_from(["", "/", "/x", "?q=1", "#f", "/a@b", "?u=a@b", "/\\x"])

FUZZ_URLS = st.one_of(
    st.builds(lambda s, pre, mid, suf: f"{s}://{pre}{HOST}{mid}{suf}",
              SCHEMES, st.one_of(st.just(""), JUNK), JUNK, JUNK),
    st.builds(lambda s, port, tail: f"{s}://{HOST}:{port}{tail}", SCHEMES, PORT_SPELLINGS, TAILS),
    st.builds(lambda s, user, port, tail: f"{s}://{user}@{HOST}:{port}{tail}",
              SCHEMES, st.sampled_from(["", "u", "u:p", ":", ":p", "a%40b", "evil.example\\"]),
              PORT_SPELLINGS, TAILS),
    # Weighted toward the ADMITTED side: a default-port spelling, then junk after the
    # authority, where an `@`, `:`, `\` or `%` must not be read as userinfo or a port.
    st.builds(lambda port, sep, junk: f"https://{HOST}{port}{sep}{junk}",
              st.sampled_from(["", ":", ":443", ":0443", ":00443"]),
              st.sampled_from(["/", "?", "#", "/x?", "/x#"]), JUNK),
)


def _authority_has_at(url: str) -> bool:
    """An independent reading of "the authority holds userinfo": an ``@`` between ``://`` and
    the first ``/``, ``?`` or ``#``. It does not go through ``urlparse``."""
    rest = url.split("://", 1)[1] if "://" in url else ""
    for stop in "/?#":
        rest = rest.split(stop, 1)[0]
    return "@" in rest


@settings(max_examples=600, deadline=None)
@example(f"https://{HOST}:+443/x")
@example(f"https://{HOST}:-1/x")
@example(f"https://{HOST}:65536/x")
@example(f"https://{HOST}:4_43/x")
@example(f"https://{HOST}: 443/x")
@example(f"https://{HOST}:0443/x")
@example(f"https://{HOST}:/x")
@example(f"https://u@{HOST}:8443/x")
@example(f"https://evil.example\\@{HOST}/x")
@given(FUZZ_URLS)
def test_fuzz_what_the_guard_admits_httpx_fetches_from_the_listed_host_on_443(
        guard_client: EbsiHttpClient, url: str) -> None:
    admitted = _admits(guard_client, url)        # raises on anything but HttpForbiddenHost
    try:
        read = httpx.URL(url)                    # the oracle, not the subject
    except Exception:
        return                                   # httpx cannot read it: nothing to compare
    if admitted:
        assert read.scheme == "https", url
        assert read.host == HOST, url
        assert read.port in (None, 443), url
        assert read.userinfo == b"", url


@settings(max_examples=600, deadline=None)
@given(FUZZ_URLS)
def test_fuzz_the_guard_and_the_pin_agree_except_on_userinfo(
        guard_client: EbsiHttpClient, url: str) -> None:
    admitted = _admits(guard_client, url)
    assert admitted == (_on_origin(url, PIN) and not _authority_has_at(url)), url


@pytest.mark.parametrize("spelling", [
    "+443", "+8443", "-1", "65536", "4_43", " 443", "443 ", "0x1bb", "٤٤٣"])
def test_ports_the_two_parsers_read_differently_land_on_the_refused_side(
        guard_client: EbsiHttpClient, spelling: str) -> None:
    # `urlparse` and httpx disagree about these on some interpreters (3.14 raises on `+443`,
    # `4_43` and a space; older ones read them). Whatever this interpreter does, the guard
    # either refuses the URL or what httpx fetches is the default port: never another one.
    url = f"https://{HOST}:{spelling}/x"
    if _admits(guard_client, url):
        assert httpx.URL(url).port in (None, 443)
    else:
        with pytest.raises(HttpForbiddenHost):
            guard_client._guard_host(url)


# --------------------------------------------------------------------------- #
# The shared reader (openvc_ebsi._url): imported inside each test
# --------------------------------------------------------------------------- #

def test_read_origin_scheme_host_port() -> None:
    from openvc_ebsi._url import Origin, read_origin
    assert read_origin(f"https://{HOST}/x") == Origin("https", HOST, 443)
    assert read_origin(f"HTTPS://{HOST.upper()}:443/x") == ("https", HOST, 443)
    assert read_origin(f"https://{HOST}:") == ("https", HOST, 443)
    assert read_origin(f"https://{HOST}:0443") == ("https", HOST, 443)
    assert read_origin(f"https://{HOST}:8443") == ("https", HOST, 8443)
    assert read_origin(f"https://u:p@{HOST}:8443") == ("https", HOST, 8443)     # userinfo ignored
    assert read_origin("https://[::1]:9/x") == ("https", "::1", 9)
    assert read_origin("https:///x") == ("https", "", 443)                      # no host: ""


def test_read_origin_only_an_absent_https_port_is_filled_in() -> None:
    from openvc_ebsi._url import read_origin
    assert read_origin(f"https://{HOST}:0")[2] == 0          # `is None`, never truthiness
    assert read_origin(f"https://{HOST}:00")[2] == 0
    assert read_origin(f"http://{HOST}")[2] is None          # http has no default filled in
    assert read_origin(f"ftp://{HOST}:21")[2] == 21
    assert read_origin(f"{HOST}/x") == ("", "", None)


@pytest.mark.parametrize("url", [
    f"https://{HOST}/x\ty", f"https://{HOST}/x y", f"https://{HOST}́/x", f"https://{HOST}/\x7f",
    "\x00", "é", " ",
])
def test_read_origin_refuses_what_is_not_visible_ascii_with_its_own_class(url: str) -> None:
    from openvc_ebsi._url import UrlDoesNotParse, UrlError, UrlNotVisibleAscii, read_origin
    with pytest.raises(UrlNotVisibleAscii) as exc_info:
        read_origin(url)
    assert type(exc_info.value) is UrlNotVisibleAscii
    assert isinstance(exc_info.value, UrlError) and not isinstance(exc_info.value, UrlDoesNotParse)
    # not a ValueError: a caller that forgets to map it is not swallowed by `except ValueError`
    assert not isinstance(exc_info.value, ValueError)


@pytest.mark.parametrize("url", [
    f"https://{HOST}:99999/x", f"https://{HOST}:abc/x", "https://[::1/x", f"https://[{HOST}]/x",
    f"https://{HOST}:443:443/x",
])
def test_read_origin_refuses_what_urlparse_cannot_read_with_its_own_class(url: str) -> None:
    from openvc_ebsi._url import UrlDoesNotParse, UrlError, UrlNotVisibleAscii, read_origin
    with pytest.raises(UrlDoesNotParse) as exc_info:
        read_origin(url)
    assert type(exc_info.value) is UrlDoesNotParse
    assert isinstance(exc_info.value, UrlError)
    assert not isinstance(exc_info.value, UrlNotVisibleAscii)
    assert type(exc_info.value.__cause__) is ValueError      # urlparse's own error is kept


def test_read_origin_checks_ascii_before_urlparse(monkeypatch: pytest.MonkeyPatch) -> None:
    # On CPython <= 3.12 urlparse NFKC-normalizes a non-ASCII netloc in quadratic time.
    from openvc_ebsi import _url

    def no_urlparse(url: str) -> None:
        raise AssertionError("urlparse reached")
    monkeypatch.setattr(_url, "urlparse", no_urlparse)
    with pytest.raises(_url.UrlNotVisibleAscii):
        _url.read_origin(f"https://{HOST}́/x")
    with pytest.raises(_url.UrlNotVisibleAscii):
        _url.carries_userinfo(f"https://u@{HOST}́/x")


@pytest.mark.parametrize("url,expected", [
    (f"https://{HOST}/x", False),
    (f"https://{HOST}", False),
    (f"https://u@{HOST}/x", True),
    (f"https://u:p@{HOST}/x", True),
    (f"https://@{HOST}/x", True),
    (f"https://:@{HOST}/x", True),
    (f"https://:p@{HOST}", True),
    (f"https://{HOST}/a@b", False),
    (f"https://{HOST}?u=a@b", False),
    (f"https://{HOST}#@b", False),
    (f"https://{HOST}:443/@", False),
    (f"https://u@{HOST}:8443", True),
])
def test_carries_userinfo(url: str, expected: bool) -> None:
    from openvc_ebsi._url import carries_userinfo
    assert carries_userinfo(url) is expected


def test_the_reader_and_the_formatters_are_the_same_function_for_guard_and_pin() -> None:
    # The pin's string is the reader's tuple, formatted: `https://host:443` / `http://host:`.
    from openvc_ebsi._url import read_origin
    for url in (f"https://{HOST}", f"https://{HOST}:8443/x", f"http://{HOST}", f"https://{HOST}:0",
                "https://[::1]:7", f"HTTPS://{HOST.upper()}"):
        scheme, host, port = read_origin(url)
        assert _origin(url) == f"{scheme}://{host}:{'' if port is None else port}"
    assert _origin(f"https://{HOST}") == f"https://{HOST}:443"
    assert _origin(f"http://{HOST}") == f"http://{HOST}:"
