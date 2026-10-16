"""
tests/test_ebsi_address_guard.py — the opt-in resolved-address guard of the EBSI client (#322).

The client's host allow-list matches a NAME and trusts DNS for it (threat model R4). With
``address_guard=AddressGuard()`` each request resolves the name, refuses the host if ANY
answer is not globally routable, and connects to the validated address while the TLS server
name, the certificate check and ``Host`` stay the name.

Negatives first. Every refusal below asserts the EXACT class (``type(exc) is X``), that ZERO
requests reached the transport, how often the resolver was called, and that nothing was
cached, so none of them can pass on an earlier failure. The MockTransport tests show what the
transport is handed; the loopback TLS tests at the end show what a real handshake does with it
(SNI, certificate check against the NAME, and no connection reuse across names).

Address classification is the standard library's ``ipaddress`` through
``openvc.fetch.ip_is_forbidden``; the table below was measured, with zero differences, on
CPython 3.10.20, 3.11.15, 3.12.13, 3.13.16, 3.14.8 and 3.15.0rc3. Not pinned, because they
differ by patch level or are not forbidden: ``::ffff:8.8.8.8`` (a mapped PUBLIC address),
``192.88.99.1``, ``192.0.0.9`` / ``192.0.0.10`` and ``2001:20::1``.

Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

httpx = pytest.importorskip("httpx")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import openvc.fetch  # noqa: E402
import openvc_ebsi.http as ebsi_http  # noqa: E402
from openvc.errors import OpenvcError  # noqa: E402
from openvc.fetch import ip_is_forbidden  # noqa: E402
from openvc_ebsi.errors import EbsiError  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    AddressGuard,
    EbsiHttpClient,
    HttpAddressGuardUnavailable,
    HttpAddressResolutionFailed,
    HttpError,
    HttpForbiddenAddress,
    HttpForbiddenHost,
    HttpNotFound,
    HttpTransientExhausted,
    RetryPolicy,
    for_ebsi,
)

HOST = "api-pilot.ebsi.eu"
OTHER_HOST = "api-conformance.ebsi.eu"
URL = f"https://{HOST}/x"
PUBLIC = "93.184.216.34"
PUBLIC_B = "1.1.1.1"
PUBLIC_V6 = "2606:2800:220:1::1"

# Zero backoff so the retry-loop tests do not sleep.
FAST_RETRY = RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)

_REAL_GETPROXIES = urllib.request.getproxies


@pytest.fixture(autouse=True)
def _no_environment_proxy(monkeypatch):
    """A developer machine may have a system proxy (``getproxies`` reads the macOS and
    Windows settings); a guarded client refuses to be built behind one. The proxy tests
    set their own."""
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #

class Resolver:
    """A resolver that records its calls. Each argument is the answer for one call (a list
    of address strings, or an exception to raise); the last one repeats."""

    def __init__(self, *answers: Any) -> None:
        self.calls: list[tuple[str, int]] = []
        self._answers = list(answers)

    def __call__(self, host: str, port: int) -> Any:
        self.calls.append((host, port))
        answer = self._answers[min(len(self.calls), len(self._answers)) - 1]
        if isinstance(answer, BaseException):
            raise answer
        return answer


class Wire:
    """A MockTransport handler that records every request it is handed. Each argument is the
    response for one request (an ``httpx.Response``, an exception to raise, or a callable);
    the last one repeats."""

    def __init__(self, *responses: Any) -> None:
        self.requests: list[httpx.Request] = []
        self._responses = list(responses) or [httpx.Response(200, json={"ok": True})]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self._responses[min(len(self.requests), len(self._responses)) - 1]
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item(request)
        return item


def _any_port(client: EbsiHttpClient) -> None:
    """Take the name check as a host-only check: https and a listed host, any port, userinfo
    allowed. The tests that use it are about how the PINNED request is built from such a URL
    (a port, userinfo, a loopback test server), whatever the name guard in front of it admits;
    the tests about the name guard itself use the client's own."""
    def host_only(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in client._allowed:
            raise HttpForbiddenHost("host not in allow-list", url=url)
    client._guard_host = host_only


def _guarded(wire: Wire, resolver: Any, *, hosts: tuple[str, ...] = (HOST,),
             any_port: bool = False, **kwargs: Any) -> EbsiHttpClient:
    kwargs.setdefault("retry", FAST_RETRY)
    client = EbsiHttpClient(allowed_hosts=set(hosts),
                            address_guard=AddressGuard(resolver=resolver), **kwargs)
    client._client = httpx.Client(transport=httpx.MockTransport(wire))
    if any_port:
        _any_port(client)
    return client


def _unguarded(wire: Wire, **kwargs: Any) -> EbsiHttpClient:
    kwargs.setdefault("retry", FAST_RETRY)
    client = EbsiHttpClient(allowed_hosts={HOST}, **kwargs)
    client._client = httpx.Client(transport=httpx.MockTransport(wire))
    return client


def _refused(client: EbsiHttpClient, wire: Wire, resolver: Resolver, url: str = URL,
             calls: int = 1) -> HttpForbiddenAddress:
    """Run a get that must be refused by the address guard, with every invariant of a refusal."""
    with pytest.raises(HttpForbiddenAddress) as info:
        client.get_json(url)
    assert type(info.value) is HttpForbiddenAddress
    assert wire.requests == []                      # nothing reached the transport
    assert len(resolver.calls) == calls             # and a refusal is never retried
    assert client._cache.get(url) is None           # nor cached
    assert info.value.url == url                    # the ORIGINAL URL, not a pinned one
    return info.value


# --------------------------------------------------------------------------- #
# The address table: what the guard refuses, and what it lets through
# --------------------------------------------------------------------------- #

# (class, address). The first thirteen are the table of tests/test_fetch.py::test_forbidden_ips,
# copied; the rest is every class #322 names. Note the two ways is_global alone is wrong:
# 224.0.0.1 / ff0e::1 report is_global=True (only is_multicast catches them) and
# 64:ff9b::808:808 / ::808:808 report is_global=True too (only is_reserved does).
FORBIDDEN = [
    ("private", "10.0.0.1"), ("private", "172.16.0.1"), ("private", "192.168.1.1"),
    ("loopback", "127.0.0.1"), ("loopback", "::1"),
    ("link-local / cloud metadata", "169.254.169.254"), ("link-local", "fe80::1"),
    ("link-local with scope id", "fe80::1%eth0"),
    ("unspecified", "0.0.0.0"), ("multicast", "224.0.0.1"),
    ("CGNAT", "100.64.0.1"), ("IPv4-mapped CGNAT", "::ffff:100.64.0.1"),
    ("IPv4-mapped private", "::ffff:10.0.0.1"),
    # the rest of the classes
    ("this network 0/8", "0.1.2.3"), ("private", "172.31.255.255"),
    ("loopback", "127.1.2.3"), ("link-local", "169.254.0.1"),
    ("unspecified", "::"), ("unique-local", "fc00::1"), ("unique-local", "fd00::1"),
    ("multicast", "239.255.255.255"), ("multicast", "ff02::1"), ("multicast", "ff0e::1"),
    ("CGNAT", "100.127.255.255"),
    ("benchmarking", "198.18.0.1"), ("benchmarking", "198.19.255.255"),
    ("benchmarking v6", "2001:2::1"),
    ("documentation", "192.0.2.1"), ("documentation", "198.51.100.1"),
    ("documentation", "203.0.113.1"), ("documentation", "2001:db8::1"),
    ("documentation", "3fff::1"),
    ("IETF protocol assignments", "192.0.0.1"),
    ("reserved", "240.0.0.1"), ("broadcast", "255.255.255.255"), ("discard-only", "100::1"),
    ("IPv4-mapped loopback", "::ffff:127.0.0.1"),
    ("IPv4-mapped metadata", "::ffff:169.254.169.254"),
    ("IPv4-mapped unspecified", "::ffff:0.0.0.0"),
    ("IPv4-mapped private", "::ffff:192.168.1.1"),
    ("IPv4-compatible loopback", "::7f00:1"), ("IPv4-compatible private", "::a00:1"),
    ("IPv4-compatible PUBLIC embedded", "::808:808"), ("IPv4-compatible dotted", "::8.8.8.8"),
    ("NAT64 loopback", "64:ff9b::7f00:1"), ("NAT64 private", "64:ff9b::a00:1"),
    ("NAT64 metadata", "64:ff9b::a9fe:a9fe"), ("NAT64 PUBLIC embedded", "64:ff9b::808:808"),
    ("NAT64 local-use private", "64:ff9b:1::a00:1"),
    ("NAT64 local-use PUBLIC embedded", "64:ff9b:1::808:808"),
    ("6to4 loopback", "2002:7f00:1::"), ("6to4 private", "2002:a00:1::"),
    ("6to4 metadata", "2002:a9fe:a9fe::"), ("6to4 PUBLIC embedded", "2002:808:808::1"),
    ("6to4", "2002::1"),
    ("Teredo", "2001:0:4136:e378:8000:63bf:3fff:fdd2"), ("Teredo", "2001::1"),
    # fec0::/10 (RFC 3879, deprecated site-local): is_global=True and no other flag, only
    # is_site_local catches it (both ends of the prefix).
    ("site-local", "fec0::1"), ("site-local", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
]

ALLOWED = [PUBLIC, PUBLIC_B, "8.8.8.8", PUBLIC_V6, "2001:4860:4860::8888", "2a00:1450:4001::1"]


def test_the_public_function_is_the_private_one():
    assert openvc.fetch.ip_is_forbidden is openvc.fetch._ip_is_forbidden
    assert "ip_is_forbidden" in openvc.fetch.__all__


@pytest.mark.parametrize("label, address", FORBIDDEN, ids=[a for _, a in FORBIDDEN])
def test_the_classifier_forbids(label, address):
    assert ip_is_forbidden(address) is True, label


@pytest.mark.parametrize("address", ALLOWED)
def test_the_classifier_allows_public_addresses(address):
    assert ip_is_forbidden(address) is False


@pytest.mark.parametrize("label, address", FORBIDDEN, ids=[a for _, a in FORBIDDEN])
def test_a_forbidden_answer_is_refused_without_a_request(label, address):
    resolver, wire = Resolver([address]), Wire()
    client = _guarded(wire, resolver)
    _refused(client, wire, resolver)


@pytest.mark.parametrize("answer", [
    [PUBLIC, "10.0.0.1"], ["10.0.0.1", PUBLIC],
    [PUBLIC, PUBLIC_B, "169.254.169.254"], ["169.254.169.254", PUBLIC, PUBLIC_B],
    [PUBLIC, PUBLIC_V6, "::1"], ["::1", PUBLIC_V6, PUBLIC],
    [PUBLIC, "64:ff9b::808:808"],
])
def test_any_forbidden_address_rejects_the_host_in_either_order(answer):
    resolver, wire = Resolver(answer), Wire()
    client = _guarded(wire, resolver)
    _refused(client, wire, resolver)


def test_the_message_names_the_host_and_the_address_and_is_bounded():
    resolver, wire = Resolver([PUBLIC, "10.0.0.1"]), Wire()
    client = _guarded(wire, resolver)
    error = _refused(client, wire, resolver)
    assert HOST in str(error) and "10.0.0.1" in str(error)

    hostile, wire = Resolver(["A" * 1_000_000]), Wire()
    error = _refused(_guarded(wire, hostile), wire, hostile)
    assert len(str(error)) < 600


def test_the_error_is_a_host_error_an_ebsi_error_and_an_openvc_error():
    assert issubclass(HttpForbiddenAddress, HttpForbiddenHost)
    assert issubclass(HttpForbiddenAddress, HttpError)
    assert issubclass(HttpForbiddenAddress, EbsiError)
    assert issubclass(HttpForbiddenAddress, OpenvcError)
    for cls in (HttpAddressResolutionFailed, HttpAddressGuardUnavailable):
        assert issubclass(cls, HttpError) and not issubclass(cls, HttpForbiddenHost)


# --- unparseable and hostile answers ------------------------------------------------------

@pytest.mark.parametrize("answer", [
    "", "not-an-ip", "1.2.3", "1.2.3.4.5", "999.1.1.1", "0x7f.0.0.1", "127.1", "2130706433",
    "::g", "[::1]", " 8.8.8.8", "8.8.8.8 ", "8.8.8.8\n", "8.8.8.8\x00", "8.8.8.8/32",
    "٨.٨.٨.٨",                                   # Arabic-Indic digits: not ASCII
    "8.8.8.8" + "0" * 200,                       # over-long
    "A" * 100_000,
    PUBLIC_V6 + "%eth0",                         # a PUBLIC address with a scope id
    None, 7, 1.5, b"8.8.8.8", ["8.8.8.8"], object(),
])
def test_an_answer_that_is_not_exactly_a_public_address_is_refused(answer):
    resolver, wire = Resolver([answer]), Wire()
    client = _guarded(wire, resolver)
    _refused(client, wire, resolver)


def test_one_bad_entry_among_good_ones_rejects_the_host():
    resolver, wire = Resolver([PUBLIC, "not-an-ip", PUBLIC_B]), Wire()
    _refused(_guarded(wire, resolver), wire, resolver)


def test_a_str_subclass_cannot_tell_the_parser_one_thing_and_the_classifier_another():
    # `ipaddress` reads a str subclass through its own __str__. One that says a forbidden
    # address the first time and a public one after would be parsed as the first and
    # classified as the second: the guard would return 10.0.0.1 as validated. The guard
    # reads the characters once (str.__str__), so it parses and classifies the same text.
    class Flip(str):
        said = 0

        def __str__(self) -> str:
            Flip.said += 1
            return "10.0.0.1" if Flip.said == 1 else PUBLIC

    resolver, wire = Resolver([Flip("10.0.0.1")]), Wire()
    _refused(_guarded(wire, resolver), wire, resolver)
    assert Flip.said == 0                          # its own __str__ was never consulted


# --- IP-literal hosts ----------------------------------------------------------------------

@pytest.mark.parametrize("host, url", [
    ("10.0.0.5", "https://10.0.0.5/x"),
    ("127.0.0.1", "https://127.0.0.1/x"),
    ("::1", "https://[::1]/x"),
    ("169.254.169.254", "https://169.254.169.254/latest/meta-data"),
    ("100.64.0.1", "https://100.64.0.1:8443/x"),
])
def test_an_allow_listed_ip_literal_is_classified_without_dns(host, url):
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver, hosts=(host,), any_port=True)
    _refused(client, wire, resolver, url, calls=0)         # the resolver was never called


@pytest.mark.parametrize("host", ["127.1", "0x7f.1", "2130706433", "127.0.1", "0x7f000001"])
def test_numeric_shorthand_hosts_are_refused_through_the_resolver(host):
    # ipaddress does not read these as addresses, so they reach the resolver; libc reads them
    # as 127.0.0.1 (measured on macOS; glibc not measured), and the guard sees that answer.
    resolver, wire = Resolver(["127.0.0.1"]), Wire()
    client = _guarded(wire, resolver, hosts=(host,))
    _refused(client, wire, resolver, f"https://{host}/x")


def test_a_public_ip_literal_host_is_pinned_to_itself():
    resolver, wire = Resolver(["10.0.0.1"]), Wire()          # would be refused, but is not asked
    client = _guarded(wire, resolver, hosts=(PUBLIC,), any_port=True)
    assert client.get_json(f"https://{PUBLIC}:8443/x") == {"ok": True}
    request = wire.requests[0]
    assert resolver.calls == []
    assert request.url.host == PUBLIC and request.url.port == 8443
    assert request.headers["host"] == f"{PUBLIC}:8443"
    assert request.extensions["sni_hostname"] == PUBLIC


def test_a_public_ipv6_literal_host_keeps_its_brackets_in_host():
    resolver, wire = Resolver([]), Wire()
    client = _guarded(wire, resolver, hosts=(PUBLIC_V6,), any_port=True)
    assert client.get_json(f"https://[{PUBLIC_V6}]:8443/x") == {"ok": True}
    request = wire.requests[0]
    assert request.headers["host"] == f"[{PUBLIC_V6}]:8443"
    assert request.extensions["sni_hostname"] == PUBLIC_V6


# --- ordering: the name check runs first and unchanged -------------------------------------

@pytest.mark.parametrize("url", [
    "https://evil.example/x",                                   # off the allow-list
    "https://api-pilot.ebsi.eu.evil.example/x",
    "https://issuer.example/.well-known/did.json",               # a did:web-style host
    "https://evil.example@api-pilot.ebsi.eu.evil.example/x",
    "https://api-pilot.ebsi.eu@evil.example/x",                  # userinfo naming an allowed host
])
def test_a_host_off_the_allow_list_is_the_name_guards_error_and_the_resolver_is_not_called(url):
    resolver, wire = Resolver(["10.0.0.1"]), Wire()
    client = _guarded(wire, resolver)
    with pytest.raises(HttpForbiddenHost) as info:
        client.get_json(url)
    assert type(info.value) is HttpForbiddenHost             # not HttpForbiddenAddress
    assert resolver.calls == [] and wire.requests == []


@pytest.mark.parametrize("url", [
    "http://api-pilot.ebsi.eu/x",                             # not https
    "ftp://api-pilot.ebsi.eu/x",
    "https://api-pilot.ebsi.eu/é",                            # not ASCII
    "https://api-pilot.ebsi.eu:99999/x",                      # port out of range
    "https://api-pilot.ebsi.eu:abc/x",
    "https://api-pilot.ebsi.eu/a b",                          # a space
    "https://api-pilot.ebsi.eu/a\tb",                         # a control character
    "https://[::1/x",                                         # unbalanced bracket
    "/x",
    "",
])
def test_non_https_non_ascii_and_unparseable_urls_keep_todays_error(url):
    resolver, wire = Resolver(["10.0.0.1"]), Wire()
    client = _guarded(wire, resolver)
    with pytest.raises(HttpForbiddenHost) as info:
        client.get_json(url)
    assert type(info.value) is HttpForbiddenHost
    assert resolver.calls == [] and wire.requests == []


def test_a_guarded_client_never_reaches_the_did_web_fetch(monkeypatch):
    def boom(*args: Any, **kwargs: Any) -> Any:           # pragma: no cover - must not run
        raise AssertionError("the did:web fetch was reached from the EBSI client")

    for name in ("_https_get", "_resolve_public_ips", "_https_fetch_guarded", "https_json_fetch"):
        monkeypatch.setattr(openvc.fetch, name, boom)
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver)
    assert client.get_json(URL) == {"ok": True}                       # the happy path
    with pytest.raises(HttpForbiddenHost) as info:                    # a did:web host
        client.get_json("https://issuer.example/.well-known/did.json")
    assert type(info.value) is HttpForbiddenHost
    assert len(wire.requests) == 1


# --------------------------------------------------------------------------- #
# What the transport is handed
# --------------------------------------------------------------------------- #

def test_rebinding_the_second_answer_is_checked_and_refused():
    resolver = Resolver([PUBLIC], ["10.0.0.1"])
    wire = Wire()
    client = _guarded(wire, resolver)
    url_1, url_2 = f"https://{HOST}/one", f"https://{HOST}/two"       # two cache misses
    assert client.get_json(url_1) == {"ok": True}
    with pytest.raises(HttpForbiddenAddress) as info:
        client.get_json(url_2)
    assert type(info.value) is HttpForbiddenAddress
    assert resolver.calls == [(HOST, 443), (HOST, 443)]               # once per attempt
    assert len(wire.requests) == 1                                     # none for the second
    assert client._cache.get(url_2) is None
    request = wire.requests[0]
    assert request.url.host == PUBLIC                                  # the validated literal
    assert request.headers["host"] == HOST                              # the NAME, in Host
    assert request.extensions["sni_hostname"] == HOST                   # and as the TLS name
    assert request.headers["connection"] == "close"
    assert all(r.url.host != HOST for r in wire.requests)               # never the name


def test_the_pinned_request_keeps_the_path_and_the_query_verbatim():
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver)
    client.get_json(f"https://{HOST}/did-registry/v5/identifiers/did:ebsi:zX?a=1&b=%2F#frag")
    request = wire.requests[0]
    assert request.url.raw_path == b"/did-registry/v5/identifiers/did:ebsi:zX?a=1&b=%2F"
    assert request.url.scheme == "https"
    assert request.url.host == PUBLIC                  # rebuilt around the validated address


def test_an_explicit_port_is_kept_in_the_pinned_url_and_in_host():
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver, any_port=True)
    client.get_json(f"https://{HOST}:8443/x")
    request = wire.requests[0]
    assert resolver.calls == [(HOST, 8443)]
    assert request.url.host == PUBLIC and request.url.port == 8443
    assert request.headers["host"] == f"{HOST}:8443"


def test_port_443_written_out_is_the_default_port():
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver)
    client.get_json(f"https://{HOST}:443/x")
    request = wire.requests[0]
    assert resolver.calls == [(HOST, 443)]
    assert request.headers["host"] == HOST                              # as httpx writes it


def test_port_zero_is_not_read_as_the_default_port():
    # `parsed.port or 443` would turn an explicit :0 into 443 (#253 keeps :0 off-origin).
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver, any_port=True)
    client.get_json(f"https://{HOST}:0/x")
    assert resolver.calls == [(HOST, 0)]
    assert wire.requests[0].url.port == 0 and wire.requests[0].headers["host"] == f"{HOST}:0"


def test_scheme_and_host_case_are_read_as_the_name_guard_reads_them():
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver)
    client.get_json("HTTPS://API-PILOT.EBSI.EU/x")
    request = wire.requests[0]
    assert resolver.calls == [(HOST, 443)]
    assert request.url.host == PUBLIC and request.url.scheme == "https"
    assert request.headers["host"] == HOST and request.extensions["sni_hostname"] == HOST


def test_an_ipv6_answer_is_bracketed_in_the_url_and_the_name_is_not():
    resolver, wire = Resolver([PUBLIC_V6]), Wire()
    client = _guarded(wire, resolver)
    client.get_json(URL)
    request = wire.requests[0]
    assert str(request.url) == f"https://[{PUBLIC_V6}]/x"
    assert request.url.host == PUBLIC_V6
    assert request.headers["host"] == HOST                              # not bracketed
    assert request.extensions["sni_hostname"] == HOST


def test_userinfo_never_reaches_the_pinned_request():
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver, any_port=True)
    client.get_json(f"https://user:secret@{HOST}/x")
    request = wire.requests[0]
    assert request.url.userinfo == b"" and "authorization" not in request.headers
    assert request.url.host == PUBLIC


def test_an_allow_listed_name_inside_the_userinfo_cannot_keep_the_name_as_the_target():
    # An edit-the-string implementation (replace the host by the address) would rewrite the
    # first occurrence, in the userinfo, and leave the NAME as the connect target.
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver, any_port=True)
    client.get_json(f"https://{HOST}:x@{HOST}/p")
    request = wire.requests[0]
    assert request.url.host == PUBLIC and request.url.userinfo == b""
    assert request.headers["host"] == HOST


def test_the_pinned_request_is_for_the_name_that_was_asked():
    resolver, wire = Resolver([PUBLIC], [PUBLIC_B]), Wire()
    client = _guarded(wire, resolver, hosts=(HOST, OTHER_HOST))
    client.get_json(f"https://{HOST}/a")
    client.get_json(f"https://{OTHER_HOST}/b")
    first, second = wire.requests
    assert (first.url.host, first.headers["host"], first.extensions["sni_hostname"]) == \
        (PUBLIC, HOST, HOST)
    assert (second.url.host, second.headers["host"], second.extensions["sni_hostname"]) == \
        (PUBLIC_B, OTHER_HOST, OTHER_HOST)
    assert [c[0] for c in resolver.calls] == [HOST, OTHER_HOST]


def test_the_cache_is_keyed_by_the_original_url_and_is_read_before_the_guard():
    resolver, wire = Resolver([PUBLIC]), Wire()
    client = _guarded(wire, resolver)
    assert client.get_json(URL) == {"ok": True}
    assert client._cache.get(URL) == {"ok": True}
    assert client.get_json(URL) == {"ok": True}                         # a hit: no I/O at all
    assert len(resolver.calls) == 1 and len(wire.requests) == 1


def test_a_refusal_is_not_remembered():
    resolver, wire = Resolver(["10.0.0.1"], [PUBLIC]), Wire()
    client = _guarded(wire, resolver)
    with pytest.raises(HttpForbiddenAddress):
        client.get_json(URL)
    assert client.get_json(URL) == {"ok": True}                    # a later honest answer works
    assert len(resolver.calls) == 2


# --- resolution failures: the same as a connection failure without the guard ----------------

def test_a_resolver_error_is_retried_like_a_connect_error_and_ends_the_same_way():
    # Reference: with no guard, a connect error is retried `attempts` times, then exhausted.
    reference_wire = Wire(httpx.ConnectError("boom"))
    with pytest.raises(HttpTransientExhausted) as reference:
        _unguarded(reference_wire).get_json(URL)
    assert len(reference_wire.requests) == 3

    resolver, wire = Resolver(socket.gaierror(socket.EAI_NONAME, "nodename nor servname")), Wire()
    with pytest.raises(HttpTransientExhausted) as info:
        _guarded(wire, resolver).get_json(URL)
    assert type(info.value) is type(reference.value) is HttpTransientExhausted
    assert len(resolver.calls) == 3 and wire.requests == []             # per RetryPolicy
    assert info.value.url == URL


@pytest.mark.parametrize("failure", [
    socket.gaierror(socket.EAI_AGAIN, "temporary failure"), ValueError("label too long"),
    UnicodeError("label empty or too long"), TypeError("not iterable"), OSError("net down"),
    TimeoutError("slow"), [], (),
])
def test_resolution_failures_are_typed_and_retried(failure):
    resolver, wire = Resolver(failure), Wire()
    client = _guarded(wire, resolver)
    with pytest.raises(HttpTransientExhausted) as info:
        client.get_json(URL)
    assert type(info.value) is HttpTransientExhausted
    assert len(resolver.calls) == 3 and wire.requests == []
    assert client._cache.get(URL) is None


def test_a_resolver_that_returns_none_is_a_typed_failure_not_a_type_error():
    resolver, wire = Resolver(None), Wire()
    with pytest.raises(HttpTransientExhausted):
        _guarded(wire, resolver).get_json(URL)


def test_a_resolver_that_recovers_is_used_on_the_next_attempt():
    resolver, wire = Resolver(socket.gaierror(8, "x"), [PUBLIC]), Wire()
    assert _guarded(wire, resolver).get_json(URL) == {"ok": True}
    assert len(resolver.calls) == 2 and len(wire.requests) == 1


def test_addresses_raises_only_typed_errors_for_a_failing_resolver():
    guard = AddressGuard(resolver=Resolver(ValueError("x")))
    with pytest.raises(HttpAddressResolutionFailed) as info:
        guard.addresses(HOST, 443)
    assert type(info.value) is HttpAddressResolutionFailed
    with pytest.raises(HttpAddressResolutionFailed):
        AddressGuard(resolver=Resolver([])).addresses(HOST, 443)


@pytest.mark.parametrize("failure", [
    RuntimeError("resolver bug"), KeyError("k"), AttributeError("a"), StopIteration(),
    ZeroDivisionError("z"),
])
def test_an_injected_resolvers_own_exceptions_propagate_unchanged_and_are_not_retried(failure):
    # The docstring of AddressGuard.addresses: only OSError / ValueError / TypeError are
    # a resolution failure. Anything else is a bug in the caller's resolver, and is not
    # hidden behind the retry loop.
    resolver, wire = Resolver(failure), Wire()
    with pytest.raises(type(failure)) as info:
        _guarded(wire, resolver).get_json(URL)
    assert info.value is failure
    assert len(resolver.calls) == 1 and wire.requests == []
    with pytest.raises(type(failure)):
        AddressGuard(resolver=Resolver(failure)).addresses(HOST, 443)


# --- rotation (D4) --------------------------------------------------------------------------

def test_a_connect_failure_rotates_to_the_next_validated_address():
    resolver = Resolver([PUBLIC, PUBLIC_B])
    wire = Wire(httpx.ConnectError("no route"), httpx.Response(200, json={"ok": True}))
    assert _guarded(wire, resolver).get_json(URL) == {"ok": True}
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC_B]
    assert len(resolver.calls) == 2                                      # validated per attempt


def test_rotation_wraps_around_and_is_bounded_by_the_retry_policy():
    resolver = Resolver([PUBLIC, PUBLIC_B])
    wire = Wire(httpx.ConnectError("no route"))
    with pytest.raises(HttpTransientExhausted):
        _guarded(wire, resolver).get_json(URL)
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC_B, PUBLIC]   # 3 attempts


DEAD_V6 = ["2606:2800:220:1::1", "2001:4860:4860::8888", "2a00:1450:4001::1",
           "2a00:1450:4001::2"]


def _v6_dead(request: httpx.Request) -> httpx.Response:
    """An IPv6-broken client: every IPv6 literal fails to connect, IPv4 answers."""
    if ":" in request.url.host:
        raise httpx.ConnectError("no route to host")
    return httpx.Response(200, json={"ok": True})


@pytest.mark.parametrize("dead, attempts, reached", [
    (2, 3, True),      # the address at position 3 is reached by the default policy
    (3, 3, False),     # position 4 is not: the bound is the policy's, not the address count
    (3, 4, True),      # RetryPolicy(attempts=len(answer)) reaches it
    (4, 4, False),
    (4, 5, True),
])
def test_rotation_reaches_the_address_at_position_k_only_if_the_policy_allows_k_attempts(
        dead, attempts, reached):
    # The AddressGuard docstring and the CHANGELOG state this bound.
    answer = DEAD_V6[:dead] + [PUBLIC]
    wire = Wire(_v6_dead)
    client = _guarded(wire, Resolver(answer),
                      retry=RetryPolicy(attempts=attempts, backoff_base_s=0.0, backoff_max_s=0.0))
    if reached:
        assert client.get_json(URL) == {"ok": True}
        assert [r.url.host for r in wire.requests] == answer
    else:
        with pytest.raises(HttpTransientExhausted) as info:
            client.get_json(URL)
        assert type(info.value) is HttpTransientExhausted
        assert [r.url.host for r in wire.requests] == answer[:attempts]       # PUBLIC never tried


def test_the_default_policy_tries_three_addresses_and_no_more(monkeypatch):
    answer = DEAD_V6[:3] + [PUBLIC]
    wire = Wire(_v6_dead)
    client = EbsiHttpClient(allowed_hosts={HOST}, address_guard=AddressGuard(
        resolver=Resolver(answer)))
    client._client = httpx.Client(transport=httpx.MockTransport(wire))
    assert client._retry == RetryPolicy() and client._retry.attempts == 3
    monkeypatch.setattr(client, "_sleep_before_retry", lambda *args, **kwargs: None)
    with pytest.raises(HttpTransientExhausted):
        client.get_json(URL)
    assert [r.url.host for r in wire.requests] == DEAD_V6[:3]


@pytest.mark.parametrize("failure", [
    httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"),
    httpx.ConnectTimeout("connect timed out"), httpx.ReadTimeout("read timed out"),
    httpx.WriteError("write failed"), httpx.RemoteProtocolError("server disconnected"),
], ids=lambda failure: type(failure).__name__)
def test_any_transport_error_rotates_to_the_next_address(failure):
    resolver = Resolver([PUBLIC, PUBLIC_B])
    wire = Wire(failure, httpx.Response(200, json={"ok": True}))
    assert _guarded(wire, resolver).get_json(URL) == {"ok": True}
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC_B]


def test_rotation_survives_a_resolver_that_reorders_its_answer():
    resolver = Resolver([PUBLIC, PUBLIC_B], [PUBLIC_B, PUBLIC])
    wire = Wire(httpx.ConnectError("no route"), httpx.Response(200, json={"ok": True}))
    _guarded(wire, resolver).get_json(URL)
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC_B]


def test_a_single_address_is_retried_on_itself():
    resolver = Resolver([PUBLIC])
    wire = Wire(httpx.ConnectError("no route"), httpx.Response(200, json={"ok": True}))
    _guarded(wire, resolver).get_json(URL)
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC]


@pytest.mark.parametrize("status, error", [(404, HttpNotFound), (403, HttpError), (400, HttpError)])
def test_a_client_error_is_never_rotated(status, error):
    resolver, wire = Resolver([PUBLIC, PUBLIC_B]), Wire(httpx.Response(status))
    with pytest.raises(error) as info:
        _guarded(wire, resolver).get_json(URL)
    assert type(info.value) is error
    assert len(wire.requests) == 1 and len(resolver.calls) == 1


def test_duplicate_answers_count_once():
    # getaddrinfo can repeat an address (one entry per socket type); it is one address.
    resolver, wire = Resolver([PUBLIC, PUBLIC, PUBLIC_B]), Wire(
        httpx.ConnectError("no route"), httpx.Response(200, json={"ok": True}))
    _guarded(wire, resolver).get_json(URL)
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC_B]


def test_a_5xx_is_retried_on_the_next_address_and_validated_again():
    resolver = Resolver([PUBLIC, PUBLIC_B])
    wire = Wire(httpx.Response(503), httpx.Response(200, json={"ok": True}))
    assert _guarded(wire, resolver).get_json(URL) == {"ok": True}
    assert len(resolver.calls) == 2
    assert [r.url.host for r in wire.requests] == [PUBLIC, PUBLIC_B]


def test_the_address_can_turn_bad_between_attempts():
    # The window a name-based connect would leave: attempt 1 is fine, attempt 2 rebinds.
    resolver = Resolver([PUBLIC], ["10.0.0.1"])
    wire = Wire(httpx.ConnectError("no route"))
    with pytest.raises(HttpForbiddenAddress):
        _guarded(wire, resolver).get_json(URL)
    assert len(wire.requests) == 1 and len(resolver.calls) == 2


# --------------------------------------------------------------------------- #
# Environment proxy (D3)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("proxies", [
    {"https": "http://proxy.invalid:3128"},
    {"all": "http://proxy.invalid:3128"},
    {"https": "http://proxy.invalid:3128", "no": "internal.example"},
    {"http": "http://proxy.invalid:3128", "all": "socks5://proxy.invalid:1080"},
])
def test_a_guard_behind_an_environment_proxy_is_refused_at_construction(monkeypatch, proxies):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: proxies)
    built: list[Any] = []
    monkeypatch.setattr(httpx, "Client", lambda **kw: built.append(kw))
    with pytest.raises(HttpAddressGuardUnavailable) as info:
        EbsiHttpClient(allowed_hosts={HOST}, address_guard=AddressGuard())
    assert type(info.value) is HttpAddressGuardUnavailable
    assert "address_guard" in str(info.value) and "proxy" in str(info.value)
    assert built == []                                     # nothing was built, nothing to close


def test_for_ebsi_forwards_the_guard_and_is_refused_behind_a_proxy_too(monkeypatch):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://p.invalid:3128"})
    with pytest.raises(HttpAddressGuardUnavailable):
        for_ebsi("pilot", address_guard=AddressGuard())


def test_the_real_proxy_variables_are_read(monkeypatch):
    monkeypatch.setattr(urllib.request, "getproxies", _REAL_GETPROXIES)
    for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    with pytest.raises(HttpAddressGuardUnavailable):
        EbsiHttpClient(allowed_hosts={HOST}, address_guard=AddressGuard())


@pytest.mark.parametrize("no_proxy", [HOST, f".{HOST}", "ebsi.eu", f"{HOST},{OTHER_HOST}", "*"])
def test_no_proxy_is_not_an_exemption(monkeypatch, no_proxy):
    # httpx matches NO_PROXY against the host of the request URL, which a pinned request makes
    # the ADDRESS, so naming the EBSI hosts does not keep the request off the proxy (see the
    # loopback test below, which measures it). Refused whatever NO_PROXY says.
    monkeypatch.setattr(urllib.request, "getproxies",
                        lambda: {"https": "http://p.invalid:3128", "no": no_proxy})
    with pytest.raises(HttpAddressGuardUnavailable) as info:
        EbsiHttpClient(allowed_hosts={HOST, OTHER_HOST}, address_guard=AddressGuard())
    assert type(info.value) is HttpAddressGuardUnavailable


def test_without_the_guard_a_proxy_changes_nothing(monkeypatch):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://p.invalid:3128"})
    EbsiHttpClient(allowed_hosts={HOST}).close()
    for_ebsi("pilot").close()


def test_no_proxy_means_the_guard_is_built():
    EbsiHttpClient(allowed_hosts={HOST}, address_guard=AddressGuard()).close()
    for_ebsi("pilot", address_guard=AddressGuard()).close()


# --------------------------------------------------------------------------- #
# Default off
# --------------------------------------------------------------------------- #

def test_without_a_guard_the_request_is_the_original_byte_for_byte(monkeypatch):
    def boom(*args: Any, **kwargs: Any) -> Any:           # pragma: no cover - must not run
        raise AssertionError("the address guard ran with address_guard=None")

    monkeypatch.setattr(ebsi_http, "ip_is_forbidden", boom)
    monkeypatch.setattr(ebsi_http.socket, "getaddrinfo", boom)
    wire = Wire()
    client = _unguarded(wire)
    url = f"https://{HOST}/did-registry/v5/identifiers/did:ebsi:zX?a=1"
    assert client.get_json(url) == {"ok": True}
    request = wire.requests[0]
    assert str(request.url) == url
    assert "sni_hostname" not in request.extensions
    assert request.headers["connection"] == "keep-alive"      # httpx's own default, untouched


def test_the_guard_changes_no_constructor_argument_of_the_http_client(monkeypatch):
    real = httpx.Client
    seen: list[dict[str, Any]] = []

    def record(**kwargs: Any) -> httpx.Client:
        seen.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "Client", record)
    EbsiHttpClient(allowed_hosts={HOST}).close()
    EbsiHttpClient(allowed_hosts={HOST}, address_guard=AddressGuard()).close()
    assert len(seen) == 2
    jars = [kwargs.pop("cookies") for kwargs in seen]          # a fresh jar per client (#317)
    assert seen[0] == seen[1]                                  # one pooled client, same config
    assert type(jars[0]._policy) is type(jars[1]._policy)      # and the same no-cookie policy


def test_the_default_guard_uses_the_system_resolver_for_tcp(monkeypatch):
    calls: list[tuple[Any, ...]] = []

    def fake(host: str, port: int, **kwargs: Any) -> list[Any]:
        calls.append((host, port, kwargs))
        return [(2, 1, 6, "", (PUBLIC, port)), (2, 1, 6, "", (PUBLIC, port)),
                (10, 1, 6, "", (PUBLIC_V6, port, 0, 0))]

    monkeypatch.setattr(ebsi_http.socket, "getaddrinfo", fake)
    assert AddressGuard().addresses(HOST, 8443) == [PUBLIC, PUBLIC_V6]
    assert calls == [(HOST, 8443, {"proto": socket.IPPROTO_TCP})]


# --------------------------------------------------------------------------- #
# Fuzz: only typed errors, and only addresses the classifier accepts
# --------------------------------------------------------------------------- #

_ANSWER = st.one_of(
    st.text(max_size=80),
    st.text(min_size=60, max_size=400),
    st.ip_addresses(v=4).map(str),
    st.ip_addresses(v=6).map(str),
    st.ip_addresses(v=6).map(lambda ip: f"{ip}%eth0"),
    st.integers(), st.floats(), st.none(), st.binary(max_size=20),
    st.sampled_from(["", "not-an-ip", "::ffff:8.8.8.8", "fe80::1%eth0", "127.1", "٨.٨.٨.٨",
                     "8.8.8.8\x00", "[::1]", "::ffff:10.0.0.1", "64:ff9b::808:808"]),
)


@settings(max_examples=400, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(_ANSWER, max_size=10))
def test_fuzz_the_guard_returns_only_public_addresses_or_raises_a_typed_error(answers):
    guard = AddressGuard(resolver=lambda host, port: answers)
    try:
        out = guard.addresses("node.example", 443)
    except EbsiError as exc:
        assert type(exc) in (HttpForbiddenAddress, HttpAddressResolutionFailed)
        return
    assert out and len(set(out)) == len(out)
    for address in out:
        assert isinstance(address, str)
        parsed = ipaddress.ip_address(address)                       # never ValueError
        assert getattr(parsed, "scope_id", None) is None
        assert ip_is_forbidden(address) is False


@settings(max_examples=100, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.sampled_from([socket.gaierror(8, "x"), ValueError("v"), TypeError("t"), OSError("o"),
                        UnicodeError("u"), TimeoutError("t")]))
def test_fuzz_a_failing_resolver_is_always_the_typed_resolution_error(failure):
    guard = AddressGuard(resolver=Resolver(failure))
    with pytest.raises(HttpAddressResolutionFailed):
        guard.addresses("node.example", 443)


# --------------------------------------------------------------------------- #
# A real handshake on loopback: SNI, the certificate check, no reuse across names
# --------------------------------------------------------------------------- #

def _make_cert(directory: Path, tag: str, names: list[str],
               ips: tuple[str, ...] = ()) -> tuple[str, str]:
    """A self-signed certificate valid for the DNS *names* and the IP addresses *ips* (it is
    its own trust anchor)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, tag)])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt_names: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    alt_names += [x509.IPAddress(ipaddress.ip_address(a)) for a in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, False, False,
                                         False), True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / f"{tag}.crt", directory / f"{tag}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return str(cert_path), str(key_path)


def _trusting(*cert_paths: str) -> ssl.SSLContext:
    context = ssl.create_default_context()
    for path in cert_paths:
        context.load_verify_locations(cafile=path)
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


class _TlsServer:
    """A one-purpose HTTPS server on 127.0.0.1 that records the SNI of every handshake and
    the request line, ``Host`` and ``Authorization`` of every request it is sent."""

    def __init__(self, cert_files: tuple[str, str]) -> None:
        self.events: list[tuple[Any, ...]] = []
        self.accepts = 0
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(*cert_files)
        self._context.sni_callback = self._on_sni
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _on_sni(self, ssl_socket: Any, server_name: Any, context: Any) -> None:
        self.events.append(("sni", server_name))

    def _accept_loop(self) -> None:
        while True:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        raw.settimeout(5)
        try:
            tls = self._context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            self.events.append(("handshake-failed",))
            raw.close()
            return
        buffer = b""
        try:
            while True:
                while b"\r\n\r\n" not in buffer:
                    chunk = tls.recv(65536)
                    if not chunk:
                        return
                    buffer += chunk
                head, buffer = buffer.split(b"\r\n\r\n", 1)
                lines = head.split(b"\r\n")
                headers = {k.strip().lower().decode(): v.strip().decode()
                           for k, _, v in (ln.partition(b":") for ln in lines[1:])}
                self.events.append(("req", lines[0].decode(), headers.get("host"),
                                    headers.get("authorization")))
                body = b'{"ok": true}'
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: %d\r\n\r\n" % len(body) + body)
        except (ssl.SSLError, OSError):
            pass
        finally:
            tls.close()

    def requests(self) -> list[tuple[Any, ...]]:
        return [e for e in self.events if e[0] == "req"]

    def close(self) -> None:
        self._sock.close()


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@pytest.fixture
def loopback(monkeypatch):
    """Let the guard accept 127.0.0.1, the one thing the fixed classifier never would, so a
    real client can reach a real local server. Everything else about the guard is unchanged."""
    monkeypatch.setattr(ebsi_http, "ip_is_forbidden", lambda address: False)

    # And keep these tests off the real network when they fail: a client that connected by
    # NAME would otherwise resolve api-pilot.ebsi.eu and try its real addresses. A name
    # resolves to loopback here; a literal (what the guarded client connects to) is untouched.
    real_getaddrinfo = socket.getaddrinfo
    names_resolved: list[str] = []            # every NAME something asked the system to resolve

    def loopback_only(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(host, str) and not _is_literal(host):
            names_resolved.append(host)
            host = "127.0.0.1"
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", loopback_only)
    servers: list[_TlsServer] = []

    def start(cert_files: tuple[str, str]) -> _TlsServer:
        server = _TlsServer(cert_files)
        servers.append(server)
        return server

    start.names_resolved = names_resolved
    yield start
    for server in servers:
        server.close()


def _tls_client(server_cert: str, *, hosts: tuple[str, ...] = (HOST,)) -> EbsiHttpClient:
    client = EbsiHttpClient(
        allowed_hosts=set(hosts), retry=FAST_RETRY,
        address_guard=AddressGuard(resolver=lambda host, port: ["127.0.0.1"]))
    client._client = httpx.Client(verify=_trusting(server_cert))
    _any_port(client)                              # the test server is not on port 443
    return client


def test_tls_the_server_sees_the_name_as_sni_and_host_and_the_certificate_is_checked(
        tmp_path, loopback):
    cert = _make_cert(tmp_path, "a", [HOST])
    server = loopback(cert)
    client = _tls_client(cert[0])
    assert client.get_json(f"https://{HOST}:{server.port}/x") == {"ok": True}
    assert ("sni", HOST) in server.events
    assert server.requests() == [("req", "GET /x HTTP/1.1", f"{HOST}:{server.port}", None)]
    assert loopback.names_resolved == []        # connected to the validated literal, not the name


def test_tls_a_certificate_for_another_name_is_refused_and_no_request_is_sent(
        tmp_path, loopback):
    good = _make_cert(tmp_path, "a", [HOST])
    wrong = _make_cert(tmp_path, "wrong", ["other.example"])
    server = loopback(wrong)                       # presents a certificate for ANOTHER name
    client = _tls_client(wrong[0])                 # which the client trusts as an anchor
    with pytest.raises(HttpTransientExhausted) as info:
        client.get_json(f"https://{HOST}:{server.port}/x")
    assert type(info.value) is HttpTransientExhausted
    assert "CERTIFICATE_VERIFY_FAILED" in str(info.value) and "mismatch" in str(info.value)
    assert server.requests() == []                 # the request was never sent
    assert client._cache.get(f"https://{HOST}:{server.port}/x") is None
    # control: the same server with a certificate for the NAME is accepted
    client_ok = _tls_client(good[0])
    server_ok = loopback(good)
    assert client_ok.get_json(f"https://{HOST}:{server_ok.port}/x") == {"ok": True}


def test_tls_a_connection_checked_for_one_name_is_never_reused_for_another(tmp_path, loopback):
    # Two allow-listed names that resolve to the same address, and a server whose certificate
    # is valid for the FIRST name only. A pooled connection (keyed by the address) would
    # answer for the second name with no certificate check for it.
    cert = _make_cert(tmp_path, "a", [HOST])
    server = loopback(cert)
    client = _tls_client(cert[0], hosts=(HOST, OTHER_HOST))
    assert client.get_json(f"https://{HOST}:{server.port}/1") == {"ok": True}
    with pytest.raises(HttpTransientExhausted) as info:
        client.get_json(f"https://{OTHER_HOST}:{server.port}/2")
    assert "CERTIFICATE_VERIFY_FAILED" in str(info.value)
    assert [e[2] for e in server.requests()] == [f"{HOST}:{server.port}"]   # B never got a request


def test_tls_control_without_connection_close_the_pool_would_reuse_the_connection(
        tmp_path, loopback):
    # Guards the test above against passing vacuously: the same two pinned requests WITHOUT
    # `Connection: close` do reuse the connection, and the second name is served with no
    # certificate check. (This is what keep-alive would do; it is why the guard sends close.)
    cert = _make_cert(tmp_path, "a", [HOST])
    server = loopback(cert)
    http = httpx.Client(verify=_trusting(cert[0]))
    for name, path in ((HOST, "/1"), (OTHER_HOST, "/2")):
        with http.stream("GET", f"https://127.0.0.1:{server.port}{path}",
                         headers={"Host": f"{name}:{server.port}"},
                         extensions={"sni_hostname": name}) as response:
            response.read()
            assert response.status_code == 200
    assert server.accepts == 1 and len(server.requests()) == 2


def test_tls_every_guarded_request_uses_a_fresh_connection(tmp_path, loopback):
    cert = _make_cert(tmp_path, "a", [HOST])
    server = loopback(cert)
    client = _tls_client(cert[0])
    for path in ("/1", "/2", "/3"):
        assert client.get_json(f"https://{HOST}:{server.port}{path}") == {"ok": True}
    assert server.accepts == 3 and len(server.requests()) == 3
    assert loopback.names_resolved == []


class _ConnectProxy:
    """A minimal HTTP CONNECT proxy on 127.0.0.1 that records the CONNECT lines it is sent and
    tunnels to the target."""

    def __init__(self) -> None:
        self.seen: list[str] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._tunnel, args=(client,), daemon=True).start()

    def _tunnel(self, client: socket.socket) -> None:
        client.settimeout(5)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data += chunk
            line = data.split(b"\r\n")[0].decode()
            self.seen.append(line)
            host, _, port = line.split(" ")[1].rpartition(":")
            upstream = socket.create_connection((host, int(port)), timeout=5)
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            def pipe(source: socket.socket, sink: socket.socket) -> None:
                try:
                    while True:
                        chunk = source.recv(65536)
                        if not chunk:
                            break
                        sink.sendall(chunk)
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
            pipe(client, upstream)
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        self._sock.close()


def test_tls_no_proxy_naming_the_host_does_not_keep_a_pinned_request_off_the_proxy(
        tmp_path, monkeypatch):
    # The measurement behind test_no_proxy_is_not_an_exemption: a plain httpx client that
    # trusts the environment, HTTPS_PROXY set and NO_PROXY naming the host, is asked for the
    # pinned form of the request (the validated literal in the URL, the name as the TLS name).
    # It is still sent to the proxy, which tunnels to the address, and the certificate (valid
    # for the NAME) fails against the address: a TLS name mismatch, which is what refusing to
    # build the guarded client behind a proxy avoids.
    monkeypatch.setattr(urllib.request, "getproxies", _REAL_GETPROXIES)
    cert = _make_cert(tmp_path, "a", [HOST])
    server = _TlsServer(cert)
    proxy = _ConnectProxy()
    try:
        for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "https_proxy"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("NO_PROXY", HOST)
        with httpx.Client(verify=_trusting(cert[0])) as http:           # trust_env is the default
            with pytest.raises(httpx.ConnectError) as info:
                with http.stream("GET", f"https://127.0.0.1:{server.port}/x",
                                 headers={"Host": f"{HOST}:{server.port}"},
                                 extensions={"sni_hostname": HOST}):
                    pass
        assert proxy.seen == [f"CONNECT 127.0.0.1:{server.port} HTTP/1.1"]
        assert "CERTIFICATE_VERIFY_FAILED" in str(info.value)
        assert server.requests() == []
    finally:
        proxy.close()
        server.close()


def test_tls_userinfo_is_not_sent(tmp_path, loopback):
    cert = _make_cert(tmp_path, "a", [HOST])
    server = loopback(cert)
    client = _tls_client(cert[0])
    client.get_json(f"https://user:pw@{HOST}:{server.port}/x")
    assert server.requests() == [("req", "GET /x HTTP/1.1", f"{HOST}:{server.port}", None)]


def test_tls_a_guarded_client_does_not_trust_the_address_it_resolved_over_the_name(
        tmp_path, loopback):
    # The certificate is valid for the 127.0.0.1 IP only (no DNS name): a client that checked
    # the address instead of the name would accept it. It must not.
    cert_path, key_path = _make_cert(tmp_path, "ip-only", [], ips=("127.0.0.1",))
    server = loopback((cert_path, key_path))
    client = _tls_client(cert_path)
    with pytest.raises(HttpTransientExhausted) as info:
        client.get_json(f"https://{HOST}:{server.port}/x")
    assert "CERTIFICATE_VERIFY_FAILED" in str(info.value)
    assert server.requests() == []
