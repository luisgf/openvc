"""
tests/test_ebsi_origin_default_port.py

The origin pin of the TIR v5 walk treats an absent https port as 443 (#253).

``openvc_ebsi.versioning._origin`` builds the ``scheme://host:port`` that pins three hops of
``TirV5.parse_issuer`` / ``_iter_attribute_items`` to the listing's own origin:

  * the HATEOAS ``attributes`` URL: off-origin raises ``MalformedRegistryResponse``;
  * each revision ``href``: off-origin is skipped and never fetched;
  * ``links.next``: off-origin ends the walk and keeps the items already read.

Before #253 an absent port and ``:443`` were two different origins. A resolver whose
``base`` was ``https://api-pilot.ebsi.eu:443`` skipped every port-less ``href`` (the
``attributes`` URL raised, ``next`` stopped the walk), and a registry that wrote ``:443``
into its hrefs had them all skipped under the default base, so the issuer appeared to hold
no accreditations. RFC 3986 section 6.2.3 (scheme-based normalization): an empty port and
the scheme's default port are the same origin, as they are to httpx.

The rule, as pinned here:

  * only an ABSENT port is filled in (``port is None``), and only for https: an explicit
    ``:0`` stays port 0 and ``:8443`` stays 8443, so the fix opens no other port;
  * http keeps an empty port, so it matches no https origin;
  * scheme and host are case-insensitive.

The walk tests run against the recorded pilot fixtures (tests/fixtures/ebsi/), whose URLs
carry NO port, rewritten to write a chosen port into one hop at a time. A StubFetch route
is an exact URL, so every route is keyed by the URL the code literally fetches. Each
negative control routes the off-origin URL with real content, so a wrongful fetch shows in
the call list and in the accreditation count rather than as a 404.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import MalformedRegistryResponse
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.models import IssuerRecord
from openvc_ebsi.versioning import DidEbsiResolver, TirV5, _on_origin, _origin

PILOT_BASE = "https://api-pilot.ebsi.eu"
BASE_443 = PILOT_BASE + ":443"
FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"


# --------------------------------------------------------------------------- #
# Harness (copied from test_ebsi_verifier.py: tests/ is not a package)
# --------------------------------------------------------------------------- #

class StubFetch:
    def __init__(self, routes: dict[str, dict]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url: str) -> dict:
        self.calls.append(url)
        try:
            return self.routes[url]
        except KeyError:
            raise HttpNotFound("no stub route", url=url) from None


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _with_port(url: str, port: str) -> str:
    """A recorded URL with ``port`` (``":443"``, ``":0"``, ``""``) written after its host."""
    assert url.startswith(PILOT_BASE + "/")
    return PILOT_BASE + port + url[len(PILOT_BASE):]


@dataclass
class _Registry:
    """The recorded TIR v5 multi-hop behind a StubFetch, and the resolver that reads it."""
    did: str
    fetch: StubFetch
    resolver: DidEbsiResolver
    issuer_url: str
    attributes_url: str
    page2_url: str | None           # the `links.next` target, when the listing paginates
    hrefs: list[str]
    ids: list[str]

    def record(self) -> IssuerRecord:
        return self.resolver.issuer_record(self.did)

    def urls(self) -> list[str]:
        """Every URL a complete walk fetches, once each."""
        page2 = [self.page2_url] if self.page2_url else []
        return [self.issuer_url, self.attributes_url, *page2, *self.hrefs]


def _serve(
    *, base: str = PILOT_BASE, port: str = "", attributes_port: str | None = None,
    href_ports: tuple[str, str, str] | None = None, next_port: str | None = None,
    paginate: bool = False,
) -> _Registry:
    """Serve the recorded fixtures, writing a port into the URLs the registry hands out.

    ``base`` is the resolver's base (it sets the listing origin, and so the issuer route).
    ``port`` goes into the ``attributes`` URL, each ``href`` and the ``next`` cursor, unless
    ``attributes_port`` / ``href_ports`` (one per item) / ``next_port`` override that hop.
    ``paginate`` splits the three items 2 + 1 across two pages joined by ``links.next``."""
    attributes_port = port if attributes_port is None else attributes_port
    href_ports = (port, port, port) if href_ports is None else href_ports
    next_port = port if next_port is None else next_port

    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    items = [{**item, "href": _with_port(item["href"], p)}
             for item, p in zip(attributes["items"], href_ports)]
    attributes_url = _with_port(issuer["attributes"], attributes_port)
    issuer_url = f"{base}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: {**issuer, "attributes": attributes_url}}

    page2_url = None
    if paginate:
        page2_url = _with_port(issuer["attributes"], next_port) + "?page[after]=1&page[size]=2"
        routes[attributes_url] = {
            "items": items[:2], "total": 3, "pageSize": 2,
            "links": {"self": attributes_url, "next": page2_url}}
        routes[page2_url] = {
            "items": items[2:], "total": 3, "pageSize": 2, "links": {"self": page2_url}}
    else:
        routes[attributes_url] = {**attributes, "items": items}
    for item in items:
        routes[item["href"]] = revisions[item["id"]]

    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(
        fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=base)
    return _Registry(
        did=did, fetch=fetch, resolver=resolver, issuer_url=issuer_url,
        attributes_url=attributes_url, page2_url=page2_url,
        hrefs=[i["href"] for i in items], ids=[i["id"] for i in items])


def _ids(rec: IssuerRecord) -> list[str]:
    return [a.attribute_id for a in rec.accreditations]


# --------------------------------------------------------------------------- #
# _origin / _on_origin
# --------------------------------------------------------------------------- #

# Every spelling of the https default port: all one origin as https://api-pilot.ebsi.eu:443.
DEFAULT_PORT_SPELLINGS = [
    pytest.param("https://api-pilot.ebsi.eu", id="absent"),
    pytest.param("https://api-pilot.ebsi.eu:443", id="explicit-443"),
    pytest.param("https://api-pilot.ebsi.eu:", id="empty-port"),
    pytest.param("https://api-pilot.ebsi.eu:00443", id="leading-zeros"),
    pytest.param("https://api-pilot.ebsi.eu/a/b?c=1", id="absent-with-path"),
    pytest.param("https://api-pilot.ebsi.eu:443/d/e", id="explicit-with-path"),
]

# Not the same origin as https://api-pilot.ebsi.eu: another port, scheme or host.
OTHER_ORIGINS = [
    pytest.param("https://api-pilot.ebsi.eu:0", id="port-0"),
    pytest.param("https://api-pilot.ebsi.eu:00", id="port-00"),
    pytest.param("https://api-pilot.ebsi.eu:80", id="port-80"),
    pytest.param("https://api-pilot.ebsi.eu:8443", id="port-8443"),
    pytest.param("http://api-pilot.ebsi.eu", id="http-absent"),
    pytest.param("http://api-pilot.ebsi.eu:443", id="http-explicit-443"),
    pytest.param("http://api-pilot.ebsi.eu:80", id="http-explicit-80"),
    pytest.param("https://api.ebsi.eu", id="other-host"),
    pytest.param("https://api.ebsi.eu:443", id="other-host-explicit-443"),
    pytest.param("https://api-pilot.ebsi.eu.evil.example", id="host-suffix"),
]


@pytest.mark.parametrize("url", DEFAULT_PORT_SPELLINGS)
def test_origin_absent_https_port_is_443(url: str) -> None:
    # #253, RFC 3986 section 6.2.3.
    assert _origin(url) == _origin("https://api-pilot.ebsi.eu:443")
    assert _origin(url) == _origin("https://api-pilot.ebsi.eu")


@pytest.mark.parametrize("url,same_as", [
    pytest.param("HTTPS://API-PILOT.EBSI.EU", "https://api-pilot.ebsi.eu", id="upper"),
    pytest.param("HtTpS://Api-Pilot.Ebsi.Eu:443/x", "https://api-pilot.ebsi.eu:443",
                 id="mixed-explicit"),
    pytest.param("https://API-PILOT.ebsi.eu:00443", "https://api-pilot.ebsi.eu:443",
                 id="host-upper-zeros"),
    pytest.param("HTTP://API-PILOT.EBSI.EU", "http://api-pilot.ebsi.eu", id="http-upper"),
])
def test_origin_scheme_and_host_are_case_insensitive(url: str, same_as: str) -> None:
    # Each pair spells its port the same way, so this holds with or without #253.
    assert _origin(url) == _origin(same_as)


@pytest.mark.parametrize("url", OTHER_ORIGINS)
def test_origin_other_port_scheme_or_host_differs(url: str) -> None:
    # Only an ABSENT https port reads as 443. `:0` is falsy but present; `:8443` is
    # another port; http has no default filled in; and the host is part of the origin.
    assert _origin(url) != _origin("https://api-pilot.ebsi.eu")
    assert _origin(url) != _origin("https://api-pilot.ebsi.eu:443")


def test_origin_explicit_zero_port_is_its_own_origin() -> None:
    # `if port is None`, not `if not port`: port 0 must not fold into 443.
    zero = _origin("https://api-pilot.ebsi.eu:0")
    assert zero == _origin("https://api-pilot.ebsi.eu:0/x")
    assert zero == _origin("https://api-pilot.ebsi.eu:00")
    assert zero != _origin("https://api-pilot.ebsi.eu")
    assert zero != _origin("https://api-pilot.ebsi.eu:443")


def test_origin_http_keeps_an_empty_port() -> None:
    # Only https gets a default. The client refuses http anyway, so an http URL must not
    # acquire one: it stays its own, port-less origin, never http's :80 nor :443.
    assert _origin("http://api-pilot.ebsi.eu") == "http://api-pilot.ebsi.eu:"
    assert _origin("http://api-pilot.ebsi.eu") != _origin("http://api-pilot.ebsi.eu:443")
    assert _origin("http://api-pilot.ebsi.eu") != _origin("http://api-pilot.ebsi.eu:80")


@pytest.mark.parametrize("origin_of", [
    pytest.param("https://api-pilot.ebsi.eu", id="origin-absent"),
    pytest.param("https://api-pilot.ebsi.eu:443", id="origin-443"),
])
@pytest.mark.parametrize("url", DEFAULT_PORT_SPELLINGS)
def test_on_origin_true_for_every_spelling_of_the_default_port(url: str, origin_of: str) -> None:
    assert _on_origin(url, _origin(origin_of)) is True


@pytest.mark.parametrize("origin_of", [
    pytest.param("https://api-pilot.ebsi.eu", id="origin-absent"),
    pytest.param("https://api-pilot.ebsi.eu:443", id="origin-443"),
])
@pytest.mark.parametrize("url", OTHER_ORIGINS + [
    pytest.param("https://api-pilot.ebsi.eu:99999/x", id="port-out-of-range"),
    pytest.param("https://api-pilot.ebsi.eu:abc/x", id="port-not-numeric"),
])
def test_on_origin_false_off_origin_or_unparseable(url: str, origin_of: str) -> None:
    assert _on_origin(url, _origin(origin_of)) is False


def test_on_origin_explicit_zero_port_matches_only_itself() -> None:
    zero = _origin("https://api-pilot.ebsi.eu:0")
    assert _on_origin("https://api-pilot.ebsi.eu:0/x", zero) is True
    assert _on_origin("https://api-pilot.ebsi.eu/x", zero) is False
    assert _on_origin("https://api-pilot.ebsi.eu:443/x", zero) is False


# --------------------------------------------------------------------------- #
# The walk: an absent port and :443 are one origin, on every hop
# --------------------------------------------------------------------------- #

def test_base_with_443_reads_the_port_less_recorded_registry() -> None:
    # The resolver's base spells the port, the recorded registry never does. Before #253
    # the port-less `attributes` URL was off the `:443` listing origin and raised.
    reg = _serve(base=BASE_443)
    assert ":443" in reg.issuer_url
    assert ":443" not in reg.attributes_url and not any(":443" in h for h in reg.hrefs)

    rec = reg.record()
    assert rec.has_attributes and len(rec.accreditations) == 3
    assert _ids(rec) == reg.ids
    assert reg.attributes_url in reg.fetch.calls
    for href in reg.hrefs:
        assert href in reg.fetch.calls
    assert reg.fetch.calls == reg.urls()


@pytest.mark.parametrize("hops", [
    pytest.param({"attributes_port": ":443"}, id="attributes-only"),
    pytest.param({"href_ports": (":443", ":443", ":443")}, id="hrefs-only"),
    pytest.param({"next_port": ":443"}, id="next-only"),
    pytest.param({"port": ":443"}, id="every-hop"),
])
def test_default_base_follows_a_registry_that_writes_443(hops: dict) -> None:
    # The registry spells :443 where the base has no port. Before #253 the `attributes`
    # URL raised, each `href` was skipped, and a `next` ended the walk after page 1.
    reg = _serve(paginate=True, **hops)
    assert reg.page2_url is not None and ":443" not in reg.issuer_url

    rec = reg.record()
    assert rec.has_attributes and len(rec.accreditations) == 3     # 2 + 1 across two pages
    assert _ids(rec) == reg.ids
    assert reg.page2_url in reg.fetch.calls
    assert sorted(reg.fetch.calls) == sorted(reg.urls())           # each URL, once


@pytest.mark.parametrize("registry_port", [
    pytest.param("", id="attributes-and-hrefs-port-less"),
    pytest.param(":443", id="attributes-and-hrefs-443"),
])
def test_base_with_443_follows_a_next_without_a_port(registry_port: str) -> None:
    # Mixed spellings in one walk: `attributes` and the hrefs match one form, the page-1
    # `next` the other.
    reg = _serve(base=BASE_443, port=registry_port, next_port="", paginate=True)
    assert reg.page2_url is not None and ":443" not in reg.page2_url

    rec = reg.record()
    assert len(rec.accreditations) == 3
    assert _ids(rec) == reg.ids
    assert reg.page2_url in reg.fetch.calls
    assert sorted(reg.fetch.calls) == sorted(reg.urls())


# --------------------------------------------------------------------------- #
# Negative controls: the default port is the only port the change opens
# --------------------------------------------------------------------------- #

# (base, the port the rest of the registry's URLs spell): same spelling as the base, so
# the one URL on another port is the only difference the pin has to see.
BASES = [
    pytest.param(PILOT_BASE, "", id="base-default"),
    pytest.param(BASE_443, ":443", id="base-443"),
]
OTHER_PORTS = [
    pytest.param(":0", id="port-0"),
    pytest.param(":8443", id="port-8443"),
]


@pytest.mark.parametrize("bad", OTHER_PORTS)
@pytest.mark.parametrize("base,port", BASES)
def test_attributes_url_on_another_port_is_refused(base: str, port: str, bad: str) -> None:
    reg = _serve(base=base, port=port, attributes_port=bad, paginate=True)
    assert reg.attributes_url in reg.fetch.routes          # routed: a fetch would succeed

    with pytest.raises(MalformedRegistryResponse, match="listing origin"):
        reg.record()
    assert reg.attributes_url not in reg.fetch.calls
    assert reg.fetch.calls == [reg.issuer_url]


@pytest.mark.parametrize("bad", OTHER_PORTS)
@pytest.mark.parametrize("base,port", BASES)
def test_href_on_another_port_is_skipped(base: str, port: str, bad: str) -> None:
    reg = _serve(base=base, port=port, href_ports=(bad, port, port))
    assert reg.hrefs[0] in reg.fetch.routes                # routed: a fetch would succeed

    rec = reg.record()
    assert reg.hrefs[0] not in reg.fetch.calls
    assert _ids(rec) == reg.ids[1:]                        # the other two are still read
    assert reg.fetch.calls == [reg.issuer_url, reg.attributes_url, *reg.hrefs[1:]]


@pytest.mark.parametrize("bad", OTHER_PORTS)
@pytest.mark.parametrize("base,port", BASES)
def test_next_on_another_port_ends_the_walk(base: str, port: str, bad: str) -> None:
    reg = _serve(base=base, port=port, next_port=bad, paginate=True)
    assert reg.page2_url in reg.fetch.routes               # routed: a fetch would succeed

    rec = reg.record()
    assert reg.page2_url not in reg.fetch.calls
    assert reg.hrefs[2] not in reg.fetch.calls
    assert _ids(rec) == reg.ids[:2]                        # page 1 is kept, page 2 never read
    assert reg.fetch.calls == [reg.issuer_url, reg.attributes_url, *reg.hrefs[:2]]
