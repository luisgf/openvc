"""
tests/test_ebsi_verifier.py

Two tiers, by design:

  * OFFLINE (always run) — deterministic, no network:
      - full sign -> peek -> resolve -> verify round-trip using a stub Fetch;
      - TIR v5 adapter contract test exercising the multi-hop flow
        (issuer -> attributes -> revision -> decode body);
      - SSRF guard test for the HTTP client.
    These are the real safety net and the drift alarm.

  * LIVE (opt-in) — set OPENVC_EBSI_LIVE=1 to smoke-test against the real
    conformance environment. Skipped by default so CI never depends on an
    external service whose data rotates.

The TIR v5 adapter and DID-document checks run against GOLDEN FIXTURES recorded
verbatim from the pilot registry (tests/fixtures/ebsi/) — real wire shapes, so a
future EBSI change breaks a test rather than a user. Recording them caught two
real bugs: a 406 from the DID Registry's content negotiation, and the v5
`attribute.body` nesting the adapter had wrong.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import httpx
import pytest

from openvc.did.base import DidResolutionError, parse_did_document
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.errors import CredentialExpired
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import MalformedRegistryResponse
from openvc_ebsi.http import (
    EBSI_BASE,
    EBSI_HOSTS,
    EbsiHttpClient,
    HttpForbiddenHost,
    HttpNotFound,
    for_ebsi,
)
from openvc_ebsi.verify import (
    EbsiVerificationError,
    VerificationMethodNotFound,
    verify_ebsi_badge,
)
from openvc_ebsi.versioning import DidEbsiResolver, TirV5

PILOT_BASE = "https://api-pilot.ebsi.eu"


# --------------------------------------------------------------------------- #
# A dict-backed Fetch — this is why Fetch was injected as a plain callable.
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


# --------------------------------------------------------------------------- #
# Offline: full verification round-trip through the resolver
# --------------------------------------------------------------------------- #

def test_verify_roundtrip_via_resolver() -> None:
    did = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    kid = f"{did}#key-1"
    sk = P256SigningKey.generate(kid=kid)
    suite = VcJwtProofSuite()

    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:2f8a1c30-0000-4000-8000-000000000001",
        "type": ["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"],
        "issuer": did,
        "credentialSubject": {"id": "did:key:z6Mkexample", "achievement": {"name": "Test"}},
    }
    token = suite.sign(credential, signing_key=sk)

    # DID document fixture that publishes the signing key's PUBLIC jwk.
    did_doc = {
        "didDocument": {
            "id": did,
            "verificationMethod": [{
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": sk.public_jwk(),
            }],
            "assertionMethod": [kid],
        }
    }
    fetch = StubFetch({f"{PILOT_BASE}/did-registry/v5/identifiers/{did}": did_doc})
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims)

    # the exact pipeline verify_ebsi_badge performs:
    iss, header_kid = suite.peek_issuer(token)
    assert iss == did
    doc = resolver.resolve(iss)
    vm = doc.key_by_kid(header_kid)
    assert vm is not None
    verified = suite.verify(
        token, public_key_jwk=vm.public_key_jwk, expected_types=["OpenBadgeCredential"]
    )
    assert verified.issuer == did
    assert verified.subject == "did:key:z6Mkexample"


def test_verify_rejects_wrong_key() -> None:
    did = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    kid = f"{did}#key-1"
    suite = VcJwtProofSuite()
    token = suite.sign(
        {"id": "urn:uuid:x", "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:key:zX"}},
        signing_key=P256SigningKey.generate(kid=kid),
    )
    attacker = P256SigningKey.generate(kid=kid)          # different key, same kid
    from openvc.proof.vc_jwt import SignatureInvalid
    with pytest.raises(SignatureInvalid):
        suite.verify(token, public_key_jwk=attacker.public_jwk())


# --------------------------------------------------------------------------- #
# Offline: golden fixtures — TIR v5 + DID doc, recorded verbatim from pilot
# --------------------------------------------------------------------------- #

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _recorded_tir_routes() -> tuple[str, str, dict[str, dict]]:
    """The recorded TIR v5 multi-hop as a URL -> response map (verbatim pilot)."""
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, issuer["attributes"]: attributes}
    for item in attributes["items"]:
        routes[item["href"]] = revisions[item["id"]]
    return did, issuer["attributes"], routes


def test_didr_v5_parses_recorded_document() -> None:
    doc = parse_did_document(_load("didr_v5_identifiers.json"))
    assert doc.id == "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    assert doc.verification_methods, "recorded DID document has no verification methods"


def test_tir_v5_golden_issuer_record() -> None:
    suite = VcJwtProofSuite()
    did, attributes_url, routes = _recorded_tir_routes()
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=PILOT_BASE)

    rec = resolver.issuer_record(did)
    assert rec.has_attributes and len(rec.accreditations) == 3
    acc = rec.accreditations[0]
    assert acc.issuer_type == "RootTAO"                    # from attribute.issuerType
    assert acc.tao == did and acc.root_tao == did          # (from the attribute wrapper)
    assert "VerifiableAuthorisationForTrustChain" in acc.credential_types  # accreditedFor[].types
    assert acc.credential_jwt                              # extracted from attribute.body

    # the v5 multi-hop: issuer -> attributes -> one revision per listed item
    assert fetch.calls[0] == f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    assert fetch.calls[1] == attributes_url
    assert len(fetch.calls) == 2 + 3


def test_tir_v5_recorded_accreditation_signature_verifies() -> None:
    # Real ES256: a recorded accreditation verifies against the recorded DID
    # document's key — the whole pilot pipeline, frozen (did+ld+json parse -> key
    # selection -> signature verification of a genuine EBSI accreditation).
    suite = VcJwtProofSuite()
    did, _, routes = _recorded_tir_routes()
    resolver = DidEbsiResolver(StubFetch(routes), decode_jwt=suite.peek_claims,
                               tir=TirV5(), base=PILOT_BASE)
    acc = resolver.issuer_record(did).accreditations[0]
    doc = parse_did_document(_load("didr_v5_identifiers.json"))

    _, kid = suite.peek_issuer(acc.credential_jwt)
    vm = doc.key_by_kid(kid)
    assert vm is not None
    verified = suite.verify(acc.credential_jwt, public_key_jwk=vm.public_key_jwk)
    assert verified.issuer == did
    assert "VerifiableAccreditation" in verified.credential.get("type", [])


def test_tir_v5_issuer_404_is_problem_json() -> None:
    problem = _load("tir_v5_issuer_404_problem.json")      # RFC 7807 (ADR-0001 D7)
    assert problem["status"] == 404 and problem["title"] and problem["detail"]


# --------------------------------------------------------------------------- #
# Offline: TIR v5 /attributes pagination (production readiness — issue #64)
# --------------------------------------------------------------------------- #

def test_tir_v5_paginates_all_attribute_pages() -> None:
    # An issuer with more accreditations than one page: the listing spans two pages
    # (JSON:API `links.next` + `total`). The old adapter read only the first page and
    # silently dropped the rest — a fail-closed trust gap. Split the three recorded
    # items 2 + 1 across two pages and assert all three are still collected, in order.
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    items = attributes["items"]
    page1_url = issuer["attributes"]
    page2_url = page1_url + "?page[after]=1&page[size]=2"
    page1 = {"items": items[:2], "total": 3, "pageSize": 2,
             "links": {"self": page1_url, "next": page2_url}}
    page2 = {"items": items[2:], "total": 3, "pageSize": 2,
             "links": {"self": page2_url, "next": page2_url}}  # self-referential next
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, page1_url: page1, page2_url: page2}
    for item in items:
        routes[item["href"]] = revisions[item["id"]]

    fetch = StubFetch(routes)
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=PILOT_BASE)

    rec = resolver.issuer_record(did)
    assert rec.has_attributes and len(rec.accreditations) == 3      # both pages, not just page 1
    assert [a.attribute_id for a in rec.accreditations] == [i["id"] for i in items]  # order kept
    assert page1_url in fetch.calls and page2_url in fetch.calls
    assert fetch.calls.count(page2_url) == 1                        # total stopped the walk
    assert len(fetch.calls) == 1 + 2 + 3                            # issuer + 2 pages + 3 revisions


def test_tir_v5_pagination_terminates_on_self_referential_next() -> None:
    # EBSI returns `links.next` even on the last page, sometimes pointing at the SAME
    # URL. With no `total` to stop on, the seen-page guard must break the loop instead
    # of fetching forever.
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    attrs_url = issuer["attributes"]
    listing = {"items": attributes["items"], "links": {"next": attrs_url}}  # next == self, no total
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, attrs_url: listing}
    for item in attributes["items"]:
        routes[item["href"]] = revisions[item["id"]]

    fetch = StubFetch(routes)
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=PILOT_BASE)

    rec = resolver.issuer_record(did)
    assert len(rec.accreditations) == 3
    assert fetch.calls.count(attrs_url) == 1               # fetched once — did NOT loop


def test_tir_v5_pagination_does_not_follow_next_off_origin() -> None:
    # A compromised registry response cannot pivot pagination to another host via
    # `links.next` — the SSRF allow-list already bounds it, and the adapter additionally
    # refuses a `next` off the listing's own origin.
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    attrs_url = issuer["attributes"]
    evil = "https://attacker.example/trusted-issuers-registry/v5/issuers/x/attributes"
    listing = {"items": attributes["items"], "total": 99,          # claims more, but...
               "links": {"next": evil}}                            # ...next is off-origin
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, attrs_url: listing}
    for item in attributes["items"]:
        routes[item["href"]] = revisions[item["id"]]

    fetch = StubFetch(routes)
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=PILOT_BASE)

    rec = resolver.issuer_record(did)
    assert len(rec.accreditations) == 3
    assert evil not in fetch.calls                         # never fetched the foreign host


def test_tir_v5_attributes_url_off_origin_is_typed_error() -> None:
    # #172. `links.next` is origin-pinned (host AND port); `attributes` was not.
    # The HTTP client allow-list is hostname-only, so :9200 on an allow-listed
    # EBSI host would otherwise be fetched.
    issuer = _load("tir_v5_issuer.json")
    did = issuer["did"]
    evil = "https://api-pilot.ebsi.eu:9200/trusted-issuers-registry/v5/issuers/x/attributes"
    issuer = {**issuer, "attributes": evil}
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    fetch = StubFetch({issuer_url: issuer, evil: {"items": []}})
    resolver = DidEbsiResolver(
        fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=PILOT_BASE)
    with pytest.raises(MalformedRegistryResponse, match="listing origin"):
        resolver.issuer_record(did)
    assert evil not in fetch.calls


def test_tir_v5_href_off_origin_is_not_fetched() -> None:
    # #172. Same pin on each revision `href`.
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    evil = "https://api-pilot.ebsi.eu:2375/v1/steal"
    items = list(attributes["items"])
    items[0] = {**items[0], "href": evil}
    listing = {"items": items, "total": 3}
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, issuer["attributes"]: listing}
    for item in attributes["items"][1:]:
        routes[item["href"]] = revisions[item["id"]]
    routes[evil] = {"attribute": {"body": "x"}}
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(
        fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=PILOT_BASE)
    rec = resolver.issuer_record(did)
    assert evil not in fetch.calls
    assert len(rec.accreditations) == 2


# #243. A URL with no origin to compare made `_origin` raise a bare ValueError, outside
# OpenvcError. Each hop now treats it like an off-origin URL: `attributes` raises the
# typed error, an `href` is skipped, a `links.next` ends the walk. #246: so does a URL
# urlparse reads as same-origin but httpx would reject (a control character, a
# leading space, over-long) and a non-ASCII one, refused before urlparse.
UNPARSEABLE_URLS = [
    pytest.param("https://api-pilot.ebsi.eu:99999/x", id="port-out-of-range"),
    pytest.param("https://api-pilot.ebsi.eu:abc/x", id="port-not-numeric"),
    pytest.param("https://[::1/x", id="broken-ipv6"),
    pytest.param("https://api-pilot.ebsi.eu／x/y", id="non-ascii-host"),  # NFKC: '/'
    pytest.param("https://api-pilot.ebsi.eu/x/é", id="non-ascii-path"),
    pytest.param("https://api-pilot.ebsi.eu/x\ty", id="tab"),           # urlsplit drops it
    pytest.param("https://api-pilot.ebsi.eu/x\x00y", id="nul"),
    pytest.param("https://api-pilot.ebsi.eu/x\x7fy", id="del"),
    pytest.param(" https://api-pilot.ebsi.eu/x", id="leading-space"),   # urlsplit strips it
    pytest.param("https://api-pilot.ebsi.eu/" + "a" * 9000, id="over-long"),
]


def test_origin_refuses_non_ascii_before_urlparse(monkeypatch: pytest.MonkeyPatch) -> None:
    # The order matters on CPython <= 3.12, where urlparse NFKC-normalizes a non-ASCII
    # netloc in quadratic time: the check must run before urlparse ever sees the URL.
    from openvc_ebsi import _url, versioning

    def no_urlparse(url: str) -> None:
        raise AssertionError("urlparse reached")
    monkeypatch.setattr(_url, "urlparse", no_urlparse)     # the reader `_origin` calls
    with pytest.raises(MalformedRegistryResponse):
        versioning._origin("https://api-pilot.ebsi.eú/x")      # short: not the cap


@pytest.mark.parametrize("bad", UNPARSEABLE_URLS)
def test_tir_v5_unparseable_attributes_url_is_typed_error(bad: str) -> None:
    issuer = {**_load("tir_v5_issuer.json"), "attributes": bad}
    did = issuer["did"]
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    fetch = StubFetch({issuer_url: issuer})
    resolver = DidEbsiResolver(
        fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=PILOT_BASE)
    with pytest.raises(MalformedRegistryResponse) as exc_info:
        resolver.issuer_record(did)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert fetch.calls == [issuer_url]                     # nothing fetched past the issuer


@pytest.mark.parametrize("bad", UNPARSEABLE_URLS)
def test_tir_v5_unparseable_href_is_skipped(bad: str) -> None:
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    good = attributes["items"][1:]
    listing = {"items": [{**attributes["items"][0], "href": bad}, *good], "total": 3}
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, issuer["attributes"]: listing}
    for item in good:
        routes[item["href"]] = revisions[item["id"]]
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(
        fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=PILOT_BASE)
    rec = resolver.issuer_record(did)
    assert bad not in fetch.calls
    assert [a.attribute_id for a in rec.accreditations] == [i["id"] for i in good]


@pytest.mark.parametrize("bad", UNPARSEABLE_URLS)
def test_tir_v5_unparseable_next_ends_the_walk(bad: str) -> None:
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    page1 = attributes["items"][:2]
    attrs_url = issuer["attributes"]
    listing = {"items": page1, "total": 3, "links": {"next": bad}}  # claims a 2nd page
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, attrs_url: listing}
    for item in page1:
        routes[item["href"]] = revisions[item["id"]]
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(
        fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(), base=PILOT_BASE)
    rec = resolver.issuer_record(did)
    assert bad not in fetch.calls
    assert [a.attribute_id for a in rec.accreditations] == [i["id"] for i in page1]  # kept
    assert fetch.calls == [issuer_url, attrs_url, *(i["href"] for i in page1)]


@pytest.mark.parametrize("bad", UNPARSEABLE_URLS)
def test_verify_ebsi_badge_unparseable_attributes_url_is_openvc_error(bad: str) -> None:
    # The boundary itself: through verify_ebsi_badge the failure is an OpenvcError.
    did = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    kid = f"{did}#key-1"
    sk = P256SigningKey.generate(kid=kid)
    suite = VcJwtProofSuite()
    token = suite.sign(
        {"@context": ["https://www.w3.org/2018/credentials/v1"],
         "id": "urn:uuid:2f8a1c30-0000-4000-8000-000000000243",
         "type": ["VerifiableCredential", "VerifiableAttestation"], "issuer": did,
         "credentialSubject": {"id": "did:key:z6Mkexample"}},
        signing_key=sk)
    did_doc = {"didDocument": {
        "id": did,
        "verificationMethod": [{"id": kid, "type": "JsonWebKey2020",
                                "controller": did, "publicKeyJwk": sk.public_jwk()}],
        "assertionMethod": [kid]}}
    routes = {
        f"{PILOT_BASE}/did-registry/v5/identifiers/{did}": did_doc,
        f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}":
            {"did": did, "hasAttributes": True, "attributes": bad},
    }
    resolver = DidEbsiResolver(StubFetch(routes), decode_jwt=suite.peek_claims, base=PILOT_BASE)
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite, require_trust=False)
    assert type(exc_info.value) is MalformedRegistryResponse


@pytest.mark.parametrize("iss", [
    pytest.param("did:ebsi:z\tx", id="tab"),
    pytest.param("did:ebsi:z\x00x", id="nul"),
    pytest.param("did:ebsi:z\x7fx", id="del"),
    pytest.param("did:ebsi:" + "z" * 70_000, id="over-long"),   # httpx's own 64 KiB limit
])
def test_verify_ebsi_badge_hostile_iss_is_typed_before_any_request(iss: str) -> None:
    # #246. An unsigned token is enough: the issuer is peeked and put in the DID Registry
    # URL, which httpx rejected with a bare `httpx.InvalidURL`. Uses the real client so
    # the URL reaches httpx; the mock transport records any request that gets through.
    # Since #266 the resolver refuses the string as "not a did:ebsi identifier" before the
    # URL is built, so the client's `HttpForbiddenHost` (still pinned in test_ebsi_http.py
    # and, for a TIR href, below) is no longer what the caller sees: `EbsiVerificationError`.
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(404, json={})
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(client.get_json, decode_jwt=suite.peek_claims, base=PILOT_BASE)

    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    token = f"{seg({'alg': 'ES256', 'kid': iss + '#k'})}.{seg({'iss': iss, 'vc': {}})}.AAAA"
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)
    assert type(exc_info.value) is EbsiVerificationError
    assert type(exc_info.value.__cause__) is DidResolutionError
    assert "not a did:ebsi identifier" in str(exc_info.value)
    assert requests == []


def test_guard_host_still_guards_a_tir_href() -> None:
    # #246, the half #266 does not touch. A TIR `attributes` / `next` / `href` URL is
    # registry-supplied and never passes the DID check; the client's `_guard_host` is what
    # stands behind the origin pin. Direct test on a recorded revision `href`: the recorded
    # one passes, and each way it could be turned into a request the client must not make
    # is `HttpForbiddenHost`, before any I/O.
    href = _load("tir_v5_attributes.json")["items"][0]["href"]
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    try:
        client._guard_host(href)                                       # control: passes
        for bad in (
            href.replace("api-pilot.ebsi.eu", "evil.example"),         # host off the allow-list
            href.replace("https://", "http://", 1),                    # not https
            href + "\t", href + "\x00", href + "\x7f", href + " x",    # not visible ASCII
            href + "\u00e9",                                           # non-ASCII
            "https://api-pilot.ebsi.eu:99999/x",                       # port out of range
        ):
            with pytest.raises(HttpForbiddenHost) as exc_info:
                client._guard_host(bad)
            assert type(exc_info.value) is HttpForbiddenHost
    finally:
        client.close()


def test_resolver_over_the_real_client_refuses_a_tir_url_off_the_allow_list() -> None:
    # The same guard, reached through the resolver: a TIR issuer response whose
    # `attributes` URL is on the listing's origin (so the origin pin passes it) but on a
    # host the client does not allow. The issuer URL itself is served by a stub so the
    # walk gets as far as the `attributes` fetch; the mock transport records any request.
    other_base = "https://registry.example"
    did = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    issuer_url = f"{other_base}/trusted-issuers-registry/v5/issuers/{did}"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(404, json={})
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    def fetch(url: str) -> dict:
        if url == issuer_url:
            return {"did": did, "hasAttributes": True, "attributes": f"{issuer_url}/attributes"}
        return client.get_json(url)
    try:
        resolver = DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims,
                                   tir=TirV5(), base=other_base)
        with pytest.raises(HttpForbiddenHost) as exc_info:
            resolver.issuer_record(did)
        assert type(exc_info.value) is HttpForbiddenHost
        assert requests == []
    finally:
        client.close()


def test_tir_v5_malformed_registry_response_is_typed_error() -> None:
    # A non-object body (JSON `null` -> None, or an array/string/number — a flaky or
    # compromised registry) must fail closed as the typed EbsiError family, never leak a
    # bare AttributeError from a `.get` on a non-dict.
    tir = TirV5()
    decode = VcJwtProofSuite().peek_claims
    for bad in (None, [1, 2, 3], "oops", 42):
        with pytest.raises(MalformedRegistryResponse):
            tir.parse_issuer(bad, base=PILOT_BASE, did="did:ebsi:z",
                             fetch=lambda u: {}, decode=decode)
    # a well-formed issuer whose /attributes PAGE comes back as a non-object fails too
    attrs_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/did:ebsi:z/attributes"
    issuer = {"did": "did:ebsi:z", "hasAttributes": True, "attributes": attrs_url}
    with pytest.raises(MalformedRegistryResponse):
        tir.parse_issuer(issuer, base=PILOT_BASE, did="did:ebsi:z",
                         fetch=lambda u: None, decode=decode)      # null attributes page


def test_tir_v5_total_true_bool_does_not_truncate_pagination() -> None:
    # `"total": true` (a JSON bool) must NOT be read as int 1 and stop the walk after the
    # first page — bool is an int subclass, so the guard excludes it explicitly.
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    items = attributes["items"]
    page1_url = issuer["attributes"]
    page2_url = page1_url + "?page[after]=1"
    page1 = {"items": items[:2], "total": True, "links": {"next": page2_url}}  # bool total
    page2 = {"items": items[2:], "total": True, "links": {}}
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, page1_url: page1, page2_url: page2}
    for item in items:
        routes[item["href"]] = revisions[item["id"]]

    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims,
                               tir=TirV5(), base=PILOT_BASE)
    rec = resolver.issuer_record(did)
    assert len(rec.accreditations) == 3            # both pages read; total:true didn't stop us
    assert page2_url in fetch.calls


def test_tir_v5_pagination_caps_total_items() -> None:
    # The item cap bounds total revision fetches even for one huge page — a compromised
    # registry cannot fan a single verify into unbounded outbound requests.
    issuer = _load("tir_v5_issuer.json")
    attributes = _load("tir_v5_attributes.json")
    revisions = _load("tir_v5_revisions.json")
    did = issuer["did"]
    attrs_url = issuer["attributes"]
    listing = {"items": attributes["items"]}                   # 3 items, single page
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, dict] = {issuer_url: issuer, attrs_url: listing}
    for item in attributes["items"]:
        routes[item["href"]] = revisions[item["id"]]

    fetch = StubFetch(routes)
    tir = TirV5()
    tir._MAX_ATTRIBUTE_ITEMS = 2                                # shrink the cap for the test
    resolver = DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims,
                               tir=tir, base=PILOT_BASE)
    rec = resolver.issuer_record(did)
    assert len(rec.accreditations) == 2                        # capped at 2 of 3
    assert attributes["items"][2]["href"] not in fetch.calls   # 3rd revision never fetched


# --------------------------------------------------------------------------- #
# Offline: VCDM 1.1 / 2.0 dual envelope (Conformance v4 — issue #64)
# --------------------------------------------------------------------------- #

def test_verify_ebsi_badge_accepts_vcdm2_envelope() -> None:
    # EBSI Conformance v4 issues VCDM 2.0 credentials still wrapped in the JWT `vc`
    # claim (vc.validFrom / vc.validUntil replace issuanceDate / expirationDate). Prove
    # the whole badge path verifies a 2.0-generation envelope, not just 1.1.
    did = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    kid = f"{did}#key-1"
    sk = P256SigningKey.generate(kid=kid)
    suite = VcJwtProofSuite()
    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],           # VCDM 2.0 context
        "id": "urn:uuid:2f8a1c30-0000-4000-8000-0000000000c2",
        "type": ["VerifiableCredential", "VerifiableAttestation"],
        "issuer": did,
        "validFrom": "2025-01-01T00:00:00Z",                            # 2.0 field names
        "validUntil": "2035-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:key:z6Mkexample", "claim": "ok"},
    }
    token = suite.sign(credential, signing_key=sk)
    did_doc = {"didDocument": {
        "id": did,
        "verificationMethod": [{"id": kid, "type": "JsonWebKey2020",
                                "controller": did, "publicKeyJwk": sk.public_jwk()}],
        "assertionMethod": [kid]}}
    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{did}"
    routes = {
        f"{PILOT_BASE}/did-registry/v5/identifiers/{did}": did_doc,
        issuer_url: {"did": did, "hasAttributes": False},               # untrusted issuer...
    }
    resolver = DidEbsiResolver(StubFetch(routes), decode_jwt=suite.peek_claims, base=PILOT_BASE)

    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                               require_trust=False)                     # ...so require_trust=False
    assert result.issuer == did
    assert result.subject == "did:key:z6Mkexample"
    assert result.trusted is False
    assert result.credential["validFrom"] == "2025-01-01T00:00:00Z"    # the 2.0 body round-trips


def test_verify_ebsi_badge_rejects_expired_vcdm2_envelope() -> None:
    # The temporal gap the adversarial review surfaced: a VCDM 2.0 credential that
    # encodes expiry only in vc.validUntil (no JWT `exp`, as EBSI's signer emits) must be
    # rejected end-to-end, not accepted because the JWT carried no expiry claim.
    did = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    kid = f"{did}#key-1"
    sk = P256SigningKey.generate(kid=kid)
    suite = VcJwtProofSuite()
    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:2f8a1c30-0000-4000-8000-0000000000e2",
        "type": ["VerifiableCredential", "VerifiableAttestation"],
        "issuer": did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2021-01-01T00:00:00Z",                           # expired years ago
        "credentialSubject": {"id": "did:key:z6Mkexample"},
    }
    token = suite.sign(credential, signing_key=sk)                      # sign emits no JWT exp
    did_doc = {"didDocument": {
        "id": did,
        "verificationMethod": [{"id": kid, "type": "JsonWebKey2020",
                                "controller": did, "publicKeyJwk": sk.public_jwk()}],
        "assertionMethod": [kid]}}
    routes = {f"{PILOT_BASE}/did-registry/v5/identifiers/{did}": did_doc}
    resolver = DidEbsiResolver(StubFetch(routes), decode_jwt=suite.peek_claims, base=PILOT_BASE)

    with pytest.raises(CredentialExpired):                              # fails closed at verify
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite, require_trust=False)


# --------------------------------------------------------------------------- #
# Offline: production environment selection (issue #64)
# --------------------------------------------------------------------------- #

def test_for_ebsi_production_environment_is_registered() -> None:
    assert EBSI_HOSTS["production"] == "api.ebsi.eu"
    assert EBSI_BASE["production"] == "https://api.ebsi.eu"
    with for_ebsi("production") as http:
        # the production allow-list is scoped to production — a pilot host is rejected
        # by the SSRF guard before any network call.
        with pytest.raises(HttpForbiddenHost):
            http.get_json("https://api-pilot.ebsi.eu/anything")


# --------------------------------------------------------------------------- #
# Offline: SSRF guard
# --------------------------------------------------------------------------- #

def test_ssrf_guard_blocks_foreign_and_plaintext_hosts() -> None:
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    try:
        with pytest.raises(HttpForbiddenHost):
            client.get_json("https://169.254.169.254/latest/meta-data/")   # cloud metadata
        with pytest.raises(HttpForbiddenHost):
            client.get_json("http://api-pilot.ebsi.eu/anything")           # non-https
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# Offline: the registry document is bound to the DID that was asked for (#257)
# --------------------------------------------------------------------------- #
#
# `resolve(did)` must return the document OF `did`. did:web compares the parsed
# document `id` with the DID, did:webvh compares the log state's, did:key / did:jwk derive
# the document from the DID; the EBSI resolver compared nothing, so a document for another
# subject (or with no usable `id`) resolved and `key_by_kid` found its keys. Every case
# below serves a document that is otherwise good (it holds the signing key under the right
# kid), and each negative is paired with a control carrying the right `id`, so the `id` is
# the only thing that can make it fail.

def _did(seed: int) -> str:
    # A well-formed did:ebsi identifier (#266): `z` + base58btc(version byte 1 || 16 bytes).
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


BIND_DID = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
BIND_KID = f"{BIND_DID}#key-1"
BIND_URL = f"{PILOT_BASE}/did-registry/v5/identifiers/{BIND_DID}"
_ABSENT = object()                              # the document has no `id` member at all

# the document `id` member: not the requested DID, or not a usable string at all
WRONG_IDS = [
    pytest.param(_did(0xD4), id="another-did"),
    pytest.param(7, id="number"),
    pytest.param(None, id="null"),
    pytest.param([], id="list"),
    pytest.param({}, id="object"),
    pytest.param(True, id="bool"),
    pytest.param("", id="empty"),
    pytest.param(_ABSENT, id="absent"),
    pytest.param(BIND_DID.lower(), id="case-folded"),        # base58btc is case-sensitive
    pytest.param(BIND_DID + " ", id="trailing-space"),
    pytest.param(BIND_KID, id="did-url"),                    # a DID URL is not the DID
    pytest.param("did:web:example.com", id="another-method"),
]


def _bind_doc(sk: P256SigningKey, doc_id: object, *, wrapped: bool) -> dict:
    """A registry document that holds *sk*'s public key under BIND_KID, with the `id`
    member set to *doc_id* (left out for ``_ABSENT``), bare or in a `didDocument` wrapper."""
    doc: dict = {
        "verificationMethod": [{"id": BIND_KID, "type": "JsonWebKey2020",
                                "controller": BIND_DID, "publicKeyJwk": sk.public_jwk()}],
        "assertionMethod": [BIND_KID],
    }
    if doc_id is not _ABSENT:
        doc = {"id": doc_id, **doc}
    return {"didDocument": doc} if wrapped else doc


def _bind_resolver(doc: dict, suite: VcJwtProofSuite) -> DidEbsiResolver:
    # The route is keyed on the exact registry URL, so a request for anything else is a
    # HttpNotFound (a different class), not a pass for the exact-class assertions.
    return DidEbsiResolver(StubFetch({BIND_URL: doc}), decode_jwt=suite.peek_claims,
                           base=PILOT_BASE)


@pytest.mark.parametrize("wrapped", [False, True], ids=["bare", "wrapper"])
def test_resolve_accepts_the_document_whose_id_is_the_did(wrapped: bool) -> None:
    sk = P256SigningKey.generate(kid=BIND_KID)
    doc = _bind_resolver(_bind_doc(sk, BIND_DID, wrapped=wrapped),
                         VcJwtProofSuite()).resolve(BIND_DID)
    assert doc.id == BIND_DID
    vm = doc.key_by_kid(BIND_KID)
    assert vm is not None and vm.public_key_jwk == sk.public_jwk()


def test_resolve_accepts_the_recorded_registry_document() -> None:
    # The golden fixture (verbatim from the pilot registry) has `id` == the DID it was
    # fetched for, so the real registry passes the check.
    recorded = _load("didr_v5_identifiers.json")
    did = recorded["id"]
    assert did == BIND_DID
    resolver = DidEbsiResolver(
        StubFetch({f"{PILOT_BASE}/did-registry/v5/identifiers/{did}": recorded}),
        decode_jwt=VcJwtProofSuite().peek_claims, base=PILOT_BASE)
    doc = resolver.resolve(did)
    assert doc.id == did and doc.verification_methods


@pytest.mark.parametrize("wrapped", [False, True], ids=["bare", "wrapper"])
@pytest.mark.parametrize("doc_id", WRONG_IDS)
def test_resolve_refuses_a_document_that_is_not_for_the_requested_did(
        doc_id: object, wrapped: bool) -> None:
    sk = P256SigningKey.generate(kid=BIND_KID)
    suite = VcJwtProofSuite()
    # control: the same document with the right `id` resolves and names the key ...
    good = _bind_resolver(_bind_doc(sk, BIND_DID, wrapped=wrapped), suite)
    assert good.resolve(BIND_DID).key_by_kid(BIND_KID) is not None
    # ... so the `id` is the only thing wrong with this one
    resolver = _bind_resolver(_bind_doc(sk, doc_id, wrapped=wrapped), suite)
    with pytest.raises(DidResolutionError, match="!= requested") as exc_info:
        resolver.resolve(BIND_DID)
    assert type(exc_info.value) is DidResolutionError


@pytest.mark.parametrize("wrapped", [False, True], ids=["bare", "wrapper"])
@pytest.mark.parametrize("doc_id", [
    pytest.param("", id="empty"),
    pytest.param(7, id="number"),
    pytest.param(_ABSENT, id="absent"),
])
def test_resolve_refuses_the_empty_did_before_it_asks_the_registry(
        doc_id: object, wrapped: bool) -> None:
    # #257 pinned that a document with no usable `id` (the parser reads it as "") is not
    # accepted for resolve(""), where "" == "". Since #266 the empty string is not a
    # did:ebsi identifier, so it never reaches the registry: refused on syntax, with no
    # request, whatever the document at the (empty) identifier URL would have held. The
    # document-side refusal is still pinned, for a well-formed DID, by WRONG_IDS (empty,
    # number and absent among them).
    sk = P256SigningKey.generate(kid=BIND_KID)
    suite = VcJwtProofSuite()
    empty_url = f"{PILOT_BASE}/did-registry/v5/identifiers/"          # identifiers_url(base, "")
    fetch = StubFetch({empty_url: _bind_doc(sk, doc_id, wrapped=wrapped)})
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, base=PILOT_BASE)
    with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
        resolver.resolve("")
    assert type(exc_info.value) is DidResolutionError
    assert fetch.calls == []
    # control: the same kind of document, asked for by a well-formed DID, resolves
    assert _bind_resolver(_bind_doc(sk, BIND_DID, wrapped=wrapped),
                          suite).resolve(BIND_DID).id == BIND_DID


@pytest.mark.parametrize("wrapped", [False, True], ids=["bare", "wrapper"])
@pytest.mark.parametrize("doc_id", WRONG_IDS)
def test_verify_ebsi_badge_refuses_a_document_that_is_not_for_the_issuer(
        doc_id: object, wrapped: bool) -> None:
    sk = P256SigningKey.generate(kid=BIND_KID)
    suite = VcJwtProofSuite()
    token = suite.sign(
        {"@context": ["https://www.w3.org/2018/credentials/v1"],
         "id": "urn:uuid:2f8a1c30-0000-4000-8000-000000000257",
         "type": ["VerifiableCredential", "VerifiableAttestation"], "issuer": BIND_DID,
         "credentialSubject": {"id": "did:key:z6Mkexample"}},
        signing_key=sk)

    def resolver_for(doc: dict) -> DidEbsiResolver:
        routes = {BIND_URL: doc,
                  f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{BIND_DID}":
                      {"did": BIND_DID, "hasAttributes": False}}
        return DidEbsiResolver(StubFetch(routes), decode_jwt=suite.peek_claims,
                               base=PILOT_BASE)

    # control: the token verifies against the document with the right `id` ...
    ok = verify_ebsi_badge(
        token, resolver=resolver_for(_bind_doc(sk, BIND_DID, wrapped=wrapped)),
        proof_suite=suite, require_trust=False)
    assert ok.issuer == BIND_DID
    # ... and the signature is good against the wrong-`id` document too: only the binding
    # stops it
    resolver = resolver_for(_bind_doc(sk, doc_id, wrapped=wrapped))
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite, require_trust=False)
    assert type(exc_info.value) is EbsiVerificationError
    assert type(exc_info.value.__cause__) is DidResolutionError
    assert "!= requested" in str(exc_info.value)


def _registry_client(routes: dict[str, dict], paths: list[str]) -> EbsiHttpClient:
    """The real client over a mock transport: httpx does the URL handling (it drops a
    fragment and collapses dot segments before the request is sent), the handler serves
    a registry that answers the *path* it receives."""
    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        body = routes.get(request.url.path)
        return httpx.Response(404, json={}) if body is None else httpx.Response(200, json=body)
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def test_resolve_refuses_a_did_url_before_it_asks_the_registry() -> None:
    # A DID URL passed as the DID resolved by accident (#257): httpx drops the fragment, so
    # the registry returned the DID's own document, and the document `id` check refused it
    # afterwards. A DID URL is not a DID (iss and accreditedBy are DIDs), so since #266 it
    # is refused on syntax and the registry is not asked at all.
    sk = P256SigningKey.generate(kid=BIND_KID)
    suite = VcJwtProofSuite()
    paths: list[str] = []
    registry_path = f"/did-registry/v5/identifiers/{BIND_DID}"
    client = _registry_client({registry_path: _bind_doc(sk, BIND_DID, wrapped=False)}, paths)
    resolver = DidEbsiResolver(client.get_json, decode_jwt=suite.peek_claims, base=PILOT_BASE)
    assert resolver.resolve(BIND_DID).id == BIND_DID                  # control
    with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
        resolver.resolve(BIND_KID)
    assert type(exc_info.value) is DidResolutionError
    assert paths == [registry_path]                   # the control's request only: none for the URL

    token = suite.sign(
        {"id": "urn:uuid:x", "type": ["VerifiableCredential"], "issuer": BIND_KID,
         "credentialSubject": {"id": "did:key:zX"}}, signing_key=sk)
    with pytest.raises(OpenvcError) as vexc:                          # a DID URL as `iss`
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite, require_trust=False)
    assert type(vexc.value) is EbsiVerificationError
    assert type(vexc.value.__cause__) is DidResolutionError
    assert paths == [registry_path]
    client.close()


def test_resolve_refuses_a_dot_segment_iss_before_it_asks_the_registry() -> None:
    # An unsigned token's `iss` is put into the registry path, so before #266 `zA/../zB`
    # made httpx request B's resource; B's document then came back and #257's binding
    # refused it because its `id` was not the requested string. Now the string is refused
    # on syntax and the request is never made. The control proves B's resource is served
    # and that the registry does answer the collapsed path.
    other = _did(0xE5)
    sk = P256SigningKey.generate(kid=BIND_KID)
    other_doc = {"id": other, "verificationMethod": [{
        "id": f"{other}#key-1", "type": "JsonWebKey2020", "controller": other,
        "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{other}#key-1"]}
    paths: list[str] = []
    other_path = f"/did-registry/v5/identifiers/{other}"
    client = _registry_client({other_path: other_doc}, paths)
    resolver = DidEbsiResolver(client.get_json, decode_jwt=VcJwtProofSuite().peek_claims,
                               base=PILOT_BASE)
    assert resolver.resolve(other).id == other                        # control
    steered = f"{BIND_DID}/../{other}"
    with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
        resolver.resolve(steered)
    assert type(exc_info.value) is DidResolutionError
    assert paths == [other_path]                        # the control's request only
    client.close()


def test_resolve_mismatch_message_is_bounded() -> None:
    # The document `id` is registry-supplied and the requested DID is a token's `iss`:
    # both are attacker-sized, and both are cut to 200 characters in their messages. A
    # requested DID of that size is not a did:ebsi identifier (#266), so it is refused on
    # syntax with its own bounded message; the document `id` is the side that can still be
    # long at the comparison.
    long_other = "did:ebsi:" + "y" * 60_000
    sk = P256SigningKey.generate(kid=BIND_KID)
    suite = VcJwtProofSuite()

    def resolver_for(doc_id: str, calls: list[str] | None = None) -> DidEbsiResolver:
        doc = _bind_doc(sk, doc_id, wrapped=False)

        def fetch(url: str) -> dict:
            if calls is not None:
                calls.append(url)
            return doc
        return DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, base=PILOT_BASE)

    assert resolver_for(BIND_DID).resolve(BIND_DID).id == BIND_DID    # control
    with pytest.raises(DidResolutionError) as exc_info:
        resolver_for(long_other).resolve(BIND_DID)
    assert type(exc_info.value) is DidResolutionError
    assert len(long_other) == 60_009
    assert str(exc_info.value) == (                    # the registry's side, cut at 200 characters
        f"document id {long_other[:200]!r}... (60009 chars) != requested {BIND_DID!r}")

    long_did = "did:ebsi:" + "z" * 60_000
    calls: list[str] = []
    with pytest.raises(DidResolutionError) as syntax_info:
        resolver_for(long_did, calls).resolve(long_did)
    assert type(syntax_info.value) is DidResolutionError
    assert str(syntax_info.value) == (                 # the requested side, cut at 200 characters
        f"not a did:ebsi identifier: {long_did[:200]!r}... (60009 chars)")
    assert calls == []


def _long_did_registry(doc: dict, did: str):
    """A fetch that serves *doc* for any DID Registry URL and a no-attribute TIR entry
    for *did*, so a token issued by *did* can run the whole of `verify_ebsi_badge`."""
    def fetch(url: str) -> dict:
        if "/did-registry/" in url:
            return doc
        if "/trusted-issuers-registry/" in url:
            return {"did": did, "hasAttributes": False}
        raise HttpNotFound("no stub route", url=url)
    return fetch


def _long_issuer_token(suite: VcJwtProofSuite, sk: P256SigningKey, issuer: str) -> str:
    return suite.sign(
        {"@context": ["https://www.w3.org/2018/credentials/v1"],
         "id": "urn:uuid:2f8a1c30-0000-4000-8000-000000000259",
         "type": ["VerifiableCredential", "VerifiableAttestation"], "issuer": issuer,
         "credentialSubject": {"id": "did:key:z6Mkexample"}},
        signing_key=sk)


def test_verify_ebsi_badge_wrapper_messages_are_bounded() -> None:
    # The resolver's own message is cut (above), but `verify_ebsi_badge` wraps it in a
    # message of its own, and that one names the issuer (a token's `iss`, attacker-sized)
    # and the `kid` (a header field, equally so). Each is cut at 200 characters too. An
    # `iss` of that size is not a did:ebsi identifier (#266), so the DID-sized cases are:
    # the `iss` itself, a registry document whose `id` is long, and a long `kid`.
    long_did = "did:ebsi:" + "z" * 60_000                       # an `iss` that is not a DID
    long_other = "did:ebsi:" + "y" * 60_000                     # a registry-supplied `id`
    long_kid = f"{BIND_DID}#" + "k" * 60_000
    sk = P256SigningKey.generate(kid=long_kid)
    suite = VcJwtProofSuite()
    token = _long_issuer_token(suite, sk, BIND_DID)

    def doc_with(doc_id: str, vm_id: str) -> dict:
        return {"id": doc_id, "verificationMethod": [{
            "id": vm_id, "type": "JsonWebKey2020", "controller": doc_id,
            "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [vm_id]}

    def resolver_for(doc: dict, did: str, calls: list[str] | None = None) -> DidEbsiResolver:
        inner = _long_did_registry(doc, did)

        def fetch(url: str) -> dict:
            if calls is not None:
                calls.append(url)
            return inner(url)
        return DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, base=PILOT_BASE)

    # control: the same sizes, a document that is for the issuer and holds the key, verify
    ok = verify_ebsi_badge(token, resolver=resolver_for(doc_with(BIND_DID, long_kid), BIND_DID),
                           proof_suite=suite, require_trust=False)
    assert ok.issuer == BIND_DID

    # an `iss` that is not a did:ebsi identifier: the resolve wrapper, no request at all
    calls: list[str] = []
    long_token = _long_issuer_token(suite, sk, long_did)
    with pytest.raises(OpenvcError) as syntax_info:
        verify_ebsi_badge(long_token,
                          resolver=resolver_for(doc_with(long_did, long_kid), long_did, calls),
                          proof_suite=suite, require_trust=False)
    assert type(syntax_info.value) is EbsiVerificationError
    assert type(syntax_info.value.__cause__) is DidResolutionError
    assert str(syntax_info.value) == (
        f"could not resolve issuer DID {long_did[:200]!r}... (60009 chars): "
        f"not a did:ebsi identifier: {long_did[:200]!r}... (60009 chars)")
    assert calls == []

    # the registry answers with another subject's document, whose `id` is long
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(token,
                          resolver=resolver_for(doc_with(long_other, long_kid), BIND_DID),
                          proof_suite=suite, require_trust=False)
    assert type(exc_info.value) is EbsiVerificationError
    assert type(exc_info.value.__cause__) is DidResolutionError
    assert str(exc_info.value) == (
        f"could not resolve issuer DID {BIND_DID!r}: "
        f"document id {long_other[:200]!r}... (60009 chars) != requested {BIND_DID!r}")

    # the document is the issuer's but holds no key under the token's `kid`
    with pytest.raises(OpenvcError) as vm_info:
        verify_ebsi_badge(token,
                          resolver=resolver_for(doc_with(BIND_DID, f"{BIND_DID}#other"), BIND_DID),
                          proof_suite=suite, require_trust=False)
    assert type(vm_info.value) is VerificationMethodNotFound
    assert str(vm_info.value) == (
        f"no verification method for kid {long_kid[:200]!r}... ({len(long_kid)} chars) in DID "
        f"{BIND_DID!r}")


# --------------------------------------------------------------------------- #
# Live (opt-in): smoke test against real conformance
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(os.getenv("OPENVC_EBSI_LIVE") != "1", reason="live EBSI test is opt-in")
def test_live_resolve() -> None:
    # Smoke-test real DID resolution — exercises the did+ld+json content
    # negotiation the offline tests can't. Defaults to the pilot registry + a known
    # pilot DID; override with OPENVC_EBSI_ENV / OPENVC_EBSI_DID.
    env = os.getenv("OPENVC_EBSI_ENV", "pilot")
    did = os.getenv("OPENVC_EBSI_DID", "did:ebsi:zZeKyEJfUTGwajhNyNX928z")
    suite = VcJwtProofSuite()
    with for_ebsi(env) as http:
        resolver = DidEbsiResolver(http.get_json, decode_jwt=suite.peek_claims,
                                   base=EBSI_BASE[env])
        doc = resolver.resolve(did)
        assert doc.id == did
        assert doc.verification_methods, "expected at least one verification method"
