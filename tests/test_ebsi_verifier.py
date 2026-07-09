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

import json
import os
from pathlib import Path

import pytest

from openvc.did.base import parse_did_document
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import (
    EBSI_BASE,
    EBSI_HOSTS,
    EbsiHttpClient,
    HttpForbiddenHost,
    HttpNotFound,
    for_ebsi,
)
from openvc_ebsi.verify import verify_ebsi_badge
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
