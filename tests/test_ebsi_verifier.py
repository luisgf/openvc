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

Replace the inline fixtures with RECORDED real responses from conformance to turn
the adapter tests into true golden-fixture tests. The shapes here follow the v5
responses but are representative, not verbatim.
"""

from __future__ import annotations

import os

import pytest

from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import EbsiHttpClient, HttpForbiddenHost, HttpNotFound, for_ebsi
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
# Offline: TIR v5 adapter contract test — the multi-hop flow
# --------------------------------------------------------------------------- #

def test_tir_v5_parses_trust_chain() -> None:
    issuer_did = "did:ebsi:zIssuerAAAAAAAAAAAAAAAAA"
    tao_did = "did:ebsi:zTAOBBBBBBBBBBBBBBBBBBB"
    root_did = "did:ebsi:zRootCCCCCCCCCCCCCCCCCC"
    suite = VcJwtProofSuite()

    # The accreditation body is itself a VC-JWT; sign one so peek_claims can read it.
    accreditation = {
        "id": "urn:uuid:acc-1",
        "type": ["VerifiableCredential", "VerifiableAttestation",
                 "VerifiableAccreditation", "VerifiableAccreditationToAttest"],
        "issuer": tao_did,
        "credentialSubject": {
            "id": issuer_did,
            "issuerType": "TI",
            "accreditedBy": tao_did,
            "rootTao": root_did,
            "accreditedFor": ["OpenBadgeCredential"],
        },
    }
    body = suite.sign(accreditation, signing_key=P256SigningKey.generate(kid=f"{tao_did}#k"))

    issuer_url = f"{PILOT_BASE}/trusted-issuers-registry/v5/issuers/{issuer_did}"
    attrs_url = f"{issuer_url}/attributes"
    revision_url = f"{attrs_url}/447867baf/revisions/4ec707f1d"

    routes = {
        issuer_url: {"did": issuer_did, "hasAttributes": True},
        attrs_url: {"items": [{"id": "447867baf", "href": revision_url}]},
        revision_url: {"body": body},
    }
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5())

    rec = resolver.issuer_record(issuer_did)
    assert rec.has_attributes
    assert len(rec.accreditations) == 1
    acc = rec.accreditations[0]
    assert acc.issuer_type == "TI"
    assert acc.tao == tao_did
    assert acc.root_tao == root_did
    assert "OpenBadgeCredential" in acc.credential_types
    assert not acc.is_revoked

    # proves the v5 multi-hop happened: issuer -> attributes -> revision
    assert fetch.calls == [issuer_url, attrs_url, revision_url]


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
def test_live_resolve_conformance() -> None:
    # Confirm the DID + paths against hub.ebsi.eu; conformance data rotates.
    did = os.getenv("OPENVC_EBSI_DID", "did:ebsi:zZeKyEJfUTGwajhNyNX928z")
    suite = VcJwtProofSuite()
    with for_ebsi("conformance") as http:
        resolver = DidEbsiResolver(
            http.get_json, decode_jwt=suite.peek_claims,
            base="https://api-conformance.ebsi.eu",
        )
        doc = resolver.resolve(did)
        assert doc.id == did
        assert doc.verification_methods, "expected at least one verification method"
