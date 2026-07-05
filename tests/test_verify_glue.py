"""
tests/test_verify_glue.py — verify_ebsi_badge end to end, offline.

A dict-backed Fetch stands in for the EBSI registries, so the whole pipeline
(peek -> resolve -> select key -> verify signature -> TIR trust) runs
deterministically with no network. The badge and the accreditation are both real
VC-JWTs signed here, so signatures actually verify.
"""
from __future__ import annotations

import pytest

from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import SignatureInvalid, VcJwtProofSuite
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.verify import (
    IssuerNotTrusted,
    VerificationMethodNotFound,
    verify_ebsi_badge,
)
from openvc_ebsi.versioning import DidEbsiResolver, TirV5

BASE = "https://api-pilot.ebsi.eu"
ISSUER = "did:ebsi:zIssuerAAAAAAAAAAAAAAAAA"
TAO = "did:ebsi:zTAOBBBBBBBBBBBBBBBBBBB"
ROOT = "did:ebsi:zRootCCCCCCCCCCCCCCCCCC"


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


def _badge_token(suite: VcJwtProofSuite, sk: P256SigningKey) -> str:
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:badge-1",
        "type": ["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"],
        "issuer": ISSUER,
        "credentialSubject": {"id": "did:key:z6MkSubject", "achievement": {"name": "T"}},
    }
    return suite.sign(credential, signing_key=sk)


def _accreditation_token(suite: VcJwtProofSuite, *, issuer_type: str,
                         accredited_for: tuple[str, ...]) -> str:
    acc = {
        "id": "urn:uuid:acc-1",
        "type": ["VerifiableCredential", "VerifiableAccreditationToAttest"],
        "issuer": TAO,
        "credentialSubject": {
            "id": ISSUER,
            "issuerType": issuer_type,
            "accreditedBy": TAO,
            "rootTao": ROOT,
            "accreditedFor": list(accredited_for),
        },
    }
    return suite.sign(acc, signing_key=P256SigningKey.generate(kid=f"{TAO}#k"))


def _make(*, has_attributes: bool = True, issuer_type: str = "TI",
          accredited_for: tuple[str, ...] = ("OpenBadgeCredential",),
          publish_key: P256SigningKey | None = None, badge_kid: str | None = None):
    """Build (token, resolver) for a scenario. ``publish_key`` overrides the key
    the DID document publishes (for the wrong-key case); ``badge_kid`` overrides
    the kid the badge is signed with (for the VM-not-found case)."""
    suite = VcJwtProofSuite()
    kid = badge_kid or f"{ISSUER}#key-1"
    sk = P256SigningKey.generate(kid=kid)
    token = _badge_token(suite, sk)

    published = publish_key or sk
    did_doc = {
        "didDocument": {
            "id": ISSUER,
            "verificationMethod": [{
                "id": f"{ISSUER}#key-1",
                "type": "JsonWebKey2020",
                "controller": ISSUER,
                "publicKeyJwk": published.public_jwk(),
            }],
            "assertionMethod": [f"{ISSUER}#key-1"],
        }
    }

    issuer_url = f"{BASE}/trusted-issuers-registry/v5/issuers/{ISSUER}"
    attrs_url = f"{issuer_url}/attributes"
    revision_url = f"{attrs_url}/aa/revisions/bb"
    routes = {f"{BASE}/did-registry/v5/identifiers/{ISSUER}": did_doc}
    if has_attributes:
        routes[issuer_url] = {"did": ISSUER, "hasAttributes": True, "attributes": attrs_url}
        routes[attrs_url] = {"items": [{"id": "aa", "href": revision_url}]}
        routes[revision_url] = {
            "body": _accreditation_token(suite, issuer_type=issuer_type,
                                         accredited_for=accredited_for)}
    else:
        routes[issuer_url] = {"did": ISSUER, "hasAttributes": False}

    resolver = DidEbsiResolver(StubFetch(routes), decode_jwt=suite.peek_claims, tir=TirV5())
    return token, resolver, suite


def test_trusted_issuer_verifies_and_is_trusted():
    token, resolver, suite = _make()
    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                               expected_types=["OpenBadgeCredential"])
    assert result.issuer == ISSUER
    assert result.subject == "did:key:z6MkSubject"
    assert result.trusted is True
    assert result.accreditation is not None
    assert "OpenBadgeCredential" in result.accreditation.credential_types
    assert result.accreditation.tao == TAO


def test_untrusted_issuer_raises_when_required():
    token, resolver, suite = _make(has_attributes=False)
    with pytest.raises(IssuerNotTrusted):
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)


def test_untrusted_issuer_returned_when_trust_optional():
    token, resolver, suite = _make(has_attributes=False)
    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                               require_trust=False)
    assert result.trusted is False
    assert result.accreditation is None
    assert result.issuer == ISSUER          # signature still verified


def test_revoked_accreditation_is_not_trusted():
    token, resolver, suite = _make(issuer_type="revoked")
    with pytest.raises(IssuerNotTrusted):
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)


def test_accreditation_for_other_type_does_not_grant_trust():
    token, resolver, suite = _make(accredited_for=("SomeOtherCredential",))
    with pytest.raises(IssuerNotTrusted):
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                          expected_types=["OpenBadgeCredential"])


def test_verification_method_not_found():
    # Badge signed with a kid the DID document does not publish.
    token, resolver, suite = _make(badge_kid=f"{ISSUER}#ghost")
    with pytest.raises(VerificationMethodNotFound):
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)


def test_wrong_published_key_fails_signature():
    # The DID document publishes a different key than the one that signed.
    token, resolver, suite = _make(publish_key=P256SigningKey.generate(kid=f"{ISSUER}#key-1"))
    with pytest.raises(SignatureInvalid):
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)
