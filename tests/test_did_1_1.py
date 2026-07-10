"""
tests/test_did_1_1.py — DID 1.1 / CID 1.0 document tolerance (issue #76).

DID 1.1 (Candidate Recommendation Snapshot, 2026-03-05) rebases the DID document on
CID 1.0 and introduces the ``https://www.w3.org/ns/did/v1.1`` JSON-LD context. openvc's
``parse_did_document`` is **context-agnostic** — it reads the document *shape*
(``verificationMethod`` / relationships), never the ``@context`` — so a 1.1-shaped
document already resolves. These tests **pin** that tolerance so a future change cannot
silently start rejecting DID 1.1 the day issuers emit it. The relationship-semantics diff
is deferred until DID 1.1 reaches Proposed Recommendation (per the issue; nothing
speculative before CR exit).
"""
from __future__ import annotations

from openvc import verify_credential, VerificationPolicy
from openvc.did.base import DidResolutionError, parse_did_document
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite

DID = "did:web:university.example"
DID_V1_1 = "https://www.w3.org/ns/did/v1.1"
CID_V1 = "https://www.w3.org/ns/cid/v1"
VC2 = "https://www.w3.org/ns/credentials/v2"


def _multikey_ed25519(key: Ed25519SigningKey) -> str:
    return encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())


def _did_1_1_document(*, jwk_vm=None, multikey_vm=None) -> dict:
    """A DID 1.1 / CID 1.0-shaped document: the v1.1 + CID contexts, Multikey and/or
    JsonWebKey verification methods, and every relationship type."""
    vms = []
    if jwk_vm is not None:
        vms.append({"id": f"{DID}#jwk-1", "type": "JsonWebKey", "controller": DID,
                    "publicKeyJwk": jwk_vm})
    if multikey_vm is not None:
        vms.append({"id": f"{DID}#mk-1", "type": "Multikey", "controller": DID,
                    "publicKeyMultibase": multikey_vm})
    vm_ids = [vm["id"] for vm in vms]
    return {
        "@context": [DID_V1_1, CID_V1],
        "id": DID,
        "verificationMethod": vms,
        "authentication": vm_ids,
        "assertionMethod": vm_ids,
        "keyAgreement": vm_ids,
        "capabilityInvocation": vm_ids,
        "capabilityDelegation": vm_ids,
    }


class _StubResolver:
    def __init__(self, document: dict) -> None:
        self._doc = parse_did_document(document)

    def supports(self, did: str) -> bool:
        return did == DID

    def resolve(self, did: str):
        if did != DID:
            raise DidResolutionError(f"unknown DID {did!r}")
        return self._doc


def test_parse_did_1_1_cid_document_multikey_and_jwk():
    ed = Ed25519SigningKey.generate(kid="_")
    p256 = P256SigningKey.generate(kid="_")
    doc = parse_did_document(_did_1_1_document(
        jwk_vm=p256.public_jwk(), multikey_vm=_multikey_ed25519(ed)))

    assert doc.id == DID
    assert len(doc.verification_methods) == 2                # both encodings parsed
    by_id = {vm.id: vm for vm in doc.verification_methods}
    assert by_id[f"{DID}#mk-1"].public_key_jwk["crv"] == "Ed25519"   # Multikey -> JWK
    assert by_id[f"{DID}#jwk-1"].public_key_jwk["crv"] == "P-256"
    # every relationship the document declared came through
    for rel in ("authentication", "assertionMethod", "keyAgreement",
                "capabilityInvocation", "capabilityDelegation"):
        assert rel in doc.relationships and doc.relationships[rel]


def test_verify_credential_with_did_1_1_issuer_jwk():
    key = P256SigningKey.generate(kid=f"{DID}#jwk-1")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    doc = _did_1_1_document(jwk_vm=key.public_jwk())
    result = verify_credential(
        token, resolver=_StubResolver(doc), policy=VerificationPolicy(require_status=False))
    assert result.issuer == DID


def test_verify_credential_with_did_1_1_issuer_multikey():
    key = Ed25519SigningKey.generate(kid=f"{DID}#mk-1")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    doc = _did_1_1_document(multikey_vm=_multikey_ed25519(key))
    result = verify_credential(
        token, resolver=_StubResolver(doc), policy=VerificationPolicy(require_status=False))
    assert result.issuer == DID


def _credential() -> dict:
    return {
        "@context": [VC2],
        "id": "urn:uuid:did-1-1",
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "credentialSubject": {"id": "did:example:student", "degree": "BSc"},
    }
