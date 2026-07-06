"""
tests/test_vp_jwt.py — VP-JWT holder presentations (Etapa 9): sign, then verify the
holder signature + audience/nonce binding + the cascade verification of every
embedded credential through the generic pipeline. All offline.
"""
from __future__ import annotations

import pytest

from openvc import VerificationPolicy
from openvc.did.base import DidResolutionError, parse_did_document
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof.vc_jwt import ClaimsInvalid, SignatureInvalid, VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

VC2 = "https://www.w3.org/ns/credentials/v2"
ISSUER, ISSUER_VM = "did:web:issuer.example", "did:web:issuer.example#k"
HOLDER, HOLDER_VM = "did:web:holder.example", "did:web:holder.example#k"
AUD, NONCE = "https://verifier.example", "chal-123"


class _Registry:
    def __init__(self):
        self._docs: dict[str, object] = {}

    def add(self, did, vm_id, jwk):
        self._docs[did] = parse_did_document({
            "id": did,
            "verificationMethod": [{"id": vm_id, "type": "JsonWebKey2020",
                                    "controller": did, "publicKeyJwk": jwk}],
            "assertionMethod": [vm_id], "authentication": [vm_id],
        })
        return self

    def supports(self, did):
        return did in self._docs

    def resolve(self, did):
        try:
            return self._docs[did]
        except KeyError:
            raise DidResolutionError(f"unknown {did!r}") from None


def _vc(issuer_key):
    cred = {
        "@context": [VC2], "id": "urn:uuid:1", "type": ["VerifiableCredential"],
        "issuer": ISSUER, "credentialSubject": {"id": HOLDER},
    }
    return VcJwtProofSuite().sign(cred, signing_key=issuer_key)


def _setup():
    ik = P256SigningKey.generate(kid=ISSUER_VM)
    hk = Ed25519SigningKey.generate(kid=HOLDER_VM)
    reg = _Registry().add(ISSUER, ISSUER_VM, ik.public_jwk())
    reg.add(HOLDER, HOLDER_VM, hk.public_jwk())
    vp = VpJwtProofSuite().sign([_vc(ik)], holder_key=hk, audience=AUD, nonce=NONCE)
    return vp, reg, hk


def _verify(vp, reg, **over):
    kw = dict(audience=AUD, nonce=NONCE, resolver=reg,
              policy=VerificationPolicy(require_status=False))
    kw.update(over)
    return VpJwtProofSuite().verify(vp, **kw)


def test_vp_roundtrip_verifies_holder_and_cascades_to_the_vc():
    vp, reg, _ = _setup()
    result = _verify(vp, reg)
    assert result.holder == HOLDER
    assert len(result.credentials) == 1
    assert result.credentials[0].issuer == ISSUER
    assert result.claims["nonce"] == NONCE


def test_wrong_audience_rejected():
    vp, reg, _ = _setup()
    with pytest.raises(ClaimsInvalid, match="aud"):
        _verify(vp, reg, audience="https://attacker.example")


def test_wrong_nonce_rejected():
    vp, reg, _ = _setup()
    with pytest.raises(ClaimsInvalid, match="nonce"):
        _verify(vp, reg, nonce="replayed")


def test_tampered_vp_signature_rejected():
    vp, reg, _ = _setup()
    head, payload, sig = vp.split(".")
    forged = f"{head}.{payload}.{sig[:-4]}AAAA"          # corrupt the signature
    with pytest.raises(SignatureInvalid):
        _verify(forged, reg)


def test_invalid_embedded_credential_fails_the_presentation():
    # the VC is signed by a key the registry does not know -> the cascade rejects it
    from openvc.verify import KeyResolutionFailed

    hk = Ed25519SigningKey.generate(kid=HOLDER_VM)
    stray_issuer = P256SigningKey.generate(kid=ISSUER_VM)
    reg = _Registry().add(HOLDER, HOLDER_VM, hk.public_jwk())   # holder known, issuer NOT
    vp = VpJwtProofSuite().sign([_vc(stray_issuer)], holder_key=hk, audience=AUD, nonce=NONCE)
    with pytest.raises(KeyResolutionFailed):
        _verify(vp, reg)


def test_holder_key_can_be_pinned():
    vp, reg, hk = _setup()
    result = VpJwtProofSuite().verify(
        vp, audience=AUD, nonce=NONCE, holder_key_jwk=hk.public_jwk(), resolver=reg,
        policy=VerificationPolicy(require_status=False))
    assert result.holder == HOLDER


def test_holder_binding_accepts_credential_issued_to_the_holder():
    vp, reg, _ = _setup()                 # the VC's credentialSubject.id is HOLDER
    result = _verify(vp, reg, require_holder_binding=True)
    assert result.holder == HOLDER


def test_holder_binding_rejects_a_third_party_credential():
    ik = P256SigningKey.generate(kid=ISSUER_VM)
    hk = Ed25519SigningKey.generate(kid=HOLDER_VM)
    reg = _Registry().add(ISSUER, ISSUER_VM, ik.public_jwk())
    reg.add(HOLDER, HOLDER_VM, hk.public_jwk())
    third_party = {
        "@context": [VC2], "id": "urn:uuid:2", "type": ["VerifiableCredential"],
        "issuer": ISSUER, "credentialSubject": {"id": "did:web:someone.else"},
    }
    vc = VcJwtProofSuite().sign(third_party, signing_key=ik)
    vp = VpJwtProofSuite().sign([vc], holder_key=hk, audience=AUD, nonce=NONCE)
    # bound: the presenter is not the credential's subject -> rejected
    with pytest.raises(ClaimsInvalid, match="holder"):
        _verify(vp, reg, require_holder_binding=True)
    # unbound (default): a third-party presentation is allowed
    assert _verify(vp, reg).credentials[0].subject == "did:web:someone.else"
