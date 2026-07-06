"""
tests/test_did_jwk.py — the did:jwk resolver (Etapa 8) and its use through the
generic pipeline's default resolver. All offline (did:jwk is self-contained).
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import VerificationPolicy, verify_credential
from openvc.did.base import DidResolutionError
from openvc.did.did_jwk import DidJwkResolver
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite


def _did_jwk(jwk: dict) -> str:
    enc = base64.urlsafe_b64encode(
        json.dumps(jwk, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"did:jwk:{enc}"


def test_supports():
    r = DidJwkResolver()
    assert r.supports("did:jwk:eyJrdHkiOiJFQyJ9")
    assert not r.supports("did:key:z6Mkabc")


def test_resolve_public_key_and_relationships():
    jwk = P256SigningKey.generate(kid="x").public_jwk()
    did = _did_jwk(jwk)
    doc = DidJwkResolver().resolve(did)
    assert doc.id == did
    vm = doc.key_by_kid(f"{did}#0")
    assert vm is not None and vm.public_key_jwk == jwk
    assert doc.relationships["assertionMethod"] == [f"{did}#0"]
    assert doc.key_for_purpose(f"{did}#0", "assertionMethod") is not None


def test_rejects_malformed_and_private():
    r = DidJwkResolver()
    with pytest.raises(DidResolutionError):
        r.resolve("did:jwk:")                         # empty
    with pytest.raises(DidResolutionError):
        r.resolve("did:jwk:YWJj")                     # valid base64, "abc" is not JSON
    with pytest.raises(DidResolutionError):
        r.resolve(_did_jwk({"foo": "bar"}))           # JSON but not a JWK (no kty)
    priv = {"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "secret"}
    with pytest.raises(DidResolutionError):
        r.resolve(_did_jwk(priv))                     # a private key must be refused


def test_did_jwk_end_to_end_via_default_resolver():
    priv = ec.generate_private_key(ec.SECP256R1())
    did = _did_jwk(P256SigningKey(priv, kid="tmp").public_jwk())
    signer = P256SigningKey(priv, kid=f"{did}#0")     # same key, kid = the did:jwk VM
    cred = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": did,
        "credentialSubject": {"id": "did:example:subject"},
    }
    token = VcJwtProofSuite().sign(cred, signing_key=signer)
    result = verify_credential(token)                 # default resolver handles did:jwk
    assert result.format == "vc-jwt" and result.issuer == did


def test_wrong_did_jwk_key_fails():
    # a token signed by one key but naming a did:jwk built from a different key
    priv = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    did = _did_jwk(P256SigningKey(other, kid="tmp").public_jwk())   # did of the WRONG key
    signer = P256SigningKey(priv, kid=f"{did}#0")                   # but signed by priv
    cred = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"], "issuer": did,
        "credentialSubject": {"id": "did:example:s"},
    }
    token = VcJwtProofSuite().sign(cred, signing_key=signer)
    from openvc.proof.vc_jwt import SignatureInvalid
    with pytest.raises(SignatureInvalid):
        verify_credential(token, policy=VerificationPolicy(require_status=False))
