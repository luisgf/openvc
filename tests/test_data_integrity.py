"""
tests/test_data_integrity.py — the eddsa-rdfc-2022 Data Integrity proof suite.

Needs pyld (the [data-integrity] extra); skips without it. The centrepiece is a
byte-for-byte check against the official W3C vc-di-eddsa vector; the rest are
round-trip, tamper, wrong-key and malformed-input cases on a self-contained
credential (bundled VC 2.0 context, no network).
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("pyld")

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from openvc.did.base import DidResolutionError, parse_did_document  # noqa: E402
from openvc.keys import Ed25519SigningKey  # noqa: E402
from openvc.multibase import decode_multibase, read_varint  # noqa: E402
from openvc.proof.contexts import DocumentLoaderError  # noqa: E402
from openvc.proof.data_integrity import (  # noqa: E402
    CredentialExpired,
    CredentialNotYetValid,
    DataIntegrityProofSuite,
    ProofMalformed,
    ProofPurposeMismatch,
    SignatureInvalid,
    UnsupportedCryptosuite,
)

UTC = timezone.utc

FX = Path(__file__).parent / "fixtures" / "vc_di_eddsa"
VC2 = "https://www.w3.org/ns/credentials/v2"


@pytest.fixture(scope="module")
def examples_ctx():
    return {"https://www.w3.org/ns/credentials/examples/v2":
            json.loads((FX / "credentials-examples-v2.json").read_text())}


def _vector_signing_key():
    kp = json.loads((FX / "keyPair.json").read_text())
    raw = decode_multibase(kp["privateKeyMultibase"])
    _, off = read_varint(raw)                     # strip the 0x1300 multicodec
    vector = json.loads((FX / "signedDataInt.json").read_text())
    sk = Ed25519SigningKey(
        ed25519.Ed25519PrivateKey.from_private_bytes(raw[off:]),
        kid=vector["proof"]["verificationMethod"])
    return sk, vector


# --------------------------------------------------------------------------- #
# Official W3C vector — conformance
# --------------------------------------------------------------------------- #

def test_reproduces_w3c_vector_byte_for_byte(examples_ctx):
    sk, vector = _vector_signing_key()
    proof = vector["proof"]
    unsecured = {k: v for k, v in vector.items() if k != "proof"}
    signed = DataIntegrityProofSuite().add_proof(
        unsecured, signing_key=sk,
        verification_method=proof["verificationMethod"],
        proof_purpose=proof["proofPurpose"],
        created=datetime.fromisoformat(proof["created"].replace("Z", "+00:00")),
        extra_contexts=examples_ctx)
    assert signed["proof"]["proofValue"] == proof["proofValue"]
    assert signed == vector


def test_verifies_w3c_vector_resolving_did_key(examples_ctx):
    _, vector = _vector_signing_key()
    result = DataIntegrityProofSuite().verify(vector, extra_contexts=examples_ctx)
    assert result.issuer == "https://vc.example/issuers/5678"
    assert result.subject == "did:example:abcdefgh"


# --------------------------------------------------------------------------- #
# Round-trip / tamper on a self-contained credential (bundled VC2 context only)
# --------------------------------------------------------------------------- #

def _credential():
    return {
        "@context": [VC2],
        "id": "urn:uuid:1111",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:subject"},
    }


def test_sign_then_verify_roundtrip():
    sk = Ed25519SigningKey.generate(kid="did:key:zPlaceholder#zPlaceholder")
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(_credential(), signing_key=sk,
                             verification_method=sk.kid)
    result = suite.verify(signed, public_key_jwk=sk.public_jwk())
    assert result.issuer == "did:example:issuer"
    assert "@context" not in signed["proof"]        # embedded proof carries none
    assert signed["proof"]["proofValue"].startswith("z")


def test_tamper_after_signing_is_detected():
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(_credential(), signing_key=sk, verification_method=sk.kid)
    signed["credentialSubject"]["id"] = "did:example:attacker"
    with pytest.raises(SignatureInvalid):
        suite.verify(signed, public_key_jwk=sk.public_jwk())


def test_wrong_key_fails():
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    other = Ed25519SigningKey.generate(kid="did:key:z#z")
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(_credential(), signing_key=sk, verification_method=sk.kid)
    with pytest.raises(SignatureInvalid):
        suite.verify(signed, public_key_jwk=other.public_jwk())


def test_input_not_mutated():
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    cred = _credential()
    snapshot = copy.deepcopy(cred)
    DataIntegrityProofSuite().add_proof(cred, signing_key=sk, verification_method=sk.kid)
    assert cred == snapshot


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #

def test_non_ed25519_key_rejected(rsa_like=None):
    from openvc.keys import P256SigningKey
    sk = P256SigningKey.generate(kid="did:key:z#z")
    with pytest.raises(UnsupportedCryptosuite):
        DataIntegrityProofSuite().add_proof(_credential(), signing_key=sk,
                                            verification_method="did:key:z#z")


def test_double_proof_rejected():
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(_credential(), signing_key=sk, verification_method=sk.kid)
    with pytest.raises(ProofMalformed, match="already carries"):
        suite.add_proof(signed, signing_key=sk, verification_method=sk.kid)


def test_unknown_cryptosuite_rejected():
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    signed = DataIntegrityProofSuite().add_proof(
        _credential(), signing_key=sk, verification_method=sk.kid)
    signed["proof"]["cryptosuite"] = "ecdsa-sd-2023"
    with pytest.raises(UnsupportedCryptosuite):
        DataIntegrityProofSuite().verify(signed, public_key_jwk=sk.public_jwk())


def test_unbundled_context_fails_closed():
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    cred = _credential()
    cred["@context"] = [VC2, "https://evil.example/ctx"]     # not bundled/injected
    with pytest.raises(DocumentLoaderError):
        DataIntegrityProofSuite().add_proof(cred, signing_key=sk,
                                            verification_method=sk.kid)


# --------------------------------------------------------------------------- #
# Temporal validity — a signed-but-expired proof must NOT verify (the fields are
# integrity-protected, so these run on genuinely signed credentials)
# --------------------------------------------------------------------------- #

def _signed(cred: dict) -> tuple:
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    signed = DataIntegrityProofSuite().add_proof(
        cred, signing_key=sk, verification_method=sk.kid)
    return signed, sk


def test_expired_credential_does_not_verify():
    cred = _credential()
    cred["validUntil"] = "2025-01-01T00:00:00Z"              # past (today is 2026)
    signed, sk = _signed(cred)
    with pytest.raises(CredentialExpired):
        DataIntegrityProofSuite().verify(signed, public_key_jwk=sk.public_jwk())


def test_not_yet_valid_credential_does_not_verify():
    cred = _credential()
    cred["validFrom"] = "2099-01-01T00:00:00Z"              # future
    signed, sk = _signed(cred)
    with pytest.raises(CredentialNotYetValid):
        DataIntegrityProofSuite().verify(signed, public_key_jwk=sk.public_jwk())


def test_now_pins_the_evaluation_instant():
    cred = _credential()
    cred["validFrom"] = "2020-01-01T00:00:00Z"
    cred["validUntil"] = "2021-01-01T00:00:00Z"            # expired relative to today
    signed, sk = _signed(cred)
    suite = DataIntegrityProofSuite()
    # verifies "as of" a time inside the window ...
    result = suite.verify(signed, public_key_jwk=sk.public_jwk(),
                          now=datetime(2020, 6, 1, tzinfo=UTC))
    assert result.issuer == "did:example:issuer"
    # ... but not at the current wall-clock time.
    with pytest.raises(CredentialExpired):
        suite.verify(signed, public_key_jwk=sk.public_jwk())


def test_leeway_tolerates_a_just_expired_credential():
    cred = _credential()
    cred["validUntil"] = "2026-01-01T00:00:00Z"
    signed, sk = _signed(cred)
    at = datetime(2026, 1, 1, 0, 0, 30, tzinfo=UTC)        # 30 s past expiry
    DataIntegrityProofSuite(leeway_s=60).verify(
        signed, public_key_jwk=sk.public_jwk(), now=at)     # within leeway -> OK
    with pytest.raises(CredentialExpired):
        DataIntegrityProofSuite(leeway_s=0).verify(
            signed, public_key_jwk=sk.public_jwk(), now=at)


# --------------------------------------------------------------------------- #
# proofPurpose + DID verification-relationship binding via an injected resolver
# --------------------------------------------------------------------------- #

def _resolver(did: str, vm_id: str, jwk: dict, relationships: dict):
    raw = {
        "id": did,
        "verificationMethod": [
            {"id": vm_id, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}
        ],
        **relationships,
    }
    doc = parse_did_document(raw)

    class _R:
        def supports(self, d: str) -> bool:
            return d == did

        def resolve(self, d: str):
            if d != did:
                raise DidResolutionError(f"unknown {d!r}")
            return doc

    return _R()


def test_proof_purpose_mismatch_rejected():
    cred = _credential()
    sk = Ed25519SigningKey.generate(kid="did:key:z#z")
    signed = DataIntegrityProofSuite().add_proof(
        cred, signing_key=sk, verification_method=sk.kid,
        proof_purpose="authentication")
    with pytest.raises(ProofPurposeMismatch):     # default expects assertionMethod
        DataIntegrityProofSuite().verify(signed, public_key_jwk=sk.public_jwk())


def test_did_web_verifies_via_injected_resolver():
    did = "did:web:issuer.example"
    vm_id = f"{did}#assert"
    sk = Ed25519SigningKey.generate(kid=vm_id)
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(_credential(), signing_key=sk, verification_method=vm_id)
    resolver = _resolver(did, vm_id, sk.public_jwk(), {"assertionMethod": [vm_id]})
    result = suite.verify(signed, resolver=resolver)
    assert result.issuer == "did:example:issuer"


def test_did_web_key_not_authorized_for_assertion_rejected():
    did = "did:web:issuer.example"
    vm_id = f"{did}#auth"
    sk = Ed25519SigningKey.generate(kid=vm_id)
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(_credential(), signing_key=sk, verification_method=vm_id)
    # the key is registered for authentication only; the assertion proof must fail
    resolver = _resolver(did, vm_id, sk.public_jwk(),
                         {"authentication": [vm_id], "assertionMethod": []})
    with pytest.raises(ProofPurposeMismatch):
        suite.verify(signed, resolver=resolver)
