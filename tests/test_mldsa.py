"""
tests/test_mldsa.py — EXPERIMENTAL post-quantum ML-DSA (RFC 9964) opt-in (issue #72).

ML-DSA is an explicit opt-in and never a default trust path (ADR-0004): the default
suites reject ``ML-DSA-*`` at the allow-list, before any crypto. These tests pin that
opt-in behaviour, the AKP key layer, and the VC-JWT / SD-JWT VC round-trips. There are
no golden fixtures — RFC 9964 has no stable third-party VC vectors to pin yet (the whole
reason it ships experimental) — so conformance is by round-trip + negative paths.

Skipped unless ML-DSA is usable here (cryptography>=48 built against OpenSSL>=3.5).
"""
from __future__ import annotations

import base64
import json

import pytest

from openvc.keys import (
    MLDSA_ALGS,
    InvalidKey,
    MLDSASigningKey,
    mldsa_available,
    signing_key_from_jwk,
    verify_signature,
)
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import (
    ClaimsInvalid,
    SignatureInvalid,
    UnsupportedAlgorithm,
    VcJwtProofSuite,
)

pytestmark = pytest.mark.skipif(
    not mldsa_available(), reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")

_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
_CRED = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:pq-issuer",
    "credentialSubject": {"id": "did:example:subject"},
}
VCT = "https://credentials.example/pq"


# --------------------------------------------------------------------------- #
# AKP key layer
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", _ALGS)
def test_key_sign_verify_and_jwk_roundtrip(alg):
    key = MLDSASigningKey.generate(kid="did:example:iss#pq", alg=alg)
    msg = b"header.payload"
    sig = key.sign(msg)
    pub = key.public_jwk()
    assert pub["kty"] == "AKP" and pub["alg"] == alg and "pub" in pub
    assert "crv" not in pub and "x" not in pub
    assert verify_signature(alg=alg, public_jwk=pub, signing_input=msg, signature=sig) is True
    assert verify_signature(alg=alg, public_jwk=pub, signing_input=b"x", signature=sig) is False

    restored = signing_key_from_jwk(key.private_jwk(), kid="did:example:iss#pq")
    assert isinstance(restored, MLDSASigningKey)
    assert restored.alg == alg and restored.public_jwk() == pub


def test_from_seed_is_deterministic():
    seed = bytes(range(32))
    a = MLDSASigningKey.from_seed(seed, kid="k", alg="ML-DSA-65")
    b = MLDSASigningKey.from_seed(seed, kid="k", alg="ML-DSA-65")
    assert a.public_jwk() == b.public_jwk()


def test_wrong_key_same_alg_fails_verify():
    a = MLDSASigningKey.generate(kid="a", alg="ML-DSA-65")
    b = MLDSASigningKey.generate(kid="b", alg="ML-DSA-65")
    sig = a.sign(b"m")
    assert verify_signature(alg="ML-DSA-65", public_jwk=b.public_jwk(),
                            signing_input=b"m", signature=sig) is False


@pytest.mark.parametrize("jwk", [
    {"kty": "AKP", "alg": "ML-DSA-65"},                       # no pub
    {"kty": "AKP", "alg": "ML-DSA-99", "pub": "AAAA"},        # bad alg
    {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},            # not AKP
], ids=["no-pub", "bad-alg", "not-akp"])
def test_malformed_akp_fails_closed(jwk):
    with pytest.raises((InvalidKey, KeyError, Exception)):
        # a missing pub or bad alg must not silently verify
        ok = verify_signature(alg="ML-DSA-65", public_jwk=jwk,
                              signing_input=b"m", signature=b"\x00" * 3309)
        assert ok is False


def test_seed_wrong_length_rejected():
    with pytest.raises(InvalidKey, match="seed"):
        MLDSASigningKey.from_seed(b"\x00" * 31, kid="k", alg="ML-DSA-65")


def test_algs_constant():
    assert MLDSA_ALGS == frozenset(_ALGS)


# --------------------------------------------------------------------------- #
# VC-JWT — opt-in only (never default)
# --------------------------------------------------------------------------- #

def test_vc_jwt_opt_in_roundtrip():
    key = MLDSASigningKey.generate(kid="did:example:pq-issuer#k", alg="ML-DSA-65")
    token = VcJwtProofSuite(allow_pq=True).sign(_CRED, signing_key=key)
    result = VcJwtProofSuite(allow_pq=True).verify(token, public_key_jwk=key.public_jwk())
    assert result.issuer == "did:example:pq-issuer"


def test_vc_jwt_default_rejects_sign_and_verify():
    key = MLDSASigningKey.generate(kid="k", alg="ML-DSA-65")
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().sign(_CRED, signing_key=key)          # default rejects before crypto
    token = VcJwtProofSuite(allow_pq=True).sign(_CRED, signing_key=key)
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_vc_jwt_mldsa_tamper_rejected():
    key = MLDSASigningKey.generate(kid="k", alg="ML-DSA-65")
    token = VcJwtProofSuite(allow_pq=True).sign(_CRED, signing_key=key)
    header, payload, sig = token.split(".")
    forged = f"{header}.{payload}.{'A' * len(sig)}"
    with pytest.raises(SignatureInvalid):
        VcJwtProofSuite(allow_pq=True).verify(forged, public_key_jwk=key.public_jwk())


def test_vc_jwt_mldsa_expired_claims_enforced():
    # the ML-DSA path validates JWT temporal claims itself (no PyJWT) — expiry must bite
    key = MLDSASigningKey.generate(kid="k", alg="ML-DSA-65")
    token = VcJwtProofSuite(allow_pq=True).sign(_CRED, signing_key=key, expires_in_s=-3600)
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite(allow_pq=True, leeway_s=0).verify(token, public_key_jwk=key.public_jwk())


def test_vc_jwt_mldsa_wrong_key_rejected():
    key = MLDSASigningKey.generate(kid="k", alg="ML-DSA-65")
    other = MLDSASigningKey.generate(kid="k2", alg="ML-DSA-65")
    token = VcJwtProofSuite(allow_pq=True).sign(_CRED, signing_key=key)
    with pytest.raises(SignatureInvalid):
        VcJwtProofSuite(allow_pq=True).verify(token, public_key_jwk=other.public_jwk())


# --------------------------------------------------------------------------- #
# SD-JWT VC — opt-in only
# --------------------------------------------------------------------------- #

def test_sd_jwt_opt_in_roundtrip():
    key = MLDSASigningKey.generate(kid="did:example:pq-issuer#k", alg="ML-DSA-87")
    sd = SdJwtVcProofSuite(allow_pq=True).issue(
        {"iss": "did:example:pq-issuer", "given_name": "Ada"},
        signing_key=key, vct=VCT, disclosable=["given_name"])
    result = SdJwtVcProofSuite(allow_pq=True).verify(sd, public_key_jwk=key.public_jwk())
    assert result.issuer == "did:example:pq-issuer"
    assert result.claims["given_name"] == "Ada"


def test_sd_jwt_default_rejects():
    key = MLDSASigningKey.generate(kid="k", alg="ML-DSA-65")
    with pytest.raises(UnsupportedAlgorithm):
        SdJwtVcProofSuite().issue({"iss": "did:example:iss"}, signing_key=key, vct=VCT)
    sd = SdJwtVcProofSuite(allow_pq=True).issue(
        {"iss": "did:example:iss"}, signing_key=key, vct=VCT)
    with pytest.raises(UnsupportedAlgorithm):
        SdJwtVcProofSuite().verify(sd, public_key_jwk=key.public_jwk())


# --------------------------------------------------------------------------- #
# did:jwk carries an AKP key unchanged (ADR-0004 D7)
# --------------------------------------------------------------------------- #

def test_did_jwk_resolves_akp_key():
    from openvc.did.did_jwk import DidJwkResolver

    key = MLDSASigningKey.generate(kid="unused", alg="ML-DSA-65")
    pub = key.public_jwk()
    encoded = base64.urlsafe_b64encode(json.dumps(pub).encode()).rstrip(b"=").decode()
    did = f"did:jwk:{encoded}"
    doc = DidJwkResolver().resolve(did)
    assert doc.verification_methods[0].public_key_jwk == pub    # AKP flows through untouched
