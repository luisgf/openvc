"""
tests/test_rfc9864_ed25519.py — accepting the RFC 9864 fully-specified ``Ed25519``
JOSE algorithm name beside the (IANA-deprecated) polymorphic ``EdDSA`` (issue #59).

RFC 9864 (Oct 2025) marks ``EdDSA`` Deprecated in the IANA registry and gives
``Ed25519`` as the fully-specified name for the same signature. This pins the
verify-side acceptance across every JOSE-secured surface (VC-JWT, SD-JWT VC, the
status-list token) and the opt-in sign-side emission — with ``EdDSA`` still the
default and RS*/HS*/``none`` still rejected before any crypto.
"""
from __future__ import annotations

import base64
import json

import pytest

from openvc import verify_credential
from openvc.keys import Ed25519SigningKey, InvalidKey, verify_signature
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import ALLOWED_ALGS, VcJwtProofSuite
from openvc.proof.errors import SignatureInvalid

CRED = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:issuer",
    "credentialSubject": {"id": "did:example:alice"},
}


def _header_alg(token: str) -> str:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))["alg"]


# --------------------------------------------------------------------------- #
# allow-list
# --------------------------------------------------------------------------- #


def test_ed25519_on_allow_list_rs_hs_none_still_out():
    assert "Ed25519" in ALLOWED_ALGS and "EdDSA" in ALLOWED_ALGS
    for banned in ("RS256", "HS256", "none", "ES512"):
        assert banned not in ALLOWED_ALGS


# --------------------------------------------------------------------------- #
# sign-side opt-in (default emission unchanged)
# --------------------------------------------------------------------------- #


def test_default_emission_is_still_eddsa():
    assert Ed25519SigningKey.generate(kid="k").alg == "EdDSA"


def test_opt_in_emits_ed25519_in_header():
    key = Ed25519SigningKey.generate(kid="did:example:issuer#k", alg="Ed25519")
    assert key.alg == "Ed25519"
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    assert _header_alg(token) == "Ed25519"


def test_bad_alg_name_rejected_at_construction():
    with pytest.raises(InvalidKey):
        Ed25519SigningKey.generate(kid="k", alg="Ed448")
    with pytest.raises(InvalidKey):
        Ed25519SigningKey.generate(kid="k", alg="ES256")


def test_from_jwk_carries_alg_choice():
    src = Ed25519SigningKey.generate(kid="k")
    from cryptography.hazmat.primitives import serialization
    d = base64.urlsafe_b64encode(src._sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())).rstrip(b"=").decode()
    reloaded = Ed25519SigningKey.from_jwk({**src.public_jwk(), "d": d}, kid="k",
                                          alg="Ed25519")
    assert reloaded.alg == "Ed25519"


# --------------------------------------------------------------------------- #
# verify_signature accepts the alias
# --------------------------------------------------------------------------- #


def test_verify_signature_accepts_ed25519_alias():
    key = Ed25519SigningKey.generate(kid="k", alg="Ed25519")
    sig = key.sign(b"the message")
    assert verify_signature(alg="Ed25519", public_jwk=key.public_jwk(),
                            signing_input=b"the message", signature=sig)
    assert not verify_signature(alg="Ed25519", public_jwk=key.public_jwk(),
                                signing_input=b"tampered", signature=sig)


# --------------------------------------------------------------------------- #
# VC-JWT — verify a token labelled Ed25519, and EdDSA still works
# --------------------------------------------------------------------------- #


def test_vc_jwt_ed25519_roundtrip():
    key = Ed25519SigningKey.generate(kid="did:example:issuer#k", alg="Ed25519")
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    verified = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert verified.issuer == "did:example:issuer"


def test_vc_jwt_eddsa_still_verifies():
    key = Ed25519SigningKey.generate(kid="k")           # default EdDSA
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    assert _header_alg(token) == "EdDSA"
    assert VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk()).issuer


def test_vc_jwt_ed25519_wrong_key_fails_closed():
    key = Ed25519SigningKey.generate(kid="k", alg="Ed25519")
    other = Ed25519SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    with pytest.raises(SignatureInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=other.public_jwk())


def test_pipeline_verify_credential_ed25519_did_key():
    key = Ed25519SigningKey.generate(kid="_", alg="Ed25519")
    mb = encode_multibase(bytes([0xed, 0x01]) + key.public_key_raw())  # did:key Ed25519
    did = f"did:key:{mb}"
    signer = Ed25519SigningKey(key._sk, kid=f"{did}#{mb}", alg="Ed25519")
    token = VcJwtProofSuite().sign(
        {**CRED, "issuer": did}, signing_key=signer)
    result = verify_credential(token)
    assert result.issuer == did and result.format == "vc-jwt"


# --------------------------------------------------------------------------- #
# SD-JWT VC — the same acceptance on the SD-JWT surface
# --------------------------------------------------------------------------- #


def test_sd_jwt_vc_ed25519_roundtrip():
    from openvc.proof.sd_jwt import SdJwtVcProofSuite
    key = Ed25519SigningKey.generate(kid="did:example:issuer#k", alg="Ed25519")
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": "did:example:issuer", "given_name": "Alice", "age": 30},
        signing_key=key, disclosable=["given_name", "age"],
        vct="https://example.com/card")
    result = SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=key.public_jwk())
    assert result.issuer == "did:example:issuer"


# --------------------------------------------------------------------------- #
# Status-list token — the _jws compact path accepts Ed25519 too
# --------------------------------------------------------------------------- #


def test_status_list_token_ed25519_roundtrip():
    from openvc.status import new_status_list
    from openvc.status.issue import build_status_list_token, verify_status_list_token
    key = Ed25519SigningKey.generate(kid="did:example:issuer#k", alg="Ed25519")
    uri = "https://issuer.example/statuslists/1"
    token = build_status_list_token(
        signing_key=key, uri=uri, status_list=new_status_list(64, bits=1))
    claims = verify_status_list_token(token, public_key_jwk=key.public_jwk(),
                                      expected_uri=uri)
    assert claims["status_list"]["bits"] == 1
