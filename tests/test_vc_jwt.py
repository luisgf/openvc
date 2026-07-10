"""
tests/test_vc_jwt.py — the VC-JWT proof suite (``openvc.proof.vc_jwt``), issue #63.

Exercised end-to-end through ``test_verify_pipeline`` / ``test_verify_glue``; this
is the direct unit floor for the suite's three jobs — untrusted ``peek_*``, the
allow-list-before-crypto ``verify``, the envelope/credential reconciliation, and
``sign`` — plus the negative paths that must fail closed with a typed error.
"""
from __future__ import annotations

import base64
import json
import time

import pytest

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof._jws import sign_compact
from openvc.proof.errors import (
    ClaimsInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    MalformedToken,
    ProofError,
    SignatureInvalid,
    UnsupportedAlgorithm,
)
from openvc.proof.vc_jwt import ALLOWED_ALGS, VcJwtProofSuite

ISSUER = "did:example:issuer"


def _seg(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _raw_token(header: dict, payload: dict, sig: str = "") -> str:
    return f"{_seg(header)}.{_seg(payload)}.{sig}"


def _signed(key, payload: dict, *, header: dict | None = None) -> str:
    hdr = {"alg": key.alg, "typ": "JWT", "kid": key.kid}
    hdr.update(header or {})
    return sign_compact(hdr, payload, signing_key=key)


def _credential(**over) -> dict:
    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": ISSUER,
        "credentialSubject": {"id": "did:example:alice"},
    }
    vc.update(over)
    return vc


# --------------------------------------------------------------------------- #
# peek_issuer / peek_claims — untrusted, never verify
# --------------------------------------------------------------------------- #


def test_peek_issuer_from_top_level_and_kid():
    key = P256SigningKey.generate(kid="did:example:issuer#k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    iss, kid = VcJwtProofSuite().peek_issuer(token)
    assert iss == ISSUER and kid == "did:example:issuer#k"


def test_peek_issuer_from_vc_issuer_object():
    # No top-level iss; issuer nested as an object {"id": ...} in the vc.
    token = _raw_token({"alg": "EdDSA"}, {"vc": {"issuer": {"id": ISSUER}}})
    assert VcJwtProofSuite().peek_issuer(token) == (ISSUER, None)


def test_peek_issuer_missing_raises():
    token = _raw_token({"alg": "EdDSA"}, {"vc": {"type": ["VerifiableCredential"]}})
    with pytest.raises(MalformedToken):
        VcJwtProofSuite().peek_issuer(token)


def test_peek_rejects_non_compact_jws():
    with pytest.raises(MalformedToken):
        VcJwtProofSuite().peek_issuer("only.two")
    with pytest.raises(MalformedToken):
        VcJwtProofSuite().peek_claims("a.b.c.d")


# --------------------------------------------------------------------------- #
# verify — algorithm allow-list runs BEFORE any crypto
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("alg", ["none", "RS256", "HS256", "ES512", None])
def test_verify_rejects_non_allowlisted_alg_before_crypto(alg):
    key = P256SigningKey.generate(kid="k")
    header = {"typ": "JWT"} if alg is None else {"alg": alg, "typ": "JWT"}
    token = _raw_token(header, {"iss": ISSUER, "vc": _credential()}, sig="AAAA")
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert alg not in ALLOWED_ALGS


# --------------------------------------------------------------------------- #
# verify — happy path + signature integrity
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("factory", [Ed25519SigningKey, P256SigningKey])
def test_verify_roundtrip(factory):
    key = factory.generate(kid="did:example:issuer#k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    verified = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert verified.issuer == ISSUER and verified.subject == "did:example:alice"
    assert verified.credential["type"] == ["VerifiableCredential"]


def test_verify_tampered_signature_fails():
    key = P256SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    head, payload, sig = token.split(".")
    tampered = f"{head}.{payload}.{sig[:-4]}AAAA"
    with pytest.raises(SignatureInvalid):
        VcJwtProofSuite().verify(tampered, public_key_jwk=key.public_jwk())


def test_verify_wrong_key_fails():
    key = P256SigningKey.generate(kid="k")
    other = P256SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    with pytest.raises(SignatureInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=other.public_jwk())


# --------------------------------------------------------------------------- #
# verify — temporal claims
# --------------------------------------------------------------------------- #


def test_verify_expired_fails_closed():
    key = P256SigningKey.generate(kid="k")
    now = int(time.time())
    token = _signed(key, {"iss": ISSUER, "iat": now - 7200,
                          "exp": now - 3600, "vc": _credential()})
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_not_yet_valid_fails_closed():
    key = P256SigningKey.generate(kid="k")
    now = int(time.time())
    token = _signed(key, {"iss": ISSUER, "nbf": now + 3600, "vc": _credential()})
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_rejects_expired_credential_body_without_jwt_exp():
    # Defence in depth: an issuer (EBSI VCDM 2.0 among them) may encode expiry ONLY in
    # the credential body (vc.validUntil), with no JWT `exp`. The body validity window
    # must still reject it — otherwise an expired credential verifies.
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER, "nbf": int(time.time()) - 3600,   # no JWT `exp`
                          "vc": _credential(validUntil="2020-01-01T00:00:00Z")})
    with pytest.raises(CredentialExpired):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_rejects_not_yet_valid_credential_body():
    # The mirror of the above for VCDM 2.0 `validFrom` (1.1 `issuanceDate`) in the body.
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER, "nbf": int(time.time()) - 3600,
                          "vc": _credential(validFrom="2999-01-01T00:00:00Z")})
    with pytest.raises(CredentialNotYetValid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_accepts_credential_body_within_window():
    # The positive: a body window that is currently valid (past validFrom, future
    # validUntil) verifies — the new check does not reject well-formed credentials.
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER, "nbf": int(time.time()) - 3600,
                          "vc": _credential(validFrom="2020-01-01T00:00:00Z",
                                            validUntil="2999-01-01T00:00:00Z")})
    result = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert result.issuer == ISSUER


# --------------------------------------------------------------------------- #
# verify — VC-JWT envelope/credential reconciliation (defence in depth)
# --------------------------------------------------------------------------- #


def test_verify_requires_embedded_vc_object():
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER})            # no vc
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_rejects_iss_vc_issuer_mismatch():
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER,
                          "vc": _credential(issuer="did:example:someone-else")})
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_rejects_sub_subject_mismatch():
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER, "sub": "did:example:mallory",
                          "vc": _credential()})       # cs.id is did:example:alice
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_rejects_jti_id_mismatch():
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER, "jti": "urn:uuid:aaa",
                          "vc": _credential(id="urn:uuid:bbb")})
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_verify_expected_types_enforced():
    key = P256SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk(),
                                 expected_types=["OpenBadgeCredential"])
    ok = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk(),
                                  expected_types=["VerifiableCredential"])
    assert ok.issuer == ISSUER


# --------------------------------------------------------------------------- #
# verify — audience binding
# --------------------------------------------------------------------------- #


def test_verify_audience_match_and_mismatch():
    key = P256SigningKey.generate(kid="k")
    token = _signed(key, {"iss": ISSUER, "aud": "https://verifier.example",
                          "vc": _credential()})
    ok = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk(),
                                  audience="https://verifier.example")
    assert ok.issuer == ISSUER
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk(),
                                 audience="https://other.example")


def test_verify_malformed_jwk_is_typed():
    key = P256SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    with pytest.raises(ProofError):                  # not a bare exception from pyjwt
        VcJwtProofSuite().verify(token, public_key_jwk={"kty": "EC", "crv": "P-256"})


# --------------------------------------------------------------------------- #
# sign — issuance details
# --------------------------------------------------------------------------- #


def test_sign_idless_credential_has_no_jti():
    # A null jti fails RFC 7519 on the verify side; an id-less VC must round-trip.
    key = P256SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key)
    claims = VcJwtProofSuite().peek_claims(token)
    assert "jti" not in claims and claims["sub"] == "did:example:alice"


def test_sign_sets_exp_when_requested():
    key = P256SigningKey.generate(kid="k")
    token = VcJwtProofSuite().sign(_credential(), signing_key=key, expires_in_s=3600)
    claims = VcJwtProofSuite().peek_claims(token)
    assert claims["exp"] - claims["iat"] == 3600


@pytest.mark.parametrize("exp", [float("inf"), float("nan")], ids=["inf", "nan"])
def test_non_finite_exp_fails_closed_typed(exp):
    # a signed non-finite exp must fail closed as a typed ClaimsInvalid, never leak an
    # OverflowError from PyJWT's decode (adversarial-review hardening, ML-DSA PR).
    key = Ed25519SigningKey.generate(kid=f"{ISSUER}#k")
    token = _signed(key, {"iss": ISSUER, "exp": exp, "vc": _credential()})
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
