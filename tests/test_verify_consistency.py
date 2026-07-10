"""
tests/test_verify_consistency.py — verify-path consistency & fail-closed defaults
(issue #101).

Cross-format symmetry fixes from the 2026-07-10 audit: a KB-JWT is not accepted
without a verifier nonce/aud to bind it (replay foot-gun), the JOSE temporal check
is single-sourced and non-finite-safe, and VC-JWT pins the EC curve to the alg like
the other paths.
"""
from __future__ import annotations

import pytest

from openvc.keys import Ed25519SigningKey
from openvc.proof._verify_common import check_jwt_temporal
from openvc.proof.errors import ClaimsInvalid, ProofError
from openvc.proof.sd_jwt import SdJwtVcProofSuite, _b64url_encode, _json_bytes
from openvc.proof.vc_jwt import VcJwtProofSuite

VCT = "https://credentials.example/id"


def _issue_and_present(*, audience, nonce):
    issuer = Ed25519SigningKey.generate("did:example:iss#0")
    holder = Ed25519SigningKey.generate("did:key:zHolder#0")
    suite = SdJwtVcProofSuite()
    issued = suite.issue(
        {"iss": "did:example:iss", "sub": "did:example:alice", "name": "Ada"},
        signing_key=issuer, vct=VCT, disclosable=["name"], holder_jwk=holder.public_jwk())
    pres = suite.create_presentation(issued, holder_key=holder, audience=audience, nonce=nonce)
    return pres, issuer.public_jwk()


# --- M1: key binding must be bound to a verifier nonce/aud --------------------- #

def test_require_key_binding_without_nonce_aud_fails_closed():
    """A verifier that requires key binding but supplies no nonce/aud gets no replay
    protection — that must fail closed, not silently accept."""
    pres, issuer_jwk = _issue_and_present(audience="verifierA", nonce="nonce-A")
    with pytest.raises(ClaimsInvalid):
        SdJwtVcProofSuite().verify(pres, public_key_jwk=issuer_jwk, require_key_binding=True)
    # nonce alone but no aud, and aud alone but no nonce, are both insufficient
    with pytest.raises(ClaimsInvalid):
        SdJwtVcProofSuite().verify(pres, public_key_jwk=issuer_jwk,
                                   require_key_binding=True, nonce="nonce-A")
    with pytest.raises(ClaimsInvalid):
        SdJwtVcProofSuite().verify(pres, public_key_jwk=issuer_jwk,
                                   require_key_binding=True, audience="verifierA")


def test_key_binding_replay_across_verifiers_is_rejected():
    """A presentation built for verifier A must not verify for verifier B once B passes
    its own (different) nonce/aud — and it does verify for A."""
    pres, issuer_jwk = _issue_and_present(audience="verifierA", nonce="nonce-A")
    ok = SdJwtVcProofSuite().verify(pres, public_key_jwk=issuer_jwk,
                                    require_key_binding=True, audience="verifierA", nonce="nonce-A")
    assert ok.key_bound is True
    with pytest.raises(ClaimsInvalid):
        SdJwtVcProofSuite().verify(pres, public_key_jwk=issuer_jwk,
                                   require_key_binding=True, audience="verifierB", nonce="nonce-B")


# --- non-finite exp/nbf, single-sourced across the JOSE suites ----------------- #

@pytest.mark.parametrize("bad", [float("inf"), float("nan")], ids=["inf", "nan"])
def test_check_jwt_temporal_rejects_non_finite(bad):
    with pytest.raises(ClaimsInvalid):
        check_jwt_temporal({"exp": bad}, leeway_s=0)
    with pytest.raises(ClaimsInvalid):
        check_jwt_temporal({"nbf": bad}, leeway_s=0)


@pytest.mark.parametrize("bad", [float("inf"), float("nan")], ids=["inf", "nan"])
def test_sd_jwt_non_finite_exp_rejected(bad):
    """The SD-JWT path used to lack the isfinite guard, so exp=inf never expired.
    A validly-signed issuer JWT with a non-finite exp must now fail closed."""
    key = Ed25519SigningKey.generate("did:example:i#0")
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    payload = {"iss": "did:example:i", "exp": bad}
    si = f"{_b64url_encode(_json_bytes(header))}.{_b64url_encode(_json_bytes(payload))}"
    token = f"{si}.{_b64url_encode(key.sign(si.encode('ascii')))}~"
    with pytest.raises(ClaimsInvalid):
        SdJwtVcProofSuite().verify(token, public_key_jwk=key.public_jwk())


# --- VC-JWT pins the EC curve to the alg (defence in depth) -------------------- #

def test_vc_jwt_es256_rejects_a_p384_key():
    p384 = {"kty": "EC", "crv": "P-384", "x": "AA", "y": "BB"}
    with pytest.raises(ProofError):
        VcJwtProofSuite()._jwk_to_key(p384, "ES256")
    # a P-256 key under ES256 passes the curve gate (it then loads normally)
    p256 = {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
    VcJwtProofSuite()._jwk_to_key(p256, "ES256")


# --- did:web binds the document to the requested DID (no missing-id bypass) ----- #

def test_did_web_requires_matching_document_id():
    from openvc.did.base import DidResolutionError
    from openvc.did.did_web import _validated_document

    vm = {"id": "did:web:example.com#k", "type": "Multikey", "controller": "did:web:example.com",
          "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}
    # wrong id
    with pytest.raises(DidResolutionError):
        _validated_document({"id": "did:web:evil.com", "verificationMethod": [vm]},
                            "did:web:example.com")
    # missing id (used to be accepted because of the `doc.id and ...` short-circuit)
    with pytest.raises(DidResolutionError):
        _validated_document({"verificationMethod": [vm]}, "did:web:example.com")


# --- credentialSchema digestSRI fails closed when malformed -------------------- #

def test_schema_digest_sri_must_be_a_string():
    from openvc.schema import SchemaResolutionError, parse_credential_schemas

    bad = {"credentialSchema": {"id": "https://s/1", "type": "JsonSchema",
                                "digestSRI": ["not", "a", "string"]}}
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(bad)
    # a string pin (or an absent one) is preserved
    ok = parse_credential_schemas(
        {"credentialSchema": {"id": "https://s/1", "type": "JsonSchema", "digestSRI": "sha384-x"}})
    assert ok[0].digest_sri == "sha384-x"
