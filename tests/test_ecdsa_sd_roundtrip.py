"""
tests/test_ecdsa_sd_roundtrip.py — ecdsa-sd-2023 end to end (needs pyld).

Round-trip: issuer base proof -> holder derived proof -> verifier. A green verify
means every layer (skolemize, HMAC relabel, grouping, per-statement + base
signatures, ordering) is internally consistent; the selective-disclosure and
tamper cases pin the behaviour. Byte-level interop vs the official W3C vectors is
tracked separately.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

pytest.importorskip("pyld")

from openvc.keys import P256SigningKey  # noqa: E402
from openvc.proof.ecdsa_sd import (  # noqa: E402
    CredentialExpired,
    EcdsaSdProofSuite,
    SignatureInvalid,
)

UTC = timezone.utc

VC2 = "https://www.w3.org/ns/credentials/v2"
KID = "did:key:zDnaeykfoobar#zDnaeykfoobar"


def _credential() -> dict:
    # An inline @vocab defines the custom subject terms (VC2 core only aliases a
    # few, e.g. `name`); without it JSON-LD expansion would silently drop them.
    return {
        "@context": [VC2, {"@vocab": "https://vocab.example/"}],
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:subject",
            "name": "Ada Lovelace",
            "birthDate": "1815-12-10",
        },
    }


def _issue(sk, mandatory):
    return EcdsaSdProofSuite().add_base_proof(
        _credential(), signing_key=sk, verification_method=KID,
        mandatory_pointers=mandatory)


def test_roundtrip_discloses_only_selected():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer", "/validFrom"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    result = suite.verify(derived, public_key_jwk=sk.public_jwk())

    assert result.credential["issuer"] == "did:example:issuer"        # mandatory
    assert result.credential["validFrom"] == "2026-01-01T00:00:00Z"   # mandatory
    assert result.credential["credentialSubject"]["name"] == "Ada Lovelace"  # selected
    assert "birthDate" not in result.credential["credentialSubject"]  # withheld


def test_disclose_nothing_extra_still_verifies():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=[])
    result = suite.verify(derived, public_key_jwk=sk.public_jwk())
    assert result.credential["issuer"] == "did:example:issuer"
    assert "name" not in result.credential.get("credentialSubject", {})


def test_wrong_issuer_key_rejected():
    sk = P256SigningKey.generate(kid=KID)
    other = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    with pytest.raises(SignatureInvalid):
        suite.verify(derived, public_key_jwk=other.public_jwk())


def test_tampered_disclosed_value_rejected():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    derived["credentialSubject"]["name"] = "Grace Hopper"      # tamper after derive
    with pytest.raises(SignatureInvalid):
        suite.verify(derived, public_key_jwk=sk.public_jwk())


def test_tampered_mandatory_value_rejected():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer", "/validFrom"])
    derived = suite.derive_proof(base, selective_pointers=[])
    derived["validFrom"] = "1999-01-01T00:00:00Z"             # tamper a mandatory field
    with pytest.raises(SignatureInvalid):
        suite.verify(derived, public_key_jwk=sk.public_jwk())


def test_base_proof_input_not_mutated():
    sk = P256SigningKey.generate(kid=KID)
    cred = _credential()
    snapshot = copy.deepcopy(cred)
    EcdsaSdProofSuite().add_base_proof(
        cred, signing_key=sk, verification_method=KID, mandatory_pointers=["/issuer"])
    assert cred == snapshot


def test_over_disclosure_after_derive_rejected():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    # A holder tries to add a field the issuer never signed a per-statement proof for.
    derived["credentialSubject"]["birthDate"] = "1815-12-10"
    with pytest.raises(SignatureInvalid):
        suite.verify(derived, public_key_jwk=sk.public_jwk())


def test_selective_disclosure_shrinks_the_proof():
    from openvc.proof.ecdsa_sd import parse_base_proof, parse_derived_proof
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer"])                      # only /issuer mandatory
    n_base = len(parse_base_proof(base["proof"]["proofValue"])["signatures"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    n_derived = len(parse_derived_proof(derived["proof"]["proofValue"])["signatures"])
    # withholding statements must carry fewer per-statement signatures than the base.
    assert 0 < n_derived < n_base
    assert suite.verify(derived, public_key_jwk=sk.public_jwk()).issuer == "did:example:issuer"


def test_multiple_selective_pointers():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue(sk, ["/issuer"])
    derived = suite.derive_proof(
        base, selective_pointers=["/credentialSubject/name", "/credentialSubject/birthDate"])
    result = suite.verify(derived, public_key_jwk=sk.public_jwk())
    assert result.credential["credentialSubject"]["name"] == "Ada Lovelace"
    assert result.credential["credentialSubject"]["birthDate"] == "1815-12-10"


# --------------------------------------------------------------------------- #
# Temporal validity — the disclosed subset is held to the credential's window
# --------------------------------------------------------------------------- #

def _issue_dated(sk, *, valid_from: str, valid_until: str):
    cred = _credential()
    cred["validFrom"] = valid_from
    cred["validUntil"] = valid_until
    # reveal the window so the verifier can actually see and enforce it
    return EcdsaSdProofSuite().add_base_proof(
        cred, signing_key=sk, verification_method=KID,
        mandatory_pointers=["/issuer", "/validFrom", "/validUntil"])


def test_expired_derived_proof_does_not_verify():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue_dated(sk, valid_from="2024-01-01T00:00:00Z",
                        valid_until="2025-01-01T00:00:00Z")   # past
    derived = suite.derive_proof(base, selective_pointers=[])
    with pytest.raises(CredentialExpired):
        suite.verify(derived, public_key_jwk=sk.public_jwk())


def test_now_pins_the_evaluation_instant():
    sk = P256SigningKey.generate(kid=KID)
    suite = EcdsaSdProofSuite()
    base = _issue_dated(sk, valid_from="2020-01-01T00:00:00Z",
                        valid_until="2021-01-01T00:00:00Z")
    derived = suite.derive_proof(base, selective_pointers=[])
    result = suite.verify(derived, public_key_jwk=sk.public_jwk(),
                          now=datetime(2020, 6, 1, tzinfo=UTC))
    assert result.credential["issuer"] == "did:example:issuer"
    with pytest.raises(CredentialExpired):
        suite.verify(derived, public_key_jwk=sk.public_jwk())
