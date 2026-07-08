"""
tests/test_keys.py — the SigningKey / KeyAgreementKey backends and the shared
verify helpers (``openvc.keys``), issue #63.

The P-384 backend has its own thorough suite in ``test_p384``; this covers the
Ed25519 / P-256 signing backends, the P-256 key-agreement backend, the
dependency-light ``verify_signature`` and the ``signing_key_from_jwk`` factory,
the two runtime-checkable protocols, and the package-root re-export symmetry.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from openvc.keys import (
    Ed25519SigningKey,
    InvalidKey,
    KeyAgreementKey,
    P256KeyAgreementKey,
    P256SigningKey,
    signing_key_from_jwk,
    verify_signature,
)
from openvc.proof.vc_jwt import SigningKey


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# --------------------------------------------------------------------------- #
# Ed25519SigningKey
# --------------------------------------------------------------------------- #


def test_ed25519_generate_sign_verify():
    key = Ed25519SigningKey.generate(kid="did:example:issuer#k")
    assert key.alg == "EdDSA" and key.kid == "did:example:issuer#k"
    jwk = key.public_jwk()
    assert jwk == {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}
    sig = key.sign(b"the message")
    assert len(sig) == 64                                # raw Ed25519 signature
    assert verify_signature(alg="EdDSA", public_jwk=jwk,
                            signing_input=b"the message", signature=sig)
    assert not verify_signature(alg="EdDSA", public_jwk=jwk,
                                signing_input=b"tampered", signature=sig)


def test_ed25519_from_jwk_roundtrip_and_rejects_public():
    key = Ed25519SigningKey.generate(kid="k")
    d = _b64u(key._sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()))
    reloaded = Ed25519SigningKey.from_jwk({**key.public_jwk(), "d": d}, kid="k")
    assert reloaded.public_jwk() == key.public_jwk()
    with pytest.raises(InvalidKey):                      # no "d" -> not a private JWK
        Ed25519SigningKey.from_jwk(key.public_jwk(), kid="k")
    with pytest.raises(InvalidKey):                      # wrong kty
        Ed25519SigningKey.from_jwk({"kty": "EC", "crv": "P-256", "d": d}, kid="k")


def test_ed25519_from_pem_rejects_non_ed25519():
    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    with pytest.raises(InvalidKey):
        Ed25519SigningKey.from_pem(rsa_pem, kid="k")


# --------------------------------------------------------------------------- #
# P256SigningKey
# --------------------------------------------------------------------------- #


def test_p256_sign_is_raw_64_byte_rs_not_der():
    key = P256SigningKey.generate(kid="k")
    sig = key.sign(b"m")
    assert len(sig) == 64                                # raw R‖S (32+32), never DER
    # A DER ECDSA signature starts with 0x30 (SEQUENCE) and is variable-length;
    # the raw form must not look like one.
    assert sig[0] != 0x30 or len(sig) == 64
    assert verify_signature(alg="ES256", public_jwk=key.public_jwk(),
                            signing_input=b"m", signature=sig)


def test_p256_public_jwk_shape():
    jwk = P256SigningKey.generate(kid="k").public_jwk()
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    assert len(base64.urlsafe_b64decode(jwk["x"] + "==")) == 32
    assert len(base64.urlsafe_b64decode(jwk["y"] + "==")) == 32


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP521R1()], ids=["p384", "p521"])
def test_p256_constructor_rejects_wrong_curve(curve):
    with pytest.raises(InvalidKey):
        P256SigningKey(ec.generate_private_key(curve), kid="k")


def test_p256_from_jwk_roundtrip_and_negatives():
    key = P256SigningKey.generate(kid="k")
    d = _b64u(key._sk.private_numbers().private_value.to_bytes(32, "big"))
    reloaded = P256SigningKey.from_jwk({**key.public_jwk(), "d": d}, kid="k")
    assert verify_signature(alg="ES256", public_jwk=key.public_jwk(),
                            signing_input=b"m", signature=reloaded.sign(b"m"))
    with pytest.raises(InvalidKey):                      # wrong crv
        P256SigningKey.from_jwk({"kty": "EC", "crv": "P-384", "d": d}, kid="k")
    with pytest.raises(InvalidKey):                      # public JWK, no "d"
        P256SigningKey.from_jwk(key.public_jwk(), kid="k")


# --------------------------------------------------------------------------- #
# verify_signature — the shared dependency-light verifier
# --------------------------------------------------------------------------- #


def test_verify_signature_unsupported_alg():
    jwk = P256SigningKey.generate(kid="k").public_jwk()
    with pytest.raises(InvalidKey):
        verify_signature(alg="RS256", public_jwk=jwk, signing_input=b"m", signature=b"x")


def test_verify_signature_rejects_wrong_length_es256():
    key = P256SigningKey.generate(kid="k")
    with pytest.raises(InvalidKey):                      # a DER-length sig is not 64 bytes
        verify_signature(alg="ES256", public_jwk=key.public_jwk(),
                         signing_input=b"m", signature=key.sign(b"m") + b"\x00")


def test_verify_signature_typed_on_malformed_jwk():
    sig = P256SigningKey.generate(kid="k").sign(b"m")
    # An OKP key (no "y") handed to the ES256 path must fail closed as InvalidKey,
    # not leak a bare KeyError to a caller catching only KeyBackendError.
    with pytest.raises(InvalidKey):
        verify_signature(alg="ES256",
                         public_jwk=Ed25519SigningKey.generate(kid="k").public_jwk(),
                         signing_input=b"m", signature=sig)


# --------------------------------------------------------------------------- #
# signing_key_from_jwk — factory dispatch
# --------------------------------------------------------------------------- #


def test_signing_key_from_jwk_dispatch():
    ed = Ed25519SigningKey.generate(kid="k")
    ed_d = _b64u(ed._sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()))
    assert isinstance(signing_key_from_jwk({**ed.public_jwk(), "d": ed_d}, kid="k"),
                      Ed25519SigningKey)

    p256 = P256SigningKey.generate(kid="k")
    p256_d = _b64u(p256._sk.private_numbers().private_value.to_bytes(32, "big"))
    assert isinstance(signing_key_from_jwk({**p256.public_jwk(), "d": p256_d}, kid="k"),
                      P256SigningKey)

    with pytest.raises(InvalidKey):
        signing_key_from_jwk({"kty": "RSA", "d": "x"}, kid="k")


# --------------------------------------------------------------------------- #
# P256KeyAgreementKey (JWE ECDH-ES, HAIP responses)
# --------------------------------------------------------------------------- #


def test_key_agreement_shared_secret_matches_both_ways():
    alice = P256KeyAgreementKey.generate(kid="a")
    bob = P256KeyAgreementKey.generate(kid="b")
    z_ab = alice.agree(bob.public_jwk())
    z_ba = bob.agree(alice.public_jwk())
    assert z_ab == z_ba and len(z_ab) == 32              # shared X coordinate


def test_key_agreement_public_jwk_marked_enc():
    jwk = P256KeyAgreementKey.generate(kid="a").public_jwk()
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and jwk["use"] == "enc"


def test_key_agreement_rejects_non_p256_peer():
    alice = P256KeyAgreementKey.generate(kid="a")
    with pytest.raises(InvalidKey):                      # peer epk on the wrong curve
        alice.agree({"kty": "EC", "crv": "P-384", "x": "a", "y": "b"})


def test_key_agreement_rejects_malformed_epk():
    alice = P256KeyAgreementKey.generate(kid="a")
    with pytest.raises(InvalidKey):                      # missing coordinates
        alice.agree({"kty": "EC", "crv": "P-256"})


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP521R1()], ids=["p384", "p521"])
def test_key_agreement_constructor_rejects_wrong_curve(curve):
    with pytest.raises(InvalidKey):
        P256KeyAgreementKey(ec.generate_private_key(curve), kid="a")


# --------------------------------------------------------------------------- #
# Protocols are structural + runtime-checkable
# --------------------------------------------------------------------------- #


def test_signing_key_protocol_runtime_check():
    assert isinstance(Ed25519SigningKey.generate(kid="k"), SigningKey)
    assert isinstance(P256SigningKey.generate(kid="k"), SigningKey)
    assert not isinstance(object(), SigningKey)


def test_key_agreement_protocol_runtime_check():
    assert isinstance(P256KeyAgreementKey.generate(kid="k"), KeyAgreementKey)
    assert not isinstance(ed25519.Ed25519PrivateKey.generate(), KeyAgreementKey)


# --------------------------------------------------------------------------- #
# package-root re-export symmetry (issue #63)
# --------------------------------------------------------------------------- #


def test_key_surface_reexported_at_root():
    import openvc
    import openvc.keys as keys

    for name in ("Ed25519SigningKey", "P256SigningKey", "P384SigningKey",
                 "KeyAgreementKey", "P256KeyAgreementKey",
                 "signing_key_from_jwk", "verify_signature"):
        assert getattr(openvc, name) is getattr(keys, name), name
        assert name in openvc.__all__, name
    # SigningKey lives in proof.vc_jwt but is re-exported at the root too.
    assert openvc.SigningKey is SigningKey and "SigningKey" in openvc.__all__
