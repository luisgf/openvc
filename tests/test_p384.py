"""
tests/test_p384.py — P-384 signing (ES384) across the key layer, the JOSE allow-list,
and did:key (issue #22, scoped: P384SigningKey + ES384 + P-384 on ecdsa-jcs-2019).

The byte-exact W3C vc-di-ecdsa P-384 ecdsa-jcs-2019 vector is pinned in
``test_di_jcs`` (the SHA-384 hashes + the published high-S signature). This covers the
key backend, the direct ``verify_signature`` path, the deliberate ES384 allow-list
widening, and the P-384 did:key round-trip.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import InvalidKey, P384SigningKey, verify_signature
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import ALLOWED_ALGS


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# --------------------------------------------------------------------------- #
# the P384SigningKey backend
# --------------------------------------------------------------------------- #

def test_generate_and_public_jwk_shape():
    key = P384SigningKey.generate(kid="did:example:issuer#k")
    assert key.alg == "ES384"
    jwk = key.public_jwk()
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-384"
    assert len(base64.urlsafe_b64decode(jwk["x"] + "==")) == 48   # 48-byte coordinates
    assert len(base64.urlsafe_b64decode(jwk["y"] + "==")) == 48


def test_sign_is_raw_96_byte_rs_and_verifies():
    key = P384SigningKey.generate(kid="k")
    sig = key.sign(b"the message")
    assert len(sig) == 96                                # raw R‖S (48+48), never DER
    assert verify_signature(
        alg="ES384", public_jwk=key.public_jwk(), signing_input=b"the message", signature=sig)
    assert not verify_signature(
        alg="ES384", public_jwk=key.public_jwk(), signing_input=b"tampered", signature=sig)


def test_verify_signature_rejects_wrong_length():
    key = P384SigningKey.generate(kid="k")
    sig = key.sign(b"m")
    with pytest.raises(InvalidKey):                      # a 64-byte (ES256-length) sig
        verify_signature(alg="ES384", public_jwk=key.public_jwk(),
                         signing_input=b"m", signature=sig[:64])


def test_from_jwk_roundtrips():
    key = P384SigningKey.generate(kid="k")
    d = _b64u(key._sk.private_numbers().private_value.to_bytes(48, "big"))
    reloaded = P384SigningKey.from_jwk({**key.public_jwk(), "d": d}, kid="k")
    assert verify_signature(alg="ES384", public_jwk=key.public_jwk(),
                            signing_input=b"m", signature=reloaded.sign(b"m"))


def test_from_pem_roundtrips():
    sk = ec.generate_private_key(ec.SECP384R1())
    pem = sk.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    key = P384SigningKey.from_pem(pem, kid="k")
    assert verify_signature(alg="ES384", public_jwk=key.public_jwk(),
                            signing_input=b"m", signature=key.sign(b"m"))


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP521R1()], ids=["p256", "p521"])
def test_rejects_non_p384_curve(curve):
    with pytest.raises(InvalidKey):
        P384SigningKey(ec.generate_private_key(curve), kid="k")


# --------------------------------------------------------------------------- #
# the deliberate ES384 allow-list widening
# --------------------------------------------------------------------------- #

def test_es384_is_allow_listed_but_rs_and_none_stay_rejected():
    # Ed25519 (RFC 9864 fully-specified EdDSA) joined the allow-list in #59.
    assert ALLOWED_ALGS == frozenset({"ES256", "ES384", "EdDSA", "Ed25519"})
    assert "RS256" not in ALLOWED_ALGS and "HS256" not in ALLOWED_ALGS
    assert "none" not in ALLOWED_ALGS


def test_es384_signs_and_verifies_a_vc_jwt():
    from openvc.proof.vc_jwt import VcJwtProofSuite
    key = P384SigningKey.generate(kid="did:example:issuer#k")
    token = VcJwtProofSuite().sign(
        {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"],
         "issuer": "did:example:issuer", "credentialSubject": {"id": "did:example:alice"}},
        signing_key=key)
    verified = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert verified.issuer == "did:example:issuer"


# --------------------------------------------------------------------------- #
# P-384 did:key round-trip (multicodec 0x1201)
# --------------------------------------------------------------------------- #

def test_p384_did_key_roundtrips():
    from openvc.did.did_key import DidKeyResolver

    key = P384SigningKey.generate(kid="k")
    mb = encode_multibase(bytes([0x81, 0x24]) + key.public_key_raw(compressed=True))  # 0x1201
    did = f"did:key:{mb}"
    assert mb.startswith("z82")                          # the P-384 multibase signal
    resolved = DidKeyResolver().resolve(did).verification_methods[0].public_key_jwk
    assert resolved == key.public_jwk()                  # same EC P-384 JWK


# --------------------------------------------------------------------------- #
# regressions from the adversarial review — hostile input stays typed
# --------------------------------------------------------------------------- #

def test_verify_signature_typed_on_mismatched_jwk():
    from openvc.keys import Ed25519SigningKey, P256SigningKey
    sig = P384SigningKey.generate(kid="k").sign(b"m")
    for jwk in (P256SigningKey.generate(kid="k").public_jwk(),   # wrong-curve coords
                Ed25519SigningKey.generate(kid="k").public_jwk()):  # OKP, no "y"
        with pytest.raises(InvalidKey):                  # typed, not a bare ValueError/KeyError
            verify_signature(alg="ES384", public_jwk=jwk, signing_input=b"m", signature=sig)


def test_status_list_path_fails_typed_on_es384_key_mismatch():
    # verify_compact (the IETF status-list token path) must not leak an untyped error
    from openvc.proof._jws import sign_compact, verify_compact
    from openvc.proof.errors import SignatureInvalid
    from openvc.keys import P256SigningKey
    key = P384SigningKey.generate(kid="k")
    token = sign_compact({"alg": "ES384", "typ": "JWT"}, {"iss": "x"}, signing_key=key)
    with pytest.raises(SignatureInvalid):
        verify_compact(token, public_key_jwk=P256SigningKey.generate(kid="k").public_jwk())


@pytest.mark.parametrize("point", [
    b"\x04" + (1).to_bytes(48, "big") + (1).to_bytes(48, "big"),   # uncompressed off-curve
    b"\x02\x00\x00",                                               # truncated compressed
    b"",                                                          # empty
], ids=["off-curve", "truncated", "empty"])
def test_malformed_p384_did_key_is_typed(point):
    from openvc.did.base import DidResolutionError
    from openvc.did.did_key import DidKeyResolver
    did = "did:key:" + encode_multibase(bytes([0x81, 0x24]) + point)
    with pytest.raises(DidResolutionError):              # not a bare ValueError
        DidKeyResolver().resolve(did)


def test_signing_key_from_jwk_dispatches_p384():
    from openvc.keys import signing_key_from_jwk
    key = P384SigningKey.generate(kid="k")
    d = _b64u(key._sk.private_numbers().private_value.to_bytes(48, "big"))
    sk = signing_key_from_jwk({**key.public_jwk(), "d": d}, kid="k")
    assert isinstance(sk, P384SigningKey) and sk.alg == "ES384"


def test_from_jwk_rejects_zero_scalar():
    key = P384SigningKey.generate(kid="k")
    with pytest.raises(InvalidKey):
        P384SigningKey.from_jwk({**key.public_jwk(), "d": _b64u(b"\x00" * 48)}, kid="k")
