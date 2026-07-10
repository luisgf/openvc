"""
tests/test_cose.py — COSE_Sign1 / COSE_Mac0 verification (openvc.cose, RFC 9052).

Verify-only: the tests hand-build the COSE structures (there is no signing surface in
openvc) using P-256/P-384 keys and HMAC, then check the verifier. Negative paths first —
a wrong key, a tampered payload, a non-allow-listed algorithm, and a detached/attached
mismatch must all fail closed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from openvc import cbor, cose
from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign1(payload, key, *, alg=-7, x5chain=None, detached=False, external_aad=b""):
    """A COSE_Sign1 array [protected, unprotected, payload|nil, signature] over *payload*."""
    protected = cbor.encode({1: alg})
    unprotected = {} if x5chain is None else {33: x5chain}
    tbs = cbor.encode(["Signature1", protected, external_aad, payload])
    signature = key.sign(tbs)
    return [protected, unprotected, (None if detached else payload), signature]


def _mac0(payload, mac_key, *, alg=5, detached=False):
    protected = cbor.encode({1: alg})
    tbm = cbor.encode(["MAC0", protected, b"", payload])
    tag = hmac.new(mac_key, tbm, hashlib.sha256).digest()
    return [protected, {}, (None if detached else payload), tag]


# --------------------------------------------------------------------------- #
# COSE_Sign1
# --------------------------------------------------------------------------- #

def test_sign1_verifies_attached_payload_es256():
    key = P256SigningKey.generate(kid="ds")
    s = cose.parse_sign1(_sign1(b"hello mdoc", key))
    assert s.alg == -7
    assert cose.verify_sign1(s, public_jwk=key.public_jwk()) is True


def test_sign1_verifies_es384():
    key = P384SigningKey.generate(kid="ds")
    s = cose.parse_sign1(_sign1(b"payload", key, alg=-35))
    assert cose.verify_sign1(s, public_jwk=key.public_jwk()) is True


def test_sign1_verifies_detached_payload():
    key = P256SigningKey.generate(kid="dev")
    detached = b"DeviceAuthenticationBytes"
    s = cose.parse_sign1(_sign1(detached, key, detached=True))
    assert s.payload is None
    assert cose.verify_sign1(s, public_jwk=key.public_jwk(), detached_payload=detached) is True


def test_sign1_accepts_tagged_form():
    key = P256SigningKey.generate(kid="ds")
    tagged = cbor.CborTag(18, _sign1(b"x", key))
    assert cose.verify_sign1(cose.parse_sign1(tagged), public_jwk=key.public_jwk()) is True


def test_sign1_wrong_key_fails_closed():
    key, other = P256SigningKey.generate(kid="a"), P256SigningKey.generate(kid="b")
    s = cose.parse_sign1(_sign1(b"hello", key))
    assert cose.verify_sign1(s, public_jwk=other.public_jwk()) is False


def test_sign1_tampered_payload_fails():
    key = P256SigningKey.generate(kid="ds")
    array = _sign1(b"original", key)
    array[2] = b"tampered"
    assert cose.verify_sign1(cose.parse_sign1(array), public_jwk=key.public_jwk()) is False


def test_sign1_external_aad_must_match():
    key = P256SigningKey.generate(kid="ds")
    s = cose.parse_sign1(_sign1(b"p", key, external_aad=b"aad"))
    assert cose.verify_sign1(s, public_jwk=key.public_jwk(), external_aad=b"aad") is True
    assert cose.verify_sign1(s, public_jwk=key.public_jwk(), external_aad=b"other") is False


@pytest.mark.parametrize("alg", [-257, -36, 5, 0, "ES256"],
                         ids=["RS256", "ES512", "HMAC", "zero", "str"])
def test_sign1_non_allowlisted_alg_rejected_before_crypto(alg):
    key = P256SigningKey.generate(kid="ds")
    array = _sign1(b"p", key)
    array[0] = cbor.encode({1: alg}) if isinstance(alg, int) else cbor.encode({1: 0})
    s = cose.parse_sign1(array)
    with pytest.raises(cose.CoseError):        # unsupported alg or malformed -> typed, no crypto
        cose.verify_sign1(s, public_jwk=key.public_jwk())


def test_sign1_detached_and_attached_conflict_rejected():
    key = P256SigningKey.generate(kid="ds")
    s = cose.parse_sign1(_sign1(b"attached", key))          # payload present
    with pytest.raises(cose.CoseMalformed):
        cose.verify_sign1(s, public_jwk=key.public_jwk(), detached_payload=b"also")


def test_sign1_detached_without_payload_rejected():
    key = P256SigningKey.generate(kid="ds")
    s = cose.parse_sign1(_sign1(b"x", key, detached=True))   # payload nil, none supplied
    with pytest.raises(cose.CoseMalformed):
        cose.verify_sign1(s, public_jwk=key.public_jwk())


@pytest.mark.parametrize("bad", [
    [b"", {}, b"p"],                       # 3 elements, not 4
    "not-an-array",
    [b"not-cbor-map-bytes\xff", {}, b"p", b"sig"],
], ids=["short-array", "not-array", "bad-protected"])
def test_sign1_malformed_structure_rejected(bad):
    with pytest.raises(cose.CoseMalformed):
        cose.parse_sign1(bad)


def test_sign1_missing_alg_rejected():
    key = P256SigningKey.generate(kid="ds")
    array = _sign1(b"p", key)
    array[0] = cbor.encode({4: b"kid-only"})     # protected header without alg (label 1)
    with pytest.raises(cose.CoseMalformed):
        _ = cose.parse_sign1(array).alg


# --------------------------------------------------------------------------- #
# x5chain (label 33)
# --------------------------------------------------------------------------- #

def test_x5chain_single_cert_bstr_and_array():
    key = P256SigningKey.generate(kid="ds")
    single = cose.parse_sign1(_sign1(b"p", key, x5chain=b"DERCERT"))
    assert cose.x5chain_ders(single) == [b"DERCERT"]
    chain = cose.parse_sign1(_sign1(b"p", key, x5chain=[b"LEAF", b"CA"]))
    assert cose.x5chain_ders(chain) == [b"LEAF", b"CA"]


def test_x5chain_absent_is_typed_error():
    key = P256SigningKey.generate(kid="ds")
    with pytest.raises(cose.CoseMalformed, match="x5chain"):
        cose.x5chain_ders(cose.parse_sign1(_sign1(b"p", key)))


# --------------------------------------------------------------------------- #
# COSE_Key -> JWK
# --------------------------------------------------------------------------- #

def test_cose_key_ec2_p256_to_jwk():
    key = P256SigningKey.generate(kid="dev")
    jwk = key.public_jwk()
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    out = cose.cose_key_to_jwk({1: 2, -1: 1, -2: x, -3: y})
    assert out == {"kty": "EC", "crv": "P-256", "x": _b64url(x), "y": _b64url(y)}


def test_cose_key_okp_ed25519_to_jwk():
    key = Ed25519SigningKey.generate(kid="dev")
    raw = base64.urlsafe_b64decode(key.public_jwk()["x"] + "==")
    out = cose.cose_key_to_jwk({1: 1, -1: 6, -2: raw})
    assert out == {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


@pytest.mark.parametrize("cose_key, why", [
    ({1: 2, -1: 4, -2: b"\x00" * 66, -3: b"\x00" * 66}, "P-521 curve not supported"),
    ({1: 2, -1: 1, -2: b"\x00" * 16, -3: b"\x00" * 32}, "wrong-length P-256 coord"),
    ({1: 3, -1: 1}, "kty not EC2/OKP"),
    ({1: 1, -1: 6, -2: b"\x00" * 31}, "wrong-length Ed25519 x"),
    ("not-a-map", "not a map"),
], ids=["p521", "bad-coord-len", "bad-kty", "bad-okp-len", "not-map"])
def test_cose_key_rejects_out_of_profile(cose_key, why):
    with pytest.raises(cose.CoseMalformed):
        cose.cose_key_to_jwk(cose_key)


# --------------------------------------------------------------------------- #
# COSE_Mac0
# --------------------------------------------------------------------------- #

def test_mac0_verifies_and_detects_tamper():
    mac_key = b"\x2b" * 32
    detached = b"DeviceAuthenticationBytes"
    m = cose.parse_mac0(_mac0(detached, mac_key, detached=True))
    assert cose.verify_mac0(m, mac_key=mac_key, detached_payload=detached) is True
    assert cose.verify_mac0(m, mac_key=b"\x00" * 32, detached_payload=detached) is False
    assert cose.verify_mac0(m, mac_key=mac_key, detached_payload=b"other") is False


def test_mac0_non_hmac_alg_rejected():
    m = cose.parse_mac0(_mac0(b"p", b"k" * 32, alg=-7))    # -7 is a signature alg, not HMAC
    with pytest.raises(cose.CoseUnsupportedAlgorithm):
        cose.verify_mac0(m, mac_key=b"k" * 32, detached_payload=None)
