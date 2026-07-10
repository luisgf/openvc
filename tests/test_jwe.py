"""
tests/test_jwe.py — JWE Compact decryption for HAIP encrypted responses (#19).

Pins the ECDH-ES decrypt path to authoritative vectors, per "golden fixtures are the
drift alarm":

  * **RFC 7518 Appendix C** — the canonical ECDH-ES Concat KDF worked example: the KDF
    output (`VqqN6vgjbSBcIijNcacQGg`) and the ECDH shared secret `Z`, byte-for-byte;
  * **OpenID4VP 1.0 §8.3** — a real direct `ECDH-ES` + `A128GCM` + P-256 compact JWE
    with the recipient's private JWK (the exact HAIP mode); and
  * **RFC 7520 §5.5** — a byte-complete direct-ECDH-ES vector, used to cross-check the
    key-agreement half (its content encryption is CBC-HMAC, which this path does not
    implement, so only the derived CEK is asserted).

Plus round-trips for both `A128GCM`/`A256GCM` (no public GCM vector exists for the
whole assembly, so a test-only encrypt pins the GCM leg) and the fail-closed allow-list
(HAIP mandates exactly `ECDH-ES` × {`A128GCM`,`A256GCM`} on P-256).
"""
from __future__ import annotations

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openvc.keys import InvalidKey, P256KeyAgreementKey
from openvc.jwe import (
    JweDecryptionFailed,
    JweMalformed,
    UnsupportedJweAlgorithm,
    _concat_kdf,
    decrypt_compact,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- #
# RFC 7518 Appendix C — the ECDH-ES Concat KDF worked example (byte-exact)
# --------------------------------------------------------------------------- #

_APPC_Z = bytes([158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38,
                 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140,
                 254, 144, 196])
_APPC_DERIVED = bytes([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26])
_APPC_BOB = {"kty": "EC", "crv": "P-256",
             "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
             "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
             "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}
_APPC_ALICE_EPK = {"kty": "EC", "crv": "P-256",
                   "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                   "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}


def test_rfc7518_appendix_c_concat_kdf():
    derived = _concat_kdf(_APPC_Z, 128, b"A128GCM", b"Alice", b"Bob")
    assert derived == _APPC_DERIVED
    assert _b64u(derived) == "VqqN6vgjbSBcIijNcacQGg"


def test_rfc7518_appendix_c_ecdh_shared_secret():
    bob = P256KeyAgreementKey.from_jwk(_APPC_BOB, kid="bob")
    assert bob.agree(_APPC_ALICE_EPK) == _APPC_Z


# --------------------------------------------------------------------------- #
# OpenID4VP 1.0 §8.3 — a real direct ECDH-ES + A128GCM + P-256 JWE (HAIP mode)
# --------------------------------------------------------------------------- #

_OID4VP_RECIPIENT = {"kty": "EC", "kid": "ac", "use": "enc", "crv": "P-256", "alg": "ECDH-ES",
                     "x": "YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
                     "y": "Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk",
                     "d": "Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"}
_OID4VP_JWE = (
    "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImtpZCI6ImFjIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6"
    "Im5ubVZwbTNWM2piaGNhZlFhUkJrU1ZOSGx3Wkh3dC05ck9wSnVmeVlJdWsiLCJ5IjoicjRmakRxd0p5czlxVU9Q"
    "LV9iM21SNVNaRy0tQ3dPMm1pYzVWU05UWU45ZyIsImNydiI6IlAtMjU2In19..uAYcHRUSSn2X0WPX.yVzlGSYG4"
    "qbg0bq18JcUiDRw56yVnbKR8E7S7YlEtzT00RqE3Pw5oTpUG3hdLN4taHZ9gC1kwak8JOnJgQ.1wR024_3-qtAlx"
    "1oFIUpQQ")


def test_openid4vp_spec_jwe_decrypts_in_haip_mode():
    recipient = P256KeyAgreementKey.from_jwk(_OID4VP_RECIPIENT, kid="ac")
    plaintext = decrypt_compact(_OID4VP_JWE, key=recipient)
    payload = json.loads(plaintext)                       # the tag verified end to end
    assert isinstance(payload, dict) and "vp_token" in payload


# --------------------------------------------------------------------------- #
# RFC 7520 §5.5 — cross-check the key-agreement half (CBC-HMAC enc, not implemented)
# --------------------------------------------------------------------------- #

def test_rfc7520_key_agreement_derives_the_documented_cek():
    recipient = P256KeyAgreementKey.from_jwk(
        {"kty": "EC", "crv": "P-256",
         "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
         "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
         "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"}, kid="m")
    epk = {"kty": "EC", "crv": "P-256",
           "x": "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
           "y": "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs"}
    cek = _concat_kdf(recipient.agree(epk), 256, b"A128CBC-HS256", b"", b"")
    assert _b64u(cek) == "hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc"


# --------------------------------------------------------------------------- #
# round-trip (test-only encrypt) — the GCM leg, both key sizes
# --------------------------------------------------------------------------- #

from openvc.jwe import ALLOWED_ENC  # noqa: E402


def _encrypt(recipient_jwk, plaintext, *, enc="A128GCM", apu=b"", apv=b"", extra=None):
    """Test-only JWE producer (direct ECDH-ES): the wallet side of the exchange."""
    eph = ec.generate_private_key(ec.SECP256R1())
    rx = int.from_bytes(_b64u_d(recipient_jwk["x"]), "big")
    ry = int.from_bytes(_b64u_d(recipient_jwk["y"]), "big")
    z = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicNumbers(rx, ry, ec.SECP256R1()).public_key())
    en = eph.public_key().public_numbers()
    header = {"alg": "ECDH-ES", "enc": enc,
              "epk": {"kty": "EC", "crv": "P-256",
                      "x": _b64u(en.x.to_bytes(32, "big")), "y": _b64u(en.y.to_bytes(32, "big"))}}
    if apu:
        header["apu"] = _b64u(apu)
    if apv:
        header["apv"] = _b64u(apv)
    if extra:
        header.update(extra)
    cek = _concat_kdf(z, ALLOWED_ENC[enc] * 8, enc.encode(), apu, apv)
    protected = _b64u(json.dumps(header, separators=(",", ":")).encode())
    iv = os.urandom(12)
    ct_tag = AESGCM(cek).encrypt(iv, plaintext, protected.encode())
    return f"{protected}..{_b64u(iv)}.{_b64u(ct_tag[:-16])}.{_b64u(ct_tag[-16:])}"


@pytest.fixture(scope="module")
def recipient():
    return P256KeyAgreementKey.generate(kid="verifier#enc")


@pytest.mark.parametrize("enc", ["A128GCM", "A256GCM"])
def test_roundtrip(recipient, enc):
    payload = json.dumps({"vp_token": {"c": ["a.b.c~kb"]}, "state": "s"}).encode()
    jwe = _encrypt(recipient.public_jwk(), payload, enc=enc, apu=b"nonce123", apv=b"aud")
    assert decrypt_compact(jwe, key=recipient) == payload


def test_public_encryption_jwk_is_marked_use_enc(recipient):
    jwk = recipient.public_jwk()
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and jwk["use"] == "enc"


# --------------------------------------------------------------------------- #
# fail-closed allow-list + malformed input (HAIP §5.1)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", ["ECDH-ES+A128KW", "ECDH-ES+A256KW", "RSA-OAEP", "dir", "none"])
def test_rejects_non_ecdh_es_alg(recipient, alg):
    jwe = _encrypt(recipient.public_jwk(), b"{}", extra={"alg": alg})
    with pytest.raises(UnsupportedJweAlgorithm):
        decrypt_compact(jwe, key=recipient)


@pytest.mark.parametrize("enc", ["A128CBC-HS256", "A192GCM", "A256CBC-HS512", "made-up"])
def test_rejects_disallowed_enc(recipient, enc):
    jwe = _encrypt(recipient.public_jwk(), b"{}", extra={"enc": enc})
    with pytest.raises(UnsupportedJweAlgorithm):
        decrypt_compact(jwe, key=recipient)


def _rewrite_header(jwe, **override):
    parts = jwe.split(".")
    header = json.loads(_b64u_d(parts[0]))
    header.update(override)
    parts[0] = _b64u(json.dumps(header).encode())
    return ".".join(parts)


@pytest.mark.parametrize("override", [
    {"alg": ["ECDH-ES"]}, {"alg": {"x": 1}}, {"alg": 123}, {"alg": None},
    {"enc": ["A128GCM"]}, {"enc": {"x": 1}}, {"enc": 123}, {"enc": None},
], ids=["alg-list", "alg-dict", "alg-int", "alg-null",
        "enc-list", "enc-dict", "enc-int", "enc-null"])
def test_rejects_non_string_alg_enc(recipient, override):
    # a JSON list/object alg/enc must fail closed as UnsupportedJweAlgorithm, not a bare
    # TypeError from the `in frozenset/dict` membership test (adversarial-review regression)
    jwe = _rewrite_header(_encrypt(recipient.public_jwk(), b"{}"), **override)
    with pytest.raises(UnsupportedJweAlgorithm):
        decrypt_compact(jwe, key=recipient)


def test_rejects_zip_and_crit(recipient):
    for extra in ({"zip": "DEF"}, {"crit": ["exp"]}):
        jwe = _encrypt(recipient.public_jwk(), b"{}", extra=extra)
        with pytest.raises(UnsupportedJweAlgorithm):
            decrypt_compact(jwe, key=recipient)


def test_rejects_non_empty_encrypted_key(recipient):
    jwe = _encrypt(recipient.public_jwk(), b"{}")
    parts = jwe.split(".")
    parts[1] = "QUJD"                                    # a stray wrapped-key segment
    with pytest.raises(JweMalformed):
        decrypt_compact(".".join(parts), key=recipient)


def test_rejects_missing_epk(recipient):
    eph_jwe = _encrypt(recipient.public_jwk(), b"{}")
    header = json.loads(_b64u_d(eph_jwe.split(".")[0]))
    del header["epk"]
    bad = _b64u(json.dumps(header).encode()) + "." + ".".join(eph_jwe.split(".")[1:])
    with pytest.raises(JweMalformed):
        decrypt_compact(bad, key=recipient)


@pytest.mark.parametrize("epk", [
    {"kty": "OKP", "crv": "X25519", "x": "AAAA"},
    {"kty": "EC", "crv": "P-384", "x": "AA", "y": "BB"},
    {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"},   # (1,1): not on the P-256 curve
], ids=["x25519", "p384", "off-curve"])
def test_rejects_bad_epk(recipient, epk):
    jwe = _encrypt(recipient.public_jwk(), b"{}", extra={"epk": epk})
    with pytest.raises(JweMalformed):
        decrypt_compact(jwe, key=recipient)


@pytest.mark.parametrize("token", ["a.b.c.d", "a.b.c.d.e.f", "only-one-part", "a..c.d"],
                         ids=["4-parts", "6-parts", "1-part", "5-empty"])
def test_rejects_wrong_part_count_or_header(recipient, token):
    with pytest.raises(JweMalformed):
        decrypt_compact(token, key=recipient)


def test_tampered_ciphertext_fails_closed(recipient):
    jwe = _encrypt(recipient.public_jwk(), b'{"vp_token":{}}')
    p = jwe.split(".")
    ct = list(p[3])
    ct[0] = "A" if ct[0] != "A" else "B"
    p[3] = "".join(ct)
    with pytest.raises(JweDecryptionFailed):
        decrypt_compact(".".join(p), key=recipient)


def test_wrong_recipient_key_fails_closed(recipient):
    jwe = _encrypt(recipient.public_jwk(), b'{"vp_token":{}}')
    with pytest.raises(JweDecryptionFailed):
        decrypt_compact(jwe, key=P256KeyAgreementKey.generate(kid="other"))


def test_rejects_non_96_bit_iv(recipient):
    jwe = _encrypt(recipient.public_jwk(), b"{}")
    p = jwe.split(".")
    p[2] = _b64u(os.urandom(16))                          # 128-bit IV instead of 96-bit
    with pytest.raises(JweMalformed):
        decrypt_compact(".".join(p), key=recipient)


# --------------------------------------------------------------------------- #
# the P256KeyAgreementKey backend
# --------------------------------------------------------------------------- #

def test_agreement_key_from_jwk_roundtrips_ecdh():
    a = P256KeyAgreementKey.generate(kid="a")
    b = P256KeyAgreementKey.generate(kid="b")
    # ECDH is symmetric: agree(a_priv, b_pub) == agree(b_priv, a_pub)
    assert a.agree(b.public_jwk()) == b.agree(a.public_jwk())
    reloaded = P256KeyAgreementKey.from_jwk(
        {**a.public_jwk(), "d": _b64u(a._sk.private_numbers().private_value.to_bytes(32, "big"))},
        kid="a")
    assert reloaded.agree(b.public_jwk()) == a.agree(b.public_jwk())


def test_agreement_key_rejects_non_p256_peer():
    a = P256KeyAgreementKey.generate(kid="a")
    with pytest.raises(InvalidKey):
        a.agree({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"})


def test_agreement_key_rejects_non_p256_private():
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    with pytest.raises(InvalidKey):
        P256KeyAgreementKey(_ec.generate_private_key(_ec.SECP384R1()), kid="k")


def test_oversized_jwe_token_is_rejected():
    # #103: bound an attacker-supplied token before base64-decoding it.
    from openvc.jwe import MAX_JWE_BYTES, decrypt_compact
    from openvc.keys import P256KeyAgreementKey
    huge = "a" * (MAX_JWE_BYTES + 1)
    with pytest.raises(JweMalformed):
        decrypt_compact(huge, key=P256KeyAgreementKey.generate("k"))
