"""
tests/test_ecdsa_sd.py — ecdsa-sd-2023 selective disclosure.

Stage 1 here covers the self-contained serialization primitives (CBOR, multikey,
HMAC label map, proof-value encode/parse) — no pyld needed. The CBOR codec is
checked against the RFC 8949 Appendix A examples so the wire format is trustworthy.
The base -> derive -> verify round-trip lives further down (needs pyld).
"""
from __future__ import annotations

import pytest

from openvc.keys import P256SigningKey
from openvc.proof.ecdsa_sd import (
    EcdsaSdError,
    ProofValueMalformed,
    cbor_decode,
    cbor_encode,
    compress_label_map,
    decompress_label_map,
    hmac_label,
    p256_multikey_to_jwk,
    p256_public_multikey,
    parse_base_proof,
    parse_derived_proof,
    serialize_base_proof,
    serialize_derived_proof,
)


# --------------------------------------------------------------------------- #
# CBOR — checked against RFC 8949 Appendix A
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value,encoded", [
    (0, b"\x00"),
    (1, b"\x01"),
    (10, b"\x0a"),
    (23, b"\x17"),
    (24, b"\x18\x18"),
    (100, b"\x18\x64"),
    (1000, b"\x19\x03\xe8"),
    (b"", b"\x40"),
    (b"\x01\x02\x03\x04", b"\x44\x01\x02\x03\x04"),
    ("a", b"\x61\x61"),
    ("IETF", b"\x64\x49\x45\x54\x46"),
    ([], b"\x80"),
    ([1, 2, 3], b"\x83\x01\x02\x03"),
    ({1: b"\x02"}, b"\xa1\x01\x41\x02"),
])
def test_cbor_matches_rfc8949(value, encoded):
    assert cbor_encode(value) == encoded
    assert cbor_decode(encoded) == value


def test_cbor_map_keys_are_canonically_sorted():
    assert cbor_encode({2: b"b", 1: b"a", 10: b"c"}) == \
        b"\xa3\x01\x41a\x02\x41b\x0a\x41c"


def test_cbor_rejects_bool_and_negative():
    with pytest.raises(EcdsaSdError):
        cbor_encode(True)
    with pytest.raises(EcdsaSdError):
        cbor_encode(-1)


def test_cbor_rejects_trailing_bytes():
    with pytest.raises(ProofValueMalformed):
        cbor_decode(b"\x00\x00")


def test_cbor_roundtrip_proof_shape():
    shape = [b"\x00" * 64, b"\x8024" + b"\x03" * 33, b"k" * 32,
             [b"s" * 64, b"t" * 64], ["/credentialSubject/id", "/type"]]
    assert cbor_decode(cbor_encode(shape)) == shape


# --------------------------------------------------------------------------- #
# P-256 multikey
# --------------------------------------------------------------------------- #

def test_multikey_roundtrip_and_length():
    jwk = P256SigningKey.generate(kid="k").public_jwk()
    mk = p256_public_multikey(jwk)
    assert len(mk) == 35 and mk[:2] == b"\x80\x24"     # 0x1200 varint + compressed
    assert p256_multikey_to_jwk(mk) == jwk


def test_multikey_rejects_non_p256():
    with pytest.raises(EcdsaSdError):
        p256_public_multikey({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"})
    with pytest.raises(ProofValueMalformed):
        p256_multikey_to_jwk(b"\x00\x01\x02")


# --------------------------------------------------------------------------- #
# HMAC label map
# --------------------------------------------------------------------------- #

def test_hmac_label_is_deterministic_and_keyed():
    key = b"\x11" * 32
    label = hmac_label(key, "c14n0")
    assert label.startswith("u")
    assert hmac_label(key, "c14n0") == label           # deterministic
    assert hmac_label(key, "c14n1") != label           # per-label
    assert hmac_label(b"\x22" * 32, "c14n0") != label  # per-key


def test_label_map_compress_roundtrip():
    key = b"\x33" * 32
    label_map = {"c14n0": hmac_label(key, "c14n0"), "c14n2": hmac_label(key, "c14n2")}
    compressed = compress_label_map(label_map)
    assert set(compressed) == {0, 2} and all(isinstance(v, bytes) for v in compressed.values())
    assert decompress_label_map(compressed) == label_map


# --------------------------------------------------------------------------- #
# proof-value serialize / parse
# --------------------------------------------------------------------------- #

def test_base_proof_value_roundtrip():
    key = b"\x44" * 32
    pv = serialize_base_proof(
        base_signature=b"\x01" * 64,
        public_key=p256_public_multikey(P256SigningKey.generate(kid="k").public_jwk()),
        hmac_key=key,
        signatures=[b"\x02" * 64, b"\x03" * 64],
        mandatory_pointers=["/issuer", "/validFrom"])
    assert pv.startswith("u2V0A") or pv.startswith("u")   # multibase 'u' + header
    parsed = parse_base_proof(pv)
    assert parsed["base_signature"] == b"\x01" * 64
    assert parsed["hmac_key"] == key
    assert parsed["signatures"] == [b"\x02" * 64, b"\x03" * 64]
    assert parsed["mandatory_pointers"] == ["/issuer", "/validFrom"]


def test_derived_proof_value_roundtrip():
    key = b"\x55" * 32
    label_map = {"c14n0": hmac_label(key, "c14n0"), "c14n1": hmac_label(key, "c14n1")}
    pv = serialize_derived_proof(
        base_signature=b"\x01" * 64,
        public_key=p256_public_multikey(P256SigningKey.generate(kid="k").public_jwk()),
        signatures=[b"\x02" * 64],
        label_map=label_map,
        mandatory_indexes=[0, 3, 5])
    parsed = parse_derived_proof(pv)
    assert parsed["base_signature"] == b"\x01" * 64
    assert parsed["signatures"] == [b"\x02" * 64]
    assert parsed["label_map"] == label_map
    assert parsed["mandatory_indexes"] == [0, 3, 5]


def test_parse_rejects_wrong_header():
    with pytest.raises(ProofValueMalformed):
        parse_base_proof(serialize_derived_proof(
            base_signature=b"", public_key=b"", signatures=[],
            label_map={}, mandatory_indexes=[]))
