"""
tests/test_multibase.py — base58btc multibase ('z') + multicodec varint codec
(``openvc.multibase``), issue #63.

The codec is exercised indirectly by the did:key resolvers and the Data Integrity
proofValue path, and fuzzed for "decode never raises outside OpenvcError" in
``test_fuzz_codecs``. This is the direct unit floor: known vectors, leading-zero
handling (the classic base58 footgun), and the typed-error negative paths.
"""
from __future__ import annotations

import pytest

from openvc.multibase import (
    MultibaseError,
    b58btc_decode,
    b58btc_encode,
    decode_multibase,
    encode_multibase,
    read_varint,
)

# --------------------------------------------------------------------------- #
# base58btc — known vectors + leading-zero preservation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw, encoded",
    [
        (b"", ""),
        (b"\x00", "1"),                       # a leading NUL byte -> a single '1'
        (b"\x00\x00", "11"),
        (b"hello world", "StV1DL6CwTryKyV"),  # canonical base58btc test vector
        (b"\x00\x01\x02", "15T"),             # leading NUL kept in front of the body
    ],
)
def test_b58btc_known_vectors(raw, encoded):
    assert b58btc_encode(raw) == encoded
    assert b58btc_decode(encoded) == raw


@pytest.mark.parametrize(
    "raw",
    [b"\x00" * 5, bytes(range(32)), b"\xff" * 16, b"\x00\xff\x00\xff"],
)
def test_b58btc_roundtrip(raw):
    assert b58btc_decode(b58btc_encode(raw)) == raw


def test_b58btc_decode_rejects_invalid_char():
    # '0', 'O', 'I', 'l' are deliberately absent from the base58 alphabet.
    for bad in ("0", "O", "I", "l", "hello world!"):
        with pytest.raises(MultibaseError):
            b58btc_decode(bad)


# --------------------------------------------------------------------------- #
# multibase — the 'z' prefix is mandatory
# --------------------------------------------------------------------------- #


def test_encode_multibase_prefixes_z():
    assert encode_multibase(b"\x01\x02\x03").startswith("z")
    assert decode_multibase(encode_multibase(b"\x01\x02\x03")) == b"\x01\x02\x03"


def test_decode_multibase_requires_z_prefix():
    for bad in ("", "f00", "b1234", "Q1"):     # base16 'f', base32 'b', etc. unsupported
        with pytest.raises(MultibaseError):
            decode_multibase(bad)


def test_decode_multibase_empty_body():
    assert decode_multibase("z") == b""        # just the prefix -> empty bytes


# --------------------------------------------------------------------------- #
# multicodec varint (LEB128)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "data, value, consumed",
    [
        (b"\x00", 0, 1),
        (b"\x7f", 127, 1),
        (b"\x80\x01", 128, 2),
        (b"\xed\x01rest", 0xED, 2),   # Ed25519-pub multicodec 0xed01 -> value 237
        (b"\x80\x24rest", 0x1200, 2),  # P-256-pub multicodec 0x1200 -> value 4608
        (b"\x81\x24rest", 0x1201, 2),  # P-384-pub multicodec 0x1201 -> value 4609
    ],
)
def test_read_varint(data, value, consumed):
    assert read_varint(data) == (value, consumed)


def test_read_varint_truncated_raises():
    with pytest.raises(MultibaseError):
        read_varint(b"\x80")             # continuation bit set but no next byte
    with pytest.raises(MultibaseError):
        read_varint(b"\xff\xff")         # runs off the end still expecting more
