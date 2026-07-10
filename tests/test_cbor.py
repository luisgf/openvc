"""
tests/test_cbor.py — the bounded CBOR codec (openvc.cbor) for the COSE/mdoc profile.

Extends what the ecdsa-sd subset covered (test_fuzz_codecs / test_ecdsa_sd) with the
COSE/mdoc additions: negative integers, tags (kept with their exact received bytes),
booleans/null, deterministic map ordering, and the CborRaw verbatim primitive. Negative
paths first — malformed input must fail closed with a typed CborError, never a bare crash.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from openvc.cbor import (
    CborError,
    CborRaw,
    CborTag,
    decode,
    decode_from,
    encode,
)


# --------------------------------------------------------------------------- #
# RFC 8949 known-answer vectors (Appendix A), including the profile additions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value, hexbytes", [
    (0, "00"), (1, "01"), (23, "17"), (24, "1818"), (1000, "1903e8"),
    (-1, "20"), (-10, "29"), (-100, "3863"), (-1000, "3903e7"),          # negatives
    (False, "f4"), (True, "f5"), (None, "f6"),                           # simple values
    (b"", "40"), (b"\x01\x02\x03\x04", "4401020304"),
    ("", "60"), ("IETF", "6449455446"),
    ([], "80"), ([1, 2, 3], "83010203"),
    ({}, "a0"), ({1: 2, 3: 4}, "a201020304"),
])
def test_rfc8949_known_answers(value, hexbytes):
    assert encode(value).hex() == hexbytes
    assert decode(bytes.fromhex(hexbytes)) == value


def test_tag_encodes_and_decodes_with_raw_bytes():
    # #6.24(bstr) — the embedded-CBOR tag mdoc uses everywhere.
    tag = CborTag(24, b"\x01\x02")
    raw = encode(tag)
    assert raw.hex() == "d8184201" + "02"                       # d8 18 (tag24) 42 (bstr2) 0102
    back = decode(raw)
    assert isinstance(back, CborTag) and back.tag == 24 and back.value == b"\x01\x02"
    assert back.raw == raw                                      # exact received bytes kept
    assert back == tag                                          # equality ignores .raw


def test_map_keys_are_ordered_by_encoded_bytes():
    # Core-deterministic (RFC 8949 §4.2.1): sort by ENCODED key bytes, so an int key (0x0a)
    # sorts before a text key (0x61...), regardless of Python insertion order.
    out = encode({"a": 1, 10: 2, 100: 3})
    assert out.hex() == "a3" + "0a02" + "186403" + "616101"     # 10, then 100, then "a"


def test_cborraw_is_embedded_verbatim():
    inner = encode([1, 2, 3])
    assert encode([CborRaw(inner), 9]).hex() == "82" + inner.hex() + "09"


def test_negative_int_roundtrip_boundaries():
    for v in (-1, -24, -25, -256, -257, -65536, -(2 ** 32), -(2 ** 63)):
        assert decode(encode(v)) == v


def test_decode_from_walks_concatenated_items():
    blob = encode(1) + encode("x") + encode(b"z")
    v1, i = decode_from(blob, 0)
    v2, j = decode_from(blob, i)
    v3, k = decode_from(blob, j)
    assert (v1, v2, v3) == (1, "x", b"z") and k == len(blob)


# --------------------------------------------------------------------------- #
# fail-closed: malformed input -> typed CborError, never a crash
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("data, why", [
    (b"\x00\x00", "trailing bytes"),
    (b"\x9f\x00\xff", "indefinite-length array"),
    (b"\x5f\x42\x01\x02\xff", "indefinite-length bstr"),
    (b"\x1c", "reserved additional-info (28)"),
    (b"\x42\x00", "truncated byte string"),
    (b"\x63ab", "truncated text string"),
    (b"\x63\xff\xff\xff", "invalid utf-8 text"),
    (b"\xa1\xa0\x00", "map key is a map (out of profile / unhashable)"),
    (b"\xfa\x47\xc3\x50\x00", "float (single-precision) rejected"),
    (b"\xf9\x00\x14", "float16 whose bits == 20 must NOT decode as False"),
    (b"\xf9\x00\x16", "float16 whose bits == 22 must NOT decode as None"),
    (b"\xfa\x00\x00\x00\x14", "float32 whose bits == 20 must NOT decode as False"),
    (b"\xf8\x14", "non-preferred 1-byte simple value form rejected"),
    (b"\xf7", "the 'undefined' simple value rejected"),
    (b"", "empty input"),
])
def test_malformed_raises_typed_cbor_error(data, why):
    with pytest.raises(CborError):
        decode(data)


def test_deeply_nested_fails_closed_not_recursionerror():
    # 200 nested single-element arrays (0x81 ...) exceeds the bounded depth -> CborError,
    # not a RecursionError escaping the OpenvcError family.
    hostile = b"\x81" * 200 + b"\x00"
    with pytest.raises(CborError):
        decode(hostile)


def test_encode_rejects_unsupported_type():
    with pytest.raises(CborError):
        encode(object())
    with pytest.raises(CborError):
        encode(2 ** 64)                                # out of 64-bit CBOR range


# --------------------------------------------------------------------------- #
# property-based: round-trip and never-crash over the extended profile
# --------------------------------------------------------------------------- #

_scalar = (st.integers(min_value=-(2 ** 63), max_value=2 ** 64 - 1)
           | st.binary(max_size=32) | st.text(max_size=32)
           | st.booleans() | st.none())
_keys = (st.integers(min_value=-(2 ** 32), max_value=2 ** 32)
         | st.text(max_size=16) | st.binary(max_size=16))
_value = st.recursive(
    _scalar,
    lambda kids: (st.lists(kids, max_size=5)
                  | st.dictionaries(_keys, kids, max_size=5)
                  | st.builds(CborTag, st.integers(min_value=0, max_value=2 ** 32 - 1), kids)),
    max_leaves=20,
)


@settings(max_examples=300)
@given(_value)
def test_roundtrips_over_the_extended_profile(value):
    assert decode(encode(value)) == value


@settings(max_examples=400)
@given(st.binary(max_size=256))
def test_decode_never_crashes(data):
    try:
        decode(data)
    except CborError:
        pass                                          # the one allowed failure
