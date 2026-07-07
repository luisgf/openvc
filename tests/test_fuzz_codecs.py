"""
tests/test_fuzz_codecs.py — property-based fuzzing of the hand-rolled byte codecs
(issue #11).

Fail-closed is only as trustworthy as its behaviour on hostile input, and the
hand-rolled parsers (CBOR for ecdsa-sd, base58btc + LEB128 varint for multibase,
the MSB-first bitstring and the LSB-first token status list) take attacker bytes.
Two properties per codec: (1) `decode(encode(x)) == x` round-trips, and (2) `decode`
of ARBITRARY input never raises anything but the module's typed error (an
`OpenvcError`) — never a bare `ValueError` / `IndexError` / `struct.error` leaking out.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from openvc.errors import OpenvcError
from openvc.multibase import (
    MultibaseError,
    b58btc_decode,
    b58btc_encode,
    decode_multibase,
    encode_multibase,
    read_varint,
)
from openvc.status.bitstring import StatusListError, decode_bitstring, encode_bitstring
from openvc.status.token_status_list import decode_status_list, encode_status_list

pyld = pytest.importorskip("pyld")            # importing ecdsa_sd pulls the DI stack
from openvc.proof.ecdsa_sd import (  # noqa: E402
    ProofValueMalformed,
    decode_cbor,
    encode_cbor,
)

# CBOR subset ecdsa-sd uses: unsigned ints, byte/text strings, arrays, and maps
# (canonical CBOR maps have homogeneously-typed keys — ecdsa-sd uses int or str keys).
_cbor_scalar = (st.integers(min_value=0, max_value=2 ** 64 - 1)
                | st.binary(max_size=48) | st.text(max_size=48))
_cbor = st.recursive(
    _cbor_scalar,
    lambda kids: (st.lists(kids, max_size=6)
                  | st.dictionaries(st.integers(min_value=0, max_value=2 ** 32 - 1), kids,
                                    max_size=6)),
    max_leaves=15,
)


@settings(max_examples=250)
@given(_cbor)
def test_cbor_roundtrips(value):
    assert decode_cbor(encode_cbor(value)) == value


@settings(max_examples=400)
@given(st.binary(max_size=256))
def test_cbor_decode_never_crashes(data):
    try:
        decode_cbor(data)
    except ProofValueMalformed:
        pass                                  # the one allowed failure (an OpenvcError)


@settings(max_examples=300)
@given(st.binary(max_size=128))
def test_base58_roundtrips(data):
    assert b58btc_decode(b58btc_encode(data)) == data


@settings(max_examples=300)
@given(st.binary(max_size=128))
def test_multibase_roundtrips(data):
    assert decode_multibase(encode_multibase(data)) == data


@settings(max_examples=400)
@given(st.text(max_size=64))
def test_multibase_decode_never_crashes(value):
    try:
        decode_multibase(value)
    except MultibaseError:
        pass


@settings(max_examples=400)
@given(st.binary(max_size=32))
def test_read_varint_never_crashes(data):
    try:
        read_varint(data)
    except MultibaseError:
        pass


@settings(max_examples=200)
@given(st.binary(max_size=256))
def test_bitstring_roundtrips(data):
    assert decode_bitstring(encode_bitstring(data)) == data


@settings(max_examples=200)
@given(st.binary(max_size=256))
def test_token_status_list_roundtrips(data):
    assert decode_status_list(encode_status_list(data)) == data


@settings(max_examples=400)
@given(st.text(max_size=96))
def test_status_decode_never_crashes(value):
    for decode in (decode_bitstring, decode_status_list):
        try:
            decode(value)
        except StatusListError:
            pass


# --------------------------------------------------------------------------- #
# explicit MUST-REJECT corpus (named cases the fuzzers found or should keep finding)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("data", [
    b"\x63\xff\xff\xff",   # text string of invalid UTF-8 (regression: was UnicodeDecodeError)
    b"\xa1\xa0\x00",       # map with a map key (regression: was TypeError unhashable)
    b"\x42\x00",           # 2-byte byte string, only 1 byte present (truncated)
    b"\x63ab",             # 3-byte text string, only 2 bytes present (truncated)
    b"\x00\x00",           # trailing byte after a complete top-level item
    b"\x1c",               # unsupported additional-info in the head
    b"\xf5",               # a CBOR bool — not in the proof-value shape
], ids=["bad-utf8", "map-key", "trunc-bytes", "trunc-text", "trailing", "bad-head", "bool"])
def test_cbor_must_reject_with_typed_error(data):
    with pytest.raises(ProofValueMalformed):
        decode_cbor(data)


@pytest.mark.parametrize("value", ["x", "z!!!", "f", "not-multibase"],
                         ids=["no-base-char", "bad-b58", "hex-unsupported", "garbage"])
def test_multibase_must_reject_with_typed_error(value):
    with pytest.raises(MultibaseError):
        decode_multibase(value)


@settings(max_examples=200)
@given(st.binary(min_size=1, max_size=200))
def test_status_decode_arbitrary_bytes_only_typed_errors(data):
    # feed raw bytes as a (usually invalid) base64url payload; any failure must be typed
    import base64
    value = base64.urlsafe_b64encode(data).decode()
    for decode in (decode_bitstring, decode_status_list):
        try:
            decode(value)
        except OpenvcError:
            pass
