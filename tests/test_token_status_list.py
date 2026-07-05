"""
tests/test_token_status_list.py — IETF Token Status List
(draft-ietf-oauth-status-list): the packed multi-bit codec and the referenced-
token status check. All offline; the status list token is built here.
"""
from __future__ import annotations

import pytest

from openvc.status import (
    STATUS_INVALID,
    STATUS_SUSPENDED,
    STATUS_VALID,
    StatusListError,
    check_token_status,
    decode_status_list,
    encode_bitstring,
    encode_status_list,
    get_status,
    new_status_list,
    parse_token_status_ref,
    set_status,
)

LIST_URI = "https://issuer.example/statuslists/1"


# --------------------------------------------------------------------------- #
# codec — LSB-first packing, hand-verified against the draft's byte layout
# --------------------------------------------------------------------------- #

def test_bits1_packs_lsb_first():
    # draft-ietf-oauth-status-list example: statuses [1,0,0,1,1,1,0,1] -> 0xB9,
    # with index 0 in the least-significant bit of byte 0.
    data = new_status_list(8, bits=1)
    for i, s in enumerate([1, 0, 0, 1, 1, 1, 0, 1]):
        set_status(data, i, s, bits=1)
    assert bytes(data) == bytes([0xB9])
    for i, s in enumerate([1, 0, 0, 1, 1, 1, 0, 1]):
        assert get_status(bytes(data), i, bits=1) == s


def test_bits2_four_statuses_per_byte():
    data = new_status_list(4, bits=2)
    set_status(data, 0, 1, bits=2)   # bits 0-1
    set_status(data, 1, 2, bits=2)   # bits 2-3
    set_status(data, 2, 3, bits=2)   # bits 4-5
    set_status(data, 3, 0, bits=2)   # bits 6-7
    assert bytes(data) == bytes([0b00_11_10_01])   # 0x39
    assert [get_status(bytes(data), i, bits=2) for i in range(4)] == [1, 2, 3, 0]


def test_bits4_two_statuses_per_byte():
    data = new_status_list(2, bits=4)
    set_status(data, 0, 0x0A, bits=4)   # low nibble
    set_status(data, 1, 0x0F, bits=4)   # high nibble
    assert bytes(data) == bytes([0xFA])
    assert get_status(bytes(data), 0, bits=4) == 0x0A
    assert get_status(bytes(data), 1, bits=4) == 0x0F


def test_bits8_one_status_per_byte():
    data = new_status_list(3, bits=8)
    set_status(data, 0, 0x00, bits=8)
    set_status(data, 1, 0x7F, bits=8)
    set_status(data, 2, 0xFF, bits=8)
    assert bytes(data) == bytes([0x00, 0x7F, 0xFF])


def test_status_spans_byte_boundary():
    data = new_status_list(16, bits=1)
    set_status(data, 8, 1, bits=1)       # first bit of the second byte
    assert bytes(data) == bytes([0x00, 0x01])
    assert get_status(bytes(data), 8, bits=1) == 1


def test_new_status_list_sizes_up():
    assert len(new_status_list(8, bits=1)) == 1
    assert len(new_status_list(9, bits=1)) == 2
    assert len(new_status_list(4, bits=2)) == 1
    assert len(new_status_list(5, bits=2)) == 2
    assert len(new_status_list(2, bits=4)) == 1
    assert len(new_status_list(1, bits=8)) == 1


def test_encode_decode_roundtrip():
    data = new_status_list(500, bits=2)
    set_status(data, 0, 3, bits=2)
    set_status(data, 499, 2, bits=2)
    restored = decode_status_list(encode_status_list(bytes(data)))
    assert restored == bytes(data)
    assert get_status(restored, 499, bits=2) == 2


def test_encode_is_deterministic():
    data = bytes([0xB9, 0x00, 0xC3])
    assert encode_status_list(data) == encode_status_list(data)


# --------------------------------------------------------------------------- #
# codec — errors
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bits", [0, 3, 5, 7, 16])
def test_bad_bits_rejected(bits):
    with pytest.raises(StatusListError):
        get_status(bytes([0x00]), 0, bits=bits)
    with pytest.raises(StatusListError):
        new_status_list(8, bits=bits)


def test_value_that_does_not_fit_rejected():
    data = new_status_list(4, bits=2)
    with pytest.raises(StatusListError):
        set_status(data, 0, 4, bits=2)      # 4 needs 3 bits


def test_index_out_of_range():
    with pytest.raises(StatusListError):
        get_status(bytes([0x00]), 8, bits=1)
    with pytest.raises(StatusListError):
        get_status(bytes([0x00]), -1, bits=1)


def test_decode_rejects_non_zlib():
    with pytest.raises(StatusListError):
        decode_status_list("!!!not-base64-or-zlib")
    # a W3C encodedList is gzip, not zlib — must not be accepted here.
    gzip_encoded = encode_bitstring(bytes([0xFF, 0x00]))
    with pytest.raises(StatusListError):
        decode_status_list(gzip_encoded)


# --------------------------------------------------------------------------- #
# reference parsing
# --------------------------------------------------------------------------- #

def test_parse_reference():
    ref = parse_token_status_ref({"status": {"status_list": {"idx": 42, "uri": LIST_URI}}})
    assert ref is not None
    assert ref.uri == LIST_URI and ref.index == 42


def test_parse_absent_reference_is_none():
    assert parse_token_status_ref({"sub": "x"}) is None
    assert parse_token_status_ref({"status": {"other": {}}}) is None
    assert parse_token_status_ref({"status": "not-a-dict"}) is None


def test_parse_malformed_reference_raises():
    with pytest.raises(StatusListError):
        parse_token_status_ref({"status": {"status_list": {"idx": 1}}})     # no uri
    with pytest.raises(StatusListError):
        parse_token_status_ref({"status": {"status_list": {"uri": LIST_URI}}})  # no idx
    with pytest.raises(StatusListError):
        parse_token_status_ref(
            {"status": {"status_list": {"idx": -1, "uri": LIST_URI}}})       # negative
    with pytest.raises(StatusListError):
        parse_token_status_ref(
            {"status": {"status_list": {"idx": True, "uri": LIST_URI}}})     # bool, not int


# --------------------------------------------------------------------------- #
# end-to-end status check
# --------------------------------------------------------------------------- #

def _token(idx: int) -> dict:
    return {"status": {"status_list": {"idx": idx, "uri": LIST_URI}}}


def _status_list_token(set_values: dict[int, int], *, bits: int = 2, size: int = 64) -> dict:
    data = new_status_list(size, bits=bits)
    for i, v in set_values.items():
        set_status(data, i, v, bits=bits)
    return {"status_list": {"bits": bits, "lst": encode_status_list(bytes(data))}}


def test_valid_status():
    resolve = {LIST_URI: _status_list_token({7: STATUS_INVALID})}.__getitem__
    result = check_token_status(_token(3), resolve_status_list_token=resolve)
    assert result is not None
    assert result.status == STATUS_VALID
    assert result.revoked is False and result.suspended is False


def test_invalid_status_is_revoked():
    resolve = {LIST_URI: _status_list_token({42: STATUS_INVALID})}.__getitem__
    result = check_token_status(_token(42), resolve_status_list_token=resolve)
    assert result is not None
    assert result.status == STATUS_INVALID
    assert result.revoked is True and result.suspended is False


def test_suspended_status():
    resolve = {LIST_URI: _status_list_token({9: STATUS_SUSPENDED})}.__getitem__
    result = check_token_status(_token(9), resolve_status_list_token=resolve)
    assert result is not None
    assert result.suspended is True and result.revoked is False


def test_no_reference_returns_none():
    result = check_token_status({"sub": "x"}, resolve_status_list_token=dict().__getitem__)
    assert result is None


def test_check_with_malformed_token_claim_raises():
    resolve = {LIST_URI: {"status_list": {"bits": 2}}}.__getitem__   # no lst
    with pytest.raises(StatusListError):
        check_token_status(_token(1), resolve_status_list_token=resolve)
    resolve = {LIST_URI: {"no_status_list": True}}.__getitem__
    with pytest.raises(StatusListError):
        check_token_status(_token(1), resolve_status_list_token=resolve)


def test_bits1_only_expresses_valid_or_invalid():
    # A 1-bit list can flag revocation but not suspension.
    resolve = {LIST_URI: _status_list_token({5: 1}, bits=1)}.__getitem__
    result = check_token_status(_token(5), resolve_status_list_token=resolve)
    assert result is not None
    assert result.revoked is True and result.suspended is False
