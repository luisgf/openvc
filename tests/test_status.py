"""
tests/test_status.py — W3C Bitstring Status List: bit encoding and the
credentialStatus check. All offline; the status-list credential is built here.
"""
from __future__ import annotations

import pytest

from openvc.status import (
    StatusListError,
    check_credential_status,
    decode_bitstring,
    encode_bitstring,
    get_status_bit,
    parse_status_entries,
    set_status_bit,
)

LIST_URL = "https://issuer.example/status/1"


# --------------------------------------------------------------------------- #
# bitstring low level
# --------------------------------------------------------------------------- #

def test_encode_decode_roundtrip():
    bits = bytes([0b1010_0000, 0x00, 0xFF])
    assert decode_bitstring(encode_bitstring(bits)) == bits


def test_msb_first_bit_order():
    # index 0 is the top bit of byte 0.
    bits = bytes([0b1000_0000])
    assert get_status_bit(bits, 0) == 1
    assert get_status_bit(bits, 1) == 0
    bits = bytes([0b0000_0001])
    assert get_status_bit(bits, 7) == 1
    assert get_status_bit(bits, 6) == 0


def test_set_and_read_specific_indices():
    bits = bytearray(32)                      # 256 bits, all zero
    set_status_bit(bits, 5, 1)
    set_status_bit(bits, 130, 1)
    for i in range(256):
        expected = 1 if i in (5, 130) else 0
        assert get_status_bit(bytes(bits), i) == expected
    set_status_bit(bits, 5, 0)
    assert get_status_bit(bytes(bits), 5) == 0


def test_index_out_of_range():
    with pytest.raises(StatusListError):
        get_status_bit(bytes(4), 32)
    with pytest.raises(StatusListError):
        get_status_bit(bytes(4), -1)


def test_bad_encoded_list():
    with pytest.raises(StatusListError):
        decode_bitstring("not-gzip!!!")


# --------------------------------------------------------------------------- #
# entry parsing
# --------------------------------------------------------------------------- #

def _entry(purpose="revocation", index="42", type_="BitstringStatusListEntry"):
    return {
        "id": f"{LIST_URL}#{index}",
        "type": type_,
        "statusPurpose": purpose,
        "statusListIndex": index,
        "statusListCredential": LIST_URL,
    }


def test_parse_single_and_list():
    assert len(parse_status_entries({"credentialStatus": _entry()})) == 1
    both = parse_status_entries({"credentialStatus": [
        _entry("revocation", "1"), _entry("suspension", "2")]})
    assert [e.purpose for e in both] == ["revocation", "suspension"]
    assert both[0].index == 1                 # string coerced to int


def test_parse_statuslist2021_and_skips_unknown():
    entries = parse_status_entries({"credentialStatus": [
        _entry(type_="StatusList2021Entry"),
        {"type": "SomethingElse", "foo": "bar"},          # skipped
    ]})
    assert len(entries) == 1
    assert entries[0].entry_type == "StatusList2021Entry"


def test_parse_malformed_raises():
    with pytest.raises(StatusListError):
        parse_status_entries({"credentialStatus": {
            "type": "BitstringStatusListEntry", "statusPurpose": "revocation"}})


@pytest.mark.parametrize("hostile_type", [
    [{"a": 1}],          # a list carrying an unhashable member (set-intersection TypeError)
    5,                   # a non-iterable type
    {"nested": "obj"},   # a mapping, not a type list
    [None, 42],          # a list of non-string members
], ids=["unhashable-member", "non-iterable", "mapping", "non-string-members"])
def test_parse_hostile_type_is_skipped_not_crashed(hostile_type):
    """A hostile `credentialStatus.type` must be skipped like any unrecognized type, not
    crash with a bare (non-OpenvcError) TypeError — otherwise it escapes the fail-closed
    contract (a whole verify_many batch would abort). Regression from adversarial review."""
    entries = parse_status_entries({"credentialStatus": {
        "type": hostile_type, "statusListIndex": "0", "statusListCredential": "u"}})
    assert entries == []


# --------------------------------------------------------------------------- #
# end-to-end status check
# --------------------------------------------------------------------------- #

def _status_vc(purpose: str, set_indices: set[int], size_bits: int = 256) -> dict:
    bits = bytearray(size_bits // 8)
    for i in set_indices:
        set_status_bit(bits, i, 1)
    return {
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "credentialSubject": {
            "type": "BitstringStatusList",
            "statusPurpose": purpose,
            "encodedList": encode_bitstring(bytes(bits)),
        },
    }


def test_revoked_when_bit_set():
    credential = {"credentialStatus": _entry("revocation", "42")}
    resolve = {LIST_URL: _status_vc("revocation", {42})}.__getitem__
    result = check_credential_status(credential, resolve_status_list=resolve)
    assert result.revoked is True and result.suspended is False
    assert result.entries[0].is_set is True


def test_not_revoked_when_bit_clear():
    credential = {"credentialStatus": _entry("revocation", "42")}
    resolve = {LIST_URL: _status_vc("revocation", {7})}.__getitem__   # 42 clear
    result = check_credential_status(credential, resolve_status_list=resolve)
    assert result.revoked is False
    assert result.entries[0].is_set is False


def test_suspension_purpose_tracked_separately():
    credential = {"credentialStatus": _entry("suspension", "9")}
    resolve = {LIST_URL: _status_vc("suspension", {9})}.__getitem__
    result = check_credential_status(credential, resolve_status_list=resolve)
    assert result.suspended is True and result.revoked is False


def test_purpose_mismatch_between_entry_and_list_raises():
    credential = {"credentialStatus": _entry("revocation", "42")}
    resolve = {LIST_URL: _status_vc("suspension", {42})}.__getitem__   # wrong purpose
    with pytest.raises(StatusListError):
        check_credential_status(credential, resolve_status_list=resolve)


def test_no_status_is_clean():
    result = check_credential_status({"id": "urn:x"}, resolve_status_list=dict().__getitem__)
    assert result.revoked is False and result.suspended is False
    assert result.entries == ()
