"""
tests/test_status_list_status_size.py — W3C Bitstring ``statusSize`` is honoured (#380).

Bitstring Status List v1.0 §3.2 step 10 / §3.3: an entry's status is the ``statusSize``-bit
value at position ``index * statusSize``; step 13: a revocation / suspension entry is valid
iff it is 0; §2.1: ``statusSize`` is an integer > 0 and ``statusMessage`` MUST be present
when it is > 1. openvc used to read one bit at ``index`` and never look at ``statusSize``:
a revoked credential was accepted, a valid one rejected, an out-of-range position accepted.

Now ``statusSize`` (absent -> 1, an ``int`` in 1..8) is parsed into the entry, the value is
read MSB-first at ``index * size``, the range is checked against the list, and the builders
mint what the verifier reads back. Outcomes are typed (:class:`StatusListError`,
:class:`CredentialRevoked`).
"""
from __future__ import annotations

import asyncio
import base64
import json

import pytest

from openvc import VerificationPolicy, verify_credential
from openvc.aio import verify_credential_async
from openvc.keys import P256SigningKey
from openvc.resolvers import (
    default_status_list_resolver,
    default_status_list_resolver_async,
)
from openvc.status import (
    CredentialRevoked,
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    check_credential_status,
    check_credential_status_async,
    decode_bitstring,
    encode_bitstring,
    get_status_bit,
    get_status_value,
    new_bitstring,
    parse_status_entries,
    set_status_bit,
    set_status_value,
)

V2 = "https://www.w3.org/ns/credentials/v2"
URL = "https://status.university.example/lists/1"
BIND = VerificationPolicy(require_status_issuer_binding=True)
MSG2 = [{"status": "0x0", "message": "valid"}, {"status": "0x1", "message": "revoked"},
        {"status": "0x2", "message": "suspended"}, {"status": "0x3", "message": "both"}]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _party():
    key = P256SigningKey.generate(kid="issuer")
    return key, "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())


KEY, DID = _party()


def _jws(body: dict) -> str:
    head = {"alg": "ES256", "kid": f"{DID}#0", "typ": "vc+jwt"}
    signing_input = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(body).encode())}"
    return f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}"


def _entry(index, **extra) -> dict:
    return {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
            "statusListIndex": str(index), "statusListCredential": URL, **extra}


def _list_vc(bits) -> dict:
    return {"@context": [V2], "id": URL, "issuer": DID,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": {
                "id": URL + "#list", "type": "BitstringStatusList",
                "statusPurpose": "revocation", "encodedList": encode_bitstring(bytes(bits))}}


def _check(entry: dict, bits):
    return check_credential_status({"credentialStatus": entry},
                                   resolve_status_list=lambda u: _list_vc(bits))


def _credential(entry: dict) -> str:
    return _jws({"iss": DID, "vc": {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
        "credentialSubject": {"id": "did:example:alice"}, "credentialStatus": entry}})


def _pipeline(entry: dict, bits):
    served = _jws({"iss": DID, "vc": _list_vc(bits)})
    return verify_credential(
        _credential(entry), policy=BIND,
        resolve_status_list=default_status_list_resolver(fetch=lambda u: served))


def _two_bit_list(*pairs):
    """A 2-bit-status list of 131072 entries holding the given (index, value) pairs."""
    bits = new_bitstring(131072, 2)
    for index, value in pairs:
        set_status_value(bits, index, value, 2)
    return bits


# --------------------------------------------------------------------------- #
# the four measured rows of the issue
# --------------------------------------------------------------------------- #

def test_row_a_a_set_status_at_the_wide_position_is_no_longer_accepted():
    # credential 1's value 0b11 sits at bits 2-3; bit 1 (credential 0's low bit) is clear
    bits = _two_bit_list((1, 3))
    assert get_status_bit(bytes(bits), 1) == 0
    entry = _entry(1, statusSize=2, statusMessage=MSG2)
    result = _check(entry, bits)
    assert result.revoked is True
    assert result.entries[0].status_value == 3
    with pytest.raises(CredentialRevoked):
        _pipeline(entry, bits)


def test_row_b_a_valid_status_is_no_longer_rejected():
    # credential 0 holds 0b01 (bit 1 set); credential 1 (bits 2-3) is 0b00 = valid
    bits = _two_bit_list((0, 1))
    assert get_status_bit(bytes(bits), 1) == 1
    entry = _entry(1, statusSize=2, statusMessage=MSG2)
    result = _check(entry, bits)
    assert result.revoked is False and result.entries[0].status_value == 0
    assert _pipeline(entry, bits).status.revoked is False


def test_row_c_a_position_past_the_list_is_a_range_error():
    bits = new_bitstring(131072, 2)              # 262144 bits
    for index in (131072, 131082):
        with pytest.raises(StatusListError, match="out of range"):
            _check(_entry(index, statusSize=2, statusMessage=MSG2), bits)
    # the last position is in range
    assert _check(_entry(131071, statusSize=2, statusMessage=MSG2), bits).revoked is False


@pytest.mark.parametrize("bad", [0, -1, "2", 2.5, 64, 9, None, True, False, [2], {"a": 1}])
def test_row_d_a_malformed_status_size_is_refused(bad):
    with pytest.raises(StatusListError, match="statusSize"):
        parse_status_entries({"credentialStatus": _entry(1, statusSize=bad, statusMessage=MSG2)})


# --------------------------------------------------------------------------- #
# statusMessage (REC §2.1)
# --------------------------------------------------------------------------- #

def test_status_message_is_required_when_the_size_is_above_one():
    with pytest.raises(StatusListError, match="statusMessage is required"):
        parse_status_entries({"credentialStatus": _entry(1, statusSize=2)})
    with pytest.raises(StatusListError, match="statusMessage is required"):
        parse_status_entries({"credentialStatus": _entry(1, statusSize=2, statusMessage=None)})


@pytest.mark.parametrize("bad", [
    "revoked", {}, [], [{"status": "0x1"}], [{"message": "x"}], ["0x1"],
    [{"status": 1, "message": "x"}], [{"status": "0x1", "message": 1}],
    [{"status": "1", "message": "x"}], [{"status": "0xZ", "message": "x"}],
    [{"status": "0x", "message": "x"}], [{"status": "0x4", "message": "x"}],
    [{"status": "0x1", "message": "a"}, {"status": "0x01", "message": "b"}],
    [{"status": f"0x{i}", "message": "x"} for i in range(5)],
])
def test_a_malformed_status_message_is_refused(bad):
    with pytest.raises(StatusListError, match="statusMessage"):
        parse_status_entries({"credentialStatus": _entry(1, statusSize=2, statusMessage=bad)})


def test_a_size_one_entry_needs_no_message_and_defaults_to_one():
    (entry,) = parse_status_entries({"credentialStatus": _entry(5)})
    assert entry.status_size == 1 and entry.status_message == ()
    (entry,) = parse_status_entries({"credentialStatus": _entry(5, statusSize=1)})
    assert entry.status_size == 1


def test_a_parsed_entry_carries_size_and_messages():
    (entry,) = parse_status_entries(
        {"credentialStatus": _entry(1, statusSize=2, statusMessage=MSG2)})
    assert entry.status_size == 2
    assert entry.status_message[1] == ("0x1", "revoked")


def test_a_size_one_status_message_present_is_still_validated():
    with pytest.raises(StatusListError, match="statusMessage"):
        parse_status_entries({"credentialStatus": _entry(1, statusMessage="x")})


# --------------------------------------------------------------------------- #
# reading: bit order and unchanged size-1 semantics
# --------------------------------------------------------------------------- #

def test_the_value_is_read_msb_first():
    bits = bytearray(b"\x00\x00")
    bits[0] = 0b0110_0000            # entry 1 (bits 2-3 at size 2) = 0b10, entry 0 = 0b01
    assert get_status_value(bytes(bits), 0, 2) == 0b01
    assert get_status_value(bytes(bits), 1, 2) == 0b10
    assert get_status_value(bytes(bits), 2, 2) == 0


def test_size_one_is_the_old_single_bit_read():
    bits = new_bitstring(64)
    set_status_bit(bits, 17, 1)
    for i in range(64):
        assert get_status_value(bytes(bits), i) == get_status_bit(bytes(bits), i)
    assert _check(_entry(17), bits).revoked is True
    assert _check(_entry(17, statusSize=1), bits).revoked is True
    assert _check(_entry(16), bits).revoked is False


def test_a_value_straddles_a_byte_boundary():
    bits = new_bitstring(8, 3)       # entry 2 = bits 6..8
    set_status_value(bits, 2, 0b101, 3)
    assert bytes(bits[:2]) == b"\x02\x80"
    assert get_status_value(bytes(bits), 2, 3) == 0b101


def test_a_suspension_entry_reads_a_wide_value_too():
    bits = _two_bit_list((3, 2))
    entry = _entry(3, statusSize=2, statusMessage=MSG2, statusPurpose="suspension")
    vc = _list_vc(bits)
    vc["credentialSubject"]["statusPurpose"] = "suspension"
    result = check_credential_status({"credentialStatus": entry},
                                     resolve_status_list=lambda u: vc)
    assert result.suspended is True and result.revoked is False
    assert result.entries[0].status_value == 2


def test_the_async_check_reads_the_wide_value():
    async def resolve(url):
        return _list_vc(_two_bit_list((1, 3)))
    result = asyncio.run(check_credential_status_async(
        {"credentialStatus": _entry(1, statusSize=2, statusMessage=MSG2)},
        resolve_status_list=resolve))
    assert result.revoked is True and result.entries[0].status_value == 3


def test_the_async_pipeline_refuses_the_wide_revocation():
    entry = _entry(1, statusSize=2, statusMessage=MSG2)
    served = _jws({"iss": DID, "vc": _list_vc(_two_bit_list((1, 3)))})

    async def fetch(url):
        return served
    with pytest.raises(CredentialRevoked):
        asyncio.run(verify_credential_async(
            _credential(entry), policy=BIND,
            resolve_status_list=default_status_list_resolver_async(fetch=fetch)))


# --------------------------------------------------------------------------- #
# the codec
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("args", [
    (b"\x00", 0, 0), (b"\x00", -1, 1), (b"\x00", True, 1), (b"\x00", 1.0, 1),
    (b"\x00", 0, 0.5), (b"\x00", 0, 9), (b"\x00", 4, 2),
])
def test_get_status_value_refuses_bad_arguments(args):
    bits, index, size = args
    with pytest.raises(StatusListError):
        get_status_value(bits, index, size)


@pytest.mark.parametrize("value", [-1, 4, True, 1.0, "1", None])
def test_set_status_value_refuses_a_bad_value(value):
    with pytest.raises(StatusListError):
        set_status_value(bytearray(2), 0, value, 2)


def test_set_status_value_refuses_a_position_past_the_list():
    with pytest.raises(StatusListError, match="out of range"):
        set_status_value(bytearray(1), 4, 1, 2)


def test_set_status_value_overwrites_and_leaves_neighbours():
    bits = bytearray(2)
    set_status_value(bits, 1, 3, 2)
    set_status_value(bits, 2, 3, 2)
    set_status_value(bits, 1, 0, 2)
    assert get_status_value(bytes(bits), 1, 2) == 0
    assert get_status_value(bytes(bits), 2, 2) == 3


def test_new_bitstring_sizes_the_list_by_the_status_width():
    assert len(new_bitstring(1000, 1)) == 125
    assert len(new_bitstring(1000, 2)) == 250
    assert len(new_bitstring(1000, 8)) == 1000
    assert len(new_bitstring(3, 3)) == 2
    for bad in (0, 9, True, 2.0, "2"):
        with pytest.raises(StatusListError):
            new_bitstring(10, bad)
    with pytest.raises(StatusListError):
        new_bitstring(10**9, 8)          # the packed list would pass the decode ceiling


# --------------------------------------------------------------------------- #
# the builders mint what the verifier reads (every size, first / middle / last)
# --------------------------------------------------------------------------- #

def _messages(size):
    return [{"status": hex(v), "message": f"state {v}"} for v in range(2 ** size)]


@pytest.mark.parametrize("size", range(1, 9))
def test_builders_round_trip_for_every_size(size):
    count = 4096
    positions = [0, count // 2 + 1, count - 1]
    for pos in positions:
        for value in (0, 1, 2 ** size - 1):
            bits = new_bitstring(count, size)
            set_status_value(bits, pos, value, size)
            for other in positions:             # a neighbour is untouched
                if other != pos:
                    assert get_status_value(bytes(bits), other, size) == 0
            list_vc = build_status_list_credential(id=URL, issuer=DID, bitstring=bits)
            entry = build_status_list_entry(
                status_list_credential=URL, index=pos, status_size=size,
                status_message=_messages(size) if size > 1 else None)
            assert ("statusSize" in entry) is (size > 1)
            decoded = decode_bitstring(list_vc["credentialSubject"]["encodedList"])
            result = check_credential_status(
                {"credentialStatus": entry}, resolve_status_list=lambda u: list_vc)
            assert result.entries[0].status_value == value == get_status_value(
                decoded, pos, size)
            assert result.revoked is (value != 0)
            assert result.entries[0].entry.status_size == size


def test_the_builder_requires_a_message_above_size_one_and_a_valid_size():
    with pytest.raises(StatusListError, match="statusMessage is required"):
        build_status_list_entry(status_list_credential=URL, index=1, status_size=2)
    for bad in (0, 9, True, 2.0, "2", None):
        with pytest.raises(StatusListError, match="statusSize"):
            build_status_list_entry(status_list_credential=URL, index=1, status_size=bad,
                                    status_message=MSG2)
    with pytest.raises(StatusListError, match="statusMessage"):
        build_status_list_entry(status_list_credential=URL, index=1, status_size=2,
                                status_message=[{"status": "0x9", "message": "x"}])


def test_the_default_entry_is_unchanged():
    assert build_status_list_entry(status_list_credential=URL, index=7) == {
        "type": "BitstringStatusListEntry", "statusPurpose": "revocation",
        "statusListIndex": "7", "statusListCredential": URL}
