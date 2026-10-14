"""
tests/test_status_builders_hostile.py — the status builders never mint what the
verifier refuses (#230).

v1.29.2 (#215) gave the VERIFIER one rule for a status-list index (``status_index``:
an ``int``, never a ``bool`` or ``float``, below ``MAX_STATUS_INDEX = 2**27``) and made
``statusListCredential`` / ``statusPurpose`` / the IETF ``uri`` strings. The issuer-side
builders were not updated, so they minted pointers the verifier then rejected in the
field, and in two cases raised a bare ``TypeError``::

    build_status_list_entry(index=True)          -> statusListIndex 'True'
    build_status_list_entry(index=3.7)           -> statusListIndex '3.7'
    build_status_list_entry(index=2**27)         -> past the cap
    build_status_list_entry(index="5")           -> TypeError: '<' not supported
    build_token_status_reference(index=nan)      -> {"idx": nan}
    build_status_list_credential(bytes(16 MiB + 1)) -> built, then undecodable

The codec (``get_status_bit`` ...) had the same looseness: ``get_status_bit(b"\\x40",
True)`` read the bool as index 1, and a float died with a bare ``TypeError``.

An ``int`` subclass is an ``int`` to ``isinstance``, so it passes the type check, and it
can then say a different number from the one it holds (``__int__``, ``__index__``,
``__str__``, ``__repr__``, ``__format__``, the comparisons, the arithmetic). The
builders and the codec check ONE value and use that same value; the ``_LIARS`` below
pin it through the builders, the parsers and the codec.

Every case below is asserted against the EXACT class ``StatusListError`` (it has no
subclasses), never ``TypeError`` / ``ValueError`` / ``OverflowError``; the controls show
that well-formed inputs still build and round-trip through the verifier. Helpers are
self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import array
import enum
import json
import math
import sys
from fractions import Fraction

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey
from openvc.status import (
    STATUS_INVALID,
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    build_status_list_token,
    build_token_status_reference,
    check_credential_status,
    check_token_status,
    decode_bitstring,
    decode_status_list,
    encode_bitstring,
    get_status,
    get_status_bit,
    new_bitstring,
    new_status_list,
    parse_status_entries,
    parse_token_status_ref,
    set_status,
    set_status_bit,
    verify_status_list_token,
)
from openvc.status._decompress import MAX_DECOMPRESSED_BYTES
from openvc.status._index import MAX_STATUS_INDEX, status_index

LIST_URL = "https://status.example/w3c/1"
TOKEN_URI = "https://status.example/ietf/1"
ISSUER = "did:example:issuer"
NAN = float("nan")
INF = float("inf")
HUGE = 10 ** 5000          # past sys.get_int_max_str_digits: str()/repr() raise ValueError


class _HasBytes:
    """Not a buffer, but ``bytes()`` takes it through ``__bytes__``: it built a list
    before the builders asked for a buffer."""

    def __bytes__(self) -> bytes:
        return b"\xff" * 8


def _released_view() -> memoryview:
    view = memoryview(b"\x00" * 8)
    view.release()
    return view


class _Odd(int):
    """An int whose ``str`` is not its digits, as an ``IntEnum`` member was before
    Python 3.11. The W3C entry writes ``str(index)``, so a builder that kept the
    subclass would mint ``'Odd.FIVE'`` for the verifier to refuse."""

    def __str__(self) -> str:
        return "Odd.FIVE"

    __repr__ = __str__


class _Slot(enum.IntEnum):
    FIVE = 5


def _hostile(*_args, **_kwargs):
    raise RuntimeError("a hostile dunder was called")


_COMPARE = ("__lt__", "__le__", "__gt__", "__ge__")
_ARITH = (
    "__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__", "__floordiv__",
    "__rfloordiv__", "__mod__", "__rmod__", "__divmod__", "__rdivmod__", "__lshift__",
    "__rlshift__", "__rshift__", "__rrshift__", "__and__", "__rand__", "__or__", "__ror__",
)
_LIE = {                       # what each dunder says in place of the integer it holds
    "__int__": lambda self: -1,
    "__index__": lambda self: -1,
    "__str__": lambda self: "-1",
    "__repr__": lambda self: "-1",
    "__format__": lambda self, spec: "-1",
}
# comparisons that are False whatever the operands (`v < 0` and `v >= 2**27` both pass,
# `0 <= v` fails) and arithmetic that answers 10**9
_LIE.update({name: (lambda self, other: False) for name in _COMPARE})
_LIE.update({name: (lambda self, other: 10 ** 9) for name in _ARITH})


def _int_subclass(name: str, members) -> type:
    return type(name, (int,), dict(members))


def _lying(*names: str) -> type:
    return _int_subclass("Lies_" + "_".join(n.strip("_") for n in names),
                         {n: _LIE[n] for n in names})


# An int subclass per way of saying the wrong thing, then one that does all of it, and
# one whose every dunder raises: whatever the builder or the codec checks, it must be
# the integer the object holds, and nothing may call back into the object.
_LIARS = [
    pytest.param(_lying("__int__"), id="__int__"),
    pytest.param(_lying("__index__"), id="__index__"),
    pytest.param(_lying("__str__"), id="__str__"),
    pytest.param(_lying("__repr__"), id="__repr__"),
    pytest.param(_lying("__format__"), id="__format__"),
    pytest.param(_lying(*_COMPARE), id="comparisons"),
    pytest.param(_lying(*_ARITH), id="arithmetic"),
    pytest.param(_lying(*_LIE), id="all-lies"),
    pytest.param(
        _int_subclass("Raises", {name: _hostile for name in _LIE}), id="all-raise"),
]


class _EqLiar(int):
    """Equal to anything and hashed as 1, so `bits in {1, 2, 4, 8}` holds for any value."""

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return 1


class _BufferRaises:
    """Python 3.12+ (PEP 688) lets a class export a buffer; this one's export raises
    something other than TypeError/ValueError. Before 3.12 it is simply not a buffer."""

    def __buffer__(self, flags: int) -> memoryview:
        raise RuntimeError("boom")


def _refused(call) -> StatusListError:
    """Run *call*; it must raise exactly StatusListError (an OpenvcError), nothing else."""
    with pytest.raises(StatusListError) as caught:
        call()
    assert type(caught.value) is StatusListError
    assert isinstance(caught.value, OpenvcError)
    return caught.value


# --------------------------------------------------------------------------- #
# hostile values (id, value). Explicit ids: pytest cannot str() HUGE for a test id.
# --------------------------------------------------------------------------- #

BAD_INDEXES = [
    pytest.param(True, id="True"),
    pytest.param(False, id="False"),
    pytest.param(3.7, id="3.7"),
    pytest.param(5.0, id="5.0"),
    pytest.param(NAN, id="nan"),
    pytest.param(INF, id="inf"),
    pytest.param(-INF, id="-inf"),
    pytest.param(MAX_STATUS_INDEX, id="2**27"),
    pytest.param(MAX_STATUS_INDEX + 1, id="2**27+1"),
    pytest.param(HUGE, id="10**5000"),
    pytest.param(-1, id="-1"),
    pytest.param(-HUGE, id="-10**5000"),
    pytest.param("5", id="str-5"),
    pytest.param("", id="empty-str"),
    pytest.param(None, id="None"),
    pytest.param([1], id="list"),
    pytest.param({"i": 1}, id="dict"),
    pytest.param(b"5", id="bytes"),
]

BAD_STRINGS = [
    pytest.param(None, id="None"),
    pytest.param(5, id="int"),
    pytest.param(0, id="0"),               # falsy: the verifier skips a falsy list purpose
    pytest.param(False, id="False"),
    pytest.param(True, id="bool"),
    pytest.param(3.5, id="float"),
    pytest.param("", id="empty"),
    pytest.param(["https://s/1"], id="list"),
    pytest.param({"id": "https://s/1"}, id="dict"),
    pytest.param(b"https://s/1", id="bytes"),
]

BAD_SIZES = [
    pytest.param(True, id="True"),
    pytest.param(2.5, id="2.5"),
    pytest.param(8.0, id="8.0"),
    pytest.param(Fraction(8, 1), id="Fraction-8"),     # (8 + 7) // 8 worked by arithmetic
    pytest.param(Fraction(3, 2), id="Fraction-3/2"),
    pytest.param(NAN, id="nan"),
    pytest.param(INF, id="inf"),
    pytest.param("8", id="str"),
    pytest.param(None, id="None"),
    pytest.param(-1, id="-1"),
    pytest.param(MAX_STATUS_INDEX + 1, id="2**27+1"),
    pytest.param(HUGE, id="10**5000"),
    pytest.param(-HUGE, id="-10**5000"),
]


# --------------------------------------------------------------------------- #
# build_status_list_entry — the gap table, row by row
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("index", BAD_INDEXES)
def test_entry_refuses_an_index_the_verifier_would(index):
    _refused(lambda: build_status_list_entry(status_list_credential=LIST_URL, index=index))


@pytest.mark.parametrize("purpose", BAD_STRINGS)
def test_entry_refuses_a_non_string_purpose(purpose):
    _refused(lambda: build_status_list_entry(
        status_list_credential=LIST_URL, index=1, status_purpose=purpose))


@pytest.mark.parametrize("url", BAD_STRINGS)
def test_entry_refuses_a_non_string_status_list_credential(url):
    _refused(lambda: build_status_list_entry(status_list_credential=url, index=1))


def test_entry_string_index_is_a_typed_error_not_a_bare_typeerror():
    # before: `"5" < 0` -> TypeError: '<' not supported between 'str' and 'int'
    err = _refused(lambda: build_status_list_entry(
        status_list_credential=LIST_URL, index="5"))
    assert "integer" in str(err)


def test_entry_error_text_never_renders_a_huge_int():
    # str()/repr() of a 5000-digit int is a bare ValueError; brief() keeps it typed
    err = _refused(lambda: build_status_list_entry(
        status_list_credential=LIST_URL, index=HUGE))
    assert "bit integer" in str(err)
    assert "0000000000" not in str(err)


# --------------------------------------------------------------------------- #
# build_token_status_reference
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("index", BAD_INDEXES)
def test_token_reference_refuses_an_index_the_verifier_would(index):
    _refused(lambda: build_token_status_reference(uri=TOKEN_URI, index=index))


@pytest.mark.parametrize("uri", BAD_STRINGS)
def test_token_reference_refuses_a_non_string_uri(uri):
    _refused(lambda: build_token_status_reference(uri=uri, index=1))


def test_token_reference_refuses_a_string_index_the_draft_makes_an_integer():
    # the W3C entry spells the index as a string, but the IETF idx is a JSON integer
    _refused(lambda: build_token_status_reference(uri=TOKEN_URI, index="5"))


# --------------------------------------------------------------------------- #
# build_status_list_credential / build_status_list_token — the 16 MiB cap
# --------------------------------------------------------------------------- #

def test_list_credential_refuses_a_bitstring_past_the_decompression_cap():
    err = _refused(lambda: build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=bytes(MAX_DECOMPRESSED_BYTES + 1)))
    assert str(MAX_DECOMPRESSED_BYTES) in str(err)


def test_list_credential_cap_is_the_verifiers_own():
    # the premise: a list one byte past the cap is one openvc would refuse to inflate,
    # which is why the builder must not mint it
    _refused(lambda: decode_bitstring(encode_bitstring(bytes(MAX_DECOMPRESSED_BYTES + 1))))


def test_list_cap_counts_bytes_not_items():
    # array("H") holds 2 bytes per item: len() is half the byte count, and a check on
    # len() would let this 16 MiB + 2 B list through
    wide = array.array("H", bytes(MAX_DECOMPRESSED_BYTES + 2))
    assert len(wide) < MAX_DECOMPRESSED_BYTES
    err = _refused(lambda: build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=wide))
    assert str(MAX_DECOMPRESSED_BYTES + 2) in str(err)


@pytest.mark.parametrize("bitstring", [
    pytest.param(1024, id="int"),          # bytes(1024) would silently be a zeroed list
    pytest.param(HUGE, id="huge-int"),     # ... and bytes(10**5000) an OverflowError
    pytest.param("0000", id="str"),
    pytest.param(None, id="None"),
    pytest.param([0, 1], id="list"),
    pytest.param((0, 1), id="tuple"),          # bytes() took each of these as a list
    pytest.param(range(2), id="range"),
    pytest.param((n for n in (0, 1)), id="generator"),
    pytest.param({0: 1}, id="dict"),
    pytest.param(_HasBytes(), id="__bytes__"),
    pytest.param(_released_view(), id="released-memoryview"),
])
def test_list_credential_refuses_a_non_bytes_bitstring(bitstring):
    _refused(lambda: build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=bitstring))


@pytest.mark.parametrize("purpose", BAD_STRINGS)
def test_list_credential_refuses_a_non_string_purpose(purpose):
    _refused(lambda: build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=bytes(8), status_purpose=purpose))


@pytest.mark.parametrize("list_id", BAD_STRINGS)
def test_list_credential_refuses_a_non_string_id(list_id):
    _refused(lambda: build_status_list_credential(
        id=list_id, issuer=ISSUER, bitstring=bytes(8)))


def test_list_token_refuses_a_list_past_the_decompression_cap():
    sk = Ed25519SigningKey.generate(kid="k")
    err = _refused(lambda: build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=bytes(MAX_DECOMPRESSED_BYTES + 1)))
    assert str(MAX_DECOMPRESSED_BYTES) in str(err)


@pytest.mark.parametrize("status_list", [
    pytest.param(1024, id="int"),
    pytest.param(HUGE, id="huge-int"),
    pytest.param("0000", id="str"),
    pytest.param(None, id="None"),
    pytest.param([0, 1], id="list"),
    pytest.param((0, 1), id="tuple"),          # bytes() took each of these as a list
    pytest.param(range(2), id="range"),
    pytest.param((n for n in (0, 1)), id="generator"),
    pytest.param({0: 1}, id="dict"),
    pytest.param(_HasBytes(), id="__bytes__"),
    pytest.param(_released_view(), id="released-memoryview"),
])
def test_list_token_refuses_a_non_bytes_list(status_list):
    sk = Ed25519SigningKey.generate(kid="k")
    _refused(lambda: build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=status_list))


@pytest.mark.parametrize("uri", BAD_STRINGS)
def test_list_token_refuses_a_non_string_uri(uri):
    sk = Ed25519SigningKey.generate(kid="k")
    _refused(lambda: build_status_list_token(
        signing_key=sk, uri=uri, status_list=bytes(8)))


@pytest.mark.parametrize("bits", [
    pytest.param(True, id="True"),         # `True in {1, 2, 4, 8}` holds
    pytest.param(1.0, id="1.0"),           # ... and so does `1.0 in {...}`
    pytest.param(Fraction(1, 1), id="Fraction-1"),     # ... and `Fraction(1) in {...}`
    pytest.param([1], id="list"),          # unhashable: a bare TypeError from `in`
    pytest.param({"b": 1}, id="dict"),
    pytest.param("1", id="str"),
    pytest.param(None, id="None"),
    pytest.param(3, id="3"),
    pytest.param(0, id="0"),
])
def test_bits_must_be_one_of_1_2_4_8(bits):
    sk = Ed25519SigningKey.generate(kid="k")
    _refused(lambda: build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=bytes(8), bits=bits))
    _refused(lambda: new_status_list(8, bits=bits))
    _refused(lambda: get_status(bytes(8), 0, bits=bits))
    _refused(lambda: set_status(bytearray(8), 0, 1, bits=bits))


# --------------------------------------------------------------------------- #
# the codec: new_bitstring / new_status_list / get_* / set_*
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("size", BAD_SIZES)
def test_new_bitstring_refuses_a_bad_size(size):
    _refused(lambda: new_bitstring(size))


@pytest.mark.parametrize("size", BAD_SIZES)
def test_new_status_list_refuses_a_bad_size(size):
    _refused(lambda: new_status_list(size))


@pytest.mark.parametrize("bits", [1, 2, 4, 8])
def test_new_status_list_cap_is_the_packed_length_not_the_status_count(bits):
    # 16 MiB holds 2**27 one-bit statuses but only 2**24 eight-bit ones: a list the
    # token builder would refuse is not allocated in the first place
    most = MAX_DECOMPRESSED_BYTES * (8 // bits)
    assert len(new_status_list(most, bits=bits)) == MAX_DECOMPRESSED_BYTES
    _refused(lambda: new_status_list(most + 1, bits=bits))


def test_new_status_list_refuses_what_the_issue_text_would_allow_at_8_bits():
    # 2**27 statuses at 8 bits is 128 MiB: past what the verifier inflates
    _refused(lambda: new_status_list(MAX_STATUS_INDEX, bits=8))


@pytest.mark.parametrize("index", [
    pytest.param(True, id="True"),
    pytest.param(False, id="False"),
    pytest.param(2.5, id="2.5"),
    pytest.param(1.0, id="1.0"),
    pytest.param(NAN, id="nan"),
    pytest.param(INF, id="inf"),
    pytest.param("1", id="str"),
    pytest.param(None, id="None"),
    pytest.param([1], id="list"),
    pytest.param(-1, id="-1"),
    pytest.param(8, id="past-the-data"),
    pytest.param(HUGE, id="10**5000"),
    pytest.param(-HUGE, id="-10**5000"),
])
def test_bitstring_codec_refuses_a_bad_index(index):
    bits = bytearray(b"\x40")
    _refused(lambda: get_status_bit(bytes(bits), index))
    _refused(lambda: set_status_bit(bits, index, 1))
    assert bits == bytearray(b"\x40")                  # a refused write changed nothing


@pytest.mark.parametrize("bits_per", [1, 2, 4, 8])
@pytest.mark.parametrize("index", [
    pytest.param(True, id="True"),
    pytest.param(2.5, id="2.5"),
    pytest.param(NAN, id="nan"),
    pytest.param("1", id="str"),
    pytest.param(None, id="None"),
    pytest.param(-1, id="-1"),
    pytest.param(32, id="past-the-data"),         # 4 bytes hold at most 32 statuses
    pytest.param(HUGE, id="10**5000"),
])
def test_token_codec_refuses_a_bad_index(bits_per, index):
    data = bytearray(4)                           # so index 1 / 2.5 are in range if misread
    _refused(lambda: get_status(bytes(data), index, bits=bits_per))
    _refused(lambda: set_status(data, index, 1, bits=bits_per))
    assert data == bytearray(4)


@pytest.mark.parametrize("value", [
    pytest.param(2.5, id="float"),
    pytest.param("1", id="str"),
    pytest.param(None, id="None"),
    pytest.param(4, id="too-wide"),
    pytest.param(-1, id="negative"),
    pytest.param(HUGE, id="huge"),
])
def test_set_status_refuses_a_bad_value(value):
    data = bytearray(4)
    _refused(lambda: set_status(data, 0, value, bits=2))
    assert data == bytearray(4)


def test_a_bool_is_no_longer_read_as_index_1():
    # the bug: get_status_bit(b"\x40", True) returned 1, the bit of index 1
    assert get_status_bit(b"\x40", 1) == 1
    _refused(lambda: get_status_bit(b"\x40", True))
    _refused(lambda: get_status(b"\x02", True, bits=1))


def test_codec_error_texts_are_unchanged_for_ordinary_indexes():
    # existing callers (and tests) match on these
    assert "non-negative" in str(_refused(lambda: get_status_bit(b"\x00", -1)))
    assert "out of range for a 8-bit list" in str(_refused(lambda: get_status_bit(b"\x00", 8)))
    assert "out of range for a 8-status list" in str(
        _refused(lambda: get_status(b"\x00", 8, bits=1)))


# --------------------------------------------------------------------------- #
# an int subclass: check one value, use that value
# --------------------------------------------------------------------------- #

ENTRY_TYPE = "BitstringStatusListEntry"


def _w3c_pointer(index) -> dict:
    return {"type": ENTRY_TYPE, "statusPurpose": "revocation",
            "statusListIndex": index, "statusListCredential": LIST_URL}


@pytest.mark.parametrize("liar", _LIARS)
@pytest.mark.parametrize("capped", [True, False])
def test_status_index_returns_the_integer_it_checked(liar, capped):
    value = status_index(liar(5), field="i", allow_string=False, capped=capped)
    assert type(value) is int and value == 5


@pytest.mark.parametrize("liar", _LIARS)
def test_builders_emit_the_integer_they_checked(liar):
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=liar(5))
    assert entry["statusListIndex"] == "5"
    assert [e.index for e in parse_status_entries({"credentialStatus": entry})] == [5]
    ref = build_token_status_reference(uri=TOKEN_URI, index=liar(5))
    idx = ref["status"]["status_list"]["idx"]
    assert type(idx) is int and idx == 5
    assert json.loads(json.dumps(ref))["status"]["status_list"]["idx"] == 5
    parsed = parse_token_status_ref(ref)
    assert parsed is not None and parsed.index == 5


@pytest.mark.parametrize("liar", _LIARS)
def test_parsers_read_the_integer_they_checked(liar):
    # a pre-parsed document can carry an int subclass (JSON parsing never yields one)
    entries = parse_status_entries({"credentialStatus": _w3c_pointer(liar(5))})
    assert [type(e.index) for e in entries] == [int] and entries[0].index == 5
    token_claims = {"status": {"status_list": {"idx": liar(5), "uri": TOKEN_URI}}}
    parsed = parse_token_status_ref(token_claims)
    assert parsed is not None and type(parsed.index) is int and parsed.index == 5


@pytest.mark.parametrize("liar", _LIARS)
def test_parsers_refuse_a_lying_subclass_by_its_integer(liar):
    for bad in (-1, MAX_STATUS_INDEX):
        _refused(lambda: parse_status_entries({"credentialStatus": _w3c_pointer(liar(bad))}))
        _refused(lambda: parse_token_status_ref(
            {"status": {"status_list": {"idx": liar(bad), "uri": TOKEN_URI}}}))


@pytest.mark.parametrize("liar", _LIARS)
def test_builders_refuse_a_lying_subclass_by_its_integer(liar):
    # the lie would pass `< 0` / `>= 2**27` (comparisons), or mint the wrong digits
    # (__int__ -> a valid number, __str__ -> '5'): the integer it holds is what is checked
    for bad in (-1, -2, MAX_STATUS_INDEX, MAX_STATUS_INDEX + 1):
        _refused(lambda: build_status_list_entry(
            status_list_credential=LIST_URL, index=liar(bad)))
        _refused(lambda: build_token_status_reference(uri=TOKEN_URI, index=liar(bad)))


@pytest.mark.parametrize("liar", _LIARS)
def test_codec_addresses_the_integer_it_checked(liar):
    # two bytes: if the object's lie (-1) were used, index 5 would read data[-1]
    assert get_status_bit(b"\x04\x00", liar(5)) == 1
    assert get_status(bytes([0x20, 0x00]), liar(5), bits=1) == 1
    assert get_status(bytes([0x00, 0x00]), liar(5), bits=1) == 0
    flags = bytearray(2)
    set_status_bit(flags, liar(5), 1)
    assert flags == bytearray(b"\x04\x00")
    statuses = bytearray(2)
    set_status(statuses, liar(5), 1, bits=1)
    assert statuses == bytearray([0x20, 0x00])
    wide = bytearray(4)                              # 2 bits each: index 5 is byte 1
    set_status(wide, liar(5), 3, bits=2)
    assert wide == bytearray([0x00, 0x0C, 0x00, 0x00])


@pytest.mark.parametrize("liar", _LIARS)
def test_codec_refuses_a_lying_subclass_by_its_integer(liar):
    data = bytearray(2)
    for bad in (-1, 16, 17):                         # negative, and past the 16-bit list
        _refused(lambda: get_status_bit(bytes(data), liar(bad)))
        _refused(lambda: set_status_bit(data, liar(bad), 1))
        _refused(lambda: get_status(bytes(data), liar(bad), bits=1))
        _refused(lambda: set_status(data, liar(bad), 1, bits=1))
    assert data == bytearray(2)


@pytest.mark.parametrize("liar", _LIARS)
def test_set_status_writes_the_value_it_checked(liar):
    data = bytearray(2)
    set_status(data, 1, liar(2), bits=2)
    assert data == bytearray([0x08, 0x00])           # 2 << (1 * 2), not whatever the lie says
    _refused(lambda: set_status(data, 0, liar(4), bits=2))      # does not fit in 2 bits
    _refused(lambda: set_status(data, 0, liar(-1), bits=2))
    assert data == bytearray([0x08, 0x00])


@pytest.mark.parametrize("liar", _LIARS)
def test_sizes_and_bits_use_the_integer_they_checked(liar):
    assert len(new_bitstring(liar(64))) == 8
    assert len(new_status_list(liar(64), bits=liar(2))) == 16
    _refused(lambda: new_bitstring(liar(-1)))
    _refused(lambda: new_status_list(liar(MAX_STATUS_INDEX + 1)))
    _refused(lambda: new_status_list(8, bits=liar(3)))
    data = bytearray(4)
    set_status(data, 1, 3, bits=liar(2))
    assert get_status(bytes(data), 1, bits=liar(2)) == 3
    sk = Ed25519SigningKey.generate(kid="did:key:zStatus#zStatus")
    token = build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=bytes(data), bits=liar(2))
    claims = verify_status_list_token(
        token, public_key_jwk=sk.public_jwk(), expected_uri=TOKEN_URI)
    assert claims["status_list"]["bits"] == 2 and type(claims["status_list"]["bits"]) is int


def test_bits_that_claims_to_equal_a_valid_width_is_still_refused():
    # `3 in {1, 2, 4, 8}` consults the object's own __eq__ and __hash__
    sk = Ed25519SigningKey.generate(kid="k")
    _refused(lambda: new_status_list(8, bits=_EqLiar(3)))
    _refused(lambda: get_status(bytes(8), 0, bits=_EqLiar(3)))
    _refused(lambda: set_status(bytearray(8), 0, 1, bits=_EqLiar(3)))
    _refused(lambda: build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=bytes(8), bits=_EqLiar(3)))


# --------------------------------------------------------------------------- #
# the order the codec reports problems in
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("index", "value", "needle"), [
    pytest.param(32, -1, "status value -1 does not fit in 1 bit(s)", id="value-before-range"),
    pytest.param(32, 2.5, "status value 2.5 does not fit in 1 bit(s)", id="float-value"),
    pytest.param(32, "x", "status value 'x' does not fit in 1 bit(s)", id="str-value"),
    pytest.param(-1, -1, "status index must be non-negative, got -1", id="negative-first"),
    pytest.param(-1, "x", "status index must be non-negative, got -1", id="negative-str-value"),
    pytest.param(99, 1, "status index 99 out of range for a 32-status list", id="range"),
    pytest.param(0, 2, "status value 2 does not fit in 1 bit(s)", id="value"),
])
def test_set_status_reports_the_same_problem_first_as_before(index, value, needle):
    # bits, then a bad / negative index, then the value, then an index past the data:
    # the order v1.32.1 reported them in. Each message is the one it had.
    err = _refused(lambda: set_status(bytearray(4), index, value, bits=1))
    assert str(err) == needle


def test_set_status_bit_still_reads_its_value_for_truthiness():
    # unlike set_status, it never insisted on an int; only its INDEX is held to the rule
    for truthy in (1, True, 2, "x", 1.5, [0]):
        bits = bytearray(1)
        set_status_bit(bits, 3, truthy)
        assert bits == bytearray(b"\x10")
    bits = bytearray(b"\x10")
    for falsy in (0, False, 0.0, "", None):
        set_status_bit(bits, 3, falsy)
        assert bits == bytearray(1)
        set_status_bit(bits, 3, 1)
    assert bits == bytearray(b"\x10")


# --------------------------------------------------------------------------- #
# controls: well-formed input still builds and the verifier accepts it
# --------------------------------------------------------------------------- #

BOUNDARY_INDEXES = [0, 1, 7, 8, MAX_STATUS_INDEX - 1]


@pytest.mark.parametrize("index", BOUNDARY_INDEXES)
def test_entry_roundtrips_through_the_verifier(index):
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=index)
    assert entry["statusListIndex"] == str(index)       # the spec's base-10 string
    assert entry["statusPurpose"] == "revocation"
    parsed = parse_status_entries({"credentialStatus": entry})
    assert [e.index for e in parsed] == [index]
    assert parsed[0].status_list_credential == LIST_URL


@pytest.mark.parametrize("index", BOUNDARY_INDEXES)
def test_token_reference_roundtrips_through_the_verifier(index):
    ref = build_token_status_reference(uri=TOKEN_URI, index=index)
    assert ref["status"]["status_list"]["idx"] == index
    assert type(ref["status"]["status_list"]["idx"]) is int
    parsed = parse_token_status_ref(ref)
    assert parsed is not None and parsed.index == index and parsed.uri == TOKEN_URI


def test_entry_keeps_purpose_and_id():
    entry = build_status_list_entry(
        status_list_credential=LIST_URL, index=3, status_purpose="suspension",
        id=f"{LIST_URL}#3")
    assert entry["statusPurpose"] == "suspension" and entry["id"] == f"{LIST_URL}#3"
    assert parse_status_entries({"credentialStatus": entry})[0].purpose == "suspension"


def test_list_credential_accepts_bytes_and_bytearray_and_does_not_mutate():
    bits = new_bitstring(64)
    set_status_bit(bits, 5, 1)
    snapshot = bytes(bits)
    as_bytearray = build_status_list_credential(id=LIST_URL, issuer=ISSUER, bitstring=bits)
    as_bytes = build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=bytes(bits))
    assert as_bytearray == as_bytes and bytes(bits) == snapshot
    assert decode_bitstring(as_bytes["credentialSubject"]["encodedList"]) == snapshot


def _interleaved(raw: bytes) -> bytes:
    """*raw* with a 0xFF between its bytes: `memoryview(...)[::2]` shows exactly *raw*,
    over memory that holds twice as much."""
    return b"".join(bytes([byte, 0xFF]) for byte in raw)


def _two_d(raw: bytes) -> memoryview:
    return memoryview(raw).cast("B", shape=[len(raw) // 2, 2])


BYTES_LIKE = [
    pytest.param(memoryview, id="memoryview"),
    pytest.param(lambda raw: memoryview(raw)[::1], id="contiguous-slice"),
    pytest.param(lambda raw: array.array("B", raw), id="array-B"),
    # non-contiguous: the list is the bytes the view exposes, not the memory behind it
    pytest.param(lambda raw: memoryview(_interleaved(raw))[::2], id="strided-memoryview"),
    pytest.param(lambda raw: memoryview(raw[::-1])[::-1], id="reversed-memoryview"),
    pytest.param(_two_d, id="2-D-memoryview"),
]


@pytest.mark.parametrize("wrap", BYTES_LIKE)
def test_list_credential_accepts_any_bytes_like_list(wrap):
    # main built these (bytes(memoryview) works), and the result verifies: the
    # builder refuses an int or a str, not a buffer
    bits = new_bitstring(64)
    set_status_bit(bits, 3, 1)
    status_vc = build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=wrap(bytes(bits)))
    assert decode_bitstring(status_vc["credentialSubject"]["encodedList"]) == bytes(bits)
    revoked = {"credentialStatus": build_status_list_entry(
        status_list_credential=LIST_URL, index=3)}
    result = check_credential_status(revoked, resolve_status_list=lambda _u: status_vc)
    assert result is not None and result.revoked


@pytest.mark.parametrize("wrap", BYTES_LIKE)
def test_list_token_accepts_any_bytes_like_list(wrap):
    sk = Ed25519SigningKey.generate(kid="did:key:zStatus#zStatus")
    data = new_status_list(16, bits=2)
    set_status(data, 3, STATUS_INVALID, bits=2)
    token = build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=wrap(bytes(data)), bits=2)
    claims = verify_status_list_token(
        token, public_key_jwk=sk.public_jwk(), expected_uri=TOKEN_URI)
    reference = build_token_status_reference(uri=TOKEN_URI, index=3)
    result = check_token_status(reference, resolve_status_list_token=lambda _u: claims)
    assert result is not None and result.revoked


def test_the_non_contiguous_params_really_are_non_contiguous():
    # guards the fixtures above: a "strided" case that is contiguous pins nothing
    raw = bytes(range(8))
    for wrap in (lambda r: memoryview(_interleaved(r))[::2], lambda r: memoryview(r[::-1])[::-1]):
        view = wrap(raw)
        assert not view.contiguous and view.tobytes() == raw
    assert memoryview(raw)[::1].contiguous
    assert _two_d(raw).ndim == 2 and _two_d(raw).tobytes() == raw


def test_a_non_contiguous_view_is_the_bytes_it_exposes():
    raw = bytearray(b"\xb9\xa3")
    view = memoryview(_interleaved(bytes(raw)))[::2]
    assert not view.contiguous
    vc = build_status_list_credential(id=LIST_URL, issuer=ISSUER, bitstring=view)
    assert decode_bitstring(vc["credentialSubject"]["encodedList"]) == bytes(raw)
    sk = Ed25519SigningKey.generate(kid="k")
    token = build_status_list_token(signing_key=sk, uri=TOKEN_URI, status_list=view)
    claims = verify_status_list_token(
        token, public_key_jwk=sk.public_jwk(), expected_uri=TOKEN_URI)
    assert decode_status_list(claims["status_list"]["lst"]) == bytes(raw)


def test_the_cap_counts_the_bytes_a_strided_view_exposes():
    # 32 MiB of memory behind a view that shows 16 MiB + 1: over the cap
    view = memoryview(bytes(2 * (MAX_DECOMPRESSED_BYTES + 1)))[::2]
    assert view.nbytes == MAX_DECOMPRESSED_BYTES + 1 and not view.contiguous
    _refused(lambda: build_status_list_credential(id=LIST_URL, issuer=ISSUER, bitstring=view))


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 688 __buffer__ needs 3.12+")
def test_a_buffer_export_that_raises_is_a_typed_error():
    # a bare RuntimeError used to escape; the message names what fired
    sk = Ed25519SigningKey.generate(kid="k")
    err = _refused(lambda: build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=_BufferRaises()))
    assert "RuntimeError" in str(err)
    err = _refused(lambda: build_status_list_token(
        signing_key=sk, uri=TOKEN_URI, status_list=_BufferRaises()))
    assert "RuntimeError" in str(err)


def test_a_class_that_would_export_a_buffer_is_typed_on_every_version():
    # before 3.12 it is not a buffer at all (TypeError); from 3.12 its export raises
    _refused(lambda: build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=_BufferRaises()))


@pytest.mark.parametrize("index", [
    pytest.param(_Odd(5), id="int-subclass"),
    pytest.param(_Slot.FIVE, id="IntEnum"),
])
def test_an_int_subclass_index_is_emitted_as_its_digits(index):
    assert type(status_index(index, field="i", allow_string=False)) is int
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=index)
    assert entry["statusListIndex"] == "5"
    assert [e.index for e in parse_status_entries({"credentialStatus": entry})] == [5]
    ref = build_token_status_reference(uri=TOKEN_URI, index=index)
    assert type(ref["status"]["status_list"]["idx"]) is int
    parsed = parse_token_status_ref(ref)
    assert parsed is not None and parsed.index == 5
    assert get_status_bit(b"\x04", index) == 1             # the codec takes it too


def test_codec_addresses_past_the_ceiling_when_the_data_is_that_long():
    # `locate_status` skips the 2**27 ceiling (capped=False): the data length bounds a
    # codec index, so an in-memory list past 16 MiB stays addressable. Capping it
    # would make these raise.
    data = bytearray(MAX_DECOMPRESSED_BYTES + 1)
    set_status_bit(data, MAX_STATUS_INDEX, 1)
    assert get_status_bit(data, MAX_STATUS_INDEX) == 1
    assert data[MAX_DECOMPRESSED_BYTES] == 0x80
    set_status(data, MAX_STATUS_INDEX, 1, bits=1)           # LSB-first: bit 0 of byte 2**24
    assert get_status(data, MAX_STATUS_INDEX, bits=1) == 1
    set_status(data, MAX_DECOMPRESSED_BYTES, 3, bits=8)     # one status per byte
    assert get_status(data, MAX_DECOMPRESSED_BYTES, bits=8) == 3
    # ... and the data still bounds it
    _refused(lambda: get_status_bit(data, MAX_STATUS_INDEX + 8))
    _refused(lambda: get_status(data, MAX_DECOMPRESSED_BYTES + 1, bits=8))


def test_codec_still_serves_a_value_given_as_bool():
    data = new_status_list(4, bits=1)
    set_status(data, 2, True)                 # a flag-like value; only the INDEX is a bool trap
    assert get_status(bytes(data), 2) == 1


# --------------------------------------------------------------------------- #
# round trip at every list size up to the cap
# --------------------------------------------------------------------------- #

W3C_SIZES = [1, 7, 8, 9, 131072, MAX_STATUS_INDEX]


@pytest.mark.parametrize("size", W3C_SIZES)
def test_bitstring_roundtrip_up_to_the_cap(size):
    bits = new_bitstring(size)
    assert len(bits) == (size + 7) // 8
    last = size - 1
    set_status_bit(bits, last, 1)
    status_vc = build_status_list_credential(id=LIST_URL, issuer=ISSUER, bitstring=bits)

    revoked = {"credentialStatus": build_status_list_entry(
        status_list_credential=LIST_URL, index=last)}
    result = check_credential_status(revoked, resolve_status_list=lambda _u: status_vc)
    assert result is not None and result.revoked
    if last > 0:
        clear = {"credentialStatus": build_status_list_entry(
            status_list_credential=LIST_URL, index=last - 1)}
        result = check_credential_status(clear, resolve_status_list=lambda _u: status_vc)
        assert result is not None and not result.revoked


def test_bitstring_one_past_the_cap_is_refused_at_allocation():
    _refused(lambda: new_bitstring(MAX_STATUS_INDEX + 1))


@pytest.mark.parametrize("bits", [1, 2, 4, 8])
def test_token_roundtrip_up_to_the_cap(bits):
    sk = Ed25519SigningKey.generate(kid="did:key:zStatus#zStatus")
    most = MAX_DECOMPRESSED_BYTES * (8 // bits)
    for size in (1, 9, most):
        data = new_status_list(size, bits=bits)
        last = size - 1
        set_status(data, last, STATUS_INVALID, bits=bits)      # 0x01 = revoked at any width
        token = build_status_list_token(
            signing_key=sk, uri=TOKEN_URI, status_list=data, bits=bits)
        claims = verify_status_list_token(
            token, public_key_jwk=sk.public_jwk(), expected_uri=TOKEN_URI)
        reference = {**build_token_status_reference(uri=TOKEN_URI, index=last)}
        result = check_token_status(reference, resolve_status_list_token=lambda _u: claims)
        assert result is not None and result.revoked and result.status == 1
        if last > 0:
            before = {**build_token_status_reference(uri=TOKEN_URI, index=last - 1)}
            result = check_token_status(before, resolve_status_list_token=lambda _u: claims)
            assert result is not None and not result.revoked


# --------------------------------------------------------------------------- #
# the property: whatever a builder accepts, the verifier accepts
# --------------------------------------------------------------------------- #

_any_index = st.one_of(
    st.integers(),
    st.integers(min_value=MAX_STATUS_INDEX - 3, max_value=MAX_STATUS_INDEX + 3),
    st.sampled_from([0, 1, 7, 8, MAX_STATUS_INDEX - 1, MAX_STATUS_INDEX, HUGE, -HUGE]),
    st.integers(min_value=-2, max_value=40).map(_Odd),      # an int subclass is an int
    st.integers(min_value=-2, max_value=40).map(_lying("__int__", "__str__")),
    st.integers(min_value=-2, max_value=40).map(_lying(*_COMPARE)),
    st.booleans(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=12),
    st.none(),
    st.lists(st.integers(), max_size=2),
)


@settings(max_examples=300, deadline=None)
@given(index=_any_index)
def test_property_w3c_builder_accepts_only_what_the_verifier_reads_back(index):
    try:
        entry = build_status_list_entry(status_list_credential=LIST_URL, index=index)
    except StatusListError:
        return
    # accepted, so it must be an in-range int that parses back to the same index
    assert isinstance(index, int) and not isinstance(index, bool)
    held = int.__index__(index)          # the integer it holds; int(index) may be a lie
    assert 0 <= held < MAX_STATUS_INDEX
    assert entry["statusListIndex"] == str(held)
    parsed = parse_status_entries({"credentialStatus": entry})
    assert [e.index for e in parsed] == [held]


@settings(max_examples=300, deadline=None)
@given(index=_any_index)
def test_property_ietf_builder_accepts_only_what_the_verifier_reads_back(index):
    try:
        ref = build_token_status_reference(uri=TOKEN_URI, index=index)
    except StatusListError:
        return
    assert isinstance(index, int) and not isinstance(index, bool)
    held = int.__index__(index)
    assert 0 <= held < MAX_STATUS_INDEX
    assert type(ref["status"]["status_list"]["idx"]) is int
    assert ref["status"]["status_list"]["idx"] == held
    parsed = parse_token_status_ref(ref)
    assert parsed is not None and parsed.index == held
    assert not (isinstance(index, float) and math.isnan(index))


@settings(max_examples=200, deadline=None)
@given(index=_any_index, size=_any_index)
def test_property_codec_never_raises_anything_but_the_typed_error(index, size):
    # any other exception class escapes `except StatusListError` and fails the test
    calls = [
        lambda: get_status_bit(b"\x40", index),
        lambda: set_status_bit(bytearray(b"\x40"), index, 1),
        lambda: get_status(b"\x40", index, bits=2),
        lambda: set_status(bytearray(b"\x40"), index, 1, bits=2),
    ]
    if not isinstance(size, int) or size < 4096:          # do not allocate megabytes per example
        calls += [lambda: new_bitstring(size), lambda: new_status_list(size, bits=4)]
    for call in calls:
        try:
            call()
        except StatusListError:
            pass
