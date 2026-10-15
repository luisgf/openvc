"""
tests/test_message_helpers_total.py — the helpers that turn a value into error-message
text are total for a caller's object (#282).

``openvc.status._index.brief``, ``openvc.proof._verify_common.safe_repr`` and
``openvc.proof._context_validation._brief`` exist so that reporting a bad value cannot
itself fail. They bound the length and name a container by its type, which settles deep
nesting and huge ints on the wire. They did not settle a value whose own class answers
``repr()``, ``len()`` or ``bit_length()`` badly: the exception that method raised (or the
``ValueError`` of the int-to-str limit, or 1 MB of ``repr`` text) came out of the very
``raise`` meant to report the problem, so a caller got that instead of the typed
``OpenvcError``::

    build_status_list_credential(ttl=BadInt(0))      -> Hostile("a method of the value ...")
    DidWebResolver(fetch).resolve(BadStr(valid_did)) -> Hostile("a method of the value ...")

The fix reads a subclass through the built-in's own unbound methods (``str.__str__``,
``int.bit_length``, ``int.__repr__``, ``float.__repr__``), never its own, and falls back to
``an object`` for whatever still fails. This is caller-only: nothing a JSON, CBOR or XML
parser returns can carry a custom dunder, so no verifier input reaches it.

Layout: the helper matrix (every hostile object through every helper, with the exact text),
the status entry points that reach ``brief`` with a caller's object, ``did:web`` (a success
path, since ``_check_host`` formatted the DID before any check, and the id-mismatch refusal,
which formats the fetched document's ``id`` too: that one is wire data, so it is also bounded)
and ``non_negative_seconds`` (a raw ``{value!r}``). Controls come last, as separate
functions: they pass on the unfixed tree too, which is their point. Every refusal is
asserted against the EXACT class, so a test cannot pass on an earlier or a different
failure. Hostile objects are built inside the tests, never held by a parameter: pytest builds
a parameter id by calling ``str()``, which on an ``int`` subclass calls its ``__repr__``.
Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import asyncio
import enum
import tracemalloc
from typing import Any, Callable
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc.did.base import DidResolutionError
from openvc.did.did_web import AsyncDidWebResolver, DidWebResolver
from openvc.keys import Ed25519SigningKey
from openvc.openid4vp import OpenID4VPError, verify_vp_token
from openvc.proof._context_validation import _brief
from openvc.proof._verify_common import non_negative_seconds, safe_repr
from openvc.proof.errors import ProofError
from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
from openvc.status import (
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    build_status_list_token,
    build_token_status_reference,
    check_credential_status,
    check_token_status,
    get_status,
    get_status_bit,
    new_bitstring,
    new_status_list,
    parse_status_entries,
    parse_token_status_ref,
    set_status,
    set_status_bit,
)
from openvc.status._index import brief

VC2 = "https://www.w3.org/ns/credentials/v2"
HOST_DID = "did:web:example.com"
OBJ = "an object"


# --------------------------------------------------------------------------- #
# the hostile objects
# --------------------------------------------------------------------------- #

class Hostile(RuntimeError):
    """What a hostile method raises: never an OpenvcError, so it can only escape."""


def _boom(self: Any, *args: Any) -> Any:
    raise Hostile("a method of the value was called")


class BadInt(int):
    __repr__ = _boom


class BadFloat(float):
    __repr__ = _boom


class BadStr(str):
    __repr__ = _boom


class LenStr(str):
    __len__ = _boom


class ItemStr(str):
    __getitem__ = _boom


class BitInt(int):
    bit_length = _boom


class LyingInt(int):
    """A 5000-digit value that says it has one bit."""

    def bit_length(self) -> int:
        return 1


class NonStrReprInt(int):
    def __repr__(self) -> Any:
        return 1


class NonStrReprFloat(float):
    def __repr__(self) -> Any:
        return 1


class HugeReprInt(int):
    def __repr__(self) -> str:
        return "9" * 1_000_000


class HugeReprStr(str):
    def __repr__(self) -> str:
        return "9" * 1_000_000


class _RaisingName(type):
    @property
    def __name__(cls) -> str:      # type: ignore[override]
        raise Hostile("the metaclass name was read")


class RaisingNameType(metaclass=_RaisingName):
    pass


class _LongName(type):
    @property
    def __name__(cls) -> str:      # type: ignore[override]
        return "N" * 5_000_000


class LongNameType(metaclass=_LongName):
    pass


class _NonStrName(type):
    @property
    def __name__(cls) -> Any:      # type: ignore[override]
        return 5


class NonStrNameType(metaclass=_NonStrName):
    pass


# --------------------------------------------------------------------------- #
# the helper matrix: 15 objects x 3 helpers, each with the exact text
# --------------------------------------------------------------------------- #

# (id, make, brief, safe_repr, _brief). The 12th row is the issue's metaclass case; the 13th
# is its sibling, a metaclass whose __name__ is not a string; the 14th and 15th are a type name
# of 5 million characters (a metaclass's __name__, and a class created with that name), which
# is cut to 64 characters.
_CUT = "N" * 64 + "..."
MATRIX = [
    ("int-repr-raises", lambda: BadInt(5), "5", "5", "BadInt"),
    ("float-repr-raises", lambda: BadFloat(1.5), "1.5", "1.5", "BadFloat"),
    ("str-repr-raises", lambda: BadStr("abc"), "'abc'", "'abc'", "'abc'"),
    ("str-len-raises", lambda: LenStr("abc"), "'abc'", "'abc'", "'abc'"),
    ("str-getitem-raises", lambda: ItemStr("abc"), "'abc'", "'abc'", "'abc'"),
    ("int-bit_length-raises", lambda: BitInt(5), "5", "5", "BitInt"),
    ("int-bit_length-lies", lambda: LyingInt(10 ** 5000),
     "a 16610-bit integer", "LyingInt", "LyingInt"),
    ("int-repr-non-str", lambda: NonStrReprInt(5), "5", "5", "NonStrReprInt"),
    ("float-repr-non-str", lambda: NonStrReprFloat(1.5), "1.5", "1.5", "NonStrReprFloat"),
    ("int-repr-1MB", lambda: HugeReprInt(5), "5", "5", "HugeReprInt"),
    ("str-repr-1MB", lambda: HugeReprStr("abc"), "'abc'", "'abc'", "'abc'"),
    ("metaclass-name-raises", lambda: RaisingNameType(), OBJ, OBJ, OBJ),
    ("metaclass-name-non-str", lambda: NonStrNameType(), OBJ, OBJ, OBJ),
    ("metaclass-name-5MB", lambda: LongNameType(), "a " + _CUT, _CUT, _CUT),
    ("type-name-5MB", lambda: type("N" * 5_000_000, (), {})(), "a " + _CUT, _CUT, _CUT),
]
MATRIX_IDS = [row[0] for row in MATRIX]
HELPERS = {"brief": (brief, 2), "safe_repr": (safe_repr, 3), "_brief": (_brief, 4)}


@pytest.mark.parametrize("helper", list(HELPERS))
@pytest.mark.parametrize("row", MATRIX, ids=MATRIX_IDS)
def test_helper_is_total_and_shows_the_value_it_holds(helper: str, row: tuple) -> None:
    fn, column = HELPERS[helper]
    out = fn(row[1]())
    assert type(out) is str
    assert out == row[column]
    assert len(out) < 300


def test_helper_values_named_in_the_issue() -> None:
    assert brief(BadInt(5)) == "5"
    assert safe_repr(BadFloat(1.5)) == "1.5"
    assert brief(LyingInt(10 ** 5000)) == "a 16610-bit integer"
    assert safe_repr(LyingInt(10 ** 5000)) == "LyingInt"
    assert safe_repr(BadStr("abc")) == "'abc'"
    assert brief(RaisingNameType()) == "an object"


def test_a_test_double_that_claims_to_be_a_scalar_is_an_object() -> None:
    # Mock(spec=int) passes isinstance(..., int) but is not one: int.bit_length(mock) raises
    # TypeError, which used to come out of the message ("'>' not supported between Mock and
    # int"). The same for the str and float doubles.
    for spec in (int, str, float):
        assert brief(Mock(spec=spec)) == OBJ
        assert safe_repr(Mock(spec=spec)) == OBJ
    assert _brief(Mock(spec=str)) == OBJ


def test_a_type_name_is_shown_up_to_64_characters_and_cut_past_it() -> None:
    for length in (1, 63, 64):
        name = "T" * length
        obj = type(name, (), {})()
        assert brief(obj) == "a " + name
        assert safe_repr(obj) == name
        assert _brief(obj) == name
    over = type("T" * 65, (), {})()
    assert brief(over) == "a " + "T" * 64 + "..."
    assert safe_repr(over) == "T" * 64 + "..."
    assert _brief(over) == "T" * 64 + "..."


def test_a_str_subclass_is_cut_and_counted_from_the_characters_it_holds() -> None:
    class Liar(str):
        __len__ = _boom
        __getitem__ = _boom
        __repr__ = _boom

    text = "x" * 500
    assert brief(Liar(text)) == repr("x" * 32) + "..."
    assert safe_repr(Liar(text)) == repr("x" * 200) + "... (500 chars)"
    assert _brief(Liar(text)) == repr("x" * 100)[:100]


def test_an_enum_is_shown_as_the_value_it_holds() -> None:
    class N(enum.IntEnum):
        A = 1

    class S(str, enum.Enum):
        A = "a"

    assert brief(N.A) == "1"
    assert safe_repr(N.A) == "1"
    assert brief(S.A) == "'a'"
    assert safe_repr(S.A) == "'a'"
    assert _brief(S.A) == "'a'"


def test__brief_cuts_a_string_before_it_repr_s_it() -> None:
    # 16 MB of NULs: repr() of the whole string is 4 times its size. The helper cuts first.
    text = "\x00" * (16 * 1024 * 1024)
    tracemalloc.start()
    try:
        out = _brief(text)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert out == repr("\x00" * 100)[:100]
    assert peak < 1024 * 1024


# --------------------------------------------------------------------------- #
# the status entry points that reach brief() with a caller's object
# --------------------------------------------------------------------------- #

CRED: dict[str, Any] = dict(
    id="https://example.org/s/1", issuer="did:web:issuer.example", bitstring=bytes(16))
ENTRY: dict[str, Any] = dict(status_list_credential="https://example.org/s/1", index=1)
URI = "https://example.org/t/1"


def _token(**over: Any) -> str:
    key = Ed25519SigningKey(ed25519.Ed25519PrivateKey.generate(), "did:web:issuer.example#0")
    args: dict[str, Any] = dict(signing_key=key, uri=URI, status_list=bytes(16))
    args.update(over)
    return build_status_list_token(**args)


def _credential_status(**over: Any) -> dict[str, Any]:
    entry = {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
             "statusListIndex": "1", "statusListCredential": "https://example.org/s/1"}
    entry.update(over)
    return {"credentialStatus": entry}


def _list_credential(**subject: Any) -> dict[str, Any]:
    body = {"statusPurpose": "revocation",
            "encodedList": "uH4sIAAAAAAAC_2NgAAMAAAAA__8DAAAAAAAAAAA"}
    body.update(subject)
    return {"credentialSubject": body}


def _resolving(value: Any) -> Callable[[str], Any]:
    return lambda url: value


_MINIMAL_ENTRY = _credential_status()
_MINIMAL_REF = {"status": {"status_list": {"idx": 1, "uri": URI}}}

# (id, call, a piece of the message it must carry)
STATUS_CASES: list[tuple[str, Callable[[], Any], str]] = [
    # build_status_list_credential
    ("cred-ttl-BadInt", lambda: build_status_list_credential(**CRED, ttl=BadInt(0)),
     "ttl must be a positive integer or None, got 0"),
    ("cred-ttl-BadFloat", lambda: build_status_list_credential(**CRED, ttl=BadFloat(1.5)),
     "ttl must be a positive integer or None, got 1.5"),
    ("cred-ttl-LyingInt",
     lambda: build_status_list_credential(**CRED, ttl=LyingInt(-(10 ** 5000))),
     "ttl must be a positive integer or None, got a 16610-bit integer"),
    ("cred-valid_from-BadFloat",
     lambda: build_status_list_credential(**CRED, valid_from=BadFloat(1.5)),
     "valid_from must be a datetime or None, got 1.5"),
    ("cred-valid_until-BadInt",
     lambda: build_status_list_credential(**CRED, valid_until=BadInt(5)),
     "valid_until must be a datetime or None, got 5"),
    ("cred-issuer-BadInt",
     lambda: build_status_list_credential(**{**CRED, "issuer": BadInt(5)}),
     "issuer must be a non-empty string or an object with a string id, got 5"),
    ("cred-issuer-id-BadFloat",
     lambda: build_status_list_credential(**{**CRED, "issuer": {"id": BadFloat(1.5)}}),
     "issuer id must be a non-empty string, got 1.5"),
    ("cred-id-BadInt", lambda: build_status_list_credential(**{**CRED, "id": BadInt(5)}),
     "status list credential id must be a non-empty string, got 5"),
    ("cred-id-Mock", lambda: build_status_list_credential(**{**CRED, "id": Mock(spec=int)}),
     "status list credential id must be a non-empty string, got an object"),
    ("cred-subject_id-BadInt",
     lambda: build_status_list_credential(**CRED, subject_id=BadInt(5)),
     "subject_id must be a non-empty string, got 5"),
    ("cred-status_purpose-BadFloat",
     lambda: build_status_list_credential(**CRED, status_purpose=BadFloat(1.5)),
     "statusPurpose must be a non-empty string, got 1.5"),
    ("cred-contexts-BadInt", lambda: build_status_list_credential(**CRED, contexts=BadInt(5)),
     "contexts must be None or a non-empty list of context URLs and objects, got 5"),
    ("cred-contexts-first-BadInt",
     lambda: build_status_list_credential(**CRED, contexts=[BadInt(5)]),
     "the first contexts entry must be a VC base context"),
    ("cred-contexts-entry-BadFloat",
     lambda: build_status_list_credential(**CRED, contexts=[VC2, BadFloat(1.5)]),
     "contexts[1] must be a non-empty string or an object, got 1.5"),
    ("cred-bitstring-BadInt",
     lambda: build_status_list_credential(**{**CRED, "bitstring": BadInt(5)}),
     "bitstring must be bytes-like, got 5"),
    ("cred-bitstring-Mock",
     lambda: build_status_list_credential(**{**CRED, "bitstring": Mock(spec=int)}),
     "bitstring must be bytes-like, got an object"),
    # build_status_list_entry
    ("entry-index-BadFloat", lambda: build_status_list_entry(**{**ENTRY, "index": BadFloat(1.5)}),
     "statusListIndex must be an integer, got 1.5"),
    ("entry-status_list_credential-BadInt",
     lambda: build_status_list_entry(**{**ENTRY, "status_list_credential": BadInt(5)}),
     "statusListCredential must be a non-empty string, got 5"),
    ("entry-status_purpose-BadFloat",
     lambda: build_status_list_entry(**ENTRY, status_purpose=BadFloat(1.5)),
     "statusPurpose must be a non-empty string, got 1.5"),
    ("entry-id-Mock", lambda: build_status_list_entry(**ENTRY, id=Mock(spec=int)),
     "status list entry id must be a non-empty string, got an object"),
    # build_status_list_token
    ("token-uri-BadInt", lambda: _token(uri=BadInt(5)),
     "status list token uri must be a non-empty string, got 5"),
    ("token-issuer-BadFloat", lambda: _token(issuer=BadFloat(1.5)),
     "status list token issuer must be a non-empty string, got 1.5"),
    ("token-bits-BadFloat", lambda: _token(bits=BadFloat(1.0)),
     "bits must be one of 1, 2, 4, 8; got 1.0"),
    ("token-status_list-BadInt", lambda: _token(status_list=BadInt(5)),
     "status_list must be bytes-like, got 5"),
    ("token-issued_at-Mock", lambda: _token(issued_at=Mock(spec=str)),
     "issued_at must be a datetime or a finite number of epoch seconds, got an object"),
    ("token-ttl-BadInt", lambda: _token(ttl=BadInt(0)),
     "ttl must be a positive integer or None, got 0"),
    # build_token_status_reference
    ("ref-uri-BadFloat", lambda: build_token_status_reference(uri=BadFloat(1.5), index=1),
     "status_list uri must be a non-empty string, got 1.5"),
    ("ref-index-BadFloat", lambda: build_token_status_reference(uri=URI, index=BadFloat(1.5)),
     "status_list idx must be an integer, got 1.5"),
    # the codecs
    ("new_bitstring-size-BadFloat", lambda: new_bitstring(BadFloat(1.5)),
     "size must be an integer, got 1.5"),
    ("new_status_list-size-BadFloat", lambda: new_status_list(BadFloat(1.5)),
     "size must be an integer, got 1.5"),
    ("new_status_list-bits-BadFloat", lambda: new_status_list(8, bits=BadFloat(1.0)),
     "bits must be one of 1, 2, 4, 8; got 1.0"),
    ("get_status_bit-index-BadFloat", lambda: get_status_bit(bytes(1), BadFloat(1.5)),
     "must be an integer, got 1.5"),
    ("set_status_bit-index-BadFloat", lambda: set_status_bit(bytearray(1), BadFloat(1.5), 1),
     "must be an integer, got 1.5"),
    ("get_status-index-BadFloat", lambda: get_status(bytes(1), BadFloat(1.5)),
     "must be an integer, got 1.5"),
    ("get_status-bits-BadFloat", lambda: get_status(bytes(1), 0, bits=BadFloat(1.0)),
     "bits must be one of 1, 2, 4, 8; got 1.0"),
    ("set_status-index-BadFloat", lambda: set_status(bytearray(1), BadFloat(1.5), 1),
     "must be an integer, got 1.5"),
    ("set_status-value-BadFloat", lambda: set_status(bytearray(1), 0, BadFloat(1.5)),
     "status value 1.5 does not fit in 1 bit(s)"),
    # reading a credential or a resolver's answer that the caller built in process
    ("parse-statusListCredential-BadInt",
     lambda: parse_status_entries(_credential_status(statusListCredential=BadInt(5))),
     "statusListCredential must be a URL string, got 5"),
    ("parse-statusPurpose-BadFloat",
     lambda: parse_status_entries(_credential_status(statusPurpose=BadFloat(1.5))),
     "statusPurpose must be a string, got 1.5"),
    ("parse-statusListIndex-BadFloat",
     lambda: parse_status_entries(_credential_status(statusListIndex=BadFloat(1.5))),
     "statusListIndex must be an integer or a base-10 string, got 1.5"),
    ("parse-token-uri-BadInt",
     lambda: parse_token_status_ref({"status": {"status_list": {"idx": 1, "uri": BadInt(5)}}}),
     "status_list uri must be a URL string, got 5"),
    ("parse-token-idx-BadFloat",
     lambda: parse_token_status_ref(
         {"status": {"status_list": {"idx": BadFloat(1.5), "uri": URI}}}),
     "status_list idx must be an integer, got 1.5"),
    ("check-resolver-returns-BadInt",
     lambda: check_credential_status(_MINIMAL_ENTRY, resolve_status_list=_resolving(BadInt(5))),
     "resolved status-list credential must be an object, got 5"),
    ("check-list-purpose-BadInt",
     lambda: check_credential_status(
         _MINIMAL_ENTRY,
         resolve_status_list=_resolving(_list_credential(statusPurpose=BadInt(5)))),
     "status-list purpose 5 != entry purpose 'revocation'"),
    ("check-token-resolver-returns-BadFloat",
     lambda: check_token_status(
         _MINIMAL_REF, resolve_status_list_token=_resolving(BadFloat(1.5))),
     "resolved status list token claims must be an object, got 1.5"),
    ("check-token-bits-BadFloat",
     lambda: check_token_status(
         _MINIMAL_REF, resolve_status_list_token=_resolving(
             {"status_list": {"bits": BadFloat(1.0), "lst": "eJwDAAAAAAE"}})),
     "status_list.bits must be an integer, got 1.0"),
]
STATUS_IDS = [case[0] for case in STATUS_CASES]


def test_status_matrix_covers_the_call_sites() -> None:
    assert len(STATUS_CASES) >= 32
    assert len(set(STATUS_IDS)) == len(STATUS_IDS)


@pytest.mark.parametrize("case", STATUS_CASES, ids=STATUS_IDS)
def test_status_entry_point_refuses_a_hostile_object_with_a_typed_error(case: tuple) -> None:
    _, call, tail = case
    with pytest.raises(Exception) as caught:
        call()
    assert type(caught.value) is StatusListError, repr(caught.value)
    assert tail in str(caught.value)


# --------------------------------------------------------------------------- #
# did:web — the DID is formatted before any check, so a valid one used to fail
# --------------------------------------------------------------------------- #

def _fetch(url: str) -> dict[str, Any]:
    return {"id": HOST_DID, "verificationMethod": []}


def test_did_web_resolves_a_valid_did_given_as_a_str_subclass() -> None:
    assert DidWebResolver(_fetch).resolve(BadStr(HOST_DID)).id == HOST_DID


def test_did_web_async_resolves_a_valid_did_given_as_a_str_subclass() -> None:
    async def fetch(url: str) -> dict[str, Any]:
        return _fetch(url)

    doc = asyncio.run(AsyncDidWebResolver(fetch).resolve(BadStr(HOST_DID)))
    assert doc.id == HOST_DID


# Not ItemStr: _did_web_url slices the DID, which calls the subclass's own __getitem__. That is
# a data-path consumer of a str subclass (which bytes get used), not a message: out of scope.
@pytest.mark.parametrize("make", [BadStr, LenStr, HugeReprStr],
                         ids=["repr-raises", "len-raises", "repr-1MB"])
def test_did_web_refuses_a_bad_did_given_as_a_str_subclass_with_a_typed_error(
        make: type) -> None:
    with pytest.raises(Exception) as caught:
        DidWebResolver(_fetch).resolve(make("did:web:exa mple.com"))
    assert type(caught.value) is DidResolutionError, repr(caught.value)
    assert "'did:web:exa mple.com'" in str(caught.value)
    assert "is not a domain name" in str(caught.value)


# The id-mismatch refusal formats two values: the DID the caller asked for (a caller's object)
# and the fetched document's id (wire data, so unbounded until now). Both go through safe_repr.
MISMATCH_DOCS = [
    ("other-id", {"id": "did:web:other.example"}, "'did:web:other.example'"),
    ("no-id", {}, "''"),
    ("non-string-id", {"id": 5}, "''"),
]


def _mismatch(make_did: Callable[[], str], doc: dict[str, Any]) -> Exception:
    with pytest.raises(Exception) as caught:
        DidWebResolver(lambda url: doc).resolve(make_did())
    return caught.value


@pytest.mark.parametrize("make", [BadStr, LenStr, HugeReprStr],
                         ids=["repr-raises", "len-raises", "repr-1MB"])
@pytest.mark.parametrize("row", MISMATCH_DOCS, ids=[r[0] for r in MISMATCH_DOCS])
def test_did_web_mismatch_with_a_str_subclass_did_is_a_typed_error(
        make: type, row: tuple) -> None:
    exc = _mismatch(lambda: make(HOST_DID), row[1])
    assert type(exc) is DidResolutionError, repr(exc)
    assert str(exc) == f"document id {row[2]} != requested '{HOST_DID}'"


@pytest.mark.parametrize("make", [BadStr, LenStr, HugeReprStr],
                         ids=["repr-raises", "len-raises", "repr-1MB"])
@pytest.mark.parametrize("row", MISMATCH_DOCS, ids=[r[0] for r in MISMATCH_DOCS])
def test_did_web_async_mismatch_with_a_str_subclass_did_is_a_typed_error(
        make: type, row: tuple) -> None:
    async def fetch(url: str) -> dict[str, Any]:
        return row[1]

    with pytest.raises(Exception) as caught:
        asyncio.run(AsyncDidWebResolver(fetch).resolve(make(HOST_DID)))
    assert type(caught.value) is DidResolutionError, repr(caught.value)
    assert str(caught.value) == f"document id {row[2]} != requested '{HOST_DID}'"


def test_did_web_mismatch_cuts_a_huge_document_id() -> None:
    # The id is whatever the server's did.json says: 5 million characters used to come back
    # as a 5-million-character message.
    exc = _mismatch(lambda: HOST_DID, {"id": "x" * 5_000_000})
    assert type(exc) is DidResolutionError, repr(exc)
    assert str(exc) == (f"document id {'x' * 200!r}... (5000000 chars) != requested '{HOST_DID}'")


def test_did_web_async_mismatch_cuts_a_huge_document_id() -> None:
    async def fetch(url: str) -> dict[str, Any]:
        return {"id": "x" * 5_000_000}

    with pytest.raises(Exception) as caught:
        asyncio.run(AsyncDidWebResolver(fetch).resolve(HOST_DID))
    assert type(caught.value) is DidResolutionError, repr(caught.value)
    assert len(str(caught.value)) < 400
    assert "(5000000 chars)" in str(caught.value)


# --------------------------------------------------------------------------- #
# non_negative_seconds — a raw {value!r}
# --------------------------------------------------------------------------- #

SECONDS_CASES = [
    ("huge-negative-int", lambda: -(10 ** 5000), "int"),
    ("BadInt-minus-one", lambda: BadInt(-1), "-1"),
    ("BadStr-60", lambda: BadStr("60"), "'60'"),
    ("LyingInt-huge-negative", lambda: LyingInt(-(10 ** 5000)), "LyingInt"),
    ("BadFloat", lambda: BadFloat(1.5), "1.5"),
    ("list", lambda: [1, 2, 3], "list"),
    ("metaclass-name-raises", lambda: RaisingNameType(), "an object"),
]
SECONDS_IDS = [case[0] for case in SECONDS_CASES]


@pytest.mark.parametrize("case", SECONDS_CASES, ids=SECONDS_IDS)
def test_non_negative_seconds_refuses_a_hostile_value_with_its_own_class(case: tuple) -> None:
    _, make, shown = case
    with pytest.raises(Exception) as caught:
        non_negative_seconds(make(), name="leeway_s")
    assert type(caught.value) is ProofError, repr(caught.value)
    assert str(caught.value) == f"leeway_s must be a non-negative int (seconds), got {shown}"


@pytest.mark.parametrize("case", SECONDS_CASES, ids=SECONDS_IDS)
def test_sd_jwt_suite_leeway_is_a_typed_error(case: tuple) -> None:
    _, make, shown = case
    with pytest.raises(Exception) as caught:
        SdJwtVcProofSuite(leeway_s=make())
    assert type(caught.value) is SdJwtError, repr(caught.value)
    assert str(caught.value) == f"leeway_s must be a non-negative int (seconds), got {shown}"


@pytest.mark.parametrize("case", SECONDS_CASES, ids=SECONDS_IDS)
def test_sd_jwt_verify_kb_max_age_is_a_typed_error(case: tuple) -> None:
    _, make, shown = case
    with pytest.raises(Exception) as caught:
        SdJwtVcProofSuite().verify("a.b.c~", public_key_jwk={}, kb_max_age_s=make())
    assert type(caught.value) is SdJwtError, repr(caught.value)
    assert str(caught.value) == (
        f"kb_max_age_s must be a non-negative int (seconds), got {shown}")


@pytest.mark.parametrize("knob", ["leeway_s", "kb_max_age_s"])
@pytest.mark.parametrize("case", SECONDS_CASES, ids=SECONDS_IDS)
def test_verify_vp_token_duration_knobs_are_a_typed_error(case: tuple, knob: str) -> None:
    _, make, shown = case
    with pytest.raises(Exception) as caught:
        verify_vp_token(
            {}, dcql_query={"credentials": []}, nonce="n-0S6_WzA2Mj",
            client_id="x509_san_dns:verifier.example", **{knob: make()})
    assert type(caught.value) is OpenID4VPError, repr(caught.value)
    assert str(caught.value) == f"{knob} must be a non-negative int (seconds), got {shown}"


# --------------------------------------------------------------------------- #
# controls — plain values render byte for byte, before and after the fix
# --------------------------------------------------------------------------- #

def test_control_brief_renders_plain_values_byte_for_byte() -> None:
    assert brief("abc") == "'abc'"
    assert brief("x" * 40) == repr("x" * 32) + "..."
    assert brief("x" * 32) == repr("x" * 32)
    assert brief(True) == "True"
    assert brief(False) == "False"
    assert brief(2 ** 64) == "a 65-bit integer"
    assert brief(2 ** 64 - 1) == str(2 ** 64 - 1)
    assert brief(-(2 ** 64)) == "a 65-bit integer"
    assert brief(10 ** 5000) == "a 16610-bit integer"
    assert brief(5) == "5"
    assert brief(1.5) == "1.5"
    assert brief(float("nan")) == "nan"
    assert brief(float("-inf")) == "-inf"
    assert brief(None) == "a NoneType"
    assert brief([1]) == "a list"
    assert brief({}) == "a dict"
    assert brief(b"x") == "a bytes"
    assert brief("\ud800") == repr("\ud800")


def test_control_safe_repr_renders_plain_values_byte_for_byte() -> None:
    assert safe_repr("x" * 200) == repr("x" * 200)
    assert safe_repr("x" * 201) == repr("x" * 200) + "... (201 chars)"
    assert safe_repr(2 ** 64 - 1) == str(2 ** 64 - 1)
    assert safe_repr(2 ** 64) == "int"
    assert safe_repr(-(2 ** 63)) == str(-(2 ** 63))
    assert safe_repr(10 ** 5000) == "int"
    assert safe_repr(None) == "None"
    assert safe_repr(True) == "True"
    assert safe_repr(1.5) == "1.5"
    assert safe_repr(float("nan")) == "nan"
    assert safe_repr([1]) == "list"
    assert safe_repr({}) == "dict"
    assert safe_repr(b"x") == "bytes"


def test_control__brief_renders_plain_values_byte_for_byte() -> None:
    assert _brief("x" * 200) == repr("x" * 200)[:100]
    assert _brief("abc") == "'abc'"
    assert _brief("") == "''"
    assert _brief(5) == "int"
    assert _brief(None) == "NoneType"
    assert _brief(["a"]) == "list"


def test_control_non_negative_seconds_messages_are_unchanged() -> None:
    expected = {-1: "-1", "60": "'60'", float("nan"): "nan", 1.5: "1.5", None: "None",
                True: "True"}
    for value, shown in expected.items():
        with pytest.raises(ProofError) as caught:
            non_negative_seconds(value, name="leeway_s")
        assert str(caught.value) == f"leeway_s must be a non-negative int (seconds), got {shown}"
    assert non_negative_seconds(0, name="leeway_s") == 0
    assert non_negative_seconds(60, name="leeway_s") == 60


def test_control_plain_bad_values_were_always_typed() -> None:
    with pytest.raises(StatusListError, match="ttl must be a positive integer or None, got 0"):
        build_status_list_credential(**CRED, ttl=0)
    with pytest.raises(StatusListError, match="statusListIndex must be an integer, got 1.5"):
        build_status_list_entry(**{**ENTRY, "index": 1.5})


def test_control_an_int_subclass_index_reaches_brief_as_the_plain_int_it_holds() -> None:
    # status_index reduces an int subclass to the plain number first (plain_int, #250), so a
    # lying bit_length never reaches brief on that path: total before the fix too.
    with pytest.raises(StatusListError, match="must be non-negative, got a 16610-bit integer"):
        set_status_bit(bytearray(1), LyingInt(-(10 ** 5000)), 1)
