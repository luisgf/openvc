"""
tests/test_ebsi_tir_v4_shape.py — the TIR v4 adapter types the SHAPE it reads (#352).

``TirV4.parse_issuer`` iterated ``raw.get("attributes", [])`` and called ``.get`` on each
entry, so an ``attributes`` that was ``null``, a number, a string or an object, and an entry
that was not an object, escaped as a bare ``TypeError`` / ``AttributeError`` (measured on
``main`` at 3bd9e59), outside the ``EbsiError`` family a caller handles. The same adapter read
the decoded accreditation token as ``decode(body).get("vc", {}).get("credentialSubject", {})``,
which is the same bare ``AttributeError`` for a ``vc`` or ``credentialSubject`` that is sent and
is not an object. Each is now :class:`MalformedRegistryResponse`.

The readings pinned here:

* ``attributes`` ABSENT keeps meaning "no attributes" (``has_attributes`` false, no
  accreditations); ``[]`` is the same. Present, it must be a list: ``null``, ``0``, ``""``,
  ``false`` and ``{}`` are present, are not lists, and are wrong, whatever their truth value;
* every entry must be an object, and ONE bad entry rejects the WHOLE record (the maintainer's
  decision of 2026-10-20, the rule #337 applies to scalars): the good entries beside it are not
  returned. Here the bad entry is placed SECOND so a loop that returned early would show;
* inside the token, ``vc`` and ``credentialSubject`` ABSENT still read as "no types" (what v4
  always did); SENT, they must be objects, and ``null`` is not one. The v5 walk skips such a
  value instead (an accreditation with no type restriction); v4 rejects it, because a skip
  here would turn a crash into the widest accreditation there is. That the v5 walk skips is
  NOT touched by this change;
* the message shows the value through ``safe_repr``: bounded, and it cannot raise from the
  very ``raise`` meant to report a value whose ``repr()`` raises.

Not changed, and pinned as controls so nobody reads this file as changing them: an ``{}``
entry is an object and parses to an accreditation of defaults (``test_ebsi_adapter_scalar_
types.py``), and ``issuerType`` is not checked against the trust roles.

PARITY: there is NO recorded TIR v4 response in this repository (as in
``test_ebsi_adapter_scalar_types.py`` and ``test_ebsi_tir_did_binding.py``). The v4 bodies here
are SYNTHETIC: the shape the module documents, ``{hash, body, issuerType, tao, rootTao}``
inline, around the three RECORDED v5 accreditation tokens. "Parses identically" therefore means
the record the recorded wire values spell, written from the fixture and not from the adapter,
and these controls also pass on ``main`` before the change. Self-contained: ``tests/`` is not a
package, so the small stub harness is copied.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from openvc.errors import OpenvcError
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import EbsiError, MalformedRegistryResponse
from openvc_ebsi.models import Accreditation, IssuerRecord
from openvc_ebsi.versioning import DidEbsiResolver, TirV4, tir_adapter

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"
PEEK = VcJwtProofSuite().peek_claims
BASE = "https://api-pilot.ebsi.eu"

TYPES_TRUST = ("VerifiableCredential", "VerifiableAttestation",
               "VerifiableAuthorisationForTrustChain")
TYPES_TNL = ("VerifiableCredential", "VerifiableAttestation", "TrustedNodesList")
RECORDED_TYPES = (TYPES_TRUST, TYPES_TNL, TYPES_TNL)      # the three recorded accreditations


def _json(name: str) -> Any:
    return json.loads((FIXTURES / name).read_bytes())


ISSUER = _json("tir_v5_issuer.json")
DID: str = ISSUER["did"]
LISTING = _json("tir_v5_attributes.json")
REVISIONS = _json("tir_v5_revisions.json")
ATTRIBUTES: list[dict[str, Any]] = [
    dict(REVISIONS[item["id"]]["attribute"]) for item in LISTING["items"]]
ISSUER_URL = f"{BASE}/trusted-issuers-registry/v4/issuers/{DID}"


class StubFetch:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url: str) -> Any:
        self.calls.append(url)
        try:
            return self.routes[url]
        except KeyError:
            raise AssertionError(f"the walk asked for an unrouted URL: {url}") from None


class CountingDecode:
    """``VcJwtProofSuite.peek_claims``, recording every token it is handed."""

    def __init__(self) -> None:
        self.tokens: list[Any] = []

    def __call__(self, token: Any) -> dict[str, Any]:
        self.tokens.append(token)
        return PEEK(token)


class RaisingRepr:
    """Not JSON, but a caller can hand one in: its ``repr()`` and ``str()`` raise."""

    def __repr__(self) -> str:
        raise RuntimeError("repr must not be called")

    __str__ = __repr__


class RaisingStr(str):
    """A ``str`` whose own ``repr`` / ``len`` raise (``safe_repr`` reads the characters)."""

    def __repr__(self) -> str:
        raise RuntimeError("repr must not be called")

    def __len__(self) -> int:
        raise RuntimeError("len must not be called")


def _body(attributes: Any, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"did": DID, **extra}
    if attributes is not ...:
        out["attributes"] = attributes
    return out


def _parse(raw: Any, decode: Any = None) -> IssuerRecord:
    """The issue's own repro: the adapter, called directly."""
    return tir_adapter("v4").parse_issuer(
        raw, base=BASE, did=DID, fetch=StubFetch({}), decode=decode or CountingDecode())


def _resolve(raw: Any, decode: Any = None) -> tuple[StubFetch, CountingDecode, IssuerRecord]:
    """The same body through the resolver, the path every caller takes."""
    fetch, counted = StubFetch({ISSUER_URL: raw}), CountingDecode()
    resolver = DidEbsiResolver(fetch, decode or counted, base=BASE, tir=TirV4())
    return fetch, counted, resolver.issuer_record(DID)


def _expected() -> IssuerRecord:
    """The record the RECORDED wire values spell, written from the fixture: the attribute's
    ``hash`` is the id on v4 (there is no listing), the types are the recorded tokens'."""
    accs = tuple(
        Accreditation(attribute_id=a["hash"], issuer_type=a["issuerType"], tao=a["tao"],
                      root_tao=a["rootTao"], credential_types=types, credential_jwt=a["body"])
        for a, types in zip(ATTRIBUTES, RECORDED_TYPES, strict=True))
    return IssuerRecord(did=DID, has_attributes=True, accreditations=accs)


def _p(value: Any) -> Any:
    return pytest.param(value, id=f"{type(value).__name__}-{json.dumps(value)[:12]}")


# the issue's five rows, then the values that are falsy or look like a list
TABLE = [_p(v) for v in (None, 7, "x", {"a": 1}, [1])]
NOT_LISTS = [_p(v) for v in (None, 7, 0, 1.5, True, False, "x", "", "[]", {}, {"a": 1},
                             {"0": {}})]
NOT_OBJECTS = [_p(v) for v in (None, 7, 0, 1.5, True, False, "x", "", "{}", [], [{}], [1])]


# --------------------------------------------------------------------------- #
# Controls first: what parsed before parses exactly as before
# --------------------------------------------------------------------------- #

def test_the_recorded_tokens_inline_parse_to_the_wire_values() -> None:
    raw = _body(copy.deepcopy(ATTRIBUTES))
    assert _parse(raw) == _expected()
    fetch, decode, record = _resolve(raw)
    assert record == _expected()
    assert fetch.calls == [ISSUER_URL]                  # v4 is one call
    assert decode.tokens == [a["body"] for a in ATTRIBUTES]


@pytest.mark.parametrize("attributes", [..., []], ids=["absent", "empty-list"])
def test_no_attributes_keeps_meaning_no_attributes(attributes: Any) -> None:
    empty = IssuerRecord(did=DID, has_attributes=False, accreditations=())
    assert _parse(_body(attributes)) == empty
    assert _resolve(_body(attributes))[2] == empty


def test_an_empty_object_entry_is_still_an_accreditation_of_defaults() -> None:
    # unchanged on purpose (#337 pins it): the entry IS an object, its members are absent
    record = _parse(_body([{}]))
    assert record.has_attributes is True
    assert record.accreditations == (Accreditation("", "", None, None),)


def test_unknown_members_of_the_response_and_of_an_entry_are_ignored() -> None:
    attribute = {**ATTRIBUTES[0], "somethingNew": [1, {"a": None}]}
    record = _parse(_body([attribute], hasAttributes="whatever", total=1, links=[]))
    assert record.accreditations[0].attribute_id == ATTRIBUTES[0]["hash"]


@pytest.mark.parametrize("claims", [
    pytest.param({}, id="no-vc"),
    pytest.param({"vc": {}}, id="vc-empty"),
    pytest.param({"vc": {"credentialSubject": {}}}, id="subject-empty"),
    pytest.param({"vc": {"credentialSubject": {"accreditedFor": 7}}}, id="accreditedFor-7"),
])
def test_an_absent_vc_or_subject_still_reads_as_no_types(claims: dict[str, Any]) -> None:
    record = _parse(_body([{"hash": "h", "issuerType": "TI", "body": "tok"}]),
                    decode=lambda token: claims)
    assert record.accreditations[0].credential_types == ()


# --------------------------------------------------------------------------- #
# `attributes` that is not a list: the issue's table, and every falsy twin
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("attributes", NOT_LISTS)
def test_attributes_that_is_not_a_list_is_malformed(attributes: Any) -> None:
    with pytest.raises(MalformedRegistryResponse, match="attributes is not a list") as info:
        _parse(_body(attributes))
    assert type(info.value) is MalformedRegistryResponse        # the exact class
    assert isinstance(info.value, EbsiError) and isinstance(info.value, OpenvcError)


@pytest.mark.parametrize("attributes", TABLE)
def test_the_issue_table_is_malformed_not_a_bare_exception(attributes: Any) -> None:
    # `[1]` is a list: its entry is what is wrong, so its message is the entry's
    with pytest.raises(MalformedRegistryResponse,
                       match=r"attributes(\[0\])? is not an? (list|object)") as info:
        _parse(_body(attributes))
    assert type(info.value) is MalformedRegistryResponse
    assert isinstance(info.value, EbsiError) and isinstance(info.value, OpenvcError)


@pytest.mark.parametrize("attributes", TABLE)
def test_the_issue_table_is_an_ebsi_error_through_the_resolver(attributes: Any) -> None:
    # what callers catch: nothing past the one issuer request, and `decode` never ran
    fetch, counted = StubFetch({ISSUER_URL: _body(attributes)}), CountingDecode()
    resolver = DidEbsiResolver(fetch, counted, base=BASE, tir=TirV4())
    with pytest.raises(MalformedRegistryResponse) as info:
        resolver.issuer_record(DID)
    assert type(info.value) is MalformedRegistryResponse
    assert fetch.calls == [ISSUER_URL] and counted.tokens == []


# --------------------------------------------------------------------------- #
# an entry that is not an object, and the whole-record rule
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("entry", NOT_OBJECTS)
def test_an_entry_that_is_not_an_object_is_malformed(entry: Any) -> None:
    with pytest.raises(MalformedRegistryResponse, match=r"attributes\[0\] is not an object"
                       ) as info:
        _parse(_body([entry]))
    assert type(info.value) is MalformedRegistryResponse


@pytest.mark.parametrize("entry", NOT_OBJECTS)
def test_one_bad_entry_rejects_the_whole_record(entry: Any) -> None:
    # the good entry comes FIRST and parses (its token is decoded); the bad one is second
    good = copy.deepcopy(ATTRIBUTES[0])
    decode = CountingDecode()
    with pytest.raises(MalformedRegistryResponse, match=r"attributes\[1\] is not an object"
                       ) as info:
        _parse(_body([good, entry]), decode=decode)
    assert type(info.value) is MalformedRegistryResponse
    assert decode.tokens == [good["body"]]       # the first entry WAS read, none is returned


def test_the_bad_entry_is_found_after_many_good_ones() -> None:
    entries: list[Any] = [copy.deepcopy(a) for a in ATTRIBUTES] * 20 + [None]
    with pytest.raises(MalformedRegistryResponse, match=r"attributes\[60\] is not an object"):
        _parse(_body(entries))


@pytest.mark.parametrize("raw", [
    pytest.param(None, id="null"), pytest.param([], id="list"),
    pytest.param("x", id="string"), pytest.param(7, id="number"),
])
def test_a_response_that_is_not_an_object_is_malformed_when_called_directly(raw: Any) -> None:
    # the resolver checks this first (test_ebsi_tir_did_binding.py); the adapter does too, as
    # the v5 one does, so a direct call is typed as well
    with pytest.raises(MalformedRegistryResponse, match="expected a JSON object") as info:
        _parse(raw)
    assert type(info.value) is MalformedRegistryResponse


# --------------------------------------------------------------------------- #
# inside the accreditation token
# --------------------------------------------------------------------------- #

def _entry() -> dict[str, Any]:
    return {"hash": "h", "issuerType": "TI", "body": "tok"}


@pytest.mark.parametrize("value", NOT_OBJECTS)
def test_a_vc_that_is_not_an_object_is_malformed(value: Any) -> None:
    with pytest.raises(MalformedRegistryResponse, match="vc is not an object") as info:
        _parse(_body([_entry()]), decode=lambda token: {"vc": value})
    assert type(info.value) is MalformedRegistryResponse


@pytest.mark.parametrize("value", NOT_OBJECTS)
def test_a_credential_subject_that_is_not_an_object_is_malformed(value: Any) -> None:
    with pytest.raises(MalformedRegistryResponse,
                       match="credentialSubject is not an object") as info:
        _parse(_body([_entry()]), decode=lambda token: {"vc": {"credentialSubject": value}})
    assert type(info.value) is MalformedRegistryResponse


@pytest.mark.parametrize("claims", [None, [], "x", 7])
def test_claims_that_are_not_an_object_are_malformed(claims: Any) -> None:
    # a `decode` that is not the proof suite's `peek_claims` (it is injected)
    with pytest.raises(MalformedRegistryResponse, match="expected a JSON object") as info:
        _parse(_body([_entry()]), decode=lambda token: claims)
    assert type(info.value) is MalformedRegistryResponse


def test_a_bad_token_shape_in_a_later_entry_rejects_the_record() -> None:
    claims = iter([{"vc": {"credentialSubject": {}}}, {"vc": []}])
    with pytest.raises(MalformedRegistryResponse, match="vc is not an object"):
        _parse(_body([_entry(), _entry()]), decode=lambda token: next(claims))


# --------------------------------------------------------------------------- #
# the message is bounded and cannot raise
# --------------------------------------------------------------------------- #

def test_a_long_string_attributes_is_not_echoed_in_full() -> None:
    with pytest.raises(MalformedRegistryResponse) as info:
        _parse(_body("x" * 100_000))
    message = str(info.value)
    assert len(message) < 300 and "x" * 201 not in message
    assert message == ("TIR issuer response attributes is not a list: "
                       f"{'x' * 200!r}... (100000 chars)")


def test_a_long_string_entry_is_not_echoed_in_full() -> None:
    with pytest.raises(MalformedRegistryResponse) as info:
        _parse(_body(["x" * 100_000]))
    message = str(info.value)
    assert len(message) < 300 and "x" * 201 not in message
    assert message == ("TIR issuer response attributes[0] is not an object: "
                       f"{'x' * 200!r}... (100000 chars)")


def test_a_long_string_vc_is_not_echoed_in_full() -> None:
    with pytest.raises(MalformedRegistryResponse) as info:
        _parse(_body([_entry()]), decode=lambda token: {"vc": "y" * 100_000})
    assert len(str(info.value)) < 300


@pytest.mark.parametrize("make", [
    pytest.param(lambda: _body(RaisingRepr()), id="attributes"),
    pytest.param(lambda: _body([RaisingRepr()]), id="entry"),
    pytest.param(lambda: _body([1, RaisingRepr()]), id="second-entry"),
    pytest.param(lambda: _body(RaisingStr("x")), id="str-subclass-attributes"),
    pytest.param(lambda: _body([RaisingStr("x")]), id="str-subclass-entry"),
])
def test_a_value_whose_repr_raises_does_not_raise_from_the_raise(make: Any) -> None:
    with pytest.raises(MalformedRegistryResponse) as info:
        _parse(make())
    assert type(info.value) is MalformedRegistryResponse
    assert len(str(info.value)) < 300


def test_a_value_whose_repr_raises_in_the_token_does_not_raise_from_the_raise() -> None:
    with pytest.raises(MalformedRegistryResponse) as info:
        _parse(_body([_entry()]), decode=lambda token: {"vc": RaisingRepr()})
    assert type(info.value) is MalformedRegistryResponse


def test_deep_nesting_is_named_by_its_type_not_walked() -> None:
    deep: Any = []
    for _ in range(20_000):
        deep = [deep]
    for raw in (_body(deep), _body([deep])):
        with pytest.raises(MalformedRegistryResponse) as info:
            _parse(raw)
        assert type(info.value) is MalformedRegistryResponse
        assert len(str(info.value)) < 300
    # as a token member too
    with pytest.raises(MalformedRegistryResponse) as token_info:
        _parse(_body([_entry()]), decode=lambda token: {"vc": deep})
    assert len(str(token_info.value)) < 300


# --------------------------------------------------------------------------- #
# subclasses that pass `isinstance` read as the plain type they extend
# --------------------------------------------------------------------------- #

def test_a_list_and_a_dict_subclass_read_as_the_list_and_the_dict_they_hold() -> None:
    class Entries(list):    # type: ignore[type-arg]
        pass

    class Entry(dict):      # type: ignore[type-arg]
        pass

    attribute = Entry(copy.deepcopy(ATTRIBUTES[0]))
    record = _parse(_body(Entries([attribute])))
    assert record.accreditations[0].attribute_id == ATTRIBUTES[0]["hash"]
    assert record.accreditations[0].credential_types == TYPES_TRUST
