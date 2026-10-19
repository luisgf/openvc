"""
tests/test_ebsi_adapter_scalar_types.py — the TIR adapters type the scalars they copy (#337).

The TIR adapters mapped a registry body into the domain model with ``a.get("tao")`` and
``bool(raw.get("hasAttributes", False))``: ``id``, ``hash``, ``issuerType``, ``tao`` and
``rootTao`` of the wrong JSON type (an object, an array, a number) were stored as sent on the
v4, v5 and Core v1 lanes, ``body`` was too on v4 (v5 and Core v1 typed it in #321), and the
string ``"false"`` (or ``"0"``, or any non-empty string, array or object) read as
``hasAttributes: true``. Each is now checked against the type the model declares and a wrong
one is :class:`MalformedRegistryResponse`.

The readings pinned here (the three defaults are written up in the PR):

* an ABSENT member keeps the default it always had (``""``, ``None``, ``False``);
* a member that IS sent has the declared JSON type: ``null`` is wrong for ``id``, ``hash`` and
  ``issuerType`` (the model says ``str``) and for ``hasAttributes`` (``bool``), and is ``None``
  for ``tao``, ``rootTao`` and ``body`` (``str | None``);
* ``hasAttributes`` is a JSON boolean: ``0``/``1`` are numbers, ``"false"`` is a string;
* a listing item's ``id`` is typed before it can fall back to the attribute's ``hash``, and
  a ``hash`` that is not copied (the ``id`` was used) is not read.

Negatives first, each asserting the exact class and, where the order matters, how many
requests were made and that ``decode`` never ran, so a test cannot pass on an earlier
failure. The v5 and Core v1 cases run on the recorded responses (``tests/fixtures/ebsi/`` and
``tests/fixtures/ebsi/core-v1/``) with one member swapped; the v4 cases are SYNTHETIC inline
bodies, because there is no recorded TIR v4 response in this repository (as in
``test_ebsi_tir_did_binding.py``), around a recorded accreditation token. Self-contained:
``tests/`` is not a package, so the small stub harness is copied.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from openvc.errors import OpenvcError
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import EbsiError, MalformedRegistryResponse
from openvc_ebsi.models import Accreditation, IssuerRecord
from openvc_ebsi.trust import verify_trust_chain
from openvc_ebsi.versioning import DidEbsiResolver, TirAdapter, TirCoreV1, TirV4, TirV5

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"
CORE = FIXTURES / "core-v1"
PEEK = VcJwtProofSuite().peek_claims
ABSENT = object()                       # the member is left out of the body altogether

TYPES_TRUST = ("VerifiableCredential", "VerifiableAttestation",
               "VerifiableAuthorisationForTrustChain")
TYPES_TNL = ("VerifiableCredential", "VerifiableAttestation", "TrustedNodesList")


def _json(path: Path) -> Any:
    return json.loads(path.read_bytes())


# --------------------------------------------------------------------------- #
# Harness: a registry stub, a decode that counts, and one "lane" per recording
# --------------------------------------------------------------------------- #

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


@dataclass(frozen=True)
class Lane:
    """One TIR API version as recorded: where the issuer response is, and what it serves.

    ``routes`` maps URL -> body; ``inline`` is the v4 shape (the attributes are in the issuer
    body); otherwise ``listing_url`` holds ``{items: [{id, href}]}`` and each ``href`` is a
    revision ``{did, attribute}``."""
    name: str
    tir: Callable[[], TirAdapter]
    base: str
    did: str
    issuer_url: str
    routes: dict[str, Any]
    listing_url: str | None = None
    inline: bool = False
    types: tuple[tuple[str, ...], ...] = ()      # per accreditation, in the order served


def _patched(obj: dict[str, Any], patch: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(obj)
    for key, value in (patch or {}).items():
        if value is ABSENT:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def _v5_lane() -> Lane:
    base = "https://api-pilot.ebsi.eu"
    issuer = _json(FIXTURES / "tir_v5_issuer.json")
    listing = _json(FIXTURES / "tir_v5_attributes.json")
    revisions = _json(FIXTURES / "tir_v5_revisions.json")
    did = issuer["did"]
    issuer_url = f"{base}/trusted-issuers-registry/v5/issuers/{did}"
    routes: dict[str, Any] = {issuer_url: issuer, issuer["attributes"]: listing}
    for item in listing["items"]:
        routes[item["href"]] = revisions[item["id"]]
    return Lane("v5", TirV5, base, did, issuer_url, routes, listing_url=issuer["attributes"],
                types=(TYPES_TRUST, TYPES_TNL, TYPES_TNL))


def _core_lane(node: str, attribute_file: str, base: str) -> Lane:
    issuer = _json(CORE / node / "issuer.json")
    listing = _json(CORE / node / "attributes.json")
    revision = _json(CORE / node / attribute_file)
    did = issuer["did"]
    issuer_url = TirCoreV1().issuer_url(base, did)
    routes: dict[str, Any] = {issuer_url: issuer, issuer["attributes"]: listing,
                              listing["items"][0]["href"]: revision}
    return Lane(f"core-v1/{node}", TirCoreV1, base, did, issuer_url, routes,
                listing_url=issuer["attributes"], types=(TYPES_TRUST,))


def _v4_lane() -> Lane:
    # SYNTHETIC: there is no recorded TIR v4 response in this repository. The shape is the
    # one the module documents, ``{hash, body, issuerType, tao, rootTao}`` inline; the token
    # is a recorded v5 accreditation, so ``decode`` has a real VC-JWT to read.
    base = "https://api-pilot.ebsi.eu"
    issuer = _json(FIXTURES / "tir_v5_issuer.json")
    revisions = _json(FIXTURES / "tir_v5_revisions.json")
    did = issuer["did"]
    first = _json(FIXTURES / "tir_v5_attributes.json")["items"][0]["id"]
    attribute = dict(revisions[first]["attribute"])
    issuer_url = f"{base}/trusted-issuers-registry/v4/issuers/{did}"
    routes = {issuer_url: {"did": did, "attributes": [attribute]}}
    return Lane("v4", TirV4, base, did, issuer_url, routes, inline=True, types=(TYPES_TRUST,))


V5 = _v5_lane()
V4 = _v4_lane()
CORE_GRNET = _core_lane(
    "preprod-grnet", "attribute_0dc6a111.json", "https://api-preprod.ebsi.grnet.gr")
CORE_INCM = _core_lane(
    "preprod-incm", "attribute_0dc6a111.json", "https://api-preprod.ebsi.incm.pt")
CORE_PROD = _core_lane("prod-iti", "attribute_030c5a3d.json", "https://api.ebsi.iti.gr")

RECORDED = [V5, CORE_GRNET, CORE_INCM, CORE_PROD]    # every recorded walk
WALKS = [V5, CORE_GRNET]                             # the shared walk, on two lanes
ALL_LANES = [V4, V5, CORE_GRNET]


def _lane_id(lane: Lane) -> str:
    return lane.name


Parts = tuple[StubFetch, DidEbsiResolver, CountingDecode]


def _world(lane: Lane, *, issuer: dict[str, Any] | None = None,
           item: dict[str, Any] | None = None,
           attribute: dict[str, Any] | None = None) -> Parts:
    """*lane*'s recorded responses with the first accreditation's members patched: ``issuer``
    on the issuer response, ``item`` on the first listing item, ``attribute`` on the first
    attribute (inline on v4, the revision's ``attribute`` object otherwise)."""
    routes = copy.deepcopy(lane.routes)
    if lane.inline:
        body = routes[lane.issuer_url]
        body["attributes"][0] = _patched(body["attributes"][0], attribute)
        routes[lane.issuer_url] = _patched(body, issuer)
    else:
        assert lane.listing_url is not None
        routes[lane.issuer_url] = _patched(routes[lane.issuer_url], issuer)
        listing = routes[lane.listing_url]
        listing["items"][0] = _patched(listing["items"][0], item)
        revision = routes[listing["items"][0]["href"]]
        revision["attribute"] = _patched(revision["attribute"], attribute)
    fetch, decode = StubFetch(routes), CountingDecode()
    return fetch, DidEbsiResolver(fetch, decode, base=lane.base, tir=lane.tir()), decode


def _record(lane: Lane, **patches: dict[str, Any]) -> IssuerRecord:
    return _world(lane, **patches)[1].issuer_record(lane.did)


def _expected(lane: Lane) -> IssuerRecord:
    """The record the RECORDED wire values spell, written from the fixture and not from the
    adapter: the list item's ``id`` (the attribute's ``hash`` on v4, which has no listing),
    the attribute's ``issuerType`` / ``tao`` / ``rootTao`` / ``body``."""
    accs = []
    if lane.inline:
        attributes = lane.routes[lane.issuer_url]["attributes"]
        pairs = [(attribute["hash"], attribute) for attribute in attributes]
    else:
        assert lane.listing_url is not None
        pairs = [(item["id"], lane.routes[item["href"]]["attribute"])
                 for item in lane.routes[lane.listing_url]["items"]]
    for (attribute_id, attribute), types in zip(pairs, lane.types, strict=True):
        accs.append(Accreditation(
            attribute_id=attribute_id, issuer_type=attribute["issuerType"],
            tao=attribute["tao"], root_tao=attribute["rootTao"], credential_types=types,
            credential_jwt=attribute["body"]))
    return IssuerRecord(did=lane.did, has_attributes=True, accreditations=tuple(accs))


def _p(value: Any) -> Any:
    return pytest.param(value, id=f"{type(value).__name__}-{json.dumps(value)[:12]}")


# a JSON value that is not a string, and the ones that are falsy or look like what they are not
NOT_STRINGS = [_p(v) for v in ({}, {"a": 1}, [], [1], 7, 0, -1, 1.5, True, False)]
NOT_BOOLEANS = [_p(v) for v in ("false", "true", "False", "0", "1", "", " ", 0, 1, 2, 1.0, -1,
                                [], [False], {}, {"a": False}, None)]


# --------------------------------------------------------------------------- #
# Controls first: what is recorded parses exactly as before
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", RECORDED, ids=_lane_id)
def test_every_recorded_walk_parses_to_the_wire_values(lane: Lane) -> None:
    fetch, resolver, _ = _world(lane)
    record = resolver.issuer_record(lane.did)
    assert record == _expected(lane)
    assert record.has_attributes is True
    assert all(isinstance(a.issuer_type, str) and isinstance(a.tao, str)
               for a in record.accreditations)


def test_the_synthetic_v4_walk_parses_to_the_wire_values() -> None:
    assert _record(V4) == _expected(V4)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_an_absent_member_keeps_the_default_it_always_had(lane: Lane) -> None:
    gone = {"hash": ABSENT, "issuerType": ABSENT, "tao": ABSENT, "rootTao": ABSENT,
            "body": ABSENT}
    record = _record(lane, attribute=gone, **({} if lane.inline else {"item": {"id": ABSENT}}))
    acc = record.accreditations[0]
    assert (acc.attribute_id, acc.issuer_type, acc.tao, acc.root_tao) == ("", "", None, None)
    assert acc.credential_jwt is None and acc.credential_types == ()


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_null_tao_root_tao_and_body_are_none_the_model_says_str_or_none(lane: Lane) -> None:
    record = _record(lane, attribute={"tao": None, "rootTao": None, "body": None})
    acc = record.accreditations[0]
    assert acc.tao is None and acc.root_tao is None and acc.credential_jwt is None
    assert acc.issuer_type == "RootTAO"                       # the rest of the record is as sent


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_an_absent_has_attributes_is_false_and_costs_one_request(lane: Lane) -> None:
    fetch, resolver, _ = _world(lane, issuer={"hasAttributes": ABSENT})
    record = resolver.issuer_record(lane.did)
    assert record == IssuerRecord(did=lane.did, has_attributes=False, accreditations=())
    assert fetch.calls == [lane.issuer_url]


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_has_attributes_false_is_false_and_costs_one_request(lane: Lane) -> None:
    fetch, resolver, _ = _world(lane, issuer={"hasAttributes": False})
    assert resolver.issuer_record(lane.did).has_attributes is False
    assert fetch.calls == [lane.issuer_url]


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_a_listing_item_with_an_empty_id_falls_back_to_the_attributes_hash(lane: Lane) -> None:
    wire_hash = "ab" * 32
    acc = _record(lane, item={"id": ""}, attribute={"hash": wire_hash}).accreditations[0]
    assert acc.attribute_id == wire_hash
    acc = _record(lane, item={"id": ABSENT}, attribute={"hash": wire_hash}).accreditations[0]
    assert acc.attribute_id == wire_hash


@pytest.mark.parametrize("lane", RECORDED, ids=_lane_id)
@pytest.mark.parametrize("value", [*NOT_STRINGS, _p(None)])
def test_a_hash_that_is_not_copied_is_not_read(lane: Lane, value: Any) -> None:
    # the listing item's id is what the record carries; the attribute's hash is only the
    # fallback, so a hash of any type, `null` included, next to a usable id is a field
    # nothing copies (the docs say so: it is typed "where it is the value copied")
    item_id = _record(lane).accreditations[0].attribute_id
    acc = _record(lane, attribute={"hash": value}).accreditations[0]
    assert acc.attribute_id == item_id


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_member_nothing_copies_may_hold_anything(lane: Lane) -> None:
    # tolerant reads: only the copied fields are typed (Core v1 adds parentAttributeId)
    extra = {"parentAttributeId": {"a": [1]}, "somethingNew": 7}
    record = _record(lane, attribute=extra, issuer=None if lane.inline else extra,
                     **({} if lane.inline else {"item": extra}))
    assert record == _expected(lane)


# --------------------------------------------------------------------------- #
# hasAttributes is a JSON boolean (shared walk: v5 and Core v1)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("value", NOT_BOOLEANS)
def test_has_attributes_that_is_not_a_boolean_is_malformed_after_one_request(
        lane: Lane, value: Any) -> None:
    fetch, resolver, decode = _world(lane, issuer={"hasAttributes": value})
    with pytest.raises(MalformedRegistryResponse, match="hasAttributes is not a boolean") as exc:
        resolver.issuer_record(lane.did)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls == [lane.issuer_url]               # nothing followed: no listing or revision
    assert decode.tokens == []


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_the_string_false_is_no_longer_read_as_true(lane: Lane) -> None:
    # the measured defect: on cf6d100 this walked the whole listing and returned has_attributes=True
    with pytest.raises(MalformedRegistryResponse):
        _record(lane, issuer={"hasAttributes": "false"})


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_the_trust_walk_surfaces_a_non_boolean_has_attributes_as_malformed(lane: Lane) -> None:
    # malformed input, not "this issuer is not accredited", which NoTrustedAnchor would say
    _, resolver, _ = _world(lane, issuer={"hasAttributes": "false"})
    with pytest.raises(MalformedRegistryResponse) as exc:
        verify_trust_chain(lane.did, ["VerifiableAuthorisationForTrustChain"], resolver=resolver,
                           proof_suite=VcJwtProofSuite(), anchors={"did:ebsi:z" + "1" * 22})
    assert type(exc.value) is MalformedRegistryResponse


# --------------------------------------------------------------------------- #
# issuerType, tao, rootTao, body: each copied scalar, each lane
# --------------------------------------------------------------------------- #

def _assert_malformed_before_decode(lane: Lane, field: str, **where: Any) -> None:
    fetch, resolver, decode = _world(lane, **where)
    with pytest.raises(MalformedRegistryResponse, match=f"{field} is not a string") as exc:
        resolver.issuer_record(lane.did)
    assert type(exc.value) is MalformedRegistryResponse
    assert isinstance(exc.value, EbsiError) and isinstance(exc.value, OpenvcError)
    # typed before the proof suite's `decode` is handed the entry's token (a v4 body that is
    # not a string reached it as a bare AttributeError)
    assert decode.tokens == []


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("value", NOT_STRINGS)
@pytest.mark.parametrize("field", ["tao", "rootTao", "body"])
def test_an_optional_string_of_another_type_is_malformed(
        lane: Lane, field: str, value: Any) -> None:
    _assert_malformed_before_decode(lane, field, attribute={field: value})


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("value", [*NOT_STRINGS, _p(None)])
def test_an_issuer_type_of_another_type_or_null_is_malformed(lane: Lane, value: Any) -> None:
    _assert_malformed_before_decode(lane, "issuerType", attribute={"issuerType": value})


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("value", [*NOT_STRINGS, _p(None)])
def test_a_hash_of_another_type_or_null_is_malformed_when_it_is_the_attribute_id(
        lane: Lane, value: Any) -> None:
    # v4 always copies the hash; v5 and Core v1 copy it when the listing item has no usable id
    where: dict[str, Any] = {"attribute": {"hash": value}}
    if not lane.inline:
        where["item"] = {"id": ABSENT}
    _assert_malformed_before_decode(lane, "hash", **where)


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("value", [*NOT_STRINGS, _p(None)])
def test_a_listing_item_id_of_another_type_or_null_is_malformed(lane: Lane, value: Any) -> None:
    # `0`, `[]`, `{}`, `False` and `null` used to fall through to the attribute's hash
    _assert_malformed_before_decode(lane, "id", item={"id": value})


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_a_bad_id_is_not_rescued_by_a_good_hash(lane: Lane) -> None:
    with pytest.raises(MalformedRegistryResponse, match="id is not a string"):
        _record(lane, item={"id": 0}, attribute={"hash": "ab" * 32})


def test_a_bad_scalar_on_a_later_v4_accreditation_rejects_the_record() -> None:
    # one bad entry rejects the whole issuer (as a revision with no attribute object does):
    # a partial record would be a trust decision made on part of the registry's answer
    routes = copy.deepcopy(V4.routes)
    good = routes[V4.issuer_url]["attributes"][0]
    routes[V4.issuer_url]["attributes"] = [good, {**good, "rootTao": 7}]
    resolver = DidEbsiResolver(StubFetch(routes), PEEK, base=V4.base, tir=V4.tir())
    with pytest.raises(MalformedRegistryResponse, match="rootTao is not a string"):
        resolver.issuer_record(V4.did)


def test_a_bad_scalar_on_the_third_listing_item_rejects_the_record() -> None:
    routes = copy.deepcopy(V5.routes)
    third = routes[V5.listing_url]["items"][2]["href"]
    routes[third]["attribute"]["tao"] = ["did:ebsi:zZeKyEJfUTGwajhNyNX928z"]
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, PEEK, base=V5.base, tir=V5.tir())
    with pytest.raises(MalformedRegistryResponse, match="tao is not a string"):
        resolver.issuer_record(V5.did)
    assert fetch.calls[-1] == third                    # the first two were read, then it stopped


# --------------------------------------------------------------------------- #
# The message is bounded
# --------------------------------------------------------------------------- #

def _deep(n: int) -> Any:
    out: Any = []
    for _ in range(n):
        out = [out]
    return out


# safe_repr shows at most 200 characters of a string, plus the field name and a length note;
# the values below are far past that, so an unbounded echo (the value's own repr) overshoots
MESSAGE_BOUND = 400

# values whose own repr() is huge, slow or raises: a 5000-deep array (RecursionError on some
# releases), a 5000-member object, and an int past the int-to-str digit limit (ValueError)
HOSTILE = [
    pytest.param(_deep(5000), id="deep-array"),
    pytest.param({str(i): i for i in range(5000)}, id="wide-object"),
    pytest.param(10 ** 5000, id="huge-int"),
]


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("hostile", HOSTILE)
@pytest.mark.parametrize("field", ["tao", "rootTao", "issuerType"])
def test_the_message_never_carries_an_unbounded_value(lane: Lane, field: str, hostile: Any) -> None:
    with pytest.raises(MalformedRegistryResponse) as exc:
        _record(lane, attribute={field: hostile})
    assert type(exc.value) is MalformedRegistryResponse        # not a RecursionError / ValueError
    assert len(str(exc.value)) < MESSAGE_BOUND


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_the_has_attributes_message_never_carries_an_unbounded_value(lane: Lane) -> None:
    with pytest.raises(MalformedRegistryResponse) as exc:
        _record(lane, issuer={"hasAttributes": "x" * 100_000})
    assert len(str(exc.value)) < MESSAGE_BOUND
    with pytest.raises(MalformedRegistryResponse) as exc:
        _record(lane, issuer={"hasAttributes": 10 ** 5000})
    assert len(str(exc.value)) < MESSAGE_BOUND


# --------------------------------------------------------------------------- #
# The invariant, by search: whatever the registry sends, the record keeps the model's types
# --------------------------------------------------------------------------- #

_scalar = (st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False)
           | st.text(max_size=12))
_wire = st.recursive(
    _scalar,
    lambda kids: (st.lists(kids, max_size=3)
                  | st.dictionaries(st.text(max_size=4), kids, max_size=3)),
    max_leaves=6)
_maybe = st.one_of(st.just(ABSENT), _wire)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(has_attributes=_maybe, item_id=_maybe, wire_hash=_maybe, issuer_type=_maybe,
       tao=_maybe, root_tao=_maybe, body=_maybe)
def test_any_registry_json_is_a_typed_error_or_a_record_the_model_types_hold_for(
        lane: Lane, has_attributes: Any, item_id: Any, wire_hash: Any, issuer_type: Any,
        tao: Any, root_tao: Any, body: Any) -> None:
    attribute = {"hash": wire_hash, "issuerType": issuer_type, "tao": tao, "rootTao": root_tao,
                 "body": body}
    where: dict[str, Any] = {"attribute": attribute}
    if not lane.inline:
        where["issuer"] = {"hasAttributes": has_attributes}
        where["item"] = {"id": item_id}
    # `body` is a real token or garbage: garbage that IS a string is `decode`'s to reject
    # (ProofError, a different family), so only the wrong-TYPE bodies are searched here
    if isinstance(body, str) and body:
        attribute["body"] = ABSENT
    try:
        record = _record(lane, **where)
    except MalformedRegistryResponse:
        return
    assert isinstance(record.has_attributes, bool)
    for acc in record.accreditations:
        assert isinstance(acc.attribute_id, str) and isinstance(acc.issuer_type, str)
        for field in (acc.tao, acc.root_tao, acc.credential_jwt):
            assert field is None or isinstance(field, str)
