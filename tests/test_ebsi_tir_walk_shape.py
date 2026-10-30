"""
tests/test_ebsi_tir_walk_shape.py — the v5 and Core v1 TIR walk read the accreditation token
fail-closed, and the trust walk binds every accreditation to the DID it was read for (#352,
the follow-ups the adversarial review of PR #354 left open).

Measured on ``main`` at b1fd669 with real P-256 signatures through ``verify_trust_chain``, on
v5 and on Core v1 (``for_nodes`` defaults to Core v1, so that is the production lane; 1.36.0 on
PyPI carries it). A registry that places a ROOT-signed accreditation in LEAF's record got:

* (a) a ``credentialSubject`` that is not an object, a VCDM-legal **array of subjects**
  included, read by the walk as ``{}``: no types, which is the UNRESTRICTED accreditation. A
  ROOT-signed ``credentialSubject: [{"id": OTHER, "accreditedFor": [OtherType]}]`` was TRUSTED
  for LEAF, for any credential type. ``"x"``, ``7``, ``null`` and ``true`` the same. A ``vc``
  that is not an object was ``AccreditationInvalid`` in recursive mode only because the suite's
  ``verify`` wants a ``vc`` object; single-level trust, which verifies no signature, accepted
  the record as unrestricted for every one of these shapes;
* (b) ``trust.py`` skipped the subject binding when the token carried neither ``sub`` nor
  ``credentialSubject.id`` (``if verified.subject and ...``): a ROOT-signed accreditation that
  named nobody was TRUSTED for LEAF, on v4, v5 and Core v1. Sharper: an **empty** ``sub`` over a
  ``credentialSubject.id`` of OTHER was TRUSTED too (the suite's ``sub``/``id`` comparison skips
  an empty ``sub``, and the empty string is falsy), and so was ``credentialSubject.id`` of ``""``
  or ``7`` with no ``sub``;
* (c) ``accreditedFor`` as a single object, a bare string, ``[{"types": ""}]``, ``[7]``,
  ``[null]`` and ``[["T"]]`` read as no types: TRUSTED for every type (the same accreditation
  as a list of objects: ``NoTrustedAnchor``); ``types`` of ``7`` / ``null`` / ``true`` / ``1.5``
  was a bare ``TypeError`` out of ``issuer_record`` and ``verify_trust_chain``, which under
  ``for_nodes`` gets past the node client's ``except EbsiError``; a string ``types`` was split
  into characters;
* (d) a ``body`` that is not a compact JWS with a JSON-object payload escaped ``issuer_record``
  and ``verify_trust_chain`` as the proof suite's ``MalformedToken``, an ``OpenvcError`` and not
  an ``EbsiError``, on every lane; a token whose header alone is unreadable passed
  ``issuer_record`` (``peek_claims`` reads the payload) and escaped ``verify_trust_chain`` from
  ``peek_issuer`` the same way.

Now: the walk reads the token through the one reader v4 got in #354 (``vc``,
``credentialSubject`` and ``accreditedFor`` sent in a shape it does not know are
``MalformedRegistryResponse``, never "no types"; absent still means no types), a ``body`` the
suite cannot read is ``MalformedRegistryResponse`` with the suite's error as ``__cause__``, ONE
bad accreditation rejects the whole record (the maintainer's #352 decision, applied to this lane:
nothing partial is returned), and ``trust.py`` requires the JWT ``sub`` and the credential's
``credentialSubject.id``, each one that is sent, to be exactly the accredited DID, at least one
of them sent (``AccreditationInvalid``). ``peek_issuer``'s error is ``AccreditationInvalid`` too.

The adversarial review of the PR (Opus, runnable repros) added four small ones, pinned in the
last sections: ``accreditedFor`` is checked and read in ONE pass (a list from an injected
``decode`` that iterates differently the second time cannot widen what was checked); every
scalar the record copies is an exact ``str`` (a ``str`` subclass from an injected ``fetch``
whose ``.split`` answered with another token made ``peek_claims`` read one token while the
suite verified another); the binding honours ``credentialSubject.@id`` as it does ``id``; a
``credentialStatus`` the status module refuses, on a signed accreditation, is
``AccreditationInvalid`` and not the status module's ``OpenvcError`` out of
``verify_trust_chain``. And the consequence for ``verify_ebsi_badge(require_trust=False)``:
``MalformedRegistryResponse`` is not a ``TrustChainError``, so the shapes closed here raise
there too, where ``main`` returned ``trusted=True`` (the #267 stance).

Not changed, pinned as controls: the four RECORDED walks (the pilot's v5 and three Core v1
nodes) parse to the record their wire values spell; a listing item the walk cannot follow is
still skipped (it narrows trust, where a misread token widens it); a ``vc`` with no
``credentialSubject`` or no ``accreditedFor`` still reads as "no types" (this file pins the
READER's outcome; what "no types" authorises is the policy's question, which was open when this
file was written and which #368 answered with "nothing":
``test_ebsi_accreditation_deny_by_default.py``).
Self-contained: ``tests/`` is not a package.
"""
from __future__ import annotations

import base64
import copy
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest

from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.errors import MalformedToken
from openvc.proof.vc_jwt import VcJwtProofSuite, VerifiedCredential
from openvc.status import StatusListError, encode_bitstring
from openvc_ebsi.errors import EbsiError, MalformedRegistryResponse
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.models import Accreditation, IssuerRecord
from openvc_ebsi.node_client import for_nodes
from openvc_ebsi.nodes import Accepted, Node, VerifiedNodeList
from openvc_ebsi.trust import (
    AccreditationInvalid,
    NoTrustedAnchor,
    TrustChain,
    verify_trust_chain,
)
from openvc_ebsi.verify import evaluate_issuer_trust, verify_ebsi_badge
from openvc_ebsi.versioning import (
    DidEbsiResolver,
    DidRegistryAdapter,
    DidRegistryCoreV1,
    DidRegistryV5,
    TirAdapter,
    TirCoreV1,
    TirV4,
    TirV5,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"
CORE = FIXTURES / "core-v1"
SUITE = VcJwtProofSuite()
PEEK = SUITE.peek_claims
TYPES = ["OpenBadgeCredential"]
OTHER_TYPES = ["OtherType"]
MESSAGE_BOUND = 400


def _did(seed: int) -> str:
    # a well-formed did:ebsi identifier (#266): `z` + base58btc(version byte 1 || 16 bytes)
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, ROOT, OTHER = _did(0xA1), _did(0xC3), _did(0xD4)
ROOT_SK = P256SigningKey.generate(kid=f"{ROOT}#key-1")      # the anchor's real signing key


# --------------------------------------------------------------------------- #
# Harness: a LEAF record holding ROOT-signed accreditations, on each lane
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
            raise HttpNotFound("no stub route", url=url) from None


class CountingDecode:
    """The suite's ``peek_claims``, recording every token it is handed."""

    def __init__(self, read: Callable[[str], Any] = PEEK) -> None:
        self.tokens: list[Any] = []
        self._read = read

    def __call__(self, token: str) -> Any:
        self.tokens.append(token)
        return self._read(token)


@dataclass(frozen=True)
class Lane:
    name: str
    base: str
    tir: Callable[[], TirAdapter]
    didr: Callable[[], DidRegistryAdapter]

    def issuer_url(self, did: str) -> str:
        return self.tir().issuer_url(self.base, did)

    def did_url(self, did: str) -> str:
        return self.didr().identifiers_url(self.base, did)


V4 = Lane("v4", "https://api-pilot.ebsi.eu", TirV4, DidRegistryV5)
V5 = Lane("v5", "https://api-pilot.ebsi.eu", TirV5, DidRegistryV5)
CORE_V1 = Lane("core-v1", "https://api-preprod.ebsi.grnet.gr", TirCoreV1, DidRegistryCoreV1)
WALKS = [V5, CORE_V1]                     # the shared walk, the lanes this change touches
ALL_LANES = [V4, V5, CORE_V1]             # trust.py and the token wrap: every lane


def _lane_id(lane: Lane) -> str:
    return lane.name


def _did_doc(did: str, sk: P256SigningKey) -> dict[str, Any]:
    return {"didDocument": {"id": did, "verificationMethod": [{
        "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
        "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{did}#key-1"]}}


World = tuple[StubFetch, DidEbsiResolver, CountingDecode]


def world(lane: Lane, *tokens: Any, decode: Callable[[str], Any] = PEEK) -> World:
    """LEAF's TIR record on *lane*, holding one accreditation per token, each said to be from
    ROOT (``tao``), plus ROOT's DID document; the registry is what it says it is except for
    the tokens. On v4 the attributes are inline; on v5 / Core v1 the walk is issuer -> listing
    -> one revision per item."""
    issuer_url = lane.issuer_url(LEAF)
    routes: dict[str, Any] = {lane.did_url(ROOT): _did_doc(ROOT, ROOT_SK)}
    attributes = [{"hash": f"h{i}", "issuerType": "TI", "tao": ROOT, "rootTao": ROOT,
                   "body": token} for i, token in enumerate(tokens)]
    if lane is V4:
        routes[issuer_url] = {"did": LEAF, "attributes": attributes}
    else:
        listing = f"{issuer_url}/attributes"
        routes[issuer_url] = {"did": LEAF, "hasAttributes": True, "attributes": listing}
        routes[listing] = {"items": [{"id": a["hash"], "href": f"{listing}/{a['hash']}"}
                                     for a in attributes], "total": len(attributes)}
        for a in attributes:
            routes[f"{listing}/{a['hash']}"] = {"did": LEAF, "attribute": a}
    fetch, counted = StubFetch(routes), CountingDecode(decode)
    return fetch, DidEbsiResolver(fetch, counted, base=lane.base, didr=lane.didr(),
                                  tir=lane.tir()), counted


def _revision_urls(lane: Lane, fetch: StubFetch) -> list[str]:
    listing = f"{lane.issuer_url(LEAF)}/attributes"
    return [u for u in fetch.calls if u.startswith(f"{listing}/")]


def _vc(credential_subject: Any) -> dict[str, Any]:
    return {"id": "urn:uuid:acc-1", "type": ["VerifiableCredential",
                                             "VerifiableAccreditationToAttest"],
            "issuer": ROOT, "credentialSubject": credential_subject}


def signed(credential_subject: Any) -> str:
    """A ROOT-signed accreditation through the suite: ``sub`` is set from a dict subject's
    ``id`` and left out otherwise (an array subject, a scalar, an object with no ``id``)."""
    return SUITE.sign(_vc(credential_subject), signing_key=ROOT_SK)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jws(payload: dict[str, Any], *, header: dict[str, Any] | None = None) -> str:
    """A hand-built, ROOT-signed compact JWS: the way to control ``sub`` exactly."""
    now = int(time.time())
    claims = {"iss": ROOT, "nbf": now - 60, "iat": now - 60, "exp": now + 3600, **payload}
    head = header or {"alg": "ES256", "typ": "JWT", "kid": ROOT_SK.kid}
    h, p = _b64(json.dumps(head).encode()), _b64(json.dumps(claims).encode())
    return f"{h}.{p}.{_b64(ROOT_SK.sign(f'{h}.{p}'.encode()))}"


def chain(resolver: DidEbsiResolver, types: list[str] = TYPES) -> TrustChain:
    return verify_trust_chain(LEAF, types, resolver=resolver, proof_suite=SUITE,
                              anchors={ROOT})


def single_level(resolver: DidEbsiResolver) -> Accreditation | None:
    """Single-level trust: the record as the registry serves it, no signature checked."""
    return evaluate_issuer_trust(resolver.issuer_record(LEAF), TYPES)


def _p(value: Any) -> Any:
    return pytest.param(value, id=f"{type(value).__name__}-{json.dumps(value)[:14]}")


def _malformed(info: pytest.ExceptionInfo[Any]) -> None:
    assert type(info.value) is MalformedRegistryResponse          # the exact class
    assert isinstance(info.value, EbsiError) and isinstance(info.value, OpenvcError)


# --------------------------------------------------------------------------- #
# Headline (a): the array subject of ANOTHER DID, ROOT-signed, in LEAF's record
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_headline_a_root_signed_array_subject_of_another_did_is_refused(lane: Lane) -> None:
    # TRUSTED on main (the walk read the array as {}: unrestricted; no `sub` was set, so the
    # binding was skipped too). Now the record itself is refused, before any signature.
    _, resolver, _ = world(lane, signed([{"id": OTHER, "accreditedFor": [{"types": OTHER_TYPES}]}]))
    with pytest.raises(MalformedRegistryResponse,
                       match="TIR attribute token vc credentialSubject is not an object: list"
                       ) as info:
        chain(resolver)
    _malformed(info)
    with pytest.raises(MalformedRegistryResponse) as record_info:   # single-level reads this
        single_level(resolver)
    _malformed(record_info)


NOT_OBJECTS = [_p(v) for v in (None, 7, 0, 1.5, True, False, "x", "", "{}", [], [{}], [1])]


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("value", NOT_OBJECTS)
def test_a_credential_subject_that_is_not_an_object_is_malformed_on_the_walk(
        lane: Lane, value: Any) -> None:
    _, resolver, _ = world(lane, signed(value))
    with pytest.raises(MalformedRegistryResponse, match="credentialSubject is not an object"
                       ) as info:
        chain(resolver)
    _malformed(info)


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("value", NOT_OBJECTS)
def test_a_vc_that_is_not_an_object_is_malformed_on_the_walk(lane: Lane, value: Any) -> None:
    # recursive mode was AccreditationInvalid (the suite wants a `vc` object); single-level
    # mode TRUSTED the record as unrestricted. Both are now the record's own error.
    _, resolver, _ = world(lane, jws({"vc": value, "sub": LEAF}))
    with pytest.raises(MalformedRegistryResponse, match="TIR attribute token vc is not an object"
                       ) as info:
        chain(resolver)
    _malformed(info)
    with pytest.raises(MalformedRegistryResponse) as record_info:
        single_level(resolver)
    _malformed(record_info)


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("claims", [_p(v) for v in (None, [], "x", 7)])
def test_claims_that_are_not_an_object_are_malformed_on_the_walk(lane: Lane, claims: Any) -> None:
    # an injected `decode` that is not the suite's (the suite's own refuses these itself)
    _, resolver, _ = world(lane, "tok", decode=lambda token: claims)
    with pytest.raises(MalformedRegistryResponse, match="expected a JSON object") as info:
        resolver.issuer_record(LEAF)
    _malformed(info)


# --------------------------------------------------------------------------- #
# Headline (b): a ROOT-signed accreditation that names nobody, on EVERY lane
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_headline_b_an_accreditation_naming_no_subject_is_refused(lane: Lane) -> None:
    # TRUSTED on main: `verified.subject` was None, so the binding was skipped. The token is
    # genuinely ROOT-signed and scoped to the credential's type; only the subject is missing.
    _, resolver, _ = world(lane, signed({"accreditedFor": [{"types": TYPES}]}))
    with pytest.raises(AccreditationInvalid, match="names no subject") as info:
        chain(resolver)
    assert type(info.value) is AccreditationInvalid
    assert isinstance(info.value, EbsiError)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_headline_b_an_empty_sub_over_another_dids_subject_id_is_refused(lane: Lane) -> None:
    # TRUSTED on main: the suite skips its sub / credentialSubject.id comparison for an empty
    # `sub` and reports the subject as "", which `if verified.subject` read as "none to check"
    _, resolver, _ = world(lane, jws({"vc": _vc({"id": OTHER, "accreditedFor": [{"types": TYPES}]}),
                                      "sub": ""}))
    with pytest.raises(AccreditationInvalid,
                       match=r"accreditation subject \(sub\) '' != accredited DID") as info:
        chain(resolver)
    assert type(info.value) is AccreditationInvalid


# (sub, credentialSubject.id): ... = the member is not sent. Every row was TRUSTED on main.
ABSENT = ...
UNBOUND = [
    pytest.param(..., ..., "names no subject", id="neither"),
    pytest.param("", ..., r"subject \(sub\) ''", id="sub-empty-only"),
    pytest.param("", OTHER, r"subject \(sub\) ''", id="sub-empty-id-other"),
    pytest.param("", LEAF, r"subject \(sub\) ''", id="sub-empty-id-leaf"),
    pytest.param(..., "", r"subject \(credentialSubject.id\) ''", id="id-empty-only"),
    pytest.param(..., 7, r"subject \(credentialSubject.id\) 7", id="id-number-only"),
    pytest.param(..., None, r"subject \(credentialSubject.id\) None", id="id-null-only"),
    pytest.param(LEAF, "", r"subject \(credentialSubject.id\) ''", id="sub-leaf-id-empty"),
]


def _token(sub: Any, cs_id: Any, types: list[str] = TYPES) -> str:
    subject: dict[str, Any] = {"accreditedFor": [{"types": types}]}
    if cs_id is not ABSENT:
        subject["id"] = cs_id
    payload: dict[str, Any] = {"vc": _vc(subject)}
    if sub is not ABSENT:
        payload["sub"] = sub
    return jws(payload)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("sub, cs_id, message", UNBOUND)
def test_a_subject_that_is_sent_and_is_not_the_accredited_did_is_refused(
        lane: Lane, sub: Any, cs_id: Any, message: str) -> None:
    _, resolver, _ = world(lane, _token(sub, cs_id))
    with pytest.raises(AccreditationInvalid, match=message) as info:
        chain(resolver)
    assert type(info.value) is AccreditationInvalid
    assert isinstance(info.value, EbsiError)


# the rows the suite or the old check already refused: still refused, still the same class
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("sub, cs_id", [
    pytest.param(OTHER, ..., id="sub-other-only"),
    pytest.param(OTHER, OTHER, id="sub-other-id-other"),
    pytest.param(OTHER, LEAF, id="sub-other-id-leaf"),        # the suite: sub != id
    pytest.param(LEAF, OTHER, id="sub-leaf-id-other"),        # the suite: sub != id
    pytest.param(LEAF, 7, id="sub-leaf-id-number"),           # the suite: sub != id (7 is truthy)
    pytest.param(None, LEAF, id="sub-null"),                  # the suite: not a string
    pytest.param(7, LEAF, id="sub-number"),
    pytest.param([LEAF], LEAF, id="sub-list"),
])
def test_a_subject_of_another_did_or_type_stays_refused(lane: Lane, sub: Any, cs_id: Any) -> None:
    _, resolver, _ = world(lane, _token(sub, cs_id))
    with pytest.raises(AccreditationInvalid) as info:
        chain(resolver)
    assert type(info.value) is AccreditationInvalid


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("sub, cs_id", [
    pytest.param(LEAF, LEAF, id="both"),
    pytest.param(LEAF, ..., id="sub-only"),                   # VCDM 1.1 JWT encoding
    pytest.param(..., LEAF, id="id-only"),
])
def test_control_an_accreditation_that_names_the_accredited_did_once_or_twice_is_trusted(
        lane: Lane, sub: Any, cs_id: Any) -> None:
    _, resolver, _ = world(lane, _token(sub, cs_id))
    result = chain(resolver)
    assert result.anchor == ROOT and result.scope == frozenset(TYPES)
    assert [(h.subject, h.accreditor) for h in result.hops] == [(LEAF, ROOT)]


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_scoped_accreditation_for_another_type_is_still_no_trusted_anchor(
        lane: Lane) -> None:
    _, resolver, _ = world(lane, signed({"id": LEAF, "accreditedFor": [{"types": OTHER_TYPES}]}))
    with pytest.raises(NoTrustedAnchor):
        chain(resolver)
    assert single_level(resolver) is None


def _binding() -> Callable[..., None]:
    # imported here, not at the top: the module must still collect against `main`, which has
    # no such function, so that the headline tests can be shown red there
    from openvc_ebsi.trust import _check_subject_binding
    return _check_subject_binding


def _verified(credential_subject: Any, **claims: Any) -> VerifiedCredential:
    """A verified credential as the suite would report it, built by hand: the binding check
    reads the claims and the credential, never the suite's `subject` summary."""
    vc = _vc(credential_subject)
    return VerifiedCredential(credential=vc, issuer=ROOT, subject=claims.get("sub"),
                              claims={"iss": ROOT, "vc": vc, **claims})


def test_the_binding_refuses_a_credential_subject_that_is_not_an_object_even_with_a_sub() -> None:
    # unreachable through the walk (it refuses the shape first): the second line of defence
    check = _binding()
    for value in ([{"id": LEAF}], "x", 7, None, True, []):
        with pytest.raises(AccreditationInvalid, match="credentialSubject that is not an object"):
            check(_verified(value, sub=LEAF), subject=LEAF)


def test_the_binding_reads_the_claims_not_the_suites_subject_summary() -> None:
    # a summary that says LEAF over claims that do not: refused on the claims
    vc = _vc({"accreditedFor": []})
    verified = VerifiedCredential(credential=vc, issuer=ROOT, subject=LEAF,
                                  claims={"iss": ROOT, "vc": vc})
    check = _binding()
    with pytest.raises(AccreditationInvalid, match="names no subject"):
        check(verified, subject=LEAF)
    check(_verified({"id": LEAF}), subject=LEAF)                            # id only: fine
    check(_verified({"accreditedFor": []}, sub=LEAF), subject=LEAF)


# --------------------------------------------------------------------------- #
# (c) `accreditedFor`: the member whose misreading widens an accreditation
# --------------------------------------------------------------------------- #

WIDENED = [_p(v) for v in (                       # read as "no types" on main: TRUSTED
    {"schemaId": "s", "types": OTHER_TYPES}, "OtherType", [{"types": ""}], [7], [None],
    [["OtherType"]], [{"types": {}}], [{"types": {"OtherType": 1}}], [True], [[]],
    [{"types": [7]}], [{"types": [None]}], [{"types": [["OtherType"]]}], [{"types": [True]}])]
PARTLY_READ = [_p(v) for v in ([{"types": ["OtherType", 7]}],
                               [{"types": [None, "OtherType"]}])]   # the 7 / null was dropped
CRASHED = [_p(v) for v in ([{"types": 7}], [{"types": None}], [{"types": True}],
                           [{"types": 1.5}])]    # a bare TypeError on main
SPLIT = [_p(v) for v in ([{"types": "OtherType"}], [{"types": "OpenBadgeCredential"}])]


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("value", WIDENED + CRASHED + SPLIT + PARTLY_READ)
def test_an_accredited_for_the_reader_does_not_know_is_malformed_on_the_walk(
        lane: Lane, value: Any) -> None:
    _, resolver, _ = world(lane, signed({"id": LEAF, "accreditedFor": value}))
    with pytest.raises(MalformedRegistryResponse, match="accreditedFor") as info:
        chain(resolver)
    _malformed(info)
    with pytest.raises(MalformedRegistryResponse) as record_info:
        single_level(resolver)
    _malformed(record_info)


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("value", WIDENED + CRASHED + SPLIT + PARTLY_READ)
def test_the_walk_and_v4_give_the_same_message_for_the_same_shape(lane: Lane, value: Any) -> None:
    # one reader on every lane: the message names the member and the value the same way
    token = signed({"id": LEAF, "accreditedFor": value})
    with pytest.raises(MalformedRegistryResponse) as on_v4:
        world(V4, token)[1].issuer_record(LEAF)
    with pytest.raises(MalformedRegistryResponse) as on_walk:
        world(lane, token)[1].issuer_record(LEAF)
    assert str(on_walk.value) == str(on_v4.value)


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("accredited_for, expected", [
    pytest.param(..., (), id="absent"),
    pytest.param([], (), id="empty-list"),
    pytest.param([{}], (), id="object-without-types"),
    pytest.param([{"schemaId": "s"}], (), id="schema-only"),
    pytest.param([{"types": []}], (), id="empty-types"),
    pytest.param(["A", "B"], ("A", "B"), id="plain-strings"),
    pytest.param([{"schemaId": "s", "types": ["A", "B"]}], ("A", "B"), id="objects"),
    pytest.param(["A", {"types": ["B", "A"]}, {"types": ["C"]}], ("A", "B", "C"), id="mixed"),
])
def test_control_the_shapes_the_walk_read_keep_their_reading(
        lane: Lane, accredited_for: Any, expected: tuple[str, ...]) -> None:
    subject: dict[str, Any] = {"id": LEAF}
    if accredited_for is not ...:
        subject["accreditedFor"] = accredited_for
    record = world(lane, signed(subject))[1].issuer_record(LEAF)
    assert record.accreditations[0].credential_types == expected


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("claims", [
    pytest.param({}, id="no-vc"),
    pytest.param({"vc": {}}, id="vc-empty"),
    pytest.param({"vc": {"credentialSubject": {}}}, id="subject-empty"),
])
def test_control_an_absent_vc_or_subject_still_reads_as_no_types(
        lane: Lane, claims: dict[str, Any]) -> None:
    record = world(lane, "tok", decode=lambda token: claims)[1].issuer_record(LEAF)
    assert record.accreditations[0].credential_types == ()


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("body", [None, ""], ids=["null", "empty"])
def test_control_no_body_is_still_no_types_and_decode_never_runs(lane: Lane, body: Any) -> None:
    fetch, resolver, counted = world(lane, body)
    record = resolver.issuer_record(LEAF)
    assert record.accreditations[0].credential_types == ()
    assert record.accreditations[0].credential_jwt == body
    assert counted.tokens == []


# --------------------------------------------------------------------------- #
# one bad accreditation rejects the WHOLE record
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_one_bad_accreditation_after_a_good_one_rejects_the_record(lane: Lane) -> None:
    good = signed({"id": LEAF, "accreditedFor": [{"types": TYPES}]})
    bad = signed({"id": LEAF, "accreditedFor": [{"types": 7}]})
    fetch, resolver, counted = world(lane, good, bad)
    with pytest.raises(MalformedRegistryResponse, match=r"accreditedFor\[0\] types") as info:
        resolver.issuer_record(LEAF)
    _malformed(info)
    # the walk reads each revision as it fetches it: the good one was fetched and decoded, the
    # bad one raised, and nothing came back
    assert _revision_urls(lane, fetch) == [f"{lane.issuer_url(LEAF)}/attributes/h0",
                                           f"{lane.issuer_url(LEAF)}/attributes/h1"]
    assert counted.tokens == [good, bad]


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_a_bad_first_accreditation_stops_the_walk_before_the_second_is_fetched(lane: Lane) -> None:
    bad = signed({"id": LEAF, "accreditedFor": "OpenBadgeCredential"})
    good = signed({"id": LEAF, "accreditedFor": [{"types": TYPES}]})
    fetch, resolver, counted = world(lane, bad, good)
    with pytest.raises(MalformedRegistryResponse, match="accreditedFor is not a list"):
        chain(resolver)
    assert _revision_urls(lane, fetch) == [f"{lane.issuer_url(LEAF)}/attributes/h0"]
    assert counted.tokens == [bad]


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_a_good_accreditation_beside_a_bad_one_does_not_rescue_the_chain(lane: Lane) -> None:
    # the good one alone closes the chain; next to the bad one the record is refused as a whole
    good = signed({"id": LEAF, "accreditedFor": [{"types": TYPES}]})
    assert chain(world(lane, good)[1]).anchor == ROOT
    with pytest.raises(MalformedRegistryResponse):
        chain(world(lane, good, signed([{"id": OTHER}]))[1])


# --------------------------------------------------------------------------- #
# (d) a body the suite cannot read: typed, on every lane, in both entry points
# --------------------------------------------------------------------------- #

UNREADABLE = [pytest.param("not-a-jws", id="one-segment"),
              pytest.param("a.b.c", id="not-base64url-json"),
              pytest.param("eyJhIjoxfQ.W10.sig", id="array-payload")]


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("body", UNREADABLE)
def test_a_body_the_suite_cannot_read_is_malformed_not_a_proof_error(lane: Lane, body: str) -> None:
    for call in (lambda r: r.issuer_record(LEAF), chain):
        _, resolver, _ = world(lane, body)
        with pytest.raises(MalformedRegistryResponse,
                           match="TIR attribute token is not a readable JWS") as info:
            call(resolver)
        _malformed(info)
        assert type(info.value.__cause__) is MalformedToken         # the suite's error, kept


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_token_whose_header_alone_is_unreadable_is_accreditation_invalid(lane: Lane) -> None:
    # `peek_claims` reads the payload, so the record is built (pinned); `peek_issuer` reads the
    # header too, and its MalformedToken used to escape verify_trust_chain
    _, payload, signature = signed({"id": LEAF, "accreditedFor": [{"types": TYPES}]}).split(".")
    _, resolver, _ = world(lane, f"!!!!.{payload}.{signature}")
    record = resolver.issuer_record(LEAF)
    assert record.accreditations[0].credential_types == tuple(TYPES)
    with pytest.raises(AccreditationInvalid, match="is not a readable token") as info:
        chain(resolver)
    assert type(info.value) is AccreditationInvalid
    assert type(info.value.__cause__) is MalformedToken


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_body_of_another_type_is_still_typed_before_decode(lane: Lane) -> None:
    # #337's scalar check runs first: `decode` is never handed a number
    _, resolver, counted = world(lane, 7)
    with pytest.raises(MalformedRegistryResponse, match="body is not a string"):
        resolver.issuer_record(LEAF)
    assert counted.tokens == []


# --------------------------------------------------------------------------- #
# the message is bounded and cannot raise
# --------------------------------------------------------------------------- #

class RaisingRepr:
    def __repr__(self) -> str:
        raise RuntimeError("repr must not be called")

    __str__ = __repr__


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
@pytest.mark.parametrize("claims", [
    pytest.param({"vc": {"credentialSubject": "x" * 100_000}}, id="long-subject"),
    pytest.param({"vc": {"credentialSubject": {"accreditedFor": "x" * 100_000}}},
                 id="long-accredited-for"),
    pytest.param({"vc": {"credentialSubject": {"accreditedFor": [{"types": "x" * 100_000}]}}},
                 id="long-types"),
    pytest.param({"vc": "y" * 100_000}, id="long-vc"),
    pytest.param({"vc": {"credentialSubject": RaisingRepr()}}, id="raising-repr"),
    pytest.param({"vc": {"credentialSubject": {"accreditedFor": [{"types": RaisingRepr()}]}}},
                 id="raising-repr-types"),
])
def test_a_hostile_value_in_the_token_is_not_echoed_in_full(lane: Lane, claims: Any) -> None:
    _, resolver, _ = world(lane, "tok", decode=lambda token: claims)
    with pytest.raises(MalformedRegistryResponse) as info:
        resolver.issuer_record(LEAF)
    _malformed(info)
    assert len(str(info.value)) < MESSAGE_BOUND and "x" * 201 not in str(info.value)


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_deep_nesting_in_the_token_is_named_by_its_type_not_walked(lane: Lane) -> None:
    deep: Any = []
    for _ in range(20_000):
        deep = [deep]
    for claims in ({"vc": deep}, {"vc": {"credentialSubject": deep}},
                   {"vc": {"credentialSubject": {"accreditedFor": deep}}}):
        _, resolver, _ = world(lane, "tok", decode=lambda token: claims)
        with pytest.raises(MalformedRegistryResponse) as info:
            resolver.issuer_record(LEAF)
        assert len(str(info.value)) < MESSAGE_BOUND


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_long_suite_error_is_bounded_in_the_wrapped_message(lane: Lane) -> None:
    def decode(token: str) -> Any:
        raise MalformedToken("z" * 100_000)
    _, resolver, _ = world(lane, "tok", decode=decode)
    with pytest.raises(MalformedRegistryResponse) as info:
        resolver.issuer_record(LEAF)
    assert len(str(info.value)) < MESSAGE_BOUND and "z" * 201 not in str(info.value)
    assert type(info.value.__cause__) is MalformedToken


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_subject_that_is_attacker_sized_is_bounded_in_the_binding_message(lane: Lane) -> None:
    big = "did:ebsi:z" + "B" * 60_000
    _, resolver, _ = world(lane, _token(big, ...))
    with pytest.raises(AccreditationInvalid) as info:
        chain(resolver)
    assert len(str(info.value)) < MESSAGE_BOUND


# --------------------------------------------------------------------------- #
# what the walk still SKIPS: a listing item it cannot follow (narrows, never widens)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_control_a_listing_item_the_walk_cannot_follow_is_still_skipped(lane: Lane) -> None:
    good = signed({"id": LEAF, "accreditedFor": [{"types": TYPES}]})
    fetch, resolver, _ = world(lane, good)
    listing = f"{lane.issuer_url(LEAF)}/attributes"
    fetch.routes[listing]["items"] = [7, {"id": "x"}, {"id": "y", "href": ""},
                                      {"id": "z", "href": "https://evil.example/r"},
                                      *fetch.routes[listing]["items"]]
    fetch.routes[listing]["total"] = 5
    record = resolver.issuer_record(LEAF)
    assert [a.credential_jwt for a in record.accreditations] == [good]   # the one followable
    assert not any("evil.example" in u for u in fetch.calls)
    # and with nothing followable the record has no accreditation: untrusted, never widened
    fetch.routes[listing]["items"] = [7]
    fetch.routes[listing]["total"] = 1
    assert resolver.issuer_record(LEAF).accreditations == ()
    with pytest.raises(NoTrustedAnchor):
        chain(resolver)


# --------------------------------------------------------------------------- #
# through `for_nodes` (the production client, Core v1 by default)
# --------------------------------------------------------------------------- #

NODE = "https://api.ebsi.node-a.example"
NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _node_client(routes: dict[str, Any]) -> Any:
    expires = NOW + timedelta(days=60)
    result = VerifiedNodeList(
        environment="prod", version=4, keys_version=1, issued=NOW - timedelta(days=30),
        expires=expires, nodes=(Node(NODE, NODE[len("https://"):], "XX", "Example"),),
        accepted_list=Accepted(4, "0" * 64), accepted_keys=Accepted(1, "0" * 64))
    client = for_nodes(result, clock=lambda: NOW, decode_jwt=PEEK, address_guard=None)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/alive":
            return httpx.Response(200, json={"health_global": 1})
        body = routes.get(str(request.url))
        return httpx.Response(404 if body is None else 200, json=body)

    client.http._client.close()
    client.http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def test_a_wrong_typed_types_reaches_the_for_nodes_caller_as_an_ebsi_error() -> None:
    # on main a bare TypeError, which the node client's `except EbsiError` never saw
    lane = Lane("core-v1", NODE, TirCoreV1, DidRegistryCoreV1)
    fetch, _, _ = world(lane, signed({"id": LEAF, "accreditedFor": [{"types": 7}]}))
    client = _node_client(fetch.routes)
    try:
        with pytest.raises(MalformedRegistryResponse) as info:
            client.run(lambda session: session.resolver.issuer_record(LEAF))
        _malformed(info)
    finally:
        client.close()


def test_a_nameless_accreditation_is_refused_through_for_nodes() -> None:
    lane = Lane("core-v1", NODE, TirCoreV1, DidRegistryCoreV1)
    fetch, _, _ = world(lane, signed({"accreditedFor": [{"types": TYPES}]}))
    client = _node_client(fetch.routes)
    try:
        with pytest.raises(AccreditationInvalid, match="names no subject"):
            client.run(lambda session: verify_trust_chain(
                LEAF, TYPES, resolver=session.resolver, proof_suite=SUITE, anchors={ROOT}))
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# `verify_ebsi_badge(require_trust=False)`: the record's error is not suppressed
# --------------------------------------------------------------------------- #

LEAF_SK = P256SigningKey.generate(kid=f"{LEAF}#key-1")
BADGE = SUITE.sign({"id": "urn:uuid:badge-1",
                    "type": ["VerifiableCredential", "VerifiableAttestation", TYPES[0]],
                    "issuer": LEAF, "credentialSubject": {"id": "did:key:z6MkSubject"}},
                   signing_key=LEAF_SK)


def _badge_world(lane: Lane, token: str) -> DidEbsiResolver:
    fetch, resolver, _ = world(lane, token)
    fetch.routes[lane.did_url(LEAF)] = _did_doc(LEAF, LEAF_SK)
    return resolver


@pytest.mark.parametrize("lane", WALKS, ids=_lane_id)
def test_require_trust_false_does_not_suppress_the_records_error(lane: Lane) -> None:
    # main: `trusted=True` (the array subject read as unrestricted). MalformedRegistryResponse
    # is not a TrustChainError: malformed input is not an untrusted issuer (#267)
    resolver = _badge_world(lane, signed([{"id": OTHER, "accreditedFor": [{"types": TYPES}]}]))
    with pytest.raises(MalformedRegistryResponse) as info:
        verify_ebsi_badge(BADGE, resolver=resolver, proof_suite=SUITE, require_trust=False)
    _malformed(info)
    # the control: a scoped accreditation for another type is untrusted, not an error
    resolver = _badge_world(lane, signed({"id": LEAF, "accreditedFor": [{"types": OTHER_TYPES}]}))
    result = verify_ebsi_badge(BADGE, resolver=resolver, proof_suite=SUITE, require_trust=False)
    assert result.trusted is False


# --------------------------------------------------------------------------- #
# found by the adversarial review of the PR
# --------------------------------------------------------------------------- #

class Flip(list):                       # type: ignore[type-arg]
    """A list whose SECOND iteration is empty: a check that iterates once and a reader that
    iterates again would disagree, and "no types" is the unrestricted accreditation."""

    def __init__(self, first: list[Any]) -> None:
        super().__init__(first)
        self.reads = 0

    def __iter__(self) -> Any:
        self.reads += 1
        return iter(list.__iter__(self) if self.reads == 1 else [])


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_accredited_for_is_checked_and_read_in_one_pass(lane: Lane) -> None:
    flip = Flip([{"types": OTHER_TYPES}])
    _, resolver, _ = world(lane, "tok", decode=lambda token: {
        "vc": {"credentialSubject": {"accreditedFor": flip}}})
    record = resolver.issuer_record(LEAF)
    assert record.accreditations[0].credential_types == tuple(OTHER_TYPES)   # what was checked
    assert flip.reads == 1


class SplitsAsAnother(str):
    """Its characters are one token; its ``.split`` answers with another's segments (what
    ``peek_claims`` used to call), while ``.encode`` (what the suite verifies) is the first."""

    other: str = ""

    def split(self, *args: Any, **kwargs: Any) -> list[str]:
        return str.split(self.other, *args, **kwargs)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_str_subclass_body_is_read_as_its_characters(lane: Lane) -> None:
    # main: the record read the UNRESTRICTED token's types while ROOT had signed OtherType,
    # and the chain was TRUSTED for the credential's type
    scoped = signed({"id": LEAF, "accreditedFor": [{"types": OTHER_TYPES}]})
    unrestricted = signed({"id": LEAF})
    body = SplitsAsAnother(scoped)
    body.other = unrestricted
    fetch, resolver, _ = world(lane, scoped)
    for value in fetch.routes.values():                 # swap every copy of the body
        for attribute in value.get("attributes", []) if lane is V4 else []:
            attribute["body"] = body
        if "attribute" in value:
            value["attribute"]["body"] = body
    record = resolver.issuer_record(LEAF)
    assert type(record.accreditations[0].credential_jwt) is str
    assert record.accreditations[0].credential_types == tuple(OTHER_TYPES)
    with pytest.raises(NoTrustedAnchor):
        chain(resolver)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_binding_honours_credential_subject_at_id(lane: Lane) -> None:
    # `@id` is what `id` aliases in JSON-LD, and the suite honours it for `issuer`
    _, resolver, _ = world(lane, jws({"sub": LEAF, "vc": _vc(
        {"@id": OTHER, "accreditedFor": [{"types": TYPES}]})}))
    with pytest.raises(AccreditationInvalid,
                       match=r"subject \(credentialSubject.@id\) 'did:ebsi") as info:
        chain(resolver)
    assert type(info.value) is AccreditationInvalid
    # and alone it binds: nothing else names the DID
    _, resolver, _ = world(lane, jws({"vc": _vc(
        {"@id": LEAF, "accreditedFor": [{"types": TYPES}]})}))
    assert chain(resolver).anchor == ROOT
    # both spellings sent: each must be the DID
    _, resolver, _ = world(lane, jws({"vc": _vc(
        {"id": LEAF, "@id": OTHER, "accreditedFor": [{"types": TYPES}]})}))
    with pytest.raises(AccreditationInvalid, match=r"credentialSubject.@id"):
        chain(resolver)


STATUS_URL = "https://tao.example/acc-status/1"


def _status_list(*set_bits: int) -> dict[str, Any]:
    bits = bytearray(32)
    for index in set_bits:
        bits[index // 8] |= 1 << (7 - index % 8)
    return {"credentialSubject": {"statusPurpose": "revocation",
                                  "encodedList": encode_bitstring(bytes(bits))}}


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
@pytest.mark.parametrize("status", [
    pytest.param("x", id="string"), pytest.param([1], id="list-of-numbers"),
    pytest.param({"type": "BitstringStatusListEntry"}, id="entry-without-list"),
    pytest.param({"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
                  "statusListCredential": 7, "statusListIndex": "3"}, id="list-url-number"),
])
def test_a_credential_status_the_status_module_refuses_is_accreditation_invalid(
        lane: Lane, status: Any) -> None:
    # the token is ROOT-signed for LEAF, so only the accreditor can put this shape there; main
    # let the status module's StatusListError (an OpenvcError, not an EbsiError) escape
    vc = {**_vc({"id": LEAF, "accreditedFor": [{"types": TYPES}]}), "credentialStatus": status}
    _, resolver, _ = world(lane, jws({"sub": LEAF, "vc": vc}))
    with pytest.raises(AccreditationInvalid, match="credentialStatus that cannot be checked"
                       ) as info:
        verify_trust_chain(LEAF, TYPES, resolver=resolver, proof_suite=SUITE, anchors={ROOT},
                           resolve_status_list=lambda url: _status_list())
    assert type(info.value) is AccreditationInvalid
    assert isinstance(info.value.__cause__, StatusListError)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_well_formed_credential_status_is_still_checked(lane: Lane) -> None:
    entry = {"id": f"{STATUS_URL}#3", "type": "BitstringStatusListEntry",
             "statusPurpose": "revocation", "statusListIndex": "3",
             "statusListCredential": STATUS_URL}
    vc = {**_vc({"id": LEAF, "accreditedFor": [{"types": TYPES}]}), "credentialStatus": entry}
    _, resolver, _ = world(lane, jws({"sub": LEAF, "vc": vc}))
    clear = verify_trust_chain(LEAF, TYPES, resolver=resolver, proof_suite=SUITE, anchors={ROOT},
                               resolve_status_list=lambda url: _status_list())
    assert clear.anchor == ROOT
    from openvc_ebsi.trust import AccreditationRevoked
    with pytest.raises(AccreditationRevoked):
        verify_trust_chain(LEAF, TYPES, resolver=resolver, proof_suite=SUITE, anchors={ROOT},
                           resolve_status_list=lambda url: _status_list(3))


# --------------------------------------------------------------------------- #
# the recorded walks parse exactly as before
# --------------------------------------------------------------------------- #

TYPES_TRUST = ("VerifiableCredential", "VerifiableAttestation",
               "VerifiableAuthorisationForTrustChain")
TYPES_TNL = ("VerifiableCredential", "VerifiableAttestation", "TrustedNodesList")


def _json(path: Path) -> Any:
    return json.loads(path.read_bytes())


@dataclass(frozen=True)
class Recorded:
    """One recorded walk: the issuer response, the listing and one revision per item."""
    name: str
    tir: Callable[[], TirAdapter]
    base: str
    routes: dict[str, Any]
    issuer_url: str
    listing_url: str
    types: tuple[tuple[str, ...], ...]

    @property
    def did(self) -> str:
        return str(self.routes[self.issuer_url]["did"])


def _v5_recorded() -> Recorded:
    base = "https://api-pilot.ebsi.eu"
    issuer = _json(FIXTURES / "tir_v5_issuer.json")
    listing = _json(FIXTURES / "tir_v5_attributes.json")
    revisions = _json(FIXTURES / "tir_v5_revisions.json")
    issuer_url = f"{base}/trusted-issuers-registry/v5/issuers/{issuer['did']}"
    routes: dict[str, Any] = {issuer_url: issuer, issuer["attributes"]: listing}
    for item in listing["items"]:
        routes[item["href"]] = revisions[item["id"]]
    return Recorded("v5", TirV5, base, routes, issuer_url, issuer["attributes"],
                    (TYPES_TRUST, TYPES_TNL, TYPES_TNL))


def _core_recorded(node: str, attribute_file: str, base: str) -> Recorded:
    issuer = _json(CORE / node / "issuer.json")
    listing = _json(CORE / node / "attributes.json")
    revision = _json(CORE / node / attribute_file)
    issuer_url = TirCoreV1().issuer_url(base, issuer["did"])
    routes = {issuer_url: issuer, issuer["attributes"]: listing,
              listing["items"][0]["href"]: revision}
    return Recorded(f"core-v1/{node}", TirCoreV1, base, routes, issuer_url,
                    issuer["attributes"], (TYPES_TRUST,))


RECORDED = [
    _v5_recorded(),
    _core_recorded("preprod-grnet", "attribute_0dc6a111.json", "https://api-preprod.ebsi.grnet.gr"),
    _core_recorded("preprod-incm", "attribute_0dc6a111.json", "https://api-preprod.ebsi.incm.pt"),
    _core_recorded("prod-iti", "attribute_030c5a3d.json", "https://api.ebsi.iti.gr"),
]


def _expected(rec: Recorded) -> IssuerRecord:
    """The record the RECORDED wire values spell, written from the fixture, not the adapter."""
    items = rec.routes[rec.listing_url]["items"]
    accs = tuple(
        Accreditation(attribute_id=item["id"], issuer_type=attribute["issuerType"],
                      tao=attribute["tao"], root_tao=attribute["rootTao"],
                      credential_types=types, credential_jwt=attribute["body"],
                      accreditation_types=tuple(PEEK(attribute["body"])["vc"]["type"]))
        for item, types in zip(items, rec.types, strict=True)
        for attribute in [rec.routes[item["href"]]["attribute"]])
    return IssuerRecord(did=rec.did, has_attributes=True, accreditations=accs)


@pytest.mark.parametrize("rec", RECORDED, ids=lambda r: r.name)
def test_control_every_recorded_walk_parses_to_the_wire_values(rec: Recorded) -> None:
    fetch, counted = StubFetch(copy.deepcopy(rec.routes)), CountingDecode()
    resolver = DidEbsiResolver(fetch, counted, base=rec.base, tir=rec.tir())
    assert resolver.issuer_record(rec.did) == _expected(rec)
    assert counted.tokens == [rec.routes[item["href"]]["attribute"]["body"]
                              for item in rec.routes[rec.listing_url]["items"]]
