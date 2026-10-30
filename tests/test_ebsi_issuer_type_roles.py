"""
tests/test_ebsi_issuer_type_roles.py — the TIR ``issuerType`` is an exact allow-list (#358).

Both registries render the on-chain issuer type as a name. The legacy Trusted Issuers
Registry API v5 (``https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/openapi.json``,
``info.version`` 5.0.0, read 2026-10-30) describes ``attribute.issuerType`` as "RootTAO, TAO,
TI, Revoked or Undefined"; the EBSI Core API v1 (``/v1/openapi.json`` on every node, served
with ``Accept: application/openapi+json``, ``info.version`` 1.0.0, read the same day from
``api.ebsi.iti.gr``) enumerates ``["undefined", "RootTAO", "TAO", "TI", "Revoked"]`` and says
"``undefined`` (lowercase) is returned for type 0". The recorded fixtures hold ``RootTAO`` only.

On ``main`` at b0feaeb ``Accreditation.is_revoked`` compared with the lowercase ``revoked``,
which neither API emits, and nothing checked that the role is one of the three live ones, so an
accreditation the registry had **revoked** (``issuerType: "Revoked"``) was eligible on every lane
(v4, v5, Core v1) for single-level trust (``evaluate_issuer_trust``) and for the recursive walk
(``_pick_accreditation``), and so was ``undefined``, an empty or absent member and any other
string; and the walk accepted an accreditation signed by an accreditor whose own record said
``TI`` (a TI accrediting a TI). Now an accreditation is eligible only if its ``issuerType`` is
exactly ``RootTAO``, ``TAO`` or ``TI`` (``TRUST_ROLES``), and above the leaf only ``RootTAO`` or
``TAO`` (``DELEGATING_ROLES``) can delegate; ``is_revoked`` reads the wire spelling ``Revoked``
(and the pre-1.38 lowercase). The messages name the roles set aside, bounded.

Controls: the live roles stay eligible, and the recorded RootTAO accreditations keep a live role.
No cross-import: ``tests/`` is not a package, so the lane scaffold is local to this file.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.models import (
    DELEGATING_ROLES,
    REVOKED_ROLE,
    TRUST_ROLES,
    Accreditation,
    IssuerRecord,
)
from openvc_ebsi.trust import (
    NoTrustedAnchor,
    TrustChain,
    ineligible_note,
    verify_trust_chain,
)
from openvc_ebsi.verify import IssuerNotTrusted, evaluate_issuer_trust, verify_ebsi_badge
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
SUITE = VcJwtProofSuite()
TYPES = ["OpenBadgeCredential"]
MESSAGE_BOUND = 400
ABSENT = object()                         # the attribute has no `issuerType` member at all


def _did(seed: int) -> str:
    # a well-formed did:ebsi identifier (#266): `z` + base58btc(version byte 1 || 16 bytes)
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, MID, ROOT = _did(0xA1), _did(0xB2), _did(0xC3)
LEAF_SK = P256SigningKey.generate(kid=f"{LEAF}#key-1")
MID_SK = P256SigningKey.generate(kid=f"{MID}#key-1")
ROOT_SK = P256SigningKey.generate(kid=f"{ROOT}#key-1")
KEYS = {LEAF: LEAF_SK, MID: MID_SK, ROOT: ROOT_SK}


# --------------------------------------------------------------------------- #
# Harness: records on each lane, one attribute per (token, role, tao)
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
ALL_LANES = [V4, V5, CORE_V1]


def _lane_id(lane: Lane) -> str:
    return lane.name


def _did_doc(did: str, sk: P256SigningKey) -> dict[str, Any]:
    return {"didDocument": {"id": did, "verificationMethod": [{
        "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
        "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{did}#key-1"]}}


def accreditation(*, subject: str, accredited_by: str, types: list[str] | None = TYPES,
                  kind: str = "VerifiableAccreditationToAttest") -> str:
    """A genuine accreditation VC-JWT signed by *accredited_by*'s key for *subject*. ``types``
    ``None`` leaves ``accreditedFor`` out (the unrestricted shape ``main`` accepts for any type;
    its policy is #368's, not this file's)."""
    cs: dict[str, Any] = {"id": subject}
    if types is not None:
        cs["accreditedFor"] = [{"types": list(types)}]
    vc = {"id": f"urn:uuid:acc-{subject[-6:]}", "type": ["VerifiableCredential", kind],
          "issuer": accredited_by, "credentialSubject": cs}
    return SUITE.sign(vc, signing_key=KEYS[accredited_by])


def attribute(token: str, role: Any, *, tao: str, tag: str) -> dict[str, Any]:
    """One TIR attribute as the registry serves it; ``role`` ABSENT leaves the member out."""
    a: dict[str, Any] = {"hash": tag, "tao": tao, "rootTao": ROOT, "body": token}
    if role is not ABSENT:
        a["issuerType"] = role
    return a


def registry(lane: Lane, records: dict[str, list[dict[str, Any]]]) -> DidEbsiResolver:
    """The lane's registry holding *records* (DID -> attributes) and a DID document for every
    DID in KEYS. v4 serves the attributes inline; v5 and Core v1 as issuer -> listing -> one
    revision per item, the shape the recorded fixtures have."""
    routes: dict[str, Any] = {lane.did_url(d): _did_doc(d, sk) for d, sk in KEYS.items()}
    for did, attributes in records.items():
        issuer_url = lane.issuer_url(did)
        if lane is V4:
            routes[issuer_url] = {"did": did, "attributes": attributes}
            continue
        listing = f"{issuer_url}/attributes"
        routes[issuer_url] = {"did": did, "hasAttributes": True, "attributes": listing}
        routes[listing] = {"items": [{"id": a["hash"], "href": f"{listing}/{a['hash']}"}
                                     for a in attributes], "total": len(attributes)}
        for a in attributes:
            routes[f"{listing}/{a['hash']}"] = {"did": did, "attribute": a}
    return DidEbsiResolver(StubFetch(routes), SUITE.peek_claims, base=lane.base,
                           didr=lane.didr(), tir=lane.tir())


def one_hop(lane: Lane, role: Any, *, types: list[str] | None = TYPES) -> DidEbsiResolver:
    """LEAF accredited by ROOT (the anchor) in one hop; the attribute carries *role*."""
    token = accreditation(subject=LEAF, accredited_by=ROOT, types=types)
    return registry(lane, {LEAF: [attribute(token, role, tao=ROOT, tag="leaf")]})


def two_hops(lane: Lane, mid_role: Any, *, leaf_role: str = "TI") -> DidEbsiResolver:
    """LEAF accredited by MID, MID accredited by ROOT (the anchor): MID's own attribute, read
    from MID's record when the walk climbs, carries *mid_role*."""
    leaf = accreditation(subject=LEAF, accredited_by=MID)
    mid = accreditation(subject=MID, accredited_by=ROOT, kind="VerifiableAccreditationToAccredit")
    return registry(lane, {LEAF: [attribute(leaf, leaf_role, tao=MID, tag="leaf")],
                           MID: [attribute(mid, mid_role, tao=ROOT, tag="mid")]})


def chain(resolver: DidEbsiResolver) -> TrustChain:
    return verify_trust_chain(LEAF, TYPES, resolver=resolver, proof_suite=SUITE, anchors={ROOT})


def single_level(resolver: DidEbsiResolver) -> Accreditation | None:
    return evaluate_issuer_trust(resolver.issuer_record(LEAF), TYPES)


def badge() -> str:
    return SUITE.sign({"@context": ["https://www.w3.org/2018/credentials/v1"],
                       "id": "urn:uuid:badge-1",
                       "type": ["VerifiableCredential", "VerifiableAttestation", *TYPES],
                       "issuer": LEAF, "credentialSubject": {"id": "did:key:z6MkSubject"}},
                      signing_key=LEAF_SK)


# --------------------------------------------------------------------------- #
# Controls: the live roles, and the recorded registries
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("role", sorted(TRUST_ROLES))
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_live_role_is_eligible_at_the_leaf(lane: Lane, role: str) -> None:
    resolver = one_hop(lane, role)
    assert chain(resolver).anchor == ROOT
    picked = single_level(resolver)
    assert picked is not None and picked.issuer_type == role


@pytest.mark.parametrize("mid_role", sorted(DELEGATING_ROLES))
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_tao_or_a_roottao_can_accredit(lane: Lane, mid_role: str) -> None:
    c = chain(two_hops(lane, mid_role))
    assert [(h.subject, h.accreditor) for h in c.hops] == [(LEAF, MID), (MID, ROOT)]
    assert c.hops[1].accreditation.issuer_type == mid_role


def test_the_vocabulary_is_the_registries() -> None:
    assert TRUST_ROLES == frozenset({"RootTAO", "TAO", "TI"})
    assert DELEGATING_ROLES == frozenset({"RootTAO", "TAO"}) and DELEGATING_ROLES < TRUST_ROLES
    assert REVOKED_ROLE == "Revoked"                 # the spelling both OpenAPI documents use


def _issuer_types(obj: Any) -> set[str]:
    """Every ``issuerType`` string anywhere in a recorded response, JSON-string bodies included."""
    if isinstance(obj, dict):
        found = {v for k, v in obj.items() if k == "issuerType" and isinstance(v, str)}
        for value in obj.values():
            found |= _issuer_types(value)
        return found
    if isinstance(obj, list):
        return set().union(*(_issuer_types(v) for v in obj)) if obj else set()
    if isinstance(obj, str) and obj[:1] in "{[":
        try:
            return _issuer_types(json.loads(obj))
        except ValueError:
            return set()
    return set()


def test_control_the_recorded_registries_carry_a_live_role_only() -> None:
    # the fixtures are the drift alarm: every role the recorded v5 and Core v1 responses carry
    seen: set[str] = set()
    for path in sorted(FIXTURES.rglob("*.json")):
        seen |= _issuer_types(json.loads(path.read_text()))
    assert seen == {"RootTAO"} and seen <= TRUST_ROLES


# --------------------------------------------------------------------------- #
# Headline: an accreditation the registry REVOKED, as the registry spells it
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_headline_a_revoked_accreditation_is_refused_on_every_lane(lane: Lane) -> None:
    resolver = one_hop(lane, "Revoked")
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as info:
        chain(resolver)
    assert "'Revoked'" in str(info.value)
    assert single_level(resolver) is None
    # and through the public entry point, both trust modes
    with pytest.raises(IssuerNotTrusted, match="no valid accreditation"):
        verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE)
    with pytest.raises(NoTrustedAnchor):
        verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE, trust_anchors={ROOT})
    assert verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE,
                             require_trust=False).trusted is False


# --------------------------------------------------------------------------- #
# Everything outside the allow-list is set aside
# --------------------------------------------------------------------------- #

NOT_A_LIVE_ROLE = [
    pytest.param(ABSENT, id="absent"),
    pytest.param("", id="empty"),
    pytest.param("undefined", id="undefined-core-v1-type-0"),
    pytest.param("Undefined", id="Undefined-v5"),
    pytest.param("Revoked", id="Revoked"),
    pytest.param("revoked", id="revoked-lowercase"),
    pytest.param("REVOKED", id="REVOKED"),
    pytest.param("RootTAO ", id="trailing-space"),
    pytest.param(" TI", id="leading-space"),
    pytest.param("ti", id="ti-lowercase"),
    pytest.param("tao", id="tao-lowercase"),
    pytest.param("roottao", id="roottao-lowercase"),
    pytest.param("Roottao", id="Roottao"),
    pytest.param("TI​", id="zero-width-space"),
    pytest.param("TAO,TI", id="two-roles"),
    pytest.param("3", id="the-integer-as-text"),
    pytest.param("Banana", id="Banana"),
]


@pytest.mark.parametrize("role", NOT_A_LIVE_ROLE)
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_role_outside_the_vocabulary_is_not_eligible(lane: Lane, role: Any) -> None:
    resolver = one_hop(lane, role)
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation"):
        chain(resolver)
    assert single_level(resolver) is None


@pytest.mark.parametrize("role", ["Revoked", "undefined", "Banana"])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_role_rule_runs_before_the_type_rule(lane: Lane, role: str) -> None:
    # an accreditation with no `accreditedFor` is the unrestricted one on `main` (#368 decides
    # that policy); whatever it authorises, an ineligible role authorises nothing
    resolver = one_hop(lane, role, types=None)
    with pytest.raises(NoTrustedAnchor):
        chain(resolver)
    assert single_level(resolver) is None


@pytest.mark.parametrize("mid_role", [
    pytest.param("TI", id="a-TI-accrediting"),
    pytest.param("Revoked", id="a-revoked-accreditor"),
    pytest.param("undefined", id="an-undefined-accreditor"),
    pytest.param("", id="an-empty-role"),
    pytest.param(ABSENT, id="an-absent-role"),
])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_only_a_tao_or_a_roottao_can_accredit(lane: Lane, mid_role: Any) -> None:
    # the hop above the leaf: MID's own accreditation, read from MID's record, must say that
    # MID may accredit; a TI's record may hold a perfectly signed accreditation and still not
    # delegate (EBSI's model: a TAO or RootTAO accredits, a TI attests)
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as info:
        chain(two_hops(lane, mid_role))
    assert MID in str(info.value)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_record_mixing_roles_picks_only_an_eligible_one(lane: Lane) -> None:
    # two attributes for LEAF: a revoked one first, a live one second -> the live one is picked
    revoked = accreditation(subject=LEAF, accredited_by=ROOT)
    live = accreditation(subject=LEAF, accredited_by=ROOT)
    resolver = registry(lane, {LEAF: [attribute(revoked, "Revoked", tao=ROOT, tag="a"),
                                      attribute(live, "TI", tao=ROOT, tag="b")]})
    assert chain(resolver).hops[0].accreditation.attribute_id == "b"
    picked = single_level(resolver)
    assert picked is not None and picked.attribute_id == "b"


# --------------------------------------------------------------------------- #
# Messages: the roles set aside are named, bounded, with the DID
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_message_names_the_role_and_is_bounded(lane: Lane) -> None:
    long_role = "R" * 70_000
    resolver = one_hop(lane, long_role)
    with pytest.raises(NoTrustedAnchor) as info:
        chain(resolver)
    text = str(info.value)
    assert len(text) < MESSAGE_BOUND and LEAF in text and "issuerType" in text
    with pytest.raises(IssuerNotTrusted) as info2:
        verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE)
    assert len(str(info2.value)) < MESSAGE_BOUND and "issuerType" in str(info2.value)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_non_leaf_message_bounds_the_delegated_types(lane: Lane) -> None:
    # the review of PR #371: above the leaf the message quoted `sorted(needed)` raw, and the
    # delegated scope is what the leaf accreditation and the credential share (1 002 163
    # characters measured on `main` with 500 types of 2 000 characters, when a wildcard leaf
    # still delegated the credential's whole `type` list; #368 removed the wildcard, so the
    # leaf here lists the 500 types itself); the TI-above-the-leaf refusals of #358 route
    # through that line
    many_types = [f"T{i}" + "x" * 2000 for i in range(500)]
    leaf = accreditation(subject=LEAF, accredited_by=MID, types=many_types)
    mid = accreditation(subject=MID, accredited_by=ROOT, kind="VerifiableAccreditationToAccredit")
    resolver = registry(lane, {LEAF: [attribute(leaf, "TI", tao=MID, tag="leaf")],
                               MID: [attribute(mid, "TI", tao=ROOT, tag="mid")]})
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as info:
        verify_trust_chain(LEAF, many_types, resolver=resolver, proof_suite=SUITE,
                           anchors={ROOT})
    text = str(info.value)
    assert len(text) < 2 * MESSAGE_BOUND and MID in text and "'TI'" in text


def test_many_distinct_roles_are_counted_not_listed() -> None:
    # the review of PR #371: the note de-duplicates roles linearly (a set beside the list;
    # v4 inline attributes are uncapped) and shows at most three, counting the rest
    record = IssuerRecord(did=LEAF, has_attributes=True,
                          accreditations=tuple(_acc(f"Role{i}") for i in range(60)))
    note = ineligible_note(record, leaf=True)
    reason = "issuerType {} is not a live trust role (RootTAO, TAO or TI)"
    assert note == ("; set aside: " + "; ".join(reason.format(repr(f"Role{i}")) for i in range(3))
                    + " and 57 more")
    assert len(note) < MESSAGE_BOUND and evaluate_issuer_trust(record, TYPES) is None


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_message_says_which_rule_set_the_accreditor_aside(lane: Lane) -> None:
    with pytest.raises(NoTrustedAnchor) as info:
        chain(two_hops(lane, "TI"))
    text = str(info.value)
    assert "'TI'" in text and "TAO" in text and "RootTAO" in text


# --------------------------------------------------------------------------- #
# The model
# --------------------------------------------------------------------------- #

def _acc(role: str, types: tuple[str, ...] = ("OpenBadgeCredential",)) -> Accreditation:
    # a `…ToAttest` kind, so only the role (or an empty `types`) decides here (#368)
    return Accreditation(attribute_id="a", issuer_type=role, tao=ROOT, root_tao=ROOT,
                         credential_types=types,
                         accreditation_types=("VerifiableAccreditationToAttest",))


@pytest.mark.parametrize("role, revoked", [
    ("Revoked", True), ("revoked", True),
    ("RootTAO", False), ("TAO", False), ("TI", False), ("undefined", False), ("", False),
    ("REVOKED", False),
])
def test_is_revoked_reads_the_wire_spelling(role: str, revoked: bool) -> None:
    assert _acc(role).is_revoked is revoked


@pytest.mark.parametrize("role, live, delegates", [
    ("RootTAO", True, True), ("TAO", True, True), ("TI", True, False),
    ("Revoked", False, False), ("revoked", False, False), ("undefined", False, False),
    ("", False, False), ("ti", False, False), ("Banana", False, False),
])
def test_the_role_predicates(role: str, live: bool, delegates: bool) -> None:
    acc = _acc(role)
    assert acc.has_trust_role is live and acc.can_accredit is delegates


@pytest.mark.parametrize("role", ["Revoked", "revoked", "undefined", "", "Banana", "ti"])
def test_evaluate_issuer_trust_unit_sets_an_ineligible_role_aside(role: str) -> None:
    record = IssuerRecord(did=LEAF, has_attributes=True,
                          accreditations=(_acc(role), _acc(role, ())))   # scoped and wildcard
    assert evaluate_issuer_trust(record, ["OpenBadgeCredential"]) is None
    live = IssuerRecord(did=LEAF, has_attributes=True, accreditations=(_acc(role), _acc("TI")))
    picked = evaluate_issuer_trust(live, ["OpenBadgeCredential"])
    assert picked is not None and picked.issuer_type == "TI"
