"""
tests/test_ebsi_accreditation_deny_by_default.py — an accreditation authorises only what its
``accreditedFor`` lists, and its ``vc.type`` must name the accreditation kind of the hop (#368).

EBSI's own schema for the Verifiable Accreditation Record (the ``credentialSchema`` every
recorded accreditation token names: the pilot Trusted Schemas Registry ``zjVFNvbE…`` and the
Core API v1 ``0xf57ce42c…`` served by every node, both read 2026-10-30) makes
``credentialSubject.accreditedFor`` REQUIRED, each entry with ``schemaId`` and ``types``. The
four recorded RootTAO accreditations (v5 pilot, Core v1 preprod GRNET / INCM, prod ITI) all
carry it, with ``vc.type`` ending in ``VerifiableAccreditationToAttest``. EBSI's trust model
issues ``VerifiableAccreditationToAccredit`` to a TAO (so it may accredit) and
``VerifiableAccreditationToAttest`` to an issuer (so it may attest).

Measured on the tree at aea5e75 (``main`` + #358) with real P-256 signatures through
``evaluate_issuer_trust`` and ``verify_trust_chain`` on v4, v5 and Core v1: a token with no
``accreditedFor`` (an onboarding authorisation, a plain ``VerifiableAttestation``, a
``…ToAttest`` without the member), with ``accreditedFor`` ``[]`` / ``[{}]`` / ``[{"types": []}]``,
with a misspelt key (``accreditedfor``, ``Types``, a Greek omicron in ``accreditedFοr``), with
the wrong ``vc.type`` (``…ToAccredit`` at the leaf, ``[VerifiableCredential]`` only, absent) was
**TRUSTED** for every credential type, single-level and recursive, and the same shapes signed for
an accreditor closed a two-hop chain. Only an accreditation scoped to another type was refused.

Now: no ``accreditedFor`` (or none with a type) authorises **nothing** (the wildcard is gone from
both policies), the leaf accreditation's ``vc.type`` must name ``VerifiableAccreditationToAttest``
and the one read from an accreditor's record ``VerifiableAccreditationToAccredit``; ``vc.type`` is
read fail-closed on every lane (a string or a list of strings, else
``MalformedRegistryResponse``). The role rule of #358 stays the first gate. The messages say why.
No cross-import: the lane scaffold is local to this file (``tests/`` is not a package).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import EbsiError
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.models import (
    ACCREDITATION_TO_ACCREDIT,
    ACCREDITATION_TO_ATTEST,
    Accreditation,
    IssuerRecord,
)
from openvc_ebsi.trust import NoTrustedAnchor, TrustChain, ineligible_note, verify_trust_chain
from openvc_ebsi.verify import IssuerNotTrusted, evaluate_issuer_trust, verify_ebsi_badge
from openvc_ebsi.versioning import (
    DidEbsiResolver,
    DidRegistryAdapter,
    DidRegistryCoreV1,
    DidRegistryV5,
    MalformedRegistryResponse,
    TirAdapter,
    TirCoreV1,
    TirV4,
    TirV5,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"
SUITE = VcJwtProofSuite()
TYPES = ["OpenBadgeCredential"]
MESSAGE_BOUND = 600
VC, VA = "VerifiableCredential", "VerifiableAttestation"
ATTEST = [VC, VA, "VerifiableAccreditation", ACCREDITATION_TO_ATTEST]
ACCREDIT = [VC, VA, "VerifiableAccreditation", ACCREDITATION_TO_ACCREDIT]
ONBOARD = [VC, VA, "VerifiableAuthorisationToOnboard"]
SCOPED = {"accreditedFor": [{"types": TYPES}]}
ABSENT = object()


def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, MID, ROOT = _did(0xA1), _did(0xB2), _did(0xC3)
LEAF_SK = P256SigningKey.generate(kid=f"{LEAF}#key-1")
MID_SK = P256SigningKey.generate(kid=f"{MID}#key-1")
ROOT_SK = P256SigningKey.generate(kid=f"{ROOT}#key-1")
KEYS = {LEAF: LEAF_SK, MID: MID_SK, ROOT: ROOT_SK}


# --------------------------------------------------------------------------- #
# Harness (as in test_ebsi_issuer_type_roles.py; copied, never imported)
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


def token(*, subject: str, accredited_by: str, vc_type: Any = ATTEST,
          subject_extra: dict[str, Any] | None = SCOPED) -> str:
    """A genuine VC-JWT signed by *accredited_by*'s key for *subject*: ``vc.type`` is *vc_type*
    (ABSENT leaves it out), ``credentialSubject`` is ``{"id": subject, **subject_extra}``."""
    vc: dict[str, Any] = {"id": f"urn:uuid:acc-{subject[-6:]}", "issuer": accredited_by,
                          "credentialSubject": {"id": subject, **(subject_extra or {})}}
    if vc_type is not ABSENT:
        vc["type"] = vc_type
    return SUITE.sign(vc, signing_key=KEYS[accredited_by])


def attribute(body: Any, *, tao: str, tag: str, role: str = "TI") -> dict[str, Any]:
    return {"hash": tag, "issuerType": role, "tao": tao, "rootTao": ROOT, "body": body}


def registry(lane: Lane, records: dict[str, list[dict[str, Any]]],
             decode: Callable[[str], Any] = SUITE.peek_claims) -> DidEbsiResolver:
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
    return DidEbsiResolver(StubFetch(routes), decode, base=lane.base, didr=lane.didr(),
                           tir=lane.tir())


def one_hop(lane: Lane, leaf_token: str) -> DidEbsiResolver:
    return registry(lane, {LEAF: [attribute(leaf_token, tao=ROOT, tag="leaf")]})


def two_hops(lane: Lane, mid_token: str, leaf_token: str | None = None) -> DidEbsiResolver:
    leaf_token = leaf_token or token(subject=LEAF, accredited_by=MID)
    return registry(lane, {LEAF: [attribute(leaf_token, tao=MID, tag="leaf")],
                           MID: [attribute(mid_token, tao=ROOT, tag="mid", role="TAO")]})


def chain(resolver: DidEbsiResolver, types: list[str] = TYPES) -> TrustChain:
    return verify_trust_chain(LEAF, types, resolver=resolver, proof_suite=SUITE, anchors={ROOT})


def single_level(resolver: DidEbsiResolver, types: list[str] = TYPES) -> Accreditation | None:
    return evaluate_issuer_trust(resolver.issuer_record(LEAF), types)


def badge() -> str:
    return SUITE.sign({"@context": ["https://www.w3.org/2018/credentials/v1"],
                       "id": "urn:uuid:badge-1", "type": [VC, VA, *TYPES], "issuer": LEAF,
                       "credentialSubject": {"id": "did:key:z6MkSubject"}}, signing_key=LEAF_SK)


def refused_everywhere(lane: Lane, resolver: DidEbsiResolver, *, match: str) -> str:
    """Both policies and both public trust modes refuse; returns the chain's message."""
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as info:
        chain(resolver)
    assert match in str(info.value), (lane.name, str(info.value))
    assert single_level(resolver) is None
    with pytest.raises(IssuerNotTrusted, match="no valid accreditation"):
        verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE)
    with pytest.raises(NoTrustedAnchor):
        verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE, trust_anchors={ROOT})
    assert verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE,
                             require_trust=False).trusted is False
    return str(info.value)


# --------------------------------------------------------------------------- #
# Controls
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_scoped_to_attest_accreditation_is_trusted(lane: Lane) -> None:
    resolver = one_hop(lane, token(subject=LEAF, accredited_by=ROOT))
    assert chain(resolver).anchor == ROOT
    picked = single_level(resolver)
    assert picked is not None and picked.accreditation_types == tuple(ATTEST)
    assert verify_ebsi_badge(badge(), resolver=resolver, proof_suite=SUITE,
                             trust_anchors={ROOT}).trusted is True


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_vcdm_string_type_naming_to_attest_is_read(lane: Lane) -> None:
    # VCDM 1.1 lets `type` be a single string; the reader accepts it as a one-element list
    resolver = one_hop(lane, token(subject=LEAF, accredited_by=ROOT,
                                   vc_type=ACCREDITATION_TO_ATTEST))
    picked = single_level(resolver)
    assert picked is not None and picked.accreditation_types == (ACCREDITATION_TO_ATTEST,)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_to_accredit_accreditor_closes_a_two_hop_chain(lane: Lane) -> None:
    mid = token(subject=MID, accredited_by=ROOT, vc_type=ACCREDIT)
    c = chain(two_hops(lane, mid))
    assert [(h.subject, h.accreditor) for h in c.hops] == [(LEAF, MID), (MID, ROOT)]
    assert ACCREDITATION_TO_ACCREDIT in c.hops[1].accreditation.accreditation_types


def _walk(obj: Any):
    """Every JSON object anywhere in a recorded response, JSON-string bodies and JWT payloads
    included."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk(value)
    elif isinstance(obj, str):
        if obj[:1] in "{[":
            try:
                yield from _walk(json.loads(obj))
            except ValueError:
                return
        elif obj.count(".") == 2 and obj.startswith("ey"):
            try:
                yield from _walk(SUITE.peek_claims(obj))
            except OpenvcError:
                return


def test_control_every_recorded_accreditation_is_scoped_and_to_attest() -> None:
    # the drift alarm: the recorded registries (v5 pilot, Core v1 preprod and prod) hold only
    # accreditations EBSI's schema would accept, each `…ToAttest` with an `accreditedFor`
    seen = 0
    for path in sorted(FIXTURES.rglob("*.json")):
        for obj in _walk(json.loads(path.read_text())):
            vc = obj.get("vc")
            if not isinstance(vc, dict) or "credentialSubject" not in vc:
                continue
            seen += 1
            assert ACCREDITATION_TO_ATTEST in vc["type"], path
            entries = vc["credentialSubject"]["accreditedFor"]
            assert entries and all(e["types"] and e["schemaId"] for e in entries), path
    assert seen >= 4


# --------------------------------------------------------------------------- #
# Headline: a RootTAO-signed NON-accreditation for the same DID, in its record
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_headline_an_onboarding_authorisation_authorises_nothing(lane: Lane) -> None:
    onboarding = token(subject=LEAF, accredited_by=ROOT, vc_type=ONBOARD, subject_extra=None)
    text = refused_everywhere(lane, one_hop(lane, onboarding), match=ACCREDITATION_TO_ATTEST)
    assert "accreditedFor" in text or "vc.type" in text


# --------------------------------------------------------------------------- #
# No `accreditedFor` (or none with a type) authorises nothing
# --------------------------------------------------------------------------- #

NOTHING_LISTED = [
    pytest.param(None, id="accreditedFor-absent"),
    pytest.param({"accreditedFor": []}, id="empty-list"),
    pytest.param({"accreditedFor": [{}]}, id="entry-without-types"),
    pytest.param({"accreditedFor": [{"types": []}]}, id="entry-with-no-type"),
    pytest.param({"accreditedFor": [{"schemaId": "https://s.example/x"}]}, id="schemaId-only"),
    pytest.param({"accreditedfor": [{"types": TYPES}]}, id="misspelt-accreditedfor"),
    pytest.param({"accreditedFor": [{"Types": TYPES}]}, id="misspelt-Types"),
    pytest.param({"accreditedFοr": [{"types": TYPES}]}, id="greek-omicron"),
    pytest.param({"accredited_for": [{"types": TYPES}]}, id="snake-case"),
]


@pytest.mark.parametrize("subject_extra", NOTHING_LISTED)
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_an_accreditation_listing_no_type_authorises_nothing(
        lane: Lane, subject_extra: dict[str, Any] | None) -> None:
    resolver = one_hop(lane, token(subject=LEAF, accredited_by=ROOT, subject_extra=subject_extra))
    text = refused_everywhere(lane, resolver, match="accreditedFor")
    assert len(text) < MESSAGE_BOUND


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_single_level_trust_has_no_wildcard_either(lane: Lane) -> None:
    # the single-level policy trusted the node's list for a type-less accreditation (#109's
    # consistency fix made the walk agree); both now agree the other way
    resolver = one_hop(lane, token(subject=LEAF, accredited_by=ROOT, subject_extra=None))
    assert single_level(resolver, ["AnyCredentialType"]) is None
    assert single_level(resolver, []) is None                  # even a credential with no type


# --------------------------------------------------------------------------- #
# `vc.type` must name the accreditation kind of the hop
# --------------------------------------------------------------------------- #

NOT_TO_ATTEST = [
    pytest.param(ACCREDIT, id="ToAccredit-at-the-leaf"),
    pytest.param([VC], id="VerifiableCredential-only"),
    pytest.param([VC, VA], id="plain-attestation"),
    pytest.param(ABSENT, id="type-absent"),
    pytest.param([], id="type-empty"),
    pytest.param(["VerifiableAccreditationToAttest "], id="trailing-space"),
    pytest.param(["verifiableaccreditationtoattest"], id="lowercase"),
    pytest.param(["VerifiableAccreditationTo​Attest"], id="zero-width-space"),
]


@pytest.mark.parametrize("vc_type", NOT_TO_ATTEST)
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_leaf_accreditation_must_be_to_attest(lane: Lane, vc_type: Any) -> None:
    # `accreditedFor` lists the credential's type, so only the kind rule refuses here
    resolver = one_hop(lane, token(subject=LEAF, accredited_by=ROOT, vc_type=vc_type))
    refused_everywhere(lane, resolver, match=ACCREDITATION_TO_ATTEST)


@pytest.mark.parametrize("mid_type", [
    pytest.param(ATTEST, id="ToAttest-above-the-leaf"),
    pytest.param(ONBOARD, id="onboarding"),
    pytest.param([VC, VA], id="plain-attestation"),
    pytest.param(ABSENT, id="type-absent"),
])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_an_accreditor_must_hold_an_accreditation_to_accredit(lane: Lane, mid_type: Any) -> None:
    mid = token(subject=MID, accredited_by=ROOT, vc_type=mid_type)
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as info:
        chain(two_hops(lane, mid))
    assert MID in str(info.value) and ACCREDITATION_TO_ACCREDIT in str(info.value)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_an_accreditor_whose_accreditation_lists_no_type_delegates_nothing(lane: Lane) -> None:
    mid = token(subject=MID, accredited_by=ROOT, vc_type=ACCREDIT, subject_extra=None)
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as info:
        chain(two_hops(lane, mid))
    assert MID in str(info.value) and "accreditedFor" in str(info.value)


# --------------------------------------------------------------------------- #
# Records mixing shapes pick only a conforming accreditation; the rules compose
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_record_mixing_shapes_picks_the_conforming_accreditation(lane: Lane) -> None:
    onboarding = token(subject=LEAF, accredited_by=ROOT, vc_type=ONBOARD, subject_extra=None)
    typeless = token(subject=LEAF, accredited_by=ROOT, subject_extra={"accreditedFor": []})
    proper = token(subject=LEAF, accredited_by=ROOT)
    resolver = registry(lane, {LEAF: [attribute(onboarding, tao=ROOT, tag="a"),
                                      attribute(typeless, tao=ROOT, tag="b"),
                                      attribute(proper, tao=ROOT, tag="c")]})
    assert chain(resolver).hops[0].accreditation.attribute_id == "c"
    picked = single_level(resolver)
    assert picked is not None and picked.attribute_id == "c"


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_role_rule_still_runs_first(lane: Lane) -> None:
    # a perfectly shaped accreditation under a `Revoked` role is set aside for the role (#358),
    # and the message says so before anything about its shape
    resolver = registry(lane, {LEAF: [attribute(token(subject=LEAF, accredited_by=ROOT),
                                                tao=ROOT, tag="leaf", role="Revoked")]})
    text = refused_everywhere(lane, resolver, match="'Revoked'")
    assert ACCREDITATION_TO_ATTEST not in text


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_scoped_accreditation_for_another_type_is_still_refused(lane: Lane) -> None:
    resolver = one_hop(lane, token(subject=LEAF, accredited_by=ROOT,
                                   subject_extra={"accreditedFor": [{"types": ["OtherType"]}]}))
    with pytest.raises(NoTrustedAnchor):
        chain(resolver)
    assert single_level(resolver) is None


# --------------------------------------------------------------------------- #
# `vc.type` is read fail-closed on every lane
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("vc_type", [
    pytest.param(7, id="int"), pytest.param(None, id="null"), pytest.param(True, id="bool"),
    pytest.param({"a": 1}, id="object"), pytest.param([7], id="list-with-int"),
    pytest.param([VC, None], id="list-with-null"), pytest.param([[VC]], id="nested-list"),
])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_vc_type_of_an_unknown_shape_is_malformed_on_every_lane(lane: Lane, vc_type: Any) -> None:
    # the suite will not sign such a credential, so the token comes from an injected `decode`
    # that answers the shape; the record must be MalformedRegistryResponse, typed, never read
    claims = {"vc": {"type": vc_type, "credentialSubject": {"id": LEAF, **SCOPED}}}
    resolver = registry(lane, {LEAF: [attribute("x.y.z", tao=ROOT, tag="leaf")]},
                        decode=lambda body: claims)
    with pytest.raises(MalformedRegistryResponse) as info:
        resolver.issuer_record(LEAF)
    assert isinstance(info.value, EbsiError) and "type" in str(info.value)
    assert len(str(info.value)) < MESSAGE_BOUND


# --------------------------------------------------------------------------- #
# Messages and the model
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_message_is_bounded_with_a_hostile_type_list(lane: Lane) -> None:
    # a 70 000-character type and no `accreditedFor`: the kind rule answers first, bounded
    hostile = token(subject=LEAF, accredited_by=ROOT,
                    vc_type=[VC, "T" * 70_000], subject_extra=None)
    text = refused_everywhere(lane, one_hop(lane, hostile), match=ACCREDITATION_TO_ATTEST)
    assert len(text) < MESSAGE_BOUND and LEAF in text and "(70028 chars)" in text


def _acc(types: tuple[str, ...], kinds: tuple[str, ...], role: str = "TI") -> Accreditation:
    return Accreditation(attribute_id="a", issuer_type=role, tao=ROOT, root_tao=ROOT,
                         credential_types=types, accreditation_types=kinds)


def test_evaluate_issuer_trust_unit_requires_both_a_type_and_the_kind() -> None:
    proper = _acc(("OpenBadgeCredential",), tuple(ATTEST))
    typeless = _acc((), tuple(ATTEST))
    kindless = _acc(("OpenBadgeCredential",), ())
    accredit = _acc(("OpenBadgeCredential",), tuple(ACCREDIT))
    for bad in (typeless, kindless, accredit):
        record = IssuerRecord(did=LEAF, has_attributes=True, accreditations=(bad,))
        assert evaluate_issuer_trust(record, ["OpenBadgeCredential"]) is None
    record = IssuerRecord(did=LEAF, has_attributes=True,
                          accreditations=(typeless, kindless, accredit, proper))
    assert evaluate_issuer_trust(record, ["OpenBadgeCredential"]) is proper


def test_the_note_names_each_rule_once() -> None:
    record = IssuerRecord(did=LEAF, has_attributes=True, accreditations=(
        _acc((), tuple(ATTEST)), _acc(("X",), ()), _acc(("X",), tuple(ATTEST), role="Revoked")))
    note = ineligible_note(record, leaf=True)
    assert "accreditedFor" in note and ACCREDITATION_TO_ATTEST in note and "'Revoked'" in note
    assert len(note) < MESSAGE_BOUND
