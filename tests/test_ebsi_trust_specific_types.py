"""
tests/test_ebsi_trust_specific_types.py — the type match is made on the SPECIFIC types, and the
leaf must be accredited for every one of them (#367, rule (b)).

Both trust policies matched an accreditation by INTERSECTING the credential's whole ``type`` list
with the accreditation's ``accreditedFor.types``. On real EBSI data both lists start with the
generic base types (``VerifiableCredential``, ``VerifiableAttestation``; the recorded
``accreditedFor`` lists are ``[VC, VA, VerifiableAuthorisationForTrustChain]``), so the
intersection was never empty. Measured on ``main`` at 2ec271c (#358 and #368 merged) with real
P-256 signatures on v4, v5 and Core v1, single-level and recursive: a credential
``[VC, VA, MyBadge]`` was **trusted** against an accreditation for ``[VC, VA, OtherType]``, for
``[VC, VA]`` and for ``[VC]``; a credential of generic types only was trusted against anything;
``[MyBadge, Extra]`` was trusted against ``[MyBadge]``; and a two-hop chain whose leaf
accreditation listed only generic types closed through an accreditor scoped to another type.

Now the generic base types (``models.GENERIC_TYPES``: ``VerifiableCredential``,
``VerifiableAttestation``, ``VerifiableAccreditation``) are ignored on both sides and **every**
specific type of the credential must be listed by the leaf accreditation (a superset, the same
rule the hops above already followed over the delegated scope); a credential with no specific
type has nothing to be accredited for and is refused, as is an accreditation that lists only
generic types. No cross-import: the lane scaffold is local to this file.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import pytest

from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.models import (
    ACCREDITATION_TO_ACCREDIT,
    ACCREDITATION_TO_ATTEST,
    GENERIC_TYPES,
    Accreditation,
    IssuerRecord,
    specific_types,
)
from openvc_ebsi.trust import NoTrustedAnchor, TrustChain, verify_trust_chain
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

SUITE = VcJwtProofSuite()
MESSAGE_BOUND = 700
VC, VA, VACC = "VerifiableCredential", "VerifiableAttestation", "VerifiableAccreditation"
ATTEST = [VC, VA, VACC, ACCREDITATION_TO_ATTEST]
ACCREDIT = [VC, VA, VACC, ACCREDITATION_TO_ACCREDIT]
BADGE = [VC, VA, "MyBadge"]


def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, MID, ROOT = _did(0xA1), _did(0xB2), _did(0xC3)
KEYS = {d: P256SigningKey.generate(kid=f"{d}#key-1") for d in (LEAF, MID, ROOT)}


# --------------------------------------------------------------------------- #
# Harness (as in the sibling trust tests; copied, never imported)
# --------------------------------------------------------------------------- #

class StubFetch:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes

    def __call__(self, url: str) -> Any:
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


def accreditation(*, subject: str, accredited_by: str, types: list[str],
                  kind: list[str] = ATTEST) -> str:
    vc = {"id": f"urn:uuid:acc-{subject[-6:]}", "type": kind, "issuer": accredited_by,
          "credentialSubject": {"id": subject, "accreditedFor": [{"types": types}]}}
    return SUITE.sign(vc, signing_key=KEYS[accredited_by])


def attribute(body: str, *, tao: str, tag: str, role: str = "TI") -> dict[str, Any]:
    return {"hash": tag, "issuerType": role, "tao": tao, "rootTao": ROOT, "body": body}


def registry(lane: Lane, records: dict[str, list[dict[str, Any]]]) -> DidEbsiResolver:
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


def one_hop(lane: Lane, accredited_for: list[str]) -> DidEbsiResolver:
    tok = accreditation(subject=LEAF, accredited_by=ROOT, types=accredited_for)
    return registry(lane, {LEAF: [attribute(tok, tao=ROOT, tag="leaf")]})


def two_hops(lane: Lane, leaf_for: list[str], mid_for: list[str]) -> DidEbsiResolver:
    leaf = accreditation(subject=LEAF, accredited_by=MID, types=leaf_for)
    mid = accreditation(subject=MID, accredited_by=ROOT, types=mid_for, kind=ACCREDIT)
    return registry(lane, {LEAF: [attribute(leaf, tao=MID, tag="leaf")],
                           MID: [attribute(mid, tao=ROOT, tag="mid", role="TAO")]})


def chain(resolver: DidEbsiResolver, types: list[str]) -> TrustChain:
    return verify_trust_chain(LEAF, types, resolver=resolver, proof_suite=SUITE, anchors={ROOT})


def single_level(resolver: DidEbsiResolver, types: list[str]) -> Accreditation | None:
    return evaluate_issuer_trust(resolver.issuer_record(LEAF), types)


def badge(types: list[str]) -> str:
    return SUITE.sign({"@context": ["https://www.w3.org/2018/credentials/v1"],
                       "id": "urn:uuid:badge-1", "type": types, "issuer": LEAF,
                       "credentialSubject": {"id": "did:key:z6MkSubject"}},
                      signing_key=KEYS[LEAF])


def refused(lane: Lane, resolver: DidEbsiResolver, types: list[str]) -> str:
    with pytest.raises(NoTrustedAnchor) as info:
        chain(resolver, types)
    assert single_level(resolver, types) is None, lane.name
    with pytest.raises(IssuerNotTrusted):
        verify_ebsi_badge(badge(types), resolver=resolver, proof_suite=SUITE)
    with pytest.raises(NoTrustedAnchor):
        verify_ebsi_badge(badge(types), resolver=resolver, proof_suite=SUITE,
                          trust_anchors={ROOT})
    assert verify_ebsi_badge(badge(types), resolver=resolver, proof_suite=SUITE,
                             require_trust=False).trusted is False
    return str(info.value)


def trusted(lane: Lane, resolver: DidEbsiResolver, types: list[str]) -> TrustChain:
    c = chain(resolver, types)
    assert c.anchor == ROOT
    assert single_level(resolver, types) is not None, lane.name
    assert verify_ebsi_badge(badge(types), resolver=resolver, proof_suite=SUITE,
                             trust_anchors={ROOT}).trusted is True
    return c


# --------------------------------------------------------------------------- #
# Controls
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_an_accreditation_listing_the_specific_type_is_trusted(lane: Lane) -> None:
    c = trusted(lane, one_hop(lane, [VC, VA, "MyBadge"]), BADGE)
    assert c.scope == frozenset({"MyBadge"})        # the generics are not part of the scope


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_generics_on_either_side_change_nothing(lane: Lane) -> None:
    trusted(lane, one_hop(lane, ["MyBadge"]), BADGE)             # no generics in accreditedFor
    trusted(lane, one_hop(lane, [VC, VA, "MyBadge"]), ["MyBadge"])   # none in the credential
    trusted(lane, one_hop(lane, [VC, VA, "MyBadge", "Extra"]), BADGE)   # a wider accreditation


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_control_a_two_hop_chain_over_the_specific_type_closes(lane: Lane) -> None:
    c = chain(two_hops(lane, [VC, VA, "MyBadge"], [VC, VA, "MyBadge", "OtherType"]), BADGE)
    assert [(h.subject, h.accreditor) for h in c.hops] == [(LEAF, MID), (MID, ROOT)]
    assert c.scope == frozenset({"MyBadge"})


def test_the_generic_set_and_the_recorded_shape() -> None:
    assert GENERIC_TYPES == frozenset({VC, VA, VACC})
    assert specific_types([VC, VA, "VerifiableAuthorisationForTrustChain"]) == {
        "VerifiableAuthorisationForTrustChain"}             # the recorded accreditedFor lists
    assert specific_types(ATTEST) == {ACCREDITATION_TO_ATTEST}
    assert specific_types([VC, VA]) == frozenset() and specific_types([]) == frozenset()


# --------------------------------------------------------------------------- #
# Headline: generics made the intersection non-empty
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("accredited_for", [
    pytest.param([VC, VA, "OtherType"], id="scoped-to-another-type"),
    pytest.param([VC, VA], id="generic-only"),
    pytest.param([VC], id="VerifiableCredential-only"),
    pytest.param([VC, VA, VACC], id="generic-with-VerifiableAccreditation"),
    pytest.param([VA], id="VerifiableAttestation-only"),
])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_headline_a_shared_generic_type_is_not_an_accreditation_for_the_credential(
        lane: Lane, accredited_for: list[str]) -> None:
    text = refused(lane, one_hop(lane, accredited_for), BADGE)
    assert "no valid accreditation" in text and len(text) < MESSAGE_BOUND


@pytest.mark.parametrize("types", [
    pytest.param([VC, VA], id="generic-only"),
    pytest.param([VC], id="VerifiableCredential-only"),
    pytest.param([VC, VA, VACC], id="with-VerifiableAccreditation"),
    pytest.param([], id="no-type"),
])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_credential_with_no_specific_type_has_nothing_to_be_accredited_for(
        lane: Lane, types: list[str]) -> None:
    # TRUSTED on main against ANY accreditation (the generics intersected); nothing specific to
    # match means nothing to trust: refused before any registry request on the walk
    resolver = one_hop(lane, [VC, VA, "OtherType"])
    with pytest.raises(NoTrustedAnchor, match="no specific type") as info:
        chain(resolver, types)
    assert len(str(info.value)) < MESSAGE_BOUND
    assert single_level(resolver, types) is None
    if types:                                     # a badge needs a type list the suite signs
        with pytest.raises(IssuerNotTrusted, match="no specific type"):
            verify_ebsi_badge(badge(types), resolver=resolver, proof_suite=SUITE)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_every_specific_type_of_the_credential_must_be_listed(lane: Lane) -> None:
    # rule (b): `[MyBadge, Extra]` against an accreditation for `MyBadge` alone was TRUSTED on
    # main (one shared type); the issuer is not accredited for `Extra`
    text = refused(lane, one_hop(lane, [VC, VA, "MyBadge"]), [VC, VA, "MyBadge", "Extra"])
    assert "no valid accreditation" in text
    trusted(lane, one_hop(lane, [VC, VA, "MyBadge", "Extra"]), [VC, VA, "MyBadge", "Extra"])


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_record_with_several_accreditations_picks_the_one_covering_every_type(lane: Lane) -> None:
    partial = accreditation(subject=LEAF, accredited_by=ROOT, types=[VC, VA, "MyBadge"])
    full = accreditation(subject=LEAF, accredited_by=ROOT, types=[VC, VA, "MyBadge", "Extra"])
    resolver = registry(lane, {LEAF: [attribute(partial, tao=ROOT, tag="a"),
                                      attribute(full, tao=ROOT, tag="b")]})
    types = [VC, VA, "MyBadge", "Extra"]
    assert chain(resolver, types).hops[0].accreditation.attribute_id == "b"
    picked = single_level(resolver, types)
    assert picked is not None and picked.attribute_id == "b"


# --------------------------------------------------------------------------- #
# Two hops: the delegated scope is the specific types
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("leaf_for, mid_for", [
    pytest.param([VC, VA], [VC, VA, "OtherType"], id="generic-leaf-over-another-type"),
    pytest.param([VC, VA], [VC, VA], id="generic-leaf-over-generic-accreditor"),
    pytest.param([VC, VA, "MyBadge"], [VC, VA], id="specific-leaf-over-generic-accreditor"),
    pytest.param([VC, VA, "MyBadge"], [VC, VA, "OtherType"], id="specific-leaf-over-another-type"),
])
@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_a_chain_cannot_close_on_generic_types(lane: Lane, leaf_for: list[str],
                                               mid_for: list[str]) -> None:
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation"):
        chain(two_hops(lane, leaf_for, mid_for), BADGE)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_delegated_scope_is_what_the_credential_needs(lane: Lane) -> None:
    # a leaf accredited for [MyBadge, Extra] issuing a MyBadge through an accreditor that may
    # only delegate MyBadge: the chain closes with scope {MyBadge}; the same accreditor cannot
    # close an [MyBadge, Extra] credential
    resolver = two_hops(lane, [VC, VA, "MyBadge", "Extra"], [VC, VA, "MyBadge"])
    assert chain(resolver, BADGE).scope == frozenset({"MyBadge"})
    with pytest.raises(NoTrustedAnchor) as info:
        chain(resolver, [VC, VA, "MyBadge", "Extra"])
    assert MID in str(info.value)


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_accreditor_must_cover_the_whole_delegated_scope(lane: Lane) -> None:
    types = [VC, VA, "MyBadge", "Extra"]
    with pytest.raises(NoTrustedAnchor) as info:
        chain(two_hops(lane, [VC, VA, "MyBadge", "Extra"], [VC, VA, "MyBadge"]), types)
    assert MID in str(info.value)
    c = chain(two_hops(lane, [VC, VA, "MyBadge", "Extra"], [VC, VA, "MyBadge", "Extra"]), types)
    assert c.scope == frozenset({"MyBadge", "Extra"})


# --------------------------------------------------------------------------- #
# The model and the note
# --------------------------------------------------------------------------- #

def _acc(types: tuple[str, ...], kind: str = ACCREDITATION_TO_ATTEST) -> Accreditation:
    return Accreditation(attribute_id="a", issuer_type="TI", tao=ROOT, root_tao=ROOT,
                         credential_types=types, accreditation_types=(VC, VA, VACC, kind))


def test_evaluate_issuer_trust_unit_matches_specific_types_as_a_superset() -> None:
    generic_only = _acc((VC, VA))
    other = _acc((VC, VA, "OtherType"))
    exact = _acc((VC, VA, "MyBadge"))
    wider = _acc(("MyBadge", "Extra"))
    rec = IssuerRecord(did=LEAF, has_attributes=True,
                       accreditations=(generic_only, other, exact, wider))
    assert evaluate_issuer_trust(rec, BADGE) is exact
    assert evaluate_issuer_trust(rec, ["MyBadge", "Extra"]) is wider
    assert evaluate_issuer_trust(rec, [VC, VA]) is None                    # nothing specific
    assert evaluate_issuer_trust(rec, ["Unknown"]) is None
    assert generic_only.specific_credential_types == frozenset()
    assert wider.specific_credential_types == {"MyBadge", "Extra"}


@pytest.mark.parametrize("lane", ALL_LANES, ids=_lane_id)
def test_the_message_names_a_generic_only_accreditation(lane: Lane) -> None:
    text = refused(lane, one_hop(lane, [VC, VA]), BADGE)
    assert "only generic types" in text and len(text) < MESSAGE_BOUND
