"""
tests/test_trust_chain.py — recursive EBSI trust-chain verification, offline.

Builds a real 3-level chain: a leaf issuer (TI) accredited by a middle TAO,
itself accredited by a RootTAO anchor. Every accreditation is a genuine VC-JWT
signed by the accreditor, and each accreditor's DID publishes the matching key,
so signatures actually verify at every hop.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from openvc.did.base import DidResolutionError
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import encode_bitstring, set_status_bit
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.trust import (
    AccreditationInvalid,
    AccreditationRevoked,
    NoTrustedAnchor,
    verify_trust_chain,
)
from openvc_ebsi.verify import verify_ebsi_badge
from openvc_ebsi.versioning import DidEbsiResolver, TirV5

ACC_STATUS_URL = "https://tao.example/acc-status/1"


def _acc_status_entry(index: str = "3") -> dict:
    return {
        "id": f"{ACC_STATUS_URL}#{index}",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": index,
        "statusListCredential": ACC_STATUS_URL,
    }


def _acc_status_vc(*set_indices: int) -> dict:
    bits = bytearray(32)
    for i in set_indices:
        set_status_bit(bits, i, 1)
    return {"credentialSubject": {"statusPurpose": "revocation",
                                  "encodedList": encode_bitstring(bytes(bits))}}


BASE = "https://api-pilot.ebsi.eu"
LEAF = "did:ebsi:zLeafIssuerAAAAAAAAAA"
MID = "did:ebsi:zMidTaoBBBBBBBBBBBBBB"
ROOT = "did:ebsi:zRootTaoCCCCCCCCCCCC"
TYPES = ("OpenBadgeCredential",)


class StubFetch:
    def __init__(self, routes: dict[str, dict]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url: str) -> dict:
        self.calls.append(url)
        try:
            return self.routes[url]
        except KeyError:
            raise HttpNotFound("no stub route", url=url) from None


def _did_doc(did: str, sk: P256SigningKey) -> dict:
    return {"didDocument": {
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
            "publicKeyJwk": sk.public_jwk(),
        }],
        "assertionMethod": [f"{did}#key-1"],
    }}


def _accreditation(suite, signer: P256SigningKey, *, subject: str,
                   accredited_by: str, accredited_for: tuple[str, ...],
                   credential_status: dict | None = None) -> str:
    # Real v5 credentialSubject: id + accreditedFor objects. issuerType/tao/rootTao
    # live on the TIR `attribute` wrapper (see _tir_routes), not here.
    acc = {
        "id": f"urn:uuid:acc-{subject[-4:]}",
        "type": ["VerifiableCredential", "VerifiableAccreditationToAttest"],
        "issuer": accredited_by,
        "credentialSubject": {
            "id": subject,
            "accreditedFor": [{"types": list(accredited_for)}],
        },
    }
    if credential_status is not None:
        acc["credentialStatus"] = credential_status
    return suite.sign(acc, signing_key=signer)


def _tir_routes(base_issuer_url: str, body_token: str, tag: str, *,
                issuer_type: str, tao: str, subject: str) -> dict:
    attrs = f"{base_issuer_url}/attributes"
    rev = f"{attrs}/{tag}/revisions/r1"
    return {
        base_issuer_url: {"hasAttributes": True, "attributes": attrs},
        attrs: {"items": [{"id": tag, "href": rev}]},
        # v5 nests the signed body and the role metadata under `attribute`.
        rev: {"did": subject, "attribute": {
            "body": body_token, "hash": tag,
            "issuerType": issuer_type, "tao": tao, "rootTao": ROOT,
        }},
    }


def build_chain(*, mid_issuer_type: str = "TAO",
                mid_accredited_for: tuple[str, ...] = TYPES,
                mid_status: dict | None = None) -> SimpleNamespace:
    """A valid LEAF -(TAO)-> MID -(RootTAO)-> ROOT chain. Returns everything a
    test needs, including the shared routes dict it can mutate."""
    suite = VcJwtProofSuite()
    leaf_sk = P256SigningKey.generate(kid=f"{LEAF}#key-1")
    mid_sk = P256SigningKey.generate(kid=f"{MID}#key-1")
    root_sk = P256SigningKey.generate(kid=f"{ROOT}#key-1")

    badge = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:badge-1",
        "type": ["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"],
        "issuer": LEAF,
        "credentialSubject": {"id": "did:key:z6MkSubject"},
    }
    token = suite.sign(badge, signing_key=leaf_sk)

    leaf_acc = _accreditation(suite, mid_sk, subject=LEAF, accredited_by=MID,
                              accredited_for=TYPES)
    mid_acc = _accreditation(suite, root_sk, subject=MID, accredited_by=ROOT,
                             accredited_for=mid_accredited_for, credential_status=mid_status)

    tir = f"{BASE}/trusted-issuers-registry/v5/issuers"
    routes: dict[str, dict] = {
        f"{BASE}/did-registry/v5/identifiers/{LEAF}": _did_doc(LEAF, leaf_sk),
        f"{BASE}/did-registry/v5/identifiers/{MID}": _did_doc(MID, mid_sk),
        f"{BASE}/did-registry/v5/identifiers/{ROOT}": _did_doc(ROOT, root_sk),
    }
    routes.update(_tir_routes(f"{tir}/{LEAF}", leaf_acc, "leaf",
                              issuer_type="TI", tao=MID, subject=LEAF))
    routes.update(_tir_routes(f"{tir}/{MID}", mid_acc, "mid",
                              issuer_type=mid_issuer_type, tao=ROOT, subject=MID))

    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5())
    keys = SimpleNamespace(leaf=leaf_sk, mid=mid_sk, root=root_sk)
    return SimpleNamespace(token=token, resolver=resolver, suite=suite,
                           routes=routes, fetch=fetch, keys=keys)


# --------------------------------------------------------------------------- #
# verify_trust_chain directly
# --------------------------------------------------------------------------- #

def test_chain_reaches_anchor():
    c = build_chain()
    chain = verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                               proof_suite=c.suite, anchors={ROOT})
    assert chain.anchor == ROOT
    assert [(h.subject, h.accreditor) for h in chain.hops] == [(LEAF, MID), (MID, ROOT)]


def test_chain_no_anchor_reached():
    c = build_chain()
    with pytest.raises(NoTrustedAnchor):
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                           proof_suite=c.suite, anchors={"did:ebsi:zSomeoneElse"})


def test_chain_leaf_is_anchor_is_trivially_trusted():
    c = build_chain()
    chain = verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                               proof_suite=c.suite, anchors={LEAF})
    assert chain.anchor == LEAF and chain.hops == ()


def test_chain_tampered_accreditor_key_fails():
    # MID's DID publishes a different key than the one that signed LEAF's
    # accreditation -> that accreditation's signature must fail.
    c = build_chain()
    other = P256SigningKey.generate(kid=f"{MID}#key-1")
    c.routes[f"{BASE}/did-registry/v5/identifiers/{MID}"] = _did_doc(MID, other)
    with pytest.raises(AccreditationInvalid):
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                           proof_suite=c.suite, anchors={ROOT})


_ABSENT = object()                          # the accreditor's document has no `id` member


@pytest.mark.parametrize("doc_id", [
    pytest.param("did:ebsi:zSomebodyElse", id="another-did"),
    pytest.param(None, id="null"),
    pytest.param("", id="empty"),
    pytest.param(_ABSENT, id="absent"),
])
@pytest.mark.parametrize("accreditor", [MID, ROOT], ids=["mid", "root"])
def test_chain_accreditor_document_for_another_did_fails(accreditor, doc_id):
    # #257. The accreditor's DID Registry document carries the right key (so the
    # accreditation's signature WOULD verify) but its `id` is not the accreditor's DID.
    # The control is the unmodified chain, which reaches the anchor.
    c = build_chain()
    assert verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver, proof_suite=c.suite,
                              anchors={ROOT}).anchor == ROOT
    doc = _did_doc(accreditor, c.keys.mid if accreditor == MID else c.keys.root)
    if doc_id is _ABSENT:
        del doc["didDocument"]["id"]
    else:
        doc["didDocument"]["id"] = doc_id
    c.routes[f"{BASE}/did-registry/v5/identifiers/{accreditor}"] = doc

    with pytest.raises(OpenvcError) as exc:
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                           proof_suite=c.suite, anchors={ROOT})
    assert type(exc.value) is AccreditationInvalid
    assert type(exc.value.__cause__) is DidResolutionError
    assert "!= requested" in str(exc.value)

    with pytest.raises(OpenvcError) as bexc:                 # and through the badge verifier
        verify_ebsi_badge(c.token, resolver=c.resolver, proof_suite=c.suite,
                          trust_anchors={ROOT})
    assert type(bexc.value) is AccreditationInvalid


BIG = "did:ebsi:z" + "B" * 60_000            # attacker-sized: 60,010 characters


@pytest.mark.parametrize("case", ["issuer", "accreditor", "kid"])
def test_chain_accreditation_failure_messages_are_bounded(case):
    # The accreditation's `iss` and `kid` come from a JWT that is read before its signature
    # is checked, and `accreditedBy` from the registry: all attacker-sized. The three
    # `AccreditationInvalid` messages that name them cut each at 200 characters.
    c = build_chain()
    assert verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver, proof_suite=c.suite,
                              anchors={ROOT}).anchor == ROOT                  # control
    tir = f"{BASE}/trusted-issuers-registry/v5/issuers"
    big_sk = P256SigningKey.generate(kid=f"{BIG}#key-1")
    if case == "issuer":           # signed by BIG, but the TIR says MID accredited the leaf
        signer, issuer, tao = big_sk, BIG, MID
    elif case == "accreditor":     # BIG accredited the leaf, and BIG's document is not BIG's
        signer, issuer, tao = big_sk, BIG, BIG
        doc = _did_doc(BIG, big_sk)
        doc["didDocument"]["id"] = "did:ebsi:zSomebodyElse"
        c.routes[f"{BASE}/did-registry/v5/identifiers/{BIG}"] = doc
    else:                          # MID accredited the leaf, under a `kid` MID's document lacks
        signer, issuer, tao = P256SigningKey.generate(kid="k" * 60_000), MID, MID
    token = _accreditation(c.suite, signer, subject=LEAF, accredited_by=issuer,
                           accredited_for=TYPES)
    c.routes.update(_tir_routes(f"{tir}/{LEAF}", token, "leaf",
                                issuer_type="TI", tao=tao, subject=LEAF))

    with pytest.raises(OpenvcError) as exc:
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver, proof_suite=c.suite,
                           anchors={ROOT})
    assert type(exc.value) is AccreditationInvalid
    shown = f"{BIG[:200]!r}... (60010 chars)"
    if case == "issuer":
        assert str(exc.value) == f"accreditation issuer {shown} != accreditedBy {MID!r}"
    elif case == "accreditor":
        assert type(exc.value.__cause__) is DidResolutionError
        assert str(exc.value).startswith(f"cannot resolve accreditor {shown}: document id ")
    else:
        assert str(exc.value) == (f"no verification method {('k' * 200)!r}... (60000 chars) "
                                  f"for accreditor {MID!r}")
    assert len(str(exc.value)) < 1000


def test_chain_revoked_mid_breaks_chain():
    c = build_chain(mid_issuer_type="revoked")   # MID's accreditation is revoked
    with pytest.raises(NoTrustedAnchor):
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                           proof_suite=c.suite, anchors={ROOT})


# --------------------------------------------------------------------------- #
# verify_ebsi_badge with trust_anchors (recursive mode end to end)
# --------------------------------------------------------------------------- #

def test_verify_badge_with_recursive_anchor():
    c = build_chain()
    result = verify_ebsi_badge(c.token, resolver=c.resolver, proof_suite=c.suite,
                               expected_types=["OpenBadgeCredential"],
                               trust_anchors={ROOT})
    assert result.trusted is True
    assert result.chain is not None and result.chain.anchor == ROOT
    assert len(result.chain.hops) == 2
    assert result.accreditation is result.chain.hops[0].accreditation


def test_verify_badge_untrusted_anchor_raises():
    c = build_chain()
    with pytest.raises(NoTrustedAnchor):
        verify_ebsi_badge(c.token, resolver=c.resolver, proof_suite=c.suite,
                          trust_anchors={"did:ebsi:zNotTheRoot"})


def test_verify_badge_untrusted_anchor_optional_returns_untrusted():
    c = build_chain()
    result = verify_ebsi_badge(c.token, resolver=c.resolver, proof_suite=c.suite,
                               trust_anchors={"did:ebsi:zNotTheRoot"},
                               require_trust=False)
    assert result.trusted is False
    assert result.chain is None
    assert result.issuer == LEAF          # signature still verified


def test_chain_records_delegated_scope():
    c = build_chain()
    chain = verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                               proof_suite=c.suite, anchors={ROOT})
    assert chain.scope == frozenset({"OpenBadgeCredential"})


# --------------------------------------------------------------------------- #
# Refinement 1: per-hop delegation scoping
# --------------------------------------------------------------------------- #

def test_delegation_scope_enforced_superset():
    # MID is only accredited for a different type, so it cannot delegate
    # OpenBadgeCredential to LEAF -> the chain must break at MID.
    c = build_chain(mid_accredited_for=("SomeOtherCredential",))
    with pytest.raises(NoTrustedAnchor, match="delegated types"):
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                           proof_suite=c.suite, anchors={ROOT})


def test_delegation_ok_when_parent_scope_is_superset():
    # MID accredited for a superset (OBC + extra) can delegate OBC -> trusted.
    c = build_chain(mid_accredited_for=("OpenBadgeCredential", "OtherCredential"))
    chain = verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                               proof_suite=c.suite, anchors={ROOT})
    assert chain.anchor == ROOT


# --------------------------------------------------------------------------- #
# Refinement 2: status-list revocation of an accreditation itself
# --------------------------------------------------------------------------- #

def test_revoked_accreditation_via_status_breaks_chain():
    c = build_chain(mid_status=_acc_status_entry("3"))
    resolve = {ACC_STATUS_URL: _acc_status_vc(3)}.__getitem__     # bit 3 set
    with pytest.raises(AccreditationRevoked):
        verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                           proof_suite=c.suite, anchors={ROOT},
                           resolve_status_list=resolve)


def test_accreditation_status_clear_still_trusts():
    c = build_chain(mid_status=_acc_status_entry("3"))
    resolve = {ACC_STATUS_URL: _acc_status_vc(9)}.__getitem__     # bit 3 clear
    chain = verify_trust_chain(LEAF, list(TYPES), resolver=c.resolver,
                               proof_suite=c.suite, anchors={ROOT},
                               resolve_status_list=resolve)
    assert chain.anchor == ROOT


def test_verify_badge_recursive_checks_accreditation_status():
    # End-to-end: a revoked accreditation surfaces through verify_ebsi_badge.
    c = build_chain(mid_status=_acc_status_entry("3"))
    resolve = {ACC_STATUS_URL: _acc_status_vc(3)}.__getitem__
    with pytest.raises(AccreditationRevoked):
        verify_ebsi_badge(c.token, resolver=c.resolver, proof_suite=c.suite,
                          trust_anchors={ROOT}, resolve_status_list=resolve)


def test_pick_accreditation_accepts_wildcard_consistent_with_single_level():
    # #109: a wildcard (no type restriction) accreditation is accepted by the single-level
    # policy (openvc_ebsi.verify) but was rejected at the leaf by the recursive walk; the
    # two now agree — an unrestricted accreditation is accepted in both, at the leaf and above.
    from openvc_ebsi.models import Accreditation, IssuerRecord
    from openvc_ebsi.trust import _pick_accreditation

    wildcard = Accreditation(attribute_id="a", issuer_type="TI", tao="did:ebsi:tao",
                             root_tao=None, credential_types=())
    record = IssuerRecord(did="did:ebsi:leaf", has_attributes=True, accreditations=(wildcard,))
    assert _pick_accreditation(record, {"SomeType"}, leaf=True) is wildcard
    assert _pick_accreditation(record, {"SomeType"}, leaf=False) is wildcard

    restricted = Accreditation(attribute_id="b", issuer_type="TI", tao="did:ebsi:tao",
                               root_tao=None, credential_types=("OtherType",))
    rec2 = IssuerRecord(did="did:ebsi:leaf", has_attributes=True, accreditations=(restricted,))
    assert _pick_accreditation(rec2, {"SomeType"}, leaf=True) is None
