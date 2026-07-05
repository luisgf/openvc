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
                   accredited_by: str, issuer_type: str, accredited_for: tuple[str, ...],
                   credential_status: dict | None = None) -> str:
    acc = {
        "id": f"urn:uuid:acc-{subject[-4:]}",
        "type": ["VerifiableCredential", "VerifiableAccreditationToAttest"],
        "issuer": accredited_by,
        "credentialSubject": {
            "id": subject,
            "issuerType": issuer_type,
            "accreditedBy": accredited_by,
            "rootTao": ROOT,
            "accreditedFor": list(accredited_for),
        },
    }
    if credential_status is not None:
        acc["credentialStatus"] = credential_status
    return suite.sign(acc, signing_key=signer)


def _tir_routes(base_issuer_url: str, body_token: str, tag: str) -> dict:
    attrs = f"{base_issuer_url}/attributes"
    rev = f"{attrs}/{tag}/revisions/r1"
    return {
        base_issuer_url: {"hasAttributes": True, "attributes": attrs},
        attrs: {"items": [{"id": tag, "href": rev}]},
        rev: {"body": body_token},
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
                              issuer_type="TI", accredited_for=TYPES)
    mid_acc = _accreditation(suite, root_sk, subject=MID, accredited_by=ROOT,
                             issuer_type=mid_issuer_type, accredited_for=mid_accredited_for,
                             credential_status=mid_status)

    tir = f"{BASE}/trusted-issuers-registry/v5/issuers"
    routes: dict[str, dict] = {
        f"{BASE}/did-registry/v5/identifiers/{LEAF}": _did_doc(LEAF, leaf_sk),
        f"{BASE}/did-registry/v5/identifiers/{MID}": _did_doc(MID, mid_sk),
        f"{BASE}/did-registry/v5/identifiers/{ROOT}": _did_doc(ROOT, root_sk),
    }
    routes.update(_tir_routes(f"{tir}/{LEAF}", leaf_acc, "leaf"))
    routes.update(_tir_routes(f"{tir}/{MID}", mid_acc, "mid"))

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
