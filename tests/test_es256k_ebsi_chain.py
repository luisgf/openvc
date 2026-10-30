"""
tests/test_es256k_ebsi_chain.py — ES256K through the EBSI chain and the recorded RootTAO (#323).

EBSI Core API v1 signs its RootTAO accreditation JWTs with ``ES256K`` (ADR-0009, open question
3). ``VcJwtProofSuite(allow_es256k=True)`` verifies them; ``verify_trust_chain`` and
``verify_ebsi_badge(trust_anchors=...)`` take the suite, so the opt-in rides on it with no new
parameter and no change to ``openvc_ebsi``. This file is the conformance claim:

* the GOLDEN: the preprod RootTAO accreditation JWT recorded on 2026-10-16
  (``tests/fixtures/ebsi/core-v1/``), byte for byte, verifies against the recorded
  ``secp256k1`` key with the opt-in and is refused without it (``UnsupportedAlgorithm``);
* the same token through the real chain path (``verify_trust_chain``) and the badge verifier;
* a SYNTHETIC chain whose root signs ES256K and whose other hops sign ES256, which reaches the
  anchor with the opt-in and is ``AccreditationInvalid`` without it.

What the recording does NOT hold: a leaf under the preprod root. The recorded chain is the
RootTAO accreditating itself (``tao == rootTao == subject``), so a recorded leaf-to-anchor walk
does not exist; the chain-level golden is the root hop through the real path (below), and
"reaches the anchor" is proved on the synthetic chain. The prod seed's DID document has an
empty ``verificationMethod``, so a prod chain cannot close with or without the opt-in.

The clock is pinned (the recorded token is valid 2026-09-21 to 2031-09-20): PyJWT reads
``datetime.now`` and the body window reads ``time.time``, and the fixture patches both.
Self-contained: ``tests/`` is not a package, so the small harness is copied.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt.api_jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from openvc.errors import OpenvcError
from openvc.multibase import b58btc_encode
from openvc.proof import _verify_common
from openvc.proof.errors import (
    ClaimsInvalid,
    ProofError,
    SignatureInvalid,
    UnsupportedAlgorithm,
)
from openvc.proof.vc_jwt import VcJwtProofSuite, VerifiedCredential
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.trust import (
    NoTrustedAnchor,
    AccreditationInvalid,
    TrustChainError,
    verify_trust_chain,
)
from openvc_ebsi.verify import IssuerNotTrusted, evaluate_issuer_trust, verify_ebsi_badge
from openvc_ebsi.versioning import (
    DidEbsiResolver,
    DidRegistryCoreV1,
    TirCoreV1,
    TirV5,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi" / "core-v1"
GRNET = "https://api-preprod.ebsi.grnet.gr"
DID = "did:ebsi:zmaEptEHQRAmkJnFV6ki3io"                    # the preprod RootTAO
OTHER_DID = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"              # well-formed, nowhere in the data
# what the RootTAO is accredited FOR (credentialSubject.accreditedFor[].types), and the types
# the accreditation credential itself carries (vc.type): two different lists in the recording
ROOT_TYPES = ["VerifiableCredential", "VerifiableAttestation",
              "VerifiableAuthorisationForTrustChain"]
ACCREDITATION_TYPES = ["VerifiableCredential", "VerifiableAttestation",
                       "VerifiableAccreditation", "VerifiableAccreditationToAttest"]
FROZEN = dt.datetime(2026, 10, 16, 12, 0, 0, tzinfo=dt.timezone.utc)   # the recording's day
AFTER_EXPIRY = dt.datetime(2032, 1, 1, tzinfo=dt.timezone.utc)
PEEK = VcJwtProofSuite().peek_claims


def opted_in() -> VcJwtProofSuite:
    """The opted-in suite, built at call time (so a tree without the keyword fails per test)."""
    return VcJwtProofSuite(allow_es256k=True)


def _rec(rel: str) -> dict[str, Any]:
    return json.loads((FIXTURES / rel).read_bytes())


def _manifest_url(rel: str) -> str:
    return _rec("MANIFEST.json")["files"][rel]["request_url"]


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


def _recorded_resolver() -> tuple[StubFetch, DidEbsiResolver]:
    names = ("did_document", "issuer", "attributes", "attribute_0dc6a111")
    fetch = StubFetch({_manifest_url(f"preprod-grnet/{n}.json"): _rec(f"preprod-grnet/{n}.json")
                       for n in names})
    return fetch, DidEbsiResolver(fetch, PEEK, base=GRNET, didr=DidRegistryCoreV1(),
                                  tir=TirCoreV1())


ROOT_TOKEN = _rec("preprod-grnet/attribute_0dc6a111.json")["attribute"]["body"]
PROD_TOKEN = _rec("prod-iti/attribute_030c5a3d.json")["attribute"]["body"]
DID_DOCUMENT = _rec("preprod-grnet/did_document.json")


def _method(kid_fragment_crv: str) -> dict[str, Any]:
    return next(m for m in DID_DOCUMENT["verificationMethod"]
                if m["publicKeyJwk"]["crv"] == kid_fragment_crv)


K1_METHOD = _method("secp256k1")
P256_METHOD = _method("P-256")


class _FrozenDatetime(dt.datetime):
    now_at = FROZEN

    @classmethod
    def now(cls, tz: Any = None) -> Any:               # type: ignore[override]
        return cls.now_at.astimezone(tz) if tz else cls.now_at.replace(tzinfo=None)


@pytest.fixture()
def frozen_clock(monkeypatch):
    """Pin both clocks the VC-JWT lane reads (PyJWT's, and the body window's)."""
    def at(moment: dt.datetime) -> None:
        stamp = moment.timestamp()
        monkeypatch.setattr(_FrozenDatetime, "now_at", moment)
        monkeypatch.setattr(jwt.api_jwt, "datetime", _FrozenDatetime)
        monkeypatch.setattr(_verify_common.time, "time", lambda: stamp)

    at(FROZEN)
    return at


class SpySuite(VcJwtProofSuite):
    """Records every verification the chain walk performs (token, key, result)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.verified: list[tuple[str, dict[str, Any], VerifiedCredential]] = []

    def verify(self, token: str, *, public_key_jwk: dict[str, Any], **kwargs: Any
               ) -> VerifiedCredential:
        result = super().verify(token, public_key_jwk=public_key_jwk, **kwargs)
        self.verified.append((token, public_key_jwk, result))
        return result


# --------------------------------------------------------------------------- #
# The recording is what it is
# --------------------------------------------------------------------------- #

def _header(token: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))


def test_the_recorded_root_accreditations_are_es256k_with_a_raw_64_octet_signature():
    for token in (ROOT_TOKEN, PROD_TOKEN):
        assert _header(token)["alg"] == "ES256K"
        assert len(base64.urlsafe_b64decode(token.split(".")[2] + "==")) == 64    # R||S, not DER
    kid = _header(ROOT_TOKEN)["kid"]
    assert kid == K1_METHOD["id"] and kid.startswith(DID + "#")
    assert K1_METHOD["publicKeyJwk"]["crv"] == "secp256k1"
    assert P256_METHOD["publicKeyJwk"]["crv"] == "P-256"       # the other key the document holds


# --------------------------------------------------------------------------- #
# The golden: refused without the opt-in, verified with it
# --------------------------------------------------------------------------- #

def test_golden_the_recorded_root_accreditation_is_refused_without_the_opt_in(frozen_clock):
    for suite in (VcJwtProofSuite(), VcJwtProofSuite(allow_pq=True)):
        with pytest.raises(UnsupportedAlgorithm, match="'ES256K' is not permitted") as exc:
            suite.verify(ROOT_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"])
        assert type(exc.value) is UnsupportedAlgorithm


def test_golden_the_recorded_root_accreditation_verifies_with_the_opt_in(frozen_clock):
    result = opted_in().verify(ROOT_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"],
                               expected_types=["VerifiableAccreditationToAttest"])
    assert result.issuer == DID and result.subject == DID
    assert result.claims["jti"] == "urn:uuid:5e91fb99-ca23-4d62-a177-f1ef91176ec1"
    assert result.credential["type"] == ACCREDITATION_TYPES
    assert result.credential["credentialSubject"]["accreditedFor"][0]["types"] == ROOT_TYPES
    assert result.expired is False


def test_golden_the_signature_is_the_recorded_one_not_a_re_signature(frozen_clock):
    # one flipped signature octet of the recorded token is refused: the verification above
    # is over these exact bytes, and the same key does not verify anything else
    head, body, sig = ROOT_TOKEN.split(".")
    raw = bytearray(base64.urlsafe_b64decode(sig + "=="))
    raw[10] ^= 0x01
    forged = f"{head}.{body}.{base64.urlsafe_b64encode(bytes(raw)).rstrip(b'=').decode()}"
    with pytest.raises(SignatureInvalid) as exc:
        opted_in().verify(forged, public_key_jwk=K1_METHOD["publicKeyJwk"])
    assert type(exc.value) is SignatureInvalid


def test_golden_the_other_key_in_the_same_document_is_refused_on_its_type(frozen_clock):
    # the DID document holds a P-256 key as well: an ES256K token never verifies against it,
    # and the refusal is the key-type pin (a plain ProofError), not a signature failure
    with pytest.raises(ProofError, match="ES256K requires an EC secp256k1 key") as exc:
        opted_in().verify(ROOT_TOKEN, public_key_jwk=P256_METHOD["publicKeyJwk"])
    assert type(exc.value) is ProofError


def test_golden_the_recorded_token_is_judged_on_its_real_window(frozen_clock):
    # valid 2026-09-21 .. 2031-09-20: a clock after that is ClaimsInvalid, and the waiver
    # verifies it and says it expired
    frozen_clock(AFTER_EXPIRY)
    with pytest.raises(ClaimsInvalid, match="expired") as exc:
        opted_in().verify(ROOT_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"])
    assert type(exc.value) is ClaimsInvalid
    waived = opted_in().verify(ROOT_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"],
                               check_temporal=False)
    assert waived.expired is True and waived.issuer == DID
    # and before nbf
    frozen_clock(dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc))
    with pytest.raises(ClaimsInvalid) as exc2:
        opted_in().verify(ROOT_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"])
    assert type(exc2.value) is ClaimsInvalid


def test_golden_a_second_recorded_signature_the_prod_root_under_the_preprod_key(frozen_clock):
    # EVIDENCE, NOT A TRUST PATH. The prod seed root's DID document has no verification method
    # (ADR-0009 D8), so a prod chain cannot close. The prod RootTAO accreditation carries the
    # same `kid` fragment as the preprod one, and its signature verifies under the PREPROD
    # secp256k1 key: a second real ES256K signature, from another node and another day. The
    # key here is read from the preprod document, never from the prod one.
    prod_doc = _rec("prod-iti/did_document.json")
    assert prod_doc.get("verificationMethod") == []
    prod_kid = _header(PROD_TOKEN)["kid"]
    assert prod_kid.split("#", 1)[1] == K1_METHOD["id"].split("#", 1)[1]
    result = opted_in().verify(PROD_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"])
    assert result.issuer == "did:ebsi:z262SoSjWAqmXpaGmzqGnJoc"
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().verify(PROD_TOKEN, public_key_jwk=K1_METHOD["publicKeyJwk"])


# --------------------------------------------------------------------------- #
# The golden through the real chain path
# --------------------------------------------------------------------------- #

def test_golden_chain_without_the_opt_in_is_accreditation_invalid_wrapping_the_refusal(
        frozen_clock):
    _, resolver = _recorded_resolver()
    with pytest.raises(AccreditationInvalid, match="ES256K") as exc:
        verify_trust_chain(DID, ROOT_TYPES, resolver=resolver, proof_suite=VcJwtProofSuite(),
                           anchors={OTHER_DID})
    assert type(exc.value) is AccreditationInvalid
    assert type(exc.value.__cause__) is UnsupportedAlgorithm


def test_golden_chain_with_the_opt_in_verifies_the_recorded_hop_then_meets_the_cycle(
        frozen_clock):
    # The recording is the root accrediting itself, so the walk verifies its one hop and
    # then sees the accreditor (itself) again: TrustChainError, not AccreditationInvalid.
    # That the hop's signature was checked, and passed, is what the spy records.
    spy = SpySuite(allow_es256k=True)
    _, resolver = _recorded_resolver()
    with pytest.raises(TrustChainError, match="accreditation cycle") as exc:
        verify_trust_chain(DID, ROOT_TYPES, resolver=resolver, proof_suite=spy,
                           anchors={OTHER_DID})
    assert type(exc.value) is TrustChainError
    assert len(spy.verified) == 1
    token, jwk, result = spy.verified[0]
    assert token == ROOT_TOKEN and jwk == K1_METHOD["publicKeyJwk"] and result.issuer == DID


def test_golden_the_leaf_that_is_itself_the_anchor_needs_no_signature_check(frozen_clock):
    # control for the two tests above: with the root as the anchor the walk returns before
    # verifying anything, so neither suite is consulted
    spy = SpySuite(allow_es256k=True)
    _, resolver = _recorded_resolver()
    chain = verify_trust_chain(DID, ROOT_TYPES, resolver=resolver, proof_suite=spy,
                               anchors={DID})
    assert chain.anchor == DID and chain.hops == () and spy.verified == []


def test_golden_verify_ebsi_badge_on_the_recorded_token_needs_the_opt_in(frozen_clock):
    # The accreditation is itself a VC-JWT issued by the root: handed to verify_ebsi_badge as
    # the badge, its signature is checked at step 4 with the suite's allow-list, the key picked
    # by `kid` out of the recorded two-key document. One suite serves the leaf and the hops.
    _, resolver = _recorded_resolver()
    with pytest.raises(UnsupportedAlgorithm) as exc:
        verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=VcJwtProofSuite())
    assert type(exc.value) is UnsupportedAlgorithm

    fetch, resolver = _recorded_resolver()
    # with the opt-in the signature verifies; trust does not follow (#367): the badge is the
    # root's own accreditation, whose specific type (`VerifiableAccreditationToAttest`) is not
    # what its `accreditedFor` lists (`VerifiableAuthorisationForTrustChain`), and the generic
    # types the two lists share no longer count. Until 1.38.0 this was `trusted=True`.
    with pytest.raises(IssuerNotTrusted, match="no valid accreditation"):
        verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=opted_in(),
                          expected_types=["VerifiableAccreditationToAttest"])
    result = verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=opted_in(),
                               expected_types=["VerifiableAccreditationToAttest"],
                               require_trust=False)
    assert result.trusted is False and result.issuer == DID
    assert result.verified.issuer == DID and result.chain is None
    assert result.accreditation is None and result.issuer_record is not None
    assert result.issuer_record.accreditations[0].issuer_type == "RootTAO"
    assert fetch.calls[0] == _manifest_url("preprod-grnet/did_document.json")


def test_golden_recursive_badge_mode_follows_the_same_two_branches(frozen_clock):
    _, resolver = _recorded_resolver()
    # the issuer is the anchor: trusted, no hop to verify
    ok = verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=opted_in(),
                           trust_anchors={DID})
    assert ok.trusted is True and ok.chain is not None and ok.chain.hops == ()
    # another anchor: the leaf pick refuses the root's own accreditation for this credential
    # (#367: its specific type is not what the accreditedFor lists), before the walk would
    # have met the self-accreditation cycle it met until 1.38.0
    with pytest.raises(NoTrustedAnchor, match="no valid accreditation") as exc:
        verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=opted_in(),
                          trust_anchors={OTHER_DID})
    assert type(exc.value) is NoTrustedAnchor
    soft = verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=opted_in(),
                             trust_anchors={OTHER_DID}, require_trust=False)
    assert soft.trusted is False and soft.chain is None
    # and without the opt-in the badge itself is refused before any trust question
    with pytest.raises(UnsupportedAlgorithm):
        verify_ebsi_badge(ROOT_TOKEN, resolver=resolver, proof_suite=VcJwtProofSuite(),
                          trust_anchors={DID})


def test_single_level_trust_still_reads_the_es256k_accreditation_without_verifying_it():
    # unchanged by the opt-in: the registry is the anchor, the accreditation's signature is
    # never checked, so the default suite sees the ES256K root as before
    _, resolver = _recorded_resolver()
    record = resolver.issuer_record(DID)
    assert evaluate_issuer_trust(record, ROOT_TYPES) is record.accreditations[0]
    assert VcJwtProofSuite().peek_claims(record.accreditations[0].credential_jwt)["iss"] == DID


# --------------------------------------------------------------------------- #
# A synthetic chain: ES256K root, ES256 below it
# --------------------------------------------------------------------------- #

BASE = "https://api-pilot.ebsi.eu"
TYPES = ["OpenBadgeCredential"]


def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, MID, ROOT = _did(0xA1), _did(0xB2), _did(0xC3)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class Signer:
    alg: str
    key: ec.EllipticCurvePrivateKey
    crv: str
    order: int

    @property
    def jwk(self) -> dict[str, Any]:
        nums = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": self.crv, "x": b64(nums.x.to_bytes(32, "big")),
                "y": b64(nums.y.to_bytes(32, "big"))}

    def sign(self, signing_input: bytes, *, high_s: bool = False) -> bytes:
        r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        if (s > self.order // 2) != high_s:
            s = self.order - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def signer(alg: str) -> Signer:
    if alg == "ES256K":
        return Signer(alg, ec.generate_private_key(ec.SECP256K1()), "secp256k1", N_K1)
    return Signer(alg, ec.generate_private_key(ec.SECP256R1()), "P-256", N_P256)


def jws(by: Signer, kid: str, payload: dict[str, Any], *, high_s: bool = False,
        header: dict[str, Any] | None = None) -> str:
    head = {"alg": by.alg, "typ": "JWT", "kid": kid}
    head.update(header or {})
    h, p = b64(json.dumps(head).encode()), b64(json.dumps(payload).encode())
    return f"{h}.{p}.{b64(by.sign(f'{h}.{p}'.encode(), high_s=high_s))}"


def _accreditation(by: Signer, kid: str, *, subject: str, accredited_by: str,
                   kind: str = "VerifiableAccreditationToAttest",
                   high_s: bool = False, header: dict[str, Any] | None = None) -> str:
    now = int(FROZEN.timestamp())
    vc = {"id": f"urn:uuid:acc-{subject[-4:]}",
          "type": ["VerifiableCredential", kind],      # the kind of the hop (#368)
          "issuer": accredited_by,
          "credentialSubject": {"id": subject, "accreditedFor": [{"types": TYPES}]}}
    return jws(by, kid, {"iss": accredited_by, "sub": subject, "nbf": now - 60, "iat": now - 60,
                         "exp": now + 3600, "vc": vc}, high_s=high_s, header=header)


def _badge(by: Signer, kid: str) -> str:
    now = int(FROZEN.timestamp())
    vc = {"id": "urn:uuid:badge-1",
          "type": ["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"],
          "issuer": LEAF, "credentialSubject": {"id": "did:key:z6MkSubject"}}
    return jws(by, kid, {"iss": LEAF, "nbf": now - 60, "iat": now - 60, "exp": now + 3600,
                         "vc": vc})


def _did_doc(did: str, *methods: Signer) -> dict[str, Any]:
    vms = [{"id": f"{did}#key-{i}", "type": "JsonWebKey2020", "controller": did,
            "publicKeyJwk": m.jwk} for i, m in enumerate(methods, start=1)]
    return {"didDocument": {"id": did, "verificationMethod": vms,
                            "assertionMethod": [vm["id"] for vm in vms]}}


def _tir_routes(did: str, token: str, tag: str, *, issuer_type: str, tao: str) -> dict:
    issuer = f"{BASE}/trusted-issuers-registry/v5/issuers/{did}"
    attrs, rev = f"{issuer}/attributes", f"{issuer}/attributes/{tag}/revisions/r1"
    return {
        issuer: {"did": did, "hasAttributes": True, "attributes": attrs},
        attrs: {"items": [{"id": tag, "href": rev}]},
        rev: {"did": did, "attribute": {"body": token, "hash": tag, "issuerType": issuer_type,
                                        "tao": tao, "rootTao": ROOT}},
    }


def build_world(*, leaf="ES256", mid="ES256", root="ES256K", high_s_root: bool = False,
                root_kid: str | None = None, root_extra_key: Signer | None = None,
                root_header: dict[str, Any] | None = None) -> SimpleNamespace:
    """LEAF -(TAO)-> MID -(RootTAO)-> ROOT, each key of the algorithm named, every token
    hand-built. The ROOT accreditation of MID is the hop that carries *root*'s algorithm."""
    leaf_k, mid_k, root_k = signer(leaf), signer(mid), signer(root)
    methods = (root_k,) if root_extra_key is None else (root_k, root_extra_key)
    badge = _badge(leaf_k, f"{LEAF}#key-1")
    leaf_acc = _accreditation(mid_k, f"{MID}#key-1", subject=LEAF, accredited_by=MID)
    mid_acc = _accreditation(root_k, root_kid or f"{ROOT}#key-1", subject=MID,
                             accredited_by=ROOT, high_s=high_s_root, header=root_header,
                             kind="VerifiableAccreditationToAccredit")
    routes: dict[str, Any] = {
        f"{BASE}/did-registry/v5/identifiers/{LEAF}": _did_doc(LEAF, leaf_k),
        f"{BASE}/did-registry/v5/identifiers/{MID}": _did_doc(MID, mid_k),
        f"{BASE}/did-registry/v5/identifiers/{ROOT}": _did_doc(ROOT, *methods),
    }
    routes.update(_tir_routes(LEAF, leaf_acc, "leaf", issuer_type="TI", tao=MID))
    routes.update(_tir_routes(MID, mid_acc, "mid", issuer_type="TAO", tao=ROOT))
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, PEEK, tir=TirV5())
    return SimpleNamespace(badge=badge, resolver=resolver, fetch=fetch, routes=routes,
                           keys=SimpleNamespace(leaf=leaf_k, mid=mid_k, root=root_k))


def walk(world: SimpleNamespace, suite: VcJwtProofSuite, **kw: Any):
    return verify_trust_chain(LEAF, TYPES, resolver=world.resolver, proof_suite=suite,
                              anchors={ROOT}, **kw)


def test_an_es256k_root_over_es256_hops_is_refused_by_the_default_suite(frozen_clock):
    world = build_world()
    with pytest.raises(AccreditationInvalid) as exc:
        walk(world, VcJwtProofSuite())
    assert type(exc.value) is AccreditationInvalid
    assert type(exc.value.__cause__) is UnsupportedAlgorithm
    assert f"accreditation for {MID!r}" in str(exc.value)          # the ROOT's hop, not the leaf's


def test_an_es256k_root_over_es256_hops_reaches_the_anchor_with_the_opt_in(frozen_clock):
    world = build_world()
    chain = walk(world, opted_in())
    assert chain.anchor == ROOT
    assert [(h.subject, h.accreditor) for h in chain.hops] == [(LEAF, MID), (MID, ROOT)]
    assert chain.scope == frozenset(TYPES)


def test_the_same_chain_through_verify_ebsi_badge(frozen_clock):
    world = build_world()
    with pytest.raises(AccreditationInvalid) as exc:
        verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=VcJwtProofSuite(),
                          trust_anchors={ROOT})
    assert type(exc.value) is AccreditationInvalid
    result = verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=opted_in(),
                               trust_anchors={ROOT}, expected_types=["OpenBadgeCredential"])
    assert result.trusted is True and result.chain is not None
    assert result.chain.anchor == ROOT and len(result.chain.hops) == 2


def test_the_high_s_form_of_the_roots_signature_closes_the_chain_too(frozen_clock):
    # Decision 2 at the chain level: accept both forms of the root's signature
    world = build_world(high_s_root=True)
    token = world.routes[f"{BASE}/trusted-issuers-registry/v5/issuers/{MID}/attributes/mid/"
                         "revisions/r1"]["attribute"]["body"]
    s = int.from_bytes(base64.urlsafe_b64decode(token.split(".")[2] + "==")[32:], "big")
    assert s > N_K1 // 2                                     # it really is the high-s twin
    assert walk(world, opted_in()).anchor == ROOT


def test_a_wrong_roots_key_is_a_signature_failure_not_a_trust_grant(frozen_clock):
    world = build_world()
    world.routes[f"{BASE}/did-registry/v5/identifiers/{ROOT}"] = _did_doc(ROOT, signer("ES256K"))
    with pytest.raises(AccreditationInvalid) as exc:
        walk(world, opted_in())
    assert type(exc.value) is AccreditationInvalid
    assert type(exc.value.__cause__) is SignatureInvalid


def test_a_root_whose_document_holds_both_keys_picks_by_kid_and_pins_the_type(frozen_clock):
    # the shape of the recorded preprod document: a secp256k1 and a P-256 method side by side
    p256_method = signer("ES256")
    world = build_world(root_extra_key=p256_method)
    assert walk(world, opted_in()).anchor == ROOT                    # kid #key-1: the secp256k1 one
    # an ES256K hop whose kid names the P-256 method: the key-type pin, wrapped
    wrong = build_world(root_extra_key=p256_method, root_kid=f"{ROOT}#key-2")
    with pytest.raises(AccreditationInvalid) as exc:
        walk(wrong, opted_in())
    assert type(exc.value) is AccreditationInvalid
    assert type(exc.value.__cause__) is ProofError
    assert "ES256K requires an EC secp256k1 key" in str(exc.value)
    # and the reverse: an ES256 hop whose kid names the secp256k1 method
    reverse = build_world(root="ES256", root_extra_key=signer("ES256K"),
                          root_kid=f"{ROOT}#key-2")
    with pytest.raises(AccreditationInvalid) as exc2:
        walk(reverse, opted_in())
    assert type(exc2.value.__cause__) is ProofError
    assert "ES256 requires an EC P-256 key" in str(exc2.value)


def test_a_hop_signed_es256_by_a_secp256k1_key_is_the_existing_pin(frozen_clock):
    world = build_world(root="ES256")
    world.routes[f"{BASE}/did-registry/v5/identifiers/{ROOT}"] = _did_doc(ROOT, signer("ES256K"))
    with pytest.raises(AccreditationInvalid) as exc:
        walk(world, opted_in())
    assert type(exc.value.__cause__) is ProofError


def test_the_gates_after_the_allow_list_still_guard_an_accreditation(frozen_clock):
    world = build_world(root_header={"crit": ["x-unknown"], "x-unknown": 1})
    with pytest.raises(AccreditationInvalid) as exc:
        walk(world, opted_in())
    assert type(exc.value.__cause__).__name__ == "MalformedToken"


def test_one_suite_serves_the_leaf_badge_and_the_hops(frozen_clock):
    # Decision 3: no separate accreditation suite. An opted-in suite lets the LEAF badge be
    # ES256K-signed too; the default suite refuses it before any trust question.
    world = build_world(leaf="ES256K")
    result = verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=opted_in(),
                               trust_anchors={ROOT})
    assert result.trusted is True and result.chain is not None
    with pytest.raises(UnsupportedAlgorithm) as exc:
        verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=VcJwtProofSuite(),
                          trust_anchors={ROOT})
    assert type(exc.value) is UnsupportedAlgorithm


def test_single_level_trust_is_unchanged_whatever_the_accreditation_algorithm(frozen_clock):
    # an ES256K accreditation of the leaf: single-level never checks its signature, with or
    # without the opt-in; recursive mode does, and so needs the opt-in
    world = build_world(mid="ES256K")
    leaf_issuer = f"{BASE}/trusted-issuers-registry/v5/issuers/{LEAF}"
    assert _header(world.routes[f"{leaf_issuer}/attributes/leaf/revisions/r1"]
                   ["attribute"]["body"])["alg"] == "ES256K"
    for suite in (VcJwtProofSuite(), opted_in()):
        single = verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=suite)
        assert single.trusted is True and single.chain is None
    with pytest.raises(AccreditationInvalid) as exc:
        verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=VcJwtProofSuite(),
                          trust_anchors={ROOT})
    assert type(exc.value.__cause__) is UnsupportedAlgorithm
    assert verify_ebsi_badge(world.badge, resolver=world.resolver, proof_suite=opted_in(),
                             trust_anchors={ROOT}).trusted is True


def test_an_all_es256_chain_is_unaffected_by_the_opt_in(frozen_clock):
    world = build_world(root="ES256")
    for suite in (VcJwtProofSuite(), opted_in()):
        assert walk(world, suite).anchor == ROOT


def test_the_chain_errors_stay_inside_the_taxonomy(frozen_clock):
    world = build_world()
    with pytest.raises(OpenvcError):
        walk(world, VcJwtProofSuite())
