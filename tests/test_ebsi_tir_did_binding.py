"""
tests/test_ebsi_tir_did_binding.py — the TIR issuer response is bound to the requested DID (#267).

`DidEbsiResolver.issuer_record` handed the registry body to the adapter and returned what
came back; neither adapter read the response's own ``did``, and ``IssuerRecord.did`` was
filled from the *request*. So a record that was about another issuer (or about nobody) was
accepted, relabelled as the requested DID, and in single-level mode it was the trust decision.
The resolver now asks the adapter where the DID sits (``TirAdapter.response_did``), compares it
with the requested DID exactly, BEFORE the adapter follows any link, and raises
``MalformedRegistryResponse`` on any difference, an absent ``did`` included, for every version.

Negatives first, each asserting the exact class, with a resolvable DID and a registry stub that
serves the mismatched record, so a test cannot pass on an earlier failure. TirV5 runs on the
recorded golden fixture with its ``did`` swapped; TirV4 has no recorded response, so its cases
are SYNTHETIC inline bodies (flagged as such). Self-contained: `tests/` is not a package.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from openvc.did.base import DidResolutionError
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import MalformedRegistryResponse
from openvc_ebsi.http import EbsiHttpClient, HttpNotFound
from openvc_ebsi.models import IssuerRecord
from openvc_ebsi.trust import verify_trust_chain
from openvc_ebsi.verify import verify_ebsi_badge
from openvc_ebsi.versioning import DidEbsiResolver, TirAdapter, TirV4, TirV5

BASE = "https://api-pilot.ebsi.eu"
FIXTURES = Path(__file__).parent / "fixtures" / "ebsi"
_ABSENT = object()                              # the response has no `did` member at all


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


GOLDEN_ISSUER = _load("tir_v5_issuer.json")
GOLDEN_ATTRS = _load("tir_v5_attributes.json")
GOLDEN_REVS = _load("tir_v5_revisions.json")
DID = GOLDEN_ISSUER["did"]                      # did:ebsi:zZeKyEJfUTGwajhNyNX928z, a RootTAO
OTHER = _did(0xD4)                              # a well-formed DID that is nobody's here
ISSUER_URL = f"{BASE}/trusted-issuers-registry/v5/issuers/{DID}"


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


def _with_did(record: dict, value: object) -> dict:
    """*record* with its `did` member set to *value* (left out for ``_ABSENT``)."""
    out = {k: v for k, v in record.items() if k != "did"}
    if value is not _ABSENT:
        out["did"] = value
    return out


def _golden_routes(response_did: object) -> dict[str, Any]:
    """The recorded TIR v5 multi-hop (issuer -> listing -> 3 revisions), the issuer
    response carrying *response_did* in place of its own."""
    routes: dict[str, Any] = {
        ISSUER_URL: _with_did(GOLDEN_ISSUER, response_did),
        GOLDEN_ISSUER["attributes"]: GOLDEN_ATTRS,
    }
    for item in GOLDEN_ATTRS["items"]:
        routes[item["href"]] = GOLDEN_REVS[item["id"]]
    return routes


def _v4_body(response_did: object) -> dict:
    # SYNTHETIC: there is no recorded TIR v4 response in this repository. v4 keeps its
    # attributes inline; the `did` is placed where the v5 record carries it.
    return _with_did({"attributes": [
        {"hash": "h1", "issuerType": "TI", "tao": OTHER, "rootTao": OTHER}]}, response_did)


def _resolver(fetch: Any, tir: TirAdapter) -> DidEbsiResolver:
    return DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=tir, base=BASE)


# the response's `did`: another DID, or not a usable string at all
WRONG_DIDS = [
    pytest.param(OTHER, id="another-did"),
    pytest.param(None, id="null"),
    pytest.param(_ABSENT, id="absent"),
    pytest.param(7, id="number"),
    pytest.param([], id="list"),
    pytest.param({}, id="object"),
    pytest.param(True, id="bool"),
    pytest.param("", id="empty"),
    pytest.param(DID.lower(), id="case-folded"),
    pytest.param(DID + " ", id="trailing-space"),
    pytest.param(DID + "#key-1", id="did-url"),
]


# --------------------------------------------------------------------------- #
# Controls first: a matching `did` resolves, on both versions
# --------------------------------------------------------------------------- #

def test_control_golden_v5_record_resolves() -> None:
    fetch = StubFetch(_golden_routes(DID))
    rec = _resolver(fetch, TirV5()).issuer_record(DID)
    assert rec.did == DID and rec.has_attributes and len(rec.accreditations) == 3
    assert len(fetch.calls) == 5                                  # issuer, listing, 3 revisions


def test_control_synthetic_v4_record_resolves() -> None:
    fetch = StubFetch({f"{BASE}/trusted-issuers-registry/v4/issuers/{DID}": _v4_body(DID)})
    rec = _resolver(fetch, TirV4()).issuer_record(DID)
    assert rec.did == DID and rec.has_attributes and len(rec.accreditations) == 1
    assert fetch.calls == [f"{BASE}/trusted-issuers-registry/v4/issuers/{DID}"]


# --------------------------------------------------------------------------- #
# The comparison, before any link is followed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", WRONG_DIDS)
def test_tir_v5_refuses_a_record_that_is_not_about_the_requested_did(value: object) -> None:
    fetch = StubFetch(_golden_routes(value))
    with pytest.raises(MalformedRegistryResponse, match="TIR issuer response names") as exc_info:
        _resolver(fetch, TirV5()).issuer_record(DID)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert fetch.calls == [ISSUER_URL]          # no `attributes` page, no revision `href`


@pytest.mark.parametrize("value", WRONG_DIDS)
def test_tir_v4_refuses_a_record_that_is_not_about_the_requested_did(value: object) -> None:
    # SYNTHETIC v4 body. An ABSENT `did` is refused for v4 too: one rule across versions.
    url = f"{BASE}/trusted-issuers-registry/v4/issuers/{DID}"
    fetch = StubFetch({url: _v4_body(value)})
    with pytest.raises(MalformedRegistryResponse, match="TIR issuer response names") as exc_info:
        _resolver(fetch, TirV4()).issuer_record(DID)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert fetch.calls == [url]


@pytest.mark.parametrize("body", [
    pytest.param(None, id="null"),
    pytest.param([], id="list"),
    pytest.param("oops", id="string"),
    pytest.param(7, id="number"),
])
@pytest.mark.parametrize("version", ["v4", "v5"])
def test_a_non_object_issuer_body_is_malformed_on_every_version(version: str, body: object) -> None:
    # `_require_object` moved up into the resolver for this body: TirV4's `parse_issuer`
    # did `raw.get(...)` on whatever it was handed, a bare AttributeError for a non-object.
    tir = TirV4() if version == "v4" else TirV5()
    url = f"{BASE}/trusted-issuers-registry/{version}/issuers/{DID}"
    fetch = StubFetch({url: body})
    with pytest.raises(MalformedRegistryResponse, match="expected a JSON object") as exc_info:
        _resolver(fetch, tir).issuer_record(DID)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert fetch.calls == [url]


def test_the_mismatch_message_is_bounded() -> None:
    # The registry-supplied `did` is attacker-sized; the requested one is validated before
    # the comparison (#266), so a requested DID that long is refused on syntax and has its
    # own bounded message in test_ebsi_did_syntax.py.
    long_did = "did:ebsi:" + "y" * 60_000
    fetch = StubFetch(_golden_routes(long_did))
    with pytest.raises(MalformedRegistryResponse) as exc_info:
        _resolver(fetch, TirV5()).issuer_record(DID)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert str(exc_info.value) == (
        f"TIR issuer response names {long_did[:200]!r}... (60009 chars), requested {DID!r}")
    assert len(str(exc_info.value)) < 300
    # a non-scalar is named by its type, never repr()ed
    fetch = StubFetch(_golden_routes([[[[[]]]]]))
    with pytest.raises(MalformedRegistryResponse) as list_info:
        _resolver(fetch, TirV5()).issuer_record(DID)
    assert str(list_info.value) == f"TIR issuer response names list, requested {DID!r}"


def test_a_did_url_is_refused_through_the_real_client() -> None:
    # A DID URL used to resolve by accident: httpx drops the fragment, the registry answered
    # with the DID's own record and `IssuerRecord.did` held the URL. Refused on syntax now
    # (#266), before a request; the control proves the registry does answer the bare DID.
    paths: list[str] = []
    record_path = f"/trusted-issuers-registry/v5/issuers/{DID}"

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.raw_path.decode())
        if request.url.path == record_path:
            return httpx.Response(200, json={"did": DID, "hasAttributes": False})
        return httpx.Response(404, json={})
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    resolver = _resolver(client.get_json, TirV5())
    assert resolver.issuer_record(DID).did == DID                       # control
    with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
        resolver.issuer_record(f"{DID}#key-1")
    assert type(exc_info.value) is DidResolutionError
    assert paths == [record_path]                                       # the control's only
    client.close()


# --------------------------------------------------------------------------- #
# The trust decision, single level: a misrouted record is no longer trusted
# --------------------------------------------------------------------------- #

def _badge_for(issuer: str):
    """A badge signed by *issuer* (not accredited anywhere), the registry's DID document for
    it, and the suite. The type is one the recorded RootTAO accreditations authorise."""
    suite = VcJwtProofSuite()
    sk = P256SigningKey.generate(kid=f"{issuer}#key-1")
    token = suite.sign({
        "@context": ["https://www.w3.org/2018/credentials/v1"], "id": "urn:uuid:badge-267",
        "type": ["VerifiableCredential", "VerifiableAuthorisationForTrustChain"],
        "issuer": issuer, "credentialSubject": {"id": "did:key:z6MkSubject"}},
        signing_key=sk)
    doc = {"id": issuer, "verificationMethod": [{
        "id": f"{issuer}#key-1", "type": "JsonWebKey2020", "controller": issuer,
        "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{issuer}#key-1"]}
    return suite, token, doc


def _single_level_registry(response_did: object) -> tuple[StubFetch, DidEbsiResolver, Any, str]:
    # OTHER holds no accreditation, but the TIR answers its issuer request with the recorded
    # RootTAO record (a misrouted answer). Everything else is in order: the badge verifies.
    suite, token, doc = _badge_for(OTHER)
    routes = _golden_routes(response_did)
    routes[f"{BASE}/trusted-issuers-registry/v5/issuers/{OTHER}"] = routes.pop(ISSUER_URL)
    routes[f"{BASE}/did-registry/v5/identifiers/{OTHER}"] = doc
    fetch = StubFetch(routes)
    return fetch, DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=BASE), \
        suite, token


def test_control_single_level_trusts_a_record_that_names_the_issuer() -> None:
    # Same stub, the record's `did` set to the issuer's own: the badge verifies as trusted,
    # on the record, and the record is the issuer's. So `did` is the only thing that differs.
    _, resolver, suite, token = _single_level_registry(OTHER)
    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)
    assert result.trusted is True
    assert result.issuer_record is not None and result.issuer_record.did == OTHER


@pytest.mark.parametrize("require_trust", [True, False])
@pytest.mark.parametrize("value", [
    pytest.param(DID, id="another-issuer"),             # the repro: the RootTAO's record
    pytest.param(None, id="null"),
    pytest.param(_ABSENT, id="absent"),
    pytest.param(7, id="number"),
])
def test_single_level_refuses_a_misrouted_record(value: object, require_trust: bool) -> None:
    # Before: trusted=True on the record of another issuer, relabelled with the issuer's DID.
    # A mismatched body is malformed input, not an untrusted issuer, so `require_trust=False`
    # does not suppress it and it is not wrapped in IssuerNotTrusted.
    fetch, resolver, suite, token = _single_level_registry(value)
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                          require_trust=require_trust)
    assert type(exc_info.value) is MalformedRegistryResponse
    assert fetch.calls[-1] == f"{BASE}/trusted-issuers-registry/v5/issuers/{OTHER}"
    assert len(fetch.calls) == 2                         # the DID document, then the one record


# --------------------------------------------------------------------------- #
# Recursive mode: the class changed from AccreditationInvalid, the outcome did not
# --------------------------------------------------------------------------- #

ROOT = _did(0xC3)
LEAF = _did(0xA1)


def _chain(response_did: object):
    """LEAF accredited by ROOT, with a genuine signed accreditation; the TIR record served
    for LEAF carries *response_did*."""
    suite = VcJwtProofSuite()
    leaf_sk = P256SigningKey.generate(kid=f"{LEAF}#key-1")
    root_sk = P256SigningKey.generate(kid=f"{ROOT}#key-1")
    token = suite.sign({
        "@context": ["https://www.w3.org/2018/credentials/v1"], "id": "urn:uuid:badge-267b",
        "type": ["VerifiableCredential", "OpenBadgeCredential"], "issuer": LEAF,
        "credentialSubject": {"id": "did:key:z6MkSubject"}}, signing_key=leaf_sk)
    acc = suite.sign({
        "id": "urn:uuid:acc-267",
        "type": ["VerifiableCredential", "VerifiableAccreditationToAttest"], "issuer": ROOT,
        "credentialSubject": {"id": LEAF, "accreditedFor": [{"types": ["OpenBadgeCredential"]}]}},
        signing_key=root_sk)
    issuer_url = f"{BASE}/trusted-issuers-registry/v5/issuers/{LEAF}"
    attrs, rev = f"{issuer_url}/attributes", f"{issuer_url}/attributes/aa/revisions/bb"

    def doc(did: str, sk: P256SigningKey) -> dict:
        return {"id": did, "verificationMethod": [{
            "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
            "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{did}#key-1"]}
    fetch = StubFetch({
        f"{BASE}/did-registry/v5/identifiers/{LEAF}": doc(LEAF, leaf_sk),
        f"{BASE}/did-registry/v5/identifiers/{ROOT}": doc(ROOT, root_sk),
        issuer_url: _with_did({"hasAttributes": True, "attributes": attrs}, response_did),
        attrs: {"items": [{"id": "aa", "href": rev}]},
        rev: {"did": LEAF, "attribute": {"body": acc, "hash": "aa", "issuerType": "TI",
                                         "tao": ROOT, "rootTao": ROOT}},
    })
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=BASE)
    return suite, token, fetch, resolver, issuer_url


def test_control_recursive_walk_reaches_the_anchor() -> None:
    suite, token, _, resolver, _ = _chain(LEAF)
    chain = verify_trust_chain(LEAF, ["OpenBadgeCredential"], resolver=resolver,
                               proof_suite=suite, anchors={ROOT})
    assert chain.anchor == ROOT and len(chain.hops) == 1
    assert verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                             trust_anchors={ROOT}).trusted is True


@pytest.mark.parametrize("value", [
    pytest.param(OTHER, id="another-did"),
    pytest.param(None, id="null"),
    pytest.param(_ABSENT, id="absent"),
])
def test_recursive_walk_refuses_a_record_that_is_not_the_walked_dids(value: object) -> None:
    # Measured on main: the misrouted record was refused LATER, as AccreditationInvalid, from
    # the signed accreditation's subject, and only after the accreditor was resolved. It is
    # now MalformedRegistryResponse at the first `issuer_record` call, before anything else
    # is fetched: the class changed, the outcome (refused) did not.
    suite, token, fetch, resolver, issuer_url = _chain(value)
    with pytest.raises(OpenvcError) as exc_info:
        verify_trust_chain(LEAF, ["OpenBadgeCredential"], resolver=resolver,
                           proof_suite=suite, anchors={ROOT})
    assert type(exc_info.value) is MalformedRegistryResponse
    assert fetch.calls == [issuer_url]

    for require_trust in (True, False):               # and through the badge verifier
        fetch.calls.clear()
        with pytest.raises(OpenvcError) as bexc:
            verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                              trust_anchors={ROOT}, require_trust=require_trust)
        assert type(bexc.value) is MalformedRegistryResponse
        assert fetch.calls == [f"{BASE}/did-registry/v5/identifiers/{LEAF}", issuer_url]


# --------------------------------------------------------------------------- #
# The hook: where the DID sits is the adapter's, the policy is the resolver's
# --------------------------------------------------------------------------- #

class _NestedV6(TirAdapter):
    """A hypothetical third-party adapter whose response keeps the DID under `subject.id`.
    It overrides `response_did` and nothing else of the policy."""
    version = "v6"

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/trusted-issuers-registry/v6/issuers/{did}"

    def response_did(self, raw: dict[str, Any]) -> Any:
        subject = raw.get("subject")
        return subject.get("id") if isinstance(subject, dict) else None

    def parse_issuer(self, raw: dict[str, Any], *, base: str, did: str,
                     fetch: Any, decode: Any) -> IssuerRecord:
        return IssuerRecord(did=did, has_attributes=False, accreditations=())


class _LegacyAdapter(TirAdapter):
    """Written before the hook existed: implements only the two abstract methods."""
    version = "v0"

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/legacy/{did}"

    def parse_issuer(self, raw: dict[str, Any], *, base: str, did: str,
                     fetch: Any, decode: Any) -> IssuerRecord:
        return IssuerRecord(did=did, has_attributes=False, accreditations=())


def test_a_new_version_moves_the_field_and_inherits_the_policy() -> None:
    url = f"{BASE}/trusted-issuers-registry/v6/issuers/{DID}"
    good = _resolver(StubFetch({url: {"subject": {"id": DID}, "did": OTHER}}), _NestedV6())
    assert good.issuer_record(DID).did == DID            # the top-level `did` is not read
    for body in ({"subject": {"id": OTHER}, "did": DID}, {"did": DID}, {"subject": 7}):
        resolver = _resolver(StubFetch({url: body}), _NestedV6())
        with pytest.raises(MalformedRegistryResponse) as exc_info:
            resolver.issuer_record(DID)
        assert type(exc_info.value) is MalformedRegistryResponse


def test_an_adapter_written_before_the_hook_still_instantiates_and_is_bound() -> None:
    assert _LegacyAdapter().response_did({"did": DID}) == DID      # the default: top level
    assert _LegacyAdapter().response_did({}) is None
    url = f"{BASE}/legacy/{DID}"
    assert _resolver(StubFetch({url: {"did": DID}}), _LegacyAdapter()).issuer_record(DID).did == DID
    with pytest.raises(MalformedRegistryResponse) as exc_info:
        _resolver(StubFetch({url: {"did": OTHER}}), _LegacyAdapter()).issuer_record(DID)
    assert type(exc_info.value) is MalformedRegistryResponse


# --------------------------------------------------------------------------- #
# The residual that is NOT closed here (delete when its follow-up lands)
# --------------------------------------------------------------------------- #

def test_residual_attributes_url_into_another_issuers_listing_still_resolves() -> None:
    # A record whose `did` is right but whose `attributes` URL points into ANOTHER issuer's
    # listing is still trusted: the listing is pinned to the origin (#172), not to
    # `.../issuers/{did}/`. It needs its own rule (and care for the recorded `links`
    # shapes). This test documents the gap and fails the day the follow-up closes it.
    other_listing = f"{BASE}/trusted-issuers-registry/v5/issuers/{OTHER}/attributes"
    routes = _golden_routes(DID)
    routes[ISSUER_URL] = {**GOLDEN_ISSUER, "attributes": other_listing}
    routes[other_listing] = routes.pop(GOLDEN_ISSUER["attributes"])
    fetch = StubFetch(routes)
    rec = _resolver(fetch, TirV5()).issuer_record(DID)
    assert rec.did == DID and len(rec.accreditations) == 3
    assert fetch.calls[1] == other_listing
