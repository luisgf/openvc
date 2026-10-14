"""
tests/test_ebsi_did_syntax.py — the DID is validated before it is put in a registry URL (#266).

`DidRegistryV5.identifiers_url`, `TirV4.issuer_url` and `TirV5.issuer_url` interpolate the
DID verbatim, and `verify_ebsi_badge` takes it from an unsigned token (`peek_issuer`) and
the trust walk takes it from the registry (`accreditedBy`). Before the check a `/`, a `..`
segment, a `?`, a `#`, a percent escape, another DID method or a whole URL steered the path
and query of a GET to an allow-listed EBSI host, and a 60 KB `iss` went out as a 60 KB path.
`DidEbsiResolver.resolve` and `.issuer_record` now refuse anything that is not
``did:ebsi:z`` + 22 or 23 base58btc characters (EBSI DevHub, "The did:ebsi DID method"),
as `DidResolutionError`, before any request.

Negatives first, each asserting the exact class and, where a client is involved, that the
mock transport recorded NO request, so a test cannot pass on a 404. Every negative is paired
with a control that makes the request, so the DID is the only thing that can make it fail.
Self-contained: `tests/` is not a package.
"""
from __future__ import annotations

import base64
import json
import random
from types import SimpleNamespace

import httpx
import pytest

from openvc.did.base import DidResolutionError
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import EbsiHttpClient, HttpNotFound
from openvc_ebsi.trust import AccreditationInvalid, NoTrustedAnchor, verify_trust_chain
from openvc_ebsi.verify import EbsiVerificationError, verify_ebsi_badge
from openvc_ebsi.versioning import (
    DidEbsiResolver,
    DidRegistryV5,
    TirV4,
    TirV5,
)

BASE = "https://api-pilot.ebsi.eu"
A = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"          # the DID in tests/fixtures/ebsi (z + 22)
B = "did:ebsi:zYcXJpGw4oxsrGXc5WdR3UA"          # any other well-formed one
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PRINTABLE = [chr(c) for c in range(0x21, 0x7F)]  # the 94 printable ASCII characters
DID_PATH = "/did-registry/v5/identifiers/"
TIR_PATH = "/trusted-issuers-registry/v5/issuers/"


def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


# --------------------------------------------------------------------------- #
# The strings that must be refused
# --------------------------------------------------------------------------- #

def _hostile() -> dict[str, str]:
    """Every case of the issue's table and acceptance list, keyed by a readable id."""
    cases: dict[str, str] = {
        # the repro table
        "dot-segment": f"{A}/../{B}",
        "another-api": f"../../../trusted-issuers-registry/v5/issuers/{B}",
        "query": f"{A}?x=1",
        "fragment": f"{A}#key-1",
        "percent-slash": f"{A}%2f..%2f{B}",
        "other-method": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "url": "https://evil.example/x",
        # near misses of the syntax
        "trailing-lf": A + "\n",
        "trailing-space": A + " ",
        "leading-space": " " + A,
        "trailing-nul": A + "\x00",
        "fullwidth-digit": A[:-1] + "１",
        "arabic-indic-digit": A[:-1] + "٣",
        "fullwidth-letter": A[:-1] + "ａ",
        "upper-scheme": "DID:EBSI:" + A[len("did:ebsi:"):],
        "upper-z": "did:ebsi:Z" + A[len("did:ebsi:z"):],
        "bare-z": "did:ebsi:z",
        "no-msi": "did:ebsi:",
        "empty": "",
        "z-plus-21": "did:ebsi:z" + "1" * 21,
        "z-plus-24": "did:ebsi:z" + "1" * 24,
        "no-z": "did:ebsi:" + A[len("did:ebsi:z"):],
        "network-qualified": f"did:ebsi:test:{A[len('did:ebsi:'):]}",
        "did-url-path": f"{A}/path",
        "did-url-versionId": "did:ebsi:zX?versionId=1",
        "did-url-fragment": "did:ebsi:zX#key-1",
        "percent-dots": f"{A}%2e%2e",
        "dotdot": "..",
        "dot": ".",
        "at": f"{A}@evil.example",
        "slashes": f"{A}//evil.example",
        "backslash": f"{A}\\..\\{B}",
        "tab": "did:ebsi:z\tx",
        "del": "did:ebsi:z\x7fx",
        "60kb": "did:ebsi:z" + "B" * 60_000,
    }
    # the fixture DID with its last character replaced by each printable ASCII character
    # outside the base58btc alphabet: 94 - 58 = 36 cases
    for c in PRINTABLE:
        if c not in BASE58:
            cases[f"last-char-{ord(c):#04x}"] = A[:-1] + c
    assert sum(1 for k in cases if k.startswith("last-char-")) == 36
    return cases


HOSTILE = _hostile()
HOSTILE_PARAMS = [pytest.param(v, id=k) for k, v in HOSTILE.items()]
# an empty `iss` is a MalformedToken from `peek_issuer`, before any resolver sees it
TOKEN_PARAMS = [pytest.param(v, id=k) for k, v in HOSTILE.items() if k != "empty"]


# --------------------------------------------------------------------------- #
# Plumbing: the real client on a mock transport; the transport records the wire
# --------------------------------------------------------------------------- #

def _client(requests: list[str], routes: dict[str, dict] | None = None) -> EbsiHttpClient:
    """The real `EbsiHttpClient` over a transport that records every request as put on the
    wire (path and query) and answers 404 unless *routes* has that path."""
    def handler(request: httpx.Request) -> httpx.Response:
        raw_path = request.url.raw_path.decode()
        requests.append(raw_path)
        body = (routes or {}).get(raw_path)
        return httpx.Response(404, json={}) if body is None else httpx.Response(200, json=body)
    client = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def _unsigned_token(iss: str) -> str:
    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'ES256', 'kid': iss + '#k'})}.{seg({'iss': iss, 'vc': {}})}.AAAA"


def _doc(did: str, sk: P256SigningKey) -> dict:
    return {"id": did, "verificationMethod": [{
        "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
        "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{did}#key-1"]}


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


# --------------------------------------------------------------------------- #
# verify_ebsi_badge: an unsigned token's `iss` never reaches the registry
# --------------------------------------------------------------------------- #

def test_control_a_well_formed_iss_does_reach_the_registry() -> None:
    # The repro's first row: the request is made, at the exact path, and the stub's 404
    # surfaces as HttpNotFound. Every negative below asserts the OPPOSITE of this.
    requests: list[str] = []
    client = _client(requests)
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(client.get_json, decode_jwt=suite.peek_claims, base=BASE)
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(_unsigned_token(A), resolver=resolver, proof_suite=suite)
    assert type(exc_info.value) is HttpNotFound
    assert requests == [DID_PATH + A]
    client.close()


@pytest.mark.parametrize("iss", TOKEN_PARAMS)
def test_verify_ebsi_badge_refuses_a_malformed_issuer_before_any_request(iss: str) -> None:
    requests: list[str] = []
    client = _client(requests)
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(client.get_json, decode_jwt=suite.peek_claims, base=BASE)
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(_unsigned_token(iss), resolver=resolver, proof_suite=suite)
    assert type(exc_info.value) is EbsiVerificationError
    assert type(exc_info.value.__cause__) is DidResolutionError
    assert "not a did:ebsi identifier" in str(exc_info.value)
    assert requests == []
    client.close()


def test_verify_ebsi_badge_message_for_a_60kb_issuer_is_bounded() -> None:
    iss = HOSTILE["60kb"]
    assert len(iss) == 60_010
    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(StubFetch({}), decode_jwt=suite.peek_claims, base=BASE)
    with pytest.raises(OpenvcError) as exc_info:
        verify_ebsi_badge(_unsigned_token(iss), resolver=resolver, proof_suite=suite)
    assert type(exc_info.value) is EbsiVerificationError
    shown = f"{iss[:200]!r}... (60010 chars)"
    assert str(exc_info.value) == (
        f"could not resolve issuer DID {shown}: not a did:ebsi identifier: {shown}")
    assert len(str(exc_info.value)) < 600       # main gave a 9-character HttpNotFound, and a
    #                                             naive typed check a 60,301-character one


# --------------------------------------------------------------------------- #
# Direct entry points: resolve and issuer_record
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("method", ["resolve", "issuer_record"])
@pytest.mark.parametrize("did", HOSTILE_PARAMS)
def test_direct_entry_points_refuse_a_malformed_did_before_any_request(
        method: str, did: str) -> None:
    requests: list[str] = []
    client = _client(requests)
    resolver = DidEbsiResolver(client.get_json, decode_jwt=VcJwtProofSuite().peek_claims,
                               base=BASE)
    with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
        getattr(resolver, method)(did)
    assert type(exc_info.value) is DidResolutionError
    assert requests == []
    client.close()


@pytest.mark.parametrize("method", ["resolve", "issuer_record"])
@pytest.mark.parametrize("did", [
    pytest.param(None, id="none"),
    pytest.param(7, id="int"),
    pytest.param(True, id="bool"),
    pytest.param(b"did:ebsi:zZeKyEJfUTGwajhNyNX928z", id="bytes"),
    pytest.param([A], id="list"),
    pytest.param({"id": A}, id="dict"),
    pytest.param(1.5, id="float"),
    pytest.param(10 ** 5000, id="huge-int"),
])
def test_direct_entry_points_refuse_a_non_string_did(method: str, did: object) -> None:
    # `re.fullmatch` on a non-str is a bare TypeError: the isinstance guard comes first.
    fetch = StubFetch({})
    resolver = DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims, base=BASE)
    with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
        getattr(resolver, method)(did)
    assert type(exc_info.value) is DidResolutionError
    assert fetch.calls == []


# --------------------------------------------------------------------------- #
# Controls: what is accepted, and that the pattern is exactly the alphabet
# --------------------------------------------------------------------------- #

def _stub_registry(did: str, sk: P256SigningKey) -> StubFetch:
    # The DID Registry document and an empty TIR record, both for `did`.
    return StubFetch({
        f"{BASE}{DID_PATH}{did}": _doc(did, sk),
        f"{BASE}{TIR_PATH}{did}": {"did": did, "hasAttributes": False},
    })


@pytest.mark.parametrize("did", [
    pytest.param(A, id="fixture-22"),
    pytest.param(_did(0x00), id="min-22"),             # 0x01 || 16 * 0x00
    pytest.param(_did(0xFF), id="max-23"),             # 0x01 || 16 * 0xff
    pytest.param("did:ebsi:z" + "1" * 22, id="alphabet-low-22"),
    pytest.param("did:ebsi:z" + "z" * 23, id="alphabet-high-23"),
])
def test_well_formed_dids_resolve_and_have_a_record(did: str) -> None:
    sk = P256SigningKey.generate(kid=f"{did}#key-1")
    fetch = _stub_registry(did, sk)
    resolver = DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims, tir=TirV5(),
                               base=BASE)
    assert resolver.resolve(did).id == did
    assert resolver.issuer_record(did).did == did
    assert fetch.calls == [f"{BASE}{DID_PATH}{did}", f"{BASE}{TIR_PATH}{did}"]


def test_the_legal_entity_encoding_is_22_or_23_characters() -> None:
    # The arithmetic behind {22,23}: 0x01 || 16 bytes lies in [2**128, 2**129), and
    # 58**22 falls inside that range. Both ends are accepted, a seeded sample is too, and
    # neither 21 nor 24 characters ever occurs.
    lengths = {len(b58btc_encode(bytes([1]) + bytes([s]) * 16)) for s in (0x00, 0xFF)}
    assert lengths == {22, 23}
    rng = random.Random(266)
    seen = set()
    for _ in range(2000):
        msi = b58btc_encode(bytes([1]) + rng.randbytes(16))
        seen.add(len(msi))
        did = "did:ebsi:z" + msi
        resolver = DidEbsiResolver(lambda url: {"id": url.rsplit("/", 1)[1]},
                                   decode_jwt=VcJwtProofSuite().peek_claims, base=BASE)
        assert resolver.resolve(did).id == did
    assert seen == {22, 23}


@pytest.mark.parametrize("char", PRINTABLE)
def test_the_last_character_is_accepted_exactly_when_it_is_base58btc(char: str) -> None:
    # 94 printable characters, each as the last one of the fixture DID: 58 pass (the
    # base58btc alphabet) and 36 are refused. The stub registry answers with a document for
    # exactly that DID, so only the syntax can make the difference.
    did = A[:-1] + char
    resolver = DidEbsiResolver(lambda url: {"id": did},
                               decode_jwt=VcJwtProofSuite().peek_claims, base=BASE)
    if char in BASE58:
        assert resolver.resolve(did).id == did
    else:
        with pytest.raises(DidResolutionError, match="not a did:ebsi identifier") as exc_info:
            resolver.resolve(did)
        assert type(exc_info.value) is DidResolutionError


def test_the_alphabet_is_ascii_and_case_sensitive() -> None:
    # No `\w`, no `\d`, no IGNORECASE: base58btc has no `0`, `O`, `I`, `l`; a Unicode letter
    # or digit is not one of its characters; upper- and lower-case are different characters.
    assert not set("0OIl") & set(BASE58)
    for c in "0OIl\u00e9\u0663\uff11\uff21":
        did = A[:-1] + c
        resolver = DidEbsiResolver(lambda url, d=did: {"id": d},
                                   decode_jwt=VcJwtProofSuite().peek_claims, base=BASE)
        with pytest.raises(DidResolutionError, match="not a did:ebsi identifier"):
            resolver.resolve(did)
    # Case is not folded either: the lower-cased fixture DID is syntactically a different
    # (valid) identifier, so it is requested as written, and the document for `A` is not it.
    fetch = StubFetch({f"{BASE}{DID_PATH}{A.lower()}": {"id": A}})
    resolver = DidEbsiResolver(fetch, decode_jwt=VcJwtProofSuite().peek_claims, base=BASE)
    with pytest.raises(DidResolutionError, match="!= requested") as exc_info:
        resolver.resolve(A.lower())
    assert type(exc_info.value) is DidResolutionError
    assert fetch.calls == [f"{BASE}{DID_PATH}{A.lower()}"]


def test_the_url_builders_stay_wire_only() -> None:
    # The adapters keep no validation of their own (so a new version inherits the
    # resolver's check and the golden tests keep working): they build what they are given.
    assert DidRegistryV5().identifiers_url(BASE, "x/../y") == (
        f"{BASE}/did-registry/v5/identifiers/x/../y")
    assert TirV5().issuer_url(BASE, "x?y") == f"{BASE}/trusted-issuers-registry/v5/issuers/x?y"
    assert TirV4().issuer_url(BASE, "x#y") == f"{BASE}/trusted-issuers-registry/v4/issuers/x#y"


# --------------------------------------------------------------------------- #
# The trust walk
# --------------------------------------------------------------------------- #

def _walk(tao: str, *, serve_tao: bool = False) -> SimpleNamespace:
    """LEAF is accredited, per the TIR, by *tao*, and the accreditation JWT is signed with
    ``iss = tao``. The routes carry LEAF's registry entries; *tao*'s own DID document is
    served only when asked for (the controls), so a request for it is a 404 otherwise."""
    suite = VcJwtProofSuite()
    leaf = _did(0xA1)
    leaf_sk = P256SigningKey.generate(kid=f"{leaf}#key-1")
    tao_sk = P256SigningKey.generate(kid=f"{tao}#key-1")
    token = suite.sign({
        "@context": ["https://www.w3.org/2018/credentials/v1"], "id": "urn:uuid:badge-1",
        "type": ["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"],
        "issuer": leaf, "credentialSubject": {"id": "did:key:z6MkSubject"}},
        signing_key=leaf_sk)
    acc = suite.sign({
        "id": "urn:uuid:acc-1", "type": ["VerifiableCredential", "VerifiableAccreditationToAttest"],
        "issuer": tao,
        "credentialSubject": {"id": leaf, "accreditedFor": [{"types": ["OpenBadgeCredential"]}]}},
        signing_key=tao_sk)
    issuer_url = f"{BASE}{TIR_PATH}{leaf}"
    attrs, rev = f"{issuer_url}/attributes", f"{issuer_url}/attributes/aa/revisions/bb"
    routes = {
        f"{BASE}{DID_PATH}{leaf}": {"didDocument": _doc(leaf, leaf_sk)},
        issuer_url: {"did": leaf, "hasAttributes": True, "attributes": attrs},
        attrs: {"items": [{"id": "aa", "href": rev}]},
        rev: {"did": leaf, "attribute": {"body": acc, "hash": "aa", "issuerType": "TI",
                                         "tao": tao, "rootTao": tao}},
    }
    if serve_tao:
        routes[f"{BASE}{DID_PATH}{tao}"] = {"didDocument": _doc(tao, tao_sk)}
    fetch = StubFetch(routes)
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=BASE)
    return SimpleNamespace(leaf=leaf, tao=tao, token=token, suite=suite, fetch=fetch,
                           resolver=resolver,
                           leaf_calls=[f"{BASE}{DID_PATH}{leaf}", issuer_url, attrs, rev])


def _reaches_the_anchor(good_tao: str) -> None:
    """The control for the walk tests: the same chain with a well-formed accreditor reaches
    the anchor, through `verify_trust_chain` and through `verify_ebsi_badge`."""
    walk = _walk(good_tao, serve_tao=True)
    chain = verify_trust_chain(walk.leaf, ["OpenBadgeCredential"], resolver=walk.resolver,
                               proof_suite=walk.suite, anchors={good_tao})
    assert chain.anchor == good_tao and len(chain.hops) == 1
    walk = _walk(good_tao, serve_tao=True)
    result = verify_ebsi_badge(walk.token, resolver=walk.resolver, proof_suite=walk.suite,
                               trust_anchors={good_tao})
    assert result.trusted is True and result.chain is not None


@pytest.mark.parametrize("subject", [
    pytest.param("did:ebsi:zA?x=1", id="query"),
    pytest.param(f"{A}/../{B}", id="dot-segment"),
    pytest.param("", id="empty"),
    pytest.param(HOSTILE["60kb"], id="60kb"),
])
def test_verify_trust_chain_malformed_subject_is_no_trusted_anchor(subject: str) -> None:
    # main gave NoTrustedAnchor too (the stub's 404 mapped through HttpNotFound); the class
    # is kept, the message now says the fact: it is not a DID, not "not registered". Before
    # the check, a direct call raised a bare DidResolutionError from the resolver.
    _reaches_the_anchor(_did(0xB2))                       # control
    walk = _walk(_did(0xB2))
    with pytest.raises(OpenvcError) as exc_info:
        verify_trust_chain(subject, ["OpenBadgeCredential"], resolver=walk.resolver,
                           proof_suite=walk.suite, anchors={walk.tao})
    assert type(exc_info.value) is NoTrustedAnchor
    assert type(exc_info.value.__cause__) is DidResolutionError
    assert str(exc_info.value).endswith(" is not a did:ebsi identifier")
    assert "registry" not in str(exc_info.value)
    assert len(str(exc_info.value)) < 300
    assert walk.fetch.calls == []                  # not one request


def test_verify_trust_chain_max_depth_zero_message_is_bounded() -> None:
    # With no hop to take, the walk's last message names the subject without ever having
    # sent it through the resolver: it is cut too.
    walk = _walk(_did(0xB2))
    with pytest.raises(OpenvcError) as exc_info:
        verify_trust_chain(HOSTILE["60kb"], ["OpenBadgeCredential"], resolver=walk.resolver,
                           proof_suite=walk.suite, anchors=set(), max_depth=0)
    assert type(exc_info.value) is NoTrustedAnchor
    assert str(exc_info.value) == (
        f"no trusted anchor within 0 hops from {HOSTILE['60kb'][:200]!r}... (60010 chars)")


HOSTILE_TAO = f"{_did(0xC3)}/../{_did(0xD4)}"


@pytest.mark.parametrize("tao", [
    pytest.param(HOSTILE_TAO, id="dot-segment"),
    pytest.param(f"{_did(0xC3)}?x=1", id="query"),
    pytest.param(f"{_did(0xC3)}#key-1", id="fragment"),
    pytest.param("did:ebsi:z" + "B" * 60_000, id="60kb"),
])
def test_hostile_tao_equal_to_the_signed_iss_is_accreditation_invalid_with_no_request(
        tao: str) -> None:
    # A `tao` that comes from the registry and equals the accreditation's signed `iss` gets
    # past the identity check; resolving it as the accreditor used to request
    # `identifiers/<tao>` (a dot segment collapsed to the other DID's resource). Now the
    # accreditor is refused on syntax, so the wrapper types it and no request names it.
    _reaches_the_anchor(_did(0xC3))                       # control: only the accreditor differs
    walk = _walk(tao)
    with pytest.raises(OpenvcError) as exc_info:
        verify_trust_chain(walk.leaf, ["OpenBadgeCredential"], resolver=walk.resolver,
                           proof_suite=walk.suite, anchors={_did(0xC3)})
    assert type(exc_info.value) is AccreditationInvalid
    assert type(exc_info.value.__cause__) is DidResolutionError
    assert str(exc_info.value).startswith("cannot resolve accreditor ")
    assert "not a did:ebsi identifier" in str(exc_info.value)
    assert len(str(exc_info.value)) < 600
    # only the leaf's own entries were read: no DID Registry request for the accreditor
    assert walk.fetch.calls == walk.leaf_calls[1:]

    walk = _walk(tao)                                      # and through the badge verifier
    with pytest.raises(OpenvcError) as bexc:
        verify_ebsi_badge(walk.token, resolver=walk.resolver, proof_suite=walk.suite,
                          trust_anchors={_did(0xC3)})
    assert type(bexc.value) is AccreditationInvalid
    assert walk.fetch.calls == walk.leaf_calls


# --------------------------------------------------------------------------- #
# verify_ebsi_badge, single level: issuer_record is public, so its failure is typed
# --------------------------------------------------------------------------- #

def test_verify_ebsi_badge_wraps_an_issuer_record_did_resolution_error() -> None:
    # `verified.issuer` was just resolved, so a token cannot hand `issuer_record` an invalid
    # string; the wrapper is for a resolver whose `issuer_record` refuses it all the same
    # (it is public API). Exact class, and the cause is the resolver's error.
    suite = VcJwtProofSuite()
    sk = P256SigningKey.generate(kid=f"{A}#key-1")
    token = suite.sign({
        "@context": ["https://www.w3.org/2018/credentials/v1"], "id": "urn:uuid:badge-2",
        "type": ["VerifiableCredential", "VerifiableAttestation"], "issuer": A,
        "credentialSubject": {"id": "did:key:z6MkSubject"}}, signing_key=sk)
    fetch = _stub_registry(A, sk)
    resolver = DidEbsiResolver(fetch, decode_jwt=suite.peek_claims, tir=TirV5(), base=BASE)
    assert verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                             require_trust=False).issuer == A          # control

    def refuse(did: str):
        raise DidResolutionError("not a did:ebsi identifier: 'x'")
    resolver.issuer_record = refuse                                    # type: ignore[method-assign]
    for require_trust in (True, False):
        with pytest.raises(OpenvcError) as exc_info:
            verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                              require_trust=require_trust)
        assert type(exc_info.value) is EbsiVerificationError
        assert type(exc_info.value.__cause__) is DidResolutionError
        assert str(exc_info.value).startswith(f"could not read the registry record of issuer {A!r}")
