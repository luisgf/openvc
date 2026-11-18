"""The JOSE lanes hold the selected key to its DID-document verification relationship.

Selection stays ``DidDocument.key_by_kid`` (a JWS ``kid`` is a hint); then, only when the
resolved document *declares* the relationship, the selected method must be referenced by it:
``assertionMethod`` for a VC-JWT / SD-JWT VC issuer JWT / status-list token, ``authentication``
for a VP-JWT holder key. An undeclared relationship stays accepted (as on the Data Integrity
lane). Every hostile case is paired with a control that verifies.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openvc import verify_credential
from openvc.aio import verify_credential_async, verify_many_async
from openvc.did.base import (
    AsyncDidResolverRegistry,
    DidResolverRegistry,
    as_async_resolver,
    parse_did_document,
)
from openvc.did.base import DidDocument, VerificationMethod
from openvc.did.did_jwk import DidJwkResolver
from openvc.did.did_key import DidKeyResolver
from openvc.did.did_webvh import DidWebvhResolver
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import verify_vp_token
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.resolvers import (
    default_status_list_token_resolver,
    default_status_list_token_resolver_async,
)
from openvc.status import build_status_list_token, new_status_list
from openvc.verify import KeyResolutionFailed, _resolve_jose_key, verify_many

V2 = "https://www.w3.org/ns/credentials/v2"
DID = "did:web:issuer.example"
URI = "https://issuer.example/statuslist/1"
AUD = "https://verifier.example"
NONCE = "n-0S6_WzA2Mj"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def vc_jwt(signer, did=DID):
    now = int(time.time())
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:s"}}
    claims = {"iss": did, "sub": "did:example:s", "nbf": now, "iat": now, "vc": vc}
    header = {"alg": signer.alg, "typ": "JWT", "kid": signer.kid}
    head = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}"
    return f"{head}.{b64u(signer.sign(head.encode()))}"


def sd_jwt(signer, did=DID):
    return SdJwtVcProofSuite().issue(
        {"iss": did, "sub": "did:example:s", "degree": "x"},
        signing_key=signer, vct="https://c.example/degree")


class StaticResolver:
    def __init__(self, docs):
        self.docs = docs

    def supports(self, did):
        return did in self.docs

    def resolve(self, did):
        return parse_did_document(self.docs[did])


def vm(key, frag, did=DID):
    return {"id": f"{did}#{frag}", "type": "JsonWebKey", "controller": did,
            "publicKeyJwk": key.public_jwk()}


K_ASSERT = Ed25519SigningKey(ed25519.Ed25519PrivateKey.generate(), kid=f"{DID}#assert")
K_AUTH = Ed25519SigningKey(ed25519.Ed25519PrivateKey.generate(), kid=f"{DID}#auth")
K_AGREE = P256SigningKey(ec.generate_private_key(ec.SECP256R1()), kid=f"{DID}#agree")

THREE = {"id": DID,
         "verificationMethod": [vm(K_ASSERT, "assert"), vm(K_AUTH, "auth"),
                                vm(K_AGREE, "agree")],
         "assertionMethod": [f"{DID}#assert"],
         "authentication": [f"{DID}#auth"],
         "keyAgreement": [f"{DID}#agree"]}


def sync_reg(doc=THREE, *extra):
    return DidResolverRegistry([StaticResolver({DID: doc}), *extra])


def async_reg(doc=THREE, *extra):
    return AsyncDidResolverRegistry(
        [as_async_resolver(StaticResolver({DID: doc})), *map(as_async_resolver, extra)])


def run_async(token, doc=THREE):
    return asyncio.run(verify_credential_async(token, resolver=async_reg(doc)))


# --------------------------------------------------------------------------- #
# the six rows of the issue, sync and async
# --------------------------------------------------------------------------- #

LANES = [
    pytest.param(vc_jwt, id="vc-jwt"),
    pytest.param(sd_jwt, id="sd-jwt-vc"),
]


@pytest.mark.parametrize("make", LANES)
def test_assertion_method_key_verifies_control(make):
    assert verify_credential(make(K_ASSERT), resolver=sync_reg()).format
    assert run_async(make(K_ASSERT)).format


@pytest.mark.parametrize("make", LANES)
@pytest.mark.parametrize("signer", [K_AUTH, K_AGREE], ids=["authentication", "keyAgreement"])
def test_key_of_another_relationship_is_refused_sync(make, signer):
    with pytest.raises(KeyResolutionFailed):
        verify_credential(make(signer), resolver=sync_reg())


@pytest.mark.parametrize("make", LANES)
@pytest.mark.parametrize("signer", [K_AUTH, K_AGREE], ids=["authentication", "keyAgreement"])
def test_key_of_another_relationship_is_refused_async(make, signer):
    with pytest.raises(KeyResolutionFailed):
        run_async(make(signer))


# --------------------------------------------------------------------------- #
# what stays accepted
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("make", LANES)
@pytest.mark.parametrize("kid", [f"{DID}#assert", "#assert", "assert"])
def test_kid_spellings_still_select(make, kid):
    # selection is unchanged: bare, #fragment and absolute kid all pick the method
    signer = Ed25519SigningKey(K_ASSERT._sk, kid=kid)
    assert verify_credential(make(signer), resolver=sync_reg()).format
    assert run_async(make(signer)).format


@pytest.mark.parametrize("make", LANES)
def test_document_without_assertion_method_member_still_verifies(make):
    doc = {k: v for k, v in THREE.items() if k != "assertionMethod"}
    assert verify_credential(make(K_AUTH), resolver=sync_reg(doc)).format
    assert run_async(make(K_AUTH), doc).format


@pytest.mark.parametrize("make", LANES)
def test_declared_but_empty_assertion_method_refuses(make):
    doc = {**THREE, "assertionMethod": []}
    with pytest.raises(KeyResolutionFailed):
        verify_credential(make(K_ASSERT), resolver=sync_reg(doc))
    with pytest.raises(KeyResolutionFailed):
        run_async(make(K_ASSERT), doc)


def test_relative_and_embedded_references_grant():
    doc = {**THREE, "assertionMethod": ["#assert"]}
    assert verify_credential(vc_jwt(K_ASSERT), resolver=sync_reg(doc)).format
    embedded = {**THREE, "assertionMethod": [vm(K_ASSERT, "assert")]}
    assert verify_credential(vc_jwt(K_ASSERT), resolver=sync_reg(embedded)).format
    with pytest.raises(KeyResolutionFailed):
        verify_credential(vc_jwt(K_AUTH), resolver=sync_reg(embedded))


def _did_key(key_cls):
    sk = key_cls.generate(kid="_")
    if key_cls is Ed25519SigningKey:
        mb = encode_multibase(bytes([0xED, 0x01]) + sk.public_key_raw())
    else:
        raw = sk._sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        mb = encode_multibase(bytes([0x80, 0x24]) + raw)
    did = f"did:key:{mb}"
    return did, type(sk)(sk._sk, kid=f"{did}#{mb}")


@pytest.mark.parametrize("make", LANES)
@pytest.mark.parametrize("key_cls", [Ed25519SigningKey, P256SigningKey])
def test_did_key_credential_still_verifies(make, key_cls):
    did, signer = _did_key(key_cls)
    reg = DidResolverRegistry([DidKeyResolver()])
    assert verify_credential(make(signer, did), resolver=reg).format
    areg = AsyncDidResolverRegistry([as_async_resolver(DidKeyResolver())])
    assert asyncio.run(verify_credential_async(make(signer, did), resolver=areg)).format


def test_resolvers_own_document_type_is_left_alone():
    class _Vm:
        public_key_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "x"}

    class OwnDoc:                      # not a DidDocument: no relationships to check
        def key_by_kid(self, kid):
            return _Vm()

    class OwnResolver:
        def resolve(self, did):
            return OwnDoc()

    assert _resolve_jose_key(OwnResolver(), DID, "k") == _Vm.public_key_jwk


# --------------------------------------------------------------------------- #
# VP-JWT holder key: authentication
# --------------------------------------------------------------------------- #

def _vp_resolver():
    return DidResolverRegistry([StaticResolver({DID: THREE}), DidKeyResolver()])


def _embedded_vc():
    did, signer = _did_key(Ed25519SigningKey)
    return vc_jwt(signer, did)


def _vp(holder_key):
    return VpJwtProofSuite().sign(
        [_embedded_vc()], holder_key=holder_key, audience=AUD, nonce=NONCE)


def test_vp_jwt_holder_authentication_key_verifies_control():
    out = VpJwtProofSuite().verify(
        _vp(K_AUTH), audience=AUD, nonce=NONCE, resolver=_vp_resolver())
    assert out.holder == DID


@pytest.mark.parametrize("signer", [K_ASSERT, K_AGREE], ids=["assertionMethod", "keyAgreement"])
def test_vp_jwt_holder_key_not_in_authentication_is_refused(signer):
    with pytest.raises(ClaimsInvalid) as exc:
        VpJwtProofSuite().verify(
            _vp(signer), audience=AUD, nonce=NONCE, resolver=_vp_resolver())
    assert type(exc.value) is ClaimsInvalid
    assert type(exc.value.__cause__) is KeyResolutionFailed
    assert "not authorized for authentication" in str(exc.value)


def test_vp_token_holder_key_not_in_authentication_is_refused():
    query = {"credentials": [{"id": "q", "format": "jwt_vc_json",
                              "require_cryptographic_holder_binding": False}]}
    ok = verify_vp_token(
        {"q": [_vp(K_AUTH)]}, dcql_query=query, nonce=NONCE, client_id=AUD,
        resolver=_vp_resolver())
    assert ok
    with pytest.raises(ClaimsInvalid) as exc:
        verify_vp_token(
            {"q": [_vp(K_ASSERT)]}, dcql_query=query, nonce=NONCE, client_id=AUD,
            resolver=_vp_resolver())
    assert type(exc.value) is ClaimsInvalid
    assert type(exc.value.__cause__) is KeyResolutionFailed
    assert "not authorized for authentication" in str(exc.value)


# --------------------------------------------------------------------------- #
# status-list token: assertionMethod, in both default resolvers
# --------------------------------------------------------------------------- #

def _status_token(signer):
    return build_status_list_token(
        signing_key=signer, uri=URI, status_list=new_status_list(8), issuer=DID)


def test_status_token_assertion_key_resolves_control():
    token = _status_token(K_ASSERT)
    claims = default_status_list_token_resolver(
        resolver=sync_reg(), fetch=lambda u: token)(URI)
    assert "status_list" in claims
    claims = asyncio.run(default_status_list_token_resolver_async(
        resolver=async_reg(), fetch=_afetch(token))(URI))
    assert "status_list" in claims


def _afetch(token):
    async def fetch(u):
        return token
    return fetch


@pytest.mark.parametrize("signer", [K_AUTH, K_AGREE], ids=["authentication", "keyAgreement"])
def test_status_token_signed_by_other_relationship_is_refused(signer):
    token = _status_token(signer)
    with pytest.raises(KeyResolutionFailed):
        default_status_list_token_resolver(resolver=sync_reg(), fetch=lambda u: token)(URI)
    with pytest.raises(KeyResolutionFailed):
        asyncio.run(default_status_list_token_resolver_async(
            resolver=async_reg(), fetch=_afetch(token))(URI))


# --------------------------------------------------------------------------- #
# did:jwk control, recorded did:webvh documents, hand-built documents
# --------------------------------------------------------------------------- #

def test_did_jwk_credential_still_verifies():
    sk = P256SigningKey.generate(kid="_")
    did = "did:jwk:" + b64u(json.dumps(sk.public_jwk()).encode())
    signer = P256SigningKey(sk._sk, kid=f"{did}#0")
    reg = DidResolverRegistry([DidJwkResolver()])
    assert verify_credential(vc_jwt(signer, did), resolver=reg).format
    areg = AsyncDidResolverRegistry([as_async_resolver(DidJwkResolver())])
    assert asyncio.run(verify_credential_async(vc_jwt(signer, did), resolver=areg)).format


WEBVH = Path(__file__).parent / "fixtures" / "didwebvh"


def test_recorded_webvh_document_with_empty_assertion_method_is_refused():
    # the didwebvh-rs golden document lists its sole key under `authentication` and
    # declares `"assertionMethod": []`: a consequence of the document's own declaration,
    # the same answer the Data Integrity lane gives
    log = (WEBVH / "basic-create.jsonl").read_text()
    did = json.loads(log.splitlines()[-1])["state"]["id"]
    resolver = DidWebvhResolver(fetch=lambda url: log)
    doc = resolver.resolve(did)
    assert doc.relationships["assertionMethod"] == []
    method = doc.verification_methods[0]
    assert method.id in doc.relationships["authentication"]
    reg = DidResolverRegistry([resolver])
    throwaway = Ed25519SigningKey.generate(kid=method.id)
    with pytest.raises(KeyResolutionFailed) as exc:
        verify_credential(vc_jwt(throwaway, did), resolver=reg)
    assert type(exc.value) is KeyResolutionFailed
    # control: the same method as a holder key is granted (authentication)
    assert _resolve_jose_key(reg, did, method.id, purpose="authentication") == \
        method.public_key_jwk


def _hand_built(relationships):
    class Custom:
        def supports(self, did):
            return did == DID

        def resolve(self, did):
            return DidDocument(
                id=DID,
                verification_methods=[VerificationMethod(
                    f"{DID}#assert", "JsonWebKey", DID, K_ASSERT.public_jwk())],
                raw={}, relationships=relationships)
    return Custom()


@pytest.mark.parametrize("relationships, accepted", [
    pytest.param(None, True, id="relationships-none"),
    pytest.param([], True, id="relationships-list"),
    pytest.param({"assertionMethod": None}, True, id="entry-none"),
    pytest.param({"assertionMethod": 7}, False, id="entry-int"),
    pytest.param({"assertionMethod": "x"}, False, id="entry-str"),
    pytest.param({"assertionMethod": {"a": 1}}, False, id="entry-dict"),
    pytest.param({"assertionMethod": [7, None, f"{DID}#assert"]}, True, id="non-string-members"),
])
def test_hand_built_relationships_never_raise_a_bare_exception(relationships, accepted):
    custom = _hand_built(relationships)
    token = vc_jwt(K_ASSERT)
    good_did, good_signer = _did_key(Ed25519SigningKey)
    good = vc_jwt(good_signer, good_did)
    batch = [good, token, good]
    reg = DidResolverRegistry([custom, DidKeyResolver()])
    areg = AsyncDidResolverRegistry(
        [as_async_resolver(custom), as_async_resolver(DidKeyResolver())])
    if accepted:
        assert verify_credential(token, resolver=reg).format
        assert asyncio.run(verify_credential_async(token, resolver=areg)).format
    else:
        with pytest.raises(KeyResolutionFailed) as exc:
            verify_credential(token, resolver=reg)
        assert type(exc.value) is KeyResolutionFailed
        with pytest.raises(KeyResolutionFailed):
            asyncio.run(verify_credential_async(token, resolver=areg))
    for results in (verify_many(batch, resolver=reg),
                    asyncio.run(verify_many_async(batch, resolver=areg))):
        assert [r.ok for r in results] == [True, accepted, True]
        if not accepted:
            assert type(results[1].error) is KeyResolutionFailed


@pytest.mark.parametrize("relationships, expected", [
    pytest.param(None, True, id="relationships-none"),
    pytest.param({"assertionMethod": 7}, False, id="entry-int"),
    pytest.param({"assertionMethod": f"{DID}#assert"}, False, id="entry-str"),
])
def test_key_for_purpose_and_grants_on_malformed_relationships(relationships, expected):
    doc = _hand_built(relationships).resolve(DID)
    got = doc.key_for_purpose(f"{DID}#assert", "assertionMethod")
    assert (got is not None) is expected
    assert doc.grants(doc.verification_methods[0], "assertionMethod") is expected
