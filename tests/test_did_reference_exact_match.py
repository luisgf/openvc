"""
tests/test_did_reference_exact_match.py — a Data Integrity proof's key is selected, and
authorized for its purpose, by exact absolute DID URL (#258).

``DidDocument.key_for_purpose`` used to compare only the text after the first ``#``: a
method was selected by its fragment alone, and a relationship entry granted it whenever the
entry's fragment matched, whatever came before the ``#``. A reference to a method of another
DID, to one version of the document, to a path, to an ``https:`` URL, or a bare ``key-1``
therefore authorized the document's own ``#key-1`` for that purpose. Selection used the same
rule and took the first match in document order, so a same-fragment method listed first
shadowed the exact one.

The rule now (DID Core 1.0 §3.2.2, CID 1.0 §3.3 steps 9 and 11):

* a method ``id`` and a relationship reference are compared as absolute DID URLs. ``did:…``
  is taken as written; ``#frag`` is resolved against the document ``id`` when that is a DID;
  anything else resolves to nothing;
* the proof's ``verificationMethod`` selects the one method whose absolute ``id`` equals it
  (never the fragment, never document order), else ``KeyResolutionError``;
* a declared relationship grants that method only through a reference that resolves to the
  same absolute ``id``, else ``ProofPurposeMismatch``. An undeclared relationship stays
  lenient, and a ``kid`` of ``None`` still falls back to the sole method.

Every hostile row uses a resolvable issuer (an injected ``did:web`` fetch, or a stub resolver
where the point is a document ``id`` that ``did:web`` would refuse) and asserts the exact
class, so none can pass on an earlier failure. The JOSE lanes keep their fragment-tolerant
``kid`` lookup (a JWS ``kid`` is a hint); that is pinned in section 7. Section 8 pins that the
lookup stays linear in the document size: a long document ``id`` is neither re-checked nor
copied once per method or reference.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
from types import SimpleNamespace
from typing import Any

import pytest

from openvc import VerificationPolicy, verify_credential, verify_many, verify_many_async
from openvc.aio import verify_credential_async
from openvc.did import base as did_base
from openvc.did.base import (
    AsyncDidResolverRegistry,
    DidResolutionError,
    DidResolverRegistry,
    parse_did_document,
)
from openvc.did.did_web import AsyncDidWebResolver, DidWebResolver
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import verify_vp_token
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import KeyResolutionError, ProofPurposeMismatch, SignatureInvalid
from openvc.verify import KeyResolutionFailed

try:
    import pyld  # noqa: F401
    _HAS_PYLD = True
except ImportError:                                    # pragma: no cover
    _HAS_PYLD = False

DID = "did:web:issuer.example"
OTHER = "did:web:other.example"
ASSERT = f"{DID}#assert"
AUTH = f"{DID}#auth"
V2 = "https://www.w3.org/ns/credentials/v2"
POLICY = VerificationPolicy(require_status=False)
NONCE = "n-258"
DOMAIN = "x509_san_dns:verifier.example"

ASSERT_KEY = Ed25519SigningKey.generate(kid="_")
AUTH_KEY = Ed25519SigningKey.generate(kid="_")

PURPOSE_DENIED = "is not authorized for proofPurpose"
NOT_IN_DOC = "not in the DID document"


# --------------------------------------------------------------------------- #
# helpers (tests/ is not a package: nothing is imported from another test module)
# --------------------------------------------------------------------------- #

def _method(vm_id: str, key: Any, controller: str = DID) -> dict:
    return {"id": vm_id, "type": "JsonWebKey2020", "controller": controller,
            "publicKeyJwk": key.public_jwk()}


def _doc(*, did: str = DID, methods: list | None = None, **relationships: Any) -> dict:
    """``did``'s document: by default ``#assert`` and ``#auth``, each with its own key."""
    if methods is None:
        methods = [_method(f"{did}#assert", ASSERT_KEY, did),
                   _method(f"{did}#auth", AUTH_KEY, did)]
    return {"id": did, "verificationMethod": methods, **relationships}


def _sync(doc: dict) -> DidResolverRegistry:
    return DidResolverRegistry([DidWebResolver(fetch=lambda url: doc)])


def _async(doc: dict) -> AsyncDidResolverRegistry:
    async def fetch(url):
        return doc
    return AsyncDidResolverRegistry([AsyncDidWebResolver(fetch=fetch)])


class _Unbound:
    """A resolver that, unlike ``did:web``, does not compare the document ``id`` with the
    DID it was asked for. A custom resolver may not, and the reference rule must not
    depend on it."""
    def __init__(self, raw: dict) -> None:
        self._doc = parse_did_document(raw)

    def supports(self, did: str) -> bool:
        return did == DID

    def resolve(self, did: str):
        return self._doc


def _credential(issuer: str = DID, subject: str = "did:example:alice") -> dict:
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer,
            "credentialSubject": {"id": subject}}


def _signed(key: Any, vm_id: str) -> dict:
    """A credential signed by *key*, issued by the DID *vm_id* belongs to."""
    return EddsaJcsProofSuite().add_proof(_credential(issuer=vm_id.split("#", 1)[0]),
                                          signing_key=key, verification_method=vm_id)


def _verifies(credential: dict, doc: dict) -> None:
    assert verify_credential(credential, resolver=_sync(doc), policy=POLICY).issuer == DID
    result = asyncio.run(verify_credential_async(credential, resolver=_async(doc),
                                                 policy=POLICY))
    assert result.issuer == DID


def _refused(credential: dict, resolver: Any, async_resolver: Any, cls: type,
             match: str) -> None:
    with pytest.raises(cls, match=match) as exc:
        verify_credential(credential, resolver=resolver, policy=POLICY)
    assert type(exc.value) is cls
    if async_resolver is not None:
        with pytest.raises(cls, match=match) as exc:
            asyncio.run(verify_credential_async(credential, resolver=async_resolver,
                                                policy=POLICY))
        assert type(exc.value) is cls


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _did_key(key: Ed25519SigningKey) -> tuple[str, str]:
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())
    return f"did:key:{mb}", f"did:key:{mb}#{mb}"


# --------------------------------------------------------------------------- #
# the issue's table. Each row is the relationship's references, built for the fragment
# of the method that signed (``frag``) and of the document's other method (``other``)
# --------------------------------------------------------------------------- #

def _grants(frag: str) -> dict[str, list]:
    return {
        "full": [f"{DID}#{frag}"],
        "relative": [f"#{frag}"],                                  # DID Core Example 9
        "embedded-full": [{"id": f"{DID}#{frag}", "type": "JsonWebKey2020"}],
        "embedded-relative": [{"id": f"#{frag}", "type": "JsonWebKey2020"}],
        "beside-a-foreign-one": [f"{OTHER}#{frag}", f"{DID}#{frag}"],
    }


def _denies(frag: str, other: str, key: Any) -> dict[str, list]:
    return {
        "control-the-other-method": [f"{DID}#{other}"],
        "another-did": [f"{OTHER}#{frag}"],
        "another-did-embedded": [_method(f"{OTHER}#{frag}", key, OTHER)],
        "bare-path-reference": [frag],
        "one-version": [f"{DID}?versionId=1#{frag}"],
        "a-path": [f"{DID}/path#{frag}"],
        "not-a-did-url": [f"https://issuer.example/#{frag}"],
        "relative-query": [f"?versionId=1#{frag}"],
        "relative-path": [f"/path#{frag}"],
        "relative-other-case": [f"#{frag.upper()}"],
        "full-other-case": [f"{DID}#{frag.upper()}"],
        "longer-fragment": [f"{DID}#{frag}-old"],
        "upper-case-scheme": [f"DID:web:issuer.example#{frag}"],
        "declared-but-empty": [],
    }


ASSERTION_GRANTS = _grants("auth")
ASSERTION_DENIES = _denies("auth", "assert", AUTH_KEY)
AUTH_GRANTS = _grants("assert")
AUTH_DENIES = _denies("assert", "auth", ASSERT_KEY)


# --------------------------------------------------------------------------- #
# 1. assertionMethod lane: verify_credential and verify_credential_async. The proof is
#    signed by #auth, which the document lists for authentication only
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("refs", ASSERTION_GRANTS.values(), ids=ASSERTION_GRANTS)
def test_assertion_lane_grants_a_reference_to_the_method(refs):
    doc = _doc(authentication=[AUTH], assertionMethod=refs)
    _verifies(_signed(AUTH_KEY, AUTH), doc)


@pytest.mark.parametrize("refs", ASSERTION_DENIES.values(), ids=ASSERTION_DENIES)
def test_assertion_lane_refuses_a_reference_to_anything_else(refs):
    doc = _doc(authentication=[AUTH], assertionMethod=refs)
    _refused(_signed(AUTH_KEY, AUTH), _sync(doc), _async(doc), ProofPurposeMismatch,
             f"{PURPOSE_DENIED} 'assertionMethod'")


def test_a_string_relationship_is_still_refused_before_any_lookup():
    # the #219 row of the table: "#assert" written as a string, a signer whose fragment is
    # one of its characters. The parser refuses it (#251), before any reference is read.
    doc = _doc(methods=[_method(ASSERT, ASSERT_KEY), _method(f"{DID}#t", AUTH_KEY)],
               assertionMethod="#assert")
    credential = _signed(AUTH_KEY, f"{DID}#t")
    with pytest.raises(KeyResolutionError, match="could not resolve") as exc:
        verify_credential(credential, resolver=_sync(doc), policy=POLICY)
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is DidResolutionError
    # the async lane raises the same class as the sync one (#283), which is also a
    # KeyResolutionFailed
    assert isinstance(exc.value, KeyResolutionFailed)
    with pytest.raises(KeyResolutionError, match="could not resolve") as afail:
        asyncio.run(verify_credential_async(credential, resolver=_async(doc), policy=POLICY))
    assert type(afail.value) is KeyResolutionError
    assert isinstance(afail.value, KeyResolutionFailed)
    assert type(afail.value.__cause__) is DidResolutionError


# --------------------------------------------------------------------------- #
# 2. authentication lane: the suite call the OpenID4VP ldp_vc holder proof makes, with the
#    roles swapped (signed by #assert, which the document lists for assertionMethod only)
# --------------------------------------------------------------------------- #

def _presentation(key: Any, vm_id: str) -> dict:
    vp = {"@context": [V2], "type": ["VerifiablePresentation"]}
    return EddsaJcsProofSuite().add_proof(vp, signing_key=key, verification_method=vm_id,
                                          proof_purpose="authentication", challenge=NONCE,
                                          domain=DOMAIN)


def _verify_authentication(vp: dict, doc: dict):
    return EddsaJcsProofSuite().verify(
        vp, resolver=_sync(doc), expected_proof_purpose="authentication",
        expected_challenge=NONCE, expected_domain=DOMAIN)


@pytest.mark.parametrize("refs", AUTH_GRANTS.values(), ids=AUTH_GRANTS)
def test_authentication_lane_grants_a_reference_to_the_method(refs):
    doc = _doc(assertionMethod=[ASSERT], authentication=refs)
    verified = _verify_authentication(_presentation(ASSERT_KEY, ASSERT), doc)
    assert verified.proof["verificationMethod"] == ASSERT


@pytest.mark.parametrize("refs", AUTH_DENIES.values(), ids=AUTH_DENIES)
def test_authentication_lane_refuses_a_reference_to_anything_else(refs):
    doc = _doc(assertionMethod=[ASSERT], authentication=refs)
    with pytest.raises(ProofPurposeMismatch, match=f"{PURPOSE_DENIED} 'authentication'") as exc:
        _verify_authentication(_presentation(ASSERT_KEY, ASSERT), doc)
    assert type(exc.value) is ProofPurposeMismatch


HOLDER = "did:web:holder.example"


def _vp_token(authentication: list) -> tuple[dict, Any]:
    """An ldp_vc presentation by HOLDER (signed by its #assert key) of a credential a did:key
    issuer made out to HOLDER, and a registry serving HOLDER's document."""
    issuer_key = Ed25519SigningKey.generate(kid="_")
    issuer, issuer_vm = _did_key(issuer_key)
    suite = EddsaJcsProofSuite()
    vc = suite.add_proof(_credential(issuer=issuer, subject=HOLDER), signing_key=issuer_key,
                         verification_method=issuer_vm)
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": HOLDER,
          "verifiableCredential": [vc]}
    signed = suite.add_proof(vp, signing_key=ASSERT_KEY, verification_method=f"{HOLDER}#assert",
                             proof_purpose="authentication", challenge=NONCE, domain=DOMAIN)
    doc = _doc(did=HOLDER, assertionMethod=[f"{HOLDER}#assert"], authentication=authentication)
    return {"c1": [signed]}, _sync(doc)


_LDP_QUERY = {"credentials": [{"id": "c1", "format": "ldp_vc"}]}


def test_vp_token_ldp_vc_holder_proof_needs_an_exact_authentication_reference():
    token, resolver = _vp_token([f"{HOLDER}#assert"])                       # control
    (presentation,) = verify_vp_token(token, dcql_query=_LDP_QUERY, nonce=NONCE,
                                      client_id=DOMAIN, resolver=resolver).presentations
    assert presentation.holder == HOLDER

    token, resolver = _vp_token([f"{OTHER}#assert"])         # same fragment, another DID
    with pytest.raises(ProofPurposeMismatch, match=f"{PURPOSE_DENIED} 'authentication'") as exc:
        verify_vp_token(token, dcql_query=_LDP_QUERY, nonce=NONCE, client_id=DOMAIN,
                        resolver=resolver)
    assert type(exc.value) is ProofPurposeMismatch


# --------------------------------------------------------------------------- #
# 3. every Data Integrity suite goes through the same lookup
# --------------------------------------------------------------------------- #

def _suite_and_key(cryptosuite: str):
    if cryptosuite == "eddsa-rdfc-2022":
        from openvc.proof.data_integrity import DataIntegrityProofSuite
        return DataIntegrityProofSuite(), Ed25519SigningKey.generate(kid="_")
    if cryptosuite == "ecdsa-rdfc-2019":
        from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
        return EcdsaRdfcProofSuite(), P256SigningKey.generate(kid="_")
    if cryptosuite == "ecdsa-jcs-2019":
        from openvc.proof.di_jcs import EcdsaJcsProofSuite
        return EcdsaJcsProofSuite(), P256SigningKey.generate(kid="_")
    if cryptosuite == "ecdsa-sd-2023":
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        return EcdsaSdProofSuite(), P256SigningKey.generate(kid="_")
    return EddsaJcsProofSuite(), Ed25519SigningKey.generate(kid="_")


def _signed_by_suite(cryptosuite: str, vm_id: str) -> tuple[dict, Any]:
    suite, key = _suite_and_key(cryptosuite)
    if cryptosuite == "ecdsa-sd-2023":
        base = suite.add_base_proof(_credential(), signing_key=key, verification_method=vm_id,
                                    mandatory_pointers=["/issuer"])
        return suite.derive_proof(base, selective_pointers=[]), key
    return suite.add_proof(_credential(), signing_key=key, verification_method=vm_id), key


_NEEDS_PYLD = pytest.mark.skipif(not _HAS_PYLD, reason="needs pyld")
SUITES = [
    "eddsa-jcs-2022",
    "ecdsa-jcs-2019",
    pytest.param("eddsa-rdfc-2022", marks=_NEEDS_PYLD),
    pytest.param("ecdsa-rdfc-2019", marks=_NEEDS_PYLD),
    pytest.param("ecdsa-sd-2023", marks=_NEEDS_PYLD),
]


@pytest.mark.parametrize("cryptosuite", SUITES)
def test_every_suite_grants_only_an_exact_reference(cryptosuite):
    vm_id = f"{DID}#k"
    credential, key = _signed_by_suite(cryptosuite, vm_id)
    for refs in ([vm_id], ["#k"]):
        _verifies(credential, _doc(methods=[_method(vm_id, key)], assertionMethod=refs))
    for refs in ([f"{OTHER}#k"], ["k"], [f"{DID}?versionId=1#k"]):
        doc = _doc(methods=[_method(vm_id, key)], assertionMethod=refs)
        _refused(credential, _sync(doc), _async(doc), ProofPurposeMismatch, PURPOSE_DENIED)


# --------------------------------------------------------------------------- #
# 4. relative spellings that do resolve, and a document id that is not a DID
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ref", [AUTH, "#auth"], ids=["full-reference", "relative-reference"])
def test_a_relative_method_id_is_resolved_against_the_document(ref):
    doc = _doc(methods=[_method(ASSERT, ASSERT_KEY), _method("#auth", AUTH_KEY)],
               authentication=[ASSERT], assertionMethod=[ref])
    _verifies(_signed(AUTH_KEY, AUTH), doc)


NOT_A_DID = {
    "https": "https://issuer.example",
    "empty": "",
    "with-a-path": f"{DID}/path",
    "with-a-query": f"{DID}?versionId=1",
    "with-a-fragment": f"{DID}#x",
    "upper-case-scheme": "DID:web:issuer.example",
    "upper-case-method": "did:WEB:issuer.example",
    "no-method-specific-id": "did:web:",
    "trailing-colon": f"{DID}:",
    "a-space": "did:web:issuer example",
    "a-bad-escape": "did:web:issuer%zz.example",
    # DIDs that did:web still fetches (https://example.com/<path>/did.json): their
    # documents must use absolute ids, which the did:web test below pins
    "a-tilde": "did:web:example.com:~alice",
    "a-plus": "did:web:example.com:user+x",
    "a-bang": "did:web:example.com:a!b",
    "an-at": "did:web:example.com:a@b",
    "a-short-escape": "did:web:example.com:c%2",
}
WEB_NOT_A_DID = {k: NOT_A_DID[k] for k in ("a-tilde", "a-plus", "a-bang", "an-at",
                                           "a-short-escape")}


@pytest.mark.parametrize("doc_id", NOT_A_DID.values(), ids=NOT_A_DID)
def test_a_relative_reference_resolves_to_nothing_when_the_document_id_is_not_a_did(doc_id):
    raw = {"id": doc_id, "verificationMethod": [_method(ASSERT, ASSERT_KEY),
                                                _method(AUTH, AUTH_KEY)],
           "authentication": [AUTH], "assertionMethod": ["#auth"]}
    doc = parse_did_document(raw)
    assert doc.key_for_purpose(AUTH, "authentication") is not None     # selected by full id
    assert doc.key_for_purpose(AUTH, "assertionMethod") is None         # "#auth" grants nothing
    _refused(_signed(AUTH_KEY, AUTH), _Unbound(raw), None, ProofPurposeMismatch,
             f"{PURPOSE_DENIED} 'assertionMethod'")


@pytest.mark.parametrize("doc_id", NOT_A_DID.values(), ids=NOT_A_DID)
def test_a_relative_method_id_names_nothing_when_the_document_id_is_not_a_did(doc_id):
    doc = parse_did_document({"id": doc_id, "verificationMethod": [_method("#auth", AUTH_KEY)]})
    assert doc.key_for_purpose(doc_id + "#auth", "assertionMethod") is None
    assert doc.key_for_purpose(AUTH, "assertionMethod") is None


@pytest.mark.parametrize("did", WEB_NOT_A_DID.values(), ids=WEB_NOT_A_DID)
def test_a_did_web_outside_the_did_syntax_needs_absolute_ids(did):
    # did:web resolves these DIDs, but they fail DID Core 1.0 §3.1, so a '#k' in their
    # document resolves to nothing (fail closed); the absolute id still verifies
    vm_id = f"{did}#k"
    credential = _signed(AUTH_KEY, vm_id)
    relative_id = _doc(did=did, methods=[_method("#k", AUTH_KEY, did)],
                       assertionMethod=["#k"])
    _refused(credential, _sync(relative_id), _async(relative_id), KeyResolutionError,
             NOT_IN_DOC)
    relative_ref = _doc(did=did, methods=[_method(vm_id, AUTH_KEY, did)],
                        assertionMethod=["#k"])
    _refused(credential, _sync(relative_ref), _async(relative_ref), ProofPurposeMismatch,
             f"{PURPOSE_DENIED} 'assertionMethod'")
    absolute = _doc(did=did, methods=[_method(vm_id, AUTH_KEY, did)],
                    assertionMethod=[vm_id])
    assert verify_credential(credential, resolver=_sync(absolute), policy=POLICY).issuer == did
    result = asyncio.run(verify_credential_async(credential, resolver=_async(absolute),
                                                 policy=POLICY))
    assert result.issuer == did


def test_a_did_document_id_resolves_a_relative_reference():
    for did in (DID, "did:web:localhost%3A8443:user:alice", "did:key:z6Mk-a_b.c"):
        doc = parse_did_document({"id": did, "verificationMethod": [_method("#k", AUTH_KEY)],
                                  "assertionMethod": ["#k"]})
        assert doc.key_for_purpose(f"{did}#k", "assertionMethod") is not None


# --------------------------------------------------------------------------- #
# 5. selection: a method is chosen by its exact absolute id, and only one may have it
# --------------------------------------------------------------------------- #

UNSELECTABLE = {
    "another-did": f"{OTHER}#auth",
    "bare": "auth",
    "one-version": f"{DID}?versionId=1#auth",
    "a-path": f"{DID}/path#auth",
    "not-a-did-url": "https://issuer.example/#auth",
    "relative-query": "?versionId=1#auth",
    "relative-path": "/path#auth",
    "other-case": f"{DID}#AUTH",
}


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "referenced-as-is"])
@pytest.mark.parametrize("vm_id", UNSELECTABLE.values(), ids=UNSELECTABLE)
def test_a_method_with_another_id_is_not_selected(vm_id, declared):
    # the method carries the signing key, and the proof names <did>#auth: only its id differs
    relationships = {"assertionMethod": [vm_id]} if declared else {}
    doc = _doc(methods=[_method(vm_id, AUTH_KEY)], **relationships)
    _refused(_signed(AUTH_KEY, AUTH), _sync(doc), _async(doc), KeyResolutionError, NOT_IN_DOC)


SHADOWS = {k: v for k, v in UNSELECTABLE.items() if k != "other-case"}


@pytest.mark.parametrize("shadow", SHADOWS.values(), ids=SHADOWS)
def test_a_same_fragment_method_listed_first_does_not_shadow_the_exact_one(shadow):
    doc = _doc(methods=[_method(shadow, ASSERT_KEY), _method(AUTH, AUTH_KEY)],
               assertionMethod=[shadow, AUTH])
    _verifies(_signed(AUTH_KEY, AUTH), doc)                         # the exact method's key
    _refused(_signed(ASSERT_KEY, AUTH), _sync(doc), _async(doc),    # the shadow's key
             SignatureInvalid, "eddsa-jcs-2022 proof does not verify")


@pytest.mark.parametrize("first", ["#auth", AUTH], ids=["relative-spelling", "same-spelling"])
def test_two_methods_with_one_absolute_id_select_neither(first):
    doc = _doc(methods=[_method(first, ASSERT_KEY), _method(AUTH, AUTH_KEY)],
               assertionMethod=[AUTH])
    for key in (ASSERT_KEY, AUTH_KEY):            # document order picks no key
        _refused(_signed(key, AUTH), _sync(doc), _async(doc), KeyResolutionError,
                 "names 2 methods in the DID document")
    assert parse_did_document(doc).key_for_purpose(AUTH, "assertionMethod") is None


def test_the_proof_verification_method_is_not_resolved_itself():
    # key_for_purpose takes the proof's identifier as given: it must already be absolute
    doc = parse_did_document(_doc(assertionMethod=[AUTH]))
    for kid in ("auth", "#auth", f"{OTHER}#auth", 7, ["#auth"]):
        assert doc.key_for_purpose(kid, "assertionMethod") is None   # type: ignore[arg-type]
    assert doc.key_for_purpose(AUTH, "assertionMethod").public_key_jwk == AUTH_KEY.public_jwk()


def _batch() -> tuple[list, dict]:
    """[good, a same-fragment foreign reference, a method with a foreign id, good], each
    from its own did:web issuer, and the documents keyed by the URL did:web fetches."""
    deny, unselectable = "did:web:deny.example", "did:web:unselectable.example"
    docs = {
        "https://issuer.example/.well-known/did.json":
            _doc(authentication=[AUTH], assertionMethod=[AUTH]),
        "https://deny.example/.well-known/did.json":
            _doc(did=deny, authentication=[f"{deny}#auth"], assertionMethod=[f"{OTHER}#auth"]),
        "https://unselectable.example/.well-known/did.json":
            _doc(did=unselectable, methods=[_method(f"{OTHER}#auth", AUTH_KEY, unselectable)]),
    }
    good = _signed(AUTH_KEY, AUTH)
    return [good, _signed(AUTH_KEY, f"{deny}#auth"),
            _signed(AUTH_KEY, f"{unselectable}#auth"), good], docs


def _check_batch(results) -> None:
    assert [r.ok for r in results] == [True, False, False, True]
    assert type(results[1].error) is ProofPurposeMismatch
    assert type(results[2].error) is KeyResolutionError
    assert NOT_IN_DOC in str(results[2].error)


def test_verify_many_fails_only_the_mismatched_items():
    batch, docs = _batch()
    registry = DidResolverRegistry([DidWebResolver(fetch=docs.__getitem__)])
    _check_batch(verify_many(batch, resolver=registry, policy=POLICY))


def test_verify_many_async_fails_only_the_mismatched_items():
    batch, docs = _batch()

    async def fetch(url):
        return docs[url]
    registry = AsyncDidResolverRegistry([AsyncDidWebResolver(fetch=fetch)])
    _check_batch(asyncio.run(verify_many_async(batch, resolver=registry, policy=POLICY)))


# a resolver may return its own document type rather than a DidDocument: only the
# key_by_kid / key_for_purpose it is called through are known to exist, and a refusal
# must still be a typed error, never an AttributeError that aborts a batch

def _foreign_doc() -> SimpleNamespace:
    real = parse_did_document(_doc(authentication=[AUTH], assertionMethod=[ASSERT]))
    return SimpleNamespace(id=real.id, verification_methods=real.verification_methods,
                           relationships=real.relationships, key_by_kid=real.key_by_kid,
                           key_for_purpose=real.key_for_purpose)


class _ForeignResolver:
    def __init__(self) -> None:
        self._doc = _foreign_doc()

    def supports(self, did: str) -> bool:
        return did == DID

    def resolve(self, did: str) -> SimpleNamespace:
        return self._doc


class _AsyncForeignResolver:
    def __init__(self) -> None:
        self._doc = _foreign_doc()

    def supports(self, did: str) -> bool:
        return did == DID

    async def resolve(self, did: str) -> SimpleNamespace:
        return self._doc


FOREIGN_REFUSALS = {
    "not-granted": (AUTH, ProofPurposeMismatch, PURPOSE_DENIED),
    "absent": (f"{DID}#absent", KeyResolutionError, NOT_IN_DOC),
}


@pytest.mark.parametrize("vm_id,cls,match", FOREIGN_REFUSALS.values(), ids=FOREIGN_REFUSALS)
def test_a_resolvers_own_document_type_is_refused_with_a_typed_error(vm_id, cls, match):
    _refused(_signed(AUTH_KEY, vm_id), _ForeignResolver(), _AsyncForeignResolver(), cls,
             match)
    good = _signed(ASSERT_KEY, ASSERT)
    assert verify_credential(good, resolver=_ForeignResolver(), policy=POLICY).issuer == DID
    result = asyncio.run(verify_credential_async(good, resolver=_AsyncForeignResolver(),
                                                 policy=POLICY))
    assert result.issuer == DID


def _foreign_batch() -> list:
    good = _signed(ASSERT_KEY, ASSERT)
    return [good, _signed(AUTH_KEY, AUTH), _signed(AUTH_KEY, f"{DID}#absent"), good]


def test_verify_many_with_a_resolvers_own_document_type_fails_only_the_bad_items():
    _check_batch(verify_many(_foreign_batch(), resolver=_ForeignResolver(), policy=POLICY))


def test_verify_many_async_with_a_resolvers_own_document_type_fails_only_the_bad_items():
    _check_batch(asyncio.run(verify_many_async(
        _foreign_batch(), resolver=_AsyncForeignResolver(), policy=POLICY)))


# --------------------------------------------------------------------------- #
# 6. unchanged: an undeclared relationship is lenient, and kid=None falls back to the
#    sole method, which must then pass the exact-reference grant
# --------------------------------------------------------------------------- #

def test_an_undeclared_relationship_stays_lenient():
    doc = _doc(authentication=[AUTH])                        # no assertionMethod member
    _verifies(_signed(AUTH_KEY, AUTH), doc)


def _sole(vm_id: str, **relationships: Any):
    return parse_did_document(_doc(methods=[_method(vm_id, AUTH_KEY)], **relationships))


@pytest.mark.parametrize("refs", [None, [AUTH], ["#auth"], [{"id": "#auth"}]],
                         ids=["undeclared", "full", "relative", "embedded-relative"])
def test_the_kidless_fallback_selects_the_sole_method(refs):
    doc = _sole(AUTH, **({} if refs is None else {"assertionMethod": refs}))
    assert doc.key_for_purpose(None, "assertionMethod").id == AUTH


@pytest.mark.parametrize("refs", [[f"{OTHER}#auth"], ["auth"], [f"{DID}?versionId=1#auth"],
                                  ["https://issuer.example/#auth"], ["#AUTH"], []],
                         ids=["another-did", "bare", "one-version", "not-a-did-url",
                              "other-case", "declared-but-empty"])
def test_the_kidless_fallback_still_needs_an_exact_reference(refs):
    assert _sole(AUTH, assertionMethod=refs).key_for_purpose(None, "assertionMethod") is None


def test_the_kidless_fallback_never_grants_an_unresolvable_id_by_its_own_spelling():
    # a bare method id resolves to nothing, and nothing must not equal nothing
    assert _sole("auth", assertionMethod=["auth"]).key_for_purpose(None, "assertionMethod") \
        is None
    assert _sole("auth").key_for_purpose(None, "assertionMethod").id == "auth"   # lenient


def test_the_kidless_fallback_still_refuses_two_methods():
    doc = parse_did_document(_doc(assertionMethod=[ASSERT, AUTH]))
    assert doc.key_for_purpose(None, "assertionMethod") is None


# --------------------------------------------------------------------------- #
# 7. not changed: the JOSE lanes keep the fragment-tolerant kid lookup
# --------------------------------------------------------------------------- #

def _vc_jwt(key: Any, kid: str) -> str:
    now = int(time.time())
    claims = {"iss": DID, "sub": "did:example:alice", "nbf": now, "iat": now,
              "vc": _credential()}
    header = {"alg": key.alg, "typ": "JWT", "kid": kid}
    signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(claims).encode())}"
    return f"{signing_input}.{_b64u(key.sign(signing_input.encode()))}"


@pytest.mark.parametrize("kid", [AUTH, "#auth", "auth"], ids=["full", "relative", "bare"])
def test_the_jose_lanes_keep_the_fragment_tolerant_kid(kid):
    doc = _doc(assertionMethod=[AUTH])
    assert parse_did_document(doc).key_by_kid(kid).id == AUTH
    assert verify_credential(_vc_jwt(AUTH_KEY, kid), resolver=_sync(doc),
                             policy=POLICY).issuer == DID
    result = asyncio.run(verify_credential_async(_vc_jwt(AUTH_KEY, kid), resolver=_async(doc),
                                                 policy=POLICY))
    assert result.issuer == DID


# --------------------------------------------------------------------------- #
# 8. the lookup is linear in the document size. The document id is as long as the DID the
#    proof names (a did:web path has no length limit), and the number of methods and
#    references is the host's to choose. The id is checked a fixed number of times, and
#    only the selected method's own relative id is resolved (and prefix-compared with the
#    id); no other method id or reference is, so neither multiplies the other
# --------------------------------------------------------------------------- #

LONG_DID = DID + ":" + "a" * 100_000
LONG_VM = f"{LONG_DID}#k"


def _long_doc(references: int, decoys: int, *, granted: bool,
              relationship: str = "assertionMethod") -> dict:
    """LONG_DID's document: the signing key at ``#k``, beside *decoys* other ``#``
    methods, and a *relationship* of *references* ``#z`` entries, then ``#k`` when
    *granted* (so a grant reads every entry too)."""
    methods = [_method("#k", AUTH_KEY, LONG_DID)]
    methods += [_method(f"#d{i}", ASSERT_KEY, LONG_DID) for i in range(decoys)]
    return {"id": LONG_DID, "verificationMethod": methods,
            relationship: ["#z"] * references + (["#k"] if granted else [])}


def _long_lane(lane: str, references: int, decoys: int, granted: bool) -> None:
    """Verify a LONG_VM proof on *lane* against :func:`_long_doc`: it verifies when
    *granted*, else it is refused with exactly ``ProofPurposeMismatch``."""
    if lane == "authentication":
        doc = _long_doc(references, decoys, granted=granted, relationship="authentication")
        vp = _presentation(AUTH_KEY, LONG_VM)
        if granted:
            assert _verify_authentication(vp, doc).proof["verificationMethod"] == LONG_VM
            return
        with pytest.raises(ProofPurposeMismatch, match=PURPOSE_DENIED) as exc:
            _verify_authentication(vp, doc)
        assert type(exc.value) is ProofPurposeMismatch
        return
    doc = _long_doc(references, decoys, granted=granted)
    credential = _signed(AUTH_KEY, LONG_VM)

    def run() -> Any:
        if lane == "assertion-async":
            return asyncio.run(verify_credential_async(credential, resolver=_async(doc),
                                                       policy=POLICY))
        return verify_credential(credential, resolver=_sync(doc), policy=POLICY)
    if granted:
        assert run().issuer == LONG_DID
        return
    with pytest.raises(ProofPurposeMismatch, match=PURPOSE_DENIED) as exc:
        run()
    assert type(exc.value) is ProofPurposeMismatch


class _CountingPattern:
    """Stands in for ``openvc.did.base._DID_SYNTAX`` and counts every call made on it."""
    def __init__(self, pattern: Any) -> None:
        self._pattern = pattern
        self.calls = 0

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._pattern, name)

        def counted(*args: Any, **kwargs: Any) -> Any:
            self.calls += 1
            return method(*args, **kwargs)
        return counted


@pytest.mark.parametrize("granted", [False, True], ids=["refused", "granted"])
@pytest.mark.parametrize("lane", ["assertion-sync", "assertion-async", "authentication"])
def test_the_document_id_is_checked_a_fixed_number_of_times(monkeypatch, lane, granted):
    # the DID syntax check runs a fixed number of times, whatever the number of methods
    # and references: it used to run once per '#' method id and once per '#' reference
    real = did_base._DID_SYNTAX
    calls = []
    for references, decoys in ((1, 0), (2_000, 200)):
        counter = _CountingPattern(real)
        monkeypatch.setattr(did_base, "_DID_SYNTAX", counter)
        _long_lane(lane, references, decoys, granted)
        calls.append(counter.calls)
    assert 1 <= calls[0] == calls[1] <= 2           # the premise: the lookup ran through it


class _ResolvedUrl(str):
    """A string built by appending to a :class:`_CountingId`: counts the prefix
    comparisons made on it, each as long as the document id."""
    counts: dict[str, int]

    def startswith(self, *args: Any) -> bool:      # type: ignore[override]
        self.counts["prefix"] += 1
        return str.startswith(self, *args)


class _CountingId(str):
    """A document ``id`` that counts how often a string is built by appending to it, and
    how often such a string is then prefix-compared."""
    counts: dict[str, int]

    def __new__(cls, value: str) -> _CountingId:
        self = super().__new__(cls, value)
        self.counts = {"appended": 0, "prefix": 0}
        return self

    def __add__(self, other: str) -> str:
        self.counts["appended"] += 1
        resolved = _ResolvedUrl(str.__add__(self, other))
        resolved.counts = self.counts
        return resolved


@pytest.mark.parametrize("granted", [False, True], ids=["refused", "granted"])
def test_no_method_or_reference_copies_the_document_id(granted):
    # resolving every '#' method id and reference against the id would build one string
    # as long as the id per entry; each is compared with the spellings of the selected
    # method's id instead. Those are computed once: recomputing them per reference
    # prefix-compares the whole id once per reference, which is as quadratic as a copy
    # (and too fast per call for the wall-clock row to see)
    counts = []
    for references, decoys in ((1, 0), (2_000, 200)):
        raw = _long_doc(references, decoys, granted=granted)
        raw["id"] = doc_id = _CountingId(LONG_DID)
        doc = parse_did_document(raw)
        assert doc.id is doc_id                       # the premise: the parser keeps it
        vm = doc.key_for_purpose(LONG_VM, "assertionMethod")
        if granted:
            assert vm is not None and vm.public_key_jwk == AUTH_KEY.public_jwk()
        else:
            assert vm is None
        counts.append(dict(doc_id.counts))
    assert counts[0] == counts[1]                     # independent of the entry count
    assert counts[1]["appended"] == 1                 # the selected method's own id, once
    assert counts[1]["prefix"] >= 1                   # the premise: its spellings are seen


@pytest.mark.parametrize("granted", [False, True], ids=["refused", "granted"])
def test_a_long_did_with_many_references_verifies_in_linear_time(granted):
    # 100 000 characters of DID by 10 000 references: re-checking the id per reference
    # took about half a minute; the linear lookup takes milliseconds. The bound is loose
    doc = _long_doc(10_000, 0, granted=granted)
    credential = _signed(AUTH_KEY, LONG_VM)
    start = time.perf_counter()
    if granted:
        assert verify_credential(credential, resolver=_sync(doc),
                                 policy=POLICY).issuer == LONG_DID
    else:
        with pytest.raises(ProofPurposeMismatch, match=PURPOSE_DENIED) as exc:
            verify_credential(credential, resolver=_sync(doc), policy=POLICY)
        assert type(exc.value) is ProofPurposeMismatch
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0, f"verify_credential took {elapsed:.1f}s"
