"""
tests/test_did_document_shape_typed.py — a DID document that is valid JSON but the wrong
shape stays inside the typed-error boundary (#219).

``parse_did_document`` used to assume the document's shape. The document is hosted by the
issuer a token names in its own ``iss``, and key resolution runs *before* the signature
check, so an unsigned token pointing at the attacker's ``did:web`` was enough to reach it. A
``null`` or scalar ``verificationMethod``, a ``didDocument`` wrapper that is not an object, a
relationship (``assertionMethod`` …) that is not an array, or a method whose ``id`` is not a
string raised a bare ``TypeError`` / ``AttributeError``. Neither is an ``OpenvcError``, so one
such credential aborted a whole ``verify_many`` / ``verify_many_async`` batch.

The parser is shared, so the same gap was open on every path that feeds it: ``did:web`` (sync
and async), the ``did:webvh`` resolved state, and the EBSI DID Registry. Each is pinned here.

Two rules, besides "typed":

* **never read a wrong-typed member as an absent one.** A relationship the document does not
  declare leaves the key purpose unenforced, so ``assertionMethod: null`` must be an error,
  not "undeclared". And a bare string must not be iterated: ``"assertionMethod": "k"`` would
  read as a reference to the one-letter fragment ``k``.
* **a malformed entry is dropped, never selected.** A method without a string ``id`` names no
  key, and a relationship entry that is neither a string nor an object with a string ``id``
  grants nothing.

Every assertion is on the exact typed class: ``DidResolutionError`` from the parser, and
``KeyResolutionFailed`` from the pipeline (which maps ``DidError`` to it).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from typing import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openvc import verify_credential, verify_many, verify_many_async
from openvc.aio import verify_credential_async
from openvc.did.base import (
    RELATIONSHIP_KEYS,
    AsyncDidResolverRegistry,
    DidResolutionError,
    DidResolverRegistry,
    as_async_resolver,
    parse_did_document,
)
from openvc.did.did_key import DidKeyResolver
from openvc.did.did_web import AsyncDidWebResolver, DidWebResolver
from openvc.did.did_webvh import (
    AsyncDidWebvhResolver,
    DidWebvhResolver,
    _jcs,
    _multihash_b58,
)
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import KeyResolutionError, ProofPurposeMismatch
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.verify import KeyResolutionFailed

DID = "did:web:evil.example"
KID = DID + "#k"
V2 = "https://www.w3.org/ns/credentials/v2"
GOOD_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}      # any well-formed public JWK


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unsigned(did: str) -> str:
    """The issue's repro: an unsigned token whose ``iss`` names the attacker's own DID."""
    seg = lambda obj: _b64u(json.dumps(obj).encode())      # noqa: E731
    return f"{seg({'alg': 'ES256', 'kid': did + '#k'})}.{seg({'iss': did, 'vc': {}})}.AAAA"


def _vm(did: str, **extra) -> dict:
    return {"id": did + "#k", "type": "JsonWebKey2020", "controller": did,
            "publicKeyJwk": GOOD_JWK, **extra}


# --------------------------------------------------------------------------- #
# the hostile documents. Each row is a factory taking the DID the document is served for
# --------------------------------------------------------------------------- #

# A JSON value of every other type, for a member that must be an array.
NOT_AN_ARRAY = {
    "null": None, "number": 5, "float": 1.5, "true": True, "false": False,
    "string": "did:web:evil.example#k", "char": "k", "empty-string": "",
    "object": {}, "id-object": {"id": KID},
}

# (id, factory) — parse_did_document must raise DidResolutionError for each
RAISES: list[tuple[str, Callable[[str], dict]]] = []
for _member in ("verificationMethod", *RELATIONSHIP_KEYS):
    for _name, _value in NOT_AN_ARRAY.items():
        RAISES.append((f"{_member}-{_name}",
                       lambda did, m=_member, v=_value: {
                           "id": did, "verificationMethod": [_vm(did)], m: v}))
for _name, _value in {"null": None, "list": [], "number": 5, "string": "x", "true": True,
                      "float": 1.5, "empty-list": [[]]}.items():
    RAISES.append((f"didDocument-{_name}", lambda did, v=_value: {"didDocument": v}))
    RAISES.append((f"didDocument-{_name}-beside-bare",
                   lambda did, v=_value: {"id": did, "verificationMethod": [_vm(did)],
                                          "didDocument": v}))

# (id, factory) — parse_did_document accepts these but no key is usable from them
USABLE_KEY_NONE: list[tuple[str, Callable[[str], dict]]] = []
for _name, _value in {"number": 7, "null": None, "list": [], "object": {}, "true": True,
                      "float": 1.5, "list-of-id": [KID], "id-object": {"id": KID}}.items():
    USABLE_KEY_NONE.append((f"vm-id-{_name}",
                            lambda did, v=_value: {"id": did, "verificationMethod": [
                                {**_vm(did), "id": v}]}))
USABLE_KEY_NONE += [
    ("vm-without-id", lambda did: {"id": did, "verificationMethod": [
        {k: v for k, v in _vm(did).items() if k != "id"}]}),
    ("vm-not-an-object", lambda did: {"id": did, "verificationMethod": [
        7, None, "x", [], [_vm(did)], True]}),
    ("vm-without-a-key", lambda did: {"id": did, "verificationMethod": [
        {"id": did + "#k", "type": "JsonWebKey2020"}]}),
    ("no-vm-member", lambda did: {"id": did}),
]


def _ids(rows):
    return [name for name, _ in rows]


# --------------------------------------------------------------------------- #
# 1. the parser itself
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("make", [make for _, make in RAISES], ids=_ids(RAISES))
def test_parse_raises_the_typed_error_for_a_wrong_shaped_document(make):
    with pytest.raises(DidResolutionError) as exc:
        parse_did_document(make(DID))
    assert type(exc.value) is DidResolutionError
    assert "must be" in str(exc.value)


@pytest.mark.parametrize("raw", [[], "x", 5, 1.5, True, None, [{}]],
                         ids=["list", "string", "int", "float", "true", "null", "list-of-obj"])
def test_parse_raises_the_typed_error_for_a_document_that_is_not_an_object(raw):
    # an injected fetch can hand over any JSON value; https_json_fetch only ever returns an
    # object, but the type annotation is not a runtime guard
    with pytest.raises(DidResolutionError, match="must be a JSON object") as exc:
        parse_did_document(raw)           # type: ignore[arg-type]
    assert type(exc.value) is DidResolutionError


@pytest.mark.parametrize("make", [make for _, make in USABLE_KEY_NONE],
                         ids=_ids(USABLE_KEY_NONE))
def test_parse_drops_a_method_that_names_no_key(make):
    doc = parse_did_document(make(DID))
    assert doc.verification_methods == []
    assert doc.key_by_kid(KID) is None and doc.key_by_kid("k") is None
    assert doc.key_for_purpose(KID, "assertionMethod") is None


def test_parse_keeps_the_good_method_beside_the_malformed_ones():
    doc = parse_did_document({"id": DID, "verificationMethod": [
        {**_vm(DID), "id": 7}, None, "x", {**_vm(DID), "id": ["a#b"]}, _vm(DID)]})
    assert [vm.id for vm in doc.verification_methods] == [KID]
    assert doc.key_by_kid(KID).kid == "k"
    assert doc.key_by_kid("k") is not None


@pytest.mark.parametrize("junk", [7, None, True, 1.5, [], {}, {"id": 7}, {"id": None},
                                  {"id": ["a"]}, {"x": KID}],
                         ids=["int", "null", "true", "float", "list", "object",
                              "id-int", "id-null", "id-list", "no-id"])
def test_a_relationship_entry_that_is_not_a_reference_grants_nothing(junk):
    doc = parse_did_document({"id": DID, "verificationMethod": [_vm(DID)],
                              "assertionMethod": [junk]})
    # declared but empty: the key exists, yet no purpose is granted. It must NOT read as
    # "undeclared", which leaves the purpose unenforced.
    assert doc.relationships == {"assertionMethod": []}
    assert doc.key_by_kid(KID) is not None
    assert doc.key_for_purpose(KID, "assertionMethod") is None


def test_junk_beside_a_real_reference_does_not_widen_or_hide_it():
    doc = parse_did_document({"id": DID, "verificationMethod": [_vm(DID)],
                              "assertionMethod": [7, None, KID, {"id": 3}, {"id": KID}]})
    assert doc.relationships == {"assertionMethod": [KID, KID]}
    assert doc.key_for_purpose(KID, "assertionMethod") is not None
    # a relationship the document never declared stays lenient (unchanged behaviour)
    assert "authentication" not in doc.relationships


def test_a_string_relationship_is_not_read_one_character_at_a_time():
    # Before the fix "assertionMethod": "k" iterated to ["k"], and key_for_purpose matched
    # it to any method whose fragment is "k" — a purpose granted by a typo or a hostile
    # document. It is now refused before any reference is read.
    with pytest.raises(DidResolutionError, match="assertionMethod must be an array"):
        parse_did_document({"id": DID, "verificationMethod": [_vm(DID)],
                            "assertionMethod": "k"})
    with pytest.raises(DidResolutionError, match="authentication must be an array"):
        parse_did_document({"id": DID, "verificationMethod": [_vm(DID)],
                            "authentication": KID})


def test_a_null_relationship_is_not_read_as_undeclared():
    # an undeclared relationship returns the key as-is; null must not fall into that branch
    undeclared = parse_did_document({"id": DID, "verificationMethod": [_vm(DID)]})
    assert undeclared.key_for_purpose(KID, "assertionMethod") is not None
    with pytest.raises(DidResolutionError):
        parse_did_document({"id": DID, "verificationMethod": [_vm(DID)],
                            "assertionMethod": None})


@pytest.mark.parametrize("field", ["type", "controller"])
@pytest.mark.parametrize("value", [7, None, ["x"], {}, True],
                         ids=["int", "null", "list", "object", "true"])
def test_a_method_type_or_controller_that_is_not_a_string_reads_as_empty(field, value):
    doc = parse_did_document({"id": DID, "verificationMethod": [{**_vm(DID), field: value}]})
    (vm,) = doc.verification_methods
    assert getattr(vm, field) == ""            # the model's str fields stay str
    assert vm.kid == "k" and vm.id == KID


def test_an_absent_controller_defaults_to_the_document_id():
    method = {k: v for k, v in _vm(DID).items() if k != "controller"}
    doc = parse_did_document({"id": DID, "verificationMethod": [method]})
    assert doc.verification_methods[0].controller == DID


@pytest.mark.parametrize("value", [[], {}, 7, None, True],
                         ids=["list", "object", "int", "null", "true"])
def test_a_document_id_that_is_not_a_string_reads_as_empty(value):
    method = {k: v for k, v in _vm(DID).items() if k != "controller"}   # takes the default
    doc = parse_did_document({"id": value, "verificationMethod": [method]})
    assert doc.id == ""                         # never equals the DID a resolver asked for
    assert doc.verification_methods[0].controller == ""
    assert isinstance(doc.id, str)


def test_the_didDocument_wrapper_is_still_unwrapped():
    wrapped = parse_did_document({"didDocument": {"id": DID, "verificationMethod": [_vm(DID)],
                                                  "assertionMethod": [KID]}})
    assert wrapped.id == DID and wrapped.key_for_purpose(KID, "assertionMethod") is not None


def test_a_document_with_every_member_well_formed_is_unchanged():
    raw = {"id": DID, "verificationMethod": [_vm(DID)],
           **{key: [KID, {"id": KID}] for key in RELATIONSHIP_KEYS}}
    doc = parse_did_document(raw)
    assert doc.id == DID and len(doc.verification_methods) == 1
    assert doc.relationships == {key: [KID, KID] for key in RELATIONSHIP_KEYS}
    assert all(doc.key_for_purpose(KID, key) is not None for key in RELATIONSHIP_KEYS)


# --------------------------------------------------------------------------- #
# 2. did:web — the issue's repro, once per row, sync and async
# --------------------------------------------------------------------------- #

def _sync_registry(doc) -> DidResolverRegistry:
    return DidResolverRegistry([DidWebResolver(fetch=lambda url: doc)])


def _async_registry(doc) -> AsyncDidResolverRegistry:
    async def fetch(url):
        return doc
    return AsyncDidResolverRegistry([AsyncDidWebResolver(fetch=fetch)])


@pytest.mark.parametrize("make", [make for _, make in RAISES], ids=_ids(RAISES))
def test_did_web_resolver_raises_the_typed_error(make):
    with pytest.raises(DidResolutionError) as exc:
        DidWebResolver(fetch=lambda url: make(DID)).resolve(DID)
    assert type(exc.value) is DidResolutionError


@pytest.mark.parametrize("make", [make for _, make in RAISES], ids=_ids(RAISES))
def test_verify_credential_types_a_wrong_shaped_document(make):
    with pytest.raises(KeyResolutionFailed) as exc:
        verify_credential(_unsigned(DID), resolver=_sync_registry(make(DID)))
    assert type(exc.value) is KeyResolutionFailed
    # failed in the parser, not on the id check that already typed the old control row
    assert type(exc.value.__cause__) is DidResolutionError
    assert "must be" in str(exc.value)


@pytest.mark.parametrize("make", [make for _, make in RAISES], ids=_ids(RAISES))
def test_verify_credential_async_types_a_wrong_shaped_document(make):
    with pytest.raises(KeyResolutionFailed) as exc:
        asyncio.run(verify_credential_async(
            _unsigned(DID), resolver=_async_registry(make(DID))))
    assert type(exc.value) is KeyResolutionFailed
    assert type(exc.value.__cause__) is DidResolutionError
    assert "must be" in str(exc.value)


@pytest.mark.parametrize("make", [make for _, make in USABLE_KEY_NONE],
                         ids=_ids(USABLE_KEY_NONE))
def test_a_malformed_method_is_never_selected_as_the_key(make):
    with pytest.raises(KeyResolutionFailed, match="no verification method") as exc:
        verify_credential(_unsigned(DID), resolver=_sync_registry(make(DID)))
    assert type(exc.value) is KeyResolutionFailed
    with pytest.raises(KeyResolutionFailed, match="no verification method") as aexc:
        asyncio.run(verify_credential_async(
            _unsigned(DID), resolver=_async_registry(make(DID))))
    assert type(aexc.value) is KeyResolutionFailed


@pytest.mark.parametrize("value", [[], {}, 7, None, "", True],
                         ids=["list", "object", "int", "null", "empty", "true"])
def test_a_document_id_that_is_not_a_string_still_fails_the_did_web_id_check(value):
    # the old control row: typed before and after, now through the "" the parser reads
    doc = {"id": value, "verificationMethod": [_vm(DID)]}
    with pytest.raises(KeyResolutionFailed, match="document id") as exc:
        verify_credential(_unsigned(DID), resolver=_sync_registry(doc))
    assert type(exc.value.__cause__) is DidResolutionError


# --------------------------------------------------------------------------- #
# 3. the batch: one hostile item never aborts the others (verify_many, verify_many_async)
# --------------------------------------------------------------------------- #

def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _vc_jwt(key, did: str) -> str:
    """A VC-JWT signed by *key* for issuer *did*, key id = ``key.kid``."""
    now = int(time.time())
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:s"}}
    claims = {"iss": did, "sub": "did:example:s", "nbf": now, "iat": now, "vc": vc}
    signing_input = (f"{_b64u(json.dumps({'alg': key.alg, 'typ': 'JWT', 'kid': key.kid}).encode())}"
                     f".{_b64u(json.dumps(claims).encode())}")
    return f"{signing_input}.{_b64u(key.sign(signing_input.encode()))}"


def _hostile_batch():
    """[good, one unsigned token per hostile document, good] and the fetch serving them."""
    rows = RAISES + USABLE_KEY_NONE
    docs: dict[str, object] = {}
    tokens = []
    for index, (_, make) in enumerate(rows):
        did = f"did:web:h{index}.example"
        docs[f"https://h{index}.example/.well-known/did.json"] = make(did)
        tokens.append(_unsigned(did))
    key, did = _did_key_p256()
    good = _vc_jwt(key, did)
    return [good, *tokens, good], docs, rows


def _check_batch(results, rows):
    assert len(results) == len(rows) + 2
    assert results[0].ok and results[-1].ok
    for result, (name, _) in zip(results[1:-1], rows):
        assert not result.ok, name
        assert type(result.error) is KeyResolutionFailed, name


def test_verify_many_isolates_every_hostile_document():
    batch, docs, rows = _hostile_batch()
    registry = DidResolverRegistry([DidKeyResolver(), DidWebResolver(fetch=docs.__getitem__)])
    _check_batch(verify_many(batch, resolver=registry), rows)


def test_verify_many_async_isolates_every_hostile_document():
    batch, docs, rows = _hostile_batch()

    async def fetch(url):
        return docs[url]
    registry = AsyncDidResolverRegistry([as_async_resolver(DidKeyResolver()),
                                         AsyncDidWebResolver(fetch=fetch)])
    _check_batch(asyncio.run(verify_many_async(batch, resolver=registry)), rows)


def test_the_issues_repro_no_longer_aborts_the_batch():
    tok = _unsigned(DID)
    registry = DidResolverRegistry([DidWebResolver(
        fetch=lambda url: {"id": DID, "verificationMethod": None})])
    results = verify_many([tok, tok], resolver=registry)
    assert [type(r.error) for r in results] == [KeyResolutionFailed, KeyResolutionFailed]


# --------------------------------------------------------------------------- #
# 4. never fail open, and never over-reject
# --------------------------------------------------------------------------- #

def _signed_did_web(*, extra: dict | None = None, vms_before=(), refs_before=()):
    """A VC-JWT signed by a P-256 key published in a did:web document that carries
    malformed entries around the real method and its reference."""
    key = P256SigningKey.generate(kid=KID)
    doc = {"id": DID,
           "verificationMethod": [*vms_before, _vm(DID, publicKeyJwk=key.public_jwk())],
           "assertionMethod": [*refs_before, KID], **(extra or {})}
    return _vc_jwt(key, DID), doc


def test_a_well_formed_method_beside_malformed_entries_still_verifies():
    token, doc = _signed_did_web(vms_before=(7, None, {"id": 7}, {"id": ["x"]}, [], "x"),
                                 refs_before=(7, None, {"id": 3}, [], {}))
    assert verify_credential(token, resolver=_sync_registry(doc)).issuer == DID
    result = asyncio.run(verify_credential_async(token, resolver=_async_registry(doc)))
    assert result.issuer == DID


def test_a_wrong_typed_relationship_never_lets_a_valid_signature_through():
    token, doc = _signed_did_web(extra={"authentication": None})
    with pytest.raises(KeyResolutionFailed):
        verify_credential(token, resolver=_sync_registry(doc))


def _di_credential(key: Ed25519SigningKey, vm_id: str) -> dict:
    cred = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
            "validFrom": "2020-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:s"}}
    return EddsaJcsProofSuite().add_proof(cred, signing_key=key, verification_method=vm_id)


def _di_doc(key: Ed25519SigningKey, **members) -> dict:
    return {"id": DID, "verificationMethod": [
        {"id": KID, "type": "JsonWebKey2020", "controller": DID,
         "publicKeyJwk": key.public_jwk()}], **members}


def test_data_integrity_lane_never_selects_a_key_through_a_wrong_shaped_document():
    key = Ed25519SigningKey(ed25519.Ed25519PrivateKey.generate(), kid=KID)
    cred = _di_credential(key, KID)
    # control: a well-formed document verifies, so the rows below are not vacuous
    ok = verify_credential(cred, resolver=_sync_registry(_di_doc(key, assertionMethod=[KID])))
    assert ok.issuer == DID

    for members in ({"assertionMethod": None}, {"assertionMethod": "k"},
                    {"assertionMethod": KID}, {"assertionMethod": {"id": KID}},
                    {"assertionMethod": 7}, {"verificationMethod": None},
                    {"verificationMethod": {"id": KID}}):
        doc = {**_di_doc(key), **members}
        with pytest.raises(KeyResolutionError) as exc:
            verify_credential(cred, resolver=_sync_registry(doc))
        assert type(exc.value) is KeyResolutionError, members

    # a declared relationship whose entries are all junk grants nothing: the key exists
    # (so it is not "not in the document") but no purpose is authorized
    for junk in ([], [7], [None, {"id": 3}], [[KID]]):
        with pytest.raises(ProofPurposeMismatch):
            verify_credential(cred, resolver=_sync_registry(
                _di_doc(key, assertionMethod=junk)))


# --------------------------------------------------------------------------- #
# 5. did:webvh — the resolved state is parsed by the same function
# --------------------------------------------------------------------------- #

def _forge_webvh_log(state_for) -> tuple[str, str]:
    """A one-entry did:webvh log the attacker signs with their own updateKey, as the
    attacker controls their own log. *state_for(did)* builds the DID document."""
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(private, kid="_")
    multikey = encode_multibase(
        bytes([0xED, 0x01]) + base64.urlsafe_b64decode(signer.public_jwk()["x"] + "=="))
    template = {"versionId": "{SCID}", "versionTime": "2026-01-01T00:00:00Z",
                "parameters": {"method": "did:webvh:1.0", "scid": "{SCID}",
                               "updateKeys": [multikey]},
                "state": state_for("did:webvh:{SCID}:evil.example")}
    scid = _multihash_b58(_jcs(template))
    entry = json.loads(json.dumps(template).replace("{SCID}", scid))
    entry["versionId"] = f"1-{_multihash_b58(_jcs({**entry, 'versionId': scid}))}"
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
             "verificationMethod": f"did:key:{multikey}#{multikey}",
             "created": "2026-01-01T00:00:00Z", "proofPurpose": "assertionMethod"}
    hash_data = hashlib.sha256(_jcs(proof)).digest() + hashlib.sha256(_jcs(entry)).digest()
    entry["proof"] = [{**proof, "proofValue": encode_multibase(signer.sign(hash_data))}]
    return f"did:webvh:{scid}:evil.example", json.dumps(entry) + "\n"


def _webvh_state(**members):
    return lambda did: {"id": did, "verificationMethod": [_vm(did)], **members}


def test_the_forged_webvh_log_is_a_valid_one():
    # the helper must produce a log the resolver accepts, or the rows below prove nothing
    did, log = _forge_webvh_log(_webvh_state(assertionMethod=[]))
    doc = DidWebvhResolver(fetch=lambda url: log).resolve(did)
    assert doc.id == did and len(doc.verification_methods) == 1


_WEBVH_ROWS = [
    ("verificationMethod-null", {"verificationMethod": None}),
    ("verificationMethod-number", {"verificationMethod": 5}),
    ("verificationMethod-object", {"verificationMethod": {"id": "x"}}),
    ("assertionMethod-null", {"assertionMethod": None}),
    ("assertionMethod-string", {"assertionMethod": "k"}),
    ("authentication-number", {"authentication": 7}),
    ("keyAgreement-object", {"keyAgreement": {}}),
]


@pytest.mark.parametrize("members", [m for _, m in _WEBVH_ROWS], ids=[n for n, _ in _WEBVH_ROWS])
def test_webvh_state_is_typed_sync_async_and_through_the_pipeline(members):
    did, log = _forge_webvh_log(lambda d: {"id": d, **members})
    with pytest.raises(DidResolutionError) as exc:
        DidWebvhResolver(fetch=lambda url: log).resolve(did)
    assert type(exc.value) is DidResolutionError and "must be" in str(exc.value)

    async def fetch(url):
        return log
    with pytest.raises(DidResolutionError) as aexc:
        asyncio.run(AsyncDidWebvhResolver(fetch=fetch).resolve(did))
    assert type(aexc.value) is DidResolutionError

    registry = DidResolverRegistry([DidWebvhResolver(fetch=lambda url: log)])
    results = verify_many([_unsigned(did)] * 2, resolver=registry)
    assert [type(r.error) for r in results] == [KeyResolutionFailed, KeyResolutionFailed]
    aregistry = AsyncDidResolverRegistry([AsyncDidWebvhResolver(fetch=fetch)])
    aresults = asyncio.run(verify_many_async([_unsigned(did)] * 2, resolver=aregistry))
    assert [type(r.error) for r in aresults] == [KeyResolutionFailed, KeyResolutionFailed]


def test_webvh_state_with_a_method_without_a_string_id_names_no_key():
    did, log = _forge_webvh_log(lambda d: {"id": d, "verificationMethod": [
        {**_vm(d), "id": 7}, {**_vm(d), "id": [d + "#k"]}]})
    assert DidWebvhResolver(fetch=lambda url: log).resolve(did).verification_methods == []


# --------------------------------------------------------------------------- #
# 6. the EBSI DID Registry — the same shared parser behind DidRegistryV5
# --------------------------------------------------------------------------- #

EBSI_DID = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"


@pytest.mark.parametrize("make", [make for _, make in RAISES], ids=_ids(RAISES))
def test_ebsi_registry_document_is_typed(make):
    pytest.importorskip("openvc_ebsi")
    from openvc_ebsi.versioning import DidEbsiResolver

    resolver = DidEbsiResolver(lambda url: make(EBSI_DID),
                               decode_jwt=VcJwtProofSuite().peek_claims)
    with pytest.raises(DidResolutionError) as exc:
        resolver.resolve(EBSI_DID)
    assert type(exc.value) is DidResolutionError


_EBSI_BADGE_ROWS = [row for row in RAISES if row[0] in {
    "verificationMethod-null", "verificationMethod-number", "assertionMethod-null",
    "authentication-number", "keyAgreement-string", "didDocument-null", "didDocument-list"}]


@pytest.mark.parametrize("make", [make for _, make in _EBSI_BADGE_ROWS],
                         ids=_ids(_EBSI_BADGE_ROWS))
def test_verify_ebsi_badge_types_a_wrong_shaped_registry_document(make):
    pytest.importorskip("openvc_ebsi")
    from openvc_ebsi.verify import EbsiVerificationError, verify_ebsi_badge
    from openvc_ebsi.versioning import DidEbsiResolver

    suite = VcJwtProofSuite()
    resolver = DidEbsiResolver(lambda url: make(EBSI_DID), decode_jwt=suite.peek_claims)
    with pytest.raises(EbsiVerificationError) as exc:
        verify_ebsi_badge(_unsigned(EBSI_DID), resolver=resolver, proof_suite=suite)
    assert type(exc.value) is EbsiVerificationError
    assert type(exc.value.__cause__) is DidResolutionError


def test_ebsi_registry_wrapper_with_a_malformed_method_names_no_key():
    pytest.importorskip("openvc_ebsi")
    from openvc_ebsi.versioning import DidEbsiResolver

    doc = {"didDocument": {"id": EBSI_DID, "verificationMethod": [
        {"id": 7, "publicKeyJwk": GOOD_JWK}, {"id": None, "publicKeyJwk": GOOD_JWK}]}}
    resolver = DidEbsiResolver(lambda url: doc, decode_jwt=VcJwtProofSuite().peek_claims)
    resolved = resolver.resolve(EBSI_DID)
    assert resolved.verification_methods == [] and resolved.key_by_kid("k") is None
