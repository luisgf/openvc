"""
tests/test_did_webvh_state_envelope.py — a did:webvh log state is the DID document itself, so
a ``didDocument`` member in the returned state is refused (#256).

``_WebvhReplay._replay`` checked ``state["id"] == did`` on the raw log state, then returned
``parse_did_document(state)``, and that parser unwraps a ``didDocument`` member when there is
one (a tolerance for a resolution envelope, ADR-0001, not for a did:webvh state). So the
``id`` that was checked was not the ``id`` of the document that came back:

* ``{"id": DID, "didDocument": {"id": "did:web:other.example", ...}}`` resolved to a document
  whose ``id``, ``raw["id"]`` and method ids were ``did:web:other.example``;
* ``{"id": DID, "verificationMethod": [#outer], "didDocument": {"id": DID, "verificationMethod":
  [#inner]}}`` resolved to ``#inner`` only, dropping the state's own methods.

The controller signs the whole state, wrapper included, so such a log passes the SCID, the
entryHash chain, the proof and pre-rotation. The wrapper never crosses the controller
boundary (every key it yields is one the controller published), and no verification lane reads
``doc.id``; what it breaks is the resolver's own contract, and agreement with other did:webvh
resolvers, for which the state *is* the document (did:webvh v1.0, "The DID Log File").

The returned (last) state is now refused with ``DidWebvhError`` when it carries a
``didDocument`` member, before the parser runs; a post-parse ``doc.id`` check backs it up, as
``did:web`` does. The earlier states are never parsed, so only the last one is looked at.

Every credential below is signed by the log controller's own key, and the log is served for
the DID the credential names, so before the fix the wrapped rows *verified*: the refusal is
what makes them fail, not a missing key. ``did:web`` and the EBSI registry keep the envelope
tolerance, and a state without a wrapper resolves as before; both are pinned as controls.

Every assertion is on the exact class: ``DidWebvhError`` from the resolver (never the
``DidResolutionError`` parent, which the parser raised for a wrapper that was not an object),
``KeyResolutionFailed`` on the JOSE lanes and on the async API, ``KeyResolutionError`` (a
``ProofError``) on the synchronous Data Integrity lane.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import openvc.did.did_webvh as webvh_module
from openvc import verify_credential, verify_many, verify_many_async
from openvc.aio import verify_credential_async
from openvc.did.base import (
    AsyncDidResolverRegistry,
    DidDocument,
    DidResolutionError,
    DidResolverRegistry,
    parse_did_document,
)
from openvc.did.did_web import DidWebResolver
from openvc.did.did_webvh import (
    AsyncDidWebvhResolver,
    DidWebvhError,
    DidWebvhResolver,
    _did_webvh_url,
    _jcs,
    _multihash_b58,
)
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import KeyResolutionError
from openvc.verify import KeyResolutionFailed

OTHER = "did:web:other.example"
V2 = "https://www.w3.org/ns/credentials/v2"
HOST = "evil.example"
FIXTURES = Path(__file__).parent / "fixtures" / "didwebvh"


# --------------------------------------------------------------------------- #
# a signed did:webvh log builder (copied: tests/ is not a package)
# --------------------------------------------------------------------------- #

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_webvh_log(states_for: list[Callable[[str], dict]], *, host: str = HOST,
                     private: ed25519.Ed25519PrivateKey | None = None,
                     deactivate_last: bool = False) -> tuple[str, str]:
    """A valid did:webvh log with one entry per element of *states_for*, signed by its own
    updateKey (the attacker controls their own log). *states_for[i](did)* builds the DID
    document of version ``i + 1``. *private* is that updateKey (generated when omitted, so a
    caller that needs the key in a state creates it first). *deactivate_last* sets
    ``deactivated`` in the parameters of the last of two or more entries. Returns
    ``(did, did.jsonl)``."""
    private = private or ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(private, kid="_")
    multikey = encode_multibase(
        bytes([0xED, 0x01]) + base64.urlsafe_b64decode(signer.public_jwk()["x"] + "=="))
    proof_options = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                     "verificationMethod": f"did:key:{multikey}#{multikey}",
                     "created": "2026-01-01T00:00:00Z", "proofPurpose": "assertionMethod"}

    def sign(entry: dict) -> dict:
        hash_data = hashlib.sha256(_jcs(proof_options)).digest() \
            + hashlib.sha256(_jcs(entry)).digest()
        return {**entry, "proof": [{**proof_options,
                                    "proofValue": encode_multibase(signer.sign(hash_data))}]}

    template = {"versionId": "{SCID}", "versionTime": "2026-01-01T00:00:00Z",
                "parameters": {"method": "did:webvh:1.0", "scid": "{SCID}",
                               "updateKeys": [multikey]},
                "state": states_for[0](f"did:webvh:{{SCID}}:{host}")}
    scid = _multihash_b58(_jcs(template))
    did = f"did:webvh:{scid}:{host}"
    genesis = json.loads(json.dumps(template).replace("{SCID}", scid))
    genesis["versionId"] = f"1-{_multihash_b58(_jcs({**genesis, 'versionId': scid}))}"
    entries = [sign(genesis)]
    assert len(states_for) <= 9, "versionTime below is one digit of the day"
    for number, state_for in enumerate(states_for[1:], start=2):
        deactivating = deactivate_last and number == len(states_for)
        update = {"versionId": entries[-1]["versionId"],
                  "versionTime": f"2026-01-0{number}T00:00:00Z",
                  "parameters": {"deactivated": True} if deactivating else {},
                  "state": state_for(did)}
        update["versionId"] = f"{number}-{_multihash_b58(_jcs(update))}"
        entries.append(sign(update))
    return did, "".join(json.dumps(entry) + "\n" for entry in entries)


def _method(did: str, jwk: dict, fragment: str = "k", **extra: Any) -> dict:
    return {"id": f"{did}#{fragment}", "type": "JsonWebKey2020", "controller": did,
            "publicKeyJwk": jwk, **extra}


class Controller:
    """The key a log is signed with. The same key signs the credentials below."""

    def __init__(self) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.jwk = Ed25519SigningKey(self.private, kid="_").public_jwk()

    def log(self, state_for: Callable[[str, dict], dict], host: str = HOST) -> tuple[str, str]:
        return _forge_webvh_log([lambda did: state_for(did, self.jwk)], host=host,
                                private=self.private)

    def key(self, kid: str) -> Ed25519SigningKey:
        return Ed25519SigningKey(self.private, kid=kid)


def _vc_jwt(key: Ed25519SigningKey, did: str) -> str:
    """A VC-JWT for issuer *did*, signed by *key*, whose ``kid`` header is ``key.kid``."""
    now = int(time.time())
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:s"}}
    claims = {"iss": did, "sub": "did:example:s", "nbf": now, "iat": now, "vc": vc}
    header = {"alg": key.alg, "typ": "JWT", "kid": key.kid}
    signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(claims).encode())}"
    return f"{signing_input}.{_b64u(key.sign(signing_input.encode()))}"


def _di_credential(key: Ed25519SigningKey, did: str) -> dict:
    """An ``eddsa-jcs-2022`` credential for issuer *did*, its proof naming ``key.kid``."""
    cred = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
            "validFrom": "2020-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:s"}}
    return EddsaJcsProofSuite().add_proof(cred, signing_key=key, verification_method=key.kid)


def _registry(logs: dict[str, str]) -> DidResolverRegistry:
    return DidResolverRegistry([DidWebvhResolver(fetch=lambda url: logs[url])])


def _async_registry(logs: dict[str, str]) -> AsyncDidResolverRegistry:
    async def fetch(url: str) -> str:
        return logs[url]
    return AsyncDidResolverRegistry([AsyncDidWebvhResolver(fetch=fetch)])


def _resolve(did: str, log: str) -> DidDocument:
    return DidWebvhResolver(fetch=lambda url: log).resolve(did)


def _resolve_async(did: str, log: str) -> DidDocument:
    async def fetch(url: str) -> str:
        return log
    return asyncio.run(AsyncDidWebvhResolver(fetch=fetch).resolve(did))


# --------------------------------------------------------------------------- #
# the wrapped states: (id, state_for(did, jwk), the fragment of the method that would sign)
# --------------------------------------------------------------------------- #

def _bare(did: str, jwk: dict) -> dict:
    return {"id": did, "verificationMethod": [_method(did, jwk)]}


def _with(member: Any) -> Callable[[str, dict], dict]:
    """The bare state plus a ``didDocument`` member that is not a document."""
    return lambda d, jwk: {**_bare(d, jwk), "didDocument": member}


WRAPPED: list[tuple[str, Callable[[str, dict], dict], str]] = [
    # the inner document names another DID: the document returned is not the one asked for
    ("foreign-id",
     lambda d, jwk: {"id": d, "didDocument": {
         "id": OTHER, "verificationMethod": [_method(OTHER, jwk)]}}, "k"),
    # the inner document has the right id and replaces the state's own methods
    ("same-id-replaces-outer-methods",
     lambda d, jwk: {"id": d, "verificationMethod": [_method(d, jwk, "outer")],
                     "didDocument": {"id": d, "verificationMethod": [_method(d, jwk, "inner")]}},
     "inner"),
    ("same-id-wrapper-only",
     lambda d, jwk: {"id": d, "didDocument": {"id": d, "verificationMethod": [_method(d, jwk)]}},
     "k"),
    ("same-id-beside-the-same-methods",
     lambda d, jwk: {"id": d, "verificationMethod": [_method(d, jwk)],
                     "didDocument": {"id": d, "verificationMethod": [_method(d, jwk)]}}, "k"),
    # a member that is present but not a document: the parser typed some of these as a plain
    # DidResolutionError, so none of them was a DidWebvhError before
    ("null-wrapper", _with(None), "k"),
    ("empty-object-wrapper", _with({}), "k"),
    ("list-wrapper", _with([]), "k"),
    ("string-wrapper", _with("x"), "k"),
    ("number-wrapper", _with(5), "k"),
    ("false-wrapper", _with(False), "k"),
]
IDS = [name for name, _, _ in WRAPPED]
STATES = [state for _, state, _ in WRAPPED]
STATES_AND_FRAGMENTS = [(state, fragment) for _, state, fragment in WRAPPED]


# --------------------------------------------------------------------------- #
# 1. the resolver: a wrapped state is refused, sync and async
# --------------------------------------------------------------------------- #

def test_the_forged_log_is_a_valid_one_and_the_bare_state_resolves_as_before():
    # the helper must produce a log the resolver accepts, or the rows below prove nothing
    control = Controller()
    did, log = control.log(_bare)
    for doc in (_resolve(did, log), _resolve_async(did, log)):
        assert doc.id == did
        assert doc.raw["id"] == did
        assert [vm.id for vm in doc.verification_methods] == [f"{did}#k"]
        assert doc.verification_methods[0].controller == did
        assert doc.verification_methods[0].public_key_jwk == control.jwk


@pytest.mark.parametrize("state_for", STATES, ids=IDS)
def test_a_wrapped_state_is_refused_naming_the_member(state_for):
    did, log = Controller().log(state_for)
    with pytest.raises(DidWebvhError, match="didDocument") as exc:
        _resolve(did, log)
    assert type(exc.value) is DidWebvhError
    assert isinstance(exc.value, DidResolutionError)
    with pytest.raises(DidWebvhError, match="didDocument") as aexc:
        _resolve_async(did, log)
    assert type(aexc.value) is DidWebvhError


@pytest.mark.parametrize("state_for", STATES, ids=IDS)
def test_the_refusal_comes_after_the_log_checks_and_is_not_one_of_them(state_for):
    # The controller signs the wrapper, so the SCID, the entryHash chain, the proof and
    # versionTime all pass. What is refused is the wrapper, not a tampered log, an id mismatch
    # or a deactivation.
    did, log = Controller().log(state_for)
    with pytest.raises(DidWebvhError) as exc:
        _resolve(did, log)
    message = str(exc.value)
    assert "didDocument" in message
    assert did in message
    assert "SCID" not in message and "entryHash" not in message and "proof" not in message
    assert "!=" not in message and "deactivated" not in message


def test_the_returned_document_is_the_state_itself_and_has_the_requested_id():
    # pins the contract the wrapper broke: the document returned for a DID has that DID's id,
    # `raw` is the state, and every method comes from the state
    control = Controller()
    did, log = control.log(lambda d, jwk: {
        "id": d, "controller": d,
        "verificationMethod": [_method(d, jwk, "a"), _method(d, jwk, "b")],
        "assertionMethod": [f"{d}#a"],
        "service": [{"id": f"{d}#s", "type": "X", "serviceEndpoint": "https://x.example/"}]})
    for doc in (_resolve(did, log), _resolve_async(did, log)):
        assert doc.id == did and doc.raw["id"] == did
        assert doc.raw["controller"] == did and doc.raw["service"][0]["id"] == f"{did}#s"
        assert [vm.id for vm in doc.verification_methods] == [f"{did}#a", f"{did}#b"]
        assert doc.relationships == {"assertionMethod": [f"{did}#a"]}


@pytest.mark.parametrize("name", ["basic-create", "key-rotation",
                                  "pre-rotation-consume", "multi-update"])
def test_every_golden_log_still_resolves_to_a_document_with_the_requested_id(name):
    text = (FIXTURES / f"{name}.jsonl").read_text()
    entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    assert all("didDocument" not in entry["state"] for entry in entries)
    did = entries[-1]["state"]["id"]
    for doc in (_resolve(did, text), _resolve_async(did, text)):
        assert doc.id == did
        assert doc.raw["id"] == did
        assert doc.verification_methods


# --------------------------------------------------------------------------- #
# 2. only the returned (last) state is looked at
# --------------------------------------------------------------------------- #

def _history(*states: Callable[[str, dict], dict]) -> tuple[str, str]:
    control = Controller()
    return _forge_webvh_log([lambda d, s=s: s(d, control.jwk) for s in states],
                            private=control.private)


def test_the_multi_entry_builder_makes_a_valid_chain():
    did, log = _history(_bare, _bare, _bare)
    assert len(log.splitlines()) == 3
    assert _resolve(did, log).id == did


def test_a_wrapper_in_an_earlier_state_is_not_looked_at():
    # intermediate states are never parsed, only checked by the log; refusing them would
    # reject a history the current document no longer carries
    did, log = _history(STATES[0], STATES[1], _bare)
    doc = _resolve(did, log)
    assert doc.id == did and [vm.id for vm in doc.verification_methods] == [f"{did}#k"]
    assert _resolve_async(did, log).id == did


@pytest.mark.parametrize("state_for", STATES, ids=IDS)
def test_a_wrapper_in_the_last_state_is_refused_after_a_clean_history(state_for):
    did, log = _history(_bare, _bare, state_for)
    with pytest.raises(DidWebvhError, match="didDocument") as exc:
        _resolve(did, log)
    assert type(exc.value) is DidWebvhError
    with pytest.raises(DidWebvhError, match="didDocument"):
        _resolve_async(did, log)


def _deactivated(*states: Callable[[str, dict], dict]) -> tuple[str, str]:
    control = Controller()
    return _forge_webvh_log([lambda d, s=s: s(d, control.jwk) for s in states],
                            private=control.private, deactivate_last=True)


def test_a_deactivated_log_with_a_bare_last_state_still_reports_the_deactivation():
    # control: the helper builds a log that really is deactivated, and the wrapper check does
    # not touch a bare state, so this keeps "is deactivated" and the row below proves ordering
    did, log = _deactivated(_bare, _bare)
    with pytest.raises(DidWebvhError, match="is deactivated") as exc:
        _resolve(did, log)
    assert type(exc.value) is DidWebvhError
    with pytest.raises(DidWebvhError, match="is deactivated"):
        _resolve_async(did, log)


@pytest.mark.parametrize("state_for", STATES, ids=IDS)
def test_a_deactivated_log_with_a_wrapped_last_state_reports_the_wrapper(state_for):
    # Ordering, as for the state `id` check that also comes first: the wrapper is refused
    # where the state is checked, before the `deactivated` flag. Both fail closed with the
    # same class; the message names the wrapper, not the deactivation.
    did, log = _deactivated(_bare, state_for)
    for resolve in (_resolve, _resolve_async):
        with pytest.raises(DidWebvhError, match="didDocument") as exc:
            resolve(did, log)
        assert type(exc.value) is DidWebvhError
        assert "deactivated" not in str(exc.value)


# --------------------------------------------------------------------------- #
# 3. defence in depth: the document the parser returns must be for the requested DID
# --------------------------------------------------------------------------- #

def _parser_returning(doc_id: str) -> Callable[[dict], DidDocument]:
    def parse(state: dict) -> DidDocument:
        real = parse_did_document(state)
        return DidDocument(id=doc_id, verification_methods=real.verification_methods,
                           raw=real.raw, relationships=real.relationships)
    return parse


def test_the_parsed_document_id_is_checked_too(monkeypatch):
    # With the wrapper refused the parsed id is the state's id, which was just compared, so
    # the second check cannot fire on its own; a parser that disagrees pins it.
    did, log = Controller().log(_bare)
    monkeypatch.setattr(webvh_module, "parse_did_document", _parser_returning(OTHER))
    with pytest.raises(DidWebvhError, match="!=") as exc:
        _resolve(did, log)
    assert type(exc.value) is DidWebvhError and OTHER in str(exc.value)
    with pytest.raises(DidWebvhError, match="!="):
        _resolve_async(did, log)
    # an empty id (what a non-string one reads as) never matches either
    monkeypatch.setattr(webvh_module, "parse_did_document", _parser_returning(""))
    with pytest.raises(DidWebvhError, match="!="):
        _resolve(did, log)


def test_the_parsed_document_id_check_passes_when_the_parser_agrees(monkeypatch):
    did, log = Controller().log(_bare)
    monkeypatch.setattr(webvh_module, "parse_did_document", _parser_returning(did))
    assert _resolve(did, log).id == did


def test_the_state_id_must_still_equal_the_requested_did():
    # unchanged: a log served for another DID, or whose state names another DID, is refused
    did, log = Controller().log(_bare)
    with pytest.raises(DidWebvhError, match="!="):
        _resolve("did:webvh:QmOther:" + HOST, log)
    other, other_log = Controller().log(lambda d, jwk: {**_bare(d, jwk), "id": OTHER})
    with pytest.raises(DidWebvhError, match="!="):
        _resolve(other, other_log)
    assert _resolve(did, log).id == did


# --------------------------------------------------------------------------- #
# 4. the pipeline: a credential whose issuer is a wrapped did:webvh fails typed
# --------------------------------------------------------------------------- #

def _scenario(state_for: Callable[[str, dict], dict], fragment: str):
    """The logs by URL (a wrapped DID and an honest neighbour on another host), and for each
    a VC-JWT and a Data Integrity credential signed by that log's own controller key with the
    method id ``<did>#<fragment>`` (the method the wrapper would expose)."""
    bad, good = Controller(), Controller()
    bad_did, bad_log = bad.log(state_for)
    good_did, good_log = good.log(_bare, host="good.example")
    logs = {_did_webvh_url(bad_did): bad_log, _did_webvh_url(good_did): good_log}
    bad_key, good_key = bad.key(f"{bad_did}#{fragment}"), good.key(f"{good_did}#k")
    return (logs, _vc_jwt(bad_key, bad_did), _di_credential(bad_key, bad_did),
            _vc_jwt(good_key, good_did), _di_credential(good_key, good_did), good_did)


@pytest.mark.parametrize("state_for,fragment", STATES_AND_FRAGMENTS, ids=IDS)
def test_the_credentials_verify_against_the_same_log_without_the_wrapper(state_for, fragment):
    # The same kind of tokens, signed by the controller key, against a log with the bare
    # state: they are good and the DID resolves, so the refusals below are the wrapper's
    # doing and not a malformed credential. (The row's fragment is the one it would use.)
    control = Controller()
    did, log = control.log(
        lambda d, jwk: {"id": d, "verificationMethod": [_method(d, jwk, fragment)]})
    logs = {_did_webvh_url(did): log}
    key = control.key(f"{did}#{fragment}")
    jwt, di = _vc_jwt(key, did), _di_credential(key, did)
    assert verify_credential(jwt, resolver=_registry(logs)).issuer == did
    assert verify_credential(di, resolver=_registry(logs)).issuer == did
    assert asyncio.run(verify_credential_async(jwt, resolver=_async_registry(logs))).issuer == did
    assert asyncio.run(verify_credential_async(di, resolver=_async_registry(logs))).issuer == did


@pytest.mark.parametrize("state_for,fragment", STATES_AND_FRAGMENTS, ids=IDS)
def test_a_credential_from_a_wrapped_did_fails_typed_on_every_lane(state_for, fragment):
    logs, jwt, di, _, _, _ = _scenario(state_for, fragment)

    # JOSE lane, sync: KeyResolutionFailed, caused by the resolver's refusal
    with pytest.raises(KeyResolutionFailed) as exc:
        verify_credential(jwt, resolver=_registry(logs))
    assert type(exc.value) is KeyResolutionFailed
    assert type(exc.value.__cause__) is DidWebvhError
    assert "didDocument" in str(exc.value.__cause__)

    # JOSE lane, async
    with pytest.raises(KeyResolutionFailed) as aexc:
        asyncio.run(verify_credential_async(jwt, resolver=_async_registry(logs)))
    assert type(aexc.value) is KeyResolutionFailed
    assert type(aexc.value.__cause__) is DidWebvhError

    # Data Integrity lane, sync: KeyResolutionError (a ProofError), as #251 pins
    with pytest.raises(KeyResolutionError) as dexc:
        verify_credential(di, resolver=_registry(logs))
    assert type(dexc.value) is KeyResolutionError
    assert not isinstance(dexc.value, KeyResolutionFailed)
    assert type(dexc.value.__cause__) is DidWebvhError

    # Data Integrity lane, async: KeyResolutionFailed
    with pytest.raises(KeyResolutionFailed) as adexc:
        asyncio.run(verify_credential_async(di, resolver=_async_registry(logs)))
    assert type(adexc.value) is KeyResolutionFailed
    assert type(adexc.value.__cause__) is DidWebvhError


@pytest.mark.parametrize("state_for,fragment", STATES_AND_FRAGMENTS, ids=IDS)
def test_verify_many_isolates_a_wrapped_did_and_the_neighbours_still_verify(
        state_for, fragment):
    logs, jwt, di, good_jwt, good_di, good_did = _scenario(state_for, fragment)
    batch = [good_jwt, jwt, good_di, di, good_jwt]
    none = type(None)

    results = verify_many(batch, resolver=_registry(logs))
    assert [r.ok for r in results] == [True, False, True, False, True]
    assert [type(r.error) for r in results] == [
        none, KeyResolutionFailed, none, KeyResolutionError, none]
    assert {r.result.issuer for r in results if r.ok} == {good_did}
    assert type(results[1].error.__cause__) is DidWebvhError
    assert type(results[3].error.__cause__) is DidWebvhError

    aresults = asyncio.run(verify_many_async(batch, resolver=_async_registry(logs)))
    assert [r.ok for r in aresults] == [True, False, True, False, True]
    assert [type(r.error) for r in aresults] == [
        none, KeyResolutionFailed, none, KeyResolutionFailed, none]
    assert {r.result.issuer for r in aresults if r.ok} == {good_did}
    assert type(aresults[1].error.__cause__) is DidWebvhError
    assert type(aresults[3].error.__cause__) is DidWebvhError


# --------------------------------------------------------------------------- #
# 5. what does not change: did:web and the EBSI registry keep the envelope
# --------------------------------------------------------------------------- #

WEB = "did:web:issuer.example"


def test_did_web_still_unwraps_a_didDocument_envelope():
    envelope = {"didDocument": {"id": WEB, "verificationMethod": [_method(WEB, Controller().jwk)]}}
    doc = DidWebResolver(fetch=lambda url: envelope).resolve(WEB)
    assert doc.id == WEB and [vm.id for vm in doc.verification_methods] == [f"{WEB}#k"]


def test_did_web_still_compares_the_unwrapped_id_with_the_requested_did():
    envelope = {"id": WEB, "didDocument": {
        "id": OTHER, "verificationMethod": [_method(OTHER, Controller().jwk)]}}
    with pytest.raises(DidResolutionError, match="!=") as exc:
        DidWebResolver(fetch=lambda url: envelope).resolve(WEB)
    assert type(exc.value) is DidResolutionError


def test_the_ebsi_registry_still_unwraps_an_envelope():
    pytest.importorskip("openvc_ebsi")
    from openvc.proof.vc_jwt import VcJwtProofSuite
    from openvc_ebsi.versioning import DidEbsiResolver

    ebsi = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"
    envelope = {"didDocument": {"id": ebsi, "verificationMethod": [
        _method(ebsi, Controller().jwk)]}}
    doc = DidEbsiResolver(lambda url: envelope,
                          decode_jwt=VcJwtProofSuite().peek_claims).resolve(ebsi)
    assert doc.id == ebsi and [vm.id for vm in doc.verification_methods] == [f"{ebsi}#k"]
    assert parse_did_document(envelope).id == ebsi
