"""
tests/test_did_webvh_scid_binding.py — the SCID of the requested ``did:webvh`` DID is bound
to the log it resolves from (#376).

did:webvh v1.0, "Reading did:webvh DID URLs": the SCID segment of the requested DID MUST
equal ``parameters.scid`` of the first log entry and the SCID segment of ``state.id`` in
every entry, and only a well-formed SCID is accepted. The genesis check compares the log's
declared SCID with the hash of the log's own genesis entry, so a log is self-consistent
under *its* SCID; what this file pins is that the log must also be the one the *requested*
DID commits to — the resolver anchors the whole replay on the DID's SCID, compares the
log's own value with it and never uses the log's in its place — and that the identifier is
checked, typed, before any fetch, by the sync and the async resolver alike.

Negatives first. The log builder is a copy of the one in
``test_did_webvh_state_envelope.py`` (``tests/`` is not a package) that lets the genesis
state name any DID: it mints a log that is valid on every other count — a SCID derived
from its own genesis, the entryHash chain, an ``eddsa-jcs-2022`` proof by its own
``updateKey`` — so a refusal below is the binding's doing. The same key signs the
credentials, and a control log with the honest ``id`` resolves and verifies on every lane.

Every assertion is on the exact class: ``DidWebvhError`` from the resolver,
``KeyResolutionFailed`` on the JOSE lanes, ``KeyResolutionError`` (a ``ProofError`` and a
``KeyResolutionFailed``) on the Data Integrity lanes, sync and async alike (#283).
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

from openvc import verify_credential, verify_many, verify_many_async
from openvc.aio import verify_credential_async
from openvc.did.base import AsyncDidResolverRegistry, DidResolverRegistry
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
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.verify import KeyResolutionFailed

V2 = "https://www.w3.org/ns/credentials/v2"
HOST = "victim.example"
FIXTURES = Path(__file__).parent / "fixtures" / "didwebvh"
# The SCID a relying party knows for the victim's DID on that host: any well-formed SCID
# the hostile log did not derive from its own genesis (here the one of a didwebvh-rs golden
# vector, so it has the shape of a real SCID).
VICTIM_SCID = "Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg"
VICTIM_DID = f"did:webvh:{VICTIM_SCID}:{HOST}"
MESSAGE_BOUND = 400


# --------------------------------------------------------------------------- #
# a signed did:webvh log builder whose genesis state names any DID
# --------------------------------------------------------------------------- #

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Controller:
    """The key a log is signed with. The same key signs the credentials below."""

    def __init__(self) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.jwk = Ed25519SigningKey(self.private, kid="_").public_jwk()
        self.multikey = encode_multibase(
            bytes([0xED, 0x01]) + base64.urlsafe_b64decode(self.jwk["x"] + "=="))

    def key(self, kid: str) -> Ed25519SigningKey:
        return Ed25519SigningKey(self.private, kid=kid)

    def state(self, did: str) -> dict:
        return {"id": did, "verificationMethod": [
            {"id": f"{did}#k", "type": "JsonWebKey2020", "controller": did,
             "publicKeyJwk": self.jwk}], "assertionMethod": [f"{did}#k"]}

    def log(self, states_for: list[Callable[[str], dict]], host: str = HOST,
            deactivate_last: bool = False) -> tuple[str, str]:
        """A valid did:webvh log with one entry per element of *states_for*, signed by this
        controller's key as its only ``updateKey``. ``states_for[0]`` is handed the DID
        with the ``{SCID}`` placeholder — an honest state puts it in ``id`` and the
        substitution turns it into the log's own DID; a hostile one writes whatever DID it
        likes — and the later ones the log's own DID. *deactivate_last* sets ``deactivated``
        in the parameters of the last of two or more entries. Returns ``(did, did.jsonl)``
        where *did* is the DID the log's own SCID spells."""
        signer = Ed25519SigningKey(self.private, kid="_")
        proof_options = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                         "verificationMethod": f"did:key:{self.multikey}#{self.multikey}",
                         "created": "2026-01-01T00:00:00Z", "proofPurpose": "assertionMethod"}

        def sign(entry: dict) -> dict:
            hash_data = hashlib.sha256(_jcs(proof_options)).digest() \
                + hashlib.sha256(_jcs(entry)).digest()
            return {**entry, "proof": [{**proof_options,
                                        "proofValue": encode_multibase(signer.sign(hash_data))}]}

        template = {"versionId": "{SCID}", "versionTime": "2026-01-01T00:00:00Z",
                    "parameters": {"method": "did:webvh:1.0", "scid": "{SCID}",
                                   "updateKeys": [self.multikey]},
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


def _hijack(controller: Controller) -> tuple[str, str]:
    """The log of the report: self-consistent under its own SCID, its genesis state naming
    the victim's DID. Returns ``(the log's own did, did.jsonl)``."""
    return controller.log([lambda _placeholder: controller.state(VICTIM_DID)])


def _honest(controller: Controller) -> tuple[str, str]:
    return controller.log([controller.state])


class _Fetch:
    """A fetch that records every URL it is asked for and serves *text*."""

    def __init__(self, text: str = "") -> None:
        self.text, self.calls = text, []

    def __call__(self, url: str) -> str:
        self.calls.append(url)
        return self.text

    async def aio(self, url: str) -> str:
        self.calls.append(url)
        return self.text


def _resolve(did: str, log: str) -> Any:
    return DidWebvhResolver(fetch=_Fetch(log)).resolve(did)


def _resolve_async(did: str, log: str) -> Any:
    return asyncio.run(AsyncDidWebvhResolver(fetch=_Fetch(log).aio).resolve(did))


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


def _sd_jwt_vc(key: Ed25519SigningKey, did: str) -> str:
    """An SD-JWT VC for issuer *did*, signed by *key* (``kid`` = ``key.kid``)."""
    return SdJwtVcProofSuite().issue(
        {"iss": did, "sub": "did:example:s", "degree": "x"},
        signing_key=key, vct="https://credentials.example/degree")


def _registry(logs: dict[str, str]) -> DidResolverRegistry:
    return DidResolverRegistry([DidWebvhResolver(fetch=lambda url: logs[url])])


def _async_registry(logs: dict[str, str]) -> AsyncDidResolverRegistry:
    async def fetch(url: str) -> str:
        return logs[url]
    return AsyncDidResolverRegistry([AsyncDidWebvhResolver(fetch=fetch)])


def _golden(name: str) -> tuple[str, str, str]:
    """``(did, did.jsonl, genesis scid)`` of a didwebvh-rs golden vector."""
    text = (FIXTURES / f"{name}.jsonl").read_text()
    entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    return entries[-1]["state"]["id"], text, entries[0]["parameters"]["scid"]


# --------------------------------------------------------------------------- #
# 1. the report: a self-consistent log under another SCID resolves nothing but its own DID
# --------------------------------------------------------------------------- #

def test_a_log_under_another_scid_does_not_resolve_the_requested_did():
    own_did, log = _hijack(Controller())
    assert own_did != VICTIM_DID and json.loads(log.splitlines()[0])["state"]["id"] == VICTIM_DID

    for resolve in (_resolve, _resolve_async):
        with pytest.raises(DidWebvhError) as exc:
            resolve(VICTIM_DID, log)
        assert type(exc.value) is DidWebvhError
        message = str(exc.value)
        assert "genesis SCID" in message and "!=" in message
        assert VICTIM_SCID in message and len(message) < MESSAGE_BOUND

    # and not under its own DID either: the state names the victim, not the log's own DID
    for resolve in (_resolve, _resolve_async):
        with pytest.raises(DidWebvhError, match="!="):
            resolve(own_did, log)


def test_a_golden_log_does_not_resolve_another_well_formed_scid_of_its_host():
    # same host, another well-formed SCID (the goldens all share one genesis, so a fresh
    # log's): refused at the genesis, before the state
    did, log, scid = _golden("basic-create")
    other_scid = _honest(Controller())[0].split(":")[2]
    assert other_scid != scid
    other = did.replace(scid, other_scid)
    for resolve in (_resolve, _resolve_async):
        with pytest.raises(DidWebvhError, match="genesis SCID") as exc:
            resolve(other, log)
        assert type(exc.value) is DidWebvhError


@pytest.mark.parametrize("bad_id_for", [
    pytest.param(lambda did: VICTIM_DID, id="another-scid"),
    pytest.param(lambda did: did.replace("did:webvh:", "DID:WEBVH:", 1), id="upper-case-method"),
    pytest.param(lambda did: did.replace("did:webvh:", "did:web:", 1), id="did-web-same-segment"),
])
def test_every_state_must_carry_the_requested_scid(bad_id_for):
    # a three-entry log, valid on every other count, whose SECOND state names another SCID,
    # or carries the right SCID as the third segment of a string that is not a did:webvh
    # (another method, another case); the final state is honest, so the unchanged last-state
    # comparison would pass and only the per-entry rule refuses it, naming the entry
    controller = Controller()
    did, log = controller.log([controller.state,
                               lambda did: controller.state(bad_id_for(did)),
                               controller.state])
    assert json.loads(log.splitlines()[-1])["state"]["id"] == did
    for resolve in (_resolve, _resolve_async):
        with pytest.raises(DidWebvhError, match=r"entry 2: .*!=") as exc:
            resolve(did, log)
        assert type(exc.value) is DidWebvhError
        assert len(str(exc.value)) < MESSAGE_BOUND


@pytest.mark.parametrize("state_id_for", [
    pytest.param(lambda placeholder: placeholder.replace(HOST, "other.example"), id="other-host"),
    pytest.param(lambda placeholder: placeholder + ":" + "a" * 100_000, id="100000-chars"),
])
def test_the_final_state_must_still_equal_the_requested_did(state_id_for):
    # the same SCID under another host, or under a 100 000-character path, in the genesis
    # state: the SCID rules pass, the unchanged full-DID comparison on the last state refuses
    # it, and the message cuts the self-signed id (a host-controlled value) by safe_repr
    controller = Controller()
    did, log = controller.log([lambda placeholder: controller.state(state_id_for(placeholder))])
    for resolve in (_resolve, _resolve_async):
        with pytest.raises(DidWebvhError, match="!=") as exc:
            resolve(did, log)
        assert type(exc.value) is DidWebvhError and "genesis SCID" not in str(exc.value)
        assert len(str(exc.value)) < MESSAGE_BOUND


def test_the_deactivated_refusal_is_bounded_too():
    # a deactivated log for a DID with a 100 000-character path, replayed directly (the URL
    # mapping is not what bounds the message): the refusal names the DID cut by safe_repr
    controller = Controller()
    did, log = controller.log([controller.state, controller.state],
                              host=HOST + ":" + "a" * 100_000, deactivate_last=True)
    with pytest.raises(DidWebvhError, match="deactivated") as exc:
        DidWebvhResolver(fetch=_Fetch(log))._replay(did, log)
    assert type(exc.value) is DidWebvhError and len(str(exc.value)) < MESSAGE_BOUND


# --------------------------------------------------------------------------- #
# 2. a malformed SCID segment is refused, typed, before any fetch
# --------------------------------------------------------------------------- #

MALFORMED = [
    pytest.param(f"did:webvh:not-a-hash:{HOST}", id="separator"),
    pytest.param(f"did:webvh::{HOST}", id="empty"),
    pytest.param("did:webvh:" + "Q" * 70_000 + f":{HOST}", id="70000-chars"),
    pytest.param("did:webvh:" + "Q" * 129 + f":{HOST}", id="129-chars"),
    pytest.param(f"did:webvh:0OIl:{HOST}", id="excluded-base58-characters"),
    pytest.param(f"did:webvh:Qmé:{HOST}", id="non-ascii"),
    pytest.param(f"did:webvh:Qm\ud800:{HOST}", id="lone-surrogate"),
    pytest.param(f"did:webvh:Qm X:{HOST}", id="space"),
]


@pytest.mark.parametrize("did", MALFORMED)
def test_a_malformed_scid_segment_is_refused_before_any_fetch(did):
    with pytest.raises(DidWebvhError) as url_exc:
        _did_webvh_url(did)
    assert type(url_exc.value) is DidWebvhError and len(str(url_exc.value)) < MESSAGE_BOUND

    fetch = _Fetch(_honest(Controller())[1])      # a valid log, were it ever fetched
    with pytest.raises(DidWebvhError) as exc:
        DidWebvhResolver(fetch=fetch).resolve(did)
    assert type(exc.value) is DidWebvhError
    assert len(str(exc.value)) < MESSAGE_BOUND
    with pytest.raises(DidWebvhError) as aexc:
        asyncio.run(AsyncDidWebvhResolver(fetch=fetch.aio).resolve(did))
    assert type(aexc.value) is DidWebvhError
    assert len(str(aexc.value)) < MESSAGE_BOUND
    assert fetch.calls == []

    # the replay holds the same contract for a direct caller, whatever log it is handed
    with pytest.raises(DidWebvhError) as rexc:
        DidWebvhResolver(fetch=fetch)._replay(did, fetch.text)
    assert type(rexc.value) is DidWebvhError and len(str(rexc.value)) < MESSAGE_BOUND
    # the replay checks the shape itself (anchoring it on the unchecked segment would pass
    # every other test here): the message is the shape check's, not a downstream one. (The
    # resolvers' own message for the empty segment is the URL mapping's structural one.)
    assert "base58btc" in str(rexc.value)


@pytest.mark.parametrize("did", MALFORMED)
def test_a_malformed_scid_segment_fails_typed_through_the_pipeline_without_a_fetch(did):
    fetch = _Fetch(_honest(Controller())[1])
    token = _vc_jwt(Controller().key(f"{did}#k"), did)
    with pytest.raises(KeyResolutionFailed) as exc:
        verify_credential(token, resolver=DidResolverRegistry([DidWebvhResolver(fetch=fetch)]))
    assert type(exc.value) is KeyResolutionFailed
    assert type(exc.value.__cause__) is DidWebvhError
    assert len(str(exc.value)) < 2 * MESSAGE_BOUND
    with pytest.raises(KeyResolutionFailed) as aexc:
        asyncio.run(verify_credential_async(
            token, resolver=AsyncDidResolverRegistry([AsyncDidWebvhResolver(fetch=fetch.aio)])))
    assert type(aexc.value) is KeyResolutionFailed
    assert fetch.calls == []


def test_scid_of_accepts_the_well_formed_and_refuses_the_boundary():
    from openvc.did.did_webvh import _scid_of       # local: the module collects on main too
    for name in ("basic-create", "key-rotation", "pre-rotation-consume", "multi-update",
                 "deactivate", "witness-threshold"):
        did, _, scid = _golden(name)
        assert _scid_of(did) == scid
    assert _scid_of("did:webvh:" + "Q" * 128 + f":{HOST}") == "Q" * 128
    with pytest.raises(DidWebvhError):
        _scid_of("did:webvh:" + "Q" * 129 + f":{HOST}")
    with pytest.raises(DidWebvhError):
        _scid_of(f"did:webvh::{HOST}")
    with pytest.raises(DidWebvhError):
        _scid_of("did:web:example.com")          # not a did:webvh at all


# --------------------------------------------------------------------------- #
# 3. the pipeline: the hostile log served at the victim's path, on every lane
# --------------------------------------------------------------------------- #

def _scenario():
    """The hostile log served at the victim DID's ``did.jsonl`` URL and an honest neighbour
    on another host; for each a VC-JWT, a Data Integrity credential and an SD-JWT VC signed
    by that log's own controller key with the method id ``<did>#k``."""
    bad, good = Controller(), Controller()
    _, bad_log = _hijack(bad)
    good_did, good_log = good.log([good.state], host="good.example")
    logs = {_did_webvh_url(VICTIM_DID): bad_log, _did_webvh_url(good_did): good_log}
    bad_key, good_key = bad.key(f"{VICTIM_DID}#k"), good.key(f"{good_did}#k")
    return (logs,
            _vc_jwt(bad_key, VICTIM_DID), _di_credential(bad_key, VICTIM_DID),
            _sd_jwt_vc(bad_key, VICTIM_DID),
            _vc_jwt(good_key, good_did), _di_credential(good_key, good_did),
            _sd_jwt_vc(good_key, good_did), good_did)


def test_the_control_log_resolves_and_its_credentials_verify_on_every_lane():
    # The same kind of tokens, signed by the controller key, against the log with the honest
    # id: the DID resolves and they verify, so the refusals below are the binding's doing
    # and not a malformed credential or log.
    control = Controller()
    did, log = _honest(control)
    assert _resolve(did, log).id == did and _resolve_async(did, log).id == did
    logs = {_did_webvh_url(did): log}
    key = control.key(f"{did}#k")
    jwt, di, sd = _vc_jwt(key, did), _di_credential(key, did), _sd_jwt_vc(key, did)
    assert verify_credential(jwt, resolver=_registry(logs)).issuer == did
    assert verify_credential(di, resolver=_registry(logs)).issuer == did
    assert verify_credential(sd, resolver=_registry(logs)).issuer == did
    assert asyncio.run(verify_credential_async(jwt, resolver=_async_registry(logs))).issuer == did
    assert asyncio.run(verify_credential_async(di, resolver=_async_registry(logs))).issuer == did
    assert asyncio.run(verify_credential_async(sd, resolver=_async_registry(logs))).issuer == did


def test_a_credential_from_the_hijacked_did_fails_typed_on_every_lane():
    logs, jwt, di, sd, _, _, _, _ = _scenario()

    # JOSE lanes, sync: KeyResolutionFailed, caused by the resolver's refusal
    for token in (jwt, sd):
        with pytest.raises(KeyResolutionFailed) as exc:
            verify_credential(token, resolver=_registry(logs))
        assert type(exc.value) is KeyResolutionFailed
        assert type(exc.value.__cause__) is DidWebvhError
        assert "genesis SCID" in str(exc.value.__cause__)

    # JOSE lanes, async
    for token in (jwt, sd):
        with pytest.raises(KeyResolutionFailed) as aexc:
            asyncio.run(verify_credential_async(token, resolver=_async_registry(logs)))
        assert type(aexc.value) is KeyResolutionFailed
        assert type(aexc.value.__cause__) is DidWebvhError

    # Data Integrity lane, sync: KeyResolutionError, a ProofError and a KeyResolutionFailed
    with pytest.raises(KeyResolutionError) as dexc:
        verify_credential(di, resolver=_registry(logs))
    assert type(dexc.value) is KeyResolutionError
    assert isinstance(dexc.value, KeyResolutionFailed)
    assert type(dexc.value.__cause__) is DidWebvhError

    # Data Integrity lane, async: the same class as the sync lane (#283)
    with pytest.raises(KeyResolutionError) as adexc:
        asyncio.run(verify_credential_async(di, resolver=_async_registry(logs)))
    assert type(adexc.value) is KeyResolutionError
    assert isinstance(adexc.value, KeyResolutionFailed)
    assert type(adexc.value.__cause__) is DidWebvhError


def test_verify_many_isolates_the_hijacked_did_and_the_neighbours_still_verify():
    logs, jwt, di, sd, good_jwt, good_di, good_sd, good_did = _scenario()
    batch = [good_jwt, jwt, good_di, di, good_sd, sd]
    none = type(None)
    expected = [none, KeyResolutionFailed, none, KeyResolutionError, none, KeyResolutionFailed]

    results = verify_many(batch, resolver=_registry(logs))
    assert [r.ok for r in results] == [True, False, True, False, True, False]
    assert [type(r.error) for r in results] == expected
    assert {r.result.issuer for r in results if r.ok} == {good_did}
    assert all(type(r.error.__cause__) is DidWebvhError for r in results if not r.ok)

    aresults = asyncio.run(verify_many_async(batch, resolver=_async_registry(logs)))
    assert [r.ok for r in aresults] == [True, False, True, False, True, False]
    assert [type(r.error) for r in aresults] == expected
    assert {r.result.issuer for r in aresults if r.ok} == {good_did}
    assert all(type(r.error.__cause__) is DidWebvhError for r in aresults if not r.ok)
