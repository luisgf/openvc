"""
tests/test_did_webvh.py — the did:webvh resolver (``openvc.did.did_webvh``, issue #68).

Conformance is pinned against **real golden vectors** recorded from the reference Rust
implementation (``decentralized-identity/didwebvh-rs`` test suite, v1.0) — genesis, key
rotation, pre-rotation consumption, multi-update and deactivation logs — so the SCID,
entryHash chain, pre-rotation and ``eddsa-jcs-2022`` proof maths are held to what other
implementations produce, not to shapes this resolver also generates. The negative paths
tamper those real logs and assert the resolver fails **closed**.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openvc.did.base import DidResolutionError, multikey_to_jwk
from openvc.did.did_webvh import DidWebvhError, DidWebvhResolver, _did_webvh_url

FIXTURES = Path(__file__).parent / "fixtures" / "didwebvh"


def _log(name: str) -> str:
    return (FIXTURES / f"{name}.jsonl").read_text()


def _entries(name: str) -> list[dict]:
    return [json.loads(line) for line in _log(name).splitlines() if line.strip()]


def _did(name: str) -> str:
    return _entries(name)[-1]["state"]["id"]


def _resolver(log_text: str) -> DidWebvhResolver:
    # The resolver derives the URL and calls the fetch; the stub ignores the URL and
    # returns the (possibly tampered) log text.
    return DidWebvhResolver(fetch=lambda _url: log_text)


def test_scid_replace_is_depth_bounded():
    """A did:webvh genesis entry nested past the SCID-replace depth bound fails closed as
    a typed DidWebvhError, never a bare RecursionError — which (via the untrusted resolve
    path) would escape verify_many's per-credential isolation and abort the batch
    (adversarial re-review of #117)."""
    from openvc.did.did_webvh import _deep_replace_scid
    deep: dict = {}
    node = deep
    for _ in range(300):                 # > _MAX_SCID_DEPTH (100), < the interpreter limit
        node["a"] = {}
        node = node["a"]
    with pytest.raises(DidWebvhError):
        _deep_replace_scid(deep, "some-scid")


# --------------------------------------------------------------------------- #
# identifier -> URL
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did,url", [
    ("did:webvh:QmSCID:example.com",
     "https://example.com/.well-known/did.jsonl"),
    ("did:webvh:QmSCID:example.com:issuers:1",
     "https://example.com/issuers/1/did.jsonl"),
    ("did:webvh:QmSCID:example.com%3A3000:dids",
     "https://example.com:3000/dids/did.jsonl"),
])
def test_did_to_url(did, url):
    assert _did_webvh_url(did) == url


def test_did_to_url_rejects_missing_parts():
    with pytest.raises(DidWebvhError):
        _did_webvh_url("did:webvh:QmSCIDonly")        # no domain after the SCID


# --------------------------------------------------------------------------- #
# positive: replay the real golden vectors
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ["basic-create", "key-rotation",
                                  "pre-rotation-consume", "multi-update"])
def test_resolves_golden_vector(name):
    doc = _resolver(_log(name)).resolve(_did(name))
    assert doc.id == _did(name)
    assert doc.verification_methods, "resolved document has no verification methods"
    # every VM key decoded to a usable JWK (did:webvh v1.0 keys are Ed25519 Multikeys)
    assert doc.verification_methods[0].public_key_jwk["kty"] == "OKP"


def test_resolver_supports_predicate():
    r = _resolver("")
    assert r.supports("did:webvh:QmX:example.com")
    assert not r.supports("did:web:example.com")
    assert not r.supports("did:key:z6Mk")


def test_key_rotation_active_key_is_the_previous_entrys():
    # In key-rotation the second entry rotates to a new key but is authorized by the
    # PREVIOUS entry's key (no pre-rotation). If the resolver used the wrong "active"
    # key set the proof check would fail — resolving proves it used the right one.
    doc = _resolver(_log("key-rotation")).resolve(_did("key-rotation"))
    assert doc.id.endswith(":example.com")


# --------------------------------------------------------------------------- #
# negative: tamper the real logs; every check must fail closed
# --------------------------------------------------------------------------- #

def _tamper(name: str, index: int, mutate) -> str:
    entries = _entries(name)
    mutate(entries[index])
    return "\n".join(json.dumps(e) for e in entries)


def test_deactivated_did_fails_closed():
    # A valid log that ends in deactivation must not hand back usable keys.
    with pytest.raises(DidWebvhError, match="deactivated"):
        _resolver(_log("deactivate")).resolve(_did("deactivate"))


def test_tampered_document_breaks_the_entry_hash():
    # Mutating the signed state (the DID document) invalidates the entryHash chain.
    did = _did("basic-create")
    log = _tamper("basic-create", 0,
                  lambda e: e["state"].__setitem__("controller", "did:webvh:evil:example.com"))
    with pytest.raises(DidWebvhError):
        _resolver(log).resolve(did)


def test_tampered_proof_value_fails():
    # Corrupt the proofValue -> the eddsa-jcs-2022 signature no longer verifies.
    did = _did("basic-create")

    def corrupt(e):
        pv = e["proof"][0]["proofValue"]
        e["proof"][0]["proofValue"] = pv[:-4] + ("aaaa" if not pv.endswith("aaaa") else "bbbb")
    with pytest.raises(DidWebvhError):
        _resolver(_tamper("basic-create", 0, corrupt)).resolve(did)


def test_forged_scid_fails():
    # Changing the SCID (in parameters and the DID) must fail the genesis SCID check.
    entries = _entries("basic-create")
    good = entries[0]["parameters"]["scid"]
    forged = good[:-3] + ("xyz" if not good.endswith("xyz") else "abc")
    log = _log("basic-create").replace(good, forged)
    with pytest.raises(DidWebvhError):
        _resolver(log).resolve(_did("basic-create").replace(good, forged))


def test_wrong_version_number_breaks_the_chain():
    did = _did("key-rotation")
    # renumber the second entry 2 -> 3: the version sequence must increment by one.
    log = _tamper("key-rotation", 1,
                  lambda e: e.__setitem__("versionId", "3-" + e["versionId"].split("-", 1)[1]))
    with pytest.raises(DidWebvhError):
        _resolver(log).resolve(did)


def test_dropped_entry_breaks_the_chain():
    # Remove the genesis entry: the remaining entry is no longer version 1 and its
    # predecessor hash no longer matches.
    entries = _entries("key-rotation")
    log = json.dumps(entries[1])
    with pytest.raises(DidWebvhError):
        _resolver(log).resolve(_did("key-rotation"))


def test_proof_by_unauthorized_key_fails():
    # Re-point the genesis proof at a different (valid did:key) verificationMethod not in
    # updateKeys: the key is no longer authorized, so no proof survives.
    did = _did("basic-create")
    other = "did:key:z6Mkt5S2GjnMWCEuof9Wc7bQ7dPu2nZ8jVvXtq8x2xY9WcaZ"
    vm = other + "#" + other[len("did:key:"):]
    log = _tamper("basic-create", 0,
                  lambda e: e["proof"][0].__setitem__("verificationMethod", vm))
    with pytest.raises(DidWebvhError):
        _resolver(log).resolve(did)


@pytest.mark.parametrize("bad", ["", "not json\n", '"a string"\n', "{}\n", "[]\n"])
def test_malformed_log_fails_closed(bad):
    with pytest.raises(DidResolutionError):
        _resolver(bad).resolve("did:webvh:QmX:example.com")


def test_document_id_must_match_requested_did():
    with pytest.raises(DidWebvhError, match="!="):
        _resolver(_log("basic-create")).resolve("did:webvh:QmX:other.example")


def test_witness_policy_fails_closed():
    # A real witnessed log (the didwebvh-rs witness-threshold vector) declares a witness
    # threshold. openvc does not verify witness co-signatures, so it must REFUSE rather
    # than silently downgrade to the un-witnessed trust model (adversarial-review MED-1).
    with pytest.raises(DidWebvhError, match="witness"):
        _resolver(_log("witness-threshold")).resolve(_did("witness-threshold"))


@pytest.mark.parametrize("witness", [
    {"threshold": 1},                          # the plain integer case
    {"threshold": 1.5},                        # float — used to bypass the int-only gate
    {"threshold": "1"},                        # string — likewise
    {"threshold": True},                       # bool truthy
    {"witnesses": [{"id": "did:key:zW"}]},     # a witnesses list with no threshold at all
    {"threshold": 2, "witnesses": [{"id": "did:key:zW"}]},
], ids=["int", "float", "string", "bool", "witnesses-no-threshold", "both"])
def test_witness_policy_active_closes_every_shape(witness):
    """#100: an active witness policy must be recognised regardless of the threshold's
    type — a float/string threshold or a bare witnesses list used to slip past the
    integer-only gate and silently downgrade trust."""
    from openvc.did.did_webvh import _witness_policy_active
    assert _witness_policy_active(witness) is True


@pytest.mark.parametrize("witness", [
    {}, None, "nonsense", {"threshold": 0}, {"threshold": False}, {"witnesses": []},
], ids=["empty", "none", "not-a-dict", "threshold-0", "threshold-false", "empty-witnesses"])
def test_witness_policy_inactive_still_resolves(witness):
    """No policy (absent, empty, or explicitly disabled) must NOT trigger the refusal."""
    from openvc.did.did_webvh import _witness_policy_active
    assert _witness_policy_active(witness) is False


def test_non_string_updatekey_fails_closed():
    # A non-string updateKeys element must fail closed, not crash _prerotation_hash with a
    # bare AttributeError before the entryHash/proof checks (adversarial-review LOW-1).
    did = _did("pre-rotation-consume")
    log = _tamper("pre-rotation-consume", 1,
                  lambda e: e["parameters"].__setitem__("updateKeys", [123]))
    with pytest.raises(DidWebvhError):
        _resolver(log).resolve(did)


# --------------------------------------------------------------------------- #
# Multikey -> JWK (the parse_did_document extension did:webvh needs)
# --------------------------------------------------------------------------- #

def test_multikey_to_jwk_ed25519():
    jwk = multikey_to_jwk("z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG")
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and "x" in jwk


def test_multikey_to_jwk_rejects_unknown_codec():
    with pytest.raises((ValueError, Exception)):
        multikey_to_jwk("z" + "1" * 20)               # not a known multicodec key
