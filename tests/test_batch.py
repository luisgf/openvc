"""
tests/test_batch.py — the batch verification API (issue #24).

`verify_many` verifies a list of credentials in one call, resolving each distinct issuer
DID / status list once (≈ O(distinct issuers), not O(credentials)) via the per-call caches
of :func:`openvc.cache.batch_resolvers`, while keeping **per-credential fail-closed**
semantics (one bad credential never aborts the others). The VP-JWT cascade reuses the same
dedup but stays fail-fast (a VP is valid only if *every* embedded credential is).

Dedup is proven by counting how often the underlying resolver / status fetch is reached.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import BatchResult, VerificationPolicy, verify_many
from openvc.cache import CachingDidResolver, batch_resolvers
from openvc.did.did_key import DidKeyResolver
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.status import encode_bitstring, set_status_bit

UTC = timezone.utc
VC2 = "https://www.w3.org/ns/credentials/v2"
STATUS_URL = "https://issuer.example/status/1"
NOW_2021 = datetime(2021, 1, 1, tzinfo=UTC)


# -- did:key + credential helpers ------------------------------------------- #

def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key(key) -> str:
    raw = base64.urlsafe_b64decode(key.public_jwk()["x"] + "==")
    return "did:key:" + encode_multibase(_leb128(0xED) + raw)


def _ed_key():
    """An Ed25519 signing key whose kid is its own resolvable did:key verificationMethod."""
    priv = ed25519.Ed25519PrivateKey.generate()
    did = _did_key(Ed25519SigningKey(priv, kid="tmp"))
    vm = f"{did}#{did[len('did:key:'):]}"
    return Ed25519SigningKey(priv, kid=vm), did, vm


def _credential(issuer_did: str, vm: str, key, subject="did:example:alice", status=None):
    cred: dict = {
        "@context": [VC2],
        "type": ["VerifiableCredential"],
        "issuer": issuer_did,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": subject},
    }
    if status is not None:
        cred["credentialStatus"] = status
    return EddsaJcsProofSuite().add_proof(cred, signing_key=key, verification_method=vm)


def _status_entry(index: str = "17") -> dict:
    return {
        "id": f"{STATUS_URL}#{index}",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": index,
        "statusListCredential": STATUS_URL,
    }


def _status_vc(*set_indices: int) -> dict:
    bits = bytearray(32)
    for i in set_indices:
        set_status_bit(bits, i, 1)
    return {
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "credentialSubject": {"statusPurpose": "revocation",
                              "encodedList": encode_bitstring(bytes(bits))},
    }


class _CountingResolver:
    """Wraps a real resolver and records every DID that reaches it."""

    def __init__(self, inner):
        self.inner = inner
        self.resolved: list[str] = []

    def supports(self, did):
        return self.inner.supports(did)

    def resolve(self, did):
        self.resolved.append(did)
        return self.inner.resolve(did)


def _policy(**kw):
    return VerificationPolicy(require_status=False, now=NOW_2021, **kw)


# --------------------------------------------------------------------------- #
# verify_many — dedup
# --------------------------------------------------------------------------- #

def test_batch_from_one_issuer_resolves_the_did_once():
    key, did, vm = _ed_key()
    creds = [_credential(did, vm, key, subject=f"did:example:{i}") for i in range(5)]
    counting = _CountingResolver(DidKeyResolver())

    results = verify_many(creds, resolver=counting, policy=_policy())

    assert all(r.ok for r in results) and len(results) == 5
    assert counting.resolved == [did]                    # one distinct issuer → one resolve


def test_batch_resolves_each_distinct_issuer_once():
    keys = [_ed_key() for _ in range(3)]
    # 2 credentials per issuer → 6 credentials, 3 distinct issuers
    creds = [_credential(did, vm, key, subject=f"did:example:{i}")
             for i, (key, did, vm) in enumerate(keys) for _ in range(2)]
    counting = _CountingResolver(DidKeyResolver())

    results = verify_many(creds, resolver=counting, policy=_policy())

    assert all(r.ok for r in results) and len(results) == 6
    assert sorted(counting.resolved) == sorted(did for _, did, _ in keys)   # 3, not 6


def test_batch_dedupes_shared_status_list_fetch():
    key, did, vm = _ed_key()
    entry = _status_entry("17")                          # index 17 unset → not revoked
    creds = [_credential(did, vm, key, subject=f"did:example:{i}", status=entry)
             for i in range(4)]
    calls: list[str] = []

    def resolve_status(url: str) -> dict:
        calls.append(url)
        return _status_vc()                              # nothing revoked

    results = verify_many(
        creds, resolver=DidKeyResolver(),
        resolve_status_list=resolve_status,
        policy=VerificationPolicy(now=NOW_2021))         # require_status defaults on
    assert all(r.ok for r in results)
    assert calls == [STATUS_URL]                         # fetched+verified once for all 4


# --------------------------------------------------------------------------- #
# verify_many — per-credential fail-closed
# --------------------------------------------------------------------------- #

def test_one_bad_credential_does_not_abort_the_batch():
    key, did, vm = _ed_key()
    good1 = _credential(did, vm, key, subject="did:example:a")
    tampered = _credential(did, vm, key, subject="did:example:b")
    tampered["credentialSubject"]["id"] = "did:example:MALLORY"      # break the signature
    good2 = _credential(did, vm, key, subject="did:example:c")
    garbage = "this-is-not-a-credential"

    results = verify_many([good1, tampered, good2, garbage],
                          resolver=_CountingResolver(DidKeyResolver()), policy=_policy())

    assert [r.ok for r in results] == [True, False, True, False]
    assert [r.index for r in results] == [0, 1, 2, 3]               # input order preserved
    assert results[0].result.subject == "did:example:a"
    assert results[2].result.subject == "did:example:c"
    from openvc.proof.errors import SignatureInvalid
    from openvc.verify import UnknownCredentialFormat
    assert isinstance(results[1].error, SignatureInvalid)          # tamper → fail-closed
    assert isinstance(results[3].error, UnknownCredentialFormat)   # garbage → fail-closed


def test_revoked_credential_is_reported_not_raised():
    key, did, vm = _ed_key()
    entry = _status_entry("17")
    cred = _credential(did, vm, key, status=entry)

    def resolve_status(url: str) -> dict:
        return _status_vc(17)                            # index 17 SET → revoked

    results = verify_many([cred], resolver=DidKeyResolver(),
                          resolve_status_list=resolve_status,
                          policy=VerificationPolicy(now=NOW_2021))
    from openvc.status import CredentialRevoked
    assert results[0].ok is False
    assert isinstance(results[0].error, CredentialRevoked)


def test_empty_batch_returns_empty_list():
    assert verify_many([], resolver=DidKeyResolver()) == []


def test_verify_many_is_fail_closed_on_hostile_inputs():
    """Every non-credential input becomes a fail-closed BatchResult and never aborts the
    batch — the whole call completes, returning one result per input."""
    from openvc.errors import OpenvcError
    weird = [None, 42, b"bytes", {}, [], "", "not.a.jwt"]
    results = verify_many(weird, resolver=DidKeyResolver())
    assert len(results) == len(weird)
    assert all((not r.ok) and isinstance(r.error, OpenvcError) for r in results)


@pytest.mark.parametrize("hostile_type", [[{"x": 1}], 5, {"nested": "obj"}],
                         ids=["unhashable-member", "non-iterable", "dict"])
def test_verify_many_survives_hostile_status_shape(hostile_type):
    """A signed credential whose credentialStatus.type is a hostile shape (a list with an
    unhashable member, a non-iterable, ...) must not crash the batch with a bare TypeError —
    the entry is skipped like any unrecognized type and the batch completes. Regression for
    the fail-closed escape found in adversarial review."""
    key, did, vm = _ed_key()
    good = _credential(did, vm, key, subject="did:example:a")
    bad = _credential(did, vm, key, subject="did:example:b",
                      status={"type": hostile_type, "statusListIndex": "0",
                              "statusListCredential": STATUS_URL})
    results = verify_many([good, bad], resolver=DidKeyResolver(), policy=_policy())
    assert [r.ok for r in results] == [True, True]      # completed; hostile status skipped


def test_batch_result_shape():
    key, did, vm = _ed_key()
    [ok] = verify_many([_credential(did, vm, key)],
                       resolver=DidKeyResolver(), policy=_policy())
    assert isinstance(ok, BatchResult)
    assert ok.ok and ok.index == 0 and ok.error is None and ok.result.issuer == did


def test_verify_many_defaults_resolver_when_none():
    key, did, vm = _ed_key()                             # did:key resolves offline by default
    [r] = verify_many([_credential(did, vm, key)], policy=_policy())
    assert r.ok and r.result.issuer == did


# --------------------------------------------------------------------------- #
# batch_resolvers — the shared per-call dedup factory
# --------------------------------------------------------------------------- #

def test_batch_resolvers_wraps_resolver_and_keeps_none():
    inner = DidKeyResolver()
    shared = batch_resolvers(inner)
    assert isinstance(shared["resolver"], CachingDidResolver)
    # a callable left unset stays None (splat-safe into verify_credential)
    assert shared["resolve_status_list"] is None
    assert shared["resolve_credential_schema"] is None


def test_batch_resolvers_memoizes_provided_callables():
    calls: list[str] = []

    def fetch(url: str) -> dict:
        calls.append(url)
        return {"u": url}

    shared = batch_resolvers(DidKeyResolver(), resolve_status_list=fetch)
    wrapped = shared["resolve_status_list"]
    assert wrapped("u1") == {"u": "u1"}
    assert wrapped("u1") == {"u": "u1"}
    assert calls == ["u1"]                               # deduped within the batch


# --------------------------------------------------------------------------- #
# VP-JWT cascade — reuses the dedup, stays fail-fast
# --------------------------------------------------------------------------- #

def _vp(embedded, holder_key, audience="https://verifier.example", nonce="n-123"):
    return VpJwtProofSuite().sign(embedded, holder_key=holder_key, audience=audience, nonce=nonce)


def test_vp_cascade_resolves_shared_issuer_did_once():
    ikey, idid, ivm = _ed_key()
    hkey, hdid, _ = _ed_key()
    embedded = [_credential(idid, ivm, ikey, subject=f"did:example:{i}") for i in range(5)]
    vp = _vp(embedded, hkey)
    counting = _CountingResolver(DidKeyResolver())

    result = VpJwtProofSuite().verify(
        vp, audience="https://verifier.example", nonce="n-123", resolver=counting,
        policy=_policy())
    assert len(result.credentials) == 5
    # holder resolved once (before the cascade), issuer resolved once for all 5 embedded VCs
    assert counting.resolved.count(idid) == 1
    assert counting.resolved.count(hdid) == 1


def test_vp_cascade_stays_fail_fast_on_a_bad_embedded_credential():
    from openvc.proof.vp_jwt import ClaimsInvalid
    ikey, idid, ivm = _ed_key()
    hkey, _, _ = _ed_key()
    good = _credential(idid, ivm, ikey, subject="did:example:a")
    bad = _credential(idid, ivm, ikey, subject="did:example:b")
    bad["credentialSubject"]["id"] = "did:example:MALLORY"          # break its signature
    vp = _vp([good, bad], hkey)

    from openvc.proof.errors import SignatureInvalid
    with pytest.raises((SignatureInvalid, ClaimsInvalid)):          # whole VP rejected
        VpJwtProofSuite().verify(
            vp, audience="https://verifier.example", nonce="n-123",
            resolver=DidKeyResolver(), policy=_policy())
