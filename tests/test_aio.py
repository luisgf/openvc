"""
tests/test_aio.py — the async verification surface (``openvc.aio``).

pytest-asyncio is not a dependency; each test drives the coroutine with
``asyncio.run()``. Helpers are self-contained (tests/ is not a package — no
cross-import). The through-line is **parity**: the async path must reach the same
outcome as the sync path over the same inputs, and keep every fail-closed gate.
"""
from __future__ import annotations

import asyncio

import pytest

from openvc import verify_credential, verify_credential_async, verify_many_async
from openvc.did.base import (
    AsyncDidResolverRegistry,
    DidResolutionError,
    as_async_resolver,
    parse_did_document,
)
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import CredentialRevoked, encode_bitstring, set_status_bit
from openvc.verify import StatusUnavailable


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# Helpers (self-contained)
# --------------------------------------------------------------------------- #

def _sync_registry(entries):
    """A sync DID registry over (did, vm, jwk) entries — wrapped with
    as_async_resolver for the async pipeline (which also exercises the adapter)."""
    docs = {
        did: parse_did_document({
            "id": did,
            "verificationMethod": [
                {"id": vm, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}],
            "assertionMethod": [vm],
            "authentication": [vm],
        })
        for did, vm, jwk in entries
    }

    class _Reg:
        def supports(self, d):
            return d in docs

        def resolve(self, d):
            if d not in docs:
                raise DidResolutionError(f"unknown DID {d!r}")
            return docs[d]

    return _Reg()


def _cred(*, issuer="did:web:issuer.example", subject=None, **extra):
    c = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "credentialSubject": subject if subject is not None else {"id": "did:example:alice"},
    }
    c.update(extra)
    return c


def _vc_jwt(cred, did="did:web:issuer.example", sk=None):
    """Sign *cred* as a VC-JWT; return (token, entry, signing_key)."""
    vm = f"{did}#key-1"
    sk = sk or P256SigningKey.generate(kid=vm)
    return VcJwtProofSuite().sign(cred, signing_key=sk), (did, vm, sk.public_jwk()), sk


def _status_vc(*set_indices):
    bits = bytearray(32)
    for i in set_indices:
        set_status_bit(bits, i, 1)
    return {
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "credentialSubject": {"statusPurpose": "revocation",
                              "encodedList": encode_bitstring(bytes(bits))},
    }


def _status_entry(index):
    return {
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": str(index),
        "statusListCredential": "https://status.example/1",
    }


# --------------------------------------------------------------------------- #
# VC-JWT — sync/async parity
# --------------------------------------------------------------------------- #

def test_vc_jwt_async_matches_sync():
    token, entry, _ = _vc_jwt(_cred())
    reg = _sync_registry([entry])
    sync = verify_credential(token, resolver=reg)
    asyncr = _run(verify_credential_async(token, resolver=as_async_resolver(reg)))
    assert asyncr.format == sync.format == "vc-jwt"
    assert asyncr.issuer == sync.issuer == "did:web:issuer.example"
    assert asyncr.credential == sync.credential


def test_vc_jwt_async_bad_signature_fails():
    from openvc.proof.errors import ProofError
    token, entry, _ = _vc_jwt(_cred())
    reg = _sync_registry([entry])
    # flip the FIRST signature char (fully-significant bits), not the last (which can
    # land on the final byte's don't-care padding bits and stay valid — a flaky pass).
    head, payload, sig = token.split(".")
    tampered = ".".join([head, payload, ("A" if sig[0] != "A" else "B") + sig[1:]])
    with pytest.raises(ProofError):
        _run(verify_credential_async(tampered, resolver=as_async_resolver(reg)))


# --------------------------------------------------------------------------- #
# did:web resolution over an async fetch
# --------------------------------------------------------------------------- #

def test_async_did_web_resolution():
    from openvc.did.did_web import AsyncDidWebResolver

    did = "did:web:issuer.example"
    token, (did_, vm, jwk), _ = _vc_jwt(_cred(issuer=did), did=did)
    did_doc = {
        "id": did,
        "verificationMethod": [
            {"id": vm, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}],
        "assertionMethod": [vm],
    }
    fetched = []

    async def _fetch(url):
        fetched.append(url)
        return did_doc

    reg = AsyncDidResolverRegistry([AsyncDidWebResolver(_fetch)])
    result = _run(verify_credential_async(token, resolver=reg))
    assert result.issuer == did
    assert fetched == ["https://issuer.example/.well-known/did.json"]


def _leb128(code):
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key_ed25519():
    """An Ed25519 signing key whose kid is its own resolvable did:key vm."""
    import base64

    from cryptography.hazmat.primitives.asymmetric import ed25519

    from openvc.multibase import encode_multibase
    priv = ed25519.Ed25519PrivateKey.generate()
    tmp = Ed25519SigningKey(priv, kid="tmp")
    raw = base64.urlsafe_b64decode(tmp.public_jwk()["x"] + "==")
    did = "did:key:" + encode_multibase(_leb128(0xED) + raw)
    vm = f"{did}#{did[len('did:key:'):]}"
    return Ed25519SigningKey(priv, kid=vm), did


def test_default_async_resolver_did_key_offline():
    # did:key resolves offline through default_async_resolver() — no injected fetch.
    sk, did = _did_key_ed25519()
    token = VcJwtProofSuite().sign(_cred(issuer=did), signing_key=sk)
    result = _run(verify_credential_async(token))
    assert result.issuer == did


# --------------------------------------------------------------------------- #
# Data Integrity (eddsa-jcs, pyld-free) — parity
# --------------------------------------------------------------------------- #

def test_data_integrity_async_matches_sync():
    from openvc.proof.di_jcs import EddsaJcsProofSuite

    did = "did:example:issuer"
    vm = f"{did}#k"
    key = Ed25519SigningKey.generate(kid=vm)
    doc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": did,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "score": 42},
    }
    secured = EddsaJcsProofSuite().add_proof(doc, signing_key=key, verification_method=vm)
    reg = _sync_registry([(did, vm, key.public_jwk())])
    sync = verify_credential(secured, resolver=reg)
    asyncr = _run(verify_credential_async(secured, resolver=as_async_resolver(reg)))
    assert asyncr.format == sync.format == "data-integrity:eddsa-jcs-2022"
    assert asyncr.issuer == sync.issuer == did
    assert asyncr.subject == sync.subject == "did:example:alice"


def test_data_integrity_async_wrong_issuer_binding_fails():
    from openvc.proof.di_jcs import EddsaJcsProofSuite
    from openvc.verify import IssuerBindingError

    # sign with a vm whose DID != issuer -> issuer binding must reject (async too)
    key = Ed25519SigningKey.generate(kid="did:example:signer#k")
    doc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "credentialSubject": {"id": "did:example:alice"},
    }
    secured = EddsaJcsProofSuite().add_proof(
        doc, signing_key=key, verification_method="did:example:signer#k")
    reg = _sync_registry([("did:example:signer", "did:example:signer#k", key.public_jwk())])
    with pytest.raises(IssuerBindingError):
        _run(verify_credential_async(secured, resolver=as_async_resolver(reg)))


# --------------------------------------------------------------------------- #
# Status (W3C) — async, revoked / ok / fail-closed parity
# --------------------------------------------------------------------------- #

def test_status_async_revoked_raises():
    token, entry, _ = _vc_jwt(_cred(credentialStatus=_status_entry(5)))
    reg = _sync_registry([entry])

    async def _resolve(url):
        return _status_vc(5)                          # index 5 revoked

    with pytest.raises(CredentialRevoked):
        _run(verify_credential_async(token, resolver=as_async_resolver(reg),
                                     resolve_status_list=_resolve))


def test_status_async_not_revoked_ok():
    token, entry, _ = _vc_jwt(_cred(credentialStatus=_status_entry(6)))
    reg = _sync_registry([entry])

    async def _resolve(url):
        return _status_vc(5)                          # only index 5 set; 6 is clear

    result = _run(verify_credential_async(token, resolver=as_async_resolver(reg),
                                          resolve_status_list=_resolve))
    assert result.status is not None and result.status.revoked is False


def test_status_async_fail_closed_without_resolver():
    # declares a status, default policy require_status=True, no resolver -> fail closed
    token, entry, _ = _vc_jwt(_cred(credentialStatus=_status_entry(5)))
    reg = _sync_registry([entry])
    with pytest.raises(StatusUnavailable):
        _run(verify_credential_async(token, resolver=as_async_resolver(reg)))


# --------------------------------------------------------------------------- #
# credentialSchema — async (JsonSchema + JsonSchemaCredential parity)
# --------------------------------------------------------------------------- #

_EMAIL_SCHEMA = {
    "$id": "https://ex/email.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "credentialSubject": {
            "type": "object",
            "properties": {"emailAddress": {"type": "string"}},
            "required": ["emailAddress"]}},
}


def _schema_entry(url="https://ex/email.json", stype="JsonSchema"):
    return {"id": url, "type": stype}


def test_schema_async_conforming_and_not():
    pytest.importorskip("jsonschema")
    import json

    async def _resolve(url):
        return json.dumps(_EMAIL_SCHEMA).encode()

    ok_token, entry, _ = _vc_jwt(
        _cred(subject={"emailAddress": "a@b.com"}, credentialSchema=_schema_entry()))
    reg = _sync_registry([entry])
    ok = _run(verify_credential_async(ok_token, resolver=as_async_resolver(reg),
                                      resolve_credential_schema=_resolve))
    assert ok.schema is not None and ok.schema.validated is True

    from openvc.schema import SchemaValidationError
    bad_token, entry2, _ = _vc_jwt(
        _cred(subject={"id": "x"}, credentialSchema=_schema_entry()))
    reg2 = _sync_registry([entry2])
    with pytest.raises(SchemaValidationError):
        _run(verify_credential_async(bad_token, resolver=as_async_resolver(reg2),
                                     resolve_credential_schema=_resolve))


def test_json_schema_credential_async_end_to_end():
    pytest.importorskip("jsonschema")

    schema_did = "did:web:schema.example"
    issuer_did = "did:web:issuer.example"
    jsc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "https://ex/email.json",
        "type": ["VerifiableCredential", "JsonSchemaCredential"],
        "issuer": schema_did,
        "credentialSubject": {"id": "https://ex/email.json", "type": "JsonSchema",
                              "jsonSchema": _EMAIL_SCHEMA},
    }
    inner_token, inner_entry, _ = _vc_jwt(jsc, did=schema_did)
    outer_token, outer_entry, _ = _vc_jwt(
        _cred(issuer=issuer_did, subject={"emailAddress": "a@b.com"},
              credentialSchema=_schema_entry(stype="JsonSchemaCredential")), did=issuer_did)
    reg = _sync_registry([inner_entry, outer_entry])

    fetched = []

    async def _resolve(url):
        fetched.append(url)
        return inner_token.encode()

    result = _run(verify_credential_async(
        outer_token, resolver=as_async_resolver(reg), resolve_credential_schema=_resolve))
    assert result.schema is not None and result.schema.validated is True
    assert fetched == ["https://ex/email.json"]        # inner meta-schema NOT re-fetched


# --------------------------------------------------------------------------- #
# verify_many_async — concurrency + independent fail-closed
# --------------------------------------------------------------------------- #

class _ConcurrencyResolver:
    """Async resolver that records peak concurrent in-flight resolves."""

    def __init__(self, inner, delay=0.02):
        self.inner = inner
        self.delay = delay
        self.active = 0
        self.max_active = 0

    def supports(self, did):
        return self.inner.supports(did)

    async def resolve(self, did):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(self.delay)
            return self.inner.resolve(did)
        finally:
            self.active -= 1


def test_verify_many_async_runs_concurrently():
    # 4 credentials from the SAME issuer; verify_many_async does not dedup (ADR D4),
    # so all 4 resolves overlap -> peak concurrency proves the fetches are not serial.
    did = "did:web:issuer.example"
    sk = P256SigningKey.generate(kid=f"{did}#key-1")
    tokens = [_vc_jwt(_cred(subject={"n": i}), did=did, sk=sk)[0] for i in range(4)]
    reg = _ConcurrencyResolver(_sync_registry([(did, f"{did}#key-1", sk.public_jwk())]))
    results = _run(verify_many_async(tokens, resolver=reg))
    assert [r.ok for r in results] == [True, True, True, True]
    assert reg.max_active >= 2                          # overlapped, not serialised


def test_verify_many_async_independent_fail_closed():
    token_ok, entry, _ = _vc_jwt(_cred())
    reg = _sync_registry([entry])
    # a garbage credential fails on its own without aborting the good one
    results = _run(verify_many_async(
        [token_ok, "not-a-credential"], resolver=as_async_resolver(reg)))
    assert results[0].ok is True
    assert results[1].ok is False and results[1].error is not None


# --------------------------------------------------------------------------- #
# The async fetch keeps the SSRF guard
# --------------------------------------------------------------------------- #

def test_async_fetch_rejects_non_https():
    from openvc.fetch import UnsafeUrlError, https_json_fetch_async
    with pytest.raises(UnsafeUrlError):
        _run(https_json_fetch_async("http://issuer.example/did.json"))


def test_async_fetch_rejects_private_host():
    from openvc.fetch import UnsafeUrlError, https_json_fetch_async
    with pytest.raises(UnsafeUrlError):                 # loopback blocked (DNS-rebind guard)
        _run(https_json_fetch_async("https://127.0.0.1/did.json"))
