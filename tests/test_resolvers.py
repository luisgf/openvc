"""
tests/test_resolvers.py — the blessed SSRF-guarded default resolvers
(`openvc.resolvers`, issue #3).

The status/schema fetch paths are caller-injected, so these factories make the
guarded fetch-and-verify path the easy one: they fetch (here through an injected
fake fetch, so no network) and — for status — verify the fetched list before
returning it, so a forged status list can never clear revocation.
"""
from __future__ import annotations

import pytest

from openvc import verify_credential
from openvc.did.base import DidResolutionError, parse_did_document
from openvc.errors import OpenvcError
from openvc.fetch import UnsafeUrlError, https_text_fetch
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.resolvers import (
    default_credential_schema_resolver,
    default_status_list_resolver,
    default_status_list_token_resolver,
)
from openvc.status import (
    STATUS_INVALID,
    CredentialRevoked,
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    build_status_list_token,
    check_token_status,
    new_bitstring,
    new_status_list,
    set_status,
    set_status_bit,
)

VC2 = "https://www.w3.org/ns/credentials/v2"
ISS = "did:web:issuer.example"
VM = f"{ISS}#key-1"
LIST_URL = "https://issuer.example/status/1"
TOKEN_URI = "https://issuer.example/statuslist/1"


def _registry(did, vm_id, jwk):
    doc = parse_did_document({
        "id": did,
        "verificationMethod": [
            {"id": vm_id, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
    })

    class _Reg:
        def supports(self, d):
            return d == did

        def resolve(self, d):
            if d != did:
                raise DidResolutionError(f"unknown DID {d!r}")
            return doc

    return _Reg()


def _subject_cred(**extra):
    c = {
        "@context": [VC2],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": ISS,
        "credentialSubject": {"id": "did:example:subject"},
    }
    c.update(extra)
    return c


# --------------------------------------------------------------------------- #
# schema resolver
# --------------------------------------------------------------------------- #

def test_schema_resolver_fetches_bytes():
    # the schema resolver now returns raw bytes (so digestSRI can be verified)
    resolve = default_credential_schema_resolver(fetch=lambda u: b'{"$schema": "s"}')
    assert resolve("https://ex/s.json") == b'{"$schema": "s"}'


# --------------------------------------------------------------------------- #
# W3C status list resolver — fetch + verify
# --------------------------------------------------------------------------- #

def _signed_status_vc(sk, revoked_index=None):
    bits = new_bitstring(64)
    if revoked_index is not None:
        set_status_bit(bits, revoked_index, 1)
    vc = build_status_list_credential(id=LIST_URL, issuer=ISS, bitstring=bits)
    return VcJwtProofSuite().sign(vc, signing_key=sk)


def test_status_list_resolver_verifies_and_returns_credential():
    sk = P256SigningKey.generate(kid=VM)
    jws = _signed_status_vc(sk)
    reg = _registry(ISS, VM, sk.public_jwk())
    resolve = default_status_list_resolver(resolver=reg, fetch=lambda u: jws)
    vc = resolve(LIST_URL)
    assert vc["credentialSubject"]["encodedList"]          # the verified credential


def test_status_list_resolver_rejects_forged_list():
    real = P256SigningKey.generate(kid=VM)
    attacker = P256SigningKey.generate(kid=VM)             # same kid, different key
    jws = _signed_status_vc(attacker)                      # signed by the wrong key
    reg = _registry(ISS, VM, real.public_jwk())            # registry has the real key
    resolve = default_status_list_resolver(resolver=reg, fetch=lambda u: jws)
    with pytest.raises(OpenvcError):                       # signature does not verify
        resolve(LIST_URL)


def test_status_list_resolver_end_to_end_revocation():
    sk = P256SigningKey.generate(kid=VM)
    reg = _registry(ISS, VM, sk.public_jwk())
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=5)
    subject = VcJwtProofSuite().sign(_subject_cred(credentialStatus=entry), signing_key=sk)

    revoked = default_status_list_resolver(resolver=reg, fetch=lambda u: _signed_status_vc(sk, 5))
    with pytest.raises(CredentialRevoked):
        verify_credential(subject, resolver=reg, resolve_status_list=revoked)

    clear = default_status_list_resolver(resolver=reg, fetch=lambda u: _signed_status_vc(sk, 7))
    result = verify_credential(subject, resolver=reg, resolve_status_list=clear)
    assert result.status is not None and not result.status.revoked


# --------------------------------------------------------------------------- #
# IETF status list token resolver — fetch + verify
# --------------------------------------------------------------------------- #

def _signed_status_token(sk, *, uri=TOKEN_URI, issuer=ISS, invalid_index=None):
    lst = new_status_list(64, bits=2)
    if invalid_index is not None:
        set_status(lst, invalid_index, STATUS_INVALID, bits=2)
    return build_status_list_token(
        signing_key=sk, uri=uri, status_list=lst, bits=2, issuer=issuer)


def test_status_list_token_resolver_verifies_and_returns_claims():
    sk = P256SigningKey.generate(kid=VM)
    token = _signed_status_token(sk, invalid_index=3)
    reg = _registry(ISS, VM, sk.public_jwk())
    resolve = default_status_list_token_resolver(resolver=reg, fetch=lambda u: token)

    claims = resolve(TOKEN_URI)
    assert "status_list" in claims
    ref = {"status": {"status_list": {"idx": 3, "uri": TOKEN_URI}}}
    assert check_token_status(ref, resolve_status_list_token=resolve).revoked


def test_status_list_token_resolver_rejects_uri_mismatch():
    sk = P256SigningKey.generate(kid=VM)
    token = _signed_status_token(sk)                        # sub == TOKEN_URI
    reg = _registry(ISS, VM, sk.public_jwk())
    resolve = default_status_list_token_resolver(resolver=reg, fetch=lambda u: token)
    with pytest.raises(StatusListError):                    # sub != the fetched uri
        resolve("https://issuer.example/statuslist/OTHER")


def test_status_list_token_resolver_requires_iss():
    sk = P256SigningKey.generate(kid=VM)
    token = _signed_status_token(sk, issuer=None)           # no iss claim
    reg = _registry(ISS, VM, sk.public_jwk())
    resolve = default_status_list_token_resolver(resolver=reg, fetch=lambda u: token)
    with pytest.raises(StatusListError):
        resolve(TOKEN_URI)


# --------------------------------------------------------------------------- #
# the guarded text fetch these default to
# --------------------------------------------------------------------------- #

def test_https_text_fetch_is_ssrf_guarded():
    with pytest.raises(UnsafeUrlError):
        https_text_fetch("http://example.com/")             # not https
    with pytest.raises(UnsafeUrlError):
        https_text_fetch("https://127.0.0.1/")              # loopback, blocked pre-connect
