"""
tests/test_status_issuer_binding.py — status-list issuer ↔ credential-issuer binding
(issue #106 / ADR-0006).

Off by default (a status list is authenticated but its issuer is unconstrained —
delegation is spec-legal); opting in binds the resolved status list's issuer to the
credential's issuer, with an allow-list for trusted delegates.
"""
from __future__ import annotations

import base64
import datetime as dt

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.status import encode_bitstring
from openvc.verify import (
    StatusListIssuerUntrusted,
    VerificationPolicy,
    _bind_status_issuer,
    _enforce_status_issuer,
)

VC2 = "https://www.w3.org/ns/credentials/v2"
STATUS_URL = "https://status-host.example/1"
NOW = dt.datetime(2021, 6, 1, tzinfo=dt.timezone.utc)


def _binding(allow=None):
    return VerificationPolicy(require_status_issuer_binding=True,
                              status_issuer_allowlist=frozenset(allow) if allow else None)


# --- the pure decision (_enforce_status_issuer) -------------------------------- #

def test_enforce_same_issuer_passes():
    _enforce_status_issuer({"issuer": "did:ex:iss"}, "issuer", "did:ex:iss", _binding())
    _enforce_status_issuer({"issuer": {"id": "did:ex:iss"}}, "issuer", "did:ex:iss", _binding())
    _enforce_status_issuer({"iss": "did:ex:iss"}, "iss", "did:ex:iss", _binding())   # IETF


def test_enforce_mismatch_fails_closed():
    with pytest.raises(StatusListIssuerUntrusted):
        _enforce_status_issuer({"issuer": "did:ex:attacker"}, "issuer", "did:ex:iss", _binding())


def test_enforce_delegate_in_allowlist_passes():
    _enforce_status_issuer({"issuer": "did:ex:status-svc"}, "issuer", "did:ex:iss",
                           _binding(allow=["did:ex:status-svc"]))


def test_enforce_missing_issuer_fails_closed():
    with pytest.raises(StatusListIssuerUntrusted):
        _enforce_status_issuer({}, "issuer", "did:ex:iss", _binding())


def test_bind_wrapper_enforces_on_resolve():
    inner = lambda uri: {"issuer": "did:ex:attacker", "x": 1}          # noqa: E731
    bound = _bind_status_issuer(inner, "did:ex:iss", _binding(), field="issuer")
    with pytest.raises(StatusListIssuerUntrusted):
        bound(STATUS_URL)
    assert _bind_status_issuer(None, "did:ex:iss", _binding(), field="issuer") is None


# --- end to end through verify_credential -------------------------------------- #

def _issuer():
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = base64.urlsafe_b64decode(Ed25519SigningKey(priv, kid="t").public_jwk()["x"] + "==")
    did = "did:key:" + encode_multibase(bytes([0xED, 0x01]) + raw)
    vm = f"{did}#{did[len('did:key:'):]}"
    return Ed25519SigningKey(priv, kid=vm), did, vm


def _signed_credential_with_status():
    key, did, vm = _issuer()
    cred = {"@context": [VC2], "type": ["VerifiableCredential"], "issuer": did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:alice"},
            "credentialStatus": {"id": f"{STATUS_URL}#17", "type": "BitstringStatusListEntry",
                                 "statusPurpose": "revocation", "statusListIndex": "17",
                                 "statusListCredential": STATUS_URL}}
    return EddsaJcsProofSuite().add_proof(cred, signing_key=key, verification_method=vm), did


def _status_list_from(issuer_did):
    bits = bytearray(32)                                  # nothing set -> not revoked
    return lambda uri: {
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_did,
        "credentialSubject": {"statusPurpose": "revocation",
                              "encodedList": encode_bitstring(bytes(bits))}}


def test_pipeline_binding_off_accepts_any_status_issuer():
    cred, _did = _signed_credential_with_status()
    # default policy: no binding -> a delegate-issued status list is accepted
    result = verify_credential(
        cred, resolve_status_list=_status_list_from("did:ex:some-delegate"),
        policy=VerificationPolicy(now=NOW))
    assert result.issuer.startswith("did:key:")


def test_pipeline_binding_on_rejects_foreign_status_issuer():
    cred, _did = _signed_credential_with_status()
    with pytest.raises(StatusListIssuerUntrusted):
        verify_credential(
            cred, resolve_status_list=_status_list_from("did:ex:attacker"),
            policy=VerificationPolicy(now=NOW, require_status_issuer_binding=True))


def test_pipeline_binding_on_accepts_same_or_allowlisted_issuer():
    cred, did = _signed_credential_with_status()
    # same issuer
    ok = verify_credential(cred, resolve_status_list=_status_list_from(did),
                           policy=VerificationPolicy(now=NOW, require_status_issuer_binding=True))
    assert ok.issuer == did
    # allow-listed delegate
    ok2 = verify_credential(
        cred, resolve_status_list=_status_list_from("did:ex:status-svc"),
        policy=VerificationPolicy(now=NOW, require_status_issuer_binding=True,
                                  status_issuer_allowlist=frozenset({"did:ex:status-svc"})))
    assert ok2.issuer == did
