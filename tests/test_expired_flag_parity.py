"""
tests/test_expired_flag_parity.py — ``VerificationResult.expired`` agrees between
the sync and async pipelines.

``VerificationPolicy(require_not_expired=False)`` waives the expiry *failure* and
reports it on the result instead. Through v1.27.1 only the sync pipeline set the
flag: the ``openvc.aio`` lanes built their result without it, so the same expired
credential came back ``expired=True`` from ``verify_credential`` and
``expired=False`` from ``verify_credential_async``.

Every case runs one credential through both pipelines and requires the **whole**
result to match, not just the flag, so the next field an async lane forgets fails
here too. Helpers are self-contained (tests/ is not a package — no cross-import);
``asyncio.run`` drives the coroutines (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from openvc import VerificationPolicy, verify_credential, verify_credential_async
from openvc.did.base import DidResolutionError, as_async_resolver, parse_did_document
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof.errors import ProofError

DID = "did:example:issuer"
VM = f"{DID}#k"
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
WAIVED = VerificationPolicy(require_not_expired=False)


def _registry(public_jwk):
    """A sync resolver for the one issuer DID (the async lane gets it through
    ``as_async_resolver``)."""
    doc = parse_did_document({
        "id": DID,
        "verificationMethod": [
            {"id": VM, "type": "JsonWebKey2020", "controller": DID, "publicKeyJwk": public_jwk}],
        "assertionMethod": [VM],
    })

    class _Reg:
        def supports(self, did):
            return did == DID

        def resolve(self, did):
            if did != DID:
                raise DidResolutionError(f"unknown DID {did!r}")
            return doc

    return _Reg()


def _vcdm(**extra):
    doc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "score": 42},
    }
    doc.update(extra)
    return doc


# Each builder returns (credential, signing key): expired, or current when not.

def _vc_jwt_exp(expired):
    from openvc.proof.vc_jwt import VcJwtProofSuite
    key = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(
        _vcdm(), signing_key=key, expires_in_s=-3600 if expired else 3600)
    return token, key


def _vc_jwt_valid_until(expired):
    # no JWT exp: the expiry lives only in the credential body
    from openvc.proof.vc_jwt import VcJwtProofSuite
    key = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(
        _vcdm(validUntil=PAST if expired else FUTURE), signing_key=key)
    return token, key


def _sd_jwt_vc(expired):
    from openvc.proof.sd_jwt import SdJwtVcProofSuite
    key = P256SigningKey.generate(kid=VM)
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": DID, "sub": "did:example:alice", "given_name": "Ada"},
        signing_key=key, vct="https://credentials.example/id", disclosable=["given_name"],
        expires_in_s=-3600 if expired else 3600)
    return sd_jwt, key


def _di_eddsa_jcs(expired):
    from openvc.proof.di_jcs import EddsaJcsProofSuite
    key = Ed25519SigningKey.generate(kid=VM)
    secured = EddsaJcsProofSuite().add_proof(
        _vcdm(validUntil=PAST if expired else FUTURE), signing_key=key, verification_method=VM)
    return secured, key


def _di_eddsa_rdfc(expired):
    pytest.importorskip("pyld")
    from openvc.proof.data_integrity import DataIntegrityProofSuite
    key = Ed25519SigningKey.generate(kid=VM)
    secured = DataIntegrityProofSuite().add_proof(
        _vcdm(validUntil=PAST if expired else FUTURE), signing_key=key, verification_method=VM)
    return secured, key


def _enveloped_vc_jwt(expired):
    token, key = _vc_jwt_exp(expired)
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": f"data:application/vc+jwt,{token}",
        "type": ["EnvelopedVerifiableCredential"],
    }, key


CASES = {
    "vc-jwt-exp": _vc_jwt_exp,
    "vc-jwt-validUntil": _vc_jwt_valid_until,
    "sd-jwt-vc": _sd_jwt_vc,
    "data-integrity-eddsa-jcs-2022": _di_eddsa_jcs,
    "data-integrity-eddsa-rdfc-2022": _di_eddsa_rdfc,
    "enveloped-vc-jwt": _enveloped_vc_jwt,
}


def _both(credential, key, policy):
    """Verify one credential through both pipelines; return (sync, async)."""
    registry = _registry(key.public_jwk())
    sync = verify_credential(credential, policy=policy, resolver=registry)
    asyncr = asyncio.run(verify_credential_async(
        credential, policy=policy, resolver=as_async_resolver(registry)))
    return sync, asyncr


@pytest.mark.parametrize("case", list(CASES))
def test_waived_expiry_is_flagged_on_both_pipelines(case):
    sync, asyncr = _both(*CASES[case](True), WAIVED)
    assert sync.expired is True
    assert asyncr.expired is True
    assert asyncr == sync


@pytest.mark.parametrize("case", list(CASES))
def test_current_credential_is_not_flagged(case):
    # control: under the waiver the flag tracks expiry, it is not stuck on
    sync, asyncr = _both(*CASES[case](False), WAIVED)
    assert sync.expired is False
    assert asyncr.expired is False
    assert asyncr == sync


@pytest.mark.parametrize("case", list(CASES))
def test_expired_credential_fails_without_the_waiver(case):
    # control: the fixtures really are expired — only the waiver admits them
    credential, key = CASES[case](True)
    registry = _registry(key.public_jwk())
    with pytest.raises(ProofError) as sync_err:
        verify_credential(credential, resolver=registry)
    with pytest.raises(ProofError) as async_err:
        asyncio.run(verify_credential_async(credential, resolver=as_async_resolver(registry)))
    assert type(async_err.value) is type(sync_err.value)


@pytest.mark.parametrize("now, expired", [
    (datetime(2020, 6, 1, tzinfo=timezone.utc), False),
    (datetime(2022, 6, 1, tzinfo=timezone.utc), True),
])
def test_flag_reads_the_pinned_now_on_both_pipelines(now, expired):
    # policy.now pins the Data Integrity validity window (validUntil 2021-01-01);
    # both pipelines must judge the flag at that instant, not the wall clock
    policy = VerificationPolicy(require_not_expired=False, now=now)
    sync, asyncr = _both(*_di_eddsa_jcs(True), policy)
    assert sync.expired is expired
    assert asyncr.expired is expired
    assert asyncr == sync


def _sd_jwt_with(claims):
    from openvc.proof.sd_jwt import SdJwtVcProofSuite
    key = P256SigningKey.generate(kid=VM)
    return SdJwtVcProofSuite().issue(
        {"iss": DID, "sub": "did:example:alice", **claims},
        signing_key=key, vct="https://credentials.example/id"), key


# Computing the flag reads VCDM dates the SD-JWT suite never reads, and reads the
# VC-JWT body at policy.now where the suite uses the wall clock. Through v1.27.1 the
# sync pipeline raised on these under the waiver (and async accepted) although the
# default policy accepts them on both.
EDGE_CASES = {
    "sd-jwt-future-validFrom":
        (lambda: _sd_jwt_with({"validFrom": "2099-01-01T00:00:00Z"}), None),
    "sd-jwt-malformed-validFrom":
        (lambda: _sd_jwt_with({"validFrom": "not-a-date"}), None),
    "sd-jwt-numeric-expirationDate":
        (lambda: _sd_jwt_with({"expirationDate": 1735689600}), None),
    "vc-jwt-now-before-validFrom":
        (lambda: _vc_jwt_valid_until(False), datetime(2019, 6, 1, tzinfo=timezone.utc)),
}


@pytest.mark.parametrize("case", list(EDGE_CASES))
def test_waiver_never_rejects_what_the_default_policy_accepts(case):
    build, now = EDGE_CASES[case]
    credential, key = build()
    registry = _registry(key.public_jwk())
    verify_credential(credential, policy=VerificationPolicy(now=now), resolver=registry)  # accepted
    sync, asyncr = _both(credential, key, VerificationPolicy(require_not_expired=False, now=now))
    assert sync.expired is False
    assert asyncr == sync
