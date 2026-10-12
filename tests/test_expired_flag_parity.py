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

Through v1.28.1 the flag was also *wrong* on both pipelines: ``openvc.verify``
re-derived expiry with other clocks and fields than the proof suites enforce. Since
1.29.0 each suite reports the expiry check it skipped, so the second half of this
file pins the flag to the default policy's own verdict: ``expired`` is True exactly
when the enforcing policy rejects the credential for its expiry.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from openvc import (
    OpenvcError,
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
)
from openvc.did.base import DidResolutionError, as_async_resolver, parse_did_document
from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey
from openvc.proof._verify_common import (
    DEFAULT_LEEWAY_S,
    check_jwt_temporal,
    check_validity_window,
)
from openvc.proof.errors import ClaimsInvalid, CredentialExpired, ProofError

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


def _schema_kwargs(schemas):
    """(sync, async) ``resolve_credential_schema`` kwargs serving *schemas*."""
    if schemas is None:
        return {}, {}

    async def fetch(url):
        return schemas[url]
    return ({"resolve_credential_schema": schemas.__getitem__},
            {"resolve_credential_schema": fetch})


def _both(credential, key, policy, schemas=None):
    """Verify one credential through both pipelines; return (sync, async). *schemas*
    maps a ``credentialSchema`` URL to the bytes a fetch would return."""
    registry = _registry(key.public_jwk())
    sync_kw, async_kw = _schema_kwargs(schemas)
    sync = verify_credential(credential, policy=policy, resolver=registry, **sync_kw)
    asyncr = asyncio.run(verify_credential_async(
        credential, policy=policy, resolver=as_async_resolver(registry), **async_kw))
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


# --------------------------------------------------------------------------- #
# The flag is the default policy's verdict (v1.29.0)
# --------------------------------------------------------------------------- #

def _strict_error(credential, key, *, now=None, schemas=None):
    """What the enforcing (default) policy raises for *credential*, or None."""
    sync_kw, _ = _schema_kwargs(schemas)
    try:
        verify_credential(credential, policy=VerificationPolicy(now=now),
                          resolver=_registry(key.public_jwk()), **sync_kw)
    except OpenvcError as exc:
        return exc
    return None


def _flag_is_the_strict_verdict(credential, key, *, now=None, schemas=None):
    """Under the waiver both pipelines accept, agree, and set ``expired`` exactly
    when the default policy rejects. Returns that rejection (or None) so the caller
    can pin *why* it rejected."""
    error = _strict_error(credential, key, now=now, schemas=schemas)
    sync, asyncr = _both(
        credential, key, VerificationPolicy(require_not_expired=False, now=now), schemas)
    assert asyncr == sync
    assert sync.expired is (error is not None), error
    return error


def _rejected_everywhere(credential, key, *, now=None, schemas=None):
    """The waiver does not admit it either: the default policy and the waived one,
    sync and async, raise the same error type. Returns that type."""
    strict = _strict_error(credential, key, now=now, schemas=schemas)
    assert strict is not None
    waived = VerificationPolicy(require_not_expired=False, now=now)
    registry = _registry(key.public_jwk())
    sync_kw, async_kw = _schema_kwargs(schemas)
    with pytest.raises(OpenvcError) as sync_err:
        verify_credential(credential, policy=waived, resolver=registry, **sync_kw)
    with pytest.raises(OpenvcError) as async_err:
        asyncio.run(verify_credential_async(
            credential, policy=waived, resolver=as_async_resolver(registry), **async_kw))
    assert type(sync_err.value) is type(strict)
    assert type(async_err.value) is type(strict)
    return type(strict)


# (a) A Data Integrity proof's own `expires`. The flag used to read only the
# credential's dates, so a lapsed proof was waived and reported current.

def _signs_expires(original, index):
    """Wrap a suite's hash step so the proof config it signs carries ``expires``:
    no ``add_proof`` takes one. The test then adds the same member to the emitted
    proof, so the verifier rebuilds exactly the signed config."""
    def wrapper(*args, **kwargs):
        args = list(args)
        args[index] = dict(args[index], expires=PAST)
        return original(*args, **kwargs)
    return wrapper


def _whole_document_proof_expires(module_name, suite_name, key_cls, *, rdf):
    def build():
        if rdf:
            pytest.importorskip("pyld")
        import importlib
        module = importlib.import_module(f"openvc.proof.{module_name}")
        key = key_cls.generate(kid=VM)
        with mock.patch.object(module, "_hash_data", _signs_expires(module._hash_data, 1)):
            secured = getattr(module, suite_name)().add_proof(
                _vcdm(validUntil=FUTURE), signing_key=key, verification_method=VM)
        secured["proof"]["expires"] = PAST
        return secured, key
    return build


def _ecdsa_sd_derived_proof_expires():
    pytest.importorskip("pyld")
    from openvc.proof import ecdsa_sd
    key = P256SigningKey.generate(kid=VM)
    suite = ecdsa_sd.EcdsaSdProofSuite()
    with mock.patch.object(ecdsa_sd, "_proof_config_hash",
                           _signs_expires(ecdsa_sd._proof_config_hash, 0)):
        base = suite.add_base_proof(
            _vcdm(validUntil=FUTURE), signing_key=key, verification_method=VM,
            mandatory_pointers=["/issuer", "/validFrom", "/validUntil"])
    base["proof"]["expires"] = PAST
    return suite.derive_proof(base, selective_pointers=["/credentialSubject"]), key


PROOF_EXPIRES = {
    "eddsa-jcs-2022": _whole_document_proof_expires(
        "di_jcs", "EddsaJcsProofSuite", Ed25519SigningKey, rdf=False),
    "ecdsa-jcs-2019-p256": _whole_document_proof_expires(
        "di_jcs", "EcdsaJcsProofSuite", P256SigningKey, rdf=False),
    "ecdsa-jcs-2019-p384": _whole_document_proof_expires(
        "di_jcs", "EcdsaJcsProofSuite", P384SigningKey, rdf=False),
    "eddsa-rdfc-2022": _whole_document_proof_expires(
        "data_integrity", "DataIntegrityProofSuite", Ed25519SigningKey, rdf=True),
    "ecdsa-rdfc-2019-p256": _whole_document_proof_expires(
        "di_ecdsa_rdfc", "EcdsaRdfcProofSuite", P256SigningKey, rdf=True),
    "ecdsa-rdfc-2019-p384": _whole_document_proof_expires(
        "di_ecdsa_rdfc", "EcdsaRdfcProofSuite", P384SigningKey, rdf=True),
    "ecdsa-sd-2023-derived": _ecdsa_sd_derived_proof_expires,
}


@pytest.mark.parametrize("case", list(PROOF_EXPIRES))
def test_lapsed_proof_expires_sets_the_flag(case):
    credential, key = PROOF_EXPIRES[case]()
    error = _flag_is_the_strict_verdict(credential, key)
    assert isinstance(error, CredentialExpired) and "proof expired" in str(error)


@pytest.mark.parametrize("now, expired", [
    (datetime(2020, 6, 1, tzinfo=timezone.utc), False),
    (datetime(2022, 6, 1, tzinfo=timezone.utc), True),
])
def test_proof_expires_is_read_at_the_pinned_now(now, expired):
    credential, key = PROOF_EXPIRES["eddsa-jcs-2022"]()
    assert (_flag_is_the_strict_verdict(credential, key, now=now) is not None) is expired


# (b) A VC-JWT body's validUntil. The suite reads it at the wall clock (JOSE `now` is
# never pinned); the flag read it at policy.now, so the two disagreed both ways.

def _stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize("until_days, now_days, rejected", [
    (-365, -730, True),     # lapsed a year ago; now pinned to before it lapsed
    (365, 730, False),      # current; now pinned to after it lapses
], ids=["lapsed-but-now-pinned-earlier", "current-but-now-pinned-later"])
def test_vc_jwt_body_is_judged_at_the_suites_clock(until_days, now_days, rejected):
    from openvc.proof.vc_jwt import VcJwtProofSuite
    wall = datetime.now(timezone.utc)
    key = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(
        _vcdm(validUntil=_stamp(wall + timedelta(days=until_days))), signing_key=key)
    error = _flag_is_the_strict_verdict(token, key, now=wall + timedelta(days=now_days))
    assert (error is not None) is rejected
    if rejected:
        assert isinstance(error, CredentialExpired)


# (c) + (d) The VC-JWT `exp`, judged by PyJWT: it coerces the value with int() and
# expires at `exp <= now - leeway` on a float clock. The flag had its own rule.

def _vc_jwt_claims(**claims):
    from openvc.proof._jws import sign_compact
    key = P256SigningKey.generate(kid=VM)
    payload = {"iss": DID, "nbf": int(time.time()) - 10, "vc": _vcdm(), **claims}
    token = sign_compact({"alg": "ES256", "typ": "JWT", "kid": VM}, payload, signing_key=key)
    return token, key


def _waiver_agrees_with_strict(credential, key):
    """Whatever the default policy makes of a credential with a *single* defect, the
    waiver agrees: an expiry rejection becomes ``expired=True``; any other rejection
    stands, with the same error type on both pipelines; an accept stays
    ``expired=False``. (With two defects the default policy may report the expiry
    first while the waiver correctly reports the other, so the message check below
    only holds for one.) Returns (the default policy's error or None, the waived sync
    result or None)."""
    strict = _strict_error(credential, key)
    try:
        sync, asyncr = _both(credential, key, WAIVED)
    except OpenvcError as exc:
        assert strict is not None and type(exc) is type(strict), (exc, strict)
        assert "expired" not in str(strict), strict    # an expiry must be waived
        assert _rejected_everywhere(credential, key) is type(strict)
        return strict, None
    assert asyncr == sync
    assert sync.expired is (strict is not None), strict
    return strict, sync


@pytest.mark.parametrize("exp", ["1000", True, -10 ** 400],
                         ids=["numeric-string", "true", "huge-negative"])
def test_exp_pyjwt_would_coerce_is_judged_as_the_default_policy_does(exp):
    # PyJWT reads these as past dates (int("1000"), int(True), the bignum); the old
    # flag refused their shape and said "current". Rejecting the shape outright under
    # every policy (#195) satisfies this too — what may not happen is a disagreement.
    error, _ = _waiver_agrees_with_strict(*_vc_jwt_claims(exp=exp))
    assert error is not None


def test_exp_pyjwt_would_coerce_to_the_future_is_judged_alike():
    _waiver_agrees_with_strict(*_vc_jwt_claims(exp=str(int(time.time()) + 3600)))


def test_float_exp_truncated_by_pyjwt_sets_the_flag():
    # a valid NumericDate: PyJWT truncates it with int() before comparing, so
    # int(now) - leeway + 0.9 is already past where `int(now) > exp + leeway` was not
    error = _flag_is_the_strict_verdict(
        *_vc_jwt_claims(exp=int(time.time()) - DEFAULT_LEEWAY_S + 0.9))
    assert isinstance(error, ClaimsInvalid) and "expired" in str(error)


def test_exp_on_pyjwts_boundary_second_sets_the_flag():
    # PyJWT expires at exp <= now - leeway (float now); exp = int(now) - leeway is past
    # it from the first instant, where `int(now) > exp + leeway` said "current"
    error = _flag_is_the_strict_verdict(
        *_vc_jwt_claims(exp=int(time.time()) - DEFAULT_LEEWAY_S))
    assert isinstance(error, ClaimsInvalid) and "expired" in str(error)


@pytest.mark.parametrize("exp", ["soon", {}, [], None, float("nan")],
                         ids=["word", "object", "array", "null", "nan"])
def test_waiver_does_not_skip_the_exp_shape_check(exp):
    # the waived lane used to switch PyJWT's exp check off, shape included; it now
    # rejects what the default policy rejects, typed (never a bare TypeError)
    assert _rejected_everywhere(*_vc_jwt_claims(exp=exp)) is ClaimsInvalid


# (e) A JsonSchemaCredential does not inherit the waivers: the schema VC is a trust
# input of the credential, like a status-list credential, not the credential itself.

SCHEMA_URL = "https://schemas.example/score.json"
SCORE_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["credentialSubject"],
    "properties": {"credentialSubject": {"type": "object", "required": ["score"]}},
}


def _with_schema_vc(*, outer_expired, schema_expired):
    """An eddsa-jcs credential declaring a JsonSchemaCredential, and the fetch map
    serving that schema VC (same issuer and key, so one resolver serves both)."""
    pytest.importorskip("jsonschema")
    from openvc.proof.di_jcs import EddsaJcsProofSuite
    key = Ed25519SigningKey.generate(kid=VM)
    suite = EddsaJcsProofSuite()
    schema_vc = suite.add_proof({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": SCHEMA_URL,
        "type": ["VerifiableCredential", "JsonSchemaCredential"],
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": PAST if schema_expired else FUTURE,
        "credentialSubject": {"id": SCHEMA_URL, "type": "JsonSchema",
                              "jsonSchema": SCORE_SCHEMA},
    }, signing_key=key, verification_method=VM)
    outer = suite.add_proof(
        _vcdm(validUntil=PAST if outer_expired else FUTURE,
              credentialSchema={"id": SCHEMA_URL, "type": "JsonSchemaCredential"}),
        signing_key=key, verification_method=VM)
    return outer, key, {SCHEMA_URL: json.dumps(schema_vc).encode()}


def test_expired_schema_credential_is_rejected_under_the_waiver():
    from openvc.schema import SchemaResolutionError
    outer, key, schemas = _with_schema_vc(outer_expired=False, schema_expired=True)
    assert _rejected_everywhere(outer, key, schemas=schemas) is SchemaResolutionError


@pytest.mark.parametrize("outer_expired", [False, True])
def test_current_schema_credential_still_validates_under_the_waiver(outer_expired):
    outer, key, schemas = _with_schema_vc(outer_expired=outer_expired, schema_expired=False)
    _flag_is_the_strict_verdict(outer, key, schemas=schemas)
    sync, _ = _both(outer, key, WAIVED, schemas)
    assert sync.expired is outer_expired
    assert sync.schema is not None and sync.schema.validated is True


def test_schema_credential_policy_inherits_neither_waiver():
    from openvc.verify import _schema_inner_policy
    outer = VerificationPolicy(
        require_not_expired=False, require_not_revoked=False, leeway_s=5,
        now=datetime(2024, 1, 1, tzinfo=timezone.utc), require_status=False,
        expected_types=["X"], audience="aud", nonce="n")
    inner = _schema_inner_policy(outer)
    assert inner.require_not_expired is True and inner.require_not_revoked is True
    assert (inner.leeway_s, inner.now, inner.require_status) == (5, outer.now, False)
    assert inner.expected_types is None and inner.audience is None and inner.nonce is None


# (f) The SD-JWT suite enforces exp only. VCDM-named claims on an SD-JWT VC are not
# its expiry, so they must not flag one the default policy accepts.

def test_sd_jwt_vcdm_named_claims_do_not_set_the_flag():
    credential, key = _sd_jwt_with({"validUntil": PAST, "expirationDate": PAST})
    assert _flag_is_the_strict_verdict(credential, key) is None


# The shared helpers say which skipped check would have failed.

def test_check_validity_window_reports_only_what_it_skipped():
    now = datetime(2022, 6, 1, tzinfo=timezone.utc)
    lapsed, lapsed_proof = {"validUntil": PAST}, {"expires": PAST}
    assert check_validity_window(lapsed, {}, now=now, leeway_s=0, check_temporal=False)
    assert check_validity_window({}, lapsed_proof, now=now, leeway_s=0, check_temporal=False)
    assert not check_validity_window(
        {"validUntil": FUTURE}, {}, now=now, leeway_s=0, check_temporal=False)
    assert not check_validity_window({"validUntil": FUTURE}, {}, now=now, leeway_s=0)
    with pytest.raises(CredentialExpired):
        check_validity_window({}, lapsed_proof, now=now, leeway_s=0)


def test_check_jwt_temporal_reports_only_what_it_skipped():
    assert check_jwt_temporal({"exp": 100}, leeway_s=0, now=200, check_temporal=False)
    assert not check_jwt_temporal({"exp": 300}, leeway_s=0, now=200, check_temporal=False)
    assert not check_jwt_temporal({"exp": 300}, leeway_s=0, now=200)
    with pytest.raises(ClaimsInvalid, match="not yet valid"):     # nbf is never waived
        check_jwt_temporal({"exp": 100, "nbf": 300}, leeway_s=0, now=200,
                           check_temporal=False)


@pytest.mark.parametrize("expires_in_s, expired", [(-3600, True), (3600, False)])
def test_ml_dsa_vc_jwt_reports_the_waived_exp(expires_in_s, expired):
    # the ML-DSA lane validates claims itself (PyJWT has no ML-DSA); the pipeline
    # never enables it, so the suite is checked directly
    from openvc.keys import MLDSASigningKey, mldsa_available
    from openvc.proof.vc_jwt import VcJwtProofSuite
    if not mldsa_available():
        pytest.skip("ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")
    key = MLDSASigningKey.generate(kid=VM, alg="ML-DSA-65")
    suite = VcJwtProofSuite(allow_pq=True)
    token = suite.sign(_vcdm(), signing_key=key, expires_in_s=expires_in_s)
    assert suite.verify(token, public_key_jwk=key.public_jwk(),
                        check_temporal=False).expired is expired
    if expired:
        with pytest.raises(ClaimsInvalid, match="expired"):
            suite.verify(token, public_key_jwk=key.public_jwk())
