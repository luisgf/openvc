"""
tests/test_credential_type_shape.py — the shape of a signed VC-JWT's `vc.type` (#433).

VC-JWT used to hand the caller whatever JSON the issuer signed as `vc.type` (a number, null,
an object, an array holding a number). The rule, after the signature verifies: a PRESENT
`type` is a non-empty string or an array of non-empty strings, else `ClaimsInvalid` naming
the shape (never the value), on the classic and the ML-DSA lane, sync and async.

Scope narrowed to VC-JWT by maintainer decision (2026-11-17). NOT decided here, pinned as
they behave today so a later change is a visible decision: on VC-JWT an absent `type`, `[]`
and a `type` without VerifiableCredential still verify; on the JCS Data Integrity pipeline
and on a `vc+sd-jwt` payload an array with a non-string member is still accepted (#275 made
the SD-JWT lane ignore non-string entries on purpose).

Self-contained (tests/ is not a package); issuers are did:jwk, resolved offline.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.keys import Ed25519SigningKey, P256SigningKey, mldsa_available
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.verify import TypeMismatch

V2 = "https://www.w3.org/ns/credentials/v2"
VC = "VerifiableCredential"
ABSENT = object()
MARKER = "attacker-chosen-marker-4711"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


ED = Ed25519SigningKey.generate(kid="_")
ED_DID = "did:jwk:" + _b64(json.dumps(ED.public_jwk()).encode())


# --------------------------------------------------------------------------- #
# VC-JWT
# --------------------------------------------------------------------------- #

def _vc_jwt(vc_type, *, key=None, did=None, alg="EdDSA"):
    key = key or ED
    did = did or ED_DID
    now = int(time.time())
    vc = {"@context": [V2], "issuer": did, "credentialSubject": {"id": "did:example:s"}}
    if vc_type is not ABSENT:
        vc["type"] = vc_type
    claims = {"iss": did, "sub": "did:example:s", "nbf": now, "iat": now, "vc": vc}
    head = (_b64(json.dumps({"alg": alg, "typ": "JWT", "kid": f"{did}#0"}).encode())
            + "." + _b64(json.dumps(claims).encode()))
    return f"{head}.{_b64(key.sign(head.encode()))}"


def _sync(token, policy=None):
    return verify_credential(token, policy=policy)


def _async(token, policy=None):
    return asyncio.run(verify_credential_async(token, policy=policy))


PIPELINES = pytest.mark.parametrize("run", [_sync, _async], ids=["sync", "async"])

REFUSED = [
    pytest.param(5, id="number"),
    pytest.param(None, id="null"),
    pytest.param(True, id="bool"),
    pytest.param(1.5, id="float"),
    pytest.param("", id="empty-string"),
    pytest.param({VC: 1}, id="object"),
    pytest.param([[VC]], id="nested-array"),
    pytest.param([VC, 5], id="member-number"),
    pytest.param([VC, None], id="member-null"),
    pytest.param([VC, ""], id="member-empty-string"),
    pytest.param([VC, {"a": 1}], id="member-object"),
]

ACCEPTED = [
    pytest.param([VC], id="control-array"),
    pytest.param(VC, id="control-string"),
    pytest.param([VC, "ExampleCredential"], id="control-two-types"),
]

# Open conformance questions: behaviour unchanged, pinned so a later decision is visible.
UNDECIDED = [
    pytest.param(ABSENT, id="absent"),
    pytest.param([], id="empty-array"),
    pytest.param(["ExampleCredential"], id="no-VerifiableCredential"),
    pytest.param("ExampleCredential", id="string-no-VerifiableCredential"),
]


@PIPELINES
@pytest.mark.parametrize("vc_type", REFUSED)
def test_malformed_type_is_refused(run, vc_type):
    with pytest.raises(ClaimsInvalid) as info:
        run(_vc_jwt(vc_type))
    assert type(info.value) is ClaimsInvalid
    assert "`type` must be a non-empty string or an array of non-empty strings" in str(info.value)


@PIPELINES
@pytest.mark.parametrize("vc_type", ACCEPTED)
def test_controls_verify(run, vc_type):
    assert run(_vc_jwt(vc_type)).credential["type"] == vc_type


@PIPELINES
@pytest.mark.parametrize("vc_type", UNDECIDED)
def test_undecided_cases_behave_as_before(run, vc_type):
    """Absent / [] / no VerifiableCredential verify today; whether to refuse them is the
    maintainer's call (#433), not part of the shape rule."""
    result = run(_vc_jwt(vc_type))
    assert result.credential.get("type", ABSENT) == vc_type


@PIPELINES
def test_message_names_the_shape_not_the_value(run):
    with pytest.raises(ClaimsInvalid) as info:
        run(_vc_jwt({MARKER: [MARKER] * 50}))
    assert MARKER not in str(info.value)
    assert "dict" in str(info.value)
    with pytest.raises(ClaimsInvalid) as info:
        run(_vc_jwt([VC, {MARKER: 1}]))
    assert MARKER not in str(info.value)
    assert "member 1" in str(info.value) and "dict" in str(info.value)


@PIPELINES
def test_malformed_type_is_refused_before_expected_types(run):
    """With expected_types pinned the shape refusal (ClaimsInvalid) fires, not TypeMismatch."""
    policy = VerificationPolicy(expected_types=[VC])
    with pytest.raises(ClaimsInvalid):
        run(_vc_jwt([VC, 5]), policy)
    with pytest.raises(ClaimsInvalid):
        run(_vc_jwt(5), policy)
    with pytest.raises(TypeMismatch):                 # a well-formed one is still judged
        run(_vc_jwt(["Other"]), policy)               # by the membership rule, unchanged
    assert run(_vc_jwt([VC]), policy).credential["type"] == [VC]


def test_verify_many_returns_a_per_item_error():
    batch = [_vc_jwt([VC]), _vc_jwt([VC, 5]), _vc_jwt(5), _vc_jwt(VC)]
    for results in (verify_many(batch), asyncio.run(verify_many_async(batch))):
        assert [r.ok for r in results] == [True, False, False, True]
        assert type(results[1].error) is ClaimsInvalid
        assert type(results[2].error) is ClaimsInvalid


@pytest.mark.skipif(not mldsa_available(), reason="ML-DSA needs cryptography>=48 on OpenSSL>=3.5")
@pytest.mark.parametrize("vc_type", [5, None, [VC, 5], {VC: 1}, ""])
def test_mldsa_lane_refuses_a_malformed_type(vc_type):
    from openvc.keys import MLDSASigningKey
    key = MLDSASigningKey.generate(kid="did:example:pq#0", alg="ML-DSA-65")
    suite = VcJwtProofSuite(allow_pq=True)
    token = _vc_jwt(vc_type, key=key, did="did:example:pq", alg="ML-DSA-65")
    with pytest.raises(ClaimsInvalid, match="`type` must be a non-empty string"):
        suite.verify(token, public_key_jwk=key.public_jwk())
    control = _vc_jwt([VC], key=key, did="did:example:pq", alg="ML-DSA-65")
    assert suite.verify(control, public_key_jwk=key.public_jwk()).credential["type"] == [VC]


# --------------------------------------------------------------------------- #
# Not decided here: the other lanes keep accepting a non-string member
# --------------------------------------------------------------------------- #

@PIPELINES
def test_di_jcs_still_accepts_an_array_type_with_a_non_string_member(run):
    """Data Integrity is unchanged by #433; a later decision on it should fail this test."""
    key = Ed25519SigningKey.generate(kid="_")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    doc = {"@context": [V2], "type": [VC, 5], "issuer": did,
           "validFrom": "2024-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:s"}}
    secured = EddsaJcsProofSuite().add_proof(
        doc, signing_key=key, verification_method=f"{did}#0")
    assert run(secured).credential["type"] == [VC, 5]


@PIPELINES
def test_sd_jwt_still_ignores_a_non_string_type_member(run):
    """#275: the `vc+sd-jwt` lane ignores non-string `type` entries on purpose; unchanged."""
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    body = {"iss": did, "issuer": did, "@context": [V2], "type": [VC, 5],
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:alice"}}
    head = {"alg": "ES256", "kid": f"{did}#0", "typ": "vc+sd-jwt"}
    signing_input = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(body).encode())}"
    token = f"{signing_input}.{_b64(key.sign(signing_input.encode()))}~"
    assert run(token).credential is not None
