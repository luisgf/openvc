"""
tests/test_typed_error_vc_shape.py — a credential's ``type`` / a presentation's
``verifiableCredential`` with a non-container shape stays inside the typed-error
boundary.

Two findings from the adversarial review of #190, plus a sibling of the first one:

* ``detect_format`` ran ``"EnvelopedVerifiableCredential" in types`` on a dict
  credential whose ``type`` was ``null`` / a number / a bool, a bare ``TypeError``. It
  was reachable at the top level, inside an ``EnvelopedVerifiableCredential``, and nested in
  ``jwt_vc_json`` / ``ldp_vc`` presentations, and it aborted a whole ``verify_many`` batch.
  The same membership test in ``_check_types`` crashed on a signed VC-JWT whose
  ``vc.type`` was ``null`` once ``policy.expected_types`` was set.
* ``VpJwtProofSuite.verify`` ran ``list(raw)`` on ``vp.verifiableCredential`` = ``5`` /
  ``null`` / ``true`` / ``1.5``, a bare ``TypeError``. Separately, a ``jwt_vc_json`` VP
  carrying no credential was accepted by ``verify_vp_token`` with zero credentials,
  although the ``ldp_vc`` lane rejects that.

Each test asserts the **typed class**, not just ``OpenvcError``, so a regression to a
different (looser) failure mode is caught. The suite itself keeps accepting a
credential-less VP (VCDM allows one, e.g. DID Auth). Only the OpenID4VP lane, which
answers a Credential Query, requires a credential.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import verify_credential, verify_many, verify_many_async
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import VpTokenMalformed, verify_vp_token
from openvc.proof._jws import sign_compact
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import (
    FORMAT_DI_EDDSA_JCS,
    TypeMismatch,
    UnknownCredentialFormat,
    VerificationPolicy,
    detect_format,
)

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
JWT_VC_DCQL = {"credentials": [{"id": "q", "format": "jwt_vc_json"}]}
LDP_VC_DCQL = {"credentials": [{"id": "q", "format": "ldp_vc"}]}

# A dict credential's `type` that is neither a string nor an array (VCDM).
NON_CONTAINER_TYPES = [
    pytest.param(None, id="null"), pytest.param(5, id="int"),
    pytest.param(1.5, id="float"), pytest.param(True, id="bool"),
    pytest.param({"a": 1}, id="object"),
]
# A `vp.verifiableCredential` that is neither a credential nor an array.
NON_CONTAINER_VCS = [
    pytest.param(5, id="int"), pytest.param(None, id="null"),
    pytest.param(True, id="bool"), pytest.param(1.5, id="float"),
]
_ABSENT = object()


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did): resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_ed25519():
    key = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())   # ed25519-pub
    return Ed25519SigningKey(key._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _did_key_p256()


@pytest.fixture(scope="module")
def holder():
    return _did_key_p256()


def _hostile_doc(type_value=None):
    """A dict credential with a hostile `type` and a proof (so it reaches detection)."""
    return {"@context": [V2], "type": type_value, "issuer": "did:example:i",
            "credentialSubject": {"id": "did:example:s"},
            "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022"}}


def _enveloped_json(doc):
    b64 = base64.b64encode(json.dumps(doc).encode()).decode()
    return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
            "id": f"data:application/vc+ld+json;base64,{b64}"}


def _vc_jwt(issuer, *, vc_type=("VerifiableCredential",)):
    """A VC-JWT signed by *issuer*; *vc_type* is written verbatim into ``vc.type``."""
    issuer_key, issuer_did = issuer
    now = int(time.time())
    vc = {"@context": [V2], "type": list(vc_type) if isinstance(vc_type, tuple) else vc_type,
          "issuer": issuer_did, "credentialSubject": {"id": "did:example:s"}}
    claims = {"iss": issuer_did, "sub": "did:example:s", "nbf": now, "iat": now, "vc": vc}
    header = {"alg": issuer_key.alg, "typ": "JWT", "kid": issuer_key.kid}
    return sign_compact(header, claims, signing_key=issuer_key)


def _vp_jwt(holder, vcs=_ABSENT):
    """A VP-JWT signed by *holder*, bound to CLIENT_ID + NONCE, whose
    ``vp.verifiableCredential`` is *vcs* VERBATIM (omitted when _ABSENT). The suite's
    ``sign`` always writes a list, so the hostile shapes are hand-signed."""
    holder_key, holder_did = holder
    now = int(time.time())
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": holder_did}
    if vcs is not _ABSENT:
        vp["verifiableCredential"] = vcs
    claims = {"iss": holder_did, "aud": CLIENT_ID, "nonce": NONCE,
              "nbf": now, "iat": now, "vp": vp}
    header = {"alg": holder_key.alg, "typ": "JWT", "kid": holder_key.kid}
    return sign_compact(header, claims, signing_key=holder_key)


def _ldp_vp(entries):
    vp_key, vp_did = _did_key_ed25519()
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": vp_did,
          "verifiableCredential": list(entries)}
    return EddsaJcsProofSuite().add_proof(
        vp, signing_key=vp_key, verification_method=vp_key.kid,
        proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)


def _suite_verify(vp):
    return VpJwtProofSuite().verify(vp, audience=CLIENT_ID, nonce=NONCE)


def _vp_token(vp, dcql):
    return verify_vp_token({"q": [vp]}, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# 1. a dict credential's non-container `type`
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("type_value", NON_CONTAINER_TYPES)
def test_detect_format_rejects_non_container_type(type_value):
    with pytest.raises(UnknownCredentialFormat, match="`type` must be a string or an array"):
        detect_format(_hostile_doc(type_value))


@pytest.mark.parametrize("type_value", NON_CONTAINER_TYPES)
def test_verify_credential_typed_on_non_container_type(type_value):
    with pytest.raises(UnknownCredentialFormat, match="`type`"):
        verify_credential(_hostile_doc(type_value))


@pytest.mark.parametrize("type_value", NON_CONTAINER_TYPES)
def test_enveloped_non_container_type_is_typed(type_value):
    # the unwrapped payload is re-dispatched through detect_format
    with pytest.raises(UnknownCredentialFormat, match="`type`"):
        verify_credential(_enveloped_json(_hostile_doc(type_value)))


@pytest.mark.parametrize("type_value", [
    pytest.param("VerifiableCredential", id="string"),
    pytest.param(["VerifiableCredential"], id="array"),
    pytest.param(("VerifiableCredential",), id="tuple-python-api"),
    pytest.param(_ABSENT, id="absent"),
])
def test_detect_format_still_classifies_a_well_shaped_or_absent_type(type_value):
    # No over-correction: a string, an array (a tuple, from a Python caller that built
    # the dict in-process; JCS signs it as an array), or no `type` at all still classify
    # by the proof (a missing `type` is left for the proof suite / VCDM checks to judge).
    doc = _hostile_doc()
    if type_value is _ABSENT:
        del doc["type"]
    else:
        doc["type"] = type_value
    assert detect_format(doc) == FORMAT_DI_EDDSA_JCS


def _deeply_nested_list(depth: int = 100_000) -> list:
    deep: list = []
    for _ in range(depth):
        deep = [deep]
    return deep


def test_deeply_nested_cryptosuite_is_typed():
    # The error message used to repr() the cryptosuite: a deeply nested one (json.loads
    # accepts ~116k levels on 3.14) raised a bare RecursionError from detect_format.
    doc = {"type": ["VerifiableCredential"],
           "proof": {"type": "DataIntegrityProof", "cryptosuite": _deeply_nested_list()}}
    with pytest.raises(UnknownCredentialFormat, match="cryptosuite list"):
        detect_format(doc)
    (result,) = verify_many([doc])
    assert isinstance(result.error, UnknownCredentialFormat)


def test_verify_many_isolates_a_non_container_type(issuer):
    # The batch repro: a bare TypeError used to abort the whole call.
    good = _vc_jwt(issuer)
    results = verify_many([good, _hostile_doc(None), _enveloped_json(_hostile_doc(5)), good])
    assert [r.ok for r in results] == [True, False, False, True]
    assert isinstance(results[1].error, UnknownCredentialFormat)
    assert isinstance(results[2].error, UnknownCredentialFormat)
    assert results[0].result is not None and results[3].result is not None


def test_verify_many_async_isolates_a_non_container_type(issuer):
    good = _vc_jwt(issuer)
    results = asyncio.run(verify_many_async([good, _hostile_doc(True), good]))
    assert [r.ok for r in results] == [True, False, True]
    assert isinstance(results[1].error, UnknownCredentialFormat)


def test_jwt_vc_json_nested_non_container_type_is_typed(holder):
    vp = VpJwtProofSuite().sign([_hostile_doc(None)], holder_key=holder[0],
                                audience=CLIENT_ID, nonce=NONCE)
    with pytest.raises(UnknownCredentialFormat, match="`type`"):
        _vp_token(vp, JWT_VC_DCQL)


def test_jwt_vc_json_enveloped_non_container_type_is_typed(holder):
    vp = VpJwtProofSuite().sign([_enveloped_json(_hostile_doc(1.5))], holder_key=holder[0],
                                audience=CLIENT_ID, nonce=NONCE)
    with pytest.raises(UnknownCredentialFormat, match="`type`"):
        _vp_token(vp, JWT_VC_DCQL)


def test_ldp_vc_nested_non_container_type_is_typed():
    with pytest.raises(UnknownCredentialFormat, match="`type`"):
        _vp_token(_ldp_vp([_hostile_doc(None)]), LDP_VC_DCQL)


# -- sibling: a signed VC-JWT's `vc.type` meets policy.expected_types ------- #

@pytest.mark.parametrize("vc_type", [
    pytest.param(None, id="null"), pytest.param(5, id="int"), pytest.param(True, id="bool"),
    # an object whose KEY is the expected type used to pass `"X" in {"X": ...}` silently
    pytest.param({"VerifiableCredential": True}, id="object-keyed-by-expected-type"),
])
def test_vc_jwt_non_container_type_with_expected_types_is_typed(issuer, vc_type):
    # The issuer signs the token, but any did:key is an issuer: the shape is hostile.
    token = _vc_jwt(issuer, vc_type=vc_type)
    policy = VerificationPolicy(expected_types=["VerifiableCredential"])
    with pytest.raises(TypeMismatch, match="missing required type"):
        verify_credential(token, policy=policy)
    with pytest.raises(ClaimsInvalid, match="missing required type"):
        VcJwtProofSuite().verify(token, public_key_jwk=issuer[0].public_jwk(),
                                 expected_types=["VerifiableCredential"])
    # ...and it never aborts a batch
    results = verify_many([_vc_jwt(issuer), token], policy=policy)
    assert results[0].ok and isinstance(results[1].error, TypeMismatch)


# --------------------------------------------------------------------------- #
# 2. a VP-JWT's non-container `vp.verifiableCredential`
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("vcs", NON_CONTAINER_VCS)
def test_vp_jwt_suite_rejects_non_container_verifiable_credential(holder, vcs):
    with pytest.raises(ClaimsInvalid, match="verifiableCredential must be"):
        _suite_verify(_vp_jwt(holder, vcs))


@pytest.mark.parametrize("vcs", NON_CONTAINER_VCS)
def test_jwt_vc_json_rejects_non_container_verifiable_credential(holder, vcs):
    with pytest.raises(ClaimsInvalid, match="verifiableCredential must be"):
        _vp_token(_vp_jwt(holder, vcs), JWT_VC_DCQL)


@pytest.mark.parametrize("vcs", [pytest.param([], id="empty"),
                                 pytest.param(_ABSENT, id="absent")])
def test_vp_jwt_suite_keeps_accepting_a_credential_less_vp(holder, vcs):
    # Public-suite behaviour is unchanged: VCDM allows a VP with no credential (DID Auth).
    verified = _suite_verify(_vp_jwt(holder, vcs))
    assert verified.credentials == ()
    assert verified.holder == holder[1]


@pytest.mark.parametrize("vcs", [pytest.param([], id="empty"),
                                 pytest.param(_ABSENT, id="absent")])
def test_jwt_vc_json_rejects_a_credential_less_vp(holder, vcs):
    # Mirrors the ldp_vc lane: a Presentation answering a Credential Query must carry one.
    with pytest.raises(VpTokenMalformed, match="embeds no verifiableCredential"):
        _vp_token(_vp_jwt(holder, vcs), JWT_VC_DCQL)


@pytest.mark.parametrize("vcs", [pytest.param([], id="empty"),
                                 pytest.param(_ABSENT, id="absent")])
def test_ldp_vc_rejects_a_credential_less_vp_too(vcs):
    # The parity this fix copies: the ldp_vc lane already failed closed here.
    vp_key, vp_did = _did_key_ed25519()
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": vp_did}
    if vcs is not _ABSENT:
        vp["verifiableCredential"] = vcs
    vp = EddsaJcsProofSuite().add_proof(
        vp, signing_key=vp_key, verification_method=vp_key.kid,
        proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    with pytest.raises(VpTokenMalformed, match="embeds no verifiableCredential"):
        _vp_token(vp, LDP_VC_DCQL)


def test_jwt_vc_json_with_a_credential_still_verifies(issuer, holder):
    # The control: the new emptiness check does not reject a normal presentation.
    (pres,) = _vp_token(_vp_jwt(holder, [_vc_jwt(issuer)]), JWT_VC_DCQL).for_query("q")
    assert len(pres.credentials) == 1 and pres.holder == holder[1]
