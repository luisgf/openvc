"""
tests/test_hostile_input.py — the typed-error boundary on attacker-controlled input
(issue #99).

The fail-closed contract has two invariants a hostile token must never break:
every failure surfaces as a typed ``OpenvcError`` (never a bare ``AttributeError`` /
``ValueError`` from deep in a parser), and ``verify_many`` isolates failures so one
bad element never aborts the batch. The regression these guard against: a JOSE
header/payload that is valid JSON but *not an object* (e.g. ``[0]``) used to crash
the untrusted *peek* path with ``AttributeError``, which escaped ``OpenvcError`` and
took the whole batch down with it.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from openvc import verify_credential, verify_many
from openvc.errors import OpenvcError
from openvc.proof._jcs import JcsError, canonicalize
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite

# JSON values that are valid JSON but not an object — the header/payload shapes that
# must fail closed with a typed MalformedToken rather than an AttributeError.
NON_OBJECT_JSON = [[0], 5, "x", None, True]
NON_OBJECT_IDS = ["list", "int", "string", "null", "bool"]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jose(header: object, payload: object, sig: bytes = b"\x00" * 64) -> str:
    """A compact JWS string with arbitrary (possibly non-object) header/payload."""
    h, p = _b64u(json.dumps(header).encode()), _b64u(json.dumps(payload).encode())
    return f"{h}.{p}.{_b64u(sig)}"


@pytest.mark.parametrize("payload", NON_OBJECT_JSON, ids=NON_OBJECT_IDS)
def test_verify_credential_typed_on_non_object_payload(payload):
    tok = _jose({"alg": "ES256", "typ": "vc+sd-jwt"}, payload) + "~"
    with pytest.raises(OpenvcError):
        verify_credential(tok)


@pytest.mark.parametrize("payload", NON_OBJECT_JSON, ids=NON_OBJECT_IDS)
def test_vc_jwt_peek_typed_on_non_object_payload(payload):
    with pytest.raises(OpenvcError):
        VcJwtProofSuite().peek_issuer(_jose({"alg": "ES256"}, payload))
    with pytest.raises(OpenvcError):
        VcJwtProofSuite().peek_claims(_jose({"alg": "ES256"}, payload))


@pytest.mark.parametrize("payload", NON_OBJECT_JSON, ids=NON_OBJECT_IDS)
def test_sd_jwt_peek_typed_on_non_object_payload(payload):
    with pytest.raises(OpenvcError):
        SdJwtVcProofSuite().peek_issuer(_jose({"alg": "ES256", "typ": "vc+sd-jwt"}, payload) + "~")


@pytest.mark.parametrize("header", NON_OBJECT_JSON, ids=NON_OBJECT_IDS)
def test_typed_on_non_object_header(header):
    with pytest.raises(OpenvcError):
        VcJwtProofSuite().peek_issuer(_jose(header, {"iss": "did:example:x"}))


def test_vc_jwt_peek_typed_on_non_string_iss_and_non_object_vc():
    # a non-string iss must not slip through and later crash int.startswith
    with pytest.raises(OpenvcError):
        VcJwtProofSuite().peek_issuer(_jose({"alg": "ES256"}, {"iss": 123}))
    # a vc that is not an object must not crash (payload.get("vc") or {}).get(...)
    with pytest.raises(OpenvcError):
        VcJwtProofSuite().peek_issuer(_jose({"alg": "ES256"}, {"vc": [1, 2]}))


def test_verify_many_isolates_a_non_object_payload():
    """The A1 regression: a hostile non-object-payload token must become a fail-closed
    BatchResult, never abort the sibling that follows it."""
    hostile = _jose({"alg": "ES256", "typ": "vc+sd-jwt"}, [0]) + "~"
    results = verify_many([hostile, "not.a.jwt", hostile])
    assert len(results) == 3
    assert all((not r.ok) and isinstance(r.error, OpenvcError) for r in results)


def test_verify_vp_token_typed_on_non_object_payload():
    from openvc.openid4vp import verify_vp_token

    hostile = _jose({"alg": "ES256", "typ": "vc+sd-jwt"}, [0]) + "~"
    dcql = {"credentials": [{"id": "my_credential", "format": "dc+sd-jwt",
                             "meta": {"vct_values": ["https://example/vct"]}}]}
    with pytest.raises(OpenvcError):     # OpenID4VPError family subclasses OpenvcError
        verify_vp_token({"my_credential": [hostile]}, dcql_query=dcql,
                        nonce="n", client_id="x509_san_dns:verifier.example")


# --- the sibling untyped-escape gaps (same class, different subsystem) --------- #

def test_jcs_lone_surrogate_is_typed():
    # json.loads can produce a lone surrogate; it must not leak UnicodeEncodeError
    with pytest.raises(JcsError):
        canonicalize({"a": "\ud800"})


def test_data_integrity_malformed_ed25519_jwk_is_typed():
    from openvc.proof.data_integrity import ProofMalformed, _verify_ed25519

    for bad_x in ["!!!not-base64!!!", "AAAA", 123, None]:
        with pytest.raises(ProofMalformed):
            _verify_ed25519({"kty": "OKP", "crv": "Ed25519", "x": bad_x}, b"data", b"sig")


def test_ecdsa_sd_hostile_proofvalue_is_typed():
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite, ProofValueMalformed

    for bad in [123, None, {"x": 1}]:
        derived = {"@context": ["https://www.w3.org/ns/credentials/v2"],
                   "proof": {"type": "DataIntegrityProof", "cryptosuite": "ecdsa-sd-2023",
                             "proofValue": bad}}
        with pytest.raises(ProofValueMalformed):
            EcdsaSdProofSuite().verify(derived)
    # a well-typed but garbage multibase string decodes-and-fails, still typed
    derived["proof"]["proofValue"] = "u!!!!not-base64"
    with pytest.raises(OpenvcError):
        EcdsaSdProofSuite().verify(derived)


def test_ecdsa_sd_unknown_context_is_typed():
    """A derived credential whose @context cannot be resolved must fail closed as a
    typed ProofError, not a raw pyld JsonLdError."""
    pytest.importorskip("pyld")
    from datetime import datetime, timezone

    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
    from openvc.proof.errors import ProofError

    fx = Path(__file__).parent / "fixtures" / "ecdsa_sd" / "prc" / "derivedRevealDocument.json"
    reveal = json.loads(fx.read_text())
    reveal["@context"] = ["https://unknown.example/does-not-exist"]
    with pytest.raises(ProofError):
        EcdsaSdProofSuite().verify(reveal, now=datetime(2025, 6, 1, tzinfo=timezone.utc))


def test_ebsi_get_json_non_object_is_typed():
    httpx = pytest.importorskip("httpx")
    from openvc_ebsi.errors import MalformedRegistryResponse
    from openvc_ebsi.http import EbsiHttpClient

    def _client(handler):
        c = EbsiHttpClient(allowed_hosts={"api-pilot.ebsi.eu"})
        c._client = httpx.Client(transport=httpx.MockTransport(handler))
        return c

    url = "https://api-pilot.ebsi.eu/anything"
    # a 200 whose body is a JSON array (not the object the adapter needs)
    with pytest.raises(MalformedRegistryResponse):
        _client(lambda req: httpx.Response(200, json=[1, 2, 3])).get_json(url)
    # a 200 whose body is not JSON at all
    with pytest.raises(MalformedRegistryResponse):
        _client(lambda req: httpx.Response(200, content=b"<html>not json")).get_json(url)
