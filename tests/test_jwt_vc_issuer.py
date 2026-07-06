"""
tests/test_jwt_vc_issuer.py — SD-JWT VC / OID4VC issuer-key discovery via
/.well-known/jwt-vc-issuer (Etapa 8), and its opt-in use through the pipeline.

All offline: the https fetch is stubbed, so no network and no real well-known host.
"""
from __future__ import annotations

import pytest

from openvc import VerificationPolicy, verify_credential
from openvc.jwt_vc_issuer import (
    JwtVcIssuerError,
    jwt_vc_issuer_metadata_url,
    resolve_jwt_vc_issuer_key,
)
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.verify import KeyResolutionFailed

ISS = "https://issuer.example"
VC2 = "https://www.w3.org/ns/credentials/v2"


# --------------------------------------------------------------------------- #
# metadata URL construction
# --------------------------------------------------------------------------- #

def test_metadata_url():
    wk = "/.well-known/jwt-vc-issuer"
    assert jwt_vc_issuer_metadata_url("https://ex.com") == f"https://ex.com{wk}"
    assert jwt_vc_issuer_metadata_url("https://ex.com/") == f"https://ex.com{wk}"
    assert jwt_vc_issuer_metadata_url("https://ex.com/tenant/1") == f"https://ex.com{wk}/tenant/1"
    with pytest.raises(JwtVcIssuerError):
        jwt_vc_issuer_metadata_url("http://ex.com")             # not https
    with pytest.raises(JwtVcIssuerError):
        jwt_vc_issuer_metadata_url("did:web:ex.com")


# --------------------------------------------------------------------------- #
# key resolution
# --------------------------------------------------------------------------- #

def _fetch(mapping):
    def fetch(url):
        try:
            return mapping[url]
        except KeyError:
            raise AssertionError(f"unexpected fetch {url!r}")
    return fetch


def test_resolve_inline_jwks_by_kid():
    jwk = {"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "kid": "k1"}
    fetch = _fetch({f"{ISS}/.well-known/jwt-vc-issuer": {"issuer": ISS, "jwks": {"keys": [jwk]}}})
    assert resolve_jwt_vc_issuer_key(ISS, "k1", fetch=fetch) == jwk


def test_resolve_via_jwks_uri_single_key_no_kid():
    jwk = {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}
    fetch = _fetch({
        f"{ISS}/.well-known/jwt-vc-issuer": {"issuer": ISS, "jwks_uri": f"{ISS}/jwks"},
        f"{ISS}/jwks": {"keys": [jwk]},
    })
    assert resolve_jwt_vc_issuer_key(ISS, None, fetch=fetch) == jwk


def test_resolve_rejects_issuer_mismatch():
    fetch = _fetch({f"{ISS}/.well-known/jwt-vc-issuer":
                    {"issuer": "https://evil.example", "jwks": {"keys": [{"kty": "EC"}]}}})
    with pytest.raises(JwtVcIssuerError, match="issuer"):
        resolve_jwt_vc_issuer_key(ISS, None, fetch=fetch)


def test_resolve_rejects_missing_kid_and_ambiguous_and_private():
    base = f"{ISS}/.well-known/jwt-vc-issuer"
    with pytest.raises(JwtVcIssuerError, match="kid"):
        resolve_jwt_vc_issuer_key(ISS, "want", fetch=_fetch(
            {base: {"issuer": ISS, "jwks": {"keys": [{"kty": "EC", "kid": "other"}]}}}))
    with pytest.raises(JwtVcIssuerError, match="multiple"):
        resolve_jwt_vc_issuer_key(ISS, None, fetch=_fetch(
            {base: {"issuer": ISS, "jwks": {"keys": [{"kty": "EC"}, {"kty": "EC"}]}}}))
    with pytest.raises(JwtVcIssuerError, match="public"):
        resolve_jwt_vc_issuer_key(ISS, None, fetch=_fetch(
            {base: {"issuer": ISS, "jwks": {"keys": [{"kty": "EC", "d": "secret"}]}}}))
    with pytest.raises(JwtVcIssuerError, match="jwks"):
        resolve_jwt_vc_issuer_key(ISS, None, fetch=_fetch({base: {"issuer": ISS}}))


# --------------------------------------------------------------------------- #
# pipeline integration (opt-in)
# --------------------------------------------------------------------------- #

def _https_issuer_token():
    sk = P256SigningKey.generate(kid="key-1")
    cred = {
        "@context": [VC2], "id": "urn:uuid:1", "type": ["VerifiableCredential"],
        "issuer": ISS, "credentialSubject": {"id": "did:example:subject"},
    }
    token = VcJwtProofSuite().sign(cred, signing_key=sk)
    jwk = dict(sk.public_jwk(), kid="key-1")
    return token, jwk


def test_pipeline_resolves_https_issuer_via_well_known():
    token, jwk = _https_issuer_token()
    fetch = _fetch({f"{ISS}/.well-known/jwt-vc-issuer": {"issuer": ISS, "jwks": {"keys": [jwk]}}})
    result = verify_credential(token, jwt_vc_issuer_fetch=fetch,
                               policy=VerificationPolicy(require_status=False))
    assert result.format == "vc-jwt" and result.issuer == ISS


def test_pipeline_https_issuer_without_fetch_fails_closed():
    token, _ = _https_issuer_token()
    with pytest.raises(KeyResolutionFailed, match="https"):
        verify_credential(token, policy=VerificationPolicy(require_status=False))


def test_pipeline_https_issuer_substitution_rejected():
    token, jwk = _https_issuer_token()
    fetch = _fetch({f"{ISS}/.well-known/jwt-vc-issuer":
                    {"issuer": "https://evil.example", "jwks": {"keys": [jwk]}}})
    with pytest.raises(KeyResolutionFailed):
        verify_credential(token, jwt_vc_issuer_fetch=fetch,
                          policy=VerificationPolicy(require_status=False))


def test_pipeline_wraps_fetch_ssrf_error_as_key_resolution_failed():
    # the SSRF-guarded fetch raises UnsafeUrlError (a DidError); the pipeline must
    # surface it as KeyResolutionFailed, not leak the raw fetch exception
    from openvc.fetch import UnsafeUrlError

    token, _ = _https_issuer_token()

    def fetch(url):
        raise UnsafeUrlError("resolved to a blocked internal address")

    with pytest.raises(KeyResolutionFailed):
        verify_credential(token, jwt_vc_issuer_fetch=fetch,
                          policy=VerificationPolicy(require_status=False))
