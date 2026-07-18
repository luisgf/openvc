"""RFC 7515 §4.1.11 — unknown JWS ``crit`` extensions fail closed on every lane (#125).

openvc processes no JWS extension header parameters, so a token that marks any as
critical must be rejected — on the VC-JWT lane (where pre-2.13 PyJWT accepted it,
CVE-2026-32597), and on the hand-rolled JWS lanes (SD-JWT issuer JWT, KB-JWT, the
IETF status-list token), which never consulted ``crit`` at all. The COSE and JWE
paths already took this stance; these tests pin the JWS lanes to it.
"""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc.keys import Ed25519SigningKey, mldsa_available
from openvc.proof._jws import sign_compact, verify_compact
from openvc.proof.errors import MalformedToken, UnsupportedAlgorithm
from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status.issue import verify_status_list_token

_FAR_FUTURE = 4102444800  # 2100-01-01, keeps temporal checks out of the way


def _key(kid: str = "did:example:issuer#k1") -> Ed25519SigningKey:
    return Ed25519SigningKey(ed25519.Ed25519PrivateKey.generate(), kid=kid)


def test_verify_compact_rejects_unknown_crit() -> None:
    key = _key()
    token = sign_compact(
        {"alg": key.alg, "kid": key.kid, "crit": ["exp"], "exp": _FAR_FUTURE},
        {"iss": "did:example:issuer"}, signing_key=key)
    with pytest.raises(MalformedToken, match="crit"):
        verify_compact(token, public_key_jwk=key.public_jwk())


def test_verify_compact_without_crit_still_verifies() -> None:
    key = _key()
    token = sign_compact(
        {"alg": key.alg, "kid": key.kid}, {"iss": "did:example:issuer"}, signing_key=key)
    header, payload = verify_compact(token, public_key_jwk=key.public_jwk())
    assert payload["iss"] == "did:example:issuer"


def test_vc_jwt_verify_rejects_unknown_crit() -> None:
    # The crit gate must fire in openvc, before the token ever reaches PyJWT.
    key = _key()
    token = sign_compact(
        {"alg": key.alg, "typ": "JWT", "kid": key.kid, "crit": ["b64"], "b64": True},
        {"iss": "did:example:issuer", "vc": {}, "exp": _FAR_FUTURE}, signing_key=key)
    with pytest.raises(MalformedToken, match="crit"):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


def test_sd_jwt_issuer_jwt_rejects_unknown_crit() -> None:
    key = _key()
    issuer_jwt = sign_compact(
        {"alg": key.alg, "typ": "dc+sd-jwt", "crit": ["x5t#S256"]},
        {"iss": "did:example:issuer", "exp": _FAR_FUTURE}, signing_key=key)
    with pytest.raises(MalformedToken, match="crit"):
        SdJwtVcProofSuite().verify(issuer_jwt + "~", public_key_jwk=key.public_jwk())


def test_status_list_token_entrypoint_rejects_unknown_crit() -> None:
    # The public status-list lane, not just the underlying verify_compact.
    key = _key()
    token = sign_compact(
        {"alg": key.alg, "typ": "statuslist+jwt", "crit": ["ttl"]},
        {"sub": "https://status.example/1", "iat": 1, "exp": _FAR_FUTURE,
         "status_list": {"bits": 1, "lst": "eNrbuRgAAhcBXQ"}},
        signing_key=key)
    with pytest.raises(MalformedToken, match="crit"):
        verify_status_list_token(token, public_key_jwk=key.public_jwk())


@pytest.mark.skipif(
    not mldsa_available(), reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")
def test_mldsa_lane_rejects_unknown_crit() -> None:
    # The crit gate runs BEFORE the ALLOWED_ALGS_PQ branch; a refactor moving it
    # into the PyJWT-only branch would silently reopen the PQ lane.
    from openvc.keys import MLDSASigningKey
    key = MLDSASigningKey.generate(kid="did:example:pq#k", alg="ML-DSA-65")
    token = sign_compact(
        {"alg": key.alg, "typ": "JWT", "kid": key.kid, "crit": ["b64"]},
        {"iss": "did:example:pq", "vc": {}, "exp": _FAR_FUTURE},
        signing_key=key, allowed_algs=frozenset({"ML-DSA-65"}))
    with pytest.raises(MalformedToken, match="crit"):
        VcJwtProofSuite(allow_pq=True).verify(token, public_key_jwk=key.public_jwk())


def _b64json(obj: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_alg_allowlist_takes_precedence_over_crit() -> None:
    # A token that is wrong twice (RS256 AND crit) must keep raising the
    # allow-list error — the crit gate never runs before the alg gate.
    token = f'{_b64json({"alg": "RS256", "crit": ["x"]})}.{_b64json({"iss": "i"})}.AAAA'
    with pytest.raises(UnsupportedAlgorithm):
        verify_compact(token, public_key_jwk={"kty": "OKP"})
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().verify(token, public_key_jwk={"kty": "OKP"})


def test_sd_jwt_typ_precedence_over_crit() -> None:
    key = _key()
    issuer_jwt = sign_compact(
        {"alg": key.alg, "typ": "JOSE", "crit": ["x"]}, {"iss": "i"}, signing_key=key)
    with pytest.raises(SdJwtError):
        SdJwtVcProofSuite().verify(issuer_jwt + "~", public_key_jwk=key.public_jwk())


def test_kb_jwt_rejects_unknown_crit() -> None:
    issuer, holder = _key(), _key("did:example:holder#k1")
    issuer_jwt = sign_compact(
        {"alg": issuer.alg, "typ": "dc+sd-jwt"},
        {"iss": "did:example:issuer", "exp": _FAR_FUTURE,
         "cnf": {"jwk": holder.public_jwk()}},
        signing_key=issuer)
    kb_jwt = sign_compact(
        {"alg": holder.alg, "typ": "kb+jwt", "crit": ["nonce2"]},
        {"aud": "verifier", "nonce": "n-1", "iat": 1, "sd_hash": "x"},
        signing_key=holder)
    with pytest.raises(MalformedToken, match="crit"):
        SdJwtVcProofSuite().verify(
            issuer_jwt + "~" + kb_jwt,
            public_key_jwk=issuer.public_jwk(), audience="verifier", nonce="n-1")
