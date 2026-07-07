"""
tests/test_conformance_openid4vp.py — verifier-side conformance / drift alarm for the
OpenID4VP 1.0 + HAIP presentation path (issue #20).

Two recorded, **offline** fixtures under ``fixtures/openid4vp`` — a plain SD-JWT VC
``vp_token`` and a HAIP ``direct_post.jwt`` (an encrypted ``vp_token`` JWE) — are
verified end to end through the public API. They are recorded from openvc with fixed
keys (ES256 signatures and the ECDH-ES ephemeral key are non-deterministic, so the
bytes are frozen once, like the EBSI pilot and ecdsa-sd interop fixtures). If a change
to the verifier — the DCQL ``vp_token`` shape handling, the KB-JWT ``nonce``/``aud``
binding, or the JWE ``ECDH-ES`` decrypt — breaks what a conformant response requires,
these fail loudly.

This is a **drift alarm on the wire contract**, not a live OIDF conformance run (that
would drive the hosted self-certification suite — a separate, networked follow-up). The
byte-exact *third-party* vectors (RFC 7518 App C, the OpenID4VP §8.3 JWE, the W3C
eddsa-jcs example, the RFC 8785 suite) are pinned in ``test_jwe`` / ``test_di_jcs``.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from openvc import verify_encrypted_vp_response, verify_vp_token
from openvc.jwe import JweDecryptionFailed
from openvc.keys import P256KeyAgreementKey
from openvc.openid4vp import FORMAT_SD_JWT_VC
from openvc.proof.errors import ClaimsInvalid

FX = Path(__file__).parent / "fixtures" / "openid4vp"


def _load(name: str) -> dict:
    return json.loads((FX / name).read_text())


# --------------------------------------------------------------------------- #
# plain SD-JWT VC vp_token (OpenID4VP 1.0)
# --------------------------------------------------------------------------- #

def test_sd_jwt_vc_vp_token_conforms_and_verifies():
    v = _load("sd_jwt_vc_vp_token.json")
    # wire shape: vp_token is a JSON object keyed by the DCQL Credential Query id,
    # values are arrays (§8.1); the presentation is an SD-JWT (has a '~').
    assert set(v["vp_token"]) == {c["id"] for c in v["dcql_query"]["credentials"]}
    assert isinstance(v["vp_token"]["my_credential"], list)
    assert "~" in v["vp_token"]["my_credential"][0]

    result = verify_vp_token(
        v["vp_token"], dcql_query=v["dcql_query"], nonce=v["nonce"], client_id=v["client_id"])
    (p,) = result.for_query("my_credential")
    assert p.format == FORMAT_SD_JWT_VC == v["expect"]["format"]
    assert p.raw.claims["given_name"] == v["expect"]["given_name"]
    assert p.raw.claims["family_name"] == v["expect"]["family_name"]


def test_sd_jwt_vc_vp_token_is_binding_evident():
    v = _load("sd_jwt_vc_vp_token.json")
    with pytest.raises(ClaimsInvalid):                    # a stale nonce must be rejected
        verify_vp_token(v["vp_token"], dcql_query=v["dcql_query"],
                        nonce="not-the-recorded-nonce", client_id=v["client_id"])


# --------------------------------------------------------------------------- #
# HAIP direct_post.jwt — an encrypted vp_token (JWE ECDH-ES + A256GCM)
# --------------------------------------------------------------------------- #

def test_haip_encrypted_vp_token_conforms_and_verifies():
    h = _load("haip_encrypted_vp_token.json")
    key = P256KeyAgreementKey.from_jwk(h["verifier_encryption_key"], kid="verifier#enc")
    result = verify_encrypted_vp_response(
        h["response_jwe"], key=key, dcql_query=h["dcql_query"],
        nonce=h["nonce"], client_id=h["client_id"])
    (p,) = result.for_query("my_credential")
    assert p.format == h["expect"]["format"]
    assert p.raw.claims["given_name"] == h["expect"]["given_name"]


def test_haip_response_is_a_conformant_jwe():
    h = _load("haip_encrypted_vp_token.json")
    parts = h["response_jwe"].split(".")
    assert len(parts) == 5                                # compact JWE
    assert parts[1] == ""                                 # direct ECDH-ES: empty encrypted key
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert header["alg"] == "ECDH-ES"                     # HAIP-mandated key agreement
    assert header["enc"] in ("A128GCM", "A256GCM")        # HAIP-mandated content encryption
    assert header["epk"]["crv"] == "P-256" and header["epk"]["kty"] == "EC"


def test_haip_encrypted_response_is_tamper_evident():
    h = _load("haip_encrypted_vp_token.json")
    key = P256KeyAgreementKey.from_jwk(h["verifier_encryption_key"], kid="verifier#enc")
    parts = h["response_jwe"].split(".")
    ciphertext = list(parts[3])
    ciphertext[0] = "A" if ciphertext[0] != "A" else "B"
    parts[3] = "".join(ciphertext)
    with pytest.raises(JweDecryptionFailed):
        verify_encrypted_vp_response(
            ".".join(parts), key=key, dcql_query=h["dcql_query"],
            nonce=h["nonce"], client_id=h["client_id"])
