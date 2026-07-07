"""
09 — HAIP encrypted response: a wallet returns the `vp_token` inside a JWE
(`direct_post.jwt`); the verifier decrypts it with its key-agreement key and verifies
the presentation in one call. openvc only *decrypts* (a verifier act) — the wallet-side
encryption here is a plain `cryptography` ECDH-ES + AES-GCM to make the example run.

Run:  python examples/09_haip_encrypted_response.py
"""
import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from _common import did_key_p256

from openvc import verify_encrypted_vp_response
from openvc.jwe import _concat_kdf                     # KDF is public (RFC 7518 §4.6)
from openvc.keys import P256KeyAgreementKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"
VCT = "https://credentials.example.com/identity_credential"


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def wallet_encrypt(recipient_jwk, response_obj, enc="A256GCM"):
    """Wallet side (NOT part of openvc): ECDH-ES to the verifier's key, then AES-GCM."""
    eph = ec.generate_private_key(ec.SECP256R1())
    rx = int.from_bytes(base64.urlsafe_b64decode(recipient_jwk["x"] + "=="), "big")
    ry = int.from_bytes(base64.urlsafe_b64decode(recipient_jwk["y"] + "=="), "big")
    z = eph.exchange(ec.ECDH(),
                     ec.EllipticCurvePublicNumbers(rx, ry, ec.SECP256R1()).public_key())
    e = eph.public_key().public_numbers()
    header = {"alg": "ECDH-ES", "enc": enc, "epk": {
        "kty": "EC", "crv": "P-256", "x": _b64u(e.x.to_bytes(32, "big")),
        "y": _b64u(e.y.to_bytes(32, "big"))}}
    cek = _concat_kdf(z, 256 if enc == "A256GCM" else 128, enc.encode(), b"", b"")
    protected = _b64u(json.dumps(header, separators=(",", ":")).encode())
    iv = os.urandom(12)
    ct_tag = AESGCM(cek).encrypt(iv, json.dumps(response_obj).encode(), protected.encode())
    return f"{protected}..{_b64u(iv)}.{_b64u(ct_tag[:-16])}.{_b64u(ct_tag[-16:])}"


issuer, issuer_did = did_key_p256()
holder, holder_did = did_key_p256()

# Issuer -> holder, then holder presents the SD-JWT VC bound to this verifier.
issued = SdJwtVcProofSuite().issue(
    {"iss": issuer_did, "given_name": "Ada", "sub": holder_did},
    signing_key=issuer, vct=VCT, disclosable=["given_name"], holder_jwk=holder.public_jwk())
presentation = SdJwtVcProofSuite().create_presentation(
    issued, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)

# The verifier owns a P-256 key-agreement key; it publishes the public half (use:"enc").
verifier_key = P256KeyAgreementKey.generate(kid="verifier#enc")

# Wallet encrypts the OpenID4VP response object to that key (direct_post.jwt).
response_jwe = wallet_encrypt(
    verifier_key.public_jwk(),
    {"vp_token": {"my_credential": [presentation]}, "state": "session-42"})
print("encrypted response (JWE):", response_jwe[:48] + "…")

# Verifier: one call — decrypt + verify the vp_token's binding.
dcql_query = {"credentials": [
    {"id": "my_credential", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}}]}
result = verify_encrypted_vp_response(
    response_jwe, key=verifier_key, dcql_query=dcql_query, nonce=NONCE, client_id=CLIENT_ID)
(p,) = result.for_query("my_credential")
print("decrypted + verified:", p.format)
print("given_name (disclosed):", p.raw.claims["given_name"])
