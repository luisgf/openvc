"""
06 — A remote SigningKey backend (AWS KMS / Vault Transit / PKCS#11 pattern).

openvc signs through the `SigningKey` protocol (`alg` / `kid` / `sign`), so a backend
where the private key never enters the process drops straight in — you implement the
protocol and delegate `sign` to the remote service. The one thing to get right: `sign`
MUST return the raw R‖S JOSE signature (64 bytes for ES256), but KMS / PKCS#11 return
a **DER** signature — so convert (this is where hand-rolled backends usually go wrong
and produce tokens that fail to verify elsewhere).

This runs offline with a mock "KMS" (a local key standing in for the remote one) so
it round-trips through `verify_credential`; the wiring to a real service is in the
comments on `sign_digest`.

Run:  python examples/06_remote_signing_key.py
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from _common import _MC_P256, _did_key

from openvc import SigningKey, VerificationPolicy, verify_credential
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite


class _MockKms:
    """Stand-in for a remote signer that holds the key and returns a DER signature.
    A real KMS never exposes the private key — you hold only a key id + the public key."""

    def __init__(self) -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())

    def sign_digest(self, digest: bytes) -> bytes:
        """Sign a 32-byte SHA-256 digest, returning a DER-encoded ECDSA signature.

        Real services (the private key never leaves them):
          * AWS KMS  — kms.sign(KeyId=…, MessageType='DIGEST', Message=digest,
                                SigningAlgorithm='ECDSA_SHA_256')['Signature']   -> DER
          * Vault    — transit sign  (marshaling_algorithm='asn1')               -> DER
          * PKCS#11  — C_Sign(CKM_ECDSA, digest)  -> raw R‖S (skip the DER decode below)
        """
        return self._priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


class RemoteP256SigningKey:
    """A `SigningKey` backed by a remote signer — the private key never enters openvc."""

    def __init__(self, kms: _MockKms, kid: str) -> None:
        self._kms = kms
        self._kid = kid

    @property
    def alg(self) -> str:
        return "ES256"

    @property
    def kid(self) -> str:
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        digest = hashlib.sha256(signing_input).digest()      # ES256 = ECDSA/P-256 + SHA-256
        der = self._kms.sign_digest(digest)                  # remote call -> DER signature
        r, s = utils.decode_dss_signature(der)               # DER -> (r, s) integers
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")  # -> raw R‖S (JOSE), 64 bytes


# --- use it exactly like an in-process backend ------------------------------------
kms = _MockKms()
# In production you'd have only the public key + the KMS key id; here derive the
# public did:key so the offline pipeline can verify what the "KMS" signed.
pub_raw = P256SigningKey(kms._priv, kid="_").public_key_raw(compressed=True)
issuer_did, vm = _did_key(pub_raw, _MC_P256)

signer = RemoteP256SigningKey(kms, kid=vm)
assert isinstance(signer, SigningKey), "must satisfy the SigningKey protocol"

credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:9c2b",
    "type": ["VerifiableCredential", "ExampleCredential"],
    "issuer": issuer_did,
    "credentialSubject": {"id": "did:example:alice", "name": "Ada Lovelace"},
}

token = VcJwtProofSuite().sign(credential, signing_key=signer)
print("signed via 'remote KMS':", token[:48] + "…")

result = verify_credential(
    token, policy=VerificationPolicy(expected_types=["ExampleCredential"]))
print("verified issuer :", result.issuer)
print("the private key never entered openvc — sign() delegated to the KMS")
