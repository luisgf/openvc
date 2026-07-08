# Keys & HSM backends

openvc signs through the **`SigningKey` protocol** (importable from `openvc`),
which has exactly three members:

<!-- docs: no-run -->
```python
class SigningKey(Protocol):
    @property
    def alg(self) -> str: ...      # the JOSE algorithm: "ES256" | "ES384" | "EdDSA"
    @property
    def kid(self) -> str: ...      # the key / verification-method id for the header
    def sign(self, signing_input: bytes) -> bytes: ...   # raw R‖S for ES*, never DER
```

Anything with those three members is a signing key. The private
key **never has to enter the process**: a PKCS#11, AWS KMS, or Vault Transit
backend implements the protocol and delegates `sign` to the remote service.

## In-process backends

`openvc.keys` ships `Ed25519SigningKey` (EdDSA — the general default),
`P256SigningKey` (ES256 — the EBSI/EUDI-compatible path), and
`P384SigningKey` (ES384), each with `.generate(kid=...)`, `.public_jwk()`,
and `.public_key_raw()`. Fine for development and for issuers whose keys live
with the process; for production issuance, prefer a remote backend.

These three backends and the `SigningKey` protocol — plus the `KeyAgreementKey`
protocol and its `P256KeyAgreementKey`, the `signing_key_from_jwk` factory, and
the dependency-light `verify_signature` helper — are all importable straight from
`openvc` as well as from `openvc.keys`; the two paths are the same objects.

## A remote backend (KMS / Vault / PKCS#11 pattern)

The one thing hand-rolled backends get wrong: **JOSE ES256 signatures are raw
`R‖S` (64 bytes), but KMS and PKCS#11 typically return DER** — convert, or
your tokens fail at every other verifier. The pattern, runnable offline with a
mock standing in for the remote service:

```python
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from openvc import SigningKey, verify_credential
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite


class MockKms:
    """Stands in for AWS KMS / Vault Transit / PKCS#11: holds the private key,
    signs a digest, returns DER. You would hold only a key id + public key."""

    def __init__(self) -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())

    def sign_digest(self, digest: bytes) -> bytes:
        # AWS KMS:  kms.sign(KeyId=…, MessageType='DIGEST', Message=digest,
        #                    SigningAlgorithm='ECDSA_SHA_256')['Signature']  -> DER
        # Vault:    transit sign (marshaling_algorithm='asn1')              -> DER
        # PKCS#11:  C_Sign(CKM_ECDSA, digest) -> already raw R‖S: skip the decode
        return self._priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


class RemoteP256SigningKey:
    """A SigningKey whose private key lives in the remote service."""

    def __init__(self, kms: MockKms, kid: str) -> None:
        self._kms, self._kid = kms, kid

    @property
    def alg(self) -> str:
        return "ES256"

    @property
    def kid(self) -> str:
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        digest = hashlib.sha256(signing_input).digest()   # ES256 = P-256 + SHA-256
        der = self._kms.sign_digest(digest)               # remote call
        r, s = utils.decode_dss_signature(der)            # DER -> (r, s)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")   # raw R‖S (JOSE)


kms = MockKms()
raw = P256SigningKey(kms._priv, kid="_").public_key_raw(compressed=True)
mb = encode_multibase(bytes([0x80, 0x24]) + raw)          # did:key for the demo
signer = RemoteP256SigningKey(kms, kid=f"did:key:{mb}#{mb}")
assert isinstance(signer, SigningKey)                     # runtime-checkable protocol

token = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "credentialSubject": {"id": "did:example:alice"},
}, signing_key=signer)
print(verify_credential(token).issuer)   # the private key never entered openvc
```

The fully-commented version is
[`examples/06_remote_signing_key.py`](https://github.com/luisgf/openvc/blob/main/examples/06_remote_signing_key.py).

## Key-agreement keys (HAIP decryption)

Decrypting HAIP `direct_post.jwt` responses uses a separate protocol —
`P256KeyAgreementKey` in-process, or your own ECDH backend — see
[Presentations & OpenID4VP](Presentations). The same rule applies: openvc
needs the *operation*, not the key material.

## The allow-list

Whatever the backend, the verifier accepts only `{ES256, ES384, EdDSA, Ed25519}` —
checked **before** any crypto runs. RS\*/HS\*/`alg: none` are rejected
outright; see the [Security model](Security-Model) for why this is
non-negotiable.

`Ed25519` is the [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)
fully-specified name for EdDSA (which IANA has deprecated as polymorphic).
`Ed25519SigningKey` still **emits `EdDSA` by default**; opt into the new name per
key with `Ed25519SigningKey.generate(kid, alg="Ed25519")` (or `.from_jwk` /
`.from_pem`). See [Versioning & deprecation](Versioning-and-Deprecation) for the
migration and why `ESP256`/`ESP384` are not accepted yet.
