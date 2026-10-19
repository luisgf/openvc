# Keys & HSM backends

openvc signs through the **`SigningKey` protocol** (importable from `openvc`),
which has exactly three members:

<!-- docs: no-run -->
```python
class SigningKey(Protocol):
    @property
    def alg(self) -> str: ...      # JOSE alg: "ES256" | "ES384" | "EdDSA" | "Ed25519" (or opt-in ML-DSA)
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

## Key thumbprints (RFC 7638)

`jwk_thumbprint` gives a key's stable identifier — the value used as a `kid`, inside
a `cnf` claim, or as a DPoP `jkt`. It digests **only** the members
[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) requires for the key type, so
`kid`/`use`/`alg` are ignored and a private key hashes identically to its public half.

```python
from openvc.keys import P256SigningKey, jwk_thumbprint

# The RFC 8037 §2 example key, with the thumbprint the RFC publishes for it.
rfc8037 = {"kty": "OKP", "crv": "Ed25519",
           "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
assert jwk_thumbprint(rfc8037) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

# Decoration does not move the digest: the same key, however it is labelled.
key = P256SigningKey.generate(kid="key-1")
assert (jwk_thumbprint(dict(key.public_jwk(), kid="other", use="sig"))
        == jwk_thumbprint(key.public_jwk()))
```

It fails closed: an unknown `kty`, a missing required member, or a non-string member
value raises `InvalidKey` rather than digesting a partial key. `jwk_thumbprint_bytes`
returns the raw digest instead of the base64url form — that is what
`dcapi_session_transcript` wants for an ISO 18013-7 handover.

## The allow-list

Whatever the backend, the verifier accepts only `{ES256, ES384, EdDSA, Ed25519}` —
checked **before** any crypto runs. RS\*/HS\*/`alg: none` are rejected
outright; see the [Security model](Security-Model) for why this is
non-negotiable. An **experimental** opt-in widens this to post-quantum ML-DSA — see
[Post-quantum](#post-quantum-ml-dsa-experimental) below. A second, verification-only
opt-in admits `ES256K` for EBSI interop — see [ES256K](#es256k-ebsi-interop-opt-in)
below. The default is unchanged by both.

`Ed25519` is the [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)
fully-specified name for EdDSA (which IANA has deprecated as polymorphic).
`Ed25519SigningKey` still **emits `EdDSA` by default**; opt into the new name per
key with `Ed25519SigningKey.generate(kid, alg="Ed25519")` (or `.from_jwk` /
`.from_pem`). See [Versioning & deprecation](Versioning-and-Deprecation) for the
migration and why `ESP256`/`ESP384` are not accepted yet.

## Post-quantum: ML-DSA (experimental)

> **Experimental — not a production trust path.** ML-DSA ([RFC 9964](https://www.rfc-editor.org/rfc/rfc9964))
> ships behind an explicit opt-in, with **no golden-fixture conformance claim** (there are
> no stable third-party ML-DSA VC vectors yet — the reason it is experimental). Design:
> [ADR-0004](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0004-ml-dsa-design.md).

`openvc.keys.MLDSASigningKey` is a post-quantum backend behind the **same `SigningKey`
protocol**: `alg` is the parameter set (`ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87`), the
private key is a 32-byte seed, and the JWK is the RFC 9964 **`AKP`** key type
(`kty: "AKP"`, `pub`, `priv` — no `crv`). It needs the `[pq]` extra (`cryptography>=48`
built against OpenSSL ≥ 3.5); check availability with `openvc.mldsa_available()`.

ML-DSA is **never** in the default allow-list — the default suites reject `ML-DSA-*`
before any crypto. Opt in per suite with `allow_pq=True` (VC-JWT and SD-JWT VC only):

<!-- docs: no-run -->
```python
from openvc import MLDSASigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite

key = MLDSASigningKey.generate(kid="did:example:issuer#pq", alg="ML-DSA-65")
token = VcJwtProofSuite(allow_pq=True).sign(credential, signing_key=key)
result = VcJwtProofSuite(allow_pq=True).verify(token, public_key_jwk=key.public_jwk())
```

Opting in adds **only** the three ML-DSA names, never the classic weak algs. `allow_pq` is
exactly `True` or `False` on both suites: any other value, a configuration string such as
`"false"` included, is refused at construction (a `ProofError`; a `SdJwtError` on the
SD-JWT VC suite) instead of being read as true. An HSM/Vault
backend uses external-mu (`sign_mu`) so the message never reaches the device in the clear —
the same private-key-never-in-process posture as the EC/Ed backends. Signatures are large
(ML-DSA-65 ≈ 3.3 KB) — a caveat for SD-JWT VC and QR transport, not a blocker. Data
Integrity quantum-resistant cryptosuites stay out (W3C FPWD); ML-DSA here is JOSE-only.

## ES256K (EBSI interop opt-in)

`ES256K` ([RFC 8812](https://www.rfc-editor.org/rfc/rfc8812): ECDSA over secp256k1 with
SHA-256) is **not** in the default allow-list. EBSI Core API v1 signs its RootTAO
accreditation JWTs with it (recorded on the preprod and prod nodes on 2026-10-16), so
recursive trust (`verify_trust_chain`, `verify_ebsi_badge(trust_anchors=...)`) cannot verify a
Core v1 root unless the suite is told to accept it. Opt in per suite, as for ML-DSA:

<!-- docs: no-run -->
```python
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.trust import verify_trust_chain

suite = VcJwtProofSuite(allow_es256k=True)       # verification only; the default list is unchanged
chain = verify_trust_chain(issuer_did, credential_types, resolver=resolver,
                           proof_suite=suite, anchors={root_tao_did})
```

What the opt-in is, and is not:

- **Verification only.** openvc has no secp256k1 signing backend, and `sign()` refuses an
  `ES256K` key on every suite (`UnsupportedAlgorithm`), opted in or not.
- **VC-JWT only.** SD-JWT VC (issuer JWT and KB-JWT), VP-JWT, status-list tokens, OpenID4VCI
  key proofs, LoTE, the WRPRC and COSE keep refusing it, whatever `allow_pq` or `allowed_algs`
  say. `verify_credential` and `verify_many` build a default suite and never opt in.
- **Never the default, and independent of `allow_pq`.** The check against the allow-list still
  runs before any crypto, and `allow_pq=True` does not imply this keyword (nor the reverse).
- **Pinned to its key type.** An `ES256K` header verifies only with an `EC` / `secp256k1` JWK
  whose `x` and `y` are full-width (32-octet) coordinates on the curve, and a header naming any
  other algorithm never verifies with a secp256k1 key; both are a plain `ProofError`, also in a
  DID document that holds a secp256k1 and a P-256 key and a `kid` that names the wrong one. The
  signature is raw `R‖S`, 64 octets, never DER.
- **The JWK members RFC 8812 section 3.2 names are checked.** If the key carries an `alg`, it
  must be `ES256K`; a `use`, `sig`; a `key_ops`, an array of strings that includes `verify`. A
  member that is present and wrong (a `null` too) is a plain `ProofError`. The ES256, ES384 and
  EdDSA branches do not read these members, as before.
- **The flag is a real boolean.** `allow_es256k` must be exactly `True` or `False`: any other
  value (the string `"false"` or `"0"` a configuration file or an environment variable
  hands over, `1`, `None`) is a `ProofError` when the suite is built, instead of being read as
  true and widening the allow-list by accident.
- **Same claim handling as ES256.** `exp`, `nbf`, `aud`, `crit`, `typ` and the SD-JWT-marker
  gates are the VC-JWT ones, unchanged. Both the low-`s` and the high-`s` form of a signature
  verify, as they already do for ES256 (RFC 8812 does not restrict `s`).
- **One suite for the leaf and the hops.** `verify_ebsi_badge` passes its one `proof_suite` to
  the leaf badge and to every accreditation in the chain, so an opted-in suite also accepts an
  `ES256K`-signed leaf badge.
- **Not experimental.** A real vector backs it: the recorded preprod RootTAO verifies against
  its DID document's secp256k1 key (the golden in `tests/test_es256k_ebsi_chain.py`). The prod
  seed root's DID document has no verification method, so a prod chain cannot close with or
  without the keyword. Single-level trust never checks the accreditation's signature and is
  unaffected.
