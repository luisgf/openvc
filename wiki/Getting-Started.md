# Getting Started

## Install

The PyPI distribution is **`openvc-core`** (bare `openvc` collides with
`opencv` under PyPI's typosquatting guard); the import package stays `openvc`:

```sh
pip install openvc-core
```

The core depends only on `cryptography` and `pyjwt`. Heavier machinery lives
behind extras:

| Extra | Adds | Pulls in |
|---|---|---|
| `openvc-core[data-integrity]` | the RDF-canonicalized Data Integrity suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `ecdsa-sd-2023`) | `pyld` |
| `openvc-core[ebsi]` | the EBSI registry client | `httpx` |
| `openvc-core[schema]` | `credentialSchema` (W3C VC JSON Schema) validation | `jsonschema` |
| `openvc-core[trustlist]` | XAdES signature verification for EU Trusted Lists | `signxml` |
| `openvc-core[all]` | everything above + the dev tools | |

The JCS Data Integrity suites (`eddsa-jcs-2022` / `ecdsa-jcs-2019`), VC-JWT,
SD-JWT VC, DIDs, and status lists all work with the bare core.

## Issue and verify your first credential

`verify_credential` is the one-call pipeline: it detects the format (VC-JWT /
SD-JWT VC / Data Integrity / enveloped), resolves the issuer key, verifies the
proof, and applies policy. Here the issuer is addressed by `did:key`, so
everything runs offline:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import VerificationPolicy, verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite

# 1. An issuer key, addressed by did:key (multicodec ed25519-pub -> base58btc).
private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

# 2. Sign a credential as a VC-JWT.
token = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:2f3a-example",
    "type": ["VerifiableCredential", "ExampleCredential"],
    "issuer": f"did:key:{mb}",
    "credentialSubject": {"id": "did:example:alice", "name": "Ada Lovelace"},
}, signing_key=issuer)

# 3. Verify: format detection, key resolution, signature, policy — one call.
result = verify_credential(
    token, policy=VerificationPolicy(expected_types=["ExampleCredential"]))
print(result.format, result.issuer, result.subject)
```

In production the issuer key usually lives in an HSM/KMS and is addressed by
`did:web` — see [Keys & HSM backends](Keys-and-HSM) and
[Resolving issuer keys](Resolving-Issuer-Keys).

## Fail-closed defaults you should know about

- A credential that **declares a `credentialStatus`** is rejected unless you
  supply a status resolver (or opt out explicitly). See
  [Status lists](Status-Lists).
- An **unresolvable issuer key**, an **unparseable timestamp**, or an
  algorithm outside the `{ES256, ES384, EdDSA}` allow-list all reject —
  ambiguity never resolves to "accept". The reasoning is laid out in the
  [Security model](Security-Model).
- Every failure raises a subclass of a single root, so
  `except OpenvcError` catches any openvc rejection.

## Where next

- One credential format per guide: [VC-JWT](VC-JWT), [SD-JWT VC](SD-JWT-VC),
  [Data Integrity](Data-Integrity).
- Verifying what a wallet sends you: [Presentations & OpenID4VP](Presentations).
- Batch and async verification: [Async verification](Async-Verification).
- The full API, module by module: the
  [API reference](https://luisgf.github.io/openvc/).
