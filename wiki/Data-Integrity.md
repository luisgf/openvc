# Data Integrity (embedded proofs)

[Data Integrity](https://www.w3.org/TR/vc-data-integrity/) embeds the proof in
the credential's JSON instead of wrapping it in a JWT, so the document stays a
plain JSON(-LD) object and the proof survives re-serialization. openvc
implements five cryptosuites behind one pattern — `add_proof` / pipeline
`verify_credential`:

| Cryptosuite | Suite class (`openvc.proof.*`) | Key | Canonicalization | Needs |
|---|---|---|---|---|
| `eddsa-rdfc-2022` | `data_integrity.DataIntegrityProofSuite` | Ed25519 | RDF (URDNA2015) | `[data-integrity]` (`pyld`) |
| `ecdsa-rdfc-2019` | `di_ecdsa_rdfc.EcdsaRdfcProofSuite` | P-256 / P-384 | RDF (URDNA2015) | `[data-integrity]` (`pyld`) |
| `eddsa-jcs-2022` | `di_jcs.EddsaJcsProofSuite` | Ed25519 | JCS (RFC 8785, stdlib) | core only |
| `ecdsa-jcs-2019` | `di_jcs.EcdsaJcsProofSuite` | P-256 / P-384 | JCS (RFC 8785, stdlib) | core only |
| `ecdsa-sd-2023` | `ecdsa_sd.EcdsaSdProofSuite` | P-256 | RDF + selective disclosure | `[data-integrity]` (`pyld`) |

The bundled JSON-LD contexts are served by an **offline document loader** — RDF
canonicalization never fetches a context from the network.

## RDF-canonicalized (`eddsa-rdfc-2022`)

<!-- docs: needs=pyld -->
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.data_integrity import DataIntegrityProofSuite

private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:9c1e-example",
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:alice"},
}
signed = DataIntegrityProofSuite().add_proof(
    credential, signing_key=issuer, verification_method=issuer.kid)

result = verify_credential(signed)      # format detected: data-integrity:eddsa
print(result.format, result.issuer)
```

## JCS — no `pyld`, pure stdlib

The JCS suites canonicalize with RFC 8785 (hand-rolled on the stdlib), so they
run on the bare core — same call shape:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite

private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

signed = EddsaJcsProofSuite().add_proof({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:alice"},
}, signing_key=issuer, verification_method=issuer.kid)

result = verify_credential(signed)      # cryptosuite auto-detected
print(result.format, result.issuer)
```

## Selective disclosure: `ecdsa-sd-2023`

The issuer adds a **base proof** naming which pointers are `mandatory`; the
holder **derives** a proof revealing only selected pointers; the verifier sees
mandatory + selected claims, nothing else:

<!-- docs: needs=pyld -->
```python
from openvc.keys import P256SigningKey
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite

KID = "did:key:zDnaExample#zDnaExample"
sk = P256SigningKey.generate(kid=KID)
suite = EcdsaSdProofSuite()

credential = {
    # The inline @vocab defines the custom subject terms; without it JSON-LD
    # expansion would silently drop them.
    "@context": ["https://www.w3.org/ns/credentials/v2",
                 {"@vocab": "https://vocab.example/"}],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:issuer",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:subject",
                          "name": "Ada Lovelace", "birthDate": "1815-12-10"},
}

base = suite.add_base_proof(          # issuer
    credential, signing_key=sk, verification_method=KID,
    mandatory_pointers=["/issuer", "/validFrom"])
derived = suite.derive_proof(         # holder
    base, selective_pointers=["/credentialSubject/name"])
result = suite.verify(derived, public_key_jwk=sk.public_jwk())   # verifier

print(result.credential["credentialSubject"])   # name disclosed, birthDate withheld
```

Make `credentialStatus` a **mandatory** pointer if you need it enforceable —
a selectively-disclosable status pointer can be withheld by the holder (see
the [Security model](Security-Model)).

## What verification enforces

Beyond the signature: the credential's **validity window**
(`validFrom` / `validUntil`), the proof's **`proofPurpose`** and `expires`,
and **issuer binding** — the proof's `verificationMethod` must be controlled
by the credential's `issuer` DID, so an attacker cannot sign someone else's
`issuer` with their own key.

## Conformance

`eddsa-rdfc-2022` reproduces the official W3C
[vc-di-eddsa](https://www.w3.org/TR/vc-di-eddsa/) test vector byte-for-byte.
`ecdsa-rdfc-2019` and `ecdsa-sd-2023` verify the official
[vc-di-ecdsa](https://www.w3.org/TR/vc-di-ecdsa/) vectors and reproduce their
published intermediates (ECDSA signing is randomized, so byte-identical proofs
are not possible). The recorded vectors live in `tests/fixtures/` as the drift
alarm.
