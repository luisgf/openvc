# SD-JWT VC (selective disclosure)

[SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) lets
an issuer mark claims as *selectively disclosable*: the holder later presents
only the claims it chooses, and proves possession of the key the credential
was bound to (`cnf`) with a **Key Binding JWT** over the verifier's `aud` +
`nonce`.

## Issue → present → verify

```python
from openvc.keys import Ed25519SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite

issuer = Ed25519SigningKey.generate(kid="https://issuer.example#key-1")
holder = Ed25519SigningKey.generate(kid="holder-key-1")
suite = SdJwtVcProofSuite()

# Issue: given_name and age are selectively disclosable; cnf binds the holder key.
sd_jwt = suite.issue(
    {"iss": "https://issuer.example", "given_name": "Ada",
     "family_name": "Lovelace", "age": 36},
    signing_key=issuer, disclosable=["given_name", "age"],
    holder_jwk=holder.public_jwk(), vct="https://credentials.example/identity")

# Present: the holder signs a KB-JWT over this verifier's aud + nonce.
presentation = suite.create_presentation(
    sd_jwt, holder_key=holder, audience="https://verifier.example", nonce="n-123")

# Verify: issuer signature, disclosure digests, KB-JWT, aud/nonce, vct.
result = suite.verify(
    presentation, public_key_jwk=issuer.public_jwk(),
    audience="https://verifier.example", nonce="n-123", require_key_binding=True,
    expected_vct="https://credentials.example/identity")
print(result.vct, result.key_bound, result.claims["given_name"])
```

The pipeline also accepts SD-JWT presentations directly —
`verify_credential(presentation, ...)` detects the format and resolves the
issuer key from `iss` (see
[Resolving issuer keys](Resolving-Issuer-Keys)).

### X.509 (`x5c`) issuer trust

An issuer anchored on a trusted list (eIDAS / EUDI) can carry its certificate chain in the
SD-JWT VC header — `suite.issue(..., x5c=[<base64 DER>, …])`, leaf first — so a verifier
chains it to its anchors and binds the leaf to `iss` in one call:

<!-- docs: no-run -->
```python
sd_jwt = suite.issue(
    {"iss": "https://issuer.example", ...}, signing_key=issuer, vct=VCT, x5c=x5c_chain)
result = verify_credential(sd_jwt, x5c_trust_anchors=[root])   # chains x5c -> root, binds iss
```

The leaf certificate's key must be the issuer's signing key and `iss` must appear in the
leaf's Subject Alternative Name, or verification fails closed (see [Trust anchors](Trust)).

## Type Metadata (`vct` + `vct#integrity`)

An issuer can pin the credential type's published
[Type Metadata](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
document with `vct#integrity`; the verifier resolves the document, checks the
hash, and validates the disclosed claims against the type's `claims` metadata
(paths + `mandatory`):

```python
import base64
import hashlib
import json

from openvc.keys import Ed25519SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.type_metadata import validate_type_metadata

VCT = "https://credentials.example.com/education_credential/v1"
type_metadata = {
    "vct": VCT,
    "name": "Example Education Credential",
    "claims": [
        {"path": ["name"], "sd": "always", "mandatory": True},
        {"path": ["degree"], "sd": "always"},
    ],
}
metadata_bytes = json.dumps(type_metadata).encode()
integrity = "sha256-" + base64.b64encode(hashlib.sha256(metadata_bytes).digest()).decode()

issuer = Ed25519SigningKey.generate(kid="https://issuer.example#key-1")
holder = Ed25519SigningKey.generate(kid="holder-key-1")
suite = SdJwtVcProofSuite()
issued = suite.issue(
    {"iss": "https://issuer.example", "vct#integrity": integrity,
     "name": "Ada Lovelace", "degree": "Mathematics"},
    signing_key=issuer, vct=VCT, disclosable=["name", "degree"],
    holder_jwk=holder.public_jwk())

verified = suite.verify(issued, public_key_jwk=issuer.public_jwk())
result = validate_type_metadata(
    verified.claims, vct=verified.vct,
    vct_integrity=verified.claims.get("vct#integrity"),
    resolve=lambda url: {VCT: metadata_bytes}[url])   # in-memory; real: fetch by URL
print(result.documents[0]["name"], [c["path"] for c in result.claims])
```

In production, resolve Type Metadata over the network with the SSRF-guarded
default — `openvc.resolvers.default_type_metadata_resolver` — instead of the
in-memory lambda above.

## Caveat: keep enforcement pointers non-disclosable

If a credential's `credentialStatus` (or `credentialSchema`) must be
enforceable, do **not** list it in `disclosable`: a holder could simply omit
the disclosure and the verifier would never see the pointer. Fail-closed
status only works for claims the holder cannot withhold — the same applies to
`ecdsa-sd-2023`'s mandatory pointers (see the
[Security model](Security-Model)).
