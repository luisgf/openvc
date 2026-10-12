# VC-JWT (JOSE)

The VC-JWT suite wraps a W3C credential in a signed JWT
([VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/)). It is the
EBSI/EUDI-compatible path (`ES256`) and supports `ES384` and `EdDSA` as well
(plus the RFC 9864 fully-specified name `Ed25519` for the latter).

## Sign and verify

```python
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite

sk = P256SigningKey.generate(kid="did:web:issuer.example#key-1")
suite = VcJwtProofSuite()

credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:5f1c-example",
    "type": ["VerifiableCredential"],
    "issuer": "did:web:issuer.example",
    "credentialSubject": {"id": "did:example:alice"},
}
token = suite.sign(credential, signing_key=sk)

# Peek reads the claims WITHOUT verifying — for routing/key discovery only.
print(suite.peek_claims(token)["iss"])

verified = suite.verify(token, public_key_jwk=sk.public_jwk())
print(verified.issuer, verified.subject)
```

`suite.verify(..., public_key_jwk=...)` is the low-level form for when you
already hold the key. Normally you let the pipeline resolve it from the
`issuer` DID — `verify_credential(token)` — see
[Resolving issuer keys](Resolving-Issuer-Keys).

## What the verifier enforces

- **The algorithm allow-list runs before any crypto.** Only
  `{ES256, ES384, EdDSA, Ed25519}` are accepted (`Ed25519` is the RFC 9864
  fully-specified name for EdDSA — see
  [Versioning & deprecation](Versioning-and-Deprecation)); `alg: none`, RS\*,
  and HS\* are rejected up front, which closes the classic alg-confusion attacks.
- **Unknown `crit` header extensions are rejected** (RFC 7515 §4.1.11). openvc
  processes no JWS extension parameters, so a token that marks any as critical
  fails closed — on the VC-JWT, SD-JWT, KB-JWT and status-list-token lanes
  alike (the COSE and JWE paths already take the same stance).
- **Envelope ↔ credential reconciliation.** The JWT claims (`iss`, `sub`,
  `exp`, `nbf`) must agree with the embedded credential (`issuer`,
  `credentialSubject.id`, validity window) — a token cannot smuggle a
  credential that says something else.
- **Temporal checks fail closed.** `exp` / `nbf` / `iat` (with a small
  clock-skew leeway) and the credential's `validFrom` / `validUntil`; a
  present-but-unparseable timestamp rejects. `exp`, `nbf` and `iat` must each be
  a finite JSON number (RFC 7519 NumericDate) when present. `null`, a string
  (even `"1700000000"`), a bool, `NaN`/`Infinity` or a container is a
  `ClaimsInvalid`. An `iat` more than the leeway in the future is rejected too.
  `require_not_expired=False` waives an *expired* verdict, never a malformed
  date, a future `nbf` or a future `iat`. In `verify_many` such a token fails as
  its own item. The classic lane (PyJWT) and the ML-DSA lane apply the same
  rules, and on both a present `sub` or `jti` must be a string.
- **A token with an `aud` needs your audience** (RFC 7519 §4.1.3,
  [ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md)).
  A VC-JWT that carries `aud` verifies only when you pass an audience that is one
  of its values: `audience=` on the suite, or `VerificationPolicy(audience=...)` on
  the pipeline. Without one, a VC-JWT addressed to another relying party is a
  `ClaimsInvalid`, not a credential anyone who holds it can use. `aud` must be a
  string or an array of strings. A VC-JWT without `aud` verifies when you pass no
  audience, and fails when you pass one. VCDM's JWT encoding defines `aud` only for
  presentations, so most VC-JWTs carry none.

## Signing keys

`sign(...)` takes anything that implements the `SigningKey` protocol. The
in-process backends are `Ed25519SigningKey` (EdDSA), `P256SigningKey` (ES256),
and `P384SigningKey` (ES384) from `openvc.keys`; an HSM/KMS/Vault backend
drops in the same way — see [Keys & HSM backends](Keys-and-HSM).

One wire-format detail worth knowing even if you never touch it: JOSE ES256
signatures are **raw `R‖S` (64 bytes), never DER**. openvc's backends produce
the right form; hand-rolled remote signers often don't (KMS and PKCS#11 return
DER), which is the classic reason a locally-fine token fails at another
verifier.
