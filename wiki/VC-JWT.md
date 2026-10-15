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
- **An SD-JWT issuer JWT is not a VC-JWT** (explicit typing, RFC 8725 §3.11). A JWS
  typed `sd-jwt`, `*+sd-jwt` or `kb+jwt` (any case, with or without the `application/`
  prefix) is a `MalformedToken` before the signature is checked. So is one whose payload
  carries an SD-JWT marker at any depth: a member named `_sd` or `_sd_alg`, or an
  array-element digest object `{"...": …}`. RFC 9901 §4.1 item 7 and §4.2.4.2 (`_sd` and
  `...` are reserved; `...` is the array-element digest object) and §4.1.1 (`_sd_alg`, top
  level only) name them, and openvc refuses `_sd_alg` at any depth too. The second test
  does not read the header, so it covers an issuer JWT with no `typ`, or one the
  first test does not know, whose `vc` object keeps its disclosable claims inside it:
  with its `~` tail dropped it would otherwise verify here with no key binding. Before
  1.34.0 only the typed case was refused (#291). No real VC-JWT carries these members,
  so a payload that does is refused whatever you meant it to be (a JSON Schema that
  describes an SD-JWT payload, used as a claim, is refused too). **Limit:** a
  zero-disclosure SD-JWT issuer JWT with no `typ`, a `vc` object and a `cnf` carries
  none of them (an `_sd_alg` alone, or a decoy digest, is already refused), so it cannot be told from a VC-JWT that carries a `cnf`, and this lane never
  enforces `cnf`: do not read a `cnf` on a VC-JWT as holder binding. The VP-JWT lane
  applies both tests to the presentation ([Presentations](Presentations#vp-jwt)).
- **Envelope ↔ credential reconciliation.** The JWT claims (`iss`, `sub`,
  `jti`, `exp`, `nbf`) must agree with the embedded credential (`issuer`,
  `credentialSubject.id`, `id`, validity window) — a token cannot smuggle a
  credential that says something else. Every identifier a present `issuer`
  carries must be `iss`: the string itself, or an object's `id` and `@id`. A
  null, empty or non-string one is rejected, not skipped. An object with no `id`
  identifies no one, and is accepted like an absent `issuer` (the VCDM 1.1 JWT
  encoding moves the id to `iss`). The SD-JWT lane applies the same rule to a W3C credential
  ([SD-JWT VC](SD-JWT-VC#w3c-credentials-secured-as-sd-jwt-vcsd-jwt)), and takes the
  issuer from `issuer` when the token has no `iss`
  ([details](SD-JWT-VC#the-issuer-when-a-w3c-credential-has-no-iss)). This lane does not
  work that way: its `peek_issuer` reads `iss`, or the issuer of the embedded `vc` when `iss`
  is falsy (absent, `null` or `""`), and never a top-level `issuer`, and `verify()` still
  requires a string `iss` on both lanes, so a VC-JWT with no `iss` is refused whatever its
  `vc.issuer` says (`ClaimsInvalid`). The SD-JWT fallback is stricter than that peek in
  every case: it applies only when `iss` is absent altogether, never for a `null` or empty
  one, and it accepts an issuer object only when all of its `id` and `@id` members agree.
- **Temporal checks fail closed.** `exp` / `nbf` / `iat` (with a small
  clock-skew leeway) and the credential's `validFrom` / `validUntil`; a
  present-but-unparseable timestamp rejects. `exp`, `nbf` and `iat` must each be
  a finite JSON number (RFC 7519 NumericDate) when present. `null`, a string
  (even `"1700000000"`), a bool, `NaN`/`Infinity` or a container is a
  `ClaimsInvalid`. A token at or past `exp` plus the leeway has expired, and an
  `iat` more than the leeway in the future is rejected too.
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
  string or an array of strings, and the audience you pass must be a non-empty
  string (a list of audiences is refused, not matched). A VC-JWT without `aud` verifies when you pass no
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
