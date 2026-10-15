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
| `openvc-core[pq]` | experimental ML-DSA (RFC 9964) signing + verification | `cryptography>=48` |
| `openvc-core[all]` | ebsi + data-integrity + schema + trustlist + pq + the dev tools | |

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
  algorithm outside the `{ES256, ES384, EdDSA, Ed25519}` allow-list all reject —
  ambiguity never resolves to "accept". The reasoning is laid out in the
  [Security model](Security-Model).
- Every failure raises a subclass of a single root, so
  `except OpenvcError` catches any openvc rejection.

## Clock skew: `leeway_s`

`VerificationPolicy.leeway_s` is the clock-skew tolerance every lane adds to its temporal
checks: a JWT's `exp`, `nbf` and `iat`, a W3C credential's `validFrom` / `validUntil`, a
Data Integrity proof's `expires`, a status list's window. The default is 60 seconds. One rule
holds everywhere openvc takes a `leeway_s`:

- **A whole number of seconds from 0 to `MAX_LEEWAY_S` (86 400, one day), as an `int` that
  is not a `bool`.** Anything else is refused, up front, with a typed error: a float
  (`60.5`, `60.0`, `NaN`, `Infinity`), a negative, a `bool`, a string, `None`, a
  `Decimal` or a numpy scalar (pass `int(x)`), and anything past a day.
- **Why so strict.** Every comparison against `NaN` is false and an infinite or huge
  window never closes, so either one switched expiry off. A string or `None` used to
  escape as a bare `TypeError` mid-batch. A leeway is the skew between two clocks, not a
  validity period: to verify as of another date, pin `now`.
- **Where it is checked, and what it raises.** `VerificationPolicy(...)` raises
  `InvalidPolicy` when it is built, so a misconfiguration fails once and not once per
  credential. Each proof suite's constructor (`VcJwtProofSuite`, `VpJwtProofSuite`, the Data
  Integrity suites) raises `ProofError`, `SdJwtVcProofSuite` raises `SdJwtError`, and the
  function entry points raise their own family: `verify_vp_token` and
  `verify_encrypted_vp_response` `OpenID4VPError`, `verify_status_list_token` and the
  four `default_status_list*_resolver` factories `StatusListError`,
  `verify_credential_request_proofs` `CredentialRequestMalformed`, the mdoc verifiers
  `MdocError`, `verify_rp_registration_certificate` `RpRegistrationError`. Each checks it
  before it reads anything else.
- `kb_max_age_s` on the policy must be a non-negative `int` too (`InvalidPolicy`), with no
  upper bound.

```python
from openvc import InvalidPolicy, VerificationPolicy

VerificationPolicy(leeway_s=0)       # no tolerance at all
VerificationPolicy(leeway_s=300)     # five minutes of skew

for bad in (60.5, float("nan"), float("inf"), -1, "60", None, True, 86_401):
    try:
        VerificationPolicy(leeway_s=bad)
    except InvalidPolicy as exc:
        print("refused:", exc)
```

## Waiving expiry or revocation

Two `VerificationPolicy` knobs, both `True` by default, turn an *expired* or
*revoked* verdict from a rejection into something you read off the result — for
an audit trail, or to tell a holder *why* a credential is no longer accepted.
They are independent of authenticity: each waives one disposition and nothing
else.

| Set to `False` | Waives | Still enforced |
|---|---|---|
| `require_not_expired` | the JWT `exp` (VC-JWT, SD-JWT VC), the credential's `validUntil` / `expirationDate`, and a Data Integrity proof's `expires` | signature and the alg allow-list, issuer key resolution and binding, holder binding (KB-JWT signature, `aud` / `nonce`, `iat` window), `nbf` / `validFrom` / `issuanceDate`, a future JWT `iat`, malformed timestamps (a `null` JWT date included), a VC-JWT's `aud` (RFC 7519 §4.1.3), `x5c` chain validity, every status check |
| `require_not_revoked` | a set `revocation` bit, W3C Bitstring or IETF Token Status List | all of the above, expiry included; fetching and verifying the status list; failing closed without a resolver (`require_status`); and **suspension**, which still raises `CredentialSuspended` |

What the result tells you:

- **`result.expired`** is `True` when the expiry waiver is on and the default
  policy would have rejected the credential for its own expiry: a VC-JWT's `exp`
  or body `validUntil` / `expirationDate`, an SD-JWT VC's `exp` (plus `validUntil`
  / `expirationDate` when it is a W3C credential secured as SD-JWT, see
  [SD-JWT VC](SD-JWT-VC#w3c-credentials-secured-as-sd-jwt-vcsd-jwt)), or a Data
  Integrity credential's `validUntil` / `expirationDate` and the proof's own
  `expires`. The proof suite that skipped the check reports it, on the clock it
  enforces with: the current time for the JOSE formats, `policy.now` for Data
  Integrity. With the default policy it is always `False`, because an expired
  credential raises instead (`CredentialExpired`, or `ClaimsInvalid` for a JWT
  `exp`).
- **Revocation has no result flag.** A waived revocation verifies, and
  `result.status.revoked` is `True`. `status` is the resolved status; the W3C
  entry wins when a credential declares both conventions.
- **Both pipelines compute `expired` the same way.** `verify_credential` and
  `verify_credential_async` (and `verify_many` / `verify_many_async`) share the
  same code for every format, so they agree on the same credential and policy.
  Before 1.28.0 ([#188](https://github.com/luisgf/openvc/pull/188)) the async
  pipeline always reported `expired=False`. The flag only observes: turning the
  waiver on never rejects a credential the default policy would accept.
- **The knobs live on `VerificationPolicy`**, so they apply to
  `verify_credential`, `verify_many` and their async twins. `verify_vp_token`
  builds its own policy, so the waivers never reach a presentation verified
  there. They concern the credential you verify, not a schema VC it points at
  ([Credential schemas](Credential-Schemas#the-two-schema-types)).

```python
import asyncio

from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import VerificationPolicy, verify_credential, verify_credential_async
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.errors import CredentialExpired
from openvc.proof.vc_jwt import VcJwtProofSuite

private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

# Correctly signed, but its validity window closed in 2020.
token = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "validUntil": "2020-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:alice"},
}, signing_key=issuer)

try:
    verify_credential(token)                       # default policy: expiry rejects
except CredentialExpired as exc:
    print("rejected:", exc)

audit = VerificationPolicy(require_not_expired=False)
result = verify_credential(token, policy=audit)   # signature, issuer, nbf still checked
assert result.expired
assert asyncio.run(verify_credential_async(token, policy=audit)).expired
```

## Where next

- One credential format per guide: [VC-JWT](VC-JWT), [SD-JWT VC](SD-JWT-VC),
  [Data Integrity](Data-Integrity).
- Verifying what a wallet sends you: [Presentations & OpenID4VP](Presentations).
- Batch and async verification: [Async verification](Async-Verification).
- The full API, module by module: the
  [API reference](https://luisgf.github.io/openvc/).
