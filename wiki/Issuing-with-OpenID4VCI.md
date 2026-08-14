# Issuing with OpenID4VCI

openvc verifies the **key proof** a wallet sends to your Credential Endpoint, and hands
you back the public key it demonstrated possession of. That key is what you bind the
credential to.

It does **not** run the endpoint. Per
[ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md),
the split is:

> **openvc:** attacker-controlled bytes that must be verified or parsed fail-closed.
> **You:** anything with a lifetime, a socket, or a deployment policy.

So the OAuth Authorization Server, the HTTP routing, the `c_nonce` store, the Credential
Response body, deferred and notification bookkeeping, and DPoP are yours (or your
framework's). What this supports claiming is *OpenID4VCI 1.0 key-proof verification* —
not "issuance", and not HAIP.

## Discovery: the offer and the metadata, parsed fail-closed

The same posture covers the two untrusted JSON documents that come *before* the key
proof: the **Credential Offer** (§4.1.1) a wallet scans, and the **Credential Issuer
Metadata** (§11.2.3) it fetches under `credential_issuer`. Both are attacker-controlled
bytes; both parsers raise on a malformed constraint rather than silently narrowing it:

```python
from openvc.openid4vci import (
    GRANT_PRE_AUTHORIZED_CODE,
    parse_credential_issuer_metadata,
    parse_credential_offer,
)

wallet_scanned_json = """
{"credential_issuer": "https://issuer.example",
 "credential_configuration_ids": ["UniversityDegree"],
 "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code":
            {"pre-authorized_code": "SplxlOBeZQ..."}}}
"""
offer = parse_credential_offer(wallet_scanned_json)     # object or JSON string
assert offer.credential_issuer.startswith("https://")   # enforced, not hoped for

fetched_metadata_json = """
{"credential_issuer": "https://issuer.example",
 "credential_endpoint": "https://issuer.example/credential",
 "batch_credential_issuance": {"batch_size": 5}}
"""
metadata = parse_credential_issuer_metadata(fetched_metadata_json)
batch = metadata.batch_size or 1                        # 1 is the fail-closed default

assert GRANT_PRE_AUTHORIZED_CODE in offer.grants
code = offer.grants[GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
assert metadata.batch_size == 5
```

What is pinned:

| Member | Rule |
|---|---|
| `credential_issuer` | present, an absolute **https** URL — it feeds the key proof's `aud` check |
| `credential_configuration_ids` | non-empty array of distinct non-empty strings |
| `credential_endpoint`, `nonce_endpoint`, … | absolute https when present |
| `authorization_servers` | when present, a non-empty array of https URLs |
| `batch_credential_issuance.batch_size` | an integer ≥ 2 |

What is **not** narrowed: `grants` members openvc does not know, per-configuration
shapes, `display`, encryption parameters — all reach you verbatim (in the typed fields
and in `raw`), because an ecosystem's extension points are none of a parser's business.

**Nothing is fetched.** A by-reference `credential_offer_uri` is *your* injected `Fetch`
to resolve, and `signed_metadata` (a JWT) reaches you as a string to verify — or not —
under your own trust rules.


## The whole flow

```python
import time

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.openid4vci import verify_credential_request_proofs
from openvc.proof._jws import sign_compact
from openvc.proof.sd_jwt import SdJwtVcProofSuite

CREDENTIAL_ISSUER = "https://issuer.example"
issuer = Ed25519SigningKey.generate(kid=f"{CREDENTIAL_ISSUER}#key-1")

# Your nonce store. See below — this MUST be atomic.
issued = {"c-nonce-abc"}
def consume_nonce(nonce):
    try:
        issued.remove(nonce)
        return True
    except KeyError:
        return False

# --- the wallet mints a key proof (OID4VCI 1.0 App. F.1) ---
wallet = P256SigningKey.generate(kid="wallet-key-1")
key_proof = sign_compact(
    {"typ": "openid4vci-proof+jwt", "alg": wallet.alg, "jwk": wallet.public_jwk()},
    {"aud": CREDENTIAL_ISSUER, "iat": int(time.time()), "nonce": "c-nonce-abc"},
    signing_key=wallet)

# --- your Credential Endpoint verifies it, then issues ---
proof, = verify_credential_request_proofs(
    {"credential_configuration_id": "UniversityDegree",
     "proofs": {"jwt": [key_proof]}},
    credential_issuer=CREDENTIAL_ISSUER,
    check_nonce=consume_nonce)

sd_jwt = SdJwtVcProofSuite().issue(
    {"iss": CREDENTIAL_ISSUER, "degree": "BSc"}, signing_key=issuer,
    vct="https://credentials.example/degree",
    holder_jwk=proof.public_jwk)          # <- the key the proof earned

assert proof.key_source == "jwk"
```

Wire it into your framework however you like — openvc never sees the request object,
the access token, or the socket:

<!-- docs: no-run -->
```python
@app.post("/credential")
def credential_endpoint(request):
    grant = my_as.introspect(request.headers["authorization"])   # yours: OAuth AS
    proofs = verify_credential_request_proofs(
        request.json(), credential_issuer=CREDENTIAL_ISSUER,
        check_nonce=my_nonce_store.consume)
    sd_jwt = SdJwtVcProofSuite().issue(
        grant.claims, signing_key=ISSUER_KEY, vct=VCT, holder_jwk=proofs[0].public_jwk)
    return {"credentials": [{"credential": sd_jwt}]}             # yours: the body
```

## The nonce store is yours, and it must be atomic

`check_nonce` is a **required** parameter. Replay is the property a key proof exists to
defend, and a plain `expected_nonce` string could not express "consume once,
atomically" — a caller comparing after the fact would have verified a signature and
*not* the replay property.

Your callable must mark the nonce used and report validity in **one** step: a Redis
`SET key val NX`, a SQL `DELETE … RETURNING`. The bug to avoid:

<!-- docs: no-run -->
```python
# WRONG — two concurrent requests both observe the nonce as unused.
if nonce in store:
    store.discard(nonce)
    return True
```

`openvc.cache.TtlCache` is **not** suitable: it documents its own lack of single-flight,
which is benign for a read cache and fatal for a single-use token.

openvc calls it **exactly once per request**, and only **after** every signature has
verified — so an unauthenticated attacker cannot burn your nonces by spraying garbage.

Pre-authorized codes, `transaction_id` and `notification_id` are entirely yours: they
are opaque identifiers with no bytes for openvc to get right, so it does not generate
them.

## What is checked, in order

Structure and allow-lists run before any cryptography. **Any failure rejects the whole
request** — there is no partial issuance.

| | Check |
|---|---|
| 1 | `typ` is `openid4vci-proof+jwt` — so a KB-JWT, VP-JWT or status-list token cannot be replayed as a key proof |
| 2 | `alg` is allow-listed (`ES256`/`ES384`/`EdDSA`/`Ed25519`), **before** any crypto |
| 3 | unknown `crit` rejected |
| 4 | `key_attestation`, if present, is a string and parses as a key attestation |
| 4b | if you passed `require_key_attestation=True`, the header **must** carry one — before crypto, before the nonce is spent |
| 5 | **exactly one** of `jwk` / `kid` / `x5c` / `trust_chain` |
| 6 | the key binds to the header `alg` — no `ES256` over an Ed25519 key; no private members in a `jwk` |
| 7 | with a `key_attestation`: the key is one of its `attested_keys` (App. D) |
| 8 | the signature |
| 9 | `aud` equals your Credential Issuer Identifier; a multi-valued `aud` is rejected |
| 10 | `iat` freshness — **both** stale and future-dated |
| 11 | `exp` / `nbf` if present; `iss` if you pinned `expected_client_id` |
| 12 | across the batch: one shared nonce, consumed once, no two proofs on the same key |

Two of these carry the weight. **`iat` in both directions**: without the future-dated
check a wallet signs once with `iat = now + 10y` and holds a proof that never expires.
**Exactly one key parameter**: two present lets an attacker pair a `kid` naming an
honest key with a `jwk` they control, and any implementation that silently prefers one
accepts it.

## Key parameters

`jwk` works out of the box. The other two are opt-in, and fail closed without their
enabling argument:

| Header | Enable with | Absent ⇒ |
|---|---|---|
| `jwk` | — | always available |
| `x5c` | `trust_anchors=[...]` | rejected — an unanchored chain is decoration, not trust |
| `kid` | `resolve_proof_key=` or `resolve_proof_key_in_context=` | rejected |
| `trust_chain` | — | typed `UnsupportedProofType` (OpenID Federation is out of scope) |
| `key_attestation` | `require_key_attestation=True` to *require* it | **not a key parameter** — see below; a header carrying only this one is rejected. Default is not to require it. |

## Key attestations

The form EU wallet stacks emit: the header carries a `kid` **and** a `key_attestation`
(App. D), and the key that signed the proof is one of the attestation's `attested_keys`.
There is nothing for a registry to look up, so `resolve_proof_key` — which sees only the
`kid` — cannot answer. `resolve_proof_key_in_context` gets everything openvc knows at
that moment, attestation already parsed
(`examples/13_oid4vci_key_attestation.py` is this, end to end and runnable):

<!-- docs: no-run -->
```python
from openvc.openid4vci import peek_key_attestation, verify_credential_request_proofs

proofs = verify_credential_request_proofs(
    body, credential_issuer=CREDENTIAL_ISSUER, check_nonce=store.consume,
    # this ecosystem reads `kid` as a position in attested_keys; yours may differ
    resolve_proof_key_in_context=lambda ctx: ctx.key_attestation.attested_keys[int(ctx.kid)])

attested = peek_key_attestation(proofs[0].key_attestation)   # UNVERIFIED
if "iso_18045_high" not in attested.key_storage:             # your policy, your call
    raise PermissionError("this credential needs high-assurance key storage")
```

Pass one resolver or the other, never both — a precedence between two key resolvers is
the same silent-preference defect the one-key-parameter rule exists to prevent.

**Which key a `kid` names is not specified.** The spec's own example uses it as an index;
other wallets use each JWK's `kid` member, or an RFC 7638 thumbprint. openvc will not
guess between them — that is your ecosystem's rule, and it is three lines above.

If your metadata publishes `key_attestations_required`, pass
`require_key_attestation=True`. A missing header is then a structure failure —
`ClaimsInvalid` — **before** the signature and **before** `check_nonce` runs. Without
the flag you only notice afterwards, by reading `VerifiedProof.key_attestation`, and
the nonce is already spent: the wallet's §8.3.1 retry becomes a loop. The policy is
yours; the ordering is only available here. Default `False`, so an issuer that does
not advertise the requirement is unchanged.

**What openvc does enforce** is App. D's MUST: with a `key_attestation` present, the key
that signed the proof must be one of its `attested_keys`. Be clear about what that buys.
It **stops no attacker** — nothing here verifies the attestation's signature, so whoever
forges a proof also forges an attestation listing their own key. It catches an honest
wallet, or *your own resolver*, handing over a key the wallet never claimed, which would
otherwise mint a credential bound to the wrong key and verify cleanly.

Deciding an attestation is genuine — its signature, its wallet-provider anchor, its
`key_storage` level, its `exp`, its `status` — is yours. `peek_key_attestation` reads one
without verifying anything, `KEY_ATTESTATION_TYP` is exported for the `typ` pin, and
`ADR-0007` D9 records why the trust model itself is not in openvc.

## Batches

`batch_size` defaults to **1**, so an issuer that never advertised
`batch_credential_issuance` rejects a batch rather than minting one credential per proof
off a single grant. Raise it deliberately:

<!-- docs: no-run -->
```python
proofs = verify_credential_request_proofs(
    body, credential_issuer=CREDENTIAL_ISSUER,
    check_nonce=store.consume, batch_size=5)
```

All proofs in a batch must carry the same nonce, and no two may be bound to the same
key — N credentials must mean N keys.

## Errors

| Raised | Meaning | Map to |
|---|---|---|
| `CredentialRequestMalformed` | the §8.2 wire contract is violated | `invalid_credential_request` |
| `ProofReplayed` | your store rejected the nonce | `invalid_nonce` — hand out a fresh one and let the wallet retry |
| `UnsupportedProofType` | `di_vp`, `trust_chain`, … | `invalid_proof` |
| `ClaimsInvalid` / `SignatureInvalid` / `MalformedToken` / `UnsupportedAlgorithm` | the shared proof leaves | `invalid_proof` |

`ProofReplayed` is deliberately **not** a `ClaimsInvalid`: "here is a fresh nonce, try
again" is a different answer from "your proof is wrong".

## Not covered

Key-attestation **trust**: the signature, the wallet-provider anchor, and whether
`key_storage` / `user_authentication` / `status` meet your bar. openvc parses one and
binds the proof key to it (above); believing it needs an anchor class of its own
(ADR-0007 D9). The `attestation` proof type — a key attestation with no proof of
possession at all — is likewise out, and refused as `UnsupportedProofType`. `di_vp`
proofs, credential-response encryption, mdoc issuance and DPoP are out of scope too.
HAIP additionally requires DPoP, key-attestation trust and client authentication, all of
which live in your endpoint.

See also: [SD-JWT VC](SD-JWT-VC) for the issuance side, [Keys & HSM
backends](Keys-and-HSM) for `SigningKey`, and [Security model](Security-Model).
