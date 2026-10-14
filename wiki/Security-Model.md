# Security model

openvc verifies Verifiable Credentials, handles signing keys, and dereferences
issuer-named URLs over the network. This page states what it defends, against
whom, and how — the reference an auditor (or an integrator) starts from. The
per-control hardening notes are in
[SECURITY.md](https://github.com/luisgf/openvc/blob/main/SECURITY.md); the
code-cited auditor annex (per-parser tables, the fail-closed invariants catalog,
the residual-risk register, and the fuzz-coverage / adversarial-review history)
is the [external-audit pack](https://github.com/luisgf/openvc/tree/main/docs/audit).

## Assets

- **The verification decision.** The accept/reject output of `verify_credential`
  (and `verify_ebsi_badge`) is the asset everything else protects: a *wrong accept*
  (a forged/tampered/expired/revoked credential accepted) is the primary harm.
- **Signing keys.** Private key material. openvc never requires it in-process on the
  signing path — signing goes through the `SigningKey` protocol, so an HSM/Vault/KMS
  backend keeps keys out of the process (see [Keys & HSM backends](Keys-and-HSM)).
- **Trust anchors.** The roots a verifier trusts: X.509 `x5c` trust anchors, the
  EBSI RootTAO, the DID documents a resolver returns. Compromise of an anchor is
  out of scope (it is the operator's root of trust) but openvc must not *widen* it.

> **On the issuer side.** The OpenID4VCI **key-proof verifier**
> ([ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md))
> adds the mirror attacker — one who *requests* a credential rather than presenting
> one — as a row in the table below. The asset is unchanged: it is still a verification
> decision over attacker-controlled bytes. The issuance *decision* is **not** openvc's;
> the protocol layer and single-use enforcement of `c_nonce` live in the consuming
> application, injected as a required callable, so a caller whose store is not atomic
> re-opens a replay window openvc cannot close for them.

## Trust boundaries

Untrusted input crosses into openvc at:

1. **The credential itself** — fully attacker-controlled bytes (a JWS/SD-JWT string
   or a JSON document). Every field is untrusted until the signature verifies.
2. **Network dereferences** — `did:web`, `/.well-known/jwt-vc-issuer`, status-list
   and `credentialSchema` URLs. The *issuer* names these URLs and (for status/schema)
   controls the bytes returned. All of these are attacker-influenced.
3. **The `SigningKey` / key-agreement backend** — an out-of-process boundary (HSM,
   Vault, KMS). openvc trusts it to sign/decrypt but not to hold key material for it.
4. **Injected resolvers** — `resolver`, `resolve_status_list*`,
   `resolve_credential_schema`, `*_fetch`. openvc's guarantees hold only for what
   these return; a custom resolver that skips verification or the SSRF guard opts
   out of the corresponding control (hence the blessed defaults in `openvc.resolvers`).

## Attacker capabilities & controls

| Attacker capability | Threat | Control |
|---|---|---|
| Present a forged / tampered credential | Wrong accept | Signature verification through the matching suite; the `{ES256, ES384, EdDSA, Ed25519}` **allow-list runs *before* any crypto** (rejects `alg:none`, RS\*, HS\* — alg-confusion defence); unknown JWS `crit` extensions are rejected on every JOSE lane (RFC 7515 §4.1.11, parity with the COSE and JWE paths); JWS is R‖S, never DER |
| Name an arbitrary issuer but sign with own key | Impersonation | **Issuer binding** — a Data Integrity proof's `verificationMethod` must be controlled by the credential's `issuer` DID; VC-JWT reconciles the JWT envelope with the embedded credential, and so does SD-JWT for a W3C credential (`vc+sd-jwt`: `iss` must match `issuer`); x5c binds the leaf SAN to `iss`. On every lane `result.issuer` is the authenticated issuer |
| Re-spell a signed RDF Data Integrity credential's JSON without changing its signed dataset (a member keyed by its IRI or an alias, an inline `@context` that re-maps a term, a term no context defines, `@included`) | The policy reads JSON the signature does not cover: an expiry, status or schema check skipped, a spoofed `credentialSubject` passing holder binding, unsigned claims | **Context validation** (VC-DI §2.4.1) after the proof verifies, on `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and `ecdsa-sd-2023`. The VC base context must come first, followed only by trusted context URLs or `@vocab`-only objects. The document and its proof must be the compacted form of their own expansion, with no `@included`/`@reverse` and no second description of the document node ([details](Data-Integrity#the-json-must-be-what-was-signed)) |
| Serve a malicious document at a fetched URL | **SSRF** (reach internal hosts / cloud metadata) | `openvc.fetch`: https-only, blocks private/loopback/link-local/reserved/multicast IPs, refuses redirects, **pins the connection to the validated IP** (closes DNS-rebinding). Status/schema fetches use the same guard via the blessed `openvc.resolvers` defaults |
| Send JSON nested thousands of levels deep (a token payload, a disclosure, a DID document, a `vp_token`, or a dict handed to `verify_credential`) | **Batch abort** (a bare `RecursionError` from `repr()` / `==` on the deep value aborts a whole `verify_many`) | Untrusted JSON is refused past **100** levels of nesting where it enters, with the format's own typed error. Objects handed over already parsed, including those an injected fetch returns, are held to the same bound, and `verify_many` isolates the item |
| Host a DID document that is valid JSON but the wrong shape (a `null` or scalar `verificationMethod`, a relationship that is not an array, a `didDocument` wrapper that is not an object, a method whose `id` is not a string) for the `did:web` / `did:webvh` issuer an unsigned token names | **Batch abort** (a bare `TypeError` / `AttributeError` from the parser aborts a whole `verify_many`), and a wrong-typed relationship read as "not declared" would leave the key purpose unenforced | `parse_did_document` raises `DidResolutionError` for a wrong-typed container (the pipeline reports `KeyResolutionFailed` for that item on the JOSE lanes and the async API, `KeyResolutionError` on the sync Data Integrity lane) and never reads it as absent; an entry without a string `id` is dropped and selects no key or purpose. The same parser serves `did:web`, `did:webvh` and the EBSI DID Registry |
| Ship a tiny highly-compressible status list | **Decompression bomb** (OOM DoS) | Status decode caps the *decompressed* output at 16 MiB and fails closed (`StatusListError`), reading incrementally so a bomb is never materialised |
| Point `credentialSchema` at a schema with a catastrophic `pattern` | **ReDoS** (CPU DoS) | Schema validation is **opt-in**; remote `$ref` is off (no SSRF via `$ref`). Residual `pattern`-ReDoS is a documented limitation (mitigation tracked) — point the schema resolver at trusted hosts |
| Swap / replay a status list or presentation | Stale-status / replay accept | Status-list token `sub` must equal the fetched URI (anti-swap); presentations bind `aud` + one-time `nonce`/`challenge`; a fetched status list is **verified** before it is trusted. On SD-JWT VC with `require_key_binding=True`, the KB-JWT is verified even when the issuer JWT is expired, so an `EXPIRED` verdict is not a substitute for holder binding. A KB-JWT's `iat` is required and bounded both ways — no older than `kb_max_age_s` (default 300 s) at `now`, never future-dated (RFC 9901 §7.3 step 5.5) — the one freshness bound a stateless verifier owns, since nonce age is the caller's |
| Backdate / post-date validity | Expired/not-yet-valid accept | Temporal checks on `validFrom`/`validUntil` (+ VCDM 1.1 aliases) and proof `expires`, on every lane that carries a VCDM credential: Data Integrity, VC-JWT, and an SD-JWT whose payload is a VCDM credential (`vc+sd-jwt`), where the JWT `exp` only dates the signature (VC-JOSE-COSE §3.1.3). An IETF SD-JWT VC's claims are never read as that window. A **present-but-unparseable** timestamp fails **closed**, never silently skipped. `require_not_expired=False` waives only the credential's own expiry, never `nbf`/`validFrom` or a date the default policy refuses as malformed, and the suite that skipped the check reports it: `expired=True` exactly when the default policy would have rejected. The trust inputs openvc verifies for you are never waived: a status-list credential (through the blessed resolvers), a `JsonSchemaCredential`, an `x5c` chain. On the VC-JWT, SD-JWT VC (issuer JWT and KB-JWT), VP-JWT, status-list token and OpenID4VCI key-proof lanes a present `exp`/`nbf`/`iat` must be a finite JSON number, `null` included: `NaN`/`Infinity` would make every comparison false, i.e. *never expires*. A token at or past `exp` plus the leeway has expired; a future `nbf`, or an `iat` more than the leeway in the future, is rejected, and the expiry waiver covers neither |
| Replay a VC-JWT addressed to another relying party | Audience-restricted token accepted by anyone who holds it | RFC 7519 §4.1.3 on both VC-JWT lanes: a token with `aud` verifies only when the caller passes an audience that is in it ([ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md)) |
| Withhold a selectively-disclosed status/schema | Skip a fail-closed gate | Documented caveat: an issuer that needs status/schema enforced must make the pointer **non-selectively-disclosable** (mandatory for ecdsa-sd, outside `disclosable` for SD-JWT) |
| Replay an SD-JWT VC + KB-JWT from another session, or relay one made for another verifier, to a caller that passed only `audience` or only `nonce` | Half-checked holder binding (`key_bound=True` after checking one of the two values) | A present KB-JWT is checked against `aud` **and** `nonce` together (RFC 9901 §7.3 step 5.6). Passing exactly one of them, or an empty one, raises `ClaimsInvalid` before any KB-JWT crypto runs. That stops a misleading flag; it does not stop the replay by itself, since a stripped KB-JWT still verifies with `key_bound=False`. `require_key_binding=True` (or checking `key_bound`) does. With neither value, `key_bound=True` is documented as possession only ([details](SD-JWT-VC)) |
| Wrap an SD-JWT VC + KB-JWT made for another verifier inside their own, correctly bound `jwt_vc_json` / `ldp_vc` presentation | Borrowed holder binding (a nested `key_bound=True` that vouches for a proof made for someone else) | A KB-JWT nested in a W3C presentation, bare or enveloped, must carry the **same** `aud` + `nonce` as that presentation (VP-JWT `aud` / `nonce`, Data Integrity `domain` / `challenge`), or the whole response is rejected. A nested SD-JWT without a KB-JWT is rejected unless the query opts out of holder binding, and then reports `key_bound=False` ([details](Presentations#sd-jwt-vcs-nested-in-a-w3c-presentation)) |
| Wrap a credential issued to someone else (a VC-JWT, a Data Integrity VC, or an SD-JWT VC with its KB-JWT stripped) inside their own, correctly bound `jwt_vc_json` / `ldp_vc` presentation | Present a victim's credential as their own (a relay by a verifier that once received it) | DCQL `require_cryptographic_holder_binding` (default `true`, OpenID4VP 1.0 §6.1) is enforced on the W3C formats: each embedded VC-JWT / Data Integrity VC must name the **authenticated** VP signer as its subject, and each nested SD-JWT VC must carry a KB-JWT bound to this exchange, or the whole response is rejected. A non-boolean flag is malformed, never coerced to `false` ([details](Presentations#holder-binding-on-the-w3c-formats)) |
| MITM a fetch | Tamper in transit | TLS with certificate validation and SNI on the pinned connection |
| Present a forged or replayed **key proof** to an issuer, to obtain a credential bound to a key they do not control | Wrong *issue* | `openvc.openid4vci`: the `openid4vci-proof+jwt` `typ` pin (no replaying a KB-JWT / VP-JWT / status-list token as a key proof), the allow-list before any crypto, **exactly one** of the `jwk`/`kid`/`x5c` header key parameters (two lets an attacker pair an honest `kid` with their own `jwk`), the key↔`alg` (kty, crv) binding, `aud` pinned to this Credential Issuer with a multi-valued `aud` rejected, and **`iat` freshness both ways** (a future-dated proof would otherwise never expire). Nonce single-use is the caller's, injected as a **required** callable and consumed once, after every signature verifies. A proof carrying a `key_attestation` must be signed by one of its `attested_keys` — but that check is **conformance, not defence**: the attestation's own signature is never verified, so a forger attests their own key; it catches an honest wallet, or your resolver, yielding a key the wallet never claimed. Believing an attestation is your job |

## Design posture

- **Fail closed.** Ambiguity, an unresolvable key, a malformed timestamp, an
  unrecognised status/schema shape, or a missing opted-in resolver all *reject*
  rather than accept.
- **Least authority on the network.** Every dereference is https-only and
  SSRF-guarded by default; nothing is fetched from an allow-list openvc did not vet.
- **HSM-friendly.** Key material need never enter the process.

## Observability

openvc is silent and dependency-free by default: it attaches a `NullHandler` to the
`openvc` logger and uses a no-op span hook. Two opt-ins let an operator see *why* a
verification accepted or rejected a credential, without pulling in a tracing dependency.

<!-- docs: no-run -->
```python
import logging
from openvc.observability import set_span_hook

# 1. Structured logs: the "openvc" logger is silent until you attach a handler.
logging.getLogger("openvc").setLevel(logging.DEBUG)
logging.basicConfig()

# 2. Spans: bridge to your tracer (OpenTelemetry, ...); a no-op until set.
set_span_hook(lambda name, attrs: tracer.start_as_current_span(name, attributes=attrs))
```

Neither logs nor spans carry credential contents or private key material — only format,
DIDs and outcomes — so enabling them does not widen the attack surface. See the
[Observability API](https://luisgf.github.io/openvc/api/observability/).

## Out of scope

- Compromise of a trusted anchor, of the host, or of the `SigningKey` backend.
- Availability of remote issuers / status lists (openvc bounds *its own* resource
  use — response size, decompressed size, recursion — but cannot guarantee a third
  party is reachable).
- Anything an **injected** resolver does after openvc hands it a URL, if the caller
  supplies a custom one instead of the guarded default.
- Side-channels in the underlying `cryptography` / `pyjwt` primitives.
