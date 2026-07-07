# Changelog

All notable changes to **openvc** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] — unreleased

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Async-friendly verification (`openvc.aio`).** New `verify_credential_async` /
  `verify_many_async` — the async counterparts of `verify_credential` / `verify_many`
  for asyncio servers (FastAPI/Starlette), so a handler `await`s verification instead of
  offloading the whole call to a thread pool, and a presentation cascade resolves its
  issuers/status-lists **concurrently** (`asyncio.gather`) instead of serialising N
  blocking fetches. Same formats, same `VerificationPolicy`, same `VerificationResult`,
  same fail-closed guarantees — the async path **reuses every proof suite, status/schema
  codec and binding check unchanged** and only re-expresses the I/O sequencing with
  `await` (no second implementation of any signature check; see
  [ADR-0002](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0002-async-verification.md)).
  New injection points mirror the sync ones with awaitables: an `AsyncDidResolver` /
  `AsyncDidResolverRegistry` (+ `as_async_resolver` to adapt any sync resolver), an
  `AsyncDidWebResolver`, `openvc.fetch.https_{json,text,bytes}_fetch_async`, and async
  default resolvers in `openvc.resolvers`. The batteries-included async fetch runs the
  **exact same** SSRF/DNS-rebind guard under `asyncio.to_thread` — identical guarantees,
  **no new dependency** (a caller may inject an `httpx.AsyncClient`-backed fetch instead).
  `verify_many_async` deliberately does not port the sync batch's cross-credential resolver
  cache (not concurrency-safe — ADR-0002 D4); overlapping the I/O is the win.
  ([#27](https://github.com/luisgf/openvc/issues/27))

## [1.8.0] — unreleased

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **`JsonSchemaCredential` — the schema-in-a-VC type.** `openvc.schema` now validates a
  `credentialSchema` entry of type `JsonSchemaCredential`, where the schema a credential
  points at is itself a **signed Verifiable Credential**. The pipeline fetches that VC,
  **verifies its proof** through the same `verify_credential` path — so every DID / x5c /
  status resolver the caller wired applies to it too, fail-closed — and applies the JSON
  Schema nested in its verified `credentialSubject.jsonSchema` to the outer credential.
  Recognised by `verify_credential(resolve_credential_schema=…)` and by standalone
  `openvc.schema.validate_credential_schema(…, verify_inner=…)`; the schema layer takes the
  verifier as an injected callable, so it stays free of an import cycle with the pipeline.
  **Bounded and fail-closed:** the schema-defining VC's *own* `credentialSchema` (the
  meta-schema) is not re-fetched, so a hostile chain of schema-VCs cannot loop; a `digestSRI`
  on the entry is enforced over the exact VC bytes before any parse/verify; the inner VC must
  actually carry the `JsonSchemaCredential` type, so a signature-valid but wrong-typed VC
  cannot stand in as the schema authority; and any inner-proof failure surfaces as a typed
  `SchemaResolutionError`. Previously such an entry raised `UnsupportedSchemaType`. Behind the
  `[schema]` extra; remote `$ref` resolution stays off.
  ([#28](https://github.com/luisgf/openvc/issues/28))

## [1.7.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Optional observability — stdlib logging + an injectable span hook.** New
  `openvc.observability`: a `logging.getLogger("openvc")` that emits structured events at
  the **resolve / fetch / status / verify** boundaries, plus `span()` / `set_span_hook()`
  — a no-op-by-default tracing hook an integrator wires to OpenTelemetry in one line
  (`set_span_hook(lambda name, attrs: tracer.start_as_current_span(name, attributes=attrs))`).
  Both are **off by default and dependency-free**: the logger carries only a `NullHandler`
  (so `import openvc` prints nothing until the app attaches a handler and lowers the level),
  and the hook is a no-op until installed — no tracing dependency enters core. Events and
  span attributes carry **public identifiers only** (format, issuer/subject DID, the DID or
  URL host, a check's outcome); private-key material, token bytes, `proofValue`, SD-JWT
  disclosures and claim contents are **never** logged. **Observability never changes a
  verification outcome:** a hook that errors — or one that tries to suppress an exception —
  can neither break a verification nor turn a fail-closed check (e.g. an unreachable status
  list) into a fail-open one. ([#25](https://github.com/luisgf/openvc/issues/25))

## [1.6.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Batch verification API.** New `openvc.verify_many(credentials, …)` verifies a list of
  credentials in one call, resolving each distinct issuer DID / status list / schema /
  issuer-metadata URL **once** — roughly O(distinct issuers), not O(credentials) — via
  the per-call caches of the new `openvc.cache.batch_resolvers`. Each credential is
  verified **independently and fail-closed**: a failure in one (bad signature, revoked,
  unresolvable key, …) becomes that item's `error` and never aborts the others. Returns a
  `BatchResult` (`index` / `ok` / `result` / `error`) per input credential, in order. The
  **VP-JWT cascade** now reuses the same dedup, so a presentation whose embedded
  credentials share an issuer resolves that DID once instead of once per credential — while
  staying fail-fast (a VP is valid only if every credential is). Composes with the core TTL
  cache ([#23](https://github.com/luisgf/openvc/issues/23)); no new dependency.
  ([#24](https://github.com/luisgf/openvc/issues/24))

### Fixed

- **`parse_status_entries` fails closed on a hostile `credentialStatus.type`.** A signed
  credential whose status entry's `type` was a non-iterable or a list carrying an
  unhashable member (e.g. `[{…}]`) raised a bare `TypeError` from the set intersection —
  escaping the `OpenvcError` contract (and, in `verify_many`, aborting the whole batch
  instead of failing that one credential). Such a `type` is now filtered to its string
  members and skipped like any unrecognized type. (Found in the #24 adversarial review.)

## [1.5.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Core TTL cache for the resolution paths.** New `openvc.cache` — a thread-safe,
  bounded, pure-stdlib `TtlCache` plus two opt-in wrappers: `CachingDidResolver` (memoizes
  `resolve(did)` — skipping the `did:web` round-trip on a batch from one issuer) and
  `cached_resolve` (wraps any `resolve_status_list` / `resolve_credential_schema` / fetch
  `Callable[[str], …]`). Only successful results are cached — a transient failure is
  retried, never pinned. **Freshness is a security property for status:** a cached status
  list cannot see a revocation until it expires, so `cached_resolve` defaults to a short
  TTL (`DEFAULT_STATUS_TTL_S = 60s`) while DID docs tolerate a longer one
  (`DEFAULT_DID_TTL_S = 300s`). Caching stays opt-in (the pipeline default resolves
  uncached, like the guarded resolvers). The thread-safe `TtlCache` that previously lived
  only in `openvc_ebsi.http` is now this core primitive, which the EBSI client consumes
  downward. No new dependency. ([#23](https://github.com/luisgf/openvc/issues/23))

## [1.4.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **`ecdsa-rdfc-2019` Data Integrity cryptosuite (whole-document ECDSA over RDF).** New
  `openvc.proof.di_ecdsa_rdfc.EcdsaRdfcProofSuite` — the ECDSA analogue of
  `eddsa-rdfc-2022`: same RDF N-Quads canonicalization (RDFC-1.0 / URDNA2015 via `pyld`)
  and config-first `hashData`, but signs **P-256/SHA-256** (ES256) or **P-384/SHA-384**
  (ES384) — raw R‖S, multibase `proofValue` — the digest chosen by the key's curve,
  reusing the multi-curve ECDSA handling built for `ecdsa-jcs-2019`. Wired into the
  `verify_credential` pipeline (`detect_format` → `data-integrity:ecdsa-rdfc-2019`).
  Behind the `[data-integrity]` extra (needs `pyld`, unlike the JCS suite). Pinned to the
  W3C *vc-di-ecdsa* `TestVectors/ecdsa-rdfc-2019-p256` and `…-p384` golden vectors: both
  SHA-256/384 `hashData` halves reproduce the published hex and each published
  `proofValue` verifies end to end via `did:key` (ECDSA is randomised, so — like
  `ecdsa-sd-2023` — interop is shown by matching intermediates and verifying reference
  proofs, not a byte-for-byte re-sign). ([#48](https://github.com/luisgf/openvc/issues/48))

## [1.3.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **P-384 signing (ES384) + P-384 on the `ecdsa-jcs-2019` cryptosuite.** New
  `openvc.keys.P384SigningKey` (ES384 — raw R‖S 96 bytes over SHA-384), and `ES384` is
  now on the JOSE allow-list beside `ES256` / `EdDSA` — a **deliberate** widening;
  `RS*` / `HS*` / `alg:none` stay rejected before any crypto. The whole-document
  `EcdsaJcsProofSuite` (`ecdsa-jcs-2019`) is now curve-flexible: **P-256/SHA-256**
  (ES256) or **P-384/SHA-384** (ES384), the digest chosen by the key's curve. `did:key`
  resolution gains the P-384 multicodec (`0x1201`, `z82…`). Pinned byte-for-byte to the
  W3C *vc-di-ecdsa* Recommendation §A.6 P-384 `ecdsa-jcs-2019` example (both SHA-384
  hashes reproduced and its published **high-S** signature verified via `did:key`).
  The RDF `ecdsa-rdfc-2019` suite is a follow-up
  ([#48](https://github.com/luisgf/openvc/issues/48)).
  ([#22](https://github.com/luisgf/openvc/issues/22))

## [1.2.0] — 2026-07-07

Completes the [1.1 — EUDI verifier interop](https://github.com/luisgf/openvc/milestone/3)
milestone: HAIP `direct_post.jwt` response decryption and SD-JWT VC Type Metadata, plus
the recorded OpenID4VP/HAIP conformance drift alarm.

### Added

- **SD-JWT VC Type Metadata (verifier side).** New `openvc.type_metadata` with
  `validate_type_metadata(payload, *, vct, vct_integrity, resolve)` — resolves the Type
  Metadata a credential's `vct` points to (draft-ietf-oauth-sd-jwt-vc-17 §4), pins it
  with `vct#integrity` (a W3C Subresource-Integrity hash over the raw bytes), enforces
  `metadata.vct == credential.vct`, walks the `extends` chain (parent-before-child, each
  integrity-pinned, cycle-/depth-bounded), composes the inherited claim metadata, and
  validates the processed payload against it — the DCQL-style `path` engine plus
  `mandatory`. Fetch is opt-in (`openvc.resolvers.default_type_metadata_resolver`, over
  the SSRF-guarded https fetch) and every failure is fail-closed. Reuses the reviewed
  digestSRI check and the JSON-fetch guards from the `credentialSchema` work.
  (Scope note: the draft removed embedded JSON Schema in draft-12, so validation is via
  the `claims` array, not a JSON Schema; the per-claim `sd` constraint needs disclosure
  provenance and is a documented non-goal.) Pinned to the draft-17 Appendix B.2 worked
  example. ([#21](https://github.com/luisgf/openvc/issues/21))
- **Decrypt HAIP / OpenID4VP 1.0 encrypted responses (`direct_post.jwt`).** New
  `openvc.jwe` with `decrypt_compact(token, *, key)` — a **decrypt-only** JWE Compact
  path for the JWE that wraps a `vp_token` in a HAIP response. Exactly the
  HAIP-mandated shape is accepted, **allow-listed before any crypto**: direct
  `ECDH-ES` key agreement (empty encrypted key) + `A128GCM` / `A256GCM` content
  encryption over an ephemeral **P-256** key. The ECDH runs through a new
  `openvc.keys.KeyAgreementKey` backend (`P256KeyAgreementKey`), mirroring
  `SigningKey` so the recipient's private half can live in an HSM/Vault; the public
  NIST SP 800-56A Concat KDF (RFC 7518 §4.6) and AES-GCM decrypt are done in-library.
  `openvc.openid4vp.verify_encrypted_vp_response(...)` (also `openvc.verify_encrypted_vp_response`)
  bridges it to [#18](https://github.com/luisgf/openvc/issues/18): decrypt then verify
  the `vp_token` with the same `nonce` / `client_id` binding. Pinned byte-for-byte to
  RFC 7518 Appendix C (the Concat KDF), a real OpenID4VP 1.0 §8.3 `ECDH-ES`+`A128GCM`
  JWE, and the RFC 7520 §5.5 key agreement; fails closed on a disallowed `alg`/`enc`,
  an off-curve or non-P-256 ephemeral key, a bad shape, or a failed tag.
  ([#19](https://github.com/luisgf/openvc/issues/19))

## [1.1.0] — 2026-07-07

The first slice of the [1.1 — EUDI verifier interop](https://github.com/luisgf/openvc/milestone/3)
milestone: OpenID4VP 1.0 `vp_token` verification and the pyld-free JCS Data Integrity
cryptosuites. The remaining milestone items (HAIP JWE-response decryption, SD-JWT VC
Type Metadata) land in later releases.

### Added

- **OpenID4VP 1.0 `vp_token` verification (stateless).** New `openvc.openid4vp` with
  `verify_vp_token(vp_token, *, dcql_query, nonce, client_id, …)` (also exported as
  `openvc.verify_vp_token`) — a read/verify-only verifier for the presentation half of
  OpenID for Verifiable Presentations 1.0 (Final, 2025-07-09). It validates the
  response shape (a JSON object keyed by DCQL Credential Query `id`, values are arrays
  — §8.1), routes each Presentation to the matching suite by `format` (`dc+sd-jwt`
  SD-JWT VC + KB-JWT, and `jwt_vc_json` W3C VP-JWT), and enforces the holder binding:
  the transaction `nonce` and the **full, prefixed** Client Identifier as the audience
  (e.g. `x509_san_dns:client.example.org`, not the bare host — §14.2 / §15.11). It
  builds no Authorization Request and keeps no session; `ldp_vc` / `mso_mdoc` raise a
  typed `UnsupportedPresentationFormat` (follow-ups, not silently skipped), and any
  binding/shape failure fails closed. Adversarially reviewed — the format is pinned to
  the query's DCQL `format` so a VC-JWT cannot be smuggled under a `dc+sd-jwt` query to
  skip the KB-JWT nonce binding (a cross-session replay), and every hostile
  `vp_token`/`dcql_query` shape raises a typed error.
  ([#18](https://github.com/luisgf/openvc/issues/18))
- **JCS Data Integrity cryptosuites — `eddsa-jcs-2022` and `ecdsa-jcs-2019`.** A
  whole-document Data Integrity path that canonicalizes with **RFC 8785 JSON
  Canonicalization Scheme** instead of RDF N-Quads, so it needs **no `pyld`** — the
  hand-rolled canonicalizer (`openvc.proof._jcs`) is pure stdlib, including a
  correct ECMAScript `Number.prototype.toString` serializer and UTF-16 code-unit
  member ordering. New `openvc.proof.di_jcs` exposes `EddsaJcsProofSuite` (Ed25519)
  and `EcdsaJcsProofSuite` (ECDSA P-256 / SHA-256); the verify pipeline
  (`verify_credential`) detects and dispatches both. The canonicalizer is pinned
  byte-for-byte to the WebPKI/cyberphone RFC 8785 reference suite and the RFC 8785
  Appendix B number table, and the `eddsa-jcs-2022` suite is pinned to the W3C
  *Data Integrity EdDSA Cryptosuites v1.0* Recommendation worked example (both
  SHA-256 hashes reproduced, and its published Ed25519 `proofValue` verified end to
  end via `did:key`). Verification **fails closed** on hostile input — non-finite
  numbers (`json` accepts `NaN`/`Infinity` by default), deeply-nested documents, a
  cross-curve verification key, or a wrong-length signature all raise a typed
  `ProofError`, never a bare exception — hardened after an adversarial review and a
  differential number-serialization fuzz against the reference oracle. The RDF
  `eddsa-rdfc-2022` / `ecdsa-sd-2023` suites are unchanged.
  ([#17](https://github.com/luisgf/openvc/issues/17))

## [1.0.1] — 2026-07-07

### Security

- **Fail closed on hostile ecdsa-sd CBOR proof values.** `decode_cbor` — which
  parses attacker-controlled proof-value bytes — raised a bare `UnicodeDecodeError`
  on a text string of invalid UTF-8, and a `TypeError` on a map with an unhashable
  (map/list) key; both now fail closed as `ProofValueMalformed`. Uncovered by new
  property-based fuzzing of the hand-rolled codecs (CBOR, base58btc/multibase,
  bitstring, token status list) that asserts decode never raises outside the typed
  `OpenvcError` family, plus an explicit MUST-REJECT corpus (behind the `hypothesis`
  dev dependency). ([#11](https://github.com/luisgf/openvc/issues/11))

## [1.0.0] — 2026-07-07

The first stable release — a frozen, documented public surface. This heading
accumulates the [1.0 — Stabilize](https://github.com/luisgf/openvc/milestone/2)
milestone; it ships once that work is complete.

### Added

- **Demarcated public API surface.** Every public module now declares an explicit
  `__all__` — the frozen, SemVer-protected surface toward 1.0. The two signing
  backends and the `SigningKey` protocol join the package root
  (`from openvc import Ed25519SigningKey, P256SigningKey, SigningKey`, alongside
  `verify_credential` & co.). The shared policy errors (`CredentialExpired`,
  `ProofPurposeMismatch`, …) now have a canonical home in `openvc.proof.errors`
  (re-exported from `_verify_common` and the suites for back-compat), so the whole
  proof-error taxonomy imports from one place. `docs/CONVENTIONS.md` gains a
  "Public surface & stability" section documenting where to import stable names and
  which paths are internal. ([#6](https://github.com/luisgf/openvc/issues/6))
- **Frozen return-object contract.** `VerificationResult`, `VerificationPolicy` and
  the per-suite `Verified*` dataclasses now have their field set pinned as public,
  **add-only** API (a `tests/test_return_contract.py` drift alarm asserts the exact
  fields): a field may be added with a default, never removed/renamed/reordered
  without a major bump. Documented in CONVENTIONS.md.
  ([#7](https://github.com/luisgf/openvc/issues/7))
- **Versioning & deprecation policy** (`docs/versioning.md`) — a published SemVer
  contract: what MAJOR/MINOR/PATCH mean, what the stability guarantee covers (the
  `__all__` surface + the return-object contract), and the deprecation cycle
  (`DeprecationWarning` + a CHANGELOG note for ≥1 minor before removal at a major).
  ([#8](https://github.com/luisgf/openvc/issues/8))
- **`credentialSchema` `digestSRI` is enforced** (`openvc.schema`) — when a
  credential pins its schema with a `sha256-`/`sha384-`/`sha512-` subresource-
  integrity hash, the hash is verified over the raw schema bytes (constant-time,
  strongest algorithm wins) **before** the schema is parsed; a mismatch fails closed.
  An issuer can thus pin the exact schema so even a compromised schema host cannot
  swap it. A guarded `openvc.fetch.https_bytes_fetch` backs it.
  ([#10](https://github.com/luisgf/openvc/issues/10))
- **Threat model** (`docs/threat-model.md`) — assets (the verify decision, signing
  keys, trust anchors), trust boundaries (the credential, network dereferences, the
  SigningKey backend, injected resolvers), and an attacker-capability → control map
  (alg-confusion, issuer impersonation, SSRF, decompression bomb, replay, temporal,
  selective-disclosure) for audit readiness. ([#16](https://github.com/luisgf/openvc/issues/16))
- **Stricter typing of the shipped surface** — mypy now enforces
  `disallow_untyped_defs` / `disallow_incomplete_defs` / `no_implicit_optional`, and
  the remaining annotation gaps are filled, so a downstream type-checker consuming
  openvc's `py.typed` annotations is not degraded.
  ([#15](https://github.com/luisgf/openvc/issues/15))
- **Docstrings on the frozen surface** — the remaining undocumented public names
  (the `SigningKey` protocol + backends and their methods, the `ecdsa_sd` codec
  functions, the DID resolver/registry) now carry a one-line docstring, so the
  generated API reference is complete. ([#14](https://github.com/luisgf/openvc/issues/14))

### Changed

- **BREAKING: `resolve_credential_schema` now returns `bytes`**, not a parsed
  ``dict`` — so a `credentialSchema.digestSRI` can be verified over the exact
  response before parsing. The blessed `openvc.resolvers.default_credential_schema_resolver`
  is updated; a custom schema resolver must return the raw bytes.
  ([#10](https://github.com/luisgf/openvc/issues/10))
- **BREAKING: unified proof-error taxonomy** (openvc.proof.errors). `ProofError`
  moved out of the `openvc.proof.vc_jwt` format module into a new
  `openvc.proof.errors` module (still re-exported from `vc_jwt` for now), and the
  leaf errors that mean the same thing across suites — `SignatureInvalid`,
  `ProofMalformed`, `UnsupportedCryptosuite` (and `UnsupportedAlgorithm`,
  `MalformedToken`, `ClaimsInvalid`) — are now **single shared classes** there
  instead of one-per-suite, so `except SignatureInvalid` (imported from any suite
  path) catches whichever suite raised it. The suite roots `SdJwtError`,
  `EcdsaSdError` / `ProofValueMalformed` and `DataIntegrityError` stay for genuinely
  suite-specific failures. **Migration:** `except ProofError` and
  `except SignatureInvalid` are unaffected; `except DataIntegrityError` /
  `except EcdsaSdError` no longer catch a signature or proof-malformed failure (those
  are now shared under `ProofError`) — catch `ProofError` or the specific leaf.
  ([#4](https://github.com/luisgf/openvc/issues/4))

### Deprecated

- **Verb-last `openvc.proof.ecdsa_sd` codec names.** `cbor_encode`/`cbor_decode`,
  `serialize_base_proof`/`parse_base_proof` and
  `serialize_derived_proof`/`parse_derived_proof` are now deprecated aliases of the
  verb-first `encode_cbor`/`decode_cbor`, `encode_base_proof`/`decode_base_proof` and
  `encode_derived_proof`/`decode_derived_proof`. Accessing a deprecated name now
  emits a `DeprecationWarning`; they are removable at the next major.
  ([#5](https://github.com/luisgf/openvc/issues/5))

## [0.9.0] — 2026-07-06

### Added

- **Blessed SSRF-guarded default resolvers** (`openvc.resolvers`) — the status and
  schema fetch paths in `verify_credential` are caller-injected, so `openvc.fetch`'s
  SSRF guard protected them only if the integrator wired it. New factories make the
  secure path the easy path: `default_credential_schema_resolver`,
  `default_status_list_resolver` (W3C Bitstring) and `default_status_list_token_resolver`
  (IETF) fetch through the guarded https fetch and, for status, **verify** the fetched
  list through the pipeline before trusting it (a fetched-but-unverified status list
  would let a forged one clear revocation). A companion `openvc.fetch.https_text_fetch`
  adds a guarded text fetch for the JWS-shaped status resources. A custom resolver
  still opts out of the guard (documented in SECURITY.md).
  ([#3](https://github.com/luisgf/openvc/issues/3))

## [0.8.1] — 2026-07-06

### Security

- **Bounded status-list decompression (compression-bomb defense)** — `decode_bitstring`
  (gzip) and `decode_status_list` (zlib) now cap the decompressed output at 16 MiB and
  fail closed with `StatusListError` instead of inflating unbounded. A status list is
  fetched from an issuer-named URL through a **caller-injected** resolver, so
  `openvc.fetch`'s 1 MiB wire cap never protected this path (and that cap is on the
  *compressed* size); a ~1 KB `encodedList` / `lst` could inflate to gigabytes and OOM
  the verifier during the routine revocation check every credential's status
  dereferences. Decode now reads incrementally and never materialises past the ceiling.
  ([#2](https://github.com/luisgf/openvc/issues/2))

## [0.8.0] — 2026-07-06

### Added

- **`credentialSchema` validation (W3C VC JSON Schema)** (`openvc.schema`) — the
  verification pipeline can now validate a credential against the JSON Schema it
  declares. Pass `resolve_credential_schema=` to `verify_credential` (e.g.
  `openvc.fetch.https_json_fetch`) and each declared `JsonSchema` is fetched and the
  whole credential validated against it; a mismatch raises `SchemaValidationError`.
  It is **opt-in** — schema conformance is a data-shape check, not a revocation gate
  — so it runs only when a resolver is supplied; set
  `VerificationPolicy.require_schema=True` to reject a credential that *declares* a
  schema but is verified without one (symmetric with `require_status`). Once opted
  in, every sub-step is fail-closed: an unreachable schema, a resource that is not a
  valid JSON Schema, a resource without `$schema` (which the spec says MUST NOT be
  processed), or an unsupported type all raise. The JSON Schema processor is the new
  optional `[schema]` extra (`jsonschema>=4.18`), imported lazily; without it a
  credential that needs validation raises `SchemaBackendUnavailable`. Remote `$ref`
  resolution is off — a non-fetching `referencing` registry is wired, so a remote
  `$ref` fails closed with no network call instead of letting `jsonschema` fetch an
  attacker-named URL (SSRF). `JsonSchemaCredential` is recognised but raises
  `UnsupportedSchemaType` for now. Schemas are untrusted input: `pattern` keywords
  run on Python's backtracking regex, so point `resolve_credential_schema` at hosts
  you trust (documented in `openvc.schema`).

## [0.7.1] — 2026-07-06

### Fixed

- **Signing a VC-JWT for a credential without an `id` no longer emits a null `jti`**
  (which RFC 7519 / PyJWT reject on verification), so an id-less credential now
  round-trips.
- **`VpJwtProofSuite.verify` defaults its resolver** to the offline
  `did:key`/`did:jwk` + SSRF-guarded `did:web` registry (like `verify_credential`),
  instead of requiring a resolver when the holder key is not pinned.

## [0.7.0] — 2026-07-06

### Added

- **Presentation binding for Data Integrity** (`challenge` / `domain`).
  `DataIntegrityProofSuite.add_proof` accepts `challenge=` / `domain=` (for an
  `authentication`-purpose proof), and `verify` enforces them via
  `expected_challenge=` / `expected_domain=` (domain may be a string or a list),
  binding a presentation proof to a verifier session against replay. Both are part
  of the signed proof config, so they are tamper-proof.
- **VP-JWT holder presentations** (`openvc.proof.vp_jwt`) — a holder wraps
  credentials in a `vp` object and signs it, binding the presentation to a verifier
  (`aud`) and a one-time challenge (`nonce`). `VpJwtProofSuite.verify` checks the
  holder signature and temporal claims, enforces `aud`/`nonce` (replay protection),
  and **cascade-verifies every embedded credential** through
  `verify_credential` — so a presentation is accepted only when the holder is
  authentic and each credential in it verifies. The holder key is resolved via an
  injected resolver or pinned.
- **Library-wide `OpenvcError` root** (`openvc.errors`). Every error openvc raises
  now descends from `OpenvcError`, so one `except OpenvcError` catches any openvc
  failure; the EBSI plugin's errors share an `EbsiError` root (itself an
  `OpenvcError`). Purely additive — the per-area roots (`ProofError`, `DidError`,
  `StatusListError`, `VerificationError`, …) and every specific error still exist
  and are still catchable individually.

### Security

- **SD-JWT temporal check fails closed on a malformed `exp`/`nbf`.** A present but
  non-numeric `exp`/`nbf` was silently skipped; it now raises `ClaimsInvalid`,
  matching the Data Integrity and status-list temporal checks (a NumericDate per
  RFC 7519).

## [0.6.0] — 2026-07-06

### Added

- **`did:jwk` resolver** (`openvc.did.did_jwk`) — the self-contained method whose
  identifier is a base64url-encoded public JWK (common in EUDI / OID4VC stacks).
  Offline like `did:key`; a `did:jwk` encoding a private key (with `d`) is refused.
  Registered in the pipeline's `default_resolver`, so `verify_credential` resolves
  `did:jwk` issuers out of the box.
- **HTTPS issuer-key discovery** (`openvc.jwt_vc_issuer`) — for a JOSE credential
  whose `iss` is an https URL, the issuer's signing key is resolved from
  `/.well-known/jwt-vc-issuer` (draft-ietf-oauth-sd-jwt-vc), verifying the
  metadata's `issuer` equals the `iss` (anti-substitution), supporting inline
  `jwks` or a `jwks_uri`, and selecting the key by `kid`. Opt-in in the pipeline
  via `verify_credential(..., jwt_vc_issuer_fetch=https_json_fetch)` (pass the
  SSRF-guarded fetch); an https issuer without it fails closed. Private keys in the
  JWKS are refused.
- **X.509 `x5c` issuer trust** (`openvc.x5c`) — for a JOSE credential whose header
  carries an `x5c` certificate chain (eIDAS / EUDI document signers), validate the
  chain to caller-provided trust anchors and return the leaf's key. Path validation
  (signatures, validity, `basicConstraints`) is done by `cryptography`'s X.509
  verifier; only the TLS EKU is relaxed. The `iss` must be bound to the leaf via its
  Subject Alternative Name (URI or DNS-host match), closing a forge-any-issuer gap.
  Only an EC P-256 leaf is accepted. Opt-in in the pipeline via
  `verify_credential(..., x5c_trust_anchors=[roots])`.

### Changed

- **Minimum `cryptography` is now `>=45`** (was `>=42`) for the X.509
  path-validation `ExtensionPolicy` the `x5c` verifier relies on.

## [0.5.0] — 2026-07-06

### Added

- **Generic verification pipeline** (`openvc.verify`) — one call,
  `verify_credential`, that verifies a credential in any supported format against
  a `VerificationPolicy`, returning a unified `VerificationResult`. It detects the
  format (VC-JWT / SD-JWT VC / Data Integrity `eddsa-rdfc-2022` + `ecdsa-sd-2023` /
  an enveloped VCDM 2.0 credential, which it unwraps), resolves the issuer key via
  a `DidResolverRegistry` (JOSE formats peek the untrusted `iss`/`kid`; Data
  Integrity resolves the proof's `verificationMethod`), verifies through the
  matching suite, and applies policy: expected type(s)/`vct`, audience and
  holder-binding for SD-JWT, `proofPurpose`, and status. Exported from the package
  root (`openvc.verify_credential`). The EBSI glue becomes a specialisation of this
  shape.

### Security

- **Status checking in the pipeline is fail-closed and format-agnostic.** Both
  status conventions — the W3C `credentialStatus` and the IETF token `status`
  reference — are checked for every format, so a status declared in the shape that
  does not match the proof format is not silently skipped. A declared status with
  no resolver raises `StatusUnavailable` (opt out with `require_status=False`); a
  resolved *revoked* status raises `CredentialRevoked` and a *suspended* one the
  new `CredentialSuspended`.
- **Data Integrity issuer binding.** The pipeline accepts an embedded-proof
  credential only when the proof's `verificationMethod` is controlled by the
  credential's `issuer` (same DID), closing a forge-any-issuer gap where a signer
  could name an arbitrary issuer and sign with their own key (`IssuerBindingError`).
  Delegated cross-DID trust remains the job of a specialised verifier
  (`verify_ebsi_badge`).

## [0.4.0] — 2026-07-06

### Security

- **Data Integrity proofs now enforce the credential's validity window.** Both
  cryptosuites (`eddsa-rdfc-2022`, `ecdsa-sd-2023`) verified only the signature,
  so a signed-but-**expired** credential — or one not yet valid — verified as
  valid. `verify()` now checks `validFrom`/`validUntil` (VCDM 2.0) and
  `issuanceDate`/`expirationDate` (VCDM 1.1), plus the proof's optional
  `expires`, against the current time within a 60 s default leeway. **Behaviour
  change:** credentials outside their validity window that used to pass will now
  raise `CredentialExpired` / `CredentialNotYetValid`. A new `now=` parameter
  pins the evaluation instant (deterministic conformance / "as of" audits), and
  the leeway is configurable via the suite constructor (`leeway_s=`). A
  present-but-unreadable timestamp **fails closed** (`MalformedTimestamp`)
  instead of being skipped, and fractional seconds of any precision parse
  correctly (older Python's stricter `fromisoformat` no longer causes a silent
  expiry bypass). This brings Data Integrity to parity with the VC-JWT / SD-JWT
  suites, which already enforced `exp`/`nbf`.
- **Data Integrity proofs now enforce `proofPurpose` and DID
  verification-relationship binding.** `verify()` requires the proof's
  `proofPurpose` to match an expected value (default `assertionMethod`), and —
  when the key is resolved from a DID document rather than an injected JWK — that
  the `verificationMethod` is actually authorized by the document for that
  purpose. A `did:web` document that separates an assertion key from an
  authentication key now rejects a proof signed by the wrong one, instead of
  accepting any key it lists.

### Added

- **Injectable DID resolver for Data Integrity verification.** `verify()` takes a
  `resolver=` (a `DidResolver` / `DidResolverRegistry`), so `did:web` (and any
  registered method) now works with embedded proofs; offline `did:key` remains
  the no-argument fallback. `DidDocument` now captures the W3C verification
  relationships (`assertionMethod`, `authentication`, …) via `key_for_purpose`.
- **Status-list issuance** (`openvc.status`) — the issuer-side counterpart to the
  existing check side, so an issuer can revoke using only openvc.
  `build_status_list_credential` assembles an (unsigned) W3C
  `BitstringStatusListCredential` to sign with any suite;
  `build_status_list_token` / `verify_status_list_token` build and verify an IETF
  status-list token (`typ: statuslist+jwt`); `build_status_list_entry` and
  `build_token_status_reference` produce the pointer each issued credential/token
  carries; and `new_bitstring` allocates a zeroed W3C list (mirroring
  `new_status_list`). Round-trip tested both ways — build → sign → revoke an index
  → the check detects it — for VC-JWT and Data Integrity issuance.
- **Generic compact-JWS signer** (`openvc.proof._jws`) — the compact-JWS assembly
  was lifted out of `VcJwtProofSuite.sign` into `sign_compact` / `verify_compact`
  / `parse_compact`, so a non-VC token (the status-list token) signs through the
  same allow-listed `{ES256, EdDSA}` `SigningKey` path. `VcJwtProofSuite.sign` now
  delegates to it; its output is byte-for-byte unchanged.

## [0.3.1] — 2026-07-05

### Added

- **ecdsa-sd-2023 is now interop-validated against the official W3C `vc-di-ecdsa`
  test vectors** (`tests/fixtures/ecdsa_sd/`): `verify` accepts reference-produced
  derived proofs, and the issuer-side HMAC-relabeled canonical N-Quads and the
  `proofHash` / `mandatoryHash` match the recorded intermediates byte for byte.
  No code change from 0.3.0 — this ships the validation and drops the
  "interop pending" caveat from the docs (ECDSA is randomised, so interop is
  shown this way rather than by reproducing a fixed proof value).

## [0.3.0] — 2026-07-05

### Added

- **ecdsa-sd-2023 selective disclosure** (`openvc.proof.ecdsa_sd`) — the second
  Data Integrity cryptosuite (P-256) and the first with selective disclosure.
  `EcdsaSdProofSuite` covers the whole flow: an issuer `add_base_proof`
  (per-statement signatures under an ephemeral key, mandatory statements bound by
  the issuer key, HMAC-blinded blank nodes), a holder `derive_proof` (reveal only
  the chosen JSON pointers), and `verify`. The proof value is a hand-rolled CBOR
  blob checked against RFC 8949 — no new dependency. Round-trip and
  tamper/over-disclosure tested; byte-level interop against the official W3C
  vectors is tracked as a follow-up (ECDSA is randomised, so — unlike
  eddsa-rdfc-2022 — correctness cannot be shown by reproducing a fixed value).

## [0.2.1] — 2026-07-05

### Fixed

- **EBSI DID resolution and the TIR trust chain now work against the real v5
  API.** The HTTP client accepted only `application/json`, which the DID Registry
  rejects with `406` (it content-negotiates `application/did+ld+json`); it now
  accepts both. The TIR v5 adapter also read the accreditation from the wrong
  place — the signed body is nested under `attribute.body`, and
  `issuerType`/`tao`/`rootTao` sit on the `attribute` wrapper (not the
  `credentialSubject`, whose `accreditedFor` is a list of `{schemaId, types}`
  objects rather than type strings). Both were caught by new golden fixtures
  recorded verbatim from the pilot registry (`tests/fixtures/ebsi/`).

## [0.2.0] — 2026-07-05

### Added

- **IETF Token Status List** (`openvc.status.token_status_list`) — the second
  status-list encoding, behind the same `openvc.status` interface as the W3C
  Bitstring list: multi-bit statuses (1/2/4/8 bits, LSB-first) with DEFLATE/zlib
  compression, `status`-claim reference parsing, and `check_token_status`
  (VALID / INVALID → revoked / SUSPENDED → suspended) over an injected resolver.
- **SD-JWT VC** (`openvc.proof.sd_jwt`) — the third proof profile (the format
  EUDI/ARF converges on), alongside VC-JWT and Data Integrity. `SdJwtVcProofSuite`
  covers issuance (salted disclosures + `_sd` digests, decoys, `cnf` holder
  binding), holder presentation (a Key Binding JWT over `aud` / `nonce` /
  `sd_hash`), and verification (recursive unpacking of nested + array disclosures
  with the algorithm allow-list and unreferenced/duplicate/overwrite defences). A
  verified credential's `status` claim is checked via the Token Status List. Pure
  JOSE — no new dependency.

## [0.1.0] — 2026-07-05

First public release: a generic, HSM-friendly Verifiable Credentials core with an
optional read-only EBSI plugin.

### Added

- **Core** — VC-JWT proof suite (`VcJwtProofSuite`: peek / verify / sign) with a
  fixed `{ES256, EdDSA}` algorithm allow-list checked before any crypto;
  `Ed25519SigningKey` / `P256SigningKey` backends behind a `SigningKey` protocol
  (HSM/Vault drop-in; correct JOSE raw `R‖S` for ES256).
- **DID resolution** — `did:key` (offline), `did:web` (with an SSRF- and
  DNS-rebinding-safe stdlib fetch that pins the connection to the validated IP),
  the W3C DID-document model, resolver protocol and registry.
- **Data Integrity proof suite** — `eddsa-rdfc-2022` embedded proofs
  (`DataIntegrityProofSuite`), RDF canonicalization via `pyld`, offline bundled
  JSON-LD contexts; reproduces the official W3C vc-di-eddsa test vector byte for
  byte. Behind the `[data-integrity]` extra.
- **Status list** — W3C Bitstring Status List revocation/suspension
  (`openvc.status`): the bit codec plus `credentialStatus` parsing and checking.
- **EBSI plugin** (read-only, `[ebsi]` extra) — versioned DID Registry / TIR
  adapters, an HTTP client (TTL cache, status-aware retries, https-only host
  allow-list), the `verify_ebsi_badge` glue, and a recursive `TI → TAO → RootTAO`
  trust chain that verifies each accreditation's signature, enforces per-hop
  delegation scoping, and (optionally) status-list-checks the accreditations.

### Packaging

- PEP 561 typed (`py.typed`), single-source `openvc.__version__`, PEP 639 SPDX
  license metadata (LGPL-3.0-or-later). Core install depends only on
  `cryptography` + `pyjwt`; `httpx` and `pyld` are optional extras.
- Published on PyPI as the **`openvc-core`** distribution; the import package
  stays `openvc` (`pip install openvc-core`, then `import openvc`).

[1.7.0]: https://github.com/luisgf/openvc/releases/tag/v1.7.0
[1.6.0]: https://github.com/luisgf/openvc/releases/tag/v1.6.0
[1.5.0]: https://github.com/luisgf/openvc/releases/tag/v1.5.0
[1.4.0]: https://github.com/luisgf/openvc/releases/tag/v1.4.0
[1.3.0]: https://github.com/luisgf/openvc/releases/tag/v1.3.0
[1.2.0]: https://github.com/luisgf/openvc/releases/tag/v1.2.0
[1.1.0]: https://github.com/luisgf/openvc/releases/tag/v1.1.0
[1.0.1]: https://github.com/luisgf/openvc/releases/tag/v1.0.1
[1.0.0]: https://github.com/luisgf/openvc/releases/tag/v1.0.0
[0.9.0]: https://github.com/luisgf/openvc/releases/tag/v0.9.0
[0.8.1]: https://github.com/luisgf/openvc/releases/tag/v0.8.1
[0.8.0]: https://github.com/luisgf/openvc/releases/tag/v0.8.0
[0.7.1]: https://github.com/luisgf/openvc/releases/tag/v0.7.1
[0.7.0]: https://github.com/luisgf/openvc/releases/tag/v0.7.0
[0.6.0]: https://github.com/luisgf/openvc/releases/tag/v0.6.0
[0.5.0]: https://github.com/luisgf/openvc/releases/tag/v0.5.0
[0.4.0]: https://github.com/luisgf/openvc/releases/tag/v0.4.0
[0.3.1]: https://github.com/luisgf/openvc/releases/tag/v0.3.1
[0.3.0]: https://github.com/luisgf/openvc/releases/tag/v0.3.0
[0.2.1]: https://github.com/luisgf/openvc/releases/tag/v0.2.1
[0.2.0]: https://github.com/luisgf/openvc/releases/tag/v0.2.0
[0.1.0]: https://github.com/luisgf/openvc/releases/tag/v0.1.0
