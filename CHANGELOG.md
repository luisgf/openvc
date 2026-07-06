# Changelog

All notable changes to **openvc** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[0.5.0]: https://github.com/luisgf/openvc/releases/tag/v0.5.0
[0.4.0]: https://github.com/luisgf/openvc/releases/tag/v0.4.0
[0.3.1]: https://github.com/luisgf/openvc/releases/tag/v0.3.1
[0.3.0]: https://github.com/luisgf/openvc/releases/tag/v0.3.0
[0.2.1]: https://github.com/luisgf/openvc/releases/tag/v0.2.1
[0.2.0]: https://github.com/luisgf/openvc/releases/tag/v0.2.0
[0.1.0]: https://github.com/luisgf/openvc/releases/tag/v0.1.0
