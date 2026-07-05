# Changelog

All notable changes to **openvc** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — unreleased

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

[0.3.0]: https://github.com/luisgf/openvc/releases/tag/v0.3.0
[0.2.1]: https://github.com/luisgf/openvc/releases/tag/v0.2.1
[0.2.0]: https://github.com/luisgf/openvc/releases/tag/v0.2.0
[0.1.0]: https://github.com/luisgf/openvc/releases/tag/v0.1.0
