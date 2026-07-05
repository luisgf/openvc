# Changelog

All notable changes to **openvc** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/luisgf/openvc/releases/tag/v0.1.0
