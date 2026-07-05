# openvc roadmap

Distilled from `SESSION-HANDOFF.md`, re-scoped for the independent `openvc`
project (Open Badges / image-baking items stay in the downstream badge library,
not here).

## Done

- Core proof suite (`VcJwtProofSuite`), key backends (`Ed25519SigningKey`,
  `P256SigningKey`), DID resolution (`did:key`, `did:web`), the DID document
  model + registry.
- EBSI plugin: versioned DID Registry / TIR adapters, the HTTP client (TTL cache,
  retries, SSRF allow-list), the version-agnostic domain model.
- **SSRF-guarded stdlib https fetch** for `did:web` (`openvc.fetch`) — https-only,
  blocks private/loopback/link-local/reserved ranges, refuses redirects.
- **`verify_ebsi_badge`** glue — peek → resolve → key select → signature/temporal
  verify → issuer trust over the TIR accreditations.
- **Recursive trust chain** (`openvc_ebsi.trust`) — walk `TI → TAO → RootTAO`,
  verifying every accreditation's signature against the accreditor's resolved
  key, up to a caller-supplied trusted RootTAO anchor. Wired into
  `verify_ebsi_badge` via `trust_anchors`. Enforces **per-hop delegation
  scoping** (each accreditor's `accreditedFor` must be a superset of the
  delegated scope) and, with a `resolve_status_list`, **status-list revocation of
  the accreditations** themselves (a revoked accreditation breaks the chain).
- **Status-list revocation** (`openvc.status`) — W3C Bitstring Status List bit
  codec (gzip + base64url, MSB-first) + `credentialStatus` parsing +
  `check_credential_status`. Wired into `verify_ebsi_badge` via
  `resolve_status_list` (a set revocation bit raises `CredentialRevoked`).
- **DNS-rebinding-safe `did:web` fetch** — the connection is pinned to the
  validated IP (resolve → validate → connect to that IP) while TLS SNI, cert
  validation and Host use the hostname, closing the TOCTOU window.
- **Data Integrity proof suite** (`openvc.proof.data_integrity`) —
  eddsa-rdfc-2022 embedded proofs (RDF canonicalization via pyld, offline
  bundled contexts), the second profile alongside VC-JWT. Verified byte-for-byte
  against the official W3C vc-di-eddsa test vector.
- **IETF Token Status List** (`openvc.status.token_status_list`) — the second
  status encoding behind the same `openvc.status` interface: 1/2/4/8-bit
  LSB-first statuses with DEFLATE/zlib, `status`-claim reference parsing, and
  `check_token_status` (VALID / INVALID → revoked / SUSPENDED → suspended).
- **SD-JWT VC** (`openvc.proof.sd_jwt`) — the third proof profile (EUDI/ARF's
  format): `SdJwtVcProofSuite` issuance (disclosures + `_sd` digests, decoys,
  `cnf` binding), holder Key Binding JWT presentation, and verification with
  recursive nested/array unpacking and the selective-disclosure defences.
- **Recorded golden EBSI fixtures** — real pilot DID Registry v5 + TIR v5
  responses recorded verbatim (`tests/fixtures/ebsi/`) drive the adapter tests,
  and a recorded accreditation's ES256 signature verifies against the recorded
  DID document. Recording them caught (and fixed) a `406` content-negotiation bug
  and a wrong TIR v5 `attribute.body` mapping.
- **CI hardening** — a coverage gate (`--cov-fail-under=80`), a scheduled
  live-EBSI drift alarm (`.github/workflows/live-ebsi.yml`), Dependabot (pip +
  actions), and Node-24 action versions. Published to PyPI as `openvc-core`.
- **ecdsa-sd-2023 selective disclosure** (`openvc.proof.ecdsa_sd`) — the P-256
  Data Integrity cryptosuite with selective disclosure: issuer base proof →
  holder derived proof (reveal chosen JSON pointers) → verify, with HMAC-blinded
  blank nodes and a hand-rolled CBOR proof value (checked against RFC 8949).
  Round-trip + tamper/over-disclosure tested.

## Next

1. **Interop: ecdsa-sd-2023 vs the W3C vectors.** Validate byte-level
   interoperability against the official vc-di-ecdsa test suite — the round-trip
   suite proves internal consistency; this proves it matches other implementations
   (ECDSA is randomised, so there is no fixed proof value to reproduce as with the
   eddsa-rdfc-2022 vector).

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): this is a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: those belong in the downstream
  badge library that consumes `openvc`.
