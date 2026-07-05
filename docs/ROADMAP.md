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
  `verify_ebsi_badge` via `trust_anchors`.
- **Status-list revocation** (`openvc.status`) — W3C Bitstring Status List bit
  codec (gzip + base64url, MSB-first) + `credentialStatus` parsing +
  `check_credential_status`. Wired into `verify_ebsi_badge` via
  `resolve_status_list` (a set revocation bit raises `CredentialRevoked`).
- **DNS-rebinding-safe `did:web` fetch** — the connection is pinned to the
  validated IP (resolve → validate → connect to that IP) while TLS SNI, cert
  validation and Host use the hostname, closing the TOCTOU window.

## Next

1. **Per-hop delegation scoping (chain refinement).** The recursive chain
   (`openvc_ebsi.trust.verify_trust_chain`, wired via `verify_ebsi_badge`'s
   `trust_anchors`) verifies each accreditation's signature and scopes the *leaf*
   hop to the credential's types; higher hops only require a valid accreditation.
   Refine to enforce that each accreditor's `accreditedFor` is a superset of what
   it delegates, and status-list-check the accreditations themselves.
2. **Token Status List (IETF)** — the other status encoding (1/2/4/8-bit
   statuses, CBOR/JWT), behind the same `openvc.status` interface as the W3C
   Bitstring list.
3. **Recorded golden fixtures.** Replace the representative inline fixtures in the
   TIR-v5 test with real recorded conformance responses, turning the adapter tests
   into true drift alarms.
4. **Data Integrity proof suite** (`openvc/proof/data_integrity.py`) — the second
   profile behind the same interface as `VcJwtProofSuite` (eddsa-rdfc-2022).
   Needs a JSON-LD canonicalization dependency (pyld), so it lands behind an
   optional extra.
5. **Packaging/CI polish** — publish a placeholder to PyPI (`openvc` is free),
   coverage reporting, and a live-EBSI job gated behind a schedule.

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): this is a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: those belong in the downstream
  badge library that consumes `openvc`.
