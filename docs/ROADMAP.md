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
  verify → single-level issuer trust check over the TIR accreditations.

## Next

1. **Recursive trust chain.** `verify.py` currently checks the issuer's own
   accreditation (non-revoked, authorises the credential type). Extend it to walk
   `TI → TAO → RootTAO`, resolving and verifying each accreditation up to a
   trusted RootTAO anchor. The domain model (`Accreditation.tao/root_tao`) already
   carries the links.
2. **Status-list revocation** (`openvc/status/`) — Bitstring / Token Status List,
   shared by any VC profile. Then wire it as the final step of `verify_ebsi_badge`
   (follow the issuer's status proxy from the TIR).
3. **Recorded golden fixtures.** Replace the representative inline fixtures in the
   TIR-v5 test with real recorded conformance responses, turning the adapter tests
   into true drift alarms.
4. **Data Integrity proof suite** (`openvc/proof/data_integrity.py`) — the second
   profile behind the same interface as `VcJwtProofSuite` (eddsa-rdfc-2022).
5. **DNS-rebinding hardening** for `openvc.fetch` — pin the connection to the
   validated IP (resolve-then-connect) to close the TOCTOU window the current
   resolve-time check documents.
6. **Packaging/CI polish** — publish a placeholder to PyPI (`openvc` is free),
   coverage reporting, and a live-EBSI job gated behind a schedule.

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): this is a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: those belong in the downstream
  badge library that consumes `openvc`.
