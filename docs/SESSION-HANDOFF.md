# Session handoff — openbadgeslib → OB 3.0 + EBSI

> **⚠️ Historical snapshot (2026-07-05, v0.1-era).** This is a dated design handoff,
> **not** the current state — openvc is at 1.x with most of what this document
> anticipates already shipped. For where the project *is*, read
> [`docs/ROADMAP.md`](ROADMAP.md), the [CHANGELOG](../CHANGELOG.md), and the GitHub
> milestones; kept only for the original design rationale. (Excluded from the docs
> site via `mkdocs.yml`.)

This is the working plan and current state as of the session on 2026-07-05, written
so Claude Code can pick up without re-deriving the design. Pair with `CLAUDE.md`
(conventions) and `docs/adr/ADR-0001-ebsi-http-client.md` (HTTP evidence/decisions).

## Goal

Evolve `openbadgeslib` from OB 2.x signing to **OB 3.0**, aligned with W3C
Verifiable Credentials, with **optional EBSI compatibility** (verification path).
Along the way, factor the generic VC machinery into a reusable core (`openvc`) so
it isn't entangled with badges.

## Strategic decisions taken this session

1. **Do not fork** a parallel EBSI project sharing a copied base — that guarantees
   drift. Instead: layered packages in one repo (core / ebsi plugin / OB layer).
2. **OB 3.0 belongs inside `openbadgeslib`**; the generic VC core is what gets
   extracted (`openvc`), *when a second consumer appears* (e.g. a verifier service).
   Until then, one repo with clean internal boundaries. Extraction later is a
   `git mv` + a `pyproject`, not a rewrite, because the core name is already neutral.
3. **Prioritise the VC-JWT proof profile** over Data Integrity: it reuses the
   existing JWS know-how and it is the bridge to EBSI (which is `jwt_vc` + ES256).
   Data Integrity is a later, second proof suite behind the same interface.
4. **EBSI: verification only.** Running an EBSI node requires org endorsement +
   EUROPEUM-EDIC approval + ISO 27001 (production); irrelevant to a library. Reads
   (resolve DID, query TIR) are plain unauthenticated REST — that is all we need.

## What is DONE (in this repo)

Core (`src/openvc/`):
- `keys.py` — `Ed25519SigningKey` (EdDSA) and `P256SigningKey` (ES256) on
  `cryptography`. Correct JOSE **R‖S** handling for ES256 (DER↔raw both ways),
  `public_jwk()`, `public_key_raw()` for did:key, `verify_signature()` (PyJWT-free),
  and a `signing_key_from_jwk` factory. HSM/Vault backends implement the same
  `SigningKey` protocol.
- `proof/vc_jwt.py` — `VcJwtProofSuite`: `peek_issuer` (untrusted iss/kid),
  `peek_claims` (untrusted full claims — used for TIR bodies), `verify`
  (algorithm allow-list {ES256, EdDSA} checked before crypto; temporal claims;
  VC-JWT envelope↔credential reconciliation), and `sign` (HSM-friendly, delegates
  raw signature to the key backend).
- `did/base.py` — `VerificationMethod`, `DidDocument` (`key_by_kid` tolerant of
  full-id or fragment kids), `DidResolver` protocol, shared W3C `parse_did_document`
  (handles bare or wrapped docs), and `DidResolverRegistry` (dispatch by method).
- `did/did_key.py` — offline did:key (Ed25519 0xed, P-256 0x1200): base58btc +
  multicodec varint decode, P-256 compressed-point decompression → JWK.
- `did/did_web.py` — did:web → https URL → fetch → parse, with an id-integrity
  check. Needs a *general* fetch (see gotcha below).

EBSI plugin (`src/openvc_ebsi/`):
- `models.py` — EBSI-specific domain types `Accreditation`, `IssuerRecord`.
- `versioning.py` — anti-corruption adapter layer: `DidRegistryV5`, `TirV4`,
  `TirV5` (TirV5 does the real multi-hop issuer→attributes→revision→decode flow and
  follows the server-provided `attributes` link per ADR-0001 D6), version registries,
  and the version-agnostic `DidEbsiResolver` (resolve + issuer_record; trust-chain
  logic operates only on domain objects).
- `http.py` — `EbsiHttpClient` (the `Fetch` capability): httpx transport, timeouts,
  bounded status-aware retries with backoff+jitter + Retry-After, thread-safe TTL
  cache (configurable `cache_ttl_s`, short by default per ADR-0001 D2), and an
  https-only host **SSRF allow-list**. `for_ebsi(env)` factory.

Tests & docs:
- `tests/test_ebsi_verifier.py` — deterministic offline e2e (sign→peek→resolve→
  verify via a stub fetch), a wrong-key negative test, the TIR-v5 multi-hop contract
  test (asserts call order), an SSRF-guard test, and an opt-in live conformance
  smoke test (`OPENVC_EBSI_LIVE=1`).
- `docs/adr/ADR-0001-ebsi-http-client.md` — live header probe + 9 decisions.

## Verified against live EBSI (2026-07-05, api-pilot.ebsi.eu)

- DID Registry returns the DID document **bare** (no `didDocument` wrapper),
  `application/did+ld+json`. Parser handles it.
- TIR v5 issuer response includes an `attributes` URL in its body (HATEOAS).
- Errors are RFC 7807 `application/problem+json`; 404 → `HttpNotFound`.
- **No cache headers at all** → client-side TTL is the only caching that works.
- DID Registry tail latency ~3.6 s → do not set aggressive timeouts.

## Known gaps / gotchas (read before continuing)

- **did:web needs a general fetch**, NOT the EBSI client (its allow-list would reject
  every legitimate host). Provide an https-only fetch that blocks private/link-local
  ranges. Reuse the retry/cache machinery but with allow-list disabled.
- **Golden fixtures are representative, not recorded.** Replace the inline fixtures
  in the TIR-v5 test with a real recorded conformance response to make it a true
  golden test.
- **The `verify_ebsi_badge` reference flow** (peek→resolve→verify→trust→revocation)
  was sketched earlier but not carried into a module. Add it as
  `openvc_ebsi/verify.py` wiring the current APIs; step 3 (revocation) waits on the
  status package below.
- **`DidEbsiResolver` currently lives in `versioning.py`.** Fine for now; optionally
  extract to `openvc_ebsi/resolver.py` and keep `versioning.py` adapters-only.
- Confirm EBSI API version paths against https://hub.ebsi.eu/changes before pinning
  (currently v5 for DIDR/TIR).

## NEXT STEPS (priority order)

1. **OB 3.0 `AchievementCredential` model** (`openbadgeslib/ob3/`): the VCDM subtype
   with `AchievementSubject`, required `type`/`@context`, issuer profile. This is what
   makes the output a *badge* rather than a generic VC. Wire it to `VcJwtProofSuite`
   for sign/verify.
2. **`openvc/status/` — StatusList revocation** (Bitstring/Token Status List), shared
   by OB 3.0 and EBSI. Then complete the verifier's revocation step (follow the
   issuer proxy registered in the TIR).
3. **`openvc_ebsi/verify.py`** — the end-to-end `verify_ebsi_badge` glue (signature +
   trust chain + revocation) over the registry.
4. **General https fetch for did:web** with private-range blocking.
5. **Record real golden fixtures** from conformance for the version adapters.
6. **Data Integrity proof suite** (`openvc/proof/data_integrity.py`) as the second
   profile behind `ProofSuite`.
7. **image baking** for OB 3.0 (`openbadgeslib/baking/`, Pillow isolated here).
8. Housekeeping: confirm `openvc` free on PyPI and register a placeholder; add CI
   running `pytest` (offline tier only).

## Package/naming notes

- Core = `openvc` (neutral, pending PyPI check). Distribution stays `openbadgeslib`.
- `openvc` must never import from `openbadgeslib` or `openvc_ebsi`.
- Plugin discovery via entry points was considered but the resolvers need injected
  dependencies (a `fetch`), so they are constructed explicitly for now.
