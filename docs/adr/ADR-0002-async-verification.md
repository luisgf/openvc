# ADR-0002 — An additive async verification surface

**Status:** Accepted
**Date:** 2026-07-07
**Context owner:** openvc.aio

## Context

`openvc`'s verification pipeline (`verify_credential`) is entirely synchronous:
every I/O boundary — `did:web` resolution, `jwt-vc-issuer` key discovery,
status-list fetch, `credentialSchema` fetch — calls a blocking function. That is
fine for a CLI or a sync worker, but it hurts asyncio servers (FastAPI / Starlette)
in two concrete ways the roadmap called out:

1. **The whole verify has to be offloaded to a thread pool.** An `async def`
   handler cannot `await verify_credential(...)`, so it must
   `run_in_executor(verify_credential, ...)` — a thread per in-flight request just
   to make a blocking call not stall the event loop.
2. **A presentation cascade serialises N blocking fetches.** Verifying a VP that
   carries several credentials resolves each issuer DID / status list one after
   another; there is no way to overlap the network waits.

The roadmap decision was made up front: **sync-only for 1.0; async is additive,
post-1.0.** This ADR records how the async surface is shaped so it adds capability
without duplicating — or endangering — the verified sync core.

## Decisions

### D1 — A parallel async surface, not a rewrite (the "Protocol variant")
We add an async *orchestration* (`openvc.aio.verify_credential_async`) and an
`AsyncDidResolver` Protocol alongside the sync ones, rather than converting the
core to a sans-I/O state machine. The async pipeline **reuses every pure/CPU
helper unchanged** — the proof suites (`suite.verify`), the status-bitstring and
token codecs, the JSON-Schema validator, issuer↔verificationMethod binding, type
checks. Only the *sequencing* around the I/O boundaries is re-expressed with
`await`. **Rationale:** there is no second implementation of any signature check,
canonicalisation, or decoder to drift or to get wrong — the async layer is a thin
I/O choreography over the same trusted primitives.

### D2 — Await injected async callables at every I/O boundary
`verify_credential_async` takes async counterparts of the same injection points the
sync path exposes: an `AsyncDidResolver`, and `resolve_status_list` /
`resolve_status_list_token` / `resolve_credential_schema` / `jwt_vc_issuer_fetch`
that each return an awaitable. The caller supplies the transport — e.g. an
`httpx.AsyncClient`-backed fetch — exactly as they supply a sync fetch today. The
crypto runs inline on the event loop (sub-millisecond); the network waits are the
only things that suspend.

### D3 — The default async fetch offloads the proven sync guard to a thread
The SSRF / DNS-rebinding guard (`openvc.fetch`) is security-critical and subtle: it
resolves the host, rejects any private/loopback/link-local/reserved address,
**pins the TCP connection to the validated IP** while keeping SNI/cert/Host for the
hostname, and refuses redirects. Re-implementing that against an async HTTP client
would be a second SSRF-sensitive code path to keep correct — `httpx` follows
redirects by default and pools connections, both of which can *undo* IP-pinning if
wired naively. So the batteries-included async fetch
(`https_json_fetch_async`, …) runs the **exact same** stdlib guard under
`asyncio.to_thread`: identical guarantees, non-blocking to the event loop,
**no new runtime dependency** (core stays `cryptography` + `pyjwt`). Callers who
want a native `httpx.AsyncClient` fetch may inject one — they then own the SSRF
contract, and `openvc.fetch` exposes the address-validation primitive to help them
honour it. **Rationale:** guard fidelity and dependency-lightness beat shaving one
thread hop off a network call that already costs milliseconds.

### D4 — Concurrency is the batch win; cross-credential dedup is not (yet) ported
`verify_many_async` verifies the credentials **concurrently** (`asyncio.gather`),
each independently fail-closed — directly fixing the serialised-cascade problem
(D-context 2). It deliberately does **not** port the sync `verify_many`'s
per-call resolver cache (`openvc.cache.batch_resolvers`): that cache is not
concurrency-safe (two coroutines resolving the same DID would race a half-filled
entry), and an async-safe single-flight cache is a separate, larger piece of work.
Overlapping the I/O is the dominant win; de-duplicating it is a later optimisation
(tracked as follow-up). Documented so the omission is a choice, not a gap.

### D5 — Fail-closed parity is mandatory
The async path preserves every fail-closed invariant of the sync path verbatim: a
declared-but-unresolvable status still raises `StatusUnavailable`; a revoked list
still raises `CredentialRevoked`; a declared `credentialSchema` under
`require_schema` still raises; a `JsonSchemaCredential`'s inner VC is still verified
(awaiting an async inner verify) and its failure still surfaces as
`SchemaResolutionError`; the Data Integrity issuer↔verificationMethod binding still
holds. The async surface may not open a fail-open hole. Tests assert this by
running the async and sync pipelines over the same fixtures and comparing outcomes.

### D6 — Offline resolvers adapt into the async registry for free
`did:key` / `did:jwk` do no I/O — their `resolve` is pure compute. Rather than
duplicate them, `as_async_resolver(sync_resolver)` wraps any sync `DidResolver` as
an `AsyncDidResolver` (its `resolve` awaits nothing). `default_async_resolver()`
is therefore `AsyncDidResolverRegistry([as_async_resolver(DidKeyResolver()),
as_async_resolver(DidJwkResolver()), AsyncDidWebResolver(<async guarded fetch>)])`.

## Consequences

- The public surface grows by an `openvc.aio` module (`verify_credential_async`,
  `verify_many_async`, `default_async_resolver`, `as_async_resolver`), an
  `AsyncDidResolver` / `AsyncDidResolverRegistry` in `openvc.did.base`, an
  `AsyncDidWebResolver`, `*_fetch_async` in `openvc.fetch`, and async default
  resolvers in `openvc.resolvers`. All **additive** — nothing in the sync path
  changes signature or behaviour.
- No runtime dependency is added. `asyncio` is stdlib; the default async fetch
  uses a thread, not a new HTTP client. `httpx` remains an EBSI-only extra.
- The async path's CPU (crypto) runs on the event loop. This is correct for the
  I/O-bound verifier case; a caller pinning many CPU-heavy verifications should
  still shard across processes — unchanged from any asyncio service.
- Because the async layer reuses the sync codecs/suites, a fix or a new proof
  format lands in both paths at once; there is no async fork to update.

## Alternatives considered

- **Sans-I/O core (yield I/O requests, drive from sync/async).** The cleanest in
  theory — one core, two drivers — but a large, invasive refactor of a
  security-critical pipeline for a post-1.0 additive feature. Rejected now; the
  Protocol variant (D1) reaches the same user-visible outcome at a fraction of the
  risk. Revisit only if a third driver (e.g. trio, or a batching scheduler) ever
  justifies it.
- **A native `httpx.AsyncClient` guarded fetch shipped in core.** Rejected as the
  *default* (D3): it duplicates the SSRF guard and pulls `httpx` toward core. Left
  open as a caller-supplied option.
