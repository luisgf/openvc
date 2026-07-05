# ADR-0001 — EBSI HTTP client: caching, retries, and transport

**Status:** Accepted
**Date:** 2026-07-05
**Context owner:** openvc_ebsi.http

## Context

Before finalising the read-only HTTP client for the EBSI registries we probed the
live endpoints to base the caching/retry design on evidence rather than
assumptions. This ADR records what EBSI actually returns and the decisions that
follow.

## Evidence (probed 2026-07-05, `api-pilot.ebsi.eu` / `api-conformance.ebsi.eu`)

| Endpoint | Status | Content-Type | Notable body |
|---|---|---|---|
| `GET /trusted-issuers-registry/v5/issuers/{did}` (pilot) | 200 | `application/json` | `{"attributes":"<url>","did":"…","hasAttributes":true}` |
| `GET /did-registry/v5/identifiers/{did}` (pilot) | 200 | `application/did+ld+json` | bare DID document (no `didDocument` wrapper); ~3.6 s latency |
| `GET /trusted-issuers-registry/v5/issuers/{did}` (conformance) | 404 | `application/problem+json` | RFC 7807: `{"status":404,"title":"Issuer Not Found",…}` |

**Caching headers present on any response:** none.
No `Cache-Control`, `ETag`, `Expires`, `Last-Modified`, `Vary`, `Age`, or `Pragma`.
Only `date`, `content-type`, CORS (`access-control-allow-origin: *`), and security
headers (`strict-transport-security`, `content-security-policy`,
`x-content-type-options: nosniff`, `x-frame-options: DENY`, COOP/CORP `same-origin`).

## Decisions

### D1 — Client-side TTL cache, NOT an RFC-compliant HTTP cache
EBSI sends no cache directives and no validators. A standards-compliant cache
(e.g. hishel) would therefore cache **nothing** — under RFC 9111 a response with
no freshness information and no `Last-Modified` is not heuristically cacheable.
Caching is only possible if *we* set the policy. → Keep the manual `TtlCache`.
**Rationale:** the choice isn't "reinvent HTTP caching"; it's "the server abdicates
caching, so freshness is our decision."

### D2 — Short TTL, no revalidation path
There is **no `ETag`/`Last-Modified`**, so conditional requests (`If-None-Match`)
are impossible — we cannot cheaply revalidate, only re-fetch. Combined with the
fact that a DID document can change when an issuer **rotates keys**, the TTL must
be short. → Default TTL kept low (minutes, not hours); make it configurable per
deployment.

### D3 — Keep httpx as the transport
Connection pooling, TLS, timeouts, and redirect control are httpx's job and are
used as-is. No hand-rolled transport. HSTS on every response aligns with our
https-only guard.

### D4 — Retries stay status-aware; consider `stamina`
httpx's built-in `retries` only covers connection errors, not `429`/`5xx`
responses, which EBSI can return. The status-aware retry loop is therefore
justified. It is a candidate to be replaced by **stamina** (backoff + jitter,
production-tested) to shrink maintained code — tracked as a follow-up, not a
blocker.

### D5 — Timeout default ~10 s (do not set aggressive)
Observed tail latency of **3.6 s** on the DID Registry (vs 0.27 s on the TIR). A
2–3 s timeout would produce false failures. → Keep a ~10 s default; revisit if
percentiles are measured in production.

### D6 — Follow the server-provided `attributes` link (HATEOAS)
The v5 issuer response includes the `attributes` URL in its body. Prefer following
that link over constructing the path client-side: it is more robust to future path
changes and keeps the adapter honest. Still subject to the SSRF allow-list (D8).

### D7 — Parse RFC 7807 `problem+json` for error detail
Errors are well-formed problem+json. Map `404 → HttpNotFound` (done) and surface
`title`/`detail` in raised errors for better diagnostics.

### D8 — SSRF host allow-list stays (application concern, no library)
The allow-list is application logic; no HTTP library provides it. The v5 flow
follows `href`/`attributes` URLs taken from registry responses, so the guard
remains necessary. https-only + host allow-list retained.

### D9 — DID document parser must handle the bare form
The DID Registry returns the DID document without a `didDocument` wrapper. The
parser's `raw.get("didDocument", raw)` fallback already handles this — confirmed
against a live response.

### D10 — Accept both `application/json` and `application/did+ld+json`
The DID Registry content-negotiates: it serves `application/did+ld+json` and
returns **406** to a bare `Accept: application/json` (the TIR is fine with
`application/json`). The original probes used curl's default `Accept: */*` and so
saw 200, masking this. The client now sends
`Accept: application/json, application/did+ld+json, */*;q=0.1` — every body is
parsed as JSON regardless of media type. Discovered while capturing the recorded
golden fixtures and fixed in `openvc_ebsi.http`; a live instance of the "re-probe
periodically" caveat below.

## Consequences

- Caching correctness is now **our** responsibility; a too-long TTL risks serving a
  DID document after a key rotation. Mitigated by a short, configurable TTL (D2).
- No revalidation means cache misses always cost a full round-trip; acceptable
  given registry reads are infrequent relative to verifications.
- These findings are a point-in-time snapshot. **Re-probe periodically**; if EBSI
  starts sending `Cache-Control`/`ETag`, revisit D1–D2 (hishel would then become
  the more correct choice).

## Reproduce

```bash
DID="did:ebsi:zZeKyEJfUTGwajhNyNX928z"
curl -sS -D - -o /dev/null \
  "https://api-pilot.ebsi.eu/did-registry/v5/identifiers/$DID"
curl -sS -D - -o /dev/null \
  "https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/issuers/$DID"
```
