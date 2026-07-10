# ADR-0006 — status-list issuer trust binding

**Status:** Accepted. **Verdict: opt-in binding, default off, delegation-aware.**
**Date:** 2026-07-10
**Context owner:** `openvc.verify` (the status-check step) + `openvc.resolvers`
**Issue:** [#106](https://github.com/luisgf/openvc/issues/106) (milestone
[Depth — mdoc, status trust & parity](https://github.com/luisgf/openvc/milestone/10));
finding **M11** of the 2026-07-10 internal audit.

## Context

`verify_credential` resolves a referenced status list, verifies **its own** proof
(the default resolvers reject a forged/unsigned list), reads the bit, and applies the
revoked/suspended policy. The IETF path additionally binds the token to the referenced
URI (`sub == uri`, the anti-swap check). But **nothing constrains *who* issued the
status list**: a list signed by any key that resolves is trusted for its bits.

The revocation URL is chosen by the credential's issuer, but it is served by a host
that may be a third party or may be compromised. If that endpoint serves a status list
signed by an **attacker-controlled** DID/key that says "nothing revoked", it verifies as
internally valid and its bits are trusted — a revoked credential can be silently
"un-revoked". The status list's authenticity is checked; its *authority over this
credential* is not.

## Options

1. **Default-require same issuer** — the status list's issuer must equal the
   credential's issuer. Strongest, but breaks a **spec-legal** pattern: neither W3C
   Bitstring Status List nor IETF Token Status List mandates that the status issuer be
   the credential issuer, and real deployments delegate status hosting/signing to a
   separate service. A hard default would reject those and would be a breaking change
   for existing openvc users.
2. **Delegation allow-list only** — always require binding, but let the caller list
   trusted delegate issuers. Still a breaking default.
3. **Opt-in binding with a delegation allow-list** — off by default (behaviour
   unchanged, spec-legal delegation keeps working); a verifier that knows its issuers
   turns on `require_status_issuer_binding`, and may add delegates via
   `status_issuer_allowlist`.

## Decision

**Option 3.** Two `VerificationPolicy` fields:

- `require_status_issuer_binding: bool = False` — when set, the resolved status list's
  issuer must equal the credential's issuer, else fail closed with the typed
  `StatusListIssuerUntrusted`.
- `status_issuer_allowlist: frozenset[str] | None = None` — issuers accepted **in
  addition** to the credential issuer (delegated status services).

Enforced in the pipeline, not the resolver: `openvc.verify._check_status` wraps the
injected status resolver in a closure that, per verification, extracts the resolved
list's issuer (W3C `issuer`, IETF `iss`) and checks it against the credential's issuer.
The resolver stays `resolve(uri)` — the binding is a pipeline concern because the
expected issuer is per-credential (a batch reuses one resolver across issuers). The
async pipeline mirrors it (`aio._check_status_async`).

Default **off** is deliberate and documented: the binding is a *hardening opt-in*, not a
silent behaviour change. The `docs/threat-model` / Security-Model note the residual gap
when it is off.

## Consequences

- No breaking change; spec-legal delegation still verifies by default.
- A verifier with a known issuer set gets fail-closed protection against a compromised
  status host with one flag, and can whitelist delegates.
- The binding is only as good as the credential's own issuer authentication (which the
  proof already establishes before the status step runs).
- Future: a per-issuer delegation map (issuer → allowed status issuers) if a deployment
  needs finer control than one global allow-list; deferred until asked for.
