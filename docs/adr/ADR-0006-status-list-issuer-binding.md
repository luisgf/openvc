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

*Amendment (1.31.0).* The pipeline only sees the list's body, so the resolver must
return a body whose `issuer` is authenticated. The default status-list resolvers now
refuse a verified list whose body names an issuer other than `result.issuer`, the
issuer its signature was verified for. Without that check, an IETF `dc+sd-jwt` list
could carry an unreconciled `issuer` claim naming the victim while being signed by the
attacker.

*Amendment (1.35.0).* The 1.31.0 rule left one legitimate shape fail-closed: a list
secured as a VC-JWT in the VCDM 1.1 JWT encoding may carry its issuer only in the JWT
`iss`, so its body has no `issuer`, or an object with no `id` or `@id` (`{"name": …}`).
The pipeline has authenticated that issuer (`result.issuer`), but the binding read the
body and found no one ([#226](https://github.com/luisgf/openvc/issues/226)). Where the
body names no one, the default status-list resolvers now return a **copy** with
`result.issuer` filled in (`issuer` set to it when absent, `id` added to an id-less
object, which keeps its other members). `result.credential` is never written to. This
admits nothing the signature did not already prove: `result.issuer` is the identity the
list was verified for, so a list an attacker signed gets the attacker's id and the
binding refuses it, naming them, unless they are in `status_issuer_allowlist`. A present
identifier is not touched (the 1.31.0 comparison still refuses a foreign one), the IETF
token path binds on `iss` as before, and a Data Integrity list cannot be issuer-less (the
lane requires the issuer to bind the proof's key). `_enforce_status_issuer` is not
relaxed: the pipeline does not fill anything in, so a custom `resolve_status_list` that
returns an issuer-less body still fails closed and should fill in the issuer it
authenticated the same way. With the binding off nothing changes.

*Addendum (2026-11, [#377](https://github.com/luisgf/openvc/issues/377)).* The issuer
binding proves **who signed** a list, not **which list** it is: a second list of the same
issuer (a shard, or any issuer-signed credential whose subject carries an `encodedList`),
served at the entry's URL by a compromised or third-party host, passed the binding and was
read for the entry's bit. The IETF lane had always pinned its token to the fetched URI
(`sub == uri`); the W3C lane now binds the resolved list to the entry that named it, in
the status check itself (`openvc.status.status_list._encoded_list`, so every lane, the
async pipeline and `openvc_ebsi`, with or without this policy flag): its `type` must
include the credential type of the entry's family (`BitstringStatusListCredential` for a
`BitstringStatusListEntry`, `StatusList2021Credential` for a `StatusList2021Entry`), its
`credentialSubject.type` must be that family's (`BitstringStatusList` / `StatusList2021`),
and its `id` (under either JSON-LD spelling, `id` or `@id`), when it carries one, must
equal the entry's `statusListCredential` as a string. A VC-JWT list in the VCDM 1.1 JWT
encoding keeps its id in `jti`, so `openvc.resolvers.authenticated_status_list` — the
public helper the default resolvers run on the list's `VerificationResult` — surfaces a
string `jti` as the `id` of an id-less body, on a copy, as it does the issuer. **A custom
`resolve_status_list` must return what that helper gives**, not `result.credential`: as
for the issuer, the pipeline fills nothing in, and a resolver that returns the bare body
hands the check an id-less list (EBSI lists, reachable only through custom resolvers, are
the common case). **The id rule is strict, by decision (2026-11-07):** a resolved list
whose `id` is not the URL the entry named is refused. The REC makes the match a MAY
(§2.2: the list "MAY express an `id` property that matches" `statusListCredential`), but
when the id is present and differs the verifier cannot say which list it is, so it fails
closed. An issuer whose lists carry non-URL ids (a `urn:uuid`, as EBSI's base schema
makes an `id` mandatory and its VCs conventionally carry) must publish each list at an
`id` equal to its URL to be checkable. A relaxation — an `id` that is not a URL treated as
absent, or a same-origin match — was considered and left for a maintainer decision if a
real deployment needs it; the live check of 2026-11-07 (88 accreditation bodies decoded
from the EBSI pilot TIR, v5) found no `credentialStatus` on any of them, so the rule
cannot touch the EBSI accreditation path today, and the shape of a live EBSI
StatusList2021 list stays unconfirmed. **Residual:** a list with no `id` at all (neither
`vc.id` nor `jti`) is accepted and bound by its issuer and its types only; publish lists
with an `id` equal to their URL (the builder does) so the binding is complete. On a list secured as SD-JWT that
residual was reachable by the host, not only by an issuer that set no `id`: a disclosable
`id` or `jti` is a disclosure the status host — the holder of a public list — can withhold
undetected (RFC 9901 §9.7). So a status-list credential is never selectively disclosable:
`SdJwtVcProofSuite.issue()` refuses any disclosable claim and any decoy on a payload typed
as one, and `verify()` refuses a presentation of one that carries an `_sd` digest or a
disclosure at all.

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
