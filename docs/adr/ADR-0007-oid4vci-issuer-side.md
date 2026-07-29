# ADR-0007 — OpenID4VCI: the key-proof verifier stays in core, the protocol layer goes downstream

**Status:** Accepted (scope decision). **Verdict: in scope, split — cryptographic
verification and wire *parsing* in `openvc`; protocol, session and endpoint
orchestration in the consumer.** Implementation is a sequence of follow-up issues, not
this ADR.
**Date:** 2026-07-24
**Context owner:** a new `openvc.openid4vci` module (+ `openvc.keys` for RFC 7638)
**Milestone:** [Q3–Q4 2026 — eIDAS deadline & ecosystem refresh](https://github.com/luisgf/openvc/milestone/12)

## Context

The EU ARF names **OpenID4VCI** the required protocol for issuing PID and
attestations. openvc covers the verifier half of that ecosystem end to end and covers
**none** of the issuance protocol: there is no `oid4vci` symbol in `src/`.

Both publication gates this project waits on are passed: **OpenID4VCI 1.0 is Final
(2025-09-16)** and **HAIP 1.0 is Final (2025-12-24)**.

The trigger is ecosystem positioning — walt.id, Keycloak and Authlete cover issuance.
The question this ADR settles is not *whether* openvc participates but **which half it
owns**, because OID4VCI is two very different things welded together: a small amount of
security-critical cryptography over attacker-controlled bytes, and a large amount of
stateful protocol orchestration.

An earlier draft of this ADR ruled the *whole* stateless protocol layer into core. That
was wrong, and the reason is in the next section.

## Evidence

### The two halves have different natural homes, and the code says so

| | Key-proof verification + wire parsing | Protocol / session orchestration |
|---|---|---|
| What it is | Verify a wallet's `openid4vci-proof+jwt`; parse an untrusted Credential Offer / Issuer Metadata | Nonce store, offer lifecycle, endpoint wiring, AS integration, `authorization_details`, deferred/notification bookkeeping |
| Needs | openvc's **private** JOSE layer | **State**, HTTP, deployment-specific policy |
| Attacker-controlled input | Yes, entirely | No — it is the issuer's own bookkeeping |
| Fits openvc's charter | Yes — consume-and-verify | No — the standing boundary excludes exactly this |

### The decisive fact: the crypto cannot live downstream

`openvc_ebsi` is the only existing plugin, and it imports **only public API** from the
core — `openvc.errors`, `openvc.cache`, `openvc.did.base`, `openvc.proof.errors`,
`openvc.proof.vc_jwt`, `openvc.status`, `openvc.observability`. Zero private symbols. It
works at the *suite* level.

The key-proof verifier cannot. It needs the raw-JWS level:

| Needed | Location | Public? |
|---|---|---|
| `parse_compact`, `verify_compact` | `proof/_jws.py:58,74` | **No** |
| `reject_unknown_crit` | `proof/_verify_common.py:44` | **No** |
| `check_jwt_temporal` | `proof/_verify_common.py:172` | **No** |
| `match_alg`, `ALG_PROFILE` | `proof/_verify_common.py:302,295` | **No** |

`CONVENTIONS.md` states leading-underscore names carry no stability guarantee. So a
downstream implementation has exactly three options, and all three are bad:

1. depend on unstable private API;
2. force openvc to promote that layer to public API — a permanent surface expansion,
   for one consumer;
3. reimplement JOSE verification downstream — which
   [ADR-0002](ADR-0002-async-verification.md) forbids in as many words ("no signature
   check exists twice to drift").

That settles the crypto half. It is core's, or it is duplicated.

### The consumer already exists and already depends on core

`openbadgeslib` declares `openvc-core>=1.21,<2` behind its `[eudi]` extra and
`openvc-core[data-integrity]` behind `[ldp]`. The dependency direction is established
and one-way. It is an *application* library, so unlike openvc it can legitimately ship
a Redis/SQL nonce store, own an endpoint, and integrate an AS.

### What the current code offers

| Asset | Reusable? |
|---|---|
| `proof/_jws.py` `verify_compact` (:74) | **Directly** — already parse → alg allow-list → `reject_unknown_crit` → `keys.verify_signature`. |
| `proof/_verify_common.py` `reject_unknown_crit` (:44), `match_alg` (:302) | **Directly** — `match_alg` gives the alg↔curve binding the proof header needs. |
| `proof/_verify_common.py` `check_jwt_temporal` (:172) | **Partly** — checks `exp`/`nbf`, **never `iat`**, and `iat` freshness *is* the key proof's replay control. New logic (D5). |
| `proof/sd_jwt.py` `issue(holder_jwk=…)` (:226-268) | **Directly** — the last mile, binding the credential to the key the proof demonstrated, is already one line. |
| `x5c.py` `load_x5c_chain` / `validate_cert_chain` / `leaf_public_jwk` (:41,:102,:180) | **The core, not the entry point.** `resolve_x5c_key` (:142) encodes `iss`→SAN and a P-256-only leaf rule that are *issuer-certificate* rules; a wallet key-attestation certificate binds differently. ADR-0005 D5 reasoning, reapplied. |
| `openid4vp.py` | **The architectural template** — payload-first/keyword-only signatures, injected I/O and time, frozen tuple-bearing results, a negative-scope paragraph in the docstring. |
| RFC 7638 JWK thumbprint | **Absent** — needed for batch dedup and `cnf`. |
| `jwe.py` | **Not reusable** — decrypt-only by explicit decision (`jwe.py:4-7`). |

### The HAIP overlay bounds the claim

HAIP 1.0 mandates for issuance: **DPoP (RFC 9449) REQUIRED**, applying to the Credential
Endpoint; **key attestations REQUIRED**; **client authentication REQUIRED** at PAR/Token
(recommended mechanism still an IETF **draft**); **authorization code flow REQUIRED**.

All four are orchestration, so all four land downstream. Recorded here so it is not
discovered later: **core's claim is "OpenID4VCI 1.0 key-proof verification". Neither
core nor this ADR licenses a "HAIP issuance" claim** — that belongs to whoever ships the
endpoint, once they ship DPoP too.

## Decisions

### D1 — Verdict: split. The crypto and the parsers are in scope; the protocol layer is not
`openvc` builds: wallet key-proof verification, and fail-closed parsing of untrusted
Credential Offers and Issuer Metadata. `openvc` does **not** build: the nonce store, the
offer lifecycle, any endpoint, any AS integration, or the response builders. Those are
the consumer's — `openbadgeslib` first (see "Ground for the consumer" below).

### D2 — The rule that decides which side anything falls on
> **In core:** attacker-controlled bytes that must be verified or parsed fail-closed.
> **Downstream:** anything with a lifetime, a socket, or a deployment policy.

Applied: a wallet's proof JWT is attacker-controlled → core. A received Credential Offer
is attacker-controlled → core (parse only). A `c_nonce` has a lifetime → downstream. A
Credential Response is the issuer's own output, not attacker-controlled → downstream.

### D3 — The charter does **not** move; the *description* of it is corrected
This is the substantive change from the earlier draft. Verifying attacker-controlled
bytes and failing closed is precisely what openvc already does — it is the same posture
as `openid4vp.py`, which verifies a received `vp_token` while building no request,
hosting no endpoint and holding no session. The OID4VCI verifier is that, one protocol
over.

So the standing boundary — **no state, no transport, dependency-light** — is preserved
intact, and no out-of-scope entry is retracted.

What *is* corrected is an inaccurate summary. The ROADMAP described the library as
"read/verify-only", which has been untrue since 1.0: `VcJwtProofSuite.sign`,
`SdJwtVcProofSuite.issue` and the status-list builders all write. The accurate statement
of the same boundary is **credential-format production in; protocols, sessions and
servers out** — and under D1 nothing crosses it.

### D4 — Nonce single-use is an injected, *required* callable — never prose, never stored
Nonce replay is part of proof verification, so core cannot ignore it; but the store has
a lifetime, so by D2 core must not own it. The resolution is to put the obligation in
the **type signature**, where openvc already puts `SigningKey` and `resolver`:

```python
ConsumeNonce = Callable[[str], bool]   # atomic mark-used; True only if THIS call consumed it
ResolveProofKey = Callable[[str], dict]  # kid -> wallet public JWK; absent => kid proofs rejected
ResolveProofKeyInContext = Callable[[ProofKeyContext], dict]   # see the 1.24.0 addendum
```

`check_nonce` is required: `require_nonce=True` (the default) with `check_nonce=None`
raises immediately — the same fail-closed guard as `sd_jwt.py:462`. A plain
`expected_nonce: str` is rejected as a design: string equality cannot express
"consume once, atomically", so a caller comparing after the fact would have verified a
signature and *not* the replay property, with the fail-open path the ergonomic one.

A callable rather than a class Protocol because `CONVENTIONS.md` reserves Protocols for
multi-member roles and uses callable aliases for single-purpose injected I/O (`Fetch`,
`ResolveTypeMetadata`, `ResolveStatusList`).

Three properties this buys:

1. **Consume-after-verify** — invoked only once every signature has verified, so an
   unauthenticated attacker cannot burn nonces.
2. **Consume-once-per-request** — with N batched proofs carrying one nonce it fires
   exactly once; a naive per-proof loop would fail the second proof.
3. **Typed failure** — `ProofReplayed`, distinct from `ClaimsInvalid`, so the caller can
   map to `invalid_nonce` (fresh nonce, let the wallet retry) rather than a hard reject.

### D5 — The key-proof verifier is the crux, and `iat` freshness is new logic
Fixed order, structure and allow-lists before any crypto, **any failure rejects the
whole request — there is no partial issuance**:

`parse_compact` → **`typ` pin** (`openid4vci-proof+jwt`, both media-type spellings) →
**alg allow-list** → `reject_unknown_crit` → **exactly one of
`jwk`/`kid`/`x5c`/`trust_chain`** → key-material rules → signature → **`aud` ==
credential issuer identifier**, literal, multi-valued `aud` rejected → **`iat`
freshness** → `exp`/`nbf` → `iss`.

Two carry the security weight:

- **`iat` freshness is new** — `check_jwt_temporal` never looks at `iat`. Both
  directions: stale (`now - iat > max_age_s + leeway_s`) **and future-dated**
  (`iat - now > leeway_s`). Without the future-dated direction a wallet signs once with
  `iat = now + 10y` and holds a proof that never expires. Non-finite and bool values
  rejected — the `NaN`-comparison fail-open trap documented at `_verify_common.py:188`.
- **Exactly one key parameter** — counted; `!= 1` rejects. Two present lets an attacker
  pair a `kid` naming an honest key with a `jwk` they control, and any implementation
  that "prefers `jwk`" accepts silently. Structurally the same defect the #89 adversarial
  review found (`claim`/`claims` precedence → scope escalation), so it is pinned by
  test, not by care.

Fail-closed defaults: `trust_anchors=None` ⇒ `x5c` rejected; `resolve_proof_key=None` ⇒
`kid` rejected; `trust_chain` ⇒ typed `UnsupportedProofType`; `batch_size` default **1**;
`max_age_s` 300; PQ algs only via an explicitly widened `allowed_algs`.

### D6 — Batch invariants live at the plural level; no public singular verifier
The verifier takes the whole request. The invariants that matter — all proofs carry the
same nonce, the nonce is consumed exactly once, no two proofs share an RFC 7638
thumbprint — exist only across the set. A public singular `verify_key_proof` would invite
the caller loop that breaks all three, so the per-proof routine stays private.

### D7 — Parsers in, builders out
`parse_credential_offer` and `parse_credential_issuer_metadata` are **in**: they consume
third-party JSON and must fail closed, which is core's home turf and pinnable against
real recorded vectors. `build_credential_response` / `_deferred_` / `_nonce_` /
`_error_` / `build_credential_offer` / `build_credential_issuer_metadata` are **out**:
pure dict-in/dict-out with no crypto and no attacker input, and every consumer will want
to shape them to its own configuration. `status/issue.py` is a precedent for keeping such
builders in core, but it is outweighed here by D2 — those artifacts are the issuer's own
output, not something to be defended against.

### D8 — The security property **generalises**; it does not double
The earlier draft introduced a co-equal second property ("no wrong-issue") and a
rewritten attacker table. Under the split that is unnecessary and would overstate what
core does. openvc's output is still a verification decision over attacker-controlled
bytes; only the *object* widens. `threat-model.md:22-23` becomes:

> **No wrong-accept** — a forged, tampered, expired, revoked, mis-issued or replayed
> credential **or key proof** must never be returned as accepted.

`wiki/Security-Model.md` gains **one row** (an attacker presenting a forged or replayed
key proof to obtain a credential bound to a key they do not control), not a new table.
The wrong-*issue* property belongs to whoever mints the credential — downstream — and is
documented there.

### D9 — What stays out of core
| Refused | Reason |
|---|---|
| Nonce/code/`transaction_id`/`notification_id` stores | D2, D4 |
| The OAuth AS; all HTTP (`tests/tools/` shim ok, `src/` not) | D2 |
| Response and offer/metadata **builders** | D7 |
| **JWE encrypt** (credential-response encryption) | `jwe.py` is decrypt-only by decision; encrypting introduces this library's first catastrophic-on-error primitive (AES-GCM IV reuse) and needs an ephemeral private key in-process. Required only when an issuer sets `encryption_required: true`, which HAIP does not require for issuance. Own ADR if ever. |
| mdoc issuance / COSE signing | Still excluded (ROADMAP); `cose.py` has no signing function. |
| `di_vp` proof type | Would drag `pyld` from `[data-integrity]` onto the issuance path. |
| Key-attestation **trust** | Parsed and bound, never believed — see the 1.24.0 addendum. The signature, the wallet-provider anchor and the assurance levels need a trust model of their own. |
| Attestation-based client authentication; DPoP | Orchestration, and the former is an IETF draft. Downstream, with HAIP. |
| `trust_chain` (OpenID Federation) proof keys | Typed `UnsupportedProofType`; another whole spec, no EU deployment blocks on it today. |

### D10 — Conformance: real vectors where they exist, self-made where they cannot
The OIDF self-certification suite (opened 2026-02-26) is a **black-box HTTP harness
driving a live issuer**. It cannot test a library that ships no server, and **openvc must
never claim issuer certification** — under D1 core does not even own the endpoint being
certified. Obtainable and worth doing: Credential Offers and Issuer Metadata recorded
from the EU reference issuer (`eudi-srv-web-issuing-eudiw-py`) as genuine third-party
vectors for the parsing half; and key-proof JWTs captured from the suite's wallet plan
against a `tests/tools/` shim, verified with a frozen clock (the technique already used
for the EUDI PID fixtures). Releases are **not** gated on either — ship on self-made
signed vectors first, as the LoTE work did in 1.22.0 — because
`tests/fixtures/trustlist/real/README.md` is this repo's own evidence that self-made
fixtures hide total-failure bugs.

## Ground for the consumer (`openbadgeslib` first)

What core commits to providing, so downstream issuance can be built against a stable
contract:

```python
from openvc.openid4vci import verify_credential_request_proofs
from openvc.proof.sd_jwt import SdJwtVcProofSuite

proofs = verify_credential_request_proofs(          # core: crypto + shape
    body,                                            #   the untrusted request
    credential_issuer="https://issuer.example",
    check_nonce=my_nonce_store.consume,              # downstream: state, injected
)
sd_jwt = SdJwtVcProofSuite().issue(                 # core: already exists
    claims=grant.claims, signing_key=ISSUER_KEY, vct=VCT,
    holder_jwk=proofs[0].public_jwk,                #   the binding the proof earned
)
```

The consumer owns everything else: the AS and grant, the nonce store's atomicity, the
HTTP endpoint and status codes, the response/offer/metadata bodies, DPoP, deferred and
notification bookkeeping, and the "no wrong-issue" property that follows from them.

Two obligations core places on the consumer, both load-bearing:

1. **`check_nonce` must be atomic** — a `SET NX` or a `DELETE … RETURNING`, not a
   read-then-write. A non-atomic store re-opens the replay window core cannot close on
   its behalf. Note that `openvc.cache.TtlCache` is explicitly **not** suitable: it
   documents its own lack of single-flight (`cache.py:24-27`), which is benign for a read
   cache and fatal for a single-use token.
2. **Codes and identifiers are the consumer's to generate** — core does not mint
   pre-authorized codes, `transaction_id` or `notification_id`.

## Consequences

- **The charter is preserved, not retracted.** Only the inaccurate "read/verify-only"
  summary is corrected (D3). The out-of-scope list gains an OID4VCI entry recording the
  split; nothing is removed from it.
- **The threat model widens by one word, not by a property** (D8) — the large cost the
  earlier draft accepted is avoided by not taking the protocol half.
- **The claim is bounded**: "OpenID4VCI 1.0 key-proof verification", symmetric with how
  openvc already presents OpenID4VP (verify what arrives; build no request, host no
  endpoint). Not "issuance", not "HAIP issuance".
- **The state seam is load-bearing.** If `check_nonce` is ever softened to optional or to
  a plain string, core becomes the fail-open surface this ADR avoids. Pin it by test.
- **Dependency-light preserved** — no new runtime dependency.
- **Downstream gains a well-defined job** rather than an implicit one, and can ship the
  stateful parts openvc refuses to.

## Addendum (1.24.0) — key attestations: parse and bind, do not trust

**Status:** Accepted. **Date:** 2026-07-29. **Issue:** #150. Amends D4 and one row of D9;
nothing else in this ADR is retracted.

D4 shipped `ResolveProofKey = Callable[[str], dict]`, and that turned out to be blind
exactly where the EU ecosystem lives. In the attested-key form the wallet sends
`{typ, alg, kid, key_attestation}` and **the key that signed the proof is inside the
header** — one of the attestation's `attested_keys`. A callback holding only the `kid`
cannot reach it, so the reporting consumer decoded the proof header a second time,
itself, to find the attestation before calling us: two implementations of "what is a
header", one of which can drift.

Two spec facts decide the shape of the fix:

1. App. D: *"If used with the `jwt` proof type, the Credential Issuer MUST validate that
   the JWT used as a proof is signed by a key contained in the attestation in the JOSE
   Header."* A MUST that applies to us and that we could not express.
2. The `jwt` proof type fixes **no rule** for how a `kid` names a key inside
   `attested_keys`. The spec's own example uses `"kid": "0"` — an index; wallets also use
   each JWK's `kid` member, or an RFC 7638 thumbprint.

So the split is three ways, and the middle one is the interesting one:

| | |
|---|---|
| **Parse — in** | `peek_key_attestation` / `peek_proof_header`. Consuming third-party bytes that must fail closed is D2's home turf, and a caller who needs the header before verification should use *our* parser, not write a second. Structure is validated, trust is not. |
| **Bind — in** | Fact 1 is enforced by default. |
| **Trust — out** | The attestation's signature, the wallet-provider anchor, `key_storage` / `user_authentication` / `status` / `exp`. Unchanged from D9: that needs an anchor class openvc has no model for. |

**The binding check stops no attacker, and must never be sold as if it did.** Whoever
forges a proof also chooses its `key_attestation`, whose signature nothing here verifies;
they simply attest their own key. What it catches is an honest wallet, or *the caller's
own resolver*, producing a key the wallet never claimed — a credential bound to the wrong
key that would otherwise verify cleanly. It is a conformance check, and the reason an
unverified blob may drive it at all is directional: it can only reject, never accept.
`threat-model.md` I19 and `Security-Model.md` are worded to that limit deliberately.

**Fact 2 stays the caller's.** openvc will not guess between index / `kid` member /
thumbprint — that is the same "silently prefers one" defect the exactly-one-key-parameter
rule exists to prevent, and a wrong guess picks the wrong key from a list the attacker
supplied. `resolve_proof_key_in_context` hands over the material; the ecosystem's rule is
one line in the caller. For the same reason a header carrying **only** `key_attestation`
and no key parameter stays rejected — spec-legal, and still not something we will resolve
from an unverified blob. That is now a tested decision rather than a side effect of the
counting rule.

**Compatibility.** `ResolveProofKey` is untouched and un-deprecated; the context resolver
is a *separate* keyword, and passing both is a caller error rather than a precedence.
Three alternatives were rejected: widening the alias to `(kid, header)` breaks every
existing callable (MAJOR — and `openbadgeslib` pins `openvc-core>=1.21,<2`, so 2.0.0 would
lock the reporting consumer out of its own fix); `inspect`-based arity dispatch silently
downgrades a resolver wrapped in `openvc.cache.cached_resolve`, which returns a one-arg
closure, losing the header with no error; and a callable alias is contravariant, so any
widening now guarantees another break the next time a resolver needs more. A context
object grows without breaking anyone.

## Follow-ups

- **File the core issues**, in dependency order: RFC 7638 thumbprint → key-proof
  verification → offer/metadata parsers. This ADR is their design input.
- **File the `openbadgeslib` issue** for the issuance endpoint built on the contract
  above, once core's verifier ships.
- Capture real Credential Offer / Issuer Metadata vectors from the EU reference issuer;
  file the conformance-suite capture into *Conformance & production readiness*.
- Revisit only if a consumer needs something core refused — each is its own ADR, not an
  incremental slide.

## References

- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
  (Final, 2025-09-16) — §8.2 Credential Request, App. F.1 the `jwt` proof type.
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
  (Final, 2025-12-24) — §4: DPoP, key attestations and client authentication REQUIRED.
- RFC 9449 (DPoP), RFC 9396 (`authorization_details`), RFC 7638 (JWK Thumbprint),
  RFC 7515 §4.1.11 (`crit`).
- EU ARF — OpenID4VCI as the issuance protocol; CIR (EU) 2024/2977 (mandatory PID/QEAA
  formats).
- [ADR-0002](ADR-0002-async-verification.md) — "no signature check exists twice to
  drift", the rule that forces the crypto half into core.
- [ADR-0005](ADR-0005-mso-mdoc-verification.md) — the scope-decision format, and the D5
  reuse-via-adapter reasoning reapplied to `x5c`.
