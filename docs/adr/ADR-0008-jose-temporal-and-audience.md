# ADR-0008 — One NumericDate rule for the JOSE lanes, and RFC 7519 §4.1.3 on VC-JWT

**Status:** Accepted. **Verdict: one shared temporal rule (`null` rejected, `exp`
exclusive, future `nbf`/`iat` rejected) on the credential, presentation, key-binding,
status-list and key-proof lanes; `aud` enforced on both VC-JWT lanes.**
**Date:** 2026-10-13
**Context owner:** `openvc.proof._verify_common` (`check_jwt_temporal`,
`check_jwt_audience`, `check_expected_audience`), used by `proof.vc_jwt`,
`proof.sd_jwt`, `proof.vp_jwt`, `status.issue` and `openid4vci`
**Follows:** [#195](https://github.com/luisgf/openvc/pull/195) (VC-JWT NumericDate
shapes), whose adversarial review found the inconsistencies below.

## Context

openvc verifies JWTs on several lanes, and on v1.28.2 they had drifted on the claims
RFC 7519 defines:

| Lane | `exp`/`nbf: null` | malformed `iat` | future `iat` | own `exp`/`nbf` read | `aud` with no audience given |
|---|---|---|---|---|---|
| VC-JWT, classic (PyJWT) | rejected (#195) | rejected (#195) | rejected (PyJWT) | yes | **accepted** (`verify_aud=False`) |
| VC-JWT, ML-DSA | rejected (#195) | rejected (#195) | **accepted** | yes | **accepted** |
| SD-JWT VC issuer JWT | **read as absent** | **accepted** | **accepted** | yes | not checked |
| SD-JWT KB-JWT | n/a | rejected (#187) | rejected (#187) | **no** | not checked |
| VP-JWT | **read as absent** | **accepted** | **accepted** | yes | n/a (audience required) |
| Status-list token | **read as absent** | not read | not read | `exp` only | not checked |

The status-list token also accepted an `exp` of `NaN`, `Infinity` or `1e400`. Every
comparison against those is false, so the list never went stale, while the code
comment said it failed closed. The ML-DSA lane also accepted a non-string `sub`/`jti`,
which PyJWT rejects on the classic lane. The shared helper truncated the clock to an
integer and accepted a token exactly at `exp` plus the leeway, up to a second later
than PyJWT.

Two of these were fixed separately before this ADR landed: the status-list token's
non-finite `exp` (1.29.2) and the ML-DSA lane's non-string `sub`/`jti` (1.30.0). The
rest, and the boundary, are what this ADR decides.

Each gap is small, but together they meant the answer to "does openvc reject this
token?" depended on which lane parsed it.

## Decision

### D1 — A present date must be a finite JSON number, `null` included

RFC 7519 §2 defines a NumericDate as a JSON number. `check_jwt_temporal` now starts
with `check_numeric_dates(claims, "exp", "nbf", "iat")`. Every lane that calls it
applies the rule: the SD-JWT VC issuer JWT (body and processed payload), the KB-JWT,
the VP-JWT, VC-JWT ML-DSA, the status-list token and the OpenID4VCI key proof. A
present `exp`/`nbf`/`iat` that is `null`, a bool, a string, a container, non-finite,
or an integer no float can hold is rejected (`ClaimsInvalid`; `StatusListError` on
the status-list token). The classic VC-JWT lane already ran the same gate before
PyJWT (#195).

This is an interop decision: it shrinks what verifies, and some issuers serialise an
unset field as `null`. We take it because the rule is the RFC's and a lenient reading
differs per lane. It is listed in the CHANGELOG as a behaviour change.

### D2 — The window: `exp` exclusive, future `nbf` and `iat` rejected

- `exp`: a token at or past `exp` plus the leeway has expired (RFC 7519 §4.1.4: the
  current time MUST be before it). The wall clock is no longer truncated, on the
  KB-JWT window either. A pinned `now`, and the OpenID4VCI key proof's instant, are
  read to the second (`utc_epoch`), as on every openvc clock check. Each comparison
  is a difference against the leeway, so a huge leeway cannot overflow a float sum.
  This is the only comparison the expiry waiver (`require_not_expired=False`)
  switches off.
- `nbf`: before it by more than the leeway is not yet valid (§4.1.5).
- `iat`: more than the leeway in the future is rejected. PyJWT's `verify_iat` already
  did this on the classic VC-JWT lane. Like `nbf`, the waiver leaves it on: a token
  minted later than now is pre-dated, not expired. `iat` stays optional and its age
  unbounded. Proofs that exist to be fresh already bound it both ways with
  `check_iat_freshness` (KB-JWT, OpenID4VCI key proof).

**KB-JWT.** RFC 9901 defines no `exp`/`nbf` on a KB-JWT, but a signed one is no
longer ignored. It is judged at the same instant as the KB-JWT's `iat` window. A
failure is a binding failure phrased without "expired" (`KB-JWT is outside its own
exp/nbf window`). Callers read an `expired` error from a required-binding verify as
"bound, but the issuer JWT expired", and no waiver applies.

**Status-list token.** The full window is judged at one instant: `now` when the
caller pins it, else the wall clock. The resolvers never pin it. A pin earlier than
the list's `iat`/`nbf` therefore rejects the list, because the list did not exist at
that instant.

### D3 — VC-JWT enforces RFC 7519 §4.1.3

> If the principal processing the claim does not identify itself with a value in the
> "aud" claim when this claim is present, then the JWT MUST be rejected.

A verifier identifies itself only through the `audience` it passes. So
`check_jwt_audience`, run on both VC-JWT lanes after the signature verifies:

- `aud` absent: accepted with no audience; rejected when one is expected (unchanged).
- `aud` present: must be a string or an array of strings, and must contain the
  caller's audience. **With no audience, any present `aud` is rejected.**

This is PyJWT's own default, which openvc had turned off with
`verify_aud=audience is not None`.

The expected audience itself must be `None` or a non-empty string
(`check_expected_audience`, before either lane runs). PyJWT matched a list of
audiences on the classic lane only. An empty audience matched an empty `aud` on the
ML-DSA lane only. Half-supporting either on one lane is worse than refusing both.

Options considered:

1. **Enforce (chosen).** It is what the RFC says and what PyJWT does by default. VCDM's
   JWT encoding defines `aud` only for presentations, so a VC-JWT that carries one was
   deliberately restricted by its issuer. None of the third-party VC-JWT or SD-JWT VC
   vectors pinned in `tests/fixtures` carries an `aud` (only key proofs and KB-JWTs
   do).
2. **Document the deviation.** Treat a VC as a bearer credential and leave audience
   binding to the presentation layer. Rejected: an issuer that restricts a credential
   to one relying party would have that restriction ignored by everyone else.
3. **Opt-in policy knob.** Adds API surface to turn on a MUST. Rejected.

## Consequences

- One rule across the lanes above. `check_jwt_temporal` single-sources it, and the
  test matrix in `tests/test_jose_temporal_claims.py` and `tests/test_vc_jwt_audience.py`
  runs each lane under the default policy and `VerificationPolicy(require_not_expired=False)`.
- **Behaviour changes**, all fail-closed, are listed under `### Changed` in the
  CHANGELOG.
- **Nested VC-JWTs in a presentation** are checked against `policy.audience`, not the
  presentation's `audience`. #190 chose that deliberately, and it stands. So
  `verify_vp_token`, which sets no `policy.audience`, rejects a nested VC-JWT that
  carries `aud`, even one addressed to the same verifier. And because a VC-JWT without
  `aud` fails when an audience is expected, one `VpJwtProofSuite.verify` call cannot
  accept a mix of VC-JWTs with and without `aud`. If real presentations need that, a
  follow-up could check a nested credential's `aud` against the presentation's
  audience whenever the credential carries one. That is not done here: it is a false
  negative, never a false accept.
- PyJWT truncates a fractional date to an `int` on the classic lane, so its verdict can
  still differ from `check_jwt_temporal`'s within one second of a boundary.

## Open — not decided here

- **§4.1.3 on SD-JWT VC.** The issuer JWT's `aud` is not checked: one with
  `aud=https://other-rp` verifies for any verifier. The KB-JWT's `aud` binds the
  holder's presentation, not an issuer's restriction, so D3's reasoning applies to it
  word for word. A KB-JWT whose `aud` names another verifier also still binds
  (`key_bound=True`) when the caller passes no audience. Both predate this ADR. They
  change SD-JWT VC verification for the EUDI ecosystem and need their own decision.
  Since [#290](https://github.com/luisgf/openvc/issues/290) a W3C VC-JOSE-COSE JWS with no
  `iss` and no `typ`, which the VC-JWT lane refuses, reaches this lane once a `~` is
  appended, so an issuer's `aud` restriction on such a token is not enforced either.
- **Other JOSE objects keep their own date handling.** The OpenID4VCI key-attestation
  JWT reads `null` as absent and its signature is not verified (ADR-0007). The WRPRC
  (`openvc.rp_registration`, ETSI TS 119 475) has its own profile rules.
- **A withheld `exp` disclosure.** An expired `exp` in a disclosure the holder
  withholds is invisible to the verifier. RFC 9901 §9.7 and SD-JWT VC forbid making
  `exp` selectively disclosable. The wiki documents this as an issuer-side rule
  (SD-JWT VC caveat), and it predates this ADR.
- ADR-0007's note that `check_jwt_temporal` "never looks at `iat`" describes the
  helper before this ADR. Its conclusion stands: key-proof freshness is still
  `check_iat_freshness`.
