# ADR-0008 — One NumericDate rule for every JOSE lane, and RFC 7519 §4.1.3 on VC-JWT

**Status:** Accepted. **Verdict: one shared temporal rule (`null` rejected, future
`iat` bounded) on every JOSE lane; `aud` enforced on both VC-JWT lanes.**
**Date:** 2026-10-13
**Context owner:** `openvc.proof._verify_common` (`check_jwt_temporal`,
`check_jwt_audience`), used by `proof.vc_jwt`, `proof.sd_jwt`, `proof.vp_jwt`,
`status.issue` and `openid4vci`
**Follows:** [#195](https://github.com/luisgf/openvc/pull/195) (VC-JWT NumericDate
shapes), whose adversarial review found the inconsistencies below.

## Context

openvc verifies JWTs on several lanes, and they had drifted on the claims RFC 7519
defines:

| Lane | `exp`/`nbf: null` | malformed `iat` | future `iat` | `aud` with no audience given |
|---|---|---|---|---|
| VC-JWT, classic (PyJWT) | rejected (#195) | rejected (#195) | rejected (PyJWT) | **accepted** (`verify_aud=False`) |
| VC-JWT, ML-DSA | rejected (#195) | rejected (#195) | **accepted** | **accepted** |
| SD-JWT VC issuer JWT | **read as absent** | **accepted** | **accepted** | not checked |
| VP-JWT | **read as absent** | **accepted** | **accepted** | n/a (audience required) |
| Status-list token | **read as absent** | not read | not read | not checked |

The status-list token also accepted an `exp` of `NaN`, `Infinity` or `1e400`. Every
comparison against those is false, so the list never went stale, while the code
comment said it failed closed. The ML-DSA lane also accepted a non-string `sub`/`jti`,
which PyJWT rejects on the classic lane.

Each gap is small, but together they meant the answer to "does openvc reject this
token?" depended on which lane parsed it.

## Decision

### D1 — A present date must be a finite JSON number, `null` included

RFC 7519 §2 defines a NumericDate as a JSON number. `check_jwt_temporal` now starts
with `check_numeric_dates(claims, "exp", "nbf", "iat")`, so on every lane that calls
it (SD-JWT VC issuer JWT and processed payload, VP-JWT, VC-JWT ML-DSA, OpenID4VCI key
proof) a present `exp`/`nbf`/`iat` that is `null`, a bool, a string, a container,
non-finite, or an integer no float can hold is `ClaimsInvalid`. The classic VC-JWT
lane already ran the same gate before PyJWT (#195). The status-list token applies the
same shape rule to all three claims and raises its own `StatusListError`.

This is an interop decision: it shrinks what verifies, and some issuers serialise an
unset field as `null`. We take it because the rule is the RFC's and a lenient reading
differs per lane. It is listed in the CHANGELOG as a behaviour change.

### D2 — An `iat` more than the leeway in the future is rejected

PyJWT's `verify_iat` already did this on the classic VC-JWT lane. `check_jwt_temporal`
now does it for the ML-DSA lane, the SD-JWT VC issuer JWT (and a disclosed `iat`) and
the VP-JWT. Like `nbf`, the expiry waiver (`require_not_expired=False`) leaves it on:
a token minted later than now is pre-dated, not expired.

`iat` stays optional, and its age is not bounded. Proofs that exist to be fresh
already bound it both ways with `check_iat_freshness` (KB-JWT, OpenID4VCI key proof).

The status-list token is the exception: only its `exp` is compared against the clock.
A verifier re-checking an archived credential pins `now` to its receipt time, and the
list it fetches today is legitimately newer than that pin. A future-`iat` or `nbf`
comparison there would reject every such re-check.

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

- One rule across lanes. `check_jwt_temporal` single-sources it, and the test matrix
  in `tests/test_jose_temporal_claims.py` and `tests/test_vc_jwt_audience.py` runs each
  lane under the default policy and `VerificationPolicy(require_not_expired=False)`.
- **Behaviour changes**, all fail-closed: `null` dates on the SD-JWT VC, VP-JWT,
  status-list token and OpenID4VCI key-proof lanes; a malformed or future `iat` on
  SD-JWT VC and VP-JWT; a future `iat` and non-string `sub`/`jti` on VC-JWT ML-DSA; an
  `aud` on a VC-JWT verified without an audience.
- **Nested VC-JWTs in a presentation** are checked against `policy.audience`, not the
  presentation's `audience`. #190 chose that deliberately, and it stands. So
  `verify_vp_token`, which sets no `policy.audience`, rejects a nested VC-JWT that
  carries `aud`, even one addressed to the same verifier. And because a VC-JWT without
  `aud` fails when an audience is expected, one `VpJwtProofSuite.verify` call cannot
  accept a mix of VC-JWTs with and without `aud`. If real presentations need that, a
  follow-up could check a nested credential's `aud` against the presentation's
  audience whenever the credential carries one. That is not done here: it is a false
  negative, never a false accept.
- **Not covered by §4.1.3 here:** the SD-JWT VC issuer JWT (SD-JWT VC carries the
  audience binding in the KB-JWT, RFC 9901 §7.3), and the status-list token (bound to
  its URL by `sub`). The VP-JWT always requires its audience, and a KB-JWT is checked
  against the caller's audience whenever one is given (always, when key binding is
  required).
- ADR-0007's note that `check_jwt_temporal` "never looks at `iat`" describes the
  helper before this ADR. Its conclusion stands: key-proof freshness is still
  `check_iat_freshness`.
