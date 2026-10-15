# VC-JOSE-COSE fixtures — two SD-JWT credentials from the W3C Recommendation

Two compact SD-JWT credentials copied **verbatim** from *Securing Verifiable Credentials
using JOSE and COSE*, the W3C Recommendation of 13 October 2026
(<https://www.w3.org/TR/vc-jose-cose/>). They are material we did not write, so the tests
that read them cannot share a blind spot with the code (the project's drift-alarm
discipline: recorded real vectors, not synthetic shapes).

## Files

- `rec-example5-no-typ.sd-jwt` — **Example 5** (§3.2.2, an SD-JWT presentation of an
  `EnvelopedVerifiableCredential`): the SD-JWT-secured credential in the
  `data:application/vc+sd-jwt,` URL of its `id`. Issuer JWT header `{kid, alg: ES256}` and
  **no `typ`** (a SHOULD, §3.2.1); payload with a VCDM v2 `@context`, an `issuer` and **no
  `iss`**; 6 disclosures, no KB-JWT.
- `rec-example21-vc-ld-json-sd-jwt-typ.sd-jwt` — **Example 21** (§8.4, "Data URIs"): the
  SD-JWT-secured credential carried in a `data:` URI. Issuer JWT header `{alg: ES384, kid,
  typ: vc+ld+json+sd-jwt, cty: vc+ld+json}`, the draft-era media type name (§6.1.3 now
  registers `vc+sd-jwt`); payload with an `iss`, an `exp` of 2024-10-14 (long past), and a
  `cnf`; 6 disclosures, no KB-JWT.

Each file holds the token on one line, with a trailing newline that the tests strip.

## What they can and cannot prove

The Recommendation publishes **no key** for either token, so neither can verify as
published. Used as is, a token clears the `typ` gate of `SdJwtVcProofSuite.verify` and
fails at the signature (`SignatureInvalid`), which proves that a real W3C header gets past
that gate. `verify()` checks the signature **before** it reads the payload, so a stranger
key says nothing about the payload gates (issuer selection from `iss` or, since #290, from
`issuer`; the VCDM conformance gate of #275). To exercise those the tests **re-sign** the
header and payload under a test key of the right curve (P-256 for Example 5, P-384 for
Example 21), leaving the disclosures untouched (the `_sd` digests hash the disclosures, not
the payload, so they still match). Example 21's own `exp` has passed, so those runs waive it
(`check_temporal=False` or `VerificationPolicy(require_not_expired=False)`).

## Consumers

- `tests/test_sd_jwt_vcdm_typ_interop.py` - section I: the real headers clear the `typ`
  gate, fail only at the signature under a stranger key, and verify end to end once
  re-signed (the suite, and the sync and async pipelines).
- `tests/test_sd_jwt_issuer_fallback.py` - section E: Example 5 as published, re-signed,
  verifies without adding an `iss` (the VCDM `issuer` selects the key, #290), and the
  pipelines' `jwt_vc_issuer_fetch` handling of its https issuer.
- `tests/test_sd_jwt_vcdm_conformance.py` - the re-signed tokens (Example 5 with an `iss`
  equal to its `issuer` added) against the `@context` / `type` conformance gate (#275):
  both pass it, and both are refused when the base context is misplaced or the `type`
  disclosure is withheld.
