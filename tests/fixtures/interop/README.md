# Third-party interop vectors

Artifacts produced by **other** implementations / published by the specs
themselves, vendored byte-for-byte so openvc's conformance is pinned against the
ecosystem instead of its own round-trip (issue #115). Retrieved **2026-07-16**.
Do not edit — any byte change breaks the signatures / digests by design.

## `sd_jwt_vc/` — SD-JWT VC issued by others

| file | source | notes |
|---|---|---|
| `rfc9901-a3-sd-jwt-vc.txt` | [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) Appendix A.3 | The IETF SD-JWT standard's own SD-JWT VC example (`typ: dc+sd-jwt`, `vct: urn:eudi:pid:de:1`). De-wrapped from the RFC text; correctness is self-proving — the ES256 issuer signature only verifies if the bytes are exact. |
| `rfc9901-a5-issuer-key.json` | RFC 9901 Appendix A.5 | The published P-256 issuer public key, stated in the RFC to "validate the Issuer signatures in the above examples". |
| `eudi-pid-sd-jwt-vc.txt` | [eudi-lib-jvm-siop-openid4vp-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt/blob/main/src/test/resources/example/sd-jwt-vc-pid.txt) | A real EUDI reference-implementation PID (`vct: urn:eudi:pid:1`, ES256, issuer cert in `x5c`, 27 disclosures, issuance form). |
| `eudi-pid-issuer.pem` | extracted from the PID's own `x5c` at retrieval | `CN=Kotlin PID Issuer DEV` leaf; the key the PID's issuer signature verifies under. |
| `eudi-pid-holder-key.json` | [same repo](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt/blob/main/src/test/resources/example/sd-jwt-vc-pid-key.json) | The holder key (private part included) whose public half is the PID's `cnf` — lets tests build/verify a KB-JWT. |

Both SD-JWT VCs carry an `exp` (EUDI PID: 2026-08-01; RFC 9901: 2029), so the
tests **freeze the clock** to the 2026-07-16 retrieval date — the fixed signed
bytes cannot be re-minted with a later expiry, and the point is the signature,
not wall-clock liveness.

## `status/` — W3C Bitstring Status List `encodedList` decode vectors

| file | source | decodes to |
|---|---|---|
| `w3c-rec-example3-encodedList.txt` | [VC Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) (W3C Recommendation, 2025-05-15), Example 3 | 131 072 bits (16 KiB), all clear — the spec's minimum-size list. |
| `digitalbazaar-100k-50k-revoked-encodedList.txt` | [digitalbazaar/vc-bitstring-status-list](https://github.com/digitalbazaar/vc-bitstring-status-list/blob/main/tests/mock-sl-credentials.js) `encodedList100KWith50KthRevoked` | 100 000 bits with exactly one set. NB: under the REC's MSB-first order the set bit is **index 50007**, not 50000 — the constant's name assumes LSB-first, so this doubles as a bit-order regression. |

Both are **multibase**-encoded (leading `u`), as the REC mandates (`encodedList`
MUST be "multibase-encoded base64url"). They are decode vectors only — unsigned
`encodedList` strings, not signed credentials.
