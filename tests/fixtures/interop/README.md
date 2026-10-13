# Third-party interop vectors

Artifacts produced by **other** implementations / published by the specs
themselves, vendored byte-for-byte so openvc's conformance is pinned against the
ecosystem instead of its own round-trip (issue #115). Retrieved **2026-07-16**
unless a section says otherwise. Do not edit — any byte change breaks the
signatures / digests by design.

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

## `openid4vp/eudi-dev-capture/` — a `vp_token` presented by a third-party wallet

One genuine OpenID4VP 1.0 exchange, captured on 2026-10-10 by
[@EgorKhaklin](https://github.com/EgorKhaklin) ([polaris-id](https://github.com/EgorKhaklin/polaris-id))
and contributed on [#121](https://github.com/luisgf/openvc/issues/121). The
**eudi-dev** testing wallet (v2.3.7, by Dominik Schlosser — Go, Apache-2.0; *not*
the EUDI reference implementation) presented an SD-JWT VC with its Key Binding JWT
over `direct_post.jwt` to **polaris-oid4vp** 1.0.0rc16, which accepted it.

Vendored byte-for-byte on **2026-10-13** from
[`lab/interop/eudi-dev/capture/` at `76b2369`](https://github.com/EgorKhaklin/polaris-id/tree/76b236909079418123ef6cdce66bb1068306b187/lab/interop/eudi-dev/capture).
Licensed **Apache-2.0**, both the vector and its provenance record; eudi-dev, which
produced the presentation layer, is Apache-2.0 too. As the author asked,
[`PROVENANCE.md`](openid4vp/eudi-dev-capture/PROVENANCE.md) is kept beside the files,
unmodified: it says how each file was made, by which software, and at which instant.

**Who made which bytes**, per that record: the **presentation layer** is eudi-dev's —
DCQL matching, disclosure selection, the KB-JWT, the DCQL-keyed `vp_token` and the
response encryption — and that is what this vector pins. The inner credential comes
from polaris-id's test issuer, under an `x5c` leaf chained to a CA generated for the
run (`issuer-ca.pem`). The request object is polaris-oid4vp's. **Every key is a test
key.**

| file | what it is |
|---|---|
| `presentation.txt` | `<issuer JWT>~<disclosure>~<disclosure>~<KB-JWT>`, one line, no trailing newline. |
| `vp-token.json` | The `vp_token` exactly as eudi-dev sent it, keyed by the DCQL query id `pid`. |
| `request.json` | What a verifier checks against: `nonce`, `client_id` (with its `x509_hash:` prefix — the KB-JWT's `aud`) and `dcql_query`. *Assembled* by the author from `request.jwt`'s payload. |
| `request.jwt` | The signed request object (JAR, ES256) those values come from. |
| `issuer-ca.pem` | The trust anchor the credential's `x5c` leaf chains to. |
| `response.jwe` | The encrypted `direct_post.jwt` response as posted (ECDH-ES + A128GCM). |
| `verifier-decryption-key.test-only.jwk.json` | The request's ephemeral ECDH-ES private key, so `response.jwe` opens offline — **test material, never trust**. |
| `PROVENANCE.md` | The author's provenance record and licence statement, unmodified. |

The tests pin every file's SHA-256: the seven data files against PROVENANCE.md's own
table, and PROVENANCE.md itself so the attribution is never edited by accident. They
verify with `now` pinned to the **capture instant**, 2026-10-10T19:49:20Z
(`1791661760`) — the second the verifier reached its verdict, i.e. its own receipt
time. The KB-JWT is only fresh then and the issuer leaf expires 2026-11-09, so pinning
`now` instead of reading the wall clock keeps the bytes verifiable for good. The
capture's "an hour later" control is kept as a regression test: it is what found
[#186](https://github.com/luisgf/openvc/issues/186).
