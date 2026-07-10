# openvc roadmap

The **forward roadmap is managed as GitHub issues** — one issue per item, each
landed through its own pull request. Browse it by milestone:

- **[Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6)** —
  dated correctness/conformance work: the binding TLv6 trusted-list cutover, the
  RFC 9864 / RFC 9901 / Token Status List churn, the `ldp_vc` presentation lane, the
  crypto-floor tests, and this post-1.0 documentation truth pass.
- **[Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7)** —
  completing the EUDI relying-party story: the `mso_mdoc` scope decision, the W3C
  Digital Credentials API, EBSI's production launch, relying-party certificates
  (WRPAC/WRPRC), `did:webvh`, W3C test-suite registration, a Spanish education
  walkthrough, and the ML-DSA design spike.
- **[Long term — PQ, BBS & 2.0](https://github.com/luisgf/openvc/milestone/8)** —
  post-quantum credentials (RFC 9964), the BBS gate re-evaluation, the W3C
  1.1/2.1 maintenance wave + DID 1.1, an external security review, and the 2.0
  breaking-cleanup window.

All items: <https://github.com/luisgf/openvc/issues>. Shipped history:
[CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) and the
[releases](https://github.com/luisgf/openvc/releases).

## Where 1.0 got us (shipped)

1.0 delivered the promise: a **dependency-light** (`cryptography` + `pyjwt` only),
**fail-closed**, **HSM-friendly** Verifiable Credentials *core* with a demarcated,
frozen, documented public surface — including the return-object contract downstream
libraries destructure — and a real deprecation policy, so consumers build on it
without fear of silent breakage. The 1.x line then grew breadth exactly where the
2026 EUDI stack demands it, always additively and always read/verify-only: the three
proof families (VC-JWT, SD-JWT VC, Data Integrity — RDF `eddsa-rdfc-2022` /
`ecdsa-rdfc-2019`, JCS `eddsa-jcs-2022` / `ecdsa-jcs-2019`, and selective-disclosure
`ecdsa-sd-2023`), `did:key` / `did:jwk` / `did:web` (+ `did:ebsi` in the plugin),
`/.well-known/jwt-vc-issuer` and X.509 `x5c` issuer trust, both status-list encodings
(W3C Bitstring + IETF Token Status List) with issuance, stateless OpenID4VP 1.0
`vp_token` verification (SD-JWT VC, VP-JWT, `ldp_vc` and — experimental — ISO 18013-5
`mso_mdoc` over the Digital Credentials API) including HAIP encrypted responses, EU
Trusted Lists (LOTL→TL, TLv6) as trust anchors, a core TTL cache, batch and async
verification, observability, and — experimental — post-quantum ML-DSA (RFC 9964)
signing/verification behind an explicit opt-in.

## Direction

Post-1.0, openvc grows only where the EU digital-identity stack requires it —
consuming (never generating) OpenID4VP/HAIP presentations and their EU trust anchors,
tracking the JOSE/COSE and Data Integrity spec churn, and preparing for post-quantum
(a first experimental ML-DSA rail has landed) — always additively, always
read/verify-only, never at the cost of the dependency-light
and fail-closed invariants that are its entire reason to exist. The milestones above
sequence that; the out-of-scope list below is the standing boundary.

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: the downstream badge library that
  consumes `openvc`.
- **OpenID4VP request generation, session/state**: wallet / RP-server concerns. The
  OpenID4VP + HAIP items are strictly stateless *consume-and-verify* (verify a
  received `vp_token`, decrypt a received JWE).
- **ISO mdoc — engagement / proximity / issuance / COSE signing**: device engagement,
  NFC/BLE/QR proximity flows, issuance, and a COSE *signing* surface stay out. Server-side
  *verification* of an OpenID4VP-delivered `mso_mdoc` is the exception, now **shipped**
  (experimental): [ADR-0005](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0005-mso-mdoc-verification.md)
  ruled it in scope and [#86](https://github.com/luisgf/openvc/issues/86) implemented it —
  read-only IssuerAuth (COSE_Sign1 + `x5chain`→IACA + `valueDigests`) + DeviceAuth over the
  Digital Credentials API SessionTranscript, hand-rolled COSE/CBOR with no new dependency.
- **COSE/CWT (`vc+cose`) securing**: openvc is JOSE-first for EBSI/EUDI; a COSE
  signing surface duplicates the JOSE path against thin demand.
- **BBS / bbs-2023** unlinkable selective disclosure — *deferred, not rejected*:
  mandatorily pairing-based (BLS12-381) with no mature, audited pure-Python library in
  2026 and a spec at Candidate Recommendation Draft. Revisited under a documented gate
  (CFRG RFC + W3C Recommendation + a bindable pairing library) —
  [issue #73](https://github.com/luisgf/openvc/issues/73).
- **CycloneDX SBOM generation**: the runtime dependency graph is two nodes; PEP 740
  attestations (via Trusted Publishing) and `pip-audit` already cover provenance.
