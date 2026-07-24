# openvc roadmap

The **forward roadmap is managed as GitHub issues** — one issue per item, each
landed through its own pull request. Browse it by milestone:

- **[Q3–Q4 2026 — eIDAS deadline & ecosystem refresh](https://github.com/luisgf/openvc/milestone/12)** —
  the 2026-07 standards-review wave, anchored on CIR (EU) 2025/848 applying
  2026-12-24: the third-party `vp_token` capture and the draft→RFC cite swaps
  (Token Status List, SD-JWT VC) remain; the WRPRC parser against the final ETSI
  TS 119 475, the pyld 3.x / PyJWT 2.13 dependency refresh, Python 3.15 in CI and
  the documentation truth pass have shipped.
- **[Conformance & production readiness](https://github.com/luisgf/openvc/milestone/11)** —
  deferred follow-ups that each need a real signed artifact or a launched
  external service before they can land — today: the EBSI production launch
  (Q4 2026 under EUROPEUM-EDIC).
- **[Long term — PQ, BBS & 2.0](https://github.com/luisgf/openvc/milestone/8)** —
  the 2027 horizon: the BBS gate re-evaluation, the external security review,
  and the 2.0 breaking-cleanup window keyed to the W3C 2.1/1.1 maintenance
  wave (April 2027) + DID 1.1.

All items: <https://github.com/luisgf/openvc/issues>. Shipped history:
[CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) and the
[releases](https://github.com/luisgf/openvc/releases).

## Where 1.0 got us (shipped)

1.0 delivered the promise: a **dependency-light** (`cryptography` + `pyjwt` only),
**fail-closed**, **HSM-friendly** Verifiable Credentials *core* with a demarcated,
frozen, documented public surface — including the return-object contract downstream
libraries destructure — and a real deprecation policy, so consumers build on it
without fear of silent breakage. The 1.x line then grew breadth exactly where the
2026 EUDI stack demands it, always additively and always without state or transport: the three
proof families (VC-JWT, SD-JWT VC, Data Integrity — RDF `eddsa-rdfc-2022` /
`ecdsa-rdfc-2019`, JCS `eddsa-jcs-2022` / `ecdsa-jcs-2019`, and selective-disclosure
`ecdsa-sd-2023`), `did:key` / `did:jwk` / `did:web` (+ `did:ebsi` in the plugin),
`/.well-known/jwt-vc-issuer` and X.509 `x5c` issuer trust, both status-list encodings
(W3C Bitstring + IETF Token Status List) with issuance, stateless OpenID4VP 1.0
`vp_token` verification (SD-JWT VC, VP-JWT, `ldp_vc` and — experimental — ISO 18013-5
`mso_mdoc` over the Digital Credentials API) including HAIP encrypted responses, EU
trusted lists as trust anchors in both encodings (ETSI TS 119 612 XML LOTL→TL, TLv6,
and the TS 119 602 JSON Lists of Trusted Entities with the EU WRPAC/WRPRC
provider-list profiles), both halves of the EUDI relying-party
certificate pair (the X.509 **WRPAC** and the JWT/CWT **WRPRC** with its entitlement
cross-checks), a core TTL cache, batch and async
verification, observability, and — experimental — post-quantum ML-DSA (RFC 9964)
signing/verification behind an explicit opt-in.

## Direction

Post-1.0, openvc grows only where the EU digital-identity stack requires it —
consuming (never generating) OpenID4VP/HAIP presentations and their EU trust anchors,
securing and issuing the credential formats themselves, tracking the JOSE/COSE and
Data Integrity spec churn, and preparing for post-quantum (a first experimental ML-DSA
rail has landed) — always additively, and never at the cost of the three invariants
that are its entire reason to exist: **no state, no transport, dependency-light**,
all three fail-closed. The milestones above sequence that; the out-of-scope list below
is the standing boundary.

Note what that boundary is *not*: openvc has signed since 1.0 (`VcJwtProofSuite.sign`,
`SdJwtVcProofSuite.issue`, the status-list builders), so "read/verify-only" was never an
accurate description and is retired as a framing. The line that has actually held, and
still holds unchanged, is **credential-format production in; protocols, sessions and
servers out** — see [ADR-0007](adr/ADR-0007-oid4vci-issuer-side.md), which applies it to
OpenID4VCI without moving it.

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: the downstream badge library that
  consumes `openvc`.
- **OpenID4VP request generation**: a wallet / RP-server concern. The OpenID4VP + HAIP
  items are strictly stateless *consume-and-verify* (verify a received `vp_token`,
  decrypt a received JWE).
- **OAuth Authorization Servers, HTTP endpoints, and state storage**: the standing
  boundary, now stated in its general form. openvc runs no server, holds no session,
  and stores no `c_nonce`, code, `transaction_id` or `notification_id`. Where a
  protocol needs such state, the store is **injected as a required callable** and the
  library keeps nothing.
- **OpenID4VCI — the protocol layer**: out; the **key-proof verifier is in**.
  [ADR-0007](adr/ADR-0007-oid4vci-issuer-side.md) splits it on the standing rule —
  *attacker-controlled bytes that must be verified or parsed fail-closed* are openvc's;
  *anything with a lifetime, a socket or a deployment policy* is the consumer's. So in:
  wallet key-proof verification (OID4VCI 1.0 App. F.1) and fail-closed parsing of
  untrusted Credential Offers and Issuer Metadata — the same posture as the OpenID4VP
  verifier, one protocol over. Out: the nonce/code stores, every endpoint, the AS, and
  the response/offer/metadata **builders**, which belong to the issuing application
  (`openbadgeslib` first). Also out: JWE *encrypt*, key-attestation verification,
  `di_vp` proofs and DPoP. The claim this supports is **OpenID4VCI 1.0 key-proof
  verification** — not "issuance", not *HAIP issuance*.
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
