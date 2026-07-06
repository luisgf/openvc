# openvc roadmap

The **forward roadmap is managed as GitHub issues** — one issue per item, each
landed through its own pull request. Browse it by milestone:

- **[0.8.x — Security patches](https://github.com/luisgf/openvc/milestone/1)** —
  ship-now remote-DoS / SSRF fixes, no API break.
- **[1.0 — Stabilize](https://github.com/luisgf/openvc/milestone/2)** — one
  breaking cleanup of the error taxonomy, then freeze a demarcated, documented
  public surface **and** the `verify_credential` / `VerificationPolicy` /
  `Verified*` return-object contract; harden (schema ReDoS, digestSRI) and prove
  fail-closed (adversarial corpus + codec fuzzing).
- **[1.1 — EUDI verifier interop](https://github.com/luisgf/openvc/milestone/3)** —
  stateless, read-only OpenID4VP 1.0 `vp_token` verification + HAIP JWE-response
  decryption, SD-JWT VC Type Metadata, and the **pyld-free** RFC 8785 JCS Data
  Integrity path. All additive.
- **[post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4)** — P-384
  curves, EU Trusted Lists (LOTL→TL) trust anchoring, a core TTL cache, batch
  verification, an async story, and observability.

All items: <https://github.com/luisgf/openvc/issues>. Shipped history:
[CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) and the
[releases](https://github.com/luisgf/openvc/releases).

## Direction toward 1.0

openvc's 1.0 is a promise: a **dependency-light** (`cryptography` + `pyjwt` only),
**fail-closed**, **HSM-friendly** Verifiable Credentials *core* with a demarcated,
frozen, documented public surface — including the return-object contract that
downstream libraries destructure — plus a real deprecation policy, so consumers
build on it without fear of silent breakage. After 1.0, openvc grows breadth only
where the 2026 EUDI stack demands it — consuming (never generating) OpenID4VP/HAIP
presentations and their EU trust anchors, adding JCS cryptosuites and P-384 —
always additively, always read/verify-only, never at the cost of the
dependency-light and fail-closed invariants that are its entire reason to exist.

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: the downstream badge library that
  consumes `openvc`.
- **ISO mdoc device engagement, OpenID4VP request generation, session/state**:
  wallet / RP-server concerns. The OpenID4VP + HAIP items are strictly stateless
  *consume-and-verify* (verify a received `vp_token`, decrypt a received JWE).
- **COSE/CWT (`vc+cose`) securing**: openvc is JOSE-first for EBSI/EUDI; a COSE
  signing surface duplicates the JOSE path against thin demand.
- **BBS / bbs-2023** unlinkable selective disclosure — *deferred, not rejected*:
  mandatorily pairing-based (BLS12-381) with no mature, audited pure-Python library
  in 2026 and a spec only at Candidate Recommendation Draft. Revisit as a gated,
  fully optional `[bbs]` extra when a trustworthy pairing library exists and the
  spec advances toward Recommendation.
- **CycloneDX SBOM generation**: the runtime dependency graph is two nodes; PEP 740
  attestations (via Trusted Publishing) and `pip-audit` already cover provenance.
