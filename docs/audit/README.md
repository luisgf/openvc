# openvc — external-audit pack

Prepared for [#75 — external review of the verification core + hand-rolled
codecs](https://github.com/luisgf/openvc/issues/75). This folder is the
**audit-readiness pack**: the material a third-party reviewer (or a funding body
vetting the project) needs to scope and start a review of openvc's security
core. It is self-review documentation — the *funded external audit* itself is
gated on funding (see §5).

Anchors are pinned to **v1.20.0 (`d378b99`)**; re-anchor line numbers against the
commit under review.

## 1. What openvc is (in one paragraph)

`openvc` is a **dependency-light** (`cryptography` + `pyjwt` only),
**fail-closed**, **HSM-friendly** Verifiable Credentials **verifier core**. It
verifies three proof families (VC-JWT/JOSE, SD-JWT VC, Data Integrity —
`eddsa-rdfc-2022` / `ecdsa-rdfc-2019` / JCS variants / `ecdsa-sd-2023`), resolves
DIDs (`did:key`, `did:jwk`, `did:web`, `did:webvh`, and `did:ebsi` in the
plugin), checks status-list revocation (W3C Bitstring + IETF Token Status List),
verifies OpenID4VP presentations (incl. experimental ISO `mso_mdoc` and HAIP
JWE), and consumes EU Trusted Lists as trust anchors. To stay dependency-light it
**hand-rolls the codecs that face attacker bytes** (CBOR, COSE, JCS, multibase,
bitstring, and the trusted-list XML path) — which is exactly why they warrant
external review.

## 2. The pack

| Document | What it holds |
|---|---|
| [threat-model.md](threat-model.md) | The code-cited threat model: assets, trust boundaries, attacker model, per-suite and per-parser attack-surface tables, the **fail-closed invariants catalog** (I1–I15), and the **residual-risk register** (R1–R8) |
| [assurance.md](assurance.md) | Property-based **fuzz** coverage, the "harden-next" gap map, negative/tamper coverage by suite, and the **adversarial-review history** |
| [Security-Model](https://github.com/luisgf/openvc/wiki/Security-Model) (wiki) | The user/integrator-facing summary the threat model annex expands |
| [SECURITY.md](https://github.com/luisgf/openvc/blob/main/SECURITY.md) | Reporting policy + per-control hardening notes |
| [docs/adr/](https://github.com/luisgf/openvc/tree/main/docs/adr) | The decision records (SSRF/caching, mdoc scope, status-issuer binding, …) |

## 3. Suggested review scope & priority

Ranked by attacker leverage against the one property — **no wrong-accept**:

1. **The alg allow-list & the fail-closed pipeline** — that the
   `{ES256, ES384, EdDSA, Ed25519}` gate truly runs before any crypto, that
   every failure raises a typed `OpenvcError`, and that `verify_many` isolation
   holds (threat model I1, I14, I15).
2. **Issuer binding across all three suites** — DI `verificationMethod`↔`issuer`,
   VC-JWT envelope reconciliation, x5c SAN↔`iss` (I4–I6). The place a
   sign-with-own-key impersonation would hide.
3. **The hand-rolled attacker-facing parsers** — CBOR, COSE, mdoc, JCS,
   multibase, SD-JWT, ecdsa-sd, bitstring, decompress, and the two XML paths
   (threat model §6). Depth/size bounds and typed-error hygiene. Start with
   residual risks **R1–R3**.
4. **The SSRF surface** — `fetch.py` (IP-pin, forbidden ranges, redirect
   refusal), the resolver opt-out boundary, and the EBSI host allow-list
   (§7, R4–R5).
5. **The XAdES / Trusted-List XML trust base** — DOCTYPE refusal, the
   XAdES-BASELINE-B profile, the XSW guard, and the `signxml`/`lxml` dependency
   (I13, R6).

The residual-risk register (R1–R8) is deliberately the reviewer's shortcut to
the soft spots we already know about; **R1** (SD-JWT unbounded recursion →
batch-abort DoS) is the top harden-next item.

## 4. How to reproduce the evidence

```
pip install -e ".[all]"
pytest                       # offline, deterministic
flake8 && mypy               # lint + type-check
```

The negative corpus and the golden interop fixtures (`tests/fixtures/`, W3C
vc-di-eddsa / vc-di-ecdsa, ISO 18013-5 Annex D, EU trusted-list) are the drift
alarm; `tests/test_fuzz_codecs.py` is the property-based harness. See
[assurance.md](assurance.md) for the coverage map.

## 5. Funding routes (why this is fundable)

The external audit and any resulting fixes are the deliverable #75 gates on
funding for. openvc's **EUDI relevance** is the pitch — it verifies the exact
credential and trust-anchor formats the EU Digital Identity Wallet ecosystem
mandates, as an independent, open-source, dependency-light core. Candidate
routes:

- **NGI0 / NLnet** (NGI Zero Core / Commons Fund) — EU-funded grants for
  open-source internet-trust infrastructure; openvc's DID/VC/trust-list scope is
  squarely in remit.
- **Sovereign Tech Agency** (formerly Sovereign Tech Fund) —
  investment in foundational open-source; a dependency-light crypto-verifier core
  used downstream fits the "critical dependency" framing.

The credibility story pairs this pack with the W3C/OIDF conformance evidence
tracked in the [Conformance & production readiness](https://github.com/luisgf/openvc/milestone/11)
milestone. This document does **not** commit to a specific programme or timeline —
it records the pack so the pursuit is deliberate.

## 6. Reporting a vulnerability

Privately, per [SECURITY.md](https://github.com/luisgf/openvc/blob/main/SECURITY.md):
email **luisgf@luisgf.es** or use GitHub Security Advisories. Please do not open a
public issue for security problems.
