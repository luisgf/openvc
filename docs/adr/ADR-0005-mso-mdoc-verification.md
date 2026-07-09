# ADR-0005 — `mso_mdoc` verification: scope decision for the second mandatory EUDI format

**Status:** Accepted (scope decision). **Verdict: in scope, verify-only.**
Implementation is a dedicated follow-up issue (XL), not this ADR.
**Date:** 2026-07-09
**Context owner:** `openvc.openid4vp` + a new `openvc` COSE/mdoc verify module
**Spike:** [#65](https://github.com/luisgf/openvc/issues/65) (milestone
[Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7))

## Context

CIR (EU) 2024/2977 makes **SD-JWT VC and ISO/IEC 18013-5 mdoc** the two mandatory
PID/QEAA credential formats. openvc verifies SD-JWT VC today; a verifier without
mdoc covers only half the EUDI wallet ecosystem. `verify_vp_token` already fences
`mso_mdoc` behind a typed `UnsupportedPresentationFormat` — a **declared follow-up**,
not an oversight (`openid4vp.py:330`).

The ROADMAP's out-of-scope list excludes **device engagement / proximity flows** and
a **COSE *signing* surface**. Server-side **verification** of an
OpenID4VP-delivered mdoc is a *different, read-only* question: given a
`DeviceResponse` already carried over OpenID4VP, check the issuer's seal and the
device's holder-binding. That is consume-and-verify — squarely openvc's posture — and
this ADR decides whether and how to build it. Python has no serious answer today:
`pymdoccbor` is a static decoder over an unmaintained `pycose`.

This ADR is the trigger the ROADMAP names ("not in scope until that ADR lands"). It
**ships no code** — it settles scope, strategy, and the boundary; the build is its own
issue.

## Evidence

### What mdoc verification actually requires (ISO/IEC 18013-5 §9; -7 / OpenID4VP online)

A received `DeviceResponse` (CBOR) verifies in four steps:

1. **IssuerAuth** — a `COSE_Sign1` (RFC 9052, tag 18) over the `MobileSecurityObject`
   (MSO). The document-signer certificate rides in the COSE **unprotected header
   `x5chain` (label 33)**; its chain is validated to a caller-provided **IACA** trust
   anchor (an eIDAS/EUDI trusted-list root), and the MSO `validityInfo` window and
   `docType` are checked.
2. **Issuer-data integrity** — for every disclosed `IssuerSignedItem`, recompute its
   digest and match `MobileSecurityObject.valueDigests[nameSpace][digestID]`. This is
   the mdoc analogue of SD-JWT disclosure hashing.
3. **DeviceAuth (holder binding)** — a `COSE_Sign1` (`DeviceSignature`) or `COSE_Mac0`
   (`DeviceMac`, tag 17) over a `DeviceAuthentication` structure built from the
   **SessionTranscript**. Online, that transcript is the **OpenID4VP / ISO 18013-7
   handover** (client_id, nonce, response_uri or the DC-API origin, and the
   mdoc-generated nonce). This is the session/replay binding — the security-critical
   crux — and it is computed from exactly the OpenID4VP material [#66](
   https://github.com/luisgf/openvc/issues/66) also needs.
4. **Algorithms/keys** — COSE ES256/ES384/ES512 (and EdDSA); the device public key is
   an embedded `COSE_Key` in `MSO.deviceKeyInfo.deviceKey`.

### What the current code offers — and where it stops

| Asset | Reusable? |
|---|---|
| `openid4vp.py` `mso_mdoc` fence (`UnsupportedPresentationFormat`, line 330) | The integration seam exists — a declared follow-up. |
| `x5c.py` chain path-validation + anchor binding | **Core reusable**, but the container differs (COSE `x5chain` header, not a JOSE `x5c` array), the binding is IACA/`docType` not `iss`→SAN, and mdoc allows a broader curve set than x5c's P-256-leaf-only rule. |
| `keys.verify_signature` (ES256/384, raw R‖S) | Reusable for the COSE_Sign1 signature check. |
| `ecdsa_sd.encode_cbor` / `decode_cbor` | **Only a subset.** It is a *"minimal CBOR for the fixed proof-value shape: unsigned int, byte string, text string, array, map"* — it **rejects negative integers** (`ecdsa_sd.py:117`) and does not decode **tags** or floats. It also lives inside the `[data-integrity]`/pyld-gated module. |

COSE/mdoc CBOR needs materially more than that subset: **negative integers** (COSE
`alg` = `-7`, `COSE_Key` labels), **tags** (`COSE_Sign1` 18, `COSE_Mac0` 17,
embedded-CBOR `24`, full-date `1004` / `0`), booleans, and deterministic (CDE)
encoding for digest recomputation. So "reuse the existing CBOR codec" is only
half-true — it is a *starting point that must be extended and relocated*.

## Decisions

### D1 — Verdict: verify-only `mso_mdoc` is IN scope
Build it. It is a mandatory EUDI format, the fence already declares the follow-up, the
read-only server-side verify fits consume-and-verify, the eIDAS trust anchors are
already in-tree, and no maintained pure-Python alternative exists (first-mover, as
with ML-DSA). **Implementation is a dedicated XL issue**, filed as this ADR's
follow-up — not this PR.

### D2 — Boundary: exactly "verify a received `vp_token` mdoc"
In: parse a `DeviceResponse`, verify **IssuerAuth** (MSO COSE_Sign1 + `x5chain`→IACA +
`validityInfo` + `docType`), **issuer-data integrity** (`valueDigests`), and
**DeviceAuth** (DeviceSignature/DeviceMac over the OpenID4VP SessionTranscript). Out,
unchanged from the ROADMAP: **device engagement, NFC/BLE/QR proximity, issuance /
provisioning, and any COSE *signing* surface.** Verify one received document; nothing
about how it reached the verifier.

### D3 — Strategy: hand-rolled COSE_Sign1/Mac0 verify, NO new runtime dependency
Prefer a hand-rolled verifier over an `[mdoc]` extra. There is no maintained,
audited pure-Python COSE/mdoc library (`pymdoccbor`/`pycose` are dormant); depending
on one would break dependency-light **and** the fail-closed posture (an unmaintained
parser of attacker-controlled bytes is exactly what we must not import). The project
already hand-rolls CBOR (`ecdsa-sd`), varint, base58, and JCS. The verify surface —
`COSE_Sign1`/`COSE_Mac0` plus a bounded set of CBOR tags — is small and closed. Reuse
`keys.verify_signature` for the signature and `x5c.py`'s path validation for the
chain.

### D4 — Extract and extend the CBOR codec into a dependency-free module
Factor `encode_cbor`/`decode_cbor` out of the pyld-gated `ecdsa_sd` into a
dependency-free `openvc` CBOR module and extend it to the COSE/mdoc profile: **negative
integers, tags (17/18/24/1004/0), booleans/null**, with **deterministic (CDE)
encoding** for digest recomputation. It stays a *bounded, spec-scoped* subset — not a
general CBOR library. `ecdsa-sd` then imports the shared codec (no behaviour change;
its proof-value shape is a strict subset of the extended one).

### D5 — Reuse `x5c` path-validation, but via an mdoc-specific adapter
Do **not** force mdoc through the JOSE `x5c` entry point. Its container (COSE
`x5chain` header vs a JOSE array), issuer binding (IACA / `docType` vs `iss`→SAN), and
curve set differ. Factor the reusable path-validation core (chain signatures,
validity, name-chaining to a caller anchor) so both the JOSE `x5c` path and a new mdoc
IssuerAuth adapter call it. The eIDAS/EUDI trusted-list anchors (`openvc.trustlist`)
root both.

### D6 — Sequence the implementation with/after the Digital Credentials API (#66)
DeviceAuth binds to the OpenID4VP SessionTranscript/handover, which is exactly what
[#66](https://github.com/luisgf/openvc/issues/66) (OpenID4VP over the W3C DC API,
origin binding) computes. Building mdoc DeviceAuth before that handover is settled
would duplicate — or worse, diverge from — the session-binding logic. → The mdoc
implementation issue **depends on / sequences with #66**; the transcript builder is
shared, single-sourced.

### D7 — Fail-closed, adversarially reviewed, and in the audit scope; ship experimental first
mdoc verify materially expands the attacker-controlled-bytes parser surface (CBOR,
COSE, X.509, the transcript). It ships fail-closed with the standard adversarial
review, is **explicitly in scope for the funded external audit
([#75](https://github.com/luisgf/openvc/issues/75))**, and lands behind an
`experimental` label until it is interop-tested against the EUDI reference wallet and
the ISO 18013-5 reference vectors.

### D8 — Conformance by pinned real vectors, not synthetic shapes
Pin recorded real `DeviceResponse` vectors (EUDI reference wallet / ISO 18013-5 Annex
D) as golden fixtures — the same drift-alarm discipline as the W3C/EBSI suites. A
verifier proven only against shapes it also produces proves nothing.

## Consequences

- **New hand-rolled COSE + extended CBOR** is real code and real audit surface —
  accepted, and bounded: a closed set of COSE structures + tags, reusing
  `x5c`/`keys`, gated by #75 and an experimental label.
- **Dependency-light preserved** — no runtime dependency added; the CBOR extraction
  is net-neutral for `ecdsa-sd`.
- **Couples to #66** — the SessionTranscript builder is shared; the two are sequenced.
- **Completes the EUDI two-format mandate** — SD-JWT VC (done) + mdoc (planned)
  together cover PID/QEAA.
- The `ecdsa-sd` CBOR functions move modules — a mechanical, tested refactor with no
  behaviour change (its shape is a subset of the extended codec).

## Follow-ups

- **File the implementation issue** (verify-only `mso_mdoc`, this boundary), sequenced
  with #66 and flagged for the #75 audit. This ADR is its design input.
- The ROADMAP out-of-scope note is updated in this PR to record the verdict (verify-only
  in scope; proximity / issuance / COSE-signing still out).
- Track ISO 18013-7 and the OpenID4VP mdoc handover as they finalise.

## References

- CIR (EU) 2024/2977 (mandatory PID/QEAA formats: SD-JWT VC + ISO 18013-5 mdoc).
- ISO/IEC 18013-5:2021 §9 (mdoc security: IssuerAuth, DeviceAuth, `valueDigests`);
  ISO/IEC 18013-7 + OpenID4VP (online SessionTranscript / handover).
- RFC 9052 / 9053 (COSE: `COSE_Sign1` tag 18, `COSE_Mac0` tag 17, `COSE_Key`);
  RFC 8949 (CBOR, deterministic encoding).
