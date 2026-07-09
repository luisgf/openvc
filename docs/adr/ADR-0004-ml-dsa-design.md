# ADR-0004 — ML-DSA (RFC 9964): post-quantum VC-JWT / SD-JWT VC behind SigningKey

**Status:** Accepted (design). Implementation deferred to
[#72](https://github.com/luisgf/openvc/issues/72) as an explicitly-experimental opt-in.
**Date:** 2026-07-09
**Context owner:** `openvc.keys` + `openvc.proof.vc_jwt` (the JOSE signing/verify path)
**Spike:** [#71](https://github.com/luisgf/openvc/issues/71) (milestone
[Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7))

## Context

The post-quantum rails openvc has been waiting for now exist:

- **RFC 9964** (May 2026) registers `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` as JOSE
  `alg` values and defines a new key type **`AKP`** ("Algorithm Key Pair") whose
  private key is a **seed only** (the `priv` member), with the public key in `pub`.
- `cryptography` **≥ 48** ships ML-DSA, including **external-mu signing**
  (`sign_mu` / `verify_mu`) — the variant that lets an HSM compute `mu` off-device,
  so openvc's HSM-first `SigningKey` story survives the jump to PQ.
- The EU coordinated PQC roadmap wants national migration plans by **end-2026** and
  high-risk systems migrated by **2030**. W3C's quantum-resistant Data Integrity
  cryptosuites are an explicitly-experimental **FPWD** (Jun 2026).
- No maintained Python VC library signs ML-DSA credentials today. This is first-mover
  space, aligned with openvc's "the `cryptography`-grade primitive for W3C/IETF
  credentials" positioning.

This ADR is the **output of the #71 spike**: it decides *how* ML-DSA would fit the
existing code without breaking the invariants, and *how far* to take it now. It
**ships no code** — the implementation is issue #72, gated experimental.

## Evidence

### What `cryptography` exposes (probed 2026-07-09, `cryptography 49.0.0` / OpenSSL 4.0.1)

| Fact | Value |
|---|---|
| Module | `cryptography.hazmat.primitives.asymmetric.mldsa` |
| Classes | `MLDSA{44,65,87}{Private,Public}Key` |
| Private constructors | `generate()`, `from_seed_bytes(...)`, `private_bytes_raw()` |
| **Raw private (seed)** | **32 bytes** — exactly the RFC 9964 `AKP` `priv` seed |
| Public raw | `public_bytes_raw()` → **1952 bytes** (ML-DSA-65) |
| Signing | `sign(data, context=None)` and **`sign_mu(...)`** (external-mu / HSM) |
| Verifying | `verify(sig, data)` and `verify_mu(...)` |
| **Signature size** | **3309 bytes** (ML-DSA-65) |
| Failure surface | `mldsa.UnsupportedAlgorithm` when the OpenSSL build lacks ML-DSA (needs OpenSSL ≥ 3.5) |

The `sign`/`sign_mu` split matters: `sign_mu` is the external-mu path RFC 9964 leans
on to keep the HSM story — the device computes `mu`, never the message — so the
`SigningKey` abstraction still holds with a hardware backend.

### What the current code shape constrains

- **JOSE allow-list** — `ALLOWED_ALGS = frozenset({"ES256", "ES384", "EdDSA",
  "Ed25519"})` in `src/openvc/proof/vc_jwt.py`, checked **before any crypto** (the
  primary alg-confusion defence). `_jws.sign_compact` re-checks it before signing.
- **VC-JWT verify delegates to PyJWT** — `VcJwtProofSuite._jwk_to_key` hands off to
  `ECAlgorithm.from_jwk` / `OKPAlgorithm.from_jwk` and `_JWT.decode(...)`. PyJWT
  ships **no ML-DSA algorithm and no `AKP` key type**; it already needs a private
  `PyJWT()` instance taught the RFC 9864 `"Ed25519"` name.
- **The dependency-light verifier** — `keys.verify_signature(*, alg, public_jwk,
  signing_input, signature)` dispatches on `alg` straight onto `cryptography`
  primitives (no PyJWT). This is what the SD-JWT / VP / status / `did:key`
  self-contained paths use.
- **JWK → backend dispatch** — `keys.signing_key_from_jwk` keys on `(kty, crv)` and
  knows only `OKP/Ed25519`, `EC/P-256`, `EC/P-384`. `AKP` has **no `crv`** — the
  parameter set lives in `alg`.
- **`did:jwk`** decodes *any* JWK object (`did_jwk.py`) — an `AKP` JWK resolves the
  moment the key loader understands `AKP`, no resolver change. **`did:key`** is a
  fixed multicodec table (`did_key.py`: `0xed`, `0x1200`, `0x1201`); ML-DSA code
  points are **draft/provisional** in the multicodec registry, not a stable
  assignment.
- **Data Integrity** picks its alg from the resolved key's `(kty, crv)` via
  `_verify_common.ALG_PROFILE` — a curve map with no notion of a lattice key.

## Decisions

### D1 — Ship ML-DSA, but as an explicitly-experimental opt-in (never default)
The demand signal (EU PQC calendar, first-mover gap) justifies building the rail
now; the immaturity (no stable interop vectors, provisional `did:key` code points,
W3C DI still FPWD) forbids making it a default trust path. → Implement in #72 behind
an explicit opt-in; the default `ALLOWED_ALGS` is **unchanged**, so a deployment that
does not opt in rejects `ML-DSA-*` at the allow-list, before any crypto.

### D2 — Gate on a `[pq]` extra + a runtime capability check, NOT a core floor bump
ML-DSA needs `cryptography ≥ 48` **and** an OpenSSL ≥ 3.5 build (the probe host has
OpenSSL 4.0.1; a wheel built against older OpenSSL raises `mldsa.UnsupportedAlgorithm`
at runtime even on `cryptography 49`). The dependency-light core stays
`cryptography>=45` + `pyjwt`. → New `pq = ["cryptography>=48"]` optional-dependency
group; the ML-DSA module imports `mldsa` lazily and a helper probes real capability
(import + a throwaway `generate`) so a missing/old OpenSSL fails **closed with a typed
error**, not an opaque stack trace. No new *runtime* dependency for anyone who does
not opt in.

### D3 — `AKP` key parsing: a new `MLDSASigningKey`, dispatch on `(kty="AKP", alg)`
`AKP` carries the parameter set in `alg`, not `crv`, so `signing_key_from_jwk` gains
an `AKP` branch that keys on `alg ∈ {ML-DSA-44, ML-DSA-65, ML-DSA-87}`, reading `pub`
and (for signing) the 32-byte `priv` seed via `from_seed_bytes`. A new
`MLDSASigningKey` implements the **existing** `SigningKey` protocol unchanged: `alg`,
`kid`, and `sign(signing_input) -> bytes` returning the raw ML-DSA signature. There is
**no R‖S transform** — unlike ES256/384, the `cryptography` ML-DSA signature is
already the JOSE-wire form, so `sign` is a straight pass-through.

### D4 — Verify through `keys.verify_signature`, not PyJWT
PyJWT has no ML-DSA `Algorithm`; teaching it one would only wrap `cryptography`
anyway, and would couple us to PyJWT internals for a lattice scheme. → Extend the
dependency-light `keys.verify_signature` with `ML-DSA-*` branches (load `pub` via
`from_public_bytes`, call `verify`). The VC-JWT suite routes an ML-DSA token's
**signature check** through this primitive (claims/temporal validation still reuse the
JWT logic), keeping one verify primitive and no PyJWT-internal coupling. `sd_jwt` /
`vp_jwt` inherit it for free, since they already lean on `verify_signature`.

### D5 — Allow-list stays fail-closed: a separate PQ set, merged only when opted in
Add `ALLOWED_ALGS_PQ = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})`. The
effective allow-list is `ALLOWED_ALGS | ALLOWED_ALGS_PQ` **only** when the caller
opts in (per-call or per-suite flag). The alg-confusion defence is unchanged for
everyone else — the allow-list check still runs before crypto, and `alg: none` / RS*
/ HS* stay rejected. Opting in never *widens* to the classic weak algs; it adds only
the three ML-DSA names.

### D6 — HSM story via external-mu; keep an in-process backend for dev/tests
The `SigningKey` contract already fits (raw-bytes `sign`), so nothing in the protocol
changes. Document that a Vault/PKCS#11 backend uses **`sign_mu`** (external-mu) so the
message never reaches the HSM in the clear — the same "private key never enters the
process" posture as the EC/Ed backends. The software `MLDSASigningKey` is for dev,
tests, and low-assurance issuance, exactly like `Ed25519SigningKey` / `P256SigningKey`.

### D7 — Prefer `did:jwk`; gate `did:key` ML-DSA behind the experimental flag
`did:jwk` needs **no** change — it decodes any JWK, so an `AKP` public JWK resolves
once D3's loader lands. Recommend `did:jwk` as the encoding for the experimental
phase. `did:key` ML-DSA requires multicodec code points that are still **draft** in
the multicodec table; add them only under the experimental opt-in and document that
the identifier may change if the assignments are revised. This keeps a stable-URI
promise from being made on an unstable table.

### D8 — Data Integrity PQ suites stay OUT
`ALG_PROFILE` (the DI curve→alg map) is **untouched**; ML-DSA is **JOSE-only**
(VC-JWT + SD-JWT VC), matching the issue scope. W3C's quantum-resistant DI
cryptosuites are FPWD/experimental — revisit under the same documented-gate discipline
as BBS ([#73](https://github.com/luisgf/openvc/issues/73)) when they reach a stable
draft.

### D9 — No hybrid/composite signatures yet — watch, don't build
`draft-ietf-jose-pq-composite-sigs` (an ML-DSA + EC composite `alg`) is early and
moving. A pure ML-DSA credential is **not** a hybrid. For a conservative migration,
the application layer can dual-sign (attach an ES256 proof *and* an ML-DSA proof) with
no library change — two independent proofs, each verifiable on its own — rather than a
composite alg openvc would have to model. Track the draft; do not implement composite
until it stabilises.

### D10 — Label everything ML-DSA "experimental — not a production trust path"
Concretely: opt-in import/flag (D1/D5), an `experimental` marker in the docstrings and
the CHANGELOG entry, **no** default allow-listing, and **no** golden-fixture
conformance claim (there are no stable third-party ML-DSA VC vectors to pin — the
drift alarm cannot cover it yet, which is *why* it is experimental). It is a
forward-compatibility rail, not a supported suite, until RFC 9964 gains interop
vectors and the surrounding specs mature.

## Consequences

- **Size.** ML-DSA-65 signatures are **3309 B** and public keys **1952 B**, vs 64 B /
  ~33 B for ES256 — one to two orders of magnitude. VC-JWT and especially SD-JWT VC
  payloads (and any QR transport) grow accordingly; a caveat for the docs, not a
  blocker.
- **Dependency-light preserved.** ML-DSA lives behind the `[pq]` extra + a runtime
  guard; the core install is unchanged (`cryptography>=45` + `pyjwt`).
- **No conformance pin yet.** The golden-fixture drift alarm does not cover ML-DSA
  until stable vectors exist — an explicit, documented gap consistent with the
  experimental label.
- **One verify primitive.** Routing through `keys.verify_signature` (D4) keeps the PQ
  path off PyJWT internals and reuses the curve/alg-pinning discipline already there.

## Follow-ups (re-evaluate the experimental label when…)

- **#72** implements this ADR (experimental opt-in: `[pq]` extra, `AKP` loader,
  `MLDSASigningKey`, verify branches, opt-in allow-list).
- RFC 9964 gains published interop test vectors (→ a golden fixture, → drop
  "experimental").
- The multicodec ML-DSA code points are finalised (→ stable `did:key`).
- W3C quantum-resistant DI cryptosuites advance past FPWD (→ reconsider D8).
- `draft-ietf-jose-pq-composite-sigs` stabilises (→ reconsider D9).

## Reproduce

```bash
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric import mldsa
sk = mldsa.MLDSA65PrivateKey.generate()
sig = sk.sign(b"hello ML-DSA")
sk.public_key().verify(sig, b"hello ML-DSA")          # raises on failure
print("sig", len(sig), "pub",
      len(sk.public_key().public_bytes_raw()),
      "seed", len(sk.private_bytes_raw()))             # 3309 1952 32
print("external-mu:", hasattr(sk, "sign_mu"))          # True (HSM path)
PY
```
