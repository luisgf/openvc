# openvc — assurance evidence (fuzz corpora + review history)

Part of the external-audit pack ([README](README.md)) for
[#75](https://github.com/luisgf/openvc/issues/75). Companion to the
[threat model](threat-model.md). Anchors as of **v1.20.0 (`d378b99`)**.

This document is the "show your work" half of the pack: what randomized and
negative testing already exists, where it does **not** yet reach, and the
adversarial-review history that produced the current controls.

---

## 1. Property-based fuzzing

The primary harness is `tests/test_fuzz_codecs.py`, **Hypothesis**
property-based. Its contract (two properties per codec):

1. `decode(encode(x)) == x` — round-trip.
2. `decode(arbitrary_bytes)` raises **only the module's typed `OpenvcError`**,
   never a bare `ValueError` / `IndexError` / `struct.error` / `UnicodeDecodeError`.

`tests/test_cbor.py:144-145` adds a second `@given(st.binary)` never-crash
harness directly on the shared CBOR decoder.

**Property-fuzzed codecs** (the low-level byte parsers):

| Codec | Entry points | Anchor |
|---|---|---|
| CBOR (via ecdsa-sd subset + core) | `decode_cbor`/`encode_cbor`, `openvc.cbor.decode` | `test_fuzz_codecs.py:50-62`; `test_cbor.py:144` |
| base58btc | `b58btc_encode`/`b58btc_decode` | `test_fuzz_codecs.py:66-68` |
| multibase | `encode_multibase`/`decode_multibase` | `test_fuzz_codecs.py:71-83` |
| LEB128 varint | `read_varint` | `test_fuzz_codecs.py:86-92` |
| bitstring status (MSB-first) | `encode_bitstring`/`decode_bitstring` | `test_fuzz_codecs.py:95-114` |
| token status list (LSB-first) | `encode_status_list`/`decode_status_list` | `test_fuzz_codecs.py:101-152` |

Plus two inline **MUST-REJECT corpora** (`test_fuzz_codecs.py:117-152`) —
regression cases the fuzzers found (bad-UTF8 CBOR, map-as-key, truncated
strings, trailing byte, bad head, bool; no-base multibase, bad-b58, garbage) —
each asserted to raise the module's typed error. There is no external seeded
corpus directory; "corpus" = these parametrized lists.

## 2. Coverage map — the "harden next" list

"Property-fuzz" = a Hypothesis `@given` arbitrary-input harness. Only the
low-level byte codecs have one; every **structural / higher-level** attacker-
facing parser is currently guarded by **example-based negative tests only**.

| Parser | Property-fuzz | Negative/example tests | Verdict |
|---|---|---|---|
| `cbor` | ✅ | ✅ (`test_cbor.py`) | Strong |
| `multibase`/base58/varint | ✅ | ✅ | Strong |
| `ecdsa_sd` CBOR | ✅ | ✅ (`test_ecdsa_sd.py`) | Strong |
| `status/bitstring` + `token_status_list` | ✅ | ✅ + bomb tests | Strong |
| `status/_decompress` | ❌ | ✅ bomb + exact-cap boundary (`test_status_decompress.py:46-82`) | Gap: no property-fuzz |
| `proof/_jcs` | ❌ | ✅ depth/non-finite/surrogate (`test_di_jcs.py:388,415`) | **Gap** |
| `cose` | ❌ | ✅ rich (`test_cose.py:72-212`) | **Gap** |
| `mdoc` | ❌ | ✅ rich, parametrized malformed (`test_mdoc.py:365`) | **Gap** |
| `proof/sd_jwt` | ✅ (`test_hostile_input.py`) | ✅ rich (`test_sd_jwt.py`) + nesting/recursion | Strong |
| `jwe` | ❌ | ✅ rich (`test_jwe.py:167-294`) | **Gap** |
| `trustlist/parse` (XML) | ❌ | ✅ XXE/entity-bomb/oversize (`test_trustlist.py:104-144`) | **Gap** |
| `trustlist/xades` (XML) | ❌ | ✅ DTD/tamper/forged (`test_trustlist_xades.py:123-229`) | **Gap** |

**Highest-value property-fuzz targets:** `cose`, `mdoc`, `jwe`, and the two XML
parsers — they consume the most complex attacker-controlled structure and
currently have zero randomized coverage. (`sd_jwt` shared this gap until v1.20.1,
when its recursion/nesting harness landed alongside the **R1** fix.)

## 3. Negative / tamper coverage by suite

Example-based, but broad. Representative anchors:

- **VC-JWT / hostile input** — non-object header/payload, non-string `iss`,
  batch-isolation of a hostile item (`test_hostile_input.py:51-85`).
- **SD-JWT** — unreferenced/forged/duplicate disclosure, wrong key, expired,
  `vct` mismatch, KB `aud`/`nonce`/`sd_hash` tamper, non-numeric `exp`/`nbf`
  (`test_sd_jwt.py:118-333`).
- **Data Integrity** — published W3C eddsa/ecdsa vectors are tamper-evident,
  cross-curve/wrong-key/wrong-cryptosuite fail-closed, RFC 8785 non-finite
  rejection, canonicalize depth guard (`test_di_jcs.py:190-426`).
- **ecdsa-sd** — CBOR bool/negative/trailing/non-P256/wrong-header, tampered &
  over-disclosed values, unknown `@context` → typed (`test_ecdsa_sd*`).
- **mdoc** — tampered item/digest/`issuerAuth`, malformed & non-CBOR response,
  expired MSO, untrusted IACA, DS without EKU, device-MAC/transcript mismatch,
  wrong-origin `vp_token` (`test_mdoc.py:77-450`).
- **COSE** — wrong key, tampered payload, non-allow-listed alg before crypto,
  detached/attached conflict, missing alg, `crit` labels (`test_cose.py:72-212`).
- **JWE** — tampered ciphertext, non-ECDH-ES alg, disallowed `enc`, `zip`/`crit`
  rejected, bad `epk`/IV, oversize (`test_jwe.py:167-294`).
- **Status** — bad encoded list, hostile `type`, value overflow, compression
  bombs at the cap boundary (`test_status*`, `test_status_decompress.py`).
- **Trust / XML** — wrong cert, tampered body, DTD/DOCTYPE entity bomb, external-
  entity XXE, oversize, forged national TL (`test_trustlist*`).

## 4. Adversarial-review history

openvc lands security work through its own PRs with adversarial review; the two
most recent waves (both 2026-07-10) are the deepest. History by theme, most
recent first (`git log`, short hashes).

**Recent hardening waves (milestones #9–#10)**
- `90404f9` — depth wave: mdoc DS/IACA profile, status-issuer binding, XAdES &
  async hardening (#112) · 24 files / +773
- `f4a02cf` — correctness & fail-closed wave: typed-error boundary, codec
  strictness, resource limits (#111) · 36 files / +930
- `eb0adc5` — deterministic signature-tamper regressions in schema/aio

**Typed-error / fail-closed boundary**
- `#117` — fail closed on hostile deeply-nested JSON pipeline-wide: SD-JWT `_unpack` depth bound + `RecursionError` mapped typed at every attacker-facing `json.loads` (v1.20.1); closes audit R1
- `291f79d` — library-wide `OpenvcError` root (one catchable root)
- `b4e335e` — unify proof error taxonomy + rename ecdsa_sd codecs
- `a5d6796` — fail closed on a non-numeric SD-JWT `exp`/`nbf`

**Codec depth & strictness**
- `90404f9` — CBOR/JCS nesting depth caps (`_MAX_DEPTH` 64/100), codec strictness
- `189b001` — fail closed on a deeply-nested schema (#39)
- `16e3b3c` — single-source the ECDSA DI alg profile (removes codec drift)

**Fuzzing / tamper corpus**
- `26f3f63` — fail closed on hostile ecdsa-sd CBOR, *found by new fuzzing* (#41)
  — the origin of `test_fuzz_codecs.py`

**Decompression bomb**
- `d57a749` — bound status-list decompression against compression bombs (#29)

**SSRF / network**
- `f9aab0e` — SSRF-guarded default resolvers for status + schema (#30)
- `393f445` — SSRF-guarded `did:web` fetch + `verify_ebsi_badge` glue

**JOSE / alg allow-list**
- `19ca53c` — accept the RFC 9864 fully-specified `Ed25519` alg name (#59)
- `772d1c6` — P-384 signing (ES384) + P-384 `ecdsa-jcs-2019` (#22)
- `26e01d0` — correct the ADR JOSE allow-list wording (add ES384/Ed25519) (#83)

**Schema integrity**
- `f1d69e8` — enforce `credentialSchema` `digestSRI` (#38)
- `42e3ec9` — validate `credentialSchema` (W3C VC JSON Schema)

**Presentation / replay / holder binding**
- `a09f964` — harden VP-JWT verification (replay + holder binding)
- `886db1f` — challenge/domain presentation binding for Data Integrity
- `ee1ecac` — enforce Data Integrity validity window and `proofPurpose`

**X.509 / trust anchoring**
- `82b3867` — X.509 `x5c` issuer trust for JOSE credentials
- `b933460` — emit `x5c` header on SD-JWT VC issuance to anchor the issuer (#94)
- `f18d222` — parse + validate EUDI relying-party access certs / WRPAC (#88)

**XAdES / EU Trusted List**
- `8884dc8` — consume EU Trusted Lists as an X.509 anchor source (#26)
- `0a8602a` — reference XAdES verifier behind the `[trustlist]` extra (#26)
- `90404f9` — XAdES DTD/oversize hardening

**mdoc / ISO 18013-5**
- `3e6866d` — verify ISO 18013-5 `mso_mdoc` DeviceResponse (#86)
- `90404f9` — mdoc DS EKU + IACA profile enforcement

**Threat-model docs**
- `9554ae7` — threat model for audit readiness (#35) — later mirrored into the
  wiki as [Security-Model](https://github.com/luisgf/openvc/wiki/Security-Model)
  by the wiki-as-code move (`9b7c459`, #56); this pack is its code-cited successor.

## 5. Dependency advisory reachability — PyJWT 2.13.0 batch (audited 2026-07-18)

PyJWT 2.13.0 (2026-05-21) is a security release. openvc's entire PyJWT surface is
one module — `openvc.proof.vc_jwt`: `_JWT.decode` with `algorithms=[alg]` pinned to
the single, already allow-listed header alg; keys converted to `cryptography`
objects by `openvc.keys` (never `PyJWK`); no `PyJWKClient` — JWKS fetches go through
the SSRF-guarded `openvc.fetch`. The SD-JWT issuer-JWT, KB-JWT and status-list-token
lanes verify through openvc's own JWS code, not PyJWT. Advisory by advisory:

| Advisory | Class | Reachable through openvc? |
|---|---|---|
| GHSA-xgmm-8j9v-c9wx / CVE-2026-48526 | public JWK accepted as HMAC secret | **No** — HS\* is never in the allow-list and `algorithms=` is pinned to one non-HS alg |
| GHSA-jq35-7prp-9v3f / CVE-2026-48523 | allow-list bypass with `PyJWK`/`PyJWKClient` keys | **No** — `PyJWK` objects are never constructed |
| GHSA-993g-76c3-p5m4 / CVE-2026-48522 | `PyJWKClient` SSRF (`file://`, `ftp://`, `data:`) | **No** — `PyJWKClient` unused; JWKS via `openvc.fetch` (https-only, private ranges blocked) |
| GHSA-fhv5-28vv-h8m8 / CVE-2026-48524 | `PyJWKClient` kid-driven request flood | **No** — `PyJWKClient` unused |
| GHSA-752w-5fwx-jx9f / CVE-2026-32597 | unknown `crit` extensions accepted | **Was reachable** — on the VC-JWT lane with PyJWT < 2.13, and **independently on openvc's own JWS lanes** (SD-JWT issuer JWT, KB-JWT, status-list token), which never consulted `crit`. Closed both ways: the `>=2.13` floor **and** the lane-uniform openvc-side rejection (`reject_unknown_crit`), regression-tested per lane in `tests/test_jws_crit.py` |
| GHSA-w7vc-732c-9m39 / CVE-2026-48525 | DoS via unbounded b64 decode of the unused segment of a `b64=false` detached JWS | **Marginally, pre-2.13** — a hostile token reaches `jwt.decode` on the VC-JWT lane (cost ∝ input size; no wrong-accept). Closed by the floor. The hand-rolled lanes fail closed structurally (a `b64=false` token cannot match the signing input) |

Outcome: floor raised to `pyjwt>=2.13` (defense in depth even where structurally
unreachable) plus the lane-uniform `crit` rejection. `cryptography` 49.0.0
(2026-06-12, stricter X.509 parsing) confirmed compatible: full suite green, and CI
resolves the newest `cryptography` on every run.
