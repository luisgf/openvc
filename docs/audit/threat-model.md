# openvc — threat model (auditor annex)

> **Scope note.** This is the **code-cited annex** to the user-facing
> [Security model](https://github.com/luisgf/openvc/wiki/Security-Model). That
> wiki page is the integrator's summary; this document adds `path:line`
> citations, the per-suite and per-parser attack-surface tables, the fail-closed
> **invariants catalog**, and an honest **residual-risk register** — the
> material an external reviewer starts from. Line numbers are anchors **as of
> v1.20.1**; treat them as entry points, not guarantees, and re-anchor against
> the reviewed commit.

Part of the external-audit pack ([README](README.md)) for
[#75](https://github.com/luisgf/openvc/issues/75).

---

## 1. The one property

openvc is a **verifier core**. The single security property everything else
serves is:

> **No wrong-accept** — a forged, tampered, expired, revoked, mis-issued, or
> replayed credential must never be returned as accepted.

Every design choice below is a fail-closed default in service of that property:
ambiguity, an unresolvable key, a malformed timestamp, an unrecognised status
shape, or a missing opted-in resolver **rejects** rather than accepts. The
pipeline signals a decision only by **returning** a `VerificationResult`; every
failure path **raises** a typed `OpenvcError` subclass
(`src/openvc/verify.py:320-322`) — there is no "accepted-anyway" return value.

## 2. Assets

| Asset | Why it matters | Primary protection |
|---|---|---|
| **The verification decision** | A wrong-accept is the whole harm | The fail-closed pipeline (§4, §8) |
| **Signing keys** | Private key material | Never in-process on the signing path — the `SigningKey` protocol (`src/openvc/proof/vc_jwt.py:75-92`) keeps material in an HSM/Vault/KMS |
| **Trust anchors** | The roots a verifier trusts (x5c anchors, EBSI RootTAO, resolved DID docs) | Anchor *compromise* is out of scope (operator's root of trust); openvc must never *widen* an anchor |

## 3. Trust boundaries

Untrusted input crosses into openvc at four boundaries. Every field beyond each
boundary is attacker-controlled until a signature verifies.

1. **The credential** — fully attacker-controlled bytes (a JWS/SD-JWT string, a
   JSON-LD document, a CBOR `DeviceResponse`). Parsed by the hand-rolled codecs
   in §6 *before* any signature is checked.
2. **Network dereferences** — `did:web`, `/.well-known/jwt-vc-issuer`,
   status-list and `credentialSchema` URLs. The *issuer* names these URLs and,
   for status/schema, controls the returned bytes. See §7.
3. **The `SigningKey` / `KeyAgreementKey` backend** — an out-of-process boundary
   (HSM/Vault/KMS). openvc trusts it to sign/decrypt, never to hold key material
   for it.
4. **Injected resolvers** — `resolver`, `resolve_status_list*`,
   `resolve_credential_schema`, `*_fetch`. openvc's guarantees hold only for what
   these return; a custom resolver that skips verification or the SSRF guard
   opts out of the corresponding control (`src/openvc/verify.py:304-307`). The
   blessed defaults in `openvc.resolvers` keep the guard on.

## 4. Attacker model → capability → control

| Capability | Threat | Control (with citation) |
|---|---|---|
| Present a forged / tampered credential | Wrong-accept | Signature verified through the matching suite; the `{ES256, ES384, EdDSA, Ed25519}` allow-list runs **before any crypto** — `src/openvc/proof/vc_jwt.py:55,198`, `src/openvc/proof/_jws.py:84` (rejects `alg:none`, RS\*, HS\* by exclusion → alg-confusion defence). ES256 must be raw R‖S 64 bytes, never DER — `src/openvc/keys.py:493` |
| Name issuer A but sign with key B | Impersonation | **Issuer binding**: a DI proof's `verificationMethod` must be controlled by the credential `issuer` DID — `src/openvc/verify.py:628-641`; VC-JWT reconciles the JWT envelope (`iss`/`sub`/`jti`) with the embedded `vc` — `src/openvc/proof/vc_jwt.py:360-381`; x5c binds the leaf SAN to `iss` — `src/openvc/x5c.py:56-70` |
| Serve a malicious document at a fetched URL | **SSRF** (internal hosts / cloud metadata) | `src/openvc/fetch.py`: https-only (`:126`), blocks private/loopback/link-local/reserved/multicast/unspecified (`:49-55`), rejects the host if **any** resolved address is forbidden (`:58-72`), refuses redirects (`:143-144`), and **pins the socket to the validated IP** (`:75-92`) closing DNS-rebinding |
| Ship a tiny highly-compressible status list | **Decompression bomb** (OOM DoS) | Status decode caps the *decompressed* output at 16 MiB and reads incrementally so a bomb is never materialised — `src/openvc/status/_decompress.py:23,38-40,54-66` |
| Swap / replay a status list or presentation | Stale-status / replay accept | Status token `sub` must equal the fetched URI (anti-swap) — `src/openvc/resolvers.py:122-123`; presentations bind `aud` + one-time `nonce`/`challenge`; a fetched status list is **verified before trust** — `src/openvc/resolvers.py:92-98`; optional status-issuer binding (ADR-0006) — `src/openvc/verify.py:654-669` |
| Back/post-date validity | Expired / not-yet-valid accept | Temporal checks on `validFrom`/`validUntil`/`expires` (+ VCDM 1.1 aliases) — `src/openvc/proof/_verify_common.py:90-125`; a **present-but-unparseable** timestamp fails **closed** — `:84-85`; non-finite `exp`/`nbf` rejected — `:175-182` |
| Feed hostile bytes to a hand-rolled parser | Uncaught crash / DoS / parser confusion | Depth-bounded, typed-error codecs — see §6 |
| Deeply nest the trust-list XML | XXE / entity-expansion bomb | The LOTL/TL parser refuses any DOCTYPE outright — `src/openvc/trustlist/parse.py:108-120` — which is what entities and expansion bombs require; 16 MiB + 500k-element caps — `:35-36,100-117` |
| MITM a fetch | Tamper in transit | TLS with certificate validation and SNI on the pinned connection — `src/openvc/fetch.py:79-92` |

## 5. Attack surface by proof suite

- **VC-JWT (JOSE)** — `src/openvc/proof/vc_jwt.py`. Allow-list gate at `:198`
  precedes key load (`:206`) and decode (`:208`); alg pinned to the resolved
  key's `(kty, crv)` (`:341-351`) blocking cross-curve/OKP confusion; envelope↔
  `vc` reconciliation (`:360-381`); temporal defence-in-depth on the body
  (`:237`). ML-DSA (RFC 9964) is **opt-in only** (`allow_pq=True`, `:135`),
  never in the default allow-list.
- **SD-JWT VC** — `src/openvc/proof/sd_jwt.py`. Allow-list before crypto for the
  issuer JWT (`:331-332`) and KB-JWT (`:464-465`); duplicate/unreferenced
  disclosures rejected (`:349-352,431`); claim-overwrite blocked (`:143`);
  key-binding-required-without-`aud`/`nonce` fails closed (`:447-455`). See
  **R1** in §9 for the recursion caveat.
- **Data Integrity** — `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` (RDF-canonical),
  `eddsa-jcs-2022` / `ecdsa-jcs-2019` (JCS), and selective-disclosure
  `ecdsa-sd-2023`. `verificationMethod`↔`issuer` binding (`src/openvc/verify.py:628-641`);
  cryptosuite chosen from the resolved key, never a proof field
  (`src/openvc/proof/_verify_common.py:289-303`); validity window + `proofPurpose`
  enforced (`src/openvc/proof/data_integrity.py:227`). The JCS suites and
  `ecdsa-sd` decode attacker CBOR/JSON — see §6.
- **ISO mdoc (`mso_mdoc`)** — `src/openvc/mdoc.py`, **experimental** (ADR-0005).
  IssuerAuth `COSE_Sign1` + `x5chain`→IACA + `valueDigests`, DeviceAuth over the
  Digital Credentials API SessionTranscript. Constant-time digest compare
  (`:377`); DS EKU / IACA profile enforced. All structure delegates to the CBOR
  codec (§6).
- **JWE (HAIP encrypted response)** — `src/openvc/jwe.py`, decrypt-only.
  `alg`∈`{ECDH-ES}` and `enc`∈`{A128GCM, A256GCM}` allow-listed before crypto
  (`:41-42,122-126`); `zip` rejected → no JWE zip bombs (`:127-128`); `crit`
  rejected (`:129-130`); ephemeral key pinned to P-256 (`src/openvc/keys.py:321-322`);
  2 MiB cap (`:47`).

## 6. Attack surface by hand-rolled parser (attacker-controlled bytes)

The dependency-light posture means openvc hand-rolls the codecs that face
attacker bytes. Each must be **depth/size-bounded** and **fail closed with a
typed error**. "Implicit only" = bounded by "each element consumes ≥1 byte of
finite input", with no explicit constant.

| Parser | Input | Explicit bound | Fail-closed error | Anchor |
|---|---|---|---|---|
| CBOR decoder | mdoc `DeviceResponse`, COSE headers, ecdsa-sd proofValue | Depth **64**; **no** element-count/total-size cap (implicit only) | `CborError` (typed); dup-map-key & trailing-byte rejected | `src/openvc/cbor.py:69,196-197,229-232,261-262` |
| COSE_Sign1/Mac0 | mdoc IssuerAuth/DeviceAuth | Inherits CBOR depth 64; alg allow-list `{-7,-35,-8,5}` before crypto | `CoseError` family; constant-time MAC compare | `src/openvc/cose.py:57-58,238-242,264` |
| mdoc `DeviceResponse` | OpenID4VP `vp_token` | Inherits CBOR; **depth counter resets at each embedded `#6.24`** (R3) | `MdocError` family; CBOR errors re-wrapped | `src/openvc/mdoc.py:307,315,365,377` |
| multibase / base58 / varint | `publicKeyMultibase`, `proofValue` | base58 **≤4096**; varint **≤9 bytes** | `MultibaseError` (typed) | `src/openvc/multibase.py:18,21,30-31,73-74` |
| JCS canonicalizer (RFC 8785) | JCS DI unsecured doc + proofConfig | Depth **100**; IEEE-754 range enforced; NaN/Inf rejected | `JcsError` — **not** an `OpenvcError` (R2) | `src/openvc/proof/_jcs.py:18,27,148-149` |
| SD-JWT `_unpack` / JWS decode | Holder presentation | Depth **100**; `RecursionError` mapped to typed (v1.20.1, was R1) | `SdJwtError`/`MalformedToken` (typed) | `src/openvc/proof/sd_jwt.py:66,121,397` |
| ecdsa-sd proofValue | DI selective-disclosure proof | Reuses CBOR (depth 64) + strict 5-element subset gate | `ProofValueMalformed` (typed) | `src/openvc/proof/ecdsa_sd.py:45,103-121,139-141` |
| Bitstring status | Resolved status VC `encodedList` | Delegates 16 MiB decompress cap; index bounds-checked | `StatusListError` (typed) | `src/openvc/status/bitstring.py:38,43-50` |
| Decompress (gzip/zlib) | Issuer status bytes (**not** covered by the 1 MiB fetch cap) | **16 MiB**, incremental | `DecompressionBomb` — **not** an `OpenvcError`, re-wrapped at call sites (R2) | `src/openvc/status/_decompress.py:23,28,38-66` |
| LOTL/TL XML | EU trusted-list bytes (pre-signature) | **DOCTYPE refused** (blocks XXE + expansion); 16 MiB + 500k elements | `TrustListParseError` (typed) | `src/openvc/trustlist/parse.py:22,108-120,100-117` |
| XAdES signature XML | Signed trusted-list | 16 MiB; XAdES-BASELINE-B alg profile; XSW subtree guard | `XadesError` family; hardened lxml on the reparse (R6) | `src/openvc/trustlist/xades.py:71-81,97-98,115-127` |

## 7. Network & SSRF surface

- **`fetch.py`** (the general guarded https fetch, used by `did:web` and the
  blessed resolvers): https-only; blocks private/loopback/link-local/reserved/
  multicast/unspecified; rejects the host if *any* resolved address is forbidden;
  refuses redirects; **pins the socket to the validated IP** (DNS-rebinding
  TOCTOU closed); 1 MiB response cap + wall-clock read deadline; query strings
  never logged. `src/openvc/fetch.py:41-148`. See **R5**.
- **`resolvers.py`** blessed defaults route through `fetch.py`; the two
  status-list resolvers additionally **verify the fetched artifact before
  trusting it** and enforce the anti-swap `sub == uri`. A **caller-injected**
  resolver opts out of the guard — documented, and the reason the secure path is
  the opt-in default (`src/openvc/resolvers.py:4-17`).
- **EBSI client** (`src/openvc_ebsi/http.py`): an https-only **host allow-list**
  (`api-pilot`/`api-conformance`/`api.ebsi.eu`), redirects off, TLS-verify on,
  5 MiB cap. Purpose is to block registry-supplied `href` pivots; it is a
  host-name allow-list and does **not** IP-pin (R4). `did:web` must **never** be
  resolved through it (its allow-list would reject every legitimate host).

## 8. Fail-closed invariants catalog

The invariants an auditor should try hardest to break. Each is enforced at the
cited line and pinned by a regression test — the golden fixtures and the
negative corpus are the drift alarm (see [assurance.md](assurance.md)).

| # | Invariant | Enforced at | Pinned by |
|---|---|---|---|
| I1 | Alg allow-list `{ES256, ES384, EdDSA, Ed25519}` runs **before any crypto**; `alg:none`/RS\*/HS\* rejected | `proof/vc_jwt.py:55,198`; `proof/_jws.py:84` | `test_hostile_input.py`, `test_cose.py:94` |
| I2 | ES256/384 JOSE signature is raw R‖S (64/96 bytes), never DER | `keys.py:493,506-507` | `test_vc_jwt.py` |
| I3 | PQ (ML-DSA) never in the default allow-list — opt-in only | `proof/vc_jwt.py:135` | `test_mldsa.py` |
| I4 | DI `verificationMethod` bound to the credential `issuer` DID | `verify.py:628-641` | `test_di_*` |
| I5 | VC-JWT envelope reconciled with the embedded `vc` (`iss`/`sub`/`jti`) | `proof/vc_jwt.py:360-381` | `test_vc_jwt.py` |
| I6 | x5c leaf SAN bound to `iss`; binding after path-validation | `x5c.py:56-70,151-154` | `test_x5c*`, `test_sd_jwt.py:425` |
| I7 | Present-but-unparseable timestamp fails **closed** | `proof/_verify_common.py:84-85` | `test_di_jcs.py`, `test_sd_jwt.py:333` |
| I8 | `require_status=True` by default; declared-but-unresolvable status rejects | `verify.py:147,781-787` | `test_status.py` |
| I9 | Signing goes through the `SigningKey` protocol — no private key in-process | `proof/vc_jwt.py:75-92`; `proof/_jws.py:53` | `test_keys*` |
| I10 | SSRF guard: https-only, forbidden-range block, redirect refusal, IP-pin | `fetch.py:49-92,126,143-144` | `test_fetch*` |
| I11 | Status decompression bounded at 16 MiB, incremental | `status/_decompress.py:23,38-66` | `test_status_decompress.py:46-82` |
| I12 | CBOR depth ≤ 64; JCS depth ≤ 100; duplicate map key rejected | `cbor.py:69,229-232`; `proof/_jcs.py:18` | `test_cbor.py:104,152`; `test_di_jcs.py:388` |
| I13 | Trust-list XML refuses DOCTYPE (XXE + expansion closed) | `trustlist/parse.py:108-120` | `test_trustlist.py:104,121` |
| I14 | Every internal failure subclasses `OpenvcError` and re-raises typed | `verify.py:105-123,320-322` | `test_hostile_input.py` |
| I15 | `verify_many` isolates per-credential — one bad item never aborts the batch | `verify.py:458-465` | `test_hostile_input.py:79-85` |
| I16 | Hostile deeply-nested input fails closed **pipeline-wide** — every attacker-facing recursive parse is depth-bounded or maps `RecursionError` to a typed error (the `json.loads` sites, SD-JWT `_unpack`=100, did:webvh SCID walk=100) | `proof/sd_jwt.py:66,129`; `verify.py`, `proof/vc_jwt.py`, `proof/_jws.py`, `jwe.py`, `did/did_jwk.py`, `did/did_webvh.py`, `fetch.py`, `resolvers.py` | `test_hostile_input.py`, `test_did_webvh.py` |

## 9. Residual risks & known limitations

The honest register. None is a wrong-accept (I1–I7 hold); the open items are
**availability / typed-error-hygiene** hardening and documented caveats — the
"harden next" list an external reviewer should weigh. Ranked by our assessment;
items marked **✅ Resolved** have since been fixed and stay here as an audit trail.

- **R1 — SD-JWT `_unpack` / `json.loads` nesting bound. ✅ Resolved in v1.20.1
  ([#117](https://github.com/luisgf/openvc/issues/117)).** `_unpack`
  (`src/openvc/proof/sd_jwt.py:121`) recursed with no depth parameter, and
  `_decode_jws`/`_index_disclosures` caught only `(ValueError, json.JSONDecodeError)`.
  Hostile deeply-nested JSON — or a **chain** of disclosures (each disclosing an object
  carrying the next `_sd` digest, individually shallow) — made `json.loads` (and
  `_unpack`) raise `RecursionError`, which is **not** an `OpenvcError`. Because
  `verify_many` isolates items with `except OpenvcError` (`src/openvc/verify.py:464`),
  that uncaught `RecursionError` escaped per-credential isolation and **aborted the whole
  batch** (DoS; no wrong-accept). **Fixed:** `_unpack` now caps depth at 100
  (`sd_jwt.py:66,129`) and the `json.loads` sites map `RecursionError` to a typed error
  (`sd_jwt.py:397,439`) — invariant **I16**, pinned by `test_hostile_input.py`.
  Adversarial review then found the identical batch-abort at the **sibling** `json.loads`
  sites — VC-JWT peek/verify, the enveloped-VC unwrap (`verify.py`), `_jws`, `jwe`, and the
  DID / fetch / resolver paths; all now map `RecursionError` to a typed error too, so
  `verify_many` isolation and invariant I14 hold across **all** credential formats.
- **R2 — Two typed errors escape the `OpenvcError` hierarchy.**
  `JcsError(Exception)` (`src/openvc/proof/_jcs.py:27`) and
  `DecompressionBomb(Exception)` (`src/openvc/status/_decompress.py:28`) do not
  subclass `OpenvcError`. Both are re-wrapped by their in-tree callers, so the
  module *boundary* is typed — but a downstream caller of `_jcs.canonicalize` /
  the decompress helpers directly would not catch them via `except OpenvcError`,
  weakening invariant I14 at the sub-module level. *Fix:* rebase both on
  `OpenvcError`.
- **R3 — CBOR has no explicit collection-count/total-size cap; depth resets at
  embedded-CBOR boundaries.** `src/openvc/cbor.py` bounds nesting depth (64) but
  array/map element counts only implicitly. `mdoc` decodes embedded `#6.24`
  blobs with fresh `cbor.decode` calls (`src/openvc/mdoc.py:307,315,365`), so the
  64-frame budget resets at each boundary. Finite input length is the only hard
  bound. *Impact:* CPU/allocation pressure under a large but well-formed
  document; no wrong-accept. *Consider:* an explicit element-count and/or
  cumulative-size cap.
- **R4 — EBSI client is a host-name allow-list, no IP-pin.**
  `src/openvc_ebsi/http.py` trusts DNS for allow-listed EBSI hosts and does not
  pin to a validated IP (unlike `fetch.py`). DNS-rebinding of an allow-listed
  host is out of scope of this guard *by design* (its job is blocking
  registry-supplied `href` pivots), but a reviewer should confirm the threat
  model accepts that.
- **R5 — `fetch.py` leans on stdlib `ipaddress` classification.** No explicit
  IPv4-mapped-IPv6 (`::ffff:a.b.c.d`) / NAT64 normalization beyond what
  `ipaddress` classifies on the target Python. Worth an auditor sanity-check
  across the supported interpreter range.
- **R6 — XAdES primary verify relies on `signxml`/`lxml` DTD-forbidding.**
  openvc sets `resolve_entities=False, no_network=True, load_dtd=False`
  explicitly only on its defence-in-depth whole-document reparse
  (`src/openvc/trustlist/xades.py:97-98`); the signature verification itself is
  delegated to `signxml` and inherits its (DTD-forbidding) defaults. The `[trustlist]`
  extra's `signxml`/`lxml` versions are part of the trust base.
- **R7 — Selective-disclosure status/schema withholding.** For SD-JWT VC and
  `ecdsa-sd-2023`, a holder can withhold `credentialStatus`/`credentialSchema`,
  so the fail-closed status gate cannot fire (`src/openvc/verify.py:30-35,517-518`).
  Documented caveat: issuers must make those pointers **mandatory /
  non-disclosable**.
- **R8 — `credentialSchema` pattern-ReDoS.** Schema validation is opt-in and
  remote `$ref` is off; a catastrophic `pattern` in a trusted schema is a
  residual CPU-DoS. Point the schema resolver at trusted hosts.

## 10. Out of scope

- Compromise of a trusted anchor, of the host, or of the `SigningKey` backend.
- Availability of remote issuers / status lists (openvc bounds *its own*
  resource use, not third-party reachability).
- Anything an **injected** resolver does after openvc hands it a URL, if the
  caller supplies a custom one instead of the guarded default.
- Side-channels in the underlying `cryptography` / `pyjwt` primitives.
- EBSI **write/onboarding**; OpenID4VP **request generation / session state**;
  ISO mdoc **issuance / proximity / COSE signing** — all out of scope by design
  (see [ROADMAP](https://github.com/luisgf/openvc/blob/main/docs/ROADMAP.md)).
