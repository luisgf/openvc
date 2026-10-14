# openvc — threat model (auditor annex)

> **Scope note.** This is the **code-cited annex** to the user-facing
> [Security model](https://github.com/luisgf/openvc/wiki/Security-Model). That
> wiki page is the integrator's summary; this document adds `path:line`
> citations, the per-suite and per-parser attack-surface tables, the fail-closed
> **invariants catalog**, and an honest **residual-risk register** — the
> material an external reviewer starts from. Line numbers are anchors **as of
> v1.24.0** (no v1.24.1 was ever tagged), except rows added with later fixes — I20
> and the context-validation rows among them — which are as of their own release;
> treat them as entry points, not guarantees, and re-anchor against the reviewed
> commit. Entries added by the 2026-10-13 catch-up — the rest of the
> v1.25.0–v1.31.2 hardening, I21, and the evidence added to I5–I18 — cite symbols
> and test names instead of line numbers, so they stay valid as the code moves.

Part of the external-audit pack ([README](README.md)) for
[#75](https://github.com/luisgf/openvc/issues/75).

---

## 1. The one property

openvc is a **verifier core**. The single security property everything else
serves is:

> **No wrong-accept** — a forged, tampered, expired, revoked, mis-issued, or
> replayed credential **or key proof** must never be returned as accepted.

> **Scope note (2026-07-24).** The object widened rather than the property doubling.
> [ADR-0007](../adr/ADR-0007-oid4vci-issuer-side.md) rules an OpenID4VCI **key-proof
> verifier** into scope (`openvc.openid4vci`, shipped in 1.23.0) while keeping the
> protocol layer — nonce stores, endpoints, the AS — out, in the consumer. openvc's
> output is still a verification decision over attacker-controlled bytes, so the same
> fail-closed discipline covers both; the attacker simply arrives from the other side,
> *requesting* a credential rather than presenting one (§8, I17–I18). The
> wrong-*issue* property — never mint a credential bound to a key the requester does
> not control — belongs to whoever mints it, downstream, and with it the atomicity of
> the injected nonce store (§10).

> **Scope note (2026-10-13).** I21 guards an *authorization* decision rather than a
> credential accept: a relying-party registration certificate (WRPRC, ETSI TS 119 475)
> decides what a relying party may request. There the property reads **no
> wrong-authorize** — a request outside the registered grant must never be authorized —
> and it fails closed the same way.

Every design choice below is a fail-closed default in service of that property:
ambiguity, an unresolvable key, a malformed timestamp, an unrecognised status
shape, or a missing opted-in resolver **rejects** rather than accepts. The
pipeline signals a decision only by **returning** a `VerificationResult`; every
failure path **raises** a typed `OpenvcError` subclass
(`src/openvc/verify.py:320-322`) — there is no "accepted-anyway" return value.

## 2. Assets

| Asset | Why it matters | Primary protection |
|---|---|---|
| **The verification decision** | A wrong-accept — or, for a relying-party registration (WRPRC), a wrong-authorize — is the whole harm | The fail-closed pipeline (§4, §8) |
| **Signing keys** | Private key material | Never in-process on the signing path — the `SigningKey` protocol (`src/openvc/proof/vc_jwt.py:75-92`) keeps material in an HSM/Vault/KMS |
| **Trust anchors** | The roots a verifier trusts (x5c anchors, EBSI RootTAO, resolved DID docs) | Anchor *compromise* is out of scope (operator's root of trust); openvc must never *widen* an anchor |

## 3. Trust boundaries

Untrusted input crosses into openvc at five boundaries. Every field beyond each
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
5. **Relying-party certificates and requests** — a WRPRC (JWT or CWT), its WRPAC
   and the DCQL request are attacker-controlled until the registrar's signature
   verifies and I21's cross-checks pass.

## 4. Attacker model → capability → control

| Capability | Threat | Control (with citation) |
|---|---|---|
| Present a forged / tampered credential | Wrong-accept | Signature verified through the matching suite; the `{ES256, ES384, EdDSA, Ed25519}` allow-list runs **before any crypto** — `src/openvc/proof/vc_jwt.py:55,198`, `src/openvc/proof/_jws.py:84` (rejects `alg:none`, RS\*, HS\* by exclusion → alg-confusion defence). ES256 must be raw R‖S 64 bytes, never DER — `src/openvc/keys.py:575-589` |
| Name issuer A but sign with key B | Impersonation | **Issuer binding**: a DI proof's `verificationMethod` must be controlled by the credential `issuer` DID — `src/openvc/verify.py:628-641`; VC-JWT reconciles the JWT envelope (`iss`/`sub`/`jti`) with the embedded `vc` — `src/openvc/proof/vc_jwt.py:360-381`; x5c binds the leaf SAN to `iss` — `src/openvc/x5c.py:56-70`; a W3C `vc+sd-jwt` credential is reconciled the same way, and every identifier a present `issuer` carries must be `iss` — `issuer_identifiers` (#221); an https `iss` that Python and a WHATWG parser read as different hosts is refused before the `/.well-known/jwt-vc-issuer` fetch and never binds an x5c `dNSName` — `_parse_https_issuer` in `jwt_vc_issuer.py` (#236) |
| Re-spell a signed RDF Data Integrity credential's JSON while keeping its signed dataset (IRI-keyed or aliased member, inline `@context` re-mapping a term, undefined term, `@included`) | Wrong-accept: the policy reads JSON the signature does not cover (expiry/status/schema skipped, `credentialSubject` spoofed past holder binding, unsigned claims) | **Context validation** (VC-DI §2.4.1) after the proof verifies and before any policy read — `src/openvc/proof/_context_validation.py:67-80`, called at `src/openvc/proof/data_integrity.py:233`, `src/openvc/proof/di_ecdsa_rdfc.py:205`, `src/openvc/proof/ecdsa_sd.py:683` (and on the signing side). VC base context first, then only loader-served URLs or absolute-IRI `@vocab`-only objects (`:83-100`); the document and proof must equal the compaction of their own expansion (`:109-132`), with no `@included`/`@reverse`/`@index`/`@direction`, no nested re-description of the document node, and nothing the RDF conversion drops — every node id, type and property a well-formed absolute IRI, no blank-node property (`:144-175`) |
| Serve a malicious document at a fetched URL | **SSRF** (internal hosts / cloud metadata) | `src/openvc/fetch.py`: https-only (`:126`), blocks private/loopback/link-local/reserved/multicast/unspecified (`:49-55`) and, since v1.25.0, any other address that is not `is_global` (RFC 6598 CGNAT, #156), rejects the host if **any** resolved address is forbidden (`:58-72`), refuses redirects (`:143-144`), and **pins the socket to the validated IP** (`:75-92`) closing DNS-rebinding |
| Ship a tiny highly-compressible status list | **Decompression bomb** (OOM DoS) | Status decode caps the *decompressed* output at 16 MiB and reads incrementally so a bomb is never materialised — `src/openvc/status/_decompress.py:23,38-40,54-66` |
| Swap / replay a status list or presentation | Stale-status / replay accept | Status token `sub` must equal the fetched URI (anti-swap) — `src/openvc/resolvers.py:122-123`; presentations bind `aud` + one-time `nonce`/`challenge`; a fetched status list is **verified before trust** — `src/openvc/resolvers.py:92-98`; optional status-issuer binding (ADR-0006) — `src/openvc/verify.py:654-669`, and the default status-list resolvers refuse a verified list whose body names an issuer other than its signer (#221); a nested SD-JWT VC's KB-JWT is held to the enclosing presentation's `aud` / `nonce`, and `VcJwtProofSuite` refuses a JWS typed `sd-jwt` / `*+sd-jwt` / `kb+jwt` before key load (explicit typing, RFC 8725 §3.11 — `_reject_sd_jwt_typ`), so a tail-stripped SD-JWT issuer JWT cannot verify as a VC-JWT and sidestep `require_key_binding=True` (#189); with `require_key_binding=True` the KB-JWT is verified before the issuer JWT's `exp` / `nbf`, so an `expired` verdict never stands in for holder binding (#182) |
| Wrap a credential issued to someone else (a VC-JWT, a Data Integrity VC, or an SD-JWT VC with its KB-JWT stripped) inside their own, correctly bound `jwt_vc_json` / `ldp_vc` presentation | Wrong-accept: a victim's credential presented as their own (a relay by a verifier that once received it) | DCQL `require_cryptographic_holder_binding` (default `true`, OpenID4VP 1.0 §6.1) is enforced on the W3C formats: each embedded VC-JWT / Data Integrity VC must name the **authenticated** VP signer as its single subject, and each nested SD-JWT VC must carry a KB-JWT bound to this exchange, or the whole response is rejected; a non-boolean flag is malformed, never coerced to `false` — `_check_holder_bound` in `openvc/openid4vp.py` (#196) |
| Pair one's own WRPAC with another relying party's WRPRC, or request beyond the registered grant (an unregistered or format-less query, an uncovered `meta`, a second `claim` / `claims` spelling, an empty grant) | Wrong-authorize: a relying party receives attributes it never registered for | `check_matches_access_certificate` binds the WRPRC `sub` to the WRPAC entity identifier (absent on either side fails); `check_request_within_registration` requires a matching non-blank `format`, a covered `meta`, a named claim set, and every path inside the grants of the entries that apply; `claim` wins by presence on the grant side, the union is read on the request side — `rp_registration.py` (I21; #89, #152, #160, #161) |
| Back/post-date validity | Expired / not-yet-valid accept | Temporal checks on `validFrom`/`validUntil`/`expires` (+ VCDM 1.1 aliases) — `src/openvc/proof/_verify_common.py:90-125`; a **present-but-unparseable** timestamp fails **closed** — `:84-85`; a present JWT `exp`/`nbf`/`iat` that is not a finite JSON number (`null` included) rejected on the VC-JWT, SD-JWT VC issuer/KB-JWT, VP-JWT, status-list and key-proof lanes, `exp` exclusive and a future `iat` bounded — `check_jwt_temporal` in the same module; VC-JWT `aud` enforced per RFC 7519 §4.1.3 — `check_jwt_audience` (ADR-0008); SD-JWT VC also applies `exp` / `nbf` to the processed payload (#174), and since #229 a disclosed `exp` / `nbf` is refused outright (a withheld one is R7); a W3C `vc+sd-jwt` payload is held to its VCDM validity window (#198); under the opt-in `require_not_expired=False` waiver, the reported `expired` is each suite's own verdict on the check it skipped (#203) |
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
  issuer JWT (`:419-424`) and KB-JWT (`:608-611`); duplicate/unreferenced
  disclosures rejected (`:457-460,552-553`); claim-overwrite blocked (`:174`);
  key-binding-required-without-`aud`/`nonce` fails closed (`:571-579`), and so
  does a present KB-JWT checked against only one of `aud`/`nonce`, or an empty
  one (`:584-604`, #191); a present KB-JWT's `iat` is
  required and bounded in both directions — no older than `kb_max_age_s` (default
  300 s) plus leeway, not future-dated past it — at the caller's `now` (a naive `now`
  is UTC), through `check_iat_freshness`, which the key proof shares (#186). See
  **R1** in §9 for the recursion caveat.
- **Data Integrity** — `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` (RDF-canonical),
  `eddsa-jcs-2022` / `ecdsa-jcs-2019` (JCS), and selective-disclosure
  `ecdsa-sd-2023`. `verificationMethod`↔`issuer` binding (`src/openvc/verify.py:628-641`);
  cryptosuite chosen from the resolved key, never a proof field
  (`src/openvc/proof/_verify_common.py:289-303`); validity window + `proofPurpose`
  enforced (`src/openvc/proof/data_integrity.py:235,238`). The RDF suites sign the
  dataset but the policy reads the JSON, so context validation
  (`src/openvc/proof/_context_validation.py`, invariant I20) ties the two together
  first. The JCS suites sign the JSON itself. The JCS suites and
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
- **Relying-party registration certificate (WRPRC)** — `src/openvc/rp_registration.py`.
  The JWT form (`rc-wrp+jwt`) is verified over the JOSE lane as a subset of JAdES
  baseline B-B; the CWT form (`rc-wrp+cwt`) over `openvc.cose`, **provisionally**,
  since the spec allocates no CBOR claim keys. Signature verification only proves a
  registrar signed something; the authorization decision is two further cross-checks,
  `check_matches_access_certificate` (WRPRC `sub` ↔ WRPAC entity identifier) and
  `check_request_within_registration` (requested ⊆ registered) — invariant I21.

## 6. Attack surface by hand-rolled parser (attacker-controlled bytes)

The dependency-light posture means openvc hand-rolls the codecs that face
attacker bytes. Each must be **depth/size-bounded** and **fail closed with a
typed error**. "Implicit only" = bounded by "each element consumes ≥1 byte of
finite input", with no explicit constant.

| Parser | Input | Explicit bound | Fail-closed error | Anchor |
|---|---|---|---|---|
| CBOR decoder | mdoc `DeviceResponse`, COSE headers, ecdsa-sd proofValue | Depth **64**; **no** element-count/total-size cap (implicit only) | `CborError` (typed); dup-map-key & trailing-byte rejected | `src/openvc/cbor.py:69,196-197,229-232,261-262` |
| COSE_Sign1/Mac0 | mdoc IssuerAuth/DeviceAuth; the CWT form of a WRPRC | Inherits CBOR depth 64; alg allow-list `{-7,-35,-8,5}` before crypto | `CoseError` family (a non-integer `crit` label too, #170); constant-time MAC compare | `src/openvc/cose.py:57-58,238-242,264` |
| mdoc `DeviceResponse` | OpenID4VP `vp_token` | Inherits CBOR; **depth counter resets at each embedded `#6.24`** (R3) | `MdocError` family; CBOR errors re-wrapped | `src/openvc/mdoc.py:307,315,365,377` |
| multibase / base58 / varint | `publicKeyMultibase`, `proofValue` | base58 **≤4096**; varint **≤9 bytes** | `MultibaseError` (typed) | `src/openvc/multibase.py:18,21,30-31,73-74` |
| JCS canonicalizer (RFC 8785) | JCS DI unsecured doc + proofConfig | Depth **100**; IEEE-754 range enforced; NaN/Inf rejected | `JcsError` — **not** an `OpenvcError` (R2) | `src/openvc/proof/_jcs.py:18,27,148-149` |
| SD-JWT `_unpack` / JWS decode | Holder presentation | Depth **100**; `RecursionError` mapped to typed (v1.20.1, was R1) | `SdJwtError`/`MalformedToken` (typed) | `src/openvc/proof/sd_jwt.py:66,121,397` |
| ecdsa-sd proofValue | DI selective-disclosure proof | Reuses CBOR (depth 64) + strict 5-element subset gate | `ProofValueMalformed` (typed) | `src/openvc/proof/ecdsa_sd.py:45,103-121,139-141` |
| Bitstring status | Resolved status VC `encodedList` | Delegates 16 MiB decompress cap; index bounds-checked; corrupt DEFLATE (`zlib.error`) re-wrapped since v1.29.2 | `StatusListError` (typed) | `src/openvc/status/bitstring.py` |
| Status index | Credential's `statusListIndex` / `status.status_list.idx` | One shared rule: non-negative `int` (never `bool`/`float`) or ASCII-digit string (W3C only), below 2^27 (the decompress cap at 1 bit/status); the entry's URL / `statusPurpose` must be strings (never `str()`'d); error text never `repr()`s a container or a >64-bit int | `StatusListError` (typed) — was a bare `OverflowError` on `Infinity`/`1e400` before v1.29.2 | `src/openvc/status/_index.py` |
| Decompress (gzip/zlib) | Issuer status bytes (**not** covered by the 1 MiB fetch cap) | **16 MiB**, incremental | `DecompressionBomb` — **not** an `OpenvcError`, re-wrapped at call sites (R2) | `src/openvc/status/_decompress.py:23,28,38-66` |
| LOTL/TL XML | EU trusted-list bytes (pre-signature) | **DOCTYPE refused** (blocks XXE + expansion); 16 MiB + 500k elements | `TrustListParseError` (typed) | `src/openvc/trustlist/parse.py:22,108-120,100-117` |
| XAdES signature XML | Signed trusted-list | 16 MiB; XAdES-BASELINE-B alg profile; XSW subtree guard | `XadesError` family; hardened lxml on the reparse (R6) | `src/openvc/trustlist/xades.py:71-81,97-98,115-127` |

## 7. Network & SSRF surface

- **`fetch.py`** (the general guarded https fetch, used by `did:web` and the
  blessed resolvers): https-only; blocks private/loopback/link-local/reserved/
  multicast/unspecified; rejects the host if *any* resolved address is forbidden;
  refuses redirects; **pins the socket to the validated IP** (DNS-rebinding
  TOCTOU closed); 1 MiB response cap + wall-clock read deadline; query strings
  never logged. `src/openvc/fetch.py:41-148`. See **R5**. Since v1.25.0 it also
  refuses any other address that is not `is_global` (RFC 6598 CGNAT, #156), and a
  malformed or non-ASCII URL, a control character in the host or a host over 253
  characters is refused before DNS (#207, #235).
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
  Because the allow-list matches the host and not the port, the TIR v5 adapter pins
  `links.next`, the HATEOAS `attributes` URL and every revision `href` to the
  listing's `scheme://host:port` (`_origin` in `openvc_ebsi/versioning.py`; #172).
  A URL with no origin to compare is treated as off-origin: a typed
  `MalformedRegistryResponse` on the `attributes` hop, skipped on `links.next` and
  `href`. That covers a port that does not parse (`:99999`, `:abc`) and a broken IPv6
  literal, which raised a bare `ValueError` before v1.32.1 (#243). It also covers a URL
  the client would read differently: anything but visible ASCII (refused before
  `urlparse`) or over 8 KiB (#246). The client applies the same rule before any I/O:
  a URL that is not visible ASCII, or that `urlparse` cannot read (port included), is
  `HttpForbiddenHost`, and `httpx.InvalidURL` is mapped to it. Before v1.32.1 an
  unsigned token whose `iss` held a control character escaped `verify_ebsi_badge` as
  a bare `httpx.InvalidURL` (#246). A body httpx cannot decompress is a
  `MalformedRegistryResponse`; before v1.32.1 it escaped as a bare
  `httpx.DecodingError` (#248). The allow-list says which host answers, not which
  document: `DidEbsiResolver.resolve` holds the parsed document's `id` (after a
  `didDocument` wrapper is unwrapped) to the DID it asked for, exactly, and raises
  `DidResolutionError` otherwise, as `did:web` and `did:webvh` do. A missing, non-string
  or empty `id` never matches; neither does a DID URL (`did:ebsi:zX#key-1`), which
  resolved by accident before v1.32.4 because httpx drops the fragment. Compromise of
  the registry itself is still out of scope (§10): it can serve a matching `id` with its
  own key. What the check closes is a misrouted or steered response (a registry bug, a
  wrong `base`, an unsigned token's `iss` such as `did:ebsi:zA/../did:ebsi:zB`, which
  httpx turns into a request for B's resource) being accepted as the requested DID's
  document. The DID is still put into the registry path unvalidated, and the TIR issuer
  response's own `did` is still not read; both are outside #257 (#257, v1.32.4).

## 8. Fail-closed invariants catalog

The invariants an auditor should try hardest to break. Each is enforced at the
cited line and pinned by a regression test — the golden fixtures and the
negative corpus are the drift alarm (see [assurance.md](assurance.md)).

| # | Invariant | Enforced at | Pinned by |
|---|---|---|---|
| I1 | Alg allow-list `{ES256, ES384, EdDSA, Ed25519}` runs **before any crypto**; `alg:none`/RS\*/HS\* rejected | `proof/vc_jwt.py:55,198`; `proof/_jws.py:84` | `test_hostile_input.py`, `test_cose.py:94` |
| I2 | ES256/384 JOSE signature is raw R‖S (64/96 bytes), never DER | `keys.py:575-589` | `test_vc_jwt.py` |
| I3 | PQ (ML-DSA) never in the default allow-list — opt-in only | `proof/vc_jwt.py:135` | `test_mldsa.py` |
| I4 | DI `verificationMethod` bound to the credential `issuer` DID | `verify.py:628-641` | `test_di_*` |
| I5 | VC-JWT, and a W3C SD-JWT (`vc+sd-jwt`), reconcile the JWT envelope with the credential (`iss`/`sub`/`jti`); every identifier a present `issuer` carries must be `iss` | `proof/vc_jwt.py:360-381`; `issuer_identifiers` (`proof/_verify_common.py`) | `test_vc_jwt.py`, `test_sd_jwt_vcdm_consistency.py` |
| I6 | x5c leaf SAN bound to `iss`; binding after path-validation; a `dNSName` binds only an unambiguous https `iss` | `x5c.py:56-70,151-154`; `_parse_https_issuer` (`jwt_vc_issuer.py`) | `test_x5c*`, `test_sd_jwt.py:425`, `test_https_issuer_identifier.py` |
| I7 | Present-but-unparseable timestamp fails **closed** | `proof/_verify_common.py:84-85`; `check_jwt_temporal` (same module) | `test_di_jcs.py`, `test_sd_jwt.py:333`, `test_jose_temporal_claims.py`, `test_vc_jwt_numeric_dates.py`, `test_sd_jwt_vcdm_validity.py` |
| I8 | `require_status=True` by default; declared-but-unresolvable status rejects | `verify.py:147,781-787` | `test_status.py` |
| I9 | Signing goes through the `SigningKey` protocol — no private key in-process | `proof/vc_jwt.py:75-92`; `proof/_jws.py:53` | `test_keys*` |
| I10 | SSRF guard: https-only, forbidden-range block (any address that is not `is_global`, RFC 6598 CGNAT included), redirect refusal, IP-pin | `fetch.py:49-92,126,143-144` | `test_fetch*`, `test_did_web_hostile_host.py` |
| I11 | Status decompression bounded at 16 MiB, incremental | `status/_decompress.py:23,38-66` | `test_status_decompress.py:46-82` |
| I12 | CBOR depth ≤ 64; JCS depth ≤ 100; duplicate map key rejected | `cbor.py:69,229-232`; `proof/_jcs.py:18` | `test_cbor.py:104,152`; `test_di_jcs.py:388` |
| I13 | Trust-list XML refuses DOCTYPE (XXE + expansion closed) | `trustlist/parse.py:108-120` | `test_trustlist.py:104,121` |
| I14 | Every internal failure subclasses `OpenvcError` and re-raises typed | `verify.py:105-123,320-322` | `test_hostile_input.py`, `test_typed_error_unhashable_header.py`, `test_typed_error_vc_shape.py`, `test_unhashable_proof_purpose.py`, `test_status_index_hostile.py`, `test_did_web_hostile_host.py`, `test_did_document_shape_typed.py`, `test_typed_clock_pins.py`, `test_cose.py` (`test_a_non_integer_crit_label_is_cose_malformed_not_typeerror`), `test_vc_jwt_numeric_dates.py`, `test_sd_jwt_kb_freshness.py`, `test_ebsi_verifier.py` (`test_verify_ebsi_badge_unparseable_attributes_url_is_openvc_error`, `test_verify_ebsi_badge_hostile_iss_is_typed_before_any_request`), `test_ebsi_http.py` |
| I15 | `verify_many` isolates per-credential — one bad item never aborts the batch. A hostile DID-document shape — valid JSON, wrong structure — served for an unsigned token's own `did:web` issuer used to abort the batch; `parse_did_document` now raises `DidResolutionError` (#219, fixed in v1.32.3) | `verify.py:458-465` | `test_hostile_input.py` (`test_verify_many_isolates_a_non_string_kid`, `test_verify_many_isolates_a_non_object_payload`, `test_verify_many_isolates_a_deeply_nested_sd_jwt`, `test_verify_many_isolates_deeply_nested_across_formats`); the batch tests in `test_typed_error_unhashable_header.py`, `test_typed_error_vc_shape.py`, `test_unhashable_proof_purpose.py`, `test_status_index_hostile.py`, `test_did_web_hostile_host.py`, `test_typed_clock_pins.py`; `test_did_document_shape_typed.py` (`test_verify_many_isolates_every_hostile_document`, `test_verify_many_async_isolates_every_hostile_document`); `test_vc_jwt_numeric_dates.py` (`test_verify_many_isolates_malformed_numeric_date`) |
| I16 | Hostile deeply-nested input fails closed **pipeline-wide**: every untrusted JSON parse goes through one loader that refuses nesting past **100** (`openvc._json`; 3.14's `json.loads` parses ~116k levels while `repr()` / `==` overflow far sooner), objects handed over already parsed (credential / `vp_token` dicts, DI suite input, injected-fetch DID documents and issuer metadata, RP DCQL) are held to the same bound, the pipeline maps any residual `RecursionError` to a typed error, and SD-JWT `_unpack` / JCS / did:webvh SCID walk stay capped at 100 | `_json.py`; `proof/sd_jwt.py:66,129`; `verify.py`, `aio.py`, `openid4vp.py`, `proof/vc_jwt.py`, `proof/_jws.py`, `proof/_verify_common.py`, `jwe.py`, `did/base.py`, `did/did_jwk.py`, `did/did_webvh.py`, `jwt_vc_issuer.py`, `fetch.py`, `resolvers.py` | `test_hostile_input.py`, `test_did_webvh.py`, `test_typed_error_deep_nesting.py`, `test_typed_error_vc_shape.py` (`test_deeply_nested_cryptosuite_is_typed`) |
| I17 | An OID4VCI key proof is pinned to `typ: openid4vci-proof+jwt` and must carry **exactly one** of `jwk`/`kid`/`x5c`/`trust_chain`, with the key bound to the header `alg`'s (kty, crv) | `openid4vci.py:676,752,855` | `test_openid4vci.py`, `test_openid4vci_vectors.py` |
| I18 | Key-proof `iat` freshness is enforced in **both** directions (stale *and* future-dated, non-finite rejected), and the nonce is consumed **exactly once per request, after every signature verifies** | `openid4vci.py:915,917,655` | `test_openid4vci.py`, `test_openid4vci_vectors.py`, `test_sd_jwt_kb_freshness.py` (the freshness helper, `check_iat_freshness`, is shared with the SD-JWT KB-JWT) |
| I19 | A key proof carrying a `key_attestation` must be signed by one of its `attested_keys` (OID4VCI App. D), compared by RFC 7638 thumbprint. **Not an attacker control** — the attestation's signature is never checked here, so a forger attests their own key; this catches an honest wallet, or the caller's own `resolve_proof_key*`, yielding a key the wallet never claimed, and can only reject, never accept | `openid4vci.py:833` | `test_openid4vci.py`, `test_openid4vci_vectors.py` |
| I20 | An RDF Data Integrity document is accepted, and signed, only in the compacted form of its own expansion under the VC base context plus loader-served URLs or absolute-IRI `@vocab`-only objects — no `@included`/`@reverse`/`@index`/`@direction`, no nested re-description of the document node, and nothing the RDF conversion drops (safe mode: every node id, type and property a well-formed absolute IRI, no blank-node property) — so every JSON member the policy reads is one the signature covers | `proof/_context_validation.py:67-175`; `proof/data_integrity.py:181,233`; `proof/di_ecdsa_rdfc.py:149,205`; `proof/ecdsa_sd.py:512,683` | `test_di_context_validation.py` |
| I21 | WRPRC authorization fails closed: the WRPRC `sub` must equal the WRPAC entity identifier (absent on either side is a failure, never a match), and a DCQL request is authorized only if every credential query (a) has at least one registered entry with the same non-blank string `format` and a `meta` that covers the query's, (b) names at least one claim — a query naming none asks for every attribute and is always refused — and (c) has every requested claim path inside the union of the grants of the entries so matched; an entry with an empty grant, or registered for a different `meta`, contributes nothing. Grant-side spelling precedence is narrow and decided by key presence (`claim` over `claims`, never their union), while the request side reads the union | `check_matches_access_certificate`, `check_request_within_registration`, `_registered_paths` (`rp_registration.py`) | `test_rp_registration.py` |

## 9. Residual risks & known limitations

The honest register. No open item is a wrong-accept that openvc's own checks could
catch (I1–I7, I20 and I21 hold); the open items are **availability /
typed-error-hygiene** hardening and documented caveats — the "harden next" list an
external reviewer should weigh. One caveat, **R7**, is an issuer-configuration gap: an
expired or revoked credential whose issuer made `exp` / `nbf` / status selectively
disclosable verifies when the holder withholds them. Since #229 openvc refuses to
*issue* such claims and rejects a presentation that *discloses* one; a withheld
disclosure from a third-party issuer remains undetectable by design. **R9** was a wrong-accept and is resolved. Ranked by our assessment;
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
  across the supported interpreter range. Since v1.25.0 `test_forbidden_ips` pins
  the IPv4-mapped private and CGNAT forms on every CI interpreter; the mapped-form
  classification still varies across `ipaddress` versions.
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
  non-disclosable**. The same holds for a selectively disclosable `exp` / `nbf` / `status` on
  SD-JWT VC: a **disclosed** `exp` / `nbf` is enforced on the processed payload since
  v1.25.0 (#174), and a disclosed `status` was already read from it, but a
  **withheld** one leaves the credential verified as if it had none. A disclosable
  `cnf` is never read: key binding uses only the issuer-signed body's `cnf`, so any
  KB-JWT presented against it is refused and a KB-stripped presentation verifies with
  `key_bound=False`. **Narrowed in #229:** `SdJwtVcProofSuite.issue` refuses to make
  `iss` / `nbf` / `exp` / `cnf` / `vct` / `vct#integrity` / `aka_vcts` / `status`
  (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3), `credentialStatus` and `@context` (plus
  the VCDM validity window on a VCDM payload) selectively disclosable through
  `disclosable` (digests a caller writes into `claims` itself are signed as given).
  `verify()` rejects (`SdJwtError`) a
  presentation that presents such a disclosure, or one of its sub-claims, and a
  `dc+sd-jwt` with no `vct` (`ClaimsInvalid`). What remains is the **withheld**
  disclosure from a third-party issuer: a withheld digest is indistinguishable
  from a decoy (RFC 9901 §9.7), so no verifier can see it. Pinned as a limitation
  in `tests/test_sdjwt_non_disclosable.py`. `credentialSchema` is not refused:
  schema validation is opt-in data-shape checking, not a gate.
- **R8 — `credentialSchema` pattern-ReDoS.** Schema validation is opt-in and
  remote `$ref` is off; a catastrophic `pattern` in a trusted schema is a
  residual CPU-DoS. Point the schema resolver at trusted hosts.
- **R9 — RDF Data Integrity suites read JSON their signature does not cover. ✅
  Resolved in v1.30.2 (GHSA-vrxg-57v4-85mc).** This one was a **wrong-accept**.
  `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and `ecdsa-sd-2023` sign the RDF dataset, while
  the validity window, status, schema, issuer/subject and holder binding read the JSON.
  JSON that expands to the same dataset could therefore:
  - hide a signed member: re-keyed to its IRI, aliased by an inline `@context`, or
    moved into `@included`;
  - re-map `credentialSubject` by replacing the VC context;
  - forge the whole top level over a node id the RDF conversion drops (whitespace in
    the IRI, or a relative id under `{"@base": null}`), with the real node restated
    elsewhere;
  - carry a claim no context defines, or one under a blank-node `@vocab`, which is
    dropped from the dataset and so never signed.

  **Fixed:** context validation plus JSON-LD safe mode (I20).
  **Residual:** a node the issuer's own graph references from several places may be
  described in any of them (RDF semantics). Only the document node is pinned to the
  top level. A `credentialStatus` left as a bare reference still fails closed
  (`StatusListError`; inside an array, `StatusUnavailable` unless
  `require_status=False`). Caller-supplied `extra_contexts` are trusted: one
  that gives a core VC term a second, shorter name can still hide that member.
  They are scoped to the call, though: since v1.27.1 only the bundled contexts are
  tagged `static` in pyld's process-global cache, so one caller's injected document
  never governs another caller's canonicalization through a URL it serves (#185). An
  inline context that `@import`s a URL is still resolved once into that cache and
  reused by later calls (#225, open); on the verify path the v1.30.2 inline-context
  rule refuses such a document, so it is not reachable there today.
- **R10 — Untyped exits at the verification boundary. ✅ Resolved in v1.32.3
  ([#219](https://github.com/luisgf/openvc/issues/219)).** The last known
  attacker-controlled inputs that escaped `OpenvcError`, so that I14 did not hold for
  them, are typed. (Caller configuration is a separate class: a string or `None`
  `leeway_s` still raises a bare `TypeError` on the VP-JWT, status-list-token and
  `check_jwt_temporal` lanes, tracked as
  [#228](https://github.com/luisgf/openvc/issues/228) /
  [#232](https://github.com/luisgf/openvc/issues/232).) Three EBSI exits
  were typed in v1.32.1 (§7): a registry URL that `_origin` could not parse (#243), a URL
  the HTTP client could not parse, reachable from a token's `iss` (#246), and a registry
  body that does not decompress (#248). The fourth, the only one that reached
  `verify_many`, was a hostile DID-document shape — valid JSON, wrong structure — served
  for an unsigned token's own `did:web` issuer: `parse_did_document` raised a bare
  `TypeError` / `AttributeError` and aborted the batch, with no key needed (#219). None
  was a wrong-accept; each failed closed, untyped. **Fixed:** a wrong-typed
  `didDocument`, `verificationMethod` or relationship raises `DidResolutionError`, is never
  read as undeclared, and a method or reference without a string `id` is dropped (I14,
  I15; `test_did_document_shape_typed.py`). **Residual:** the check does not know which
  lane is asking, so a relationship that is not an array rejects the whole document, JOSE
  lanes that never read relationships included (fail-closed, and only for a document that
  breaks DID Core). A dropped method that carried a key is not counted by the `kid`-less
  sole-key fallback, as a method with an undecodable Multikey never was; the key it then
  selects is well-formed and in the issuer's own document.

## 10. Out of scope

- Compromise of a trusted anchor, of the host, or of the `SigningKey` backend.
- Availability of remote issuers / status lists (openvc bounds *its own*
  resource use, not third-party reachability).
- Anything an **injected** resolver does after openvc hands it a URL, if the
  caller supplies a custom one instead of the guarded default.
- Side-channels in the underlying `cryptography` / `pyjwt` primitives.
- EBSI **write/onboarding**; OpenID4VP **request generation**; ISO mdoc **issuance /
  proximity / COSE signing** — all out of scope by design (see
  [ROADMAP](https://github.com/luisgf/openvc/blob/main/docs/ROADMAP.md)).
- **OAuth Authorization Servers, HTTP endpoints, and every state store** — openvc runs
  no server and persists nothing. For OpenID4VCI
  ([ADR-0007](../adr/ADR-0007-oid4vci-issuer-side.md)) the whole protocol layer is out;
  openvc verifies the wallet's key proof and parses untrusted offers/metadata, nothing
  more. Single-use enforcement of `c_nonce` (and of codes, `transaction_id`,
  `notification_id`) is the **caller's**, supplied as a required injected callable —
  and it must be atomic. A non-atomic store re-opens a replay window openvc cannot
  close on the caller's behalf; that is a documented boundary, not a defended one.
  Note `openvc.cache.TtlCache` is **not** suitable for it (no single-flight, `cache.py:24-27`).
