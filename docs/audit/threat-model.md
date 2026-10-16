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
> v1.25.0–v1.31.2 hardening, I21, and the evidence added to I5–I18 — and I22 (v1.36.0)
> cite symbols and test names instead of line numbers, so they stay valid as the code
> moves.

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
| Name issuer A but sign with key B | Impersonation | **Issuer binding**: a DI proof's `verificationMethod` must be controlled by the credential `issuer` DID — `src/openvc/verify.py:628-641`; VC-JWT reconciles the JWT envelope (`iss`/`sub`/`jti`) with the embedded `vc` — `src/openvc/proof/vc_jwt.py:360-381`; x5c binds the leaf SAN to `iss` — `src/openvc/x5c.py:56-70`; a W3C credential secured as SD-JWT (a VCDM payload, whatever its issuer `typ`) is reconciled the same way, and every identifier a present `issuer` carries must be `iss` — `issuer_identifiers` (#221); a W3C SD-JWT whose issuer JWT has no `iss` member and a W3C `typ` (or none; a header `"typ": null` is a present `typ`, not a state) is keyed on the `issuer` of its body instead (VC-JOSE-COSE §4.1.2, §4.2; never a disclosed one, never the `kid`), which is as unauthenticated as `iss` until the signature verifies, and `result.issuer` is the identifier whose key verified (its claims then carry no `iss`) — `_vcdm_issuer` in `proof/sd_jwt.py` (#290); an https `iss` that Python and a WHATWG parser read as different hosts is refused before the `/.well-known/jwt-vc-issuer` fetch and never binds an x5c `dNSName` — `_parse_https_issuer` in `jwt_vc_issuer.py` (#236) |
| Re-spell a signed RDF Data Integrity credential's JSON while keeping its signed dataset (IRI-keyed or aliased member, inline `@context` re-mapping a term, undefined term, `@included`) | Wrong-accept: the policy reads JSON the signature does not cover (expiry/status/schema skipped, `credentialSubject` spoofed past holder binding, unsigned claims) | **Context validation** (VC-DI §2.4.1) after the proof verifies and before any policy read — `src/openvc/proof/_context_validation.py` (`validate_document`), called at `src/openvc/proof/data_integrity.py:236`, `src/openvc/proof/di_ecdsa_rdfc.py:205`, `src/openvc/proof/ecdsa_sd.py:749` (and on the signing side). VC base context first, then only loader-served URLs or absolute-IRI `@vocab`-only objects (`_check_context`); the document and proof must equal the compaction of their own expansion (`_check_compacted`), with no `@included`/`@reverse`/`@index`/`@direction`, no nested re-description of the document node, and nothing the RDF conversion drops — every node id, type and property a well-formed absolute IRI, no blank-node property (`_check_expanded`) |
| Serve a malicious document at a fetched URL | **SSRF** (internal hosts / cloud metadata) | `src/openvc/fetch.py`: https-only (`:126`), blocks private/loopback/link-local/reserved/multicast/unspecified (`:49-55`) and, since v1.25.0, any other address that is not `is_global` (RFC 6598 CGNAT, #156), rejects the host if **any** resolved address is forbidden (`:58-72`), refuses redirects (`:143-144`), and **pins the socket to the validated IP** (`:75-92`) closing DNS-rebinding |
| Ship a tiny highly-compressible status list | **Decompression bomb** (OOM DoS) | Status decode caps the *decompressed* output at 16 MiB and reads incrementally so a bomb is never materialised — `src/openvc/status/_decompress.py:23,38-40,54-66` |
| Swap / replay a status list or presentation | Stale-status / replay accept | Status token `sub` must equal the fetched URI (anti-swap) — `src/openvc/resolvers.py:122-123`; presentations bind `aud` + one-time `nonce`/`challenge`; a fetched status list is **verified before trust** — `src/openvc/resolvers.py:92-98`; optional status-issuer binding (ADR-0006) — `src/openvc/verify.py:654-669`, and the default status-list resolvers refuse a verified list whose body names an issuer other than its signer (#221) and, since 1.35.0, fill in that signer as the issuer of a list whose body names no one, on a copy, so the binding refuses an attacker-signed issuer-less list by name instead of failing on a missing issuer (#226); a nested SD-JWT VC's KB-JWT is held to the enclosing presentation's `aud` / `nonce`, and `VcJwtProofSuite` refuses a JWS typed `sd-jwt` / `*+sd-jwt` / `kb+jwt` before the signature is checked (explicit typing, RFC 8725 §3.11 — `_reject_sd_jwt_typ`), so a tail-stripped typed SD-JWT issuer JWT cannot verify as a VC-JWT and sidestep `require_key_binding=True` (#189); since 1.34.0 the same lane also refuses a JWS whose payload carries an SD-JWT marker at any depth, a member named `_sd` or `_sd_alg` or an array-element `"..."`, whatever its `typ`, before the signature is checked and before the suite loads its verification key (the `verify_credential` pipeline resolves the issuer first) (`_reject_sd_jwt_payload`, `MalformedToken`; RFC 9901 §4.1 item 7 and §4.2.4.2, where `_sd` and `...` are reserved and `...` is the array-element digest object, and §4.1.1, where `_sd_alg` is top level only), which closes the untyped case for every token that has a disclosure, and `VpJwtProofSuite.verify` applies both tests to a presentation before it resolves the holder key (it did not read `typ` before; #291); since 1.34.0 `SdJwtVcProofSuite.verify` also accepts an issuer JWT with no `typ`, or typed exactly `vc+ld+json+sd-jwt`, for a VCDM payload (VC-JOSE-COSE §3.2.1 makes the `typ` a SHOULD, and the Recommendation's Examples 4, 5 and 21 omit it or use the draft-era name; #288, #289): only with a VCDM base `@context` (`_declares_vcdm`, the lax test that still drives the validity window and the consistency checks), a `typ` that is present and anything else is still refused (`_ACCEPTED_ISSUER_TYP`, exact match), a payload that fails `_vcdm_nonconformity` is refused for every `typ` but `dc+sd-jwt` (#275): its first `@context` entry must be a VCDM base context (VCDM 2.0 §4.3) and its `type` must include `VerifiableCredential` and not `VerifiablePresentation` (§4.5, §4.13; `_declares_credential`), which for a token with no `typ` is what tells a credential from a presentation, since a VCDM 2.0 presentation has the same `@context` and no `vp` claim, and a token with no `typ` is also refused when it carries a `vc` or `vp` claim (VC-JOSE-COSE §1.1.2.1, restated in §3.1.3), since `_reject_sd_jwt_typ` has no `typ` to refuse and such a token would otherwise also verify as a VC-JWT once its tail is dropped; the ban cannot help a token the SD-JWT lane never sees, and the VC-JWT lane's marker fence (#291) covers that one. **Residual of #291 (R11):** a zero-disclosure SD-JWT issuer JWT with no `typ`, a `vc` object and a `cnf` carries none of `_sd`, `_sd_alg` or `"..."` (an `_sd_alg` alone, or a decoy digest, is already refused), so it cannot be told from a VC-JWT that carries a `cnf`; it still verifies as a VC-JWT, and that lane never enforces `cnf`. It needs an issuer that signs a hybrid no spec defines. **Trade-off:** this drops the explicit-typing guard of RFC 9901 §9.11 for VCDM payloads; the `@context` requirement, the `type` check, the `vc` / `vp` ban, `require_key_binding=True` (a KB-JWT is still required) and the VC-JWT lane's marker fence stand in for it; with `require_key_binding=True` the KB-JWT is verified before the issuer JWT's `exp` / `nbf`, so an `expired` verdict never stands in for holder binding (#182) |
| Present a credential its issuer restricted to another relying party (`aud`), bound to this verifier by the holder | Wrong-accept: the restriction the issuer signed is ignored, and a correct KB-JWT launders it (the KB-JWT's `aud` binds the holder's presentation, not the issuer's restriction) | RFC 7519 §4.1.3 on both VC-JWT lanes and on the SD-JWT VC issuer JWT whenever it carries `aud` (`check_jwt_audience`, ADR-0008 D3, D4): a string or an array of strings, and the caller's audience (nested, the presentation's) must be in it; with no audience a restricted credential is refused. An SD-JWT VC without `aud` is unchanged. A withheld disclosure of `aud` is invisible (R7) |
| Wrap a credential issued to someone else (a VC-JWT, a Data Integrity VC, or an SD-JWT VC with its KB-JWT stripped) inside their own, correctly bound `jwt_vc_json` / `ldp_vc` presentation | Wrong-accept: a victim's credential presented as their own (a relay by a verifier that once received it) | DCQL `require_cryptographic_holder_binding` (default `true`, OpenID4VP 1.0 §6.1) is enforced on the W3C formats: each embedded VC-JWT / Data Integrity VC must name the **authenticated** VP signer as its single subject, and each nested SD-JWT VC must carry a KB-JWT bound to this exchange, or the whole response is rejected; a non-boolean flag is malformed, never coerced to `false` — `_check_holder_bound` in `openvc/openid4vp.py` (#196). A bare credential (no presentation) is refused under the same default and accepted only when the query sets the flag to `false` (§B.1, §14.1.1: nothing binds it to the presenter, `holder=None`); the shape is decided fail-closed before anything is verified — `_w3c_shape` (#204) |
| Pair one's own WRPAC with another relying party's WRPRC, or request beyond the registered grant (an unregistered or format-less query, an uncovered `meta`, a second `claim` / `claims` spelling, an empty grant) | Wrong-authorize: a relying party receives attributes it never registered for | `check_matches_access_certificate` binds the WRPRC `sub` to the WRPAC entity identifier (absent on either side fails); `check_request_within_registration` requires a matching non-blank `format`, a covered `meta`, a named claim set, and every path inside the grants of the entries that apply; `claim` wins by presence on the grant side, the union is read on the request side — `rp_registration.py` (I21; #89, #152, #160, #161) |
| Mark a JWS header extension `critical` (`crit`) that the verifier does not process, or smuggle `b64: false` (an unencoded payload) past a verifier that reads the payload as base64url | Wrong-accept: a constraint the signer declared mandatory is ignored, or a signature is checked over bytes other than the ones then parsed | The shared `reject_unknown_crit` (RFC 7515 §4.1.11) refuses any `crit`; the two JAdES lanes (the LoTE verifier and the WRPRC lane) allow-list `{alg, typ, x5c, iat}` and refuse the rest; with **one documented exception**: the WRPRC lane alone also understands exactly `sigT` and `b64: true`, because the registrars' real tokens list both (issue #134) — a `crit` there must be a non-empty array of unique strings, every name present in the header and in `{alg, typ, x5c, iat, sigT, b64}`; `b64` must be the JSON boolean `true` and `sigT` an RFC 3339 UTC time, checked whether or not `crit` names them; `sigT` is surfaced, never used for a validity decision — `rp_registration._reject_unknown_crit`, `_check_understood_params` (I22; v1.36.0; `test_jws_crit.py`, `test_rp_registration.py`, `test_rp_registration_real_artifacts.py`) |
| Back/post-date validity | Expired / not-yet-valid accept | Temporal checks on `validFrom`/`validUntil`/`expires` (+ VCDM 1.1 aliases) — `src/openvc/proof/_verify_common.py:90-125`; a **present-but-unparseable** timestamp fails **closed** — `:84-85`; a present JWT `exp`/`nbf`/`iat` that is not a finite JSON number (`null` included) rejected on the VC-JWT, SD-JWT VC issuer/KB-JWT, VP-JWT, status-list and key-proof lanes, `exp` exclusive and a future `iat` bounded — `check_jwt_temporal` in the same module; VC-JWT `aud` enforced per RFC 7519 §4.1.3 — `check_jwt_audience` (ADR-0008); SD-JWT VC also applies `exp` / `nbf` to the processed payload (#174), and since #229 a disclosed `exp` / `nbf` is refused outright (a withheld one is R7); a W3C credential secured as SD-JWT (a VCDM payload, whatever its issuer `typ`) is held to its VCDM validity window (#198); under the opt-in `require_not_expired=False` waiver, the reported `expired` is each suite's own verdict on the check it skipped (#203) |
| Feed hostile bytes to a hand-rolled parser | Uncaught crash / DoS / parser confusion | Depth-bounded, typed-error codecs — see §6 |
| Deeply nest the trust-list XML | XXE / entity-expansion bomb | The LOTL/TL parser refuses any DOCTYPE outright — `src/openvc/trustlist/parse.py:108-120` — which is what entities and expansion bombs require; 16 MiB + 500k-element caps — `:35-36,100-117` |
| MITM a fetch | Tamper in transit | TLS with certificate validation and SNI on the pinned connection — `src/openvc/fetch.py:79-92` |

## 5. Attack surface by proof suite

- **VC-JWT (JOSE)** — `src/openvc/proof/vc_jwt.py`. Allow-list gate at `:198`
  precedes key load (`:206`) and decode (`:208`); alg pinned to the resolved
  key's `(kty, crv)` (`:341-351`) blocking cross-curve/OKP confusion; envelope↔
  `vc` reconciliation (`:360-381`); temporal defence-in-depth on the body
  (`:237`). ML-DSA (RFC 9964) is **opt-in only** (`allow_pq=True`, `:135`),
  never in the default allow-list. Explicit typing: a JWS typed as an SD-JWT or a KB-JWT
  (`_reject_sd_jwt_typ`, #189) and, whatever its `typ`, one whose payload carries an
  SD-JWT marker at any depth (`_reject_sd_jwt_payload`, #291) are `MalformedToken`
  before the signature is checked. The VP-JWT suite runs both on the presentation before it
  resolves the holder key. A zero-disclosure SD-JWT issuer JWT carries none of `_sd`,
  `_sd_alg` or `"..."` (an `_sd_alg` alone, or a decoy digest, is already refused), so a
  `cnf` on a VC-JWT is not holder binding: this lane never enforces it.
- **SD-JWT VC** — `src/openvc/proof/sd_jwt.py`. Allow-list before crypto for the
  issuer JWT (`:419-424`) and KB-JWT (`:608-611`); duplicate/unreferenced
  disclosures rejected (`:457-460,552-553`); claim-overwrite blocked (`:174`);
  key-binding-required-without-`aud`/`nonce` fails closed (`:571-579`), and so
  does a present KB-JWT checked against only one of `aud`/`nonce`, or an empty
  one (`:584-604`, #191); a present KB-JWT's `iat` is
  required and bounded in both directions — no older than `kb_max_age_s` (default
  300 s) plus leeway, not future-dated past it — at the caller's `now` (a naive `now`
  is UTC), through `check_iat_freshness`, which the key proof shares (#186). A
  present issuer JWT `typ` is matched exactly against a closed set before the signature
  is checked (`_ACCEPTED_ISSUER_TYP`): `dc+sd-jwt`, or `vc+sd-jwt` and `vc+ld+json+sd-jwt`
  for a conforming VCDM payload only, and anything else, `null` included, is an
  `SdJwtError`. A token with no `typ` is accepted for a conforming VCDM payload only too,
  and may not carry a `vc` or `vp` claim (#264, #288, #289). A W3C-typed issuer JWT with no `iss` member at all is keyed on the VCDM `issuer` of its body (`_vcdm_issuer`, #290): a non-empty string or an object whose present `id` / `@id` agree, read from the signed body only, so a disclosure cannot choose the key; a present but unusable `iss` (`null`, `""`, a number, a bool, an object) is not replaced, `dc+sd-jwt` still needs `iss`, `verify()` itself refuses an empty `iss`, and the value is unauthenticated until the signature verifies, as `iss` is. The issuer JWT's own `aud`, when it has one, is enforced on this lane (RFC 7519 §4.1.3, ADR-0008 D4, #227), whatever the payload shape or `typ`, so the fallback that lets a W3C JWS with no `iss` and no `typ`, refused as a bare JWS on the VC-JWT lane, reach it with a `~` appended holds that JWS to the same restriction (`tests/test_sd_jwt_issuer_aud.py`, section J); the §4.2 `kid` rule is not enforced (the `kid` only selects a key inside the issuer's own document). Conforming means the first
  `@context` entry is a VCDM base context and the `type` includes `VerifiableCredential`
  and not `VerifiablePresentation` (#275); a base URL elsewhere in `@context` still turns
  on the validity window and the consistency checks, but is not enough to be read as a
  credential. The trade-off is in the §4 replay row. See **R1** in
  §9 for the recursion caveat.
- **Data Integrity** — `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` (RDF-canonical),
  `eddsa-jcs-2022` / `ecdsa-jcs-2019` (JCS), and selective-disclosure
  `ecdsa-sd-2023`. `verificationMethod`↔`issuer` binding (`src/openvc/verify.py:628-641`);
  cryptosuite chosen from the resolved key, never a proof field
  (`src/openvc/proof/_verify_common.py:289-303`); validity window + `proofPurpose`
  enforced (`src/openvc/proof/data_integrity.py:235,238`). The key is selected by the
  exact absolute DID URL of its `id`, and granted the `proofPurpose` only by a
  relationship entry that resolves to that same URL (DID Core 1.0 §3.2.2, CID 1.0 §3.3);
  a same-fragment entry pointing at another DID, version, path or a bare name grants
  nothing (#258, fixed in v1.32.4; `DidDocument.key_for_purpose`,
  `resolve_verification_key`; `test_did_reference_exact_match.py`). The RDF suites sign the
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
  `check_request_within_registration` (requested ⊆ registered) — invariant I21. Its
  JWS header is the library's **one documented `crit` exception** (invariant I22): the
  lane understands `sigT` and `b64: true`, and nothing else, in `crit`. Five real
  third-party-signed WRPRCs from four producers are vendored as **provisional**
  goldens (`tests/fixtures/rp_registration/`; third-party-signed, **not**
  registrar-anchored — each verifies against its own pinned root, so they prove the
  signature and the profile parse, not that a Member State registrar vouched for
  anyone; #134's registrar-anchored goal and the CWT form stay open).

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
  As of 2026-10-16 only `api-pilot.ebsi.eu` of those three hosts serves a registry
  (`api-conformance.ebsi.eu` accepted no connection and `api.ebsi.eu` returned no HTTP
  response); production nodes are `api.ebsi.<operator domain>` hosts taken from the
  signed Trusted Nodes List
  ([ADR-0009](../adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)).
  Because the allow-list matches the host and not the port, the TIR v5 adapter pins
  `links.next`, the HATEOAS `attributes` URL and every revision `href` to the
  listing's `scheme://host:port` (`_origin` in `openvc_ebsi/versioning.py`; #172). An
  absent https port is 443 (RFC 3986 §6.2.3), so `:443` and no port are one origin,
  as they are to httpx; an explicit `:0` or another port stays off-origin (#253).
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
  `httpx.DecodingError` (#248). The allow-list says which host answers, not which path
  or which document, and the rest of this paragraph is what stands behind it.
  **The DID is validated before it is put in a registry URL** (#266, v1.33.0):
  `DidEbsiResolver.resolve` and `.issuer_record` accept only `did:ebsi:z` plus 22 or 23
  base58btc characters (the legal-entity form of the EBSI DID method: a version byte and
  16 random bytes, multibase-encoded), matched in full with an explicit ASCII class, and
  raise `DidResolutionError` otherwise, before any request. The URL builders in the
  adapters interpolate the DID verbatim, and `verify_ebsi_badge` takes it from an
  unsigned token (`iss`) and the trust walk from the registry (`accreditedBy`), so before
  the check a `/`, a `..` segment (httpx collapses it, so any path on the host was
  addressable), a `?`, a `#`, a percent escape, another DID method, a whole URL or a
  60 KB string chose the path and query of a GET to an allow-listed host. A malformed
  walk subject is `NoTrustedAnchor`, a hostile `accreditedBy` is `AccreditationInvalid`
  (no request names it), and `verify_ebsi_badge` reports `EbsiVerificationError`. The
  network-qualified form of the method (`did:ebsi:<network>:z...`) is not accepted: the
  DID Registry and TIR APIs the plugin reads serve the EBSI blockchain's own form.
  **The registry document is held to the DID asked** (#257, v1.32.4):
  `DidEbsiResolver.resolve` compares the parsed document's `id` (after a `didDocument`
  wrapper is unwrapped) with it, exactly, and raises `DidResolutionError` otherwise, as
  `did:web` and `did:webvh` do. A missing, non-string or empty `id` never matches.
  **So is the TIR issuer response** (#267, v1.33.0): `DidEbsiResolver.issuer_record`
  asks the adapter where the response names its DID (`TirAdapter.response_did`) and
  compares it with the requested DID, exactly, before the adapter follows any link, so a
  record that is not about the DID costs one request and no `attributes` page or revision
  `href` is fetched. Another DID, an absent, `null`, non-string or empty one, and a body
  that is not a JSON object, are `MalformedRegistryResponse` on every API version: a
  mismatched body is malformed input, not an untrusted issuer, so `require_trust=False`
  does not suppress it. Single-level mode verifies no accreditation signature, so this
  field is what says whose record it is; `IssuerRecord.did` is now the DID the registry
  named. Compromise of the registry itself is still out of scope (§10): it can serve a
  matching `id` or `did` with its own key. What the checks close is a misrouted or
  steered response (a registry bug, a wrong `base`, a cache keyed on less than the URL, an
  unsigned token's `iss`) being accepted as the requested DID's document or record.
  **Residual:** the TIR `attributes` URL and each revision `href` are pinned to the
  listing's origin (#172), not to `.../issuers/{did}/`, and a revision's own `did` is not
  read; both are outside #266 and #267.

## 8. Fail-closed invariants catalog

The invariants an auditor should try hardest to break. Each is enforced at the
cited line and pinned by a regression test — the golden fixtures and the
negative corpus are the drift alarm (see [assurance.md](assurance.md)).

| # | Invariant | Enforced at | Pinned by |
|---|---|---|---|
| I1 | Alg allow-list `{ES256, ES384, EdDSA, Ed25519}` runs **before any crypto**; `alg:none`/RS\*/HS\* rejected; the value is type-checked first, so a JSON array/object `alg` is a typed `UnsupportedAlgorithm`, not a bare `TypeError` | `proof/vc_jwt.py:65,243`; `proof/_jws.py:89` | `test_hostile_input.py`, `test_cose.py:94`, `test_typed_error_unhashable_header.py`, `test_typed_error_deep_headers.py` |
| I2 | ES256/384 JOSE signature is raw R‖S (64/96 bytes), never DER | `keys.py:575-589` | `test_vc_jwt.py` |
| I3 | PQ (ML-DSA) never in the default allow-list — opt-in only | `proof/vc_jwt.py:135` | `test_mldsa.py` |
| I4 | DI `verificationMethod` bound to the credential `issuer` DID | `verify.py:628-641` | `test_di_*` |
| I5 | VC-JWT, and a W3C SD-JWT (a payload that names a VCDM base context, whatever its issuer `typ`), reconcile the JWT envelope with the credential (`iss`/`sub`/`jti`); every identifier a present `issuer` carries must be `iss`; with no `iss` member and a W3C `typ` (or none), the body `issuer` stands in for it (#290) | `proof/vc_jwt.py:360-381`; `issuer_identifiers` (`proof/_verify_common.py`); `_vcdm_issuer` (`proof/sd_jwt.py`) | `test_vc_jwt.py`, `test_sd_jwt_vcdm_consistency.py`, `test_sd_jwt_issuer_fallback.py` |
| I6 | x5c leaf SAN bound to `iss`; binding after path-validation; a `dNSName` binds only an unambiguous https `iss` | `x5c.py:56-70,151-154`; `_parse_https_issuer` (`jwt_vc_issuer.py`) | `test_x5c*`, `test_sd_jwt.py:425`, `test_https_issuer_identifier.py` |
| I7 | Present-but-unparseable timestamp fails **closed** | `proof/_verify_common.py:84-85`; `check_jwt_temporal` (same module) | `test_di_jcs.py`, `test_sd_jwt.py:333`, `test_jose_temporal_claims.py`, `test_vc_jwt_numeric_dates.py`, `test_sd_jwt_vcdm_validity.py` |
| I8 | `require_status=True` by default; declared-but-unresolvable status rejects | `verify.py:147,781-787` | `test_status.py` |
| I9 | Signing goes through the `SigningKey` protocol — no private key in-process | `proof/vc_jwt.py:75-92`; `proof/_jws.py:53` | `test_keys*` |
| I10 | SSRF guard: https-only, forbidden-range block (any address that is not `is_global`, RFC 6598 CGNAT included), redirect refusal, IP-pin | `fetch.py:49-92,126,143-144` | `test_fetch*`, `test_did_web_hostile_host.py` |
| I11 | Status decompression bounded at 16 MiB, incremental | `status/_decompress.py:23,38-66` | `test_status_decompress.py:46-82` |
| I12 | CBOR depth ≤ 64; JCS depth ≤ 100; duplicate map key rejected | `cbor.py:69,229-232`; `proof/_jcs.py:18` | `test_cbor.py:104,152`; `test_di_jcs.py:388` |
| I13 | Trust-list XML refuses DOCTYPE (XXE + expansion closed) | `trustlist/parse.py:108-120` | `test_trustlist.py:104,121` |
| I14 | Every internal failure subclasses `OpenvcError` and re-raises typed | `verify.py:105-123,320-322` | `test_hostile_input.py`, `test_typed_error_unhashable_header.py`, `test_typed_error_deep_headers.py`, `test_typed_error_vc_shape.py`, `test_unhashable_proof_purpose.py`, `test_status_index_hostile.py`, `test_did_web_hostile_host.py`, `test_did_document_shape_typed.py`, `test_typed_clock_pins.py`, `test_cose.py` (`test_a_non_integer_crit_label_is_cose_malformed_not_typeerror`), `test_vc_jwt_numeric_dates.py`, `test_sd_jwt_kb_freshness.py`, `test_ebsi_verifier.py` (`test_verify_ebsi_badge_unparseable_attributes_url_is_openvc_error`, `test_verify_ebsi_badge_hostile_iss_is_typed_before_any_request`), `test_ebsi_http.py`, `test_lone_surrogate_typed.py`, `test_ecdsa_sd_derived_proof_shape.py` |
| I15 | `verify_many` isolates per-credential — one bad item never aborts the batch. A hostile DID-document shape — valid JSON, wrong structure — served for an unsigned token's own `did:web` issuer used to abort the batch; `parse_did_document` now raises `DidResolutionError` (#219, fixed in v1.32.3) | `verify.py:458-465` | `test_hostile_input.py` (`test_verify_many_isolates_a_non_string_kid`, `test_verify_many_isolates_a_non_object_payload`, `test_verify_many_isolates_a_deeply_nested_sd_jwt`, `test_verify_many_isolates_deeply_nested_across_formats`); the batch tests in `test_typed_error_unhashable_header.py`, `test_typed_error_deep_headers.py`, `test_typed_error_vc_shape.py`, `test_unhashable_proof_purpose.py`, `test_status_index_hostile.py`, `test_did_web_hostile_host.py`, `test_typed_clock_pins.py`; `test_did_document_shape_typed.py` (`test_verify_many_isolates_every_hostile_document`, `test_verify_many_async_isolates_every_hostile_document`); `test_vc_jwt_numeric_dates.py` (`test_verify_many_isolates_malformed_numeric_date`); `test_lone_surrogate_typed.py` (`test_rdf_batch_isolates_the_hostile_item`, `test_status_list_second_hop_raises_data_integrity_error`, `test_ecdsa_sd_row2_attacker_chosen_mandatory_indexes_raise_proof_malformed`, `test_ecdsa_sd_row3_edited_disclosed_statement_raises_proof_malformed`, `test_webvh_update_key_surrogate_through_the_pipeline`); `test_ecdsa_sd_derived_proof_shape.py` (`test_hostile_derived_proof_value_is_a_typed_proof_error`) |
| I16 | Hostile deeply-nested input fails closed **pipeline-wide**: every untrusted JSON parse goes through one loader that refuses nesting past **100** (`openvc._json`; 3.14's `json.loads` parses ~116k levels while `repr()` / `==` overflow far sooner), objects handed over already parsed (credential / `vp_token` dicts, DI suite input, injected-fetch DID documents and issuer metadata, RP DCQL) are held to the same bound, the pipeline maps any residual `RecursionError` to a typed error, and SD-JWT `_unpack` / JCS / did:webvh SCID walk stay capped at 100 | `_json.py`; `proof/sd_jwt.py:66,129`; `verify.py`, `aio.py`, `openid4vp.py`, `proof/vc_jwt.py`, `proof/_jws.py`, `proof/_verify_common.py`, `jwe.py`, `did/base.py`, `did/did_jwk.py`, `did/did_webvh.py`, `jwt_vc_issuer.py`, `fetch.py`, `resolvers.py` | `test_hostile_input.py`, `test_did_webvh.py`, `test_typed_error_deep_nesting.py`, `test_typed_error_vc_shape.py` (`test_deeply_nested_cryptosuite_is_typed`) |
| I17 | An OID4VCI key proof is pinned to `typ: openid4vci-proof+jwt` and must carry **exactly one** of `jwk`/`kid`/`x5c`/`trust_chain`, with the key bound to the header `alg`'s (kty, crv) | `openid4vci.py:676,752,855` | `test_openid4vci.py`, `test_openid4vci_vectors.py` |
| I18 | Key-proof `iat` freshness is enforced in **both** directions (stale *and* future-dated, non-finite rejected), and the nonce is consumed **exactly once per request, after every signature verifies** | `openid4vci.py:915,917,655` | `test_openid4vci.py`, `test_openid4vci_vectors.py`, `test_sd_jwt_kb_freshness.py` (the freshness helper, `check_iat_freshness`, is shared with the SD-JWT KB-JWT) |
| I19 | A key proof carrying a `key_attestation` must be signed by one of its `attested_keys` (OID4VCI App. D), compared by RFC 7638 thumbprint. **Not an attacker control** — the attestation's signature is never checked here, so a forger attests their own key; this catches an honest wallet, or the caller's own `resolve_proof_key*`, yielding a key the wallet never claimed, and can only reject, never accept | `openid4vci.py:833` | `test_openid4vci.py`, `test_openid4vci_vectors.py` |
| I20 | An RDF Data Integrity document is accepted, and signed, only in the compacted form of its own expansion under the VC base context plus loader-served URLs or absolute-IRI `@vocab`-only objects — no `@included`/`@reverse`/`@index`/`@direction`, no nested re-description of the document node, no array directly inside an array (outside a `@list` of lists, which compaction emits nested too), every key or `type` value that stands for an IRI any loader-served context (bundled or `extra_contexts`, listed by the document or not, so a dropped context cannot be respelled through an inline `@vocab`) defines a term for spelled as that term (as the VC base context's own term when it defines one, so an injected alias is refused), every top-level `type` value that is a served term standing for one of that term's IRIs, no entry of the top-level `credentialStatus` also described anywhere else other than as an exact copy (a nested node's `credentialStatus` included), on `ecdsa-sd-2023` the same blank-node identity for the signature as for the JSON (an injective derived-proof label map, and the presented document canonicalized without deskolemizing `urn:bnid:` IRIs), and nothing the RDF conversion drops (safe mode: every node id, type and property a well-formed absolute IRI, no blank-node property) — so every JSON member the policy reads is one the signature covers. The status check refuses a non-object `credentialStatus` array member and a typeless entry rather than skip them, and `expected_types` is matched by IRI against the expanded types, each name resolved through the served contexts only (GHSA-h9rq-wxcw-4rjc, v1.33.1) | `proof/_context_validation.py` (`validate_document`, `_check_compacted`, `_normalize`, `_term_index`, `_inline_vocabs`, `_misspelled_key`, `_is_misspelled`, `_hijacked_type`, `_check_status_in_place`, `missing_types`, `_trusted_iris`); `verify.py` / `aio.py` (`_check_di_types`); `proof/contexts/__init__.py` (`document_loader`'s `contexts`); `status/status_list.py` (`_as_entry_list`, `parse_status_entries`); `proof/data_integrity.py:184,236`; `proof/di_ecdsa_rdfc.py:149,205`; `proof/ecdsa_sd.py:563,749` (`decode_derived_proof`, `verify`, `_reveal_view`) | `test_di_context_validation.py`, `test_ecdsa_sd_interop.py` (`test_an_iri_id_on_a_signed_blank_node_is_rejected`), `test_ecdsa_sd_derived_proof_shape.py`, `test_status.py` (`test_non_object_status_member_is_refused_not_skipped`, `test_typeless_status_entry_is_refused_not_skipped`), `test_contexts.py` (`test_loader_lists_what_it_serves_read_only`) |
| I21 | WRPRC authorization fails closed: the WRPRC `sub` must equal the WRPAC entity identifier (absent on either side is a failure, never a match), and a DCQL request is authorized only if every credential query (a) has at least one registered entry with the same non-blank string `format` and a `meta` that covers the query's, (b) names at least one claim — a query naming none asks for every attribute and is always refused — and (c) has every requested claim path inside the union of the grants of the entries so matched; an entry with an empty grant, or registered for a different `meta`, contributes nothing. Grant-side spelling precedence is narrow and decided by key presence (`claim` over `claims`, never their union), while the request side reads the union | `check_matches_access_certificate`, `check_request_within_registration`, `_registered_paths` (`rp_registration.py`) | `test_rp_registration.py` |
| I22 | A JWS header extension marked `critical` is never ignored: the shared `reject_unknown_crit` refuses any `crit`; the two JAdES lanes (the LoTE verifier and the WRPRC lane) allow-list `{alg, typ, x5c, iat}` and refuse the rest; and there is **one documented exception** — the WRPRC lane alone also understands exactly `sigT` and `b64` (v1.36.0, #134; the real registrars list both). In the WRPRC lane `crit` must be a non-empty array of unique strings, each name present in the header and in `{alg, typ, x5c, iat, sigT, b64}`; `b64` must be the JSON boolean `true` (`false` is an unencoded payload, a signing input the verifier does not build) and `sigT` an RFC 3339 UTC `Z` time, each checked **whether or not `crit` names it**; `sigT` is surfaced as `claimed_signing_time` (JWT form only: a CWT's COSE protected header is not value-checked and the property is `None`) and never decides validity. The shared check and the LoTE verifier are untouched in behaviour and still refuse both names | `reject_unknown_crit` (`proof/_verify_common.py`); `_reject_unknown_crit` (`trustlist/lote.py`); `_reject_unknown_crit`, `_check_understood_params`, `_check_b64`, `_parse_sig_t` (`rp_registration.py`) | `test_jws_crit.py` (`test_*_still_refuses_sigt_and_b64`, `test_the_wrprc_lane_alone_accepts_sigt_and_b64`), `test_rp_registration.py` (the `sigT`/`b64` section), `test_rp_registration_real_artifacts.py` |

## 9. Residual risks & known limitations

The honest register. No open item is a wrong-accept that openvc's own checks could
catch (I1–I7, I20, I21 and I22 hold); the open items are **availability /
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
  **withheld** one leaves the credential verified as if it had none. An `aud` the issuer
  made disclosable is the same case since #227: disclosed, it is enforced; withheld, it is
  unseen. A disclosable
  `cnf` is never read: key binding uses only the issuer-signed body's `cnf`, so any
  KB-JWT presented against it is refused and a KB-stripped presentation verifies with
  `key_bound=False`. **Narrowed in #229:** `SdJwtVcProofSuite.issue` refuses to make
  `iss` / `nbf` / `exp` / `cnf` / `vct` / `vct#integrity` / `aka_vcts` / `status`
  (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3), `credentialStatus` and `@context` (plus
  the VCDM validity window on a VCDM payload) selectively disclosable through
  `disclosable` (digests a caller writes into `claims` itself are signed as given).
  `verify()` rejects (`SdJwtError`) a
  presentation that presents such a disclosure, or one of its sub-claims, and a
  `dc+sd-jwt` that has no `vct` (`ClaimsInvalid`, whatever its `@context`, #272:
  draft-19 §2.2.1 makes that typ mean the SD-JWT VC rules, so a VCDM `@context` does
  not waive the REQUIRED `vct`). A `vc+sd-jwt`, a draft-era `vc+ld+json+sd-jwt` or a
  token with no `typ` (#288, #289) is accepted only as a conforming VCDM payload (a base
  context first in `@context`, a `type` that says credential: #275), so without one it is
  an `SdJwtError`, a holder's withheld `type` included, and the typ alone never makes a
  payload VCDM (#264).
  What remains is the **withheld**
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
  **Follow-up, resolved in v1.33.1 (GHSA-h9rq-wxcw-4rjc), also a wrong-accept.** The
  comparison folded a one-element array into its element at any depth, so an array
  nested directly in an array — which expansion flattens — passed:
  `credentialStatus: [S1, [S2]]` on the issuer's genuine credential skipped S2's
  revocation bit, and `[[S]]` left no entry (`StatusUnavailable` by luck under
  `require_status`, unchecked without it), on all three RDF suites. Separately, a value
  that does not match its term's definition (an untyped `validUntil` / `validFrom` /
  proof `expires`, a literal `credentialStatus`) compacts under the property's IRI, so
  that spelling passed as the compacted form while the policy read only the term; an
  issuer, openvc's own signers included, could sign a credential that never expired. A
  caller-injected context that gave a core IRI another term hid the member the same
  way, at any length (an uncoerced `until`, or a `statusRef` coerced like
  `credentialStatus` but shorter, which compaction itself prefers). And when the
  issuer's graph also referenced a status entry from another property, the holder could
  move the entry's description there and leave `{"id": X}` under `credentialStatus`
  (the same dataset as the bare `X`), which the status parser skipped as an unrelated
  type; another node's `credentialStatus` served as a destination too. Finally, the
  term rule first indexed only the contexts the document listed, which the holder
  edits: dropping an injected status-list context (or moving a v2 credential onto a
  VC 1.1 base the verifier also serves) and spelling the entry through an inline
  `@vocab` kept the dataset and the compacted round trip, and the status parser
  skipped the entry as an unrelated type, under the default policy. Even indexing every
  served context left the IRIs a default verifier serves no term for: re-compacting an
  issuer's VC 1.1 credential onto the bundled v2 base alone spelled `issuanceDate` /
  `expirationDate` by IRI (an expired credential verified), and dropping the
  StatusList2021 context did the same to a `StatusList2021Entry` (skipped under
  `require_status=False`); a served context that gave one of those IRIs a term of its
  own hid it too, since the base-context rule covered only IRIs the base defines.
  And `expected_types` compared `type` as JSON text, while the signature covers each
  type's IRI: a holder replaced an issuer's published context with an inline `@vocab`
  ending inside the signed type IRI (`"…/vocab#Alumni"` for
  `…/vocab#AlumniDegreeCredential`) and wrote the type as `"DegreeCredential"`, which
  met a pin on that name on a default verifier and on one serving a context that
  defines it as another IRI. On `ecdsa-sd-2023` the move check itself could be
  bypassed: the verifier took blank-node identity for the signature from the holder's
  label map, never required to be injective, and deskolemized every `urn:bnid:` IRI in
  the presented document, while the check reads the JSON. Two JSON nodes the
  signature saw as the issuer's one id-less status entry (`_:s`, named from
  `relatedResource` too) let the holder move it and verify a revoked credential under
  `require_status=False`; the same deskolemization put a holder-chosen `urn:bnid:` IRI
  id on any node the issuer signed as a blank node (the reported subject, on the W3C
  vectors).
  **Fixed:** the fold applies to a property value only and never to an array element;
  every key or `type` value that stands for an IRI any context the loader serves
  (bundled or `extra_contexts`, listed by the document or not) defines a term for must
  be the term, and the VC base context's own term when it defines one; an IRI the
  policy reads (the validity window, the proof's `expires`, `credentialStatus`,
  `credentialSchema`, and both status-list families' entry types and members) must be
  the one key the policy reads it under, whatever the loader serves; an entry under
  the top-level `credentialStatus` described anywhere else in the document, a nested
  `credentialStatus` included, is refused unless that description is an exact copy of
  the entry (equal expanded node objects, which RDF merges into the entry's own
  statements: an OB 3.0 endorsement may repeat the outer `credentialStatus`); on
  `ecdsa-sd-2023` a derived proof's label map must be injective and the presented
  document is canonicalized as is, so blank-node identity is the same for the
  signature and for that check; and the status parser refuses a non-object
  array member and an entry with no `type`; a top-level `type` value that is a served
  term must stand for one of that term's IRIs; and on the RDF suites `expected_types`
  is matched by IRI, each name resolved through the served contexts, never the
  document's own `@context` (I20). A type only an inline `@vocab` names now meets a
  bare-name pin only when the verifier serves a context naming it, or by full IRI.
  **Residual:** code that reads `type` from the JSON, for a name no served context
  defines, can still be shown a suffix of a signed type IRI; `expected_types` is not.
  **Residual:** `ecdsa-sd-2023` relabels blank nodes by text substitution over each
  N-Quad, as the reference implementation does, so a `_:c14nN`-shaped substring inside
  a signed literal or IRI is relabeled too, and the label map's keys, which the holder
  writes, decide its spelling. Such text is not bound to its exact spelling. It needs
  an issuer to sign a value that contains such a substring.
  **Residual:** a node the issuer's own graph references from several places may be
  described in any of them (RDF semantics). Only the document node is pinned to the
  top level, and a top-level `credentialStatus` entry to it; any other node may
  still move. For example, when the issuer also names a `credentialSchema` entry from
  `relatedResource`, its `digestSRI` can be moved there and the schema is then fetched
  unpinned (a `{"id": X}` left behind fails closed: the entry needs a type). Pinning
  every policy-read entry the same way would refuse the VCDM pattern of restating a
  schema's digest under `relatedResource`. A `credentialStatus` left as a bare
  reference, `{"id": X}` or an `@list` object fails closed (`StatusListError`, whether
  alone or inside an array, under either `require_status`). A compacted
  `{"@list": [...]}` under a term not declared `@list` (only an issuer can sign one)
  still passes the validation; the status check refuses it, but under another policy
  member it is a shape the policy cannot read. The term rule is a superset that ignores
  which served contexts a document lists and where a scoped term is in scope, so an IRI
  any served context defines is refused under any other spelling, even in a document
  that never lists that context and at a node where that term is not active (a
  subject's `dcterms:created` or `sec:nonce`, both terms only inside the base context's
  `DataIntegrityProof` scope); a verifier with many `extra_contexts` sees more such
  refusals, and one it cannot read refuses every RDF credential. An `@json` value whose
  top-level array holds arrays is refused, because pyld compacts it lossily. All fail
  closed. A served term defined without `@id` is indexed under the `@vocab` values the
  served contexts set and the inline `@vocab` in effect where the document lists a
  context (and the last one); one an issuer's inline `@vocab` gave it, which the holder
  has since dropped, is not. No IRI the policy reads is defined that way.
  Caller-supplied `extra_contexts` are otherwise trusted: a term one defines for an IRI
  the VC base context does not define, and the policy does not read, is taken as that
  IRI's spelling.
  They are scoped to the call, though: since v1.27.1 only the bundled contexts are
  tagged `static` in pyld's process-global cache, so one caller's injected document
  never governs another caller's canonicalization through a URL it serves (#185). Since
  v1.35.0 every pyld call also gets a resolver of its own (`pyld_options`, #225), so an
  inline context that `@import`s a URL, in the document or in a context a caller serves,
  is no longer cached for the next caller either; the only entry kept across calls is the
  resolution of a bundled context, which references no other URL.
- **R10 — Untyped exits at the verification boundary. ✅ Resolved in v1.33.1
  ([#219](https://github.com/luisgf/openvc/issues/219) in v1.32.3,
  [#279](https://github.com/luisgf/openvc/issues/279) in v1.33.0, then the
  `ecdsa-sd-2023` derived proof value in v1.33.1).** In v1.32.3 these were the last
  known attacker-controlled inputs that escaped `OpenvcError`, so that I14 did not hold for
  them; that claim was too strong, and a second class is listed below. (Caller
  configuration was a separate class: a string or `None` `leeway_s` raised a bare
  `TypeError` on the VP-JWT, status-list-token and `check_jwt_temporal` lanes, and `NaN`,
  `Infinity` or a huge value switched expiry off on VC-JWT, VP-JWT, the status-list token
  and Data Integrity. Closed in v1.35.0
  ([#228](https://github.com/luisgf/openvc/issues/228) /
  [#232](https://github.com/luisgf/openvc/issues/232)): `leeway_s` is a whole number of
  seconds from 0 to one day, refused with a typed error at every entry point.) Three EBSI exits
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

  **A second class, found after v1.32.3 and resolved in v1.33.0 (#279).** JSON allows
  `"\ud800"`, an escape for a lone UTF-16 surrogate; `json.loads` and `openvc._json.loads`
  return a `str` holding it, and no UTF-8 form exists. Where openvc ran `.encode("utf-8")` on
  attacker text outside a guarded block the result was a bare `UnicodeEncodeError`, which
  aborted a whole `verify_many` / `verify_many_async` batch (I15). Eight sites, none a
  wrong-accept: every one failed closed, untyped. The Data Integrity canonicaliser (since
  v0.1.0, shared by `eddsa-rdfc-2022` and `ecdsa-rdfc-2019`, reached with no key because the
  hash is computed before the key is resolved, and again through `verify_vp_token`, a
  VP-JWT carrying an `ldp_vc`, the issuer side and the status-list second hop); `ecdsa-sd-2023`
  verify (holder-chosen `mandatory_indexes`, again no key) and `add_base_proof`; a
  `did:webvh` `updateKeys` entry under pre-rotation (since #90); the OpenID4VCI `proofs`
  entry, `peek_proof_header` and `peek_key_attestation` (since #144); and
  `jwk_thumbprint_bytes`. Only a *named* node's statement reaches the encode: pyld hashes a
  blank node's inside the guarded `normalize`, which is why a fixture built on a subject
  without `id` passed on `main` and proved nothing. **Fixed:** each site raises its lane's own
  class (`DataIntegrityError`, `ProofMalformed`, `DidWebvhError`, `CredentialRequestMalformed`
  / `MalformedToken`, `InvalidKey`, which the OpenID4VCI key-proof reports as `ClaimsInvalid`),
  with a message that names the code point and its index and never the text. The string is
  never repaired, so two different inputs never encode to the same bytes (I14, I15;
  `test_lone_surrogate_typed.py`). **Residual:** the JOSE lanes still accept a surrogate the
  issuer signed, as the verified bytes are what was signed; refusing it where the JSON is
  parsed was weighed and left out (a behaviour change on those lanes, and it would not cover
  a dict a caller parsed with plain `json.loads`).

  **A third site, found after v1.33.0 and resolved in v1.33.1.** `decode_derived_proof`
  checked only that an `ecdsa-sd-2023` derived proof value was a five-element CBOR array,
  so a part of another CBOR type reached the verifier: a text-string, integer or map
  `public_key` was a bare `TypeError` before the issuer's key was resolved (no key, no
  signature), an array or text-string label map an `AttributeError` the surrounding
  `except` did not list, and an integer `signatures` a `TypeError` after the genuine base
  signature. Each escaped `verify_credential` / `verify_credential_async` and aborted a
  `verify_many` / `verify_many_async` batch; none was a wrong-accept. **Fixed:** each part
  is typed at decode (byte strings, an array of byte strings, a map of unsigned integers
  to byte strings, an array of unsigned integers) and anything else is
  `ProofValueMalformed`; `AttributeError` joined the backstop (I14, I15;
  `test_ecdsa_sd_derived_proof_shape.py`).

- **R11 — SD-JWT / VC-JWT lane residuals. One open, documented.** Two caveats at the seam
  between the SD-JWT lane and the VC-JWT lane, each pinned or recorded where it lives;
  the second is closed.
  1. **A zero-disclosure SD-JWT issuer JWT can still be stripped into a VC-JWT (#291).**
     `VcJwtProofSuite.verify` refuses a JWS typed as an SD-JWT issuer JWT or a KB-JWT
     (#189) and one whose payload carries an SD-JWT marker (`_sd`, `_sd_alg`, `...`) at any
     depth (#291), before the signature is checked. A zero-disclosure issuer JWT with no
     `typ`, a `vc` object and a `cnf` carries none of `_sd`, `_sd_alg`, `...`, so it cannot
     be told from a VC-JWT that carries a `cnf`. With its `~` tail dropped it still verifies
     as a VC-JWT, without key binding, because the VC-JWT lane never enforces `cnf`. An
     issuer would have to sign a hybrid no spec defines. Pinned as a limitation in
     `tests/test_vc_jwt_sd_fence.py`; whoever closes it has to change that test.
  2. **Closed in v1.35.0 (#227): the issuer JWT's `aud` on the SD-JWT lane.** It used to be
     unchecked, so an SD-JWT VC its issuer restricted to one relying party verified for
     every verifier, and for a holder presenting it, bound, to another. RFC 7519 §4.1.3 is
     now enforced when the issuer JWT carries `aud` (ADR-0008 D4; an issuer JWT without
     one is unchanged). The W3C VC-JOSE-COSE JWS with no `iss` and no `typ` that #290 lets
     reach this lane once a `~` is appended is held to it too. What stays invisible is an
     `aud` the issuer made disclosable and the holder withheld, the R7 limit
     (`test_sd_jwt_issuer_aud.py`).
- **R12 — A signed EBSI node list authenticates the operator, not the registry's data.
  Open, documented.** EBSI Core API v1 has no fixed production host: a client picks a node
  from an OpenPGP-signed Trusted Nodes List
  ([ADR-0009](../adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md), D7). Registry
  responses (DID documents, issuer records, accreditations) are unsigned JSON from
  whichever node answers, so a dishonest listed node can serve another key for a DID, or
  forged accreditations, and `openvc_ebsi` verifies against them. The list narrows "any
  host on the internet" to the listed nodes and no further. The mitigation is comparing
  trust-critical reads across nodes: a consumer policy with a cost (twice the requests,
  against EBSI's documented 20 requests per second per IP), which openvc does not provide. The chain's real root is the single key-list key
  (a stopgap, per the list's own README): with it an attacker substitutes the custodians and
  the threshold and signs any list, and the two-custodian threshold protects only against
  compromise of the custodians. DNS or certificate compromise of one listed host is not
  defended either (R4), and a hand-built allow-list has no expiry bound. Not a defect in
  `src/`, which builds no node set from the list yet: a boundary the recipe states, in
  [EBSI node trust](https://github.com/luisgf/openvc/wiki/EBSI-Node-Trust).

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
