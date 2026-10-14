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
  batch-isolation of a hostile item (`test_hostile_input.py:51-85`); malformed
  `exp`/`nbf`/`iat` (`null`, containers, strings, bools, non-finite) typed and
  batch-isolated on every entry point, with and without the expiry waiver
  (`test_vc_jwt_numeric_dates.py`); a future `iat` and a non-string `sub`/`jti` on
  both the classic and the ML-DSA lane, and the exclusive `exp` boundary
  (`test_jose_temporal_claims.py`); an `aud` that does not name the caller's
  audience, or any `aud` when none is given (RFC 7519 §4.1.3), and an expected
  audience that is not a non-empty string, on both lanes (`test_vc_jwt_audience.py`);
  a non-string header `kid`, an array/object `alg` on every JOSE lane, SD-JWT issuer
  `typ` / `_sd_alg`, key-proof `typ` and `ldp_vc` holder-proof `cryptosuite`, and a
  credential `type` of `null`, a number or a bool, each typed and batch-isolated
  (`test_hostile_input.py`, `test_typed_error_unhashable_header.py`,
  `test_typed_error_vc_shape.py`).
- **SD-JWT** — unreferenced/forged/duplicate disclosure, wrong key, expired,
  `vct` mismatch, KB `aud`/`nonce`/`sd_hash` tamper, non-numeric `exp`/`nbf`
  (`test_sd_jwt.py:118-333`); malformed issuer-JWT `exp`/`nbf`/`iat` (`null`
  included) and a future or malformed disclosed `iat`, on every entry point with and
  without the expiry waiver; a KB-JWT's own expired, future, malformed or `null`
  `exp`/`nbf` (`test_jose_temporal_claims.py`); a KB-JWT `iat` that is missing,
  non-numeric, non-finite, stale or future-dated, at a pinned or a naive `now`
  (`test_sd_jwt_kb_freshness.py`); a KB-JWT checked against only `aud` or only `nonce`
  (`test_sd_jwt_kb_half_binding.py`); an expired `exp` that was selectively disclosed
  (`test_sd_jwt.py`); a W3C `vc+sd-jwt` payload past its `validUntil`, or naming an
  `issuer` other than `iss` (`test_sd_jwt_vcdm_validity.py`,
  `test_sd_jwt_vcdm_consistency.py`).
- **VP-JWT** — malformed `exp`/`nbf`/`iat` (`null` included) and a future `iat` on
  the presentation itself, under any `policy` (`test_jose_temporal_claims.py`); a
  scalar `vp.verifiableCredential` (`test_typed_error_vc_shape.py`); a pinned holder
  key with no resolver, where the pinned key still decides the signature
  (`test_vp_jwt_pinned_holder_no_resolver.py`).
- **Data Integrity** — published W3C eddsa/ecdsa vectors are tamper-evident,
  cross-curve/wrong-key/wrong-cryptosuite fail-closed, RFC 8785 non-finite
  rejection, canonicalize depth guard (`test_di_jcs.py:190-426`); an array/object
  `proofPurpose` (`test_unhashable_proof_purpose.py`); a clock pin that is not an
  instant (`test_typed_clock_pins.py`); an injected URL context never reaching another
  caller's canonicalization (`test_contexts.py`; the inline-`@import` path is #225,
  open).
- **ecdsa-sd** — CBOR bool/negative/trailing/non-P256/wrong-header, tampered &
  over-disclosed values, unknown `@context` → typed (`test_ecdsa_sd*`).
- **mdoc** — tampered item/digest/`issuerAuth`, malformed & non-CBOR response,
  expired MSO, untrusted IACA, DS without EKU, device-MAC/transcript mismatch,
  wrong-origin `vp_token` (`test_mdoc.py:77-450`).
- **COSE** — wrong key, tampered payload, non-allow-listed alg before crypto,
  detached/attached conflict, missing alg, `crit` labels (`test_cose.py:72-212`);
  an array or map `crit` label typed as `CoseMalformed`, and a `true` label never read
  as `alg` (`test_cose.py`).
- **JWE** — tampered ciphertext, non-ECDH-ES alg, disallowed `enc`, `zip`/`crit`
  rejected, bad `epk`/IV, oversize (`test_jwe.py:167-294`).
- **Status** — bad encoded list, hostile `type`, value overflow, compression
  bombs at the cap boundary (`test_status*`, `test_status_decompress.py`); a
  status-list token `exp`/`nbf`/`iat` that is not a finite number (`NaN`,
  `Infinity`, `1e400`, `null`), a future `nbf`/`iat`, and the window judged at a
  pinned `now` (`test_jose_temporal_claims.py`); a hostile status-list index
  (`Infinity`, `1e400`, a bool, a float, a negative or ≥ 2^27 value, a non-ASCII
  digit string) typed and batch-isolated, with and without `require_status`
  (`test_status_index_hostile.py`).
- **Trust / XML** — wrong cert, tampered body, DTD/DOCTYPE entity bomb, external-
  entity XXE, oversize, forged national TL (`test_trustlist*`).
- **did:web / guarded fetch** — a hostile `did:web` / `did:webvh` host (a bad port, an
  unbalanced bracket, an NFKC delimiter, an `@` / `/` / `#` decoded into the host, an
  over-long IDNA label or name, Unicode, an IPv4 number in any form, a NUL) typed
  before any fetch, the caller's own included; a malformed, non-ASCII or
  over-long-host URL refused before DNS; the original six shapes and a did:webvh one
  batch-isolated on `verify_many` / `verify_many_async`, and a 50k-character Unicode
  host on `verify_many_async` in under 2 s (`test_did_web_hostile_host.py`). RFC 6598
  CGNAT refused (`test_fetch.py`).
- **DID-document shape** — a document that is valid JSON but the wrong shape (a `null`,
  scalar, string or object where `verificationMethod` or a relationship must be an
  array, a `didDocument` wrapper or a whole document that is not an object, a method
  whose `id` is not a string, a string relationship read one character at a time)
  typed `DidResolutionError` and never read as undeclared, through `did:web` (sync and
  async), a forged `did:webvh` log and the EBSI registry; one good credential
  verifies beside every bad one on `verify_many` / `verify_many_async`
  (`test_did_document_shape_typed.py`).
- **Issuer key resolution (https `iss`, x5c)** — an `iss` that Python and a WHATWG
  parser read as different hosts (userinfo, a backslash, an IDN, a `%`-encoded host,
  port 0, dot segments, `;?#`) refused before the `/.well-known/jwt-vc-issuer` fetch,
  and never binding an x5c `dNSName`; a non-string `iss` typed
  (`test_https_issuer_identifier.py`).
- **EBSI TIR (plugin)** — an `attributes` URL or a revision `href` on another port of
  an allow-listed host is never fetched; a URL that does not parse (a bad port, a
  broken IPv6 literal) or that is not visible ASCII or over 8 KiB, on `attributes`,
  `links.next` or `href`, is typed or skipped, never fetched (`test_ebsi_verifier.py`).
  The client refuses such a URL, typed, before any request; a hostile token `iss`
  through `verify_ebsi_badge` included (`test_ebsi_http.py`, `test_ebsi_verifier.py`).
- **OpenID4VP `vp_token` (W3C lanes)** — a victim's credential re-wrapped in another
  holder's correctly bound `jwt_vc_json` / `ldp_vc` VP, including a KB-stripped
  SD-JWT VC, enveloped or over the DC API; a nested SD-JWT VC whose KB-JWT names
  another `aud` / `nonce`; a credential-less `jwt_vc_json` answer; a non-boolean
  `require_cryptographic_holder_binding` (`test_openid4vp_w3c_holder_binding.py`,
  `test_nested_sd_jwt_kb_binding.py`, `test_typed_error_vc_shape.py`).
- **Relying-party certificates (WRPRC authorization)** — a WRPAC↔WRPRC bind on an
  absent identifier; an unregistered format or claim; `meta` not covered; a claim
  borrowed from an entry registered for a different `meta`; a grant widened by a
  second `claim` / `claims` spelling or by a present but empty `claim`; a decoy claim
  key narrowing a request (the request side of #89's CRITICAL); a registered array
  index read as the array wildcard; a request naming no claims; a format-less entry
  matching a format-less query (`test_rp_registration.py`).
- **Expiry waiver** — under `require_not_expired=False`, `expired` equals the default
  policy's expiry verdict on both pipelines and every suite, and a schema credential
  inherits no waiver (`test_expired_flag_parity.py`).
- **OpenID4VCI key proofs** — a KB-JWT / VP-JWT / status-list token replayed as a
  key proof, non-allow-listed alg before crypto, unknown `crit`, two or zero header
  key parameters, key↔`alg` mismatch, wrong/multi-valued `aud`, `iat` stale *and*
  future-dated, nonce replay and a repeated key across a batch; and, for key
  attestations, a proof key absent from `attested_keys` on every key source, a
  non-fixed-width JWK that thumbprints differently, and a malformed attestation whose
  `InvalidKey` must not escape the module's taxonomy (`test_openid4vci.py`).
  Pinned additionally against material openvc did not mint: the spec's own signed
  App. F.1 proof under a frozen clock, its §8.2 request shapes, its App. D key
  attestation, and Issuer Metadata and Credential Offers recorded from the EU
  reference issuer
  (`test_openid4vci_vectors.py`, `tests/fixtures/openid4vci/README.md`).

## 4. Adversarial-review history

openvc lands security work through its own PRs with adversarial review. History by
theme, most recent first: entries up to 2026-07-29 are keyed by short commit hash,
later ones by issue number or advisory id, with their failure class. The 2026-07-10
waves (milestones #9–#10) were the broadest sweeps; the per-issue fixes since
(v1.25.0–v1.31.2) are filed by theme below.

**July 2026 hardening waves (milestones #9–#10)**
- `90404f9` — depth wave: mdoc DS/IACA profile, status-issuer binding, XAdES &
  async hardening (#112) · 24 files / +773
- `f4a02cf` — correctness & fail-closed wave: typed-error boundary, codec
  strictness, resource limits (#111) · 36 files / +930
- `eb0adc5` — deterministic signature-tamper regressions in schema/aio

**Typed-error / fail-closed boundary**
- `#257` — *contract gap, no wrong-accept* — `DidEbsiResolver.resolve` returned whatever `parse_did_document` made of the registry body and compared nothing, so a document whose `id` was another DID, a number, `null`, a list, empty or absent still resolved (bare or in a `didDocument` wrapper) and `key_by_kid` found its keys, where `did:web` and `did:webvh` reject the same document; a DID URL passed as the DID resolved too, because httpx drops the fragment, and so did the document an unsigned token's `iss` `did:ebsi:zA/../did:ebsi:zB` steered the request to. The resolver now compares the parsed document's `id` with the requested DID, exactly, and raises `DidResolutionError` (`EbsiVerificationError` from `verify_ebsi_badge`, `AccreditationInvalid` from `verify_trust_chain`) with both values cut by `safe_repr`; an absent, empty or non-string `id` is refused whatever was asked, so even `resolve("")` does not accept it, and the five callers' messages that name a token's `iss`, an accreditation's `accreditedBy` or a `kid` are cut the same way; the check is in the resolver, not the adapter, so a new registry version inherits it. Found by the adversarial review of #251. Not a wrong-accept: the mismatched document still had to hold a key that verifies the token. Not changed here: the DID is put in the registry path unvalidated, and the TIR issuer response's `did` is never read (v1.32.4; `test_ebsi_verifier.py`, `test_trust_chain.py`)
- `#268` — *fail-safe gap, no wrong-accept (defence in depth)* — a Credential Query's `multiple` was read in one place, `_presentation_list`, by truthiness: a truthy non-boolean (`"false"`, `"true"`, `"0"`, `1`, `1.0`, `2`, `[0]`, `{"a": 1}`) opened the query to several Presentations, all verified and returned, while a falsy one (`null`, `""`, `0`, `0.0`, `[]`, `{}`) was read as `false` by accident and never reported, and a query the wallet did not answer (allowed by `credential_sets`) never had it read at all; the query is the verifier's own input and every Presentation still went through the full pipeline, so nothing unverified was accepted, but the single-valued contract of OpenID4VP 1.0 §8.1 was not enforced and a consumer written for one Presentation per query got several. `_index_dcql` now requires `multiple` to be a JSON boolean (an absent one is still `false`; `0`, `1` and `1.0` are not booleans) on every query, answered or not, right after the same check on `require_cryptographic_holder_binding` and before any Presentation is read: `VpTokenMalformed` naming the query; a `dcql_query` with a non-boolean `multiple` verified before and now raises on every response, in both directions (a truthy value used to return several Presentations, a falsy one used to read as `false`). Found while probing for the review of #249 and left out of #254 (v1.32.5; `test_dcql_multiple_boolean.py`)
- `#224` — *fail-open on a malformed query constraint (defence in depth)* — a DCQL `meta` that was `null`, an array or a string, or an explicit `null` `vct_values` / `doctype_value`, read as "no constraint" on `dc+sd-jwt` / `mso_mdoc`, so any SD-JWT VC type or mdoc docType answered the query; the query is the verifier's own input, so this stops a verifier bug widening it, not an attacker. One reader now serves all three formats and raises `VpTokenMalformed`, before the presentation is verified; an absent key is still no constraint (v1.32.3; `test_openid4vp.py`, `test_mdoc.py`). Found by the review of that fix, **#254** — the reader ran only when a query's own presentation came up, so a query the wallet did not answer (allowed by `credential_sets`) was never checked, an earlier query's presentation failure was reported first, and `mso_mdoc` read the constraint after `expected_origins`, `trust_anchors` and the string check while `dc+sd-jwt` read it first; `_index_dcql` now validates every query's constraint (`dc+sd-jwt`, `mso_mdoc`, `jwt_vc_json` / `ldp_vc`) before any presentation is read, answered or not, an unknown format and the keys of another format stay unread, and the `pyld` requirement of `type_values` moved to the point of use so a well-formed one on an unanswered query needs none; a `dcql_query` with a malformed `meta` on a query no wallet answers verified before and now raises (v1.32.4; `test_dcql_meta_upfront.py`)
- `#219` — *batch abort, and a purpose granted by a typo* — a DID document that is valid JSON but the wrong shape (a `null` or scalar `verificationMethod`, a relationship that is not an array, a `didDocument` wrapper that is not an object, a method whose `id` is not a string) raised a bare `TypeError` / `AttributeError` from `parse_did_document`, before the signature check, so one unsigned token naming the attacker's own `did:web` aborted a whole `verify_many` batch; the `did:webvh` state and the EBSI registry shared the parser, and a string relationship was read one character at a time, so `"assertionMethod": "k"` authorized any method whose fragment is `k`; a wrong-typed container is now `DidResolutionError` (`KeyResolutionFailed` on the JOSE lanes and the async API, `KeyResolutionError` on the sync Data Integrity lane), never read as undeclared, and a method or reference without a string `id` is dropped (selected by no `kid` or purpose; a dropped keyed method is not counted by the `kid`-less sole-key fallback, as an undecodable Multikey already was) (v1.32.3; `test_did_document_shape_typed.py`)
- `#230` — *minted what the verifier refuses, and untyped error* — the issuer-side status builders were not held to the rule #215 gave the verifier: `build_status_list_entry` / `build_token_status_reference` emitted a `True`, `3.7`, `NaN` or `2**27` index, a string index raised a bare `TypeError`, and a list past the 16 MiB decompression cap built fine and could never be read back; `get_status_bit(b"\x40", True)` read the bool as bit 1. The builders and the four codec functions now share `status_index` / `packed_length` / `locate_status` in `_index.py`, and all raise `StatusListError` at build time; an `int` subclass is read through `int.__index__`, so the value checked is the value emitted (v1.32.3; `test_status_builders_hostile.py`)
- `#248` — *untyped error* — a corrupt `gzip` / `deflate` body from an allow-listed EBSI registry raised a bare `httpx.DecodingError` (a `RequestError`, not a `TransportError`) out of `get_json` and `verify_ebsi_badge`, on a 200 or on the error drain; now `MalformedRegistryResponse`, not retried. Found by the second adversarial pass on #244 (v1.32.1; `test_ebsi_http.py`)
- `#246` — *untyped error, no key needed* — the EBSI client checked a URL with `urlparse` and fetched it with httpx, which rejects what urlsplit drops or ignores (a tab, NUL, DEL) and a URL over 64 KiB with a bare `httpx.InvalidURL`; an unsigned token whose `iss` held one escaped `verify_ebsi_badge`, and so did such a TIR `attributes` / `next` / `href`. The client now refuses a URL that is not visible ASCII or that `urlparse` cannot read (port included) as `HttpForbiddenHost` before any request, and maps `httpx.InvalidURL` to it; the TIR pin applies the same rule and an 8 KiB cap. Found by the adversarial review of #244 (v1.32.1; `test_ebsi_http.py`, `test_ebsi_verifier.py`)
- `#243` — *untyped error* — an EBSI TIR v5 registry URL that does not parse (a port out of range or not numeric, a broken IPv6 literal, an NFKC delimiter) made the `_origin` pin raise a bare `ValueError` out of `verify_ebsi_badge`; it is now treated as off-origin: a `MalformedRegistryResponse` on `attributes`, skipped on `links.next` and `href`, and a non-ASCII URL is refused before `urlparse` (v1.32.1; `test_ebsi_verifier.py`)
- `#218` — *batch abort* — a clock pin that is not an instant (an epoch number, a string, a `date`, a `datetime` with no UTC equivalent) or a non-numeric `leeway_s` raised a bare `AttributeError` / `OverflowError` / `TypeError` on every datetime validity window (Data Integrity, x5c, mdoc, WRPAC, WRPRC, the trust-list walks); each lane now raises its own typed error (v1.30.5; `test_typed_clock_pins.py`)
- `#200` — *crash on caller configuration* — `VpJwtProofSuite.verify` with a pinned holder key and no resolver raised a bare `AttributeError`, a regression since v1.6.0; the resolver now defaults, and the pinned key alone still decides the VP signature (v1.30.4; `test_vp_jwt_pinned_holder_no_resolver.py`)
- `#208` — *batch abort* — a Data Integrity `proofPurpose` that is a JSON array or object raised a bare `TypeError` on all five suites, before any crypto; it is now `ProofMalformed`, checked before the DID is resolved (v1.30.3, PR #210 — the Data Integrity slice; #208 is still open; `test_unhashable_proof_purpose.py`)
- `#213` — untrusted JSON is depth-bounded (100) where it enters: on 3.14 a value `json.loads` accepts overflowed `repr()` / `==` into a bare `RecursionError` at 40+ sites (messages, status, DID/JWK, issuer metadata), found by a per-position fuzz and two adversarial reviews; one bounded loader, a depth check on pre-parsed input and a pipeline backstop close the class (v1.30.0)
- `#207` — *batch abort, and identity confusion* — a hostile `did:web` / `did:webvh` / https-issuer host (a port out of range, an unbalanced `[`, an NFKC delimiter, an over-long IDNA label, a NUL) raised a bare `ValueError` / `UnicodeError` / `InvalidURL`, before any TCP connection, so not an SSRF; and an `@`, `/` or `#` decoded into a did:web host was read as userinfo or a path, so `did:web:evil.com%40example.com` fetched its DID document from `example.com`. A `did:web` / `did:webvh` host must now be a domain name with an optional port before any fetch, the caller's own included; an https `iss` that `urlparse` cannot read is a `JwtVcIssuerError`, and on the default guarded fetch other host faults are typed before DNS (v1.30.0; `test_did_web_hostile_host.py`)
- `#215` — *batch abort, and silent coercion* — a status-list index is read by one rule: a signed `Infinity` / `1e400` index raised a bare `OverflowError` even under `require_status=False`, and `int()` silently mapped `true`, `3.7` or `"+5"` onto some bit; both are now a typed `StatusListError` (v1.29.2; `test_status_index_hostile.py`)
- `#211` — *batch abort* — an array/object `alg` (every JOSE lane), SD-JWT `typ` / `_sd_alg`, `ldp_vc` holder-proof `cryptosuite` or key-proof `typ` is unhashable, so the allow-list `in` test raised a bare `TypeError`; each check now type-checks first and raises the class a disallowed string gets (v1.29.1; `test_typed_error_unhashable_header.py`)
- `#193` — *batch abort, and a vacuous binding* — a credential `type` or VP `verifiableCredential` of `null`, a number or a bool raised a bare `TypeError`; and a `jwt_vc_json` VP carrying no credential counted the query as answered, letting `require_holder_binding` hold vacuously — now `VpTokenMalformed`, as on `ldp_vc` (v1.28.2; `test_typed_error_vc_shape.py`)
- `74bb5ac` — *untyped error* — a non-ASCII compact SD-JWT raised a bare `UnicodeEncodeError` where its `sd_hash` is computed, in `create_presentation` and on the key-binding-required verify path; now `SdJwtError`. The verify-path case, which would have aborted `verify_many`, was caught by review before any release (v1.27.0; `test_sd_jwt.py`)
- `#175` — *batch abort* — a non-string JOSE `kid` reached `kid.split` and raised a bare `AttributeError`; now `MalformedToken` (v1.25.0; `test_hostile_input.py`)
- `#170` — *batch abort* — a COSE `crit` label that is an array or a map is legal CBOR but unhashable, so it raised a bare `TypeError` before any crypto (mdoc `IssuerAuth` / `DeviceAuth`, the CWT WRPRC); now `CoseMalformed`, and a `true` label is no longer read as label 1, `alg` (v1.25.0; `test_cose.py`)
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
- `#235` — *DoS, and identity confusion* — a `did:web` / `did:webvh` host must be ASCII, at most 253 characters and not an IPv4 number in any WHATWG form: CPython's quadratic punycode encoder let one unsigned credential stall `verify_many_async` (10k CJK characters ≈ 6.6 s), and IDNA2003 resolved `did:web:faß.de` as `fass.de`. The guarded fetch refuses a non-ASCII URL before `urlparse` (v1.31.2; `test_did_web_hostile_host.py`)
- `#172` — *off-port fetch* — the EBSI client's allow-list matches the host, not the port, so the TIR v5 adapter now pins the HATEOAS `attributes` URL and every revision `href` to the listing's `scheme://host:port`, as `links.next` already was (v1.25.0; `test_ebsi_verifier.py`)
- `#156` — *SSRF* — the guard refuses any address that is not `is_global`: RFC 6598 CGNAT `100.64.0.0/10` (and, on current interpreters, its IPv4-mapped form) carries no `is_private` flag and passed (v1.25.0; `test_fetch.py::test_forbidden_ips`)
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
- `#191` — *misleading flag* — a present KB-JWT checked against only `aud` or only `nonce`, or against an empty or non-string value, is refused: it reported `key_bound=True` for a KB-JWT made for another session or verifier, and `nonce=""` cut `require_key_binding=True` down to an audience-only binding. This removes a misleading flag, not the replay: a stripped KB-JWT still verifies with `key_bound=False`, so `require_key_binding=True` stays the control (v1.30.0; `test_sd_jwt_kb_half_binding.py`)
- `#196` — **wrong-accept** — `verify_vp_token` enforces DCQL `require_cryptographic_holder_binding` (default `true`) on `jwt_vc_json` / `ldp_vc`, not only on `dc+sd-jwt`: a verifier that once received a victim's VC-JWT, Data Integrity VC or KB-stripped SD-JWT VC could re-wrap it in its own correctly bound VP and present it as its own (v1.29.0; `test_openid4vp_w3c_holder_binding.py`)
- `#189` — *misleading flag, and a binding downgrade* — an SD-JWT VC nested in a `jwt_vc_json` / `ldp_vc` presentation is held to that presentation's `aud` / `nonce`; it reported `key_bound=True` for a KB-JWT minted for another verifier. Its review added explicit typing (RFC 8725 §3.11): a tail-stripped SD-JWT issuer JWT whose payload carried a `vc` object had verified as a VC-JWT with `key_bound=None`, sidestepping `require_key_binding=True` at top level and nested; a JWS typed `sd-jwt` / `*+sd-jwt` / `kb+jwt` is now refused before key load (v1.28.1; `test_nested_sd_jwt_kb_binding.py`)
- `#186` — *stale key binding (defence in depth)* — a KB-JWT of any age, or with no `iat`, verified (the enforced `aud` / `nonce` already stopped cross-transaction replay); the KB-JWT `iat` is now required and bounded in both directions (`kb_max_age_s`, default 300 s) at the caller's `now`, a naive one read as UTC, through the helper the key proof uses (`check_iat_freshness`); found by the "an hour later" control of a third-party capture (#121). The same change typed a 400-digit `exp` / `nbf` / `iat` that escaped `math.isfinite` (v1.28.0; `test_sd_jwt_kb_freshness.py`, `test_interop_vectors.py`)
- `#182` — *misleading verdict* — with `require_key_binding=True` the KB-JWT is verified before the issuer JWT's `exp` / `nbf`, so an `expired` verdict now means the binding verified; a forged holder key or a wrong `nonce` had read as a temporal failure (v1.27.0; `test_sd_jwt.py`, `test_verify_pipeline.py`)
- `a09f964` — harden VP-JWT verification (replay + holder binding)
- `886db1f` — challenge/domain presentation binding for Data Integrity
- `ee1ecac` — enforce Data Integrity validity window and `proofPurpose`

**Temporal validity & expiry waiver**
- `#229` — **wrong-accept** — `SdJwtVcProofSuite.issue(disclosable=…)` accepted any top-level claim, so a holder who withheld the disclosure of an expired `exp` or a revoked `status` / `credentialStatus` was accepted (a withheld digest is indistinguishable from a decoy, RFC 9901 §9.7). `issue()` now refuses the draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 claims plus `credentialStatus`, `@context` and, on a VCDM payload, the VCDM window. `verify()` rejects a presented disclosure of one or of a sub-claim, and a `dc+sd-jwt` with no `vct`. A third-party issuer's withheld disclosure stays undetectable (R7). The adversarial review found a tuple `@context` slipping past the issue-time VCDM verdict, fixed before merge (v1.32.2; `test_sdjwt_non_disclosable.py`)
- `#231` — **wrong-accept** — one RFC 7519 NumericDate rule (`check_jwt_temporal`) across the SD-JWT VC issuer JWT and KB-JWT, the VP-JWT, the ML-DSA VC-JWT, the status-list token and the key proof: a status-list token dated a year ahead verified, and a KB-JWT's own `exp` / `nbf` were never read. Both VC-JWT lanes now enforce `aud` (RFC 7519 §4.1.3), so a token addressed to another relying party no longer verifies for a caller that names none. Bounding `leeway_s` is #228, still open (v1.30.5; `test_jose_temporal_claims.py`, `test_vc_jwt_audience.py`)
- `#198` — **wrong-accept** — a W3C credential secured as SD-JWT (`vc+sd-jwt`) is held to its own `validFrom` / `validUntil`: the lane read only `exp` / `nbf`, so a past `validUntil` verified under the default policy. Its review also made the shared window compare differences: a huge `leeway_s` had raised a bare `OverflowError` that aborted `verify_many` on VC-JWT and Data Integrity (v1.30.1; `test_sd_jwt_vcdm_validity.py`)
- `#203` — *misleading flag, and a schema trust input under the wrong waiver* — under `require_not_expired=False`, `expired` was re-derived with other clocks and fields than the suites enforce, so a lapsed Data Integrity `expires` or a VC-JWT `exp` on the boundary second read `False`; each suite now reports the expiry it waived. The default policy's verdict on the credential itself was never affected. The schema half was closer to a wrong-accept: an expired `JsonSchemaCredential` was applied with `schema.validated=True` under a waiver meant for the outer credential, and a schema trust input now inherits neither waiver (v1.30.0; `test_expired_flag_parity.py`)
- `#188` — *misleading flag* — the async pipeline never set `expired` under the waiver; the default policy's verdict was never affected, and #203 later replaced the mechanism (v1.28.0; `test_expired_flag_parity.py`)
- `#174` — **wrong-accept** — SD-JWT VC applies `exp` / `nbf` to the processed payload too (RFC 9901 §7.1 step 6): an expired `exp` the issuer had made selectively disclosable was ignored when disclosed. A holder who *withholds* that disclosure is still accepted — residual R7, narrowed by #229, which now refuses to issue or accept a disclosed `exp` / `nbf` (v1.25.0; the `test_sd_jwt.py` test became #229's issue-time refusal)

**Issuer identity & impersonation**
- `#236` — *identity confusion* — an https `iss` must name the same host to Python's `urlparse` as to a WHATWG parser: `https://trusted.example\@attacker.example` verified with metadata and JWKS fetched from the host Python resolved, and an x5c `dNSName` leaf for `attacker.example` bound (an exact-string issuer allow-list was never fooled). Userinfo, a backslash, non-ASCII, a `%`-encoded host, port 0, dot segments and `;?#` are refused before any fetch; the same rule guards every https URL openid4vci validates (`credential_issuer`, the metadata endpoints), which had accepted many of the same forms (v1.31.2; `test_https_issuer_identifier.py`)
- `#221` — **wrong-accept** — a W3C `vc+sd-jwt` credential gets the VC-JWT reconciliation: one signed with an attacker's own key could name `"issuer": "did:web:university.example"` in its body and verify, and `expected_types` was silently ignored on SD-JWT, so a caller's type pin passed a credential of any type (an IETF SD-JWT VC under a type pin is now rejected). Its review also refused a forged `dc+sd-jwt` status list naming the victim issuer under `require_status_issuer_binding` (v1.31.0; `test_sd_jwt_vcdm_consistency.py`)

**JSON-LD form ↔ signed dataset (RDF Data Integrity)**
- GHSA-vrxg-57v4-85mc (v1.30.2) — context validation (VC-DI §2.4.1) on
  `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` / `ecdsa-sd-2023`, on both the verify and the sign
  side: the policy reads only JSON the signature covers (threat model I20, R9). Pinned
  by `tests/test_di_context_validation.py`. The attack tests fail on v1.30.1 and pass
  here; the W3C golden vectors are unaffected.
- `#185` — *cross-caller bleed* — only the bundled, read-only contexts are tagged pyld-`static`: an injected `extra_contexts` document reached pyld's process-global cache keyed by URL, so two callers injecting different documents under one URL collided and a valid proof failed to verify (v1.27.1, follow-up to #183; `test_contexts.py`)

**X.509 / trust anchoring**
- `82b3867` — X.509 `x5c` issuer trust for JOSE credentials
- `b933460` — emit `x5c` header on SD-JWT VC issuance to anchor the issuer (#94)
- `f18d222` — parse + validate EUDI relying-party access certs / WRPAC (#88)

**Relying-party certificates (WRPAC ↔ WRPRC authorization)**
- `#161` — **wrong-authorize** — a missing, blank or non-string `format` on a WRPRC entry and on a DCQL query both normalised to `None` and matched; an absent `format` is now a failure, never a match (v1.25.0; `test_rp_registration.py`)
- `#160` — **wrong-authorize (scope escalation)** — a present but empty `claim` fell through to `claims` and widened the grant, the empty-first half of #89's two-spellings escalation; a present `claim` is now the whole grant (v1.25.0; `test_rp_registration.py`)
- `#152` — **wrong-authorize** — an empty grant authorized a DCQL request naming no claims as "equally unrestricted", so an incomplete, registrar-signed WRPRC granted the whole credential; an empty grant now grants nothing (v1.25.0; `test_rp_registration.py`)
- `#89` — **wrong-authorize (scope escalation; caught in review before release)** — the WRPRC module (ETSI TS 119 475) and its two authorization cross-checks; its adversarial review closed a CRITICAL scope escalation (a narrow decoy `claim` beside the real, wider `claims` on the request side) with asymmetric precedence: the union on the request, precedence on the grant (v1.21.0; `test_rp_registration.py`)

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
| GHSA-w7vc-732c-9m39 / CVE-2026-48525 | DoS via unbounded b64 decode of the unused segment of a `b64=false` detached JWS | **Marginally, pre-2.13** — a hostile token reaches `jwt.decode` on the VC-JWT lane (cost ∝ input size; no wrong-accept). Closed by the floor. On the hand-rolled lanes `b64` is an inert unknown parameter — verification always runs over `b64url(header).b64url(payload)`, so detached-payload confusion is impossible; and a *conformant* `b64=false` token must list `b64` in `crit` (RFC 7797 §6), which every lane now rejects |

Outcome: floor raised to `pyjwt>=2.13` (defense in depth even where structurally
unreachable) plus the lane-uniform `crit` rejection.

Not an advisory, but the same surface (found 2026-10-12, fixed in 1.30.0): PyJWT
casts `exp`/`nbf`/`iat` with `int()` and catches only `ValueError`, so a signed
`"nbf": null` raised a bare `TypeError` out of `_JWT.decode`, outside `OpenvcError`.
`vc_jwt` now checks those shapes itself before the decode (`check_numeric_dates`).
The fix's adversarial review found two more untyped exits from the decode. One is
a `RecursionError` from PyJWT's own `json.loads` on Python ≤ 3.11, where the depth
limit depends on stack depth. The other is a `UnicodeEncodeError` from a non-ASCII
signature segment. Non-ASCII tokens are now refused before decoding, and any
`TypeError`/`ValueError`/`RecursionError` from the decode maps to `ClaimsInvalid`. `cryptography` 49.0.0
(2026-06-12, stricter X.509 parsing) confirmed compatible: full suite green, and CI
resolves the newest `cryptography` on every run.
