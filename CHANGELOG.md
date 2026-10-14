# Changelog

All notable changes to **openvc** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.32.4] — unreleased

Tests and docs only; no behaviour changes. Closes the last open items of
[#208](https://github.com/luisgf/openvc/issues/208): the fix itself shipped in 1.29.1
and 1.30.3.

### Fixed (docs)

- **The Security Model wiki page names the "array where a string is expected" attack**
  ([#208](https://github.com/luisgf/openvc/issues/208)). The attack table now has a
  row for a JSON array or object in a JOSE `alg` or `typ`, an SD-JWT `_sd_alg`, a
  KB-JWT `alg`, an `ldp_vc` `cryptosuite`, an OpenID4VCI key-proof `typ` or a Data
  Integrity `proofPurpose`: formerly a bare `TypeError` that aborted a whole
  `verify_many`, now the typed error a disallowed string gets on every lane but
  `proofPurpose`, where a non-string is `ProofMalformed` (a wrong string is
  `ProofPurposeMismatch`).
- **The threat model's I1 row cites the allow-list checks where they are.** It still
  pointed at `proof/_jws.py:84` and at `proof/vc_jwt.py:55,198`; the checks are at
  `_jws.py:89` and `vc_jwt.py:243`, the constant at `vc_jwt.py:65`. I1 also lists the
  tests that pin the type check (`test_typed_error_unhashable_header.py`,
  `test_typed_error_deep_headers.py`), and I14 and I15 list the new file. The assurance case no longer calls #208 open.

### Tests

- **A deep array where a string is expected now reaches each lane's own check**
  ([#208](https://github.com/luisgf/openvc/issues/208)). Since #213 a header nested
  past 100 levels is refused at the JSON parse as `MalformedToken`, so the existing
  ~100k-level tests never got as far as the lane's allow-list check, or its message,
  and on any interpreter but CPython 3.14 the shape does not even parse. The new
  `test_typed_error_deep_headers.py` nests the array 90 levels, under the cap, on
  every interpreter. For the SD-JWT VC issuer `alg` and `typ`, `_sd_alg` and the
  KB-JWT `alg` (through the suite and `verify_vp_token`), VC-JWT `alg`,
  `proof._jws.verify_compact` (directly, the VP-JWT suite, a `jwt_vc_json` response,
  an embedded VC-JWT and the status-list token), the OpenID4VCI key-proof `typ` and
  `alg`, and the `ldp_vc` holder-proof `cryptosuite`, each test asserts the exact
  typed class and that the message names the value as `list` rather than quoting it
  (`repr()` of 90 levels works, so the message is the only way to see `safe_repr` at
  work). `test_unhashable_proof_purpose.py` gains the same for a Data Integrity
  `proofPurpose` on all five suites. `verify_many` and `verify_many_async` are shown
  to isolate one deep-array item per lane, with a control either side. Controls pin
  that 90 levels parse, that one level past the cap is `MalformedToken`, and that a
  well-formed token still verifies. The OpenID4VCI key-proof `alg` had no array or
  object case at all; `test_typed_error_unhashable_header.py` now runs the array,
  object and empty-array shapes it already ran for the other lanes against it.

  Mutation-checked against an unmodified origin/main tree: with the tests overlaid,
  all 60 pass. Removing the `isinstance` guard at any one of ten lanes fails that
  lane's deep test, and the batch tests for the lanes they cover. Putting `repr()`
  back in `safe_repr` fails 18 of the 21 tests in the new file (the other three are
  the controls) and the two WRPRC `typ` message tests. The new key-proof `alg` cases
  (array, object, empty array) fail with a bare `TypeError` when the `isinstance`
  guard at `openid4vci.py:971` is removed.

## [1.32.3] — unreleased

### Security

- **A DID document of the wrong shape is a typed error, not a batch abort**
  ([#219](https://github.com/luisgf/openvc/issues/219)). Found by the adversarial
  review of [#212](https://github.com/luisgf/openvc/pull/212).

  `parse_did_document` assumed the document's shape. A document that was valid JSON
  but the wrong shape raised a bare `TypeError` or `AttributeError`, neither of them
  an `OpenvcError`, so one such credential aborted a whole `verify_many` /
  `verify_many_async` batch. No key was needed: key resolution runs before the
  signature check, so an unsigned token whose `iss` names the attacker's own
  `did:web` was enough, and the attacker hosts the document. The default fetch only
  checks that the top level is an object. A `null` or scalar `verificationMethod`, a
  `didDocument` wrapper that is `null` or a list, a relationship (`assertionMethod`,
  `authentication`, …) that is `null` or a number, and a method whose `id` is a
  number each raised. The parser is shared, so the `did:webvh` resolved state and
  the EBSI DID Registry had the same gap.

  A `didDocument` wrapper that is not an object, and a `verificationMethod` or a
  relationship that is present but not an array, now raise `DidResolutionError`; so
  does a document that is not an object at all, which an injected fetch can return.
  `verify_credential` and `verify_many` report it for that item as
  `KeyResolutionFailed` on the JOSE lanes and on the async API, and as
  `KeyResolutionError` (a `ProofError`) on the synchronous Data Integrity lane, as
  they already did for any failed DID resolution; the cause is the
  `DidResolutionError` in each case. The EBSI plugin reports `EbsiVerificationError`.
  A wrong-typed member is never read as an absent one. An undeclared relationship
  leaves the key purpose unenforced, so reading `null` as "not declared" would have
  failed open. The check also closes a smaller grant leak: a relationship written as
  a bare string, `"assertionMethod": "k"`, was iterated one character at a time, so
  a one-letter reference authorized any method whose fragment is `k`.

  A relationship that is not an array rejects the whole document, on every lane,
  including the JOSE lanes that never read relationships: the parser does not know
  which lane is asking, and DID Core requires a set. Treating it per relationship, as
  declared but granting nothing, would keep those lanes working and was not taken. A
  document that did this verified before and now fails closed.

  A method whose `id` is not a string, and a relationship entry that is neither an id
  string nor an object with a string `id`, are dropped, as non-object entries already
  were. A dropped method is never selected: it cannot be named by a `kid`, and no
  proof purpose reaches it. A dropped relationship entry grants nothing. Dropping is
  not strictly a narrowing, though. A token with no `kid` falls back to the document's
  sole key, and the count it uses no longer includes a method dropped this way, as it
  already left out a method with no key or an undecodable Multikey. A document that
  holds a keyed method with an unreadable `id` beside one good method now resolves
  that good key for a `kid`-less token, which was refused before. The key is
  well-formed and is in the issuer's own document, so no other issuer's key is
  involved. `VerificationMethod.kid` never sees a non-string `id`. A document `id`, and a
  method's `type` or `controller`, that is not a string reads as `""`, so the model's
  `str` fields stay `str`; nothing is selected on them. `did:web` compares the
  parsed document `id` with the DID it asked for, so for `did:web` an empty `id`
  never matches. The other resolvers are not covered by that sentence: `did:webvh`
  compares the `id` of the log state, before a `didDocument` wrapper is unwrapped,
  and the EBSI registry resolver compares none.

  A well-formed document parses as before, the DID 1.1 / CID 1.0 documents included.
  Tests: `test_did_document_shape_typed.py` serves each shape (null, scalar, string,
  list and object, in every member) through the issue's `DidWebResolver(fetch=...)`
  repro and asserts the exact class on `verify_credential`, with a good credential
  beside the bad ones on both `verify_many` and `verify_many_async`. It also covers
  the async resolver, a forged `did:webvh` log whose signed state is hostile, the
  EBSI registry, the exact error class on the Data Integrity lane, and the `kid`-less
  fallback.

- **A malformed `meta.vct_values` or `meta.doctype_value` no longer reads as "no
  constraint"** ([#224](https://github.com/luisgf/openvc/issues/224)). Found while
  implementing [#205](https://github.com/luisgf/openvc/issues/205). On a `dc+sd-jwt`
  query, a `meta` that was `null`, an array or a string, or an explicit
  `"vct_values": null`, skipped the type check, so any SD-JWT VC type answered the
  query. A `mso_mdoc` query did the same with `meta` or `"doctype_value": null`, and
  any mdoc docType answered. These now raise `VpTokenMalformed`, as `type_values`
  has since #205. An absent `meta`, or a `meta` without the key, still means no
  constraint. The `dcql_query` is the verifier's own input, not the wallet's, so this
  is defence in depth: it stops a verifier-side bug from widening a query to any
  type, and no attacker can reach it.

  `vct_values` is also parsed before the SD-JWT presentation is verified. A
  malformed query used to surface as whatever the presentation failed with first
  (and only a valid presentation reached the check at all). It is now
  `VpTokenMalformed` whatever the wallet sent for that query, as for `type_values`.
  The match against the verified `vct` is unchanged. One reader (`_dcql_meta`) now serves
  `vct_values`, `doctype_value` and `type_values`, so the three formats cannot drift
  apart again. The Presentations wiki page states the rule.

### Tests

- **The type constraints are pinned in both directions** (#224). For
  `vct_values` and `doctype_value`: a `null`, empty, non-string or wrong-shaped
  value, and a `meta` that is `null`, an array, a string, `0`, `false` or `""`, all
  raise `VpTokenMalformed`. They do so with a junk presentation too, which would
  otherwise have failed with `MalformedToken` or `MdocMalformed`. Each junk case has
  a control showing it fails on its own with a sound constraint. The absent-`meta`,
  empty-`meta` and other-key cases still verify. Mutation-checked: 34 of these
  cases fail against the previous code.

## [1.32.2] — 2026-10-14

One security fix in the SD-JWT VC suite, which changes what issues and what
verifies (see *Changed*).

### Security

- **SD-JWT VC: the claims a verifier needs to judge validity are never
  selectively disclosable** ([#229](https://github.com/luisgf/openvc/issues/229)).
  `SdJwtVcProofSuite.issue(disclosable=…)` accepted any top-level claim. A holder
  can withhold any disclosure, and a withheld one is indistinguishable from a
  decoy (RFC 9901 §9.7), so the claim simply read as absent. An already-expired
  credential with a disclosable `exp` verified, and so did a revoked one with a
  disclosable `status` or `credentialStatus`, even under
  `require_status=True, require_not_revoked=True`. Reproduced on v1.32.0.
  - **Issuer side (the fix).** `issue()` raises `SdJwtError`, before it signs
    anything, when `disclosable` names `iss`, `nbf`, `exp`, `cnf`, `vct`,
    `vct#integrity`, `aka_vcts` or `status`. draft-ietf-oauth-sd-jwt-vc-19
    §2.2.2.3 says these, "including any of their sub-claims", MUST NOT be
    disclosed. openvc policy adds `credentialStatus`, which the pipeline
    enforces on SD-JWT too, and `@context`, which switches the VCDM rules on.
    When `@context` makes the payload VCDM, `validFrom`, `validUntil`,
    `issuanceDate` and `expirationDate` are also refused. Every other name
    (`sub` and `iat` included) issues byte-for-byte as before. The guard covers
    what `disclosable` produces; `_sd` digests a caller writes into `claims`
    itself are signed as given.
  - **Verifier side (defence in depth).** `verify()` rejects (`SdJwtError`) a
    presentation that *presents* a disclosure of one of those claims, at the top
    level or anywhere beneath one: `cnf.jwk`, `status.status_list`, an element of
    `aka_vcts` or `credentialStatus`. A third-party issuer that ignores the
    profile now fails visibly instead of only failing open. The rule lives in
    the SD-JWT VC profile layer. `_unpack`, the generic RFC 9901 step, only
    records where each disclosure landed.
  - **`vct` is REQUIRED on a `dc+sd-jwt`.** A `dc+sd-jwt` whose processed
    payload is not VCDM and has no non-empty string `vct` is now `ClaimsInvalid`.
    Besides `iss`, without which nothing verifies, it is the one refused claim
    whose *withholding* is detectable, because its absence is itself
    non-conformant. `issue()` requires the same: a `vct` that is not a non-empty
    string (a list, a number, `True`) raises `SdJwtError` instead of minting a
    token openvc would then reject.
  - **Not closed, by design:** a *withheld* disclosure from a third-party
    issuer. A credential whose issuer made `exp` or `status` disclosable still
    verifies, as never-expiring or with no status, when the holder omits it. No
    verifier can see a withheld digest. `tests/test_sdjwt_non_disclosable.py`
    pins this as a limitation.
  - **Deliberately not refused:** `credentialSchema` (schema validation is
    opt-in data-shape checking, and `require_schema` fails closed only on a
    missing resolver), and `aud` (the SD-JWT VC draft does not list it, and the
    suite never reads the issuer JWT's `aud`).
  - **Adversarial review of this change** found one hole in the new issuer-side
    guard, closed here. `issue()` judged "is this VCDM?" on the Python object,
    and a tuple `@context` is not a list there but is a JSON array once signed.
    So `issue(…, {"@context": ("https://www.w3.org/ns/credentials/v2",), …},
    disclosable=["validUntil"])` signed a VCDM credential whose expiry the holder
    could withhold. The verdict is now taken on the payload as the verifier will
    parse it. The review found no way past the verifier-side check: chained and
    array-element disclosures, lookalike names, `_sd_alg`, the KB-JWT ordering
    and the nested VP / OpenID4VP / enveloped paths all failed closed.

### Changed

- **Behaviour change: calls and tokens that used to succeed now fail**
  ([#229](https://github.com/luisgf/openvc/issues/229)). Each fails closed with
  a typed error, and in `verify_many` / `verify_many_async` it fails only its
  own item.
  - `SdJwtVcProofSuite.issue()` with one of the refused names in `disclosable`
    raises `SdJwtError`, alone or mixed with allowed names.
  - `issue()` with a `vct` that is not a non-empty string raises `SdJwtError`.
  - An SD-JWT presentation that presents a disclosure of a refused claim, or of
    a sub-claim of one, raises `SdJwtError` from the suite and from every
    `verify_credential*` / `verify_many*` entry point. Under
    `require_key_binding=True`, a disclosed `cnf` fails earlier, as the
    key-binding `ClaimsInvalid`. Before, a disclosed expired `exp` or past
    `validUntil` failed as expired, or, under `require_not_expired=False`,
    **verified with `expired=True`**. Waiver users re-checking archived
    presentations will now see `SdJwtError` for that shape. A disclosed `vct`,
    `status` or `credentialStatus`, or a disclosed `cnf` with no KB-JWT,
    verified.
  - A `dc+sd-jwt` with no `vct` (and no VCDM `@context`) raises `ClaimsInvalid`.

### Tests

- **`tests/test_sdjwt_non_disclosable.py`** (#229). Issue-time refusals: each name
  alone and mixed, nothing signed, the VCDM window only on a VCDM payload. Each
  presented refused disclosure, and each sub-claim shape, through the suite,
  `verify_credential`, `verify_credential_async`, `verify_many` and
  `verify_many_async`, with the good neighbours of a `[good, bad, good]` batch
  still verifying. The withheld-disclosure limitation is pinned so it is never
  mistaken for coverage. Run against v1.32.0: 130 fail, and the 40 that pass are
  the controls and the limitation pins. Existing tests that issued or presented a
  disclosable `exp`, `validUntil` or `@context`, or minted a `dc+sd-jwt` with no
  `vct`, now assert the refusal. Regression tests for the review finding (tuple
  `@context`), the string `vct` at issue, and the waiver, mutation-checked
  against the pre-review commit.

## [1.32.1] — 2026-10-14

### Security

- **A TIR v5 registry URL that does not parse is now a typed error or an
  off-origin skip, never a bare `ValueError`**
  ([#243](https://github.com/luisgf/openvc/issues/243)). Found by the audit-pack
  catch-up in 1.32.0 (#240), which recorded it as an untracked residual.

  The EBSI plugin pins three registry-supplied URLs to the listing's
  `scheme://host:port` (#172): the HATEOAS `attributes` URL, each `links.next`
  cursor and each revision `href`. The pin called `urlparse(url).port`. A port out
  of range (`:99999`) or not numeric (`:abc`), a broken IPv6 literal
  (`https://[::1/x`) or a character that NFKC folds into a delimiter made it raise a
  bare `ValueError`. That is not an `OpenvcError`, so a compromised or broken
  registry made `verify_ebsi_badge` fail closed but untyped, past code that catches
  `EbsiError` / `OpenvcError`. It was never a wrong-accept.

  A URL with no origin to compare is now handled like an off-origin one, hop by hop:
  - an `attributes` URL raises `MalformedRegistryResponse`;
  - an `href` is skipped and its revision never fetched;
  - a `links.next` ends the walk and keeps the items already read.

  So is a URL the HTTP client would read differently (#246, below): anything but
  visible ASCII, or over 8 KiB. That check runs before `urlparse` reads the URL: on
  CPython 3.12 and earlier, `urlparse` NFKC-normalizes a non-ASCII netloc in quadratic
  time (see 1.31.2). The EBSI client's https host allow-list is unchanged.

  `threat-model.md` §7 and R10 no longer list it as an open residual; R10 keeps the
  hostile DID-document shape (#219).

- **A URL the EBSI HTTP client cannot parse is refused, typed, before any request**
  ([#246](https://github.com/luisgf/openvc/issues/246)). Found by the adversarial
  review of [#244](https://github.com/luisgf/openvc/pull/244), the fix for #243.
  Present before it.

  `EbsiHttpClient.get_json` checked a URL with `urlparse` and fetched it with httpx.
  `urlsplit` drops a tab or newline and ignores other control characters; httpx
  rejects them, and a URL over 64 KiB, with `httpx.InvalidURL`. That is a plain
  `Exception`, not an `httpx.TransportError`, so it escaped `get_json` untyped. No key
  was needed: `verify_ebsi_badge` puts the issuer it peeks from an unsigned token
  into the DID Registry URL, so an `iss` such as `did:ebsi:z\tx` aborted it with a bare
  `httpx.InvalidURL`. A TIR `attributes`, `links.next` or `href` holding such a
  character passed the origin pin the same way. The guard also left a broken IPv6
  literal as a bare `ValueError`, and never read the port, so `:99999` went to the
  transport.

  The client now refuses, as `HttpForbiddenHost` and before any request, a URL that
  is not visible ASCII (checked before `urlparse`) or that `urlparse` cannot read,
  port included. `httpx.InvalidURL` is mapped to `HttpForbiddenHost` as a backstop
  and is not retried.

- **A registry body httpx cannot decompress is now `MalformedRegistryResponse`**
  ([#248](https://github.com/luisgf/openvc/issues/248)). Found by the second
  adversarial pass on #244. Present before it.

  httpx decompresses a `gzip` / `deflate` body while streaming it, and the client
  advertises both. A corrupt body raised `httpx.DecodingError`, a `RequestError` but
  not a `TransportError`, so it escaped `get_json`, and `verify_ebsi_badge`, untyped.
  It escaped from the capped read on a 200 and from the drain of any other status.
  A broken or compromised allow-listed registry was enough. It is now a
  `MalformedRegistryResponse` and is not retried.

### Fixed (docs)

- **`check_request_within_registration` describes the rule it enforces.** Its
  docstring said each requested claim path must fall inside *one* matching
  `credentials` entry. The code pools the grants of every entry whose `meta` covers
  the whole query — two entries for the same `vct`, one granting `name` and one
  `age`, authorize a query for both — and that rule is kept. TS 119 475 scopes the
  registered credentials to the intended use (clause B.2.7), not to an entry, and
  defines no either/or between entries. Pooling never borrows from an entry
  registered for another `vct`, or for only part of the query's `meta`. A
  one-entry rule would add no protection, because the relying party could split
  the query in two. The Relying-Party Certificates wiki page says the same.

### Tests

- **The pooling rule is pinned.** One test covers entries with identical `meta`:
  their grants pool, and an unregistered path is still refused. A second covers
  overlapping `meta`: an entry for `vct` A alone lends nothing to a query that a
  `vct` B credential may answer. Both were mutation-checked: a one-entry rule fails
  both, and pooling every entry of a format, whatever its `meta`, fails the second.

## [1.32.0] — 2026-10-14

### Added

- **Python 3.15 is supported**
  ([#241](https://github.com/luisgf/openvc/issues/241)). CPython 3.15.0 shipped on
  2026-10-09. Since #126 it had been an *advisory* CI leg that installed only
  `[ebsi,dev]`, because lxml had no cp315 wheel. lxml, rpds-py and cryptography now
  publish one, so 3.15 is a regular, blocking leg with `[all]` and the full 85 %
  coverage floor. A `Programming Language :: Python :: 3.15` classifier is added.

### Deprecated

- **Python 3.10** ([#241](https://github.com/luisgf/openvc/issues/241)). It reached
  end-of-life upstream on 2026-10-01. Importing openvc on 3.10 now emits a
  `FutureWarning` naming the end-of-life date and the removal in 2.0
  ([#74](https://github.com/luisgf/openvc/issues/74)). It is a `FutureWarning`
  because a `DeprecationWarning` raised during import is hidden by default outside
  test runners. Nothing is removed: 1.x still installs and is still tested on 3.10.
  `wiki/Versioning-and-Deprecation.md` gains a *Supported Python versions* section
  with the rule: a version that reaches end-of-life is deprecated in the next MINOR
  release and dropped at the next MAJOR.

### Fixed (docs)

- **The audit pack catches up with the hardening shipped since July.**
  `docs/audit/assurance.md` and `docs/audit/threat-model.md` had kept up with
  only part of it. Of the 33 `security` / `fix` commits since the last full update
  (2026-07-29), 24 were missing and 5 partly recorded; 3 were recorded and 1 is
  CI-only. Each was checked against its diff, tests and issue, then re-verified
  independently.
  - `assurance.md` §4 states the failure class of each entry it adds (wrong-accept,
    wrong-authorize, misleading flag, batch abort, DoS, …). It gains groups for
    temporal validity, issuer identity and WRPRC authorization. §3 gains suites for the surfaces that had none:
    did:web and the guarded fetch, https `iss` / x5c, the OpenID4VP W3C lanes, WRPRC
    authorization, EBSI TIR, and the expiry waiver.
  - The threat model gains **I21** (WRPRC authorization fails closed) with the
    relying-party surface across §1–§6, an attack row for re-wrapping someone else's
    credential (#196), and evidence for I5–I18. A new **R10** names the open untyped
    exits at the boundary (#219 and the EBSI `_origin` `ValueError`), R9 names #225,
    and the §9 summary no longer says no residual is a wrong-accept. **R7** now says a *withheld* disclosable `exp` / `nbf` still
    verifies as if absent (#229, open). New entries cite symbols and test names, not
    line numbers.
  - I15's `test_hostile_input.py:104/155/211` anchors, set by #155, were never correct
    in a tagged release; they now name the tests. The anchors are as of v1.24.0, not
    the never-tagged v1.24.1. The pack README's catalog span is I1–I21 and R1–R10, and its review ranking gains
    relying-party authorization.

### Tests

- **A flaky XAdES trust-list test is now deterministic.** signxml's *signer* drops
  the leading zero byte of an EC public-key coordinate when it writes the
  `ECKeyValue` (a 64-byte point instead of 65). For about 2 in 256 random P-256 keys
  the test fixture therefore carried a `KeyValue` that did not match its certificate,
  and verification rightly refused it. That was 2 failures in 600 signatures; it
  failed this PR's py3.13 leg at random. The XAdES tests now draw keys whose
  coordinates are full width: 0 failures in 600. openvc never signs XAdES, so trust-list
  verification is unaffected.


## [1.31.3] — 2026-10-13

Tests and docs only: no library code changes.

### Tests

- **The documentation-claims test runs in CI again.** `tests/test_docs_claims.py`
  ([#57](https://github.com/luisgf/openvc/pull/57)) was stacked on the README
  rewrite ([#55](https://github.com/luisgf/openvc/pull/55)). #55 merged first,
  so #57 merged into its branch and never reached `main`. The test is now on
  `main`, updated for today's code. The release runbook assumed it was running.
  - **Allow-list statements are pinned, not tokens.** `Ed25519` is also a curve
    and key name, so finding the token on a page cannot show the page lists it.
    Each prose set `{…}`, and each list of three or more algorithm names joined
    by `/`, `|` or `,`, must equal `ALLOWED_ALGS`. This covers the README,
    `SECURITY.md`, every wiki page, `docs/index.md`, `docs/api/` and
    `docs/audit/`. One historical set on the Versioning page is exempt by name.
  - **The default DID methods include `did:webvh`**, for the sync and the async
    default resolver. A malformed `did:web` / `did:webvh` host proves dispatch
    without network I/O.
  - **The version check catches a version stated as current**: an `==` pin, a
    `__version__` value, "the current/latest release is X.Y.Z". It used to fail
    on any appearance of the current version string. The release gate runs
    after the version bump, so the old rule also failed on the wiki's dated notes
    ("Before 1.31.0 …"). Replayed over every tag, it would have blocked the
    v1.29.0, v1.30.5 and v1.31.0 releases. The new rule matches nothing in any
    tag.

### Fixed (docs)

- **Two allow-list statements missed `Ed25519`**, the RFC 9864 name accepted
  since 1.11.0 ([#59](https://github.com/luisgf/openvc/issues/59)): the README
  capability table (`ES256` / `ES384` / `EdDSA`) and the `SigningKey.alg`
  comment on the Keys & HSM wiki page. The comment now also notes the opt-in
  ML-DSA algorithms. Every other page already stated the full set.

## [1.31.2] — 2026-10-13

### Security

- **A did:web host or a fetched URL can no longer stall the event loop, and a
  Unicode host no longer resolves at another domain**
  ([#235](https://github.com/luisgf/openvc/issues/235)). Found by the
  adversarial review of [#209](https://github.com/luisgf/openvc/pull/209), run
  after it merged; this change's own review found the `urlparse` cost.

  The did:web host check that #209 added IDNA-encoded the host before bounding
  its length. CPython's punycode encoder is quadratic: 10,000 CJK characters took
  about 6.6 s, and 50,000 about a minute. `AsyncDidWebResolver` runs the check on
  the event-loop thread, so one credential stalled `verify_many_async` for that
  long. It needed no valid signature, since key resolution runs before the
  signature check. Before #209 the encode ran inside `getaddrinfo` on a worker
  thread. The sync path with the default fetch had the same cost already, and so
  did https-issuer and status-list hosts.

  The guarded fetch had a second cost that did not depend on #209. On CPython
  3.12 and earlier, `urlparse` NFKC-normalizes a non-ASCII netloc, and
  out-of-order combining marks make that quadratic: a 256 KB host took about
  6.7 s and 0.5 MB about 25 s. `normalize` holds the GIL, so running the fetch on
  a worker thread still froze the event loop. A status-list or schema URL in a
  self-signed credential was enough to trigger it.

  A Unicode host also went to another registrable domain than other
  implementations use. Python's IDNA codec is IDNA2003, so `did:web:fa%C3%9F.de`
  was looked up, and its TLS name checked, as `fass.de`. IDNA2008, UTS 46 and
  browsers give `xn--fa-hia.de`. Whoever held `fass.de` controlled `faß.de` in
  openvc. `ς`, ZWJ and ZWNJ fold the same way. The same pass-through checked one
  host and connected to another for some capitals (`ẞexample.com` connected to
  `ssexample.com`). It also let U+FE13 through, which hands a caller's own fetch
  a URL that `urlparse` rejects with a bare `ValueError`.

  A did:web or did:webvh host must now be ASCII, at most 253 characters, checked
  before any per-character work. An internationalized host is written as its
  A-label (`did:web:xn--mnchen-3ya.de`). The did:web spec defines the host by
  RFC 1035/1123, which are ASCII, and forbids IP addresses. The host is now also
  refused when its last label is a number, the way WHATWG spots an IPv4 address
  (`127.0.0.1`, `2130706433`, `0x7f.1`); before, only a bracketed IPv6 literal
  was. The SSRF-guarded fetch refuses a non-ASCII URL before `urlparse` reads
  it, which also closes U+212A, the one character whose lower case is ASCII. It
  then refuses a host over 253 characters before DNS, raising `UnsafeUrlError`.
  A did:web error message names the DID through `safe_repr`: a 2 MB DID used to
  make a 16 MB message.

  These are now rejected:

  - a did:web with a Unicode host (`did:web:m%C3%BCnchen.de`; use its A-label);
  - a did:web whose host is an IPv4 address in any form;
  - an https URL with any non-ASCII character, in the host or the path, sent to
    the guarded fetch. A non-ASCII path already failed when the request was
    sent.

  Those DIDs already resolved differently in openvc than in other
  implementations, or broke the did:web spec.

- **An https `iss` names the same host to openvc as to a browser**
  ([#236](https://github.com/luisgf/openvc/issues/236)). Found by the
  adversarial review of [#209](https://github.com/luisgf/openvc/pull/209), with
  more forms from this change's own review. `jwt_vc_issuer_metadata_url` kept
  the raw netloc, and the x5c binding matched a `dNSName` against
  `urlparse(iss).hostname`. Python and a WHATWG parser (a browser, a JS
  front-end) read some `iss` values as different hosts:

  - `https://trusted.example\@attacker.example`: `attacker.example` to
    Python, `trusted.example` to a browser.
  - `https://faß.de`: Python's IDNA2003 codec gives `fass.de`, UTS 46 gives
    `xn--fa-hia.de`. `ẞ`, `ς`, and ZWJ / ZWNJ after a virama fold the same way.

  With `jwt_vc_issuer_fetch`, `verify_many` fetched the metadata and JWKS from
  the first host and returned ok. The x5c lane bound a leaf for
  `attacker.example`. A consumer that showed or trusted the issuer's host read
  the second host, and so did an allow-list that held the Unicode form.

  An https `iss` must now be free of every form that lets the two parsers name
  different hosts or paths. Each of these is now refused:

  - userinfo and a backslash;
  - a control character or whitespace (`urlparse` silently drops `\t\r\n`);
  - params, a query or a fragment, even an empty one (the metadata URL silently
    dropped them);
  - a non-ASCII character anywhere (write an IDN host as its `xn--` A-label).
    This is checked before `urlparse` runs, because on CPython 3.12 and
    earlier its NFKC pass over a non-ASCII netloc is quadratic: a 256 KB
    issuer took about 6.5 s there;
  - a percent-encoded host;
  - port 0 (the guarded fetch read it as 443);
  - a `.` or `..` path segment, encoded or not.

  `jwt_vc_issuer_metadata_url` raises `JwtVcIssuerError` (`KeyResolutionFailed`
  in the pipeline), and a non-string `iss` is typed too. The x5c lane binds a
  `dNSName` only to a clean https `iss`; an `http://` one no longer binds that
  way. A `uniformResourceIdentifier` SAN still binds when it equals the `iss`
  exactly. openid4vci's `credential_issuer` and its other URL members, which
  already refused userinfo, whitespace, a query and a fragment, now refuse the
  same forms, from one shared rule.

## [1.31.1] — 2026-10-13

Tests only: no library code changes.

### Tests

- **A third-party OpenID4VP `vp_token`, vendored byte for byte**
  ([#121](https://github.com/luisgf/openvc/issues/121)). Until now openvc's
  `vp_token` vectors were self-recorded: openvc verifying the presentation it had
  built. This one was presented by another wallet, eudi-dev v2.3.7, to another
  verifier, polaris-oid4vp, and captured with full provenance by
  [@EgorKhaklin](https://github.com/EgorKhaklin) (polaris-id), who contributed it
  under Apache-2.0 — thank you. It pins the presentation layer itself: the DCQL
  response shape, the KB-JWT and the encrypted `direct_post.jwt` response.
  - Both the plain `vp_token` and the posted JWE verify, with `now` pinned to the
    verifier's recorded capture instant.
  - Every file is SHA-256-pinned, and its `PROVENANCE.md` is kept beside it,
    unmodified.
  - The negatives: the author's "an hour later" control (which found #186), an
    expired issuer leaf, an unrelated anchor, both signatures tampered, a wrong
    `nonce`, and a `client_id` missing its `x509_hash:` prefix.

## [1.31.0] — 2026-10-13

### Security

- **A W3C credential secured as SD-JWT now gets the VC-JWT lane's consistency
  rules** ([#221](https://github.com/luisgf/openvc/issues/221)). Found by the adversarial review of
  [#199](https://github.com/luisgf/openvc/pull/199); the gap predates it. Both
  pipelines (`verify_credential`, `verify_credential_async`) and
  `SdJwtVcProofSuite.verify` were affected, bare or inside an
  `EnvelopedVerifiableCredential`. The fix applies only when the payload is VCDM
  (`vc+sd-jwt`, detected as in #198).
  - **Issuer impersonation in the credential body.** An SD-JWT signed with the
    attacker's own `did:jwk` (`iss` = the attacker) could carry
    `"issuer": "did:web:university.example"` and verify. `result.issuer` then named
    the attacker while `result.credential["issuer"]` named the university.
    VC-JOSE-COSE §4.1.2 says `iss`, if present, MUST match `issuer` (or
    `issuer.id`). The suite now applies the VC-JWT lane's reconciliation to the
    processed payload, so a disclosed `issuer` counts too, and raises
    `ClaimsInvalid` on a conflict. The same holds for `jti` / `id` and `sub` /
    `credentialSubject.id`, which openvc enforces as policy, as on VC-JWT; §3.1.3
    (non-normative) only advises against those conflicts. The expiry waiver does
    not relax the check.
  - **`policy.expected_types` was silently ignored on SD-JWT**, so a policy that
    pinned a type accepted any SD-JWT. Per VC-JOSE-COSE §5.4, a VCDM payload now
    gets the same `TypeMismatch` as VC-JWT and Data Integrity. That covers a
    withheld `type` and a malformed one (`null`, a number, an object).
  - **Behaviour change for IETF SD-JWT VCs:** a policy that sets `expected_types`
    now rejects one with `TypeMismatch` that points at `expected_vct`. An IETF
    SD-JWT VC is typed by `vct`, so the pin cannot be checked, and a pin that
    cannot be checked fails closed instead of passing. Ignoring it would also let
    a holder dodge it by withholding a disclosable `@context` from a `dc+sd-jwt`
    VCDM credential. Callers who verify both kinds under one type pin need a
    policy per format. A presentation verified under one policy that sets
    `expected_types` is rejected as a whole if it carries an IETF SD-JWT VC. An
    unset or empty `expected_types` still constrains nothing.

  The IETF lane is otherwise unchanged. A claim there that is merely named
  `issuer`, `id` or `credentialSubject` is the issuer's own vocabulary and is not
  reconciled. As on every lane, `result.issuer` (the verified `iss`) is the
  authenticated issuer.
- **A present `issuer` must identify no one but the verified `iss`, whatever its
  shape**, on the VC-JWT lane and on a W3C SD-JWT (#221, adversarial review).
  The reconciliation compared only a non-empty string `issuer` or `issuer.id`, and
  skipped every other shape. So `{"@id": "did:web:university.example"}` (the
  university, to a JSON-LD processor), `""`, `null`, `{"id": null}` and a list all
  verified as issued by the signer. Every identifier a present `issuer` carries
  must now be `iss`: the string itself, or an object's `id` and `@id`. An absent
  `issuer`, or an object with no `id` such as `{"name": …}`, is still accepted. It
  identifies no one, and the VCDM 1.1 JWT encoding moves the issuer's id to `iss`.
  The status-list check below reads an issuer the same way.
- **The status-list issuer binding (ADR-0006) can no longer be satisfied by a forged
  SD-JWT list** (#221, adversarial review; this predates the change).
  `require_status_issuer_binding` compares the `issuer` named in the resolved list's
  body, and the default resolvers returned the verified list's body as is. An IETF
  SD-JWT's `issuer` claim is not reconciled with its `iss`. A compromised status
  host could therefore serve a `dc+sd-jwt` list signed by its own key that named
  the victim issuer and cleared the revocation bit. A revoked credential then
  verified as not revoked, even with the binding on and with `expected_issuer` set
  on the resolver. `default_status_list_resolver` and its async twin now refuse a
  list whose body names an issuer other than the one its signature was verified
  for (`StatusListError`). A custom `resolve_status_list` must do the same; see
  [Status lists](https://github.com/luisgf/openvc/wiki/Status-Lists).
- **A bare-string `expected_types` is one type.** `expected_types="UniDegree"` was
  iterated one character at a time on every lane, so a credential whose `type`
  was `["U", "n", "i", …]` satisfied it. A string is now treated as a
  one-element list.

- **DCQL `meta.type_values` is now enforced for `jwt_vc_json` and `ldp_vc`**
  ([#205](https://github.com/luisgf/openvc/issues/205)). Found by the
  adversarial review of [#194](https://github.com/luisgf/openvc/pull/194).
  `verify_vp_token` never read the constraint on these two formats, so a
  Credential Query for a `UniversityDegreeCredential` was answered by any
  credential that verified. That included one the holder minted from their own
  `did:key`, even with `require_holder_binding=True`. A VP could also carry an
  unrelated credential next to the requested one. The other formats already
  enforced their equivalent constraint: `vct_values` for `dc+sd-jwt` and
  `doctype_value` for `mso_mdoc`.

  The check follows OpenID4VP 1.0 §B.1.1. **Every** embedded credential must
  have, among its fully expanded types, all the IRIs of at least one
  alternative, or the response is rejected with `ClaimsInvalid`. openvc expands
  each credential's `type` with JSON-LD against the credential's own
  `@context`. A term the context defines becomes its IRI, and a term no context
  defines stays as written, unless the context sets an absolute `@base`. The
  types come from the credential's JSON, which every accepted format signs:
  VC-JWT and every Data Integrity suite. The RDF-canonicalized suites have
  guaranteed this since 1.30.2.

  The comparison is on IRIs, not short names. `VerifiableCredential` expands to
  `https://www.w3.org/2018/credentials#VerifiableCredential`, so a query for the
  bare `"VerifiableCredential"` matches no VCDM credential. Under the VCDM 2.0
  context, which has no `@vocab`, an undefined `UniversityDegreeCredential` still
  matches as written.

  The check fails closed:
  - A malformed constraint is `VpTokenMalformed`, raised before anything is
    verified. That covers a non-object `meta`, an explicit `null`, an empty or
    flat `type_values`, and an empty or non-string type.
  - An unbundled context raises `DocumentLoaderError`.
  - A credential whose types cannot be expanded raises `ClaimsInvalid`.
  - An SD-JWT nested in the presentation never matches: its holder could
    reshape a `type` by withholding disclosures.
  - A query without `type_values` still puts no constraint on the type.

  Like `vct_values`, the check selects the right credential type, not a
  trusted issuer.

  **Upgrading:**
  - Matching needs the `[data-integrity]` extra (pyld) once a query carries
    `type_values`. Without it, `verify_vp_token` raises `OpenID4VPError`.
  - Matching also needs every context the credential cites. Only VCDM 2.0 is
    bundled. Pass the VCDM 1.1 context, and any others, through
    `extra_contexts`, which now reaches the `jwt_vc_json` lane too.
  - A query that names types by short name, such as
    `[["VerifiableCredential", …]]`, used to pass because nothing was checked.
    It now fails: write the IRIs.

  Fixed before merge, from this change's own adversarial review:
  - **Each expansion now gets its own pyld context resolver**, so no context
    is shared between calls or callers.
  - **An absolute `@base` in the credential's context is now honoured.** pyld
    skips it when no document base is passed, so an undefined type stayed
    relative where JSON-LD resolves it.
  - **An RDF-canonicalized credential's JSON `type` could be forged.** The
    review found that a holder could rewrite the JSON of an `eddsa-rdfc-2022`,
    `ecdsa-rdfc-2019` or `ecdsa-sd-2023` credential so that its signed dataset
    stayed the same while its top-level `type` named anything. The same
    weakness hid the validity window, the status and the subject from every
    other check, so it was fixed for all of them in 1.30.2
    ([GHSA-vrxg-57v4-85mc](https://github.com/luisgf/openvc/security/advisories/GHSA-vrxg-57v4-85mc)).
    This change relies on that fix. A regression test pins that the forged
    credential fails before `type_values` reads it.

### Added

- **`VerifiedSdJwt.vcdm: bool = False`** says whether the suite treated the payload
  as a W3C VCDM credential (`vc+sd-jwt`). That means it enforced the payload's
  validity window and its `issuer` / `id` / `credentialSubject.id` consistency. It
  is appended with a default, so positional constructions keep working, and the
  frozen return-object contract is updated. The pipelines read it to decide how
  `expected_types` applies.

### Changed

- The reconciliation's error message names `issuer` rather than `vc.issuer`
  (`iss '…' != issuer '…'`), because the SD-JWT lane now raises it too.

## [1.30.5] — 2026-10-13

### Security

- **The JOSE credential, presentation, key-binding, status-list and key-proof
  lanes now apply one rule to `exp`, `nbf` and `iat`, and a VC-JWT's `aud` is
  enforced** (RFC 7519 §2, §4.1.3–§4.1.6; [ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md)). The adversarial
  review of [#195](https://github.com/luisgf/openvc/pull/195) found the lanes
  still disagreeing after it, all reproduced on v1.28.2:
  - **SD-JWT VC issuer JWT.** `iat` was never shape-checked: `null`, `[]`,
    `"abc"`, `"1999999999"`, `true`, `NaN`, `1e400` and a bignum all verified,
    under the default policy and the expiry waiver, and so did a future `iat`.
    `"exp": null` / `"nbf": null` were read as absent. All are now
    `ClaimsInvalid`, and so is a malformed or future `iat` that the issuer made
    selectively disclosable.
  - **VP-JWT.** The presentation's `iat` was never read, so an `iat` of `[]`,
    `NaN`, `1e400` or a year ahead verified, and a `null` `exp`/`nbf` read as
    absent. They are now checked like the other dates.
  - **VC-JWT, ML-DSA lane.** It accepted an `iat` in the future, which PyJWT
    rejects on the classic lane. It now rejects one too.
  - **Status-list token.** `"exp": null` was read as absent, and `nbf` and
    `iat` were never read, so a list dated a year ahead verified. It now runs
    the shared rule (`StatusListError`). Its window is judged at one instant,
    the pinned `now` or the wall clock (which the resolvers always use).
  - **VC-JWT `aud`.** Neither lane checked `aud` when the caller passed no
    audience (`verify_aud=False`), so a VC-JWT addressed to
    `https://other-rp` verified for anyone who held it. RFC 7519 §4.1.3 says
    the token MUST then be rejected. Both lanes now run `check_jwt_audience`
    after the signature verifies.

  `check_jwt_temporal` single-sources the rule for the SD-JWT VC issuer JWT
  and KB-JWT, the VP-JWT, the VC-JWT ML-DSA lane, the status-list token and
  the OpenID4VCI key proof. A present date must be a finite JSON number,
  `null` included. A token at or past `exp` plus the leeway has expired, and
  that is the only comparison `require_not_expired=False` switches off (the
  result's `expired` still reports it). A future `nbf` is rejected, and so is
  an `iat` more than the leeway in the future. The key-attestation JWT and the
  WRPRC keep their own date handling.

  The adversarial review of this change found three more gaps, closed here:
  - **The KB-JWT's own `exp`/`nbf` were never read.** A holder's KB-JWT with an
    expired, `NaN`, `null` or future-dated `exp`/`nbf` still bound. They are now
    binding failures (`KB-JWT is outside its own exp/nbf window`, or a malformed
    date), never an `expired` verdict, and the waiver does not cover them.
  - **The `exp` boundary was off by up to a second.** The helper truncated the
    clock to an integer and accepted a token exactly at `exp` plus the leeway.
    RFC 7519 §4.1.4 says the current time MUST be before `exp`, which is what
    PyJWT checks on the classic lane. The wall clock is now read unrounded, on
    the KB-JWT window too; a pinned `now` is still read to the second. Every
    comparison is a difference against the leeway, so even an absurd
    `leeway_s` stays a typed result rather than a bare `OverflowError`.
  - **A mistyped `now` on `verify_status_list_token`** (a string, a `date`,
    `NaN`) is a `StatusListError`. An epoch `int` is still accepted.
  - **An empty or non-string audience split the VC-JWT lanes.** PyJWT matched a
    list of audiences on the classic lane only, and an empty audience matched an
    empty `aud` on the ML-DSA lane only. Both are now refused up front.

### Changed

- **Behaviour change: tokens that used to verify are now rejected**
  ([ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md)). Each case fails closed with a typed error, and in
  `verify_many` it fails only its own item.
  - `"exp": null`, `"nbf": null` or `"iat": null` on an SD-JWT VC issuer JWT, a
    KB-JWT, a VP-JWT, a status-list token, and `exp`/`nbf: null` on an
    OpenID4VCI key proof (the KB-JWT and the key proof already required `iat`).
    These lanes used to read `null` as absent, or never read the claim. RFC 7519
    §2 defines a NumericDate as a JSON number, and VC-JWT already rejects `null`
    (#195). An issuer that serialises an unset date as `null` must leave the
    claim out instead.
  - An `iat` more than the leeway (60 s by default) in the future, on an SD-JWT
    VC issuer JWT, a VP-JWT, an ML-DSA VC-JWT or a status-list token. The expiry
    waiver does not cover it.
  - A KB-JWT whose own `exp` has passed or whose `nbf` has not arrived.
  - A status-list token whose `nbf` has not arrived. A pinned `now` earlier
    than the list's `iat`/`nbf` now rejects the list: it did not exist at that
    instant.
  - A token exactly at `exp` plus the leeway, on every lane that uses
    `check_jwt_temporal`. It used to verify for up to one more second.
  - A VC-JWT that carries `aud` when no audience is passed. Pass `audience=` to
    `VcJwtProofSuite.verify`, or `VerificationPolicy(audience=...)` to the
    pipeline, with a value from its `aud`. A VC-JWT without `aud` still
    verifies with no audience. A VC-JWT nested in a presentation is checked
    against `policy.audience`, so `verify_vp_token` rejects one that carries
    `aud`. VCDM's JWT encoding defines `aud` only for presentations, and none of
    the third-party VC-JWT or SD-JWT VC vectors in the test fixtures carries one.
  - An `aud` that is not a string or an array of strings, on either VC-JWT lane.
  - An expected audience that is not `None` or a non-empty string: a list,
    tuple or set (which the classic lane used to match through PyJWT), `""`, or
    a number. It is now a `ClaimsInvalid` on both VC-JWT lanes.

### Fixed

- **A clock pin that is not an instant is a typed error, not a bare
  `AttributeError` / `OverflowError`.** Found by the adversarial review of
  [#203](https://github.com/luisgf/openvc/pull/203). `check_validity_window` (every
  Data Integrity suite, and the credential-body window on VC-JWT and SD-JWT VC)
  read `now.tzinfo`. An epoch `int` or an ISO string raised `AttributeError`, and
  `datetime.max` at a negative UTC offset raised `OverflowError` on the way to UTC.
  A string or `None` `leeway_s` raised `TypeError`. Each of these escaped
  `OpenvcError`, so one bad `VerificationPolicy` aborted a whole `verify_many` /
  `verify_many_async` batch instead of failing each item. The SD-JWT KB-JWT check
  already typed the same mistake through `utc_epoch`.

  `openvc.proof._verify_common` gains `utc_instant`, the datetime-returning sibling
  of `utc_epoch`, and `utc_window`, which adds the leeway the way
  `check_validity_window` already did since 1.30.1: negative or `NaN` counts as 0,
  wider than `timedelta` saturates, and windows compare differences, never
  `instant ± leeway`. Seven copies of the same `now` reader now go through them,
  each raising its own error class:
  - the Data Integrity window (`ProofError`);
  - `x5c` (`X5cError`). An `x5c` VC-JWT verified with an `int` `policy.now`
    aborted `verify_many` there too;
  - mdoc (`MdocError`);
  - the WRPAC check (`RpCertError`);
  - the WRPRC window (`RpRegistrationError`);
  - the `walk_lotl` / `walk_lote` Trusted List walkers and the pinned LoTE signer
    check (`TrustListError`).
- **The mdoc and WRPRC windows no longer overflow.** Both added the leeway with
  datetime arithmetic. On mdoc it was added to the issuer's own dates, so an MSO
  with a "never expires" `validUntil` of `9999-12-31T23:59:59Z`, or a `validFrom`
  of `0001-01-01`, raised a bare `OverflowError` from `verify_device_response`. On
  the WRPRC window, a `leeway_s` past year 9999 raised one. Both now compare
  differences, like `check_validity_window`.

Side effects of the shared reader, all edge cases:

- A `tzinfo` whose `utcoffset()` returns `None` is naive by Python's definition.
  Such a pin is now read as UTC on these lanes. They used to read it as the host's
  local time.
- `now` is passed on as a plain `datetime` in UTC, so a caller's `datetime`
  subclass is not consulted again. A subclass whose UTC conversion is not UTC is a
  typed error.
- On mdoc, a negative `leeway_s` now counts as 0, as it already did on the Data
  Integrity and WRPRC windows. It used to narrow the window.


## [1.30.4] — 2026-10-13

### Fixed

- **`VpJwtProofSuite.verify` with a pinned `holder_key_jwk` and no `resolver`
  works again** ([#200](https://github.com/luisgf/openvc/issues/200)). It raised
  a bare `AttributeError` instead, even for a VP with no credentials, so the
  failure escaped `OpenvcError` and aborted batch callers. The resolver was
  defaulted only when the holder key was not pinned. Since 1.6.0
  ([#24](https://github.com/luisgf/openvc/issues/24)) the cascade passes it to
  `batch_resolvers`, which cannot take `None`. The resolver now defaults to
  `default_resolver()` whenever none is given, as in `verify_credential` and as
  before 1.6.0. A pinned key still decides the VP signature and is never
  resolved. The resolver serves only the embedded credentials' issuers. This
  failed closed: nothing verified that should not.

## [1.30.3] — 2026-10-13

### Security

- **A Data Integrity `proofPurpose` that is not a string now fails as
  `ProofMalformed`; a JSON array or object raised a bare `TypeError`**
  ([#208](https://github.com/luisgf/openvc/issues/208)). Found by a sweep of
  `src/` after the adversarial review of
  [#197](https://github.com/luisgf/openvc/pull/197). All five suites
  (`eddsa-rdfc-2022`, `eddsa-jcs-2022`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`,
  `ecdsa-sd-2023`) resolve the signing key before checking the signature, and
  look the proof's `proofPurpose` up in the DID document's verification
  relationships. A list or dict is unhashable, so the lookup raised `TypeError`.
  That is outside `OpenvcError`, so it aborted `verify_many` /
  `verify_many_async`. No key was needed. This was a crash, never a wrong accept.
  A number or boolean, which used to reach the purpose check as
  `ProofPurposeMismatch`, is now also `ProofMalformed`, and the check runs before
  the DID is resolved. `DidDocument.key_for_purpose` now returns `None` for a
  purpose that is not a string, including `None`. The JOSE header lanes with the
  same bug were fixed in 1.29.1
  ([#211](https://github.com/luisgf/openvc/issues/211)).
- **The WRPRC `typ` and the Data Integrity `proofPurpose` mismatch messages name
  an array or object by its type instead of quoting it**, like the allow-list
  messages since 1.29.1. Since 1.30.0 refuses JSON nested past 100 levels where it
  enters ([#213](https://github.com/luisgf/openvc/issues/213)), a value deep
  enough to overflow `repr()` no longer reaches them; this is defence in depth.

## [1.30.2] — 2026-10-13

### Security

- **The RDF Data Integrity suites now validate a document's JSON-LD form before any
  policy check reads it** ([GHSA-vrxg-57v4-85mc](https://github.com/luisgf/openvc/security/advisories/GHSA-vrxg-57v4-85mc)).
  This covers `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and `ecdsa-sd-2023`. They sign the
  RDF dataset a credential expands to. The checks that follow the signature read the
  JSON, and nothing tied the two together. Many JSON documents expand to the same
  dataset, so a holder could change the JSON and keep the signature valid. Every case
  below verified under the default policy, on the sync and async pipelines:
  - **Hide a signed member from the policy.** The member was re-keyed to its full IRI,
    or given a shorter alias by an inline `@context`, or moved into `@included` or into
    a second description of the credential's own node. This skipped an expired
    `validUntil`, a future `validFrom`, a revoked `credentialStatus`, a required
    `credentialSchema`, and the proof's own `expires`. It also worked on a derived
    `ecdsa-sd-2023` credential whose validity window was mandatory.
  - **Spoof `credentialSubject`.** An inline copy of the VC context replaced the real
    one, so that `credentialSubject` named the presenter while the signed subject sat
    under another key. The result reported the presenter as the subject. Inside an
    `ldp_vc` presentation this passed `require_cryptographic_holder_binding`, so a
    holder could present someone else's credential as their own.
  - **Add unsigned claims.** The bundled v2 context has no `@vocab`. JSON-LD drops a
    term no context defines, so the signature never covered it, and any value placed
    under such a term (`credentialSubject.age_over_18: true`) verified.

  The JCS suites sign the JSON itself and were not affected, nor were VC-JWT and
  SD-JWT VC. After the proof verifies, and before signing, the RDF suites now apply
  context validation (VC Data Integrity §2.4.1). A document that fails raises a typed
  `ProofMalformed`:
  - `@context` must start with the VC base context (v2, or v1 through
    `extra_contexts`). After that, only context URLs the offline loader serves are
    allowed, plus inline objects that carry nothing but an absolute-IRI `@vocab`.
  - The document and its proof must be the compacted form of their own expansion
    under that context. The only accepted variations are a one-element array for its
    element and `{"id": X}` for `X`, which JSON-LD treats as the same value.
  - `@included`, `@reverse`, a top-level `@graph`, and a nested second description of
    the document's own node are refused.
  - Nothing may be dropped on the way to RDF (JSON-LD "safe mode"). That refuses a
    node id, type or property that is not a well-formed absolute IRI, a blank-node
    property, and `@index` / `@direction` annotations, none of which reach the signed
    dataset.
  - In a `VerifiablePresentation`, the embedded credentials are skipped by this check.
    Each one is verified on its own, under its own `@context`.

  **What this rejects that used to be accepted.** These documents were never fully
  covered by their signature, and other verifiers that apply context validation
  reject them too:
  - A credential carrying a term its contexts do not define. Issuing one with
    `add_proof` / `add_base_proof` now raises `ProofMalformed` instead of signing a
    document whose claim is not signed. Define custom terms with an inline
    `{"@vocab": "…"}` or with a context passed through `extra_contexts`.
  - An inline `@context` object with term definitions.
  - A relative IRI, such as `verification_method="k"`. JSON-LD resolved it against
    pyld's default base, so the dataset signed `http://example.org/base/k`.
  - `@index` and `@direction` annotations. openvc canonicalizes without
    `rdfDirection`, so neither was ever signed.

  The W3C golden vectors for all three suites still verify unchanged. A context
  passed through `extra_contexts` stays trusted: one that gives a core VC term a
  second, shorter name can still hide that member, so inject only contexts you have
  reviewed ([details](https://github.com/luisgf/openvc/wiki/Data-Integrity#the-json-must-be-what-was-signed)).

  Fixed before merge, from this change's own adversarial review:
  - **A blank-node `@vocab` re-opened unsigned claims.** With `{"@vocab": "_:"}`,
    every undefined term became a blank-node property. RDF conversion drops those, yet
    compaction reproduced them, so the round trip alone passed. Now an inline `@vocab`
    must be an absolute IRI, and the safe-mode rule refuses blank-node properties.
  - **A whole forged top level could ride on a dropped node id.** RDF conversion drops
    every statement whose subject is not a well-formed IRI, for example
    `"id": "urn:forged x"`. The credential's real node, restated under any of the forged
    node's properties, kept the dataset identical. This needed no inline context. It is
    the same mechanism as the `{"@base": null}` + `@included` forgery (pinned too). The
    safe-mode rule closes both.
  - `@index` and `@direction` let a value change shape without changing the dataset.
    Both are refused now.
  - A `@context` whose first entry was an object raised a bare `TypeError` in the new
    check. It is now a typed `ProofMalformed`.

## [1.30.1] — 2026-10-13

### Security

- **A W3C credential secured as SD-JWT is now held to its own `validFrom` /
  `validUntil`** ([#198](https://github.com/luisgf/openvc/issues/198)). Found by
  the adversarial review of [#188](https://github.com/luisgf/openvc/pull/188).
  The SD-JWT lane enforced only the JWT `exp` / `nbf`, on both pipelines. That
  let a VCDM credential secured with SD-JWT (VC-JOSE-COSE `vc+sd-jwt`), whose only
  expiry was a past `validUntil`, verify under the default policy, bare or inside
  an `EnvelopedVerifiableCredential`. VC-JOSE-COSE §3.2.1 makes that credential
  the SD-JWT's claim set itself. §3.1.3 says, for the JOSE encoding SD-JWT builds
  on, that `exp` dates the signature, not the data. `SdJwtVcProofSuite.verify` now
  applies the same VCDM window check as the VC-JWT lane:
  - `validFrom` / `validUntil`, or the VCDM 1.1 `issuanceDate` /
    `expirationDate`, are checked on the processed payload, so a disclosed
    `validUntil` counts.
  - It uses the current time and the suite leeway, like the VC-JWT lane.
  - A present but unparseable value fails closed (`MalformedTimestamp`).
  - `require_not_expired=False` waives only the expiry. `VerifiedSdJwt.expired`
    (1.30.0) then reports it, so `VerificationResult.expired` is `True`.

  The payload counts as a VCDM credential when its `@context` names a VCDM base
  context, or when its `typ` is `vc+sd-jwt` and it has no `vct` (a non-empty
  string). Both signals are read from the issuer-signed SD-JWT; the media type of
  an enveloping `data:` URL is not consulted.
  **IETF SD-JWT VCs are unaffected:** a `dc+sd-jwt` one, or one with the
  pre-draft-06 `vc+sd-jwt` typ and a `vct`, that merely has a claim named
  `validUntil` still verifies, and is not reported `expired`, because that name
  is not a validity bound in its vocabulary. With key binding required, the
  window is checked after the KB-JWT, so an expiry verdict still means the
  presentation was bound.

  Fixed before merge, from this change's own adversarial review:
  - **A very large `leeway_s` no longer crashes the validity-window check.** It
    added the leeway to a `datetime`, so a leeway beyond that type's range raised
    a bare `OverflowError` that aborted `verify_many`, on every lane that checks
    `validFrom` / `validUntil`. The check now compares differences, so any leeway
    is honoured as given.
  - A `vct` that is not a non-empty string (`""`, `0`, `[]`) no longer counts as
    one, so it cannot switch the `vc+sd-jwt` rule off.

### Tests

- `tests/test_sd_jwt_vcdm_validity.py` pins #198 in both directions through
  `verify_credential` and `verify_credential_async`, bare and enveloped: every
  VCDM signal enforces the window (including the waiver's `expired=True`), and
  IETF claims named like VCDM bounds are neither enforced nor flagged.

## [1.30.0] — 2026-10-13

### Security

- **A Key Binding JWT checked against only `audience` or only `nonce` is now
  rejected** ([#191](https://github.com/luisgf/openvc/issues/191)). At the top
  level (`verify_credential`, `verify_credential_async` and
  `SdJwtVcProofSuite.verify`), the KB-JWT's `aud` was checked only when an
  `audience` was passed and its `nonce` only when a `nonce` was passed, each
  independently. A caller that passed one of the two got `key_bound=True` for a
  KB-JWT that was never bound to it. With `audience` alone, a KB-JWT from another
  of the verifier's own sessions verified. With `nonce` alone, one made for
  another verifier verified. RFC 9901 §7.3 step 5.6 binds a KB-JWT by validating
  `nonce` **and** `aud`, and one of them is not a binding.

  When a KB-JWT is present and exactly one of `audience` / `nonce` is given,
  verification now raises `ClaimsInvalid` before any KB-JWT parsing or crypto
  runs. The same call with **no** KB-JWT still verifies, with `key_bound=False`,
  because `VerificationPolicy.audience` also pins a VC-JWT's `aud` and a policy
  carrying `audience` alone must keep working for those. Passing both values as
  non-empty strings, or neither, is unchanged, as is `require_key_binding=True`
  with a missing value (already refused); the one empty-value change is below.
  The KB-JWT `iat` window from 1.28.0 limited this to near-real-time
  replay. No openvc lane was affected: `verify_vp_token` and the VP cascades
  always pass both values.

  The fix stops a misleading `key_bound=True`. It does not, by itself, stop the
  replay: an attacker who strips the KB-JWT gets the same credential through with
  an honest `key_bound=False`. A caller who needs the holder binding still has to
  set `require_key_binding=True` or check `key_bound`. openvc raises rather than downgrade the flag because a
  half-configured call is a caller error that a quiet `False` would hide; the error
  points at the missing value. Passing **neither** value keeps its documented
  meaning: `key_bound=True` then proves possession of the `cnf` key for some
  verifier, not a binding to you. Changing that would change a value callers gate
  on, so it is out of scope for a patch. The wiki (*SD-JWT VC → What `key_bound`
  attests*) now has a table of every case.

  Fixed before merge, from this change's own adversarial review:
  - **An empty `audience` or `nonce` no longer counts as a binding value.** With
    both values passed, one of them empty (`nonce=""`, say, from a lost session),
    the KB-JWT was checked against `""`. Any KB-JWT the holder had signed with an
    empty nonce for that audience verified, even with `require_key_binding=True`.
    That is an audience-only binding in disguise. When either value is passed, a
    present KB-JWT is now refused (`ClaimsInvalid`) unless both are non-empty
    strings, matching the VP-JWT, OpenID4VP and nested-binding gates, which already
    refused `""`.
- **JSON nested deeper than 100 levels is refused where it enters openvc, so it can no
  longer escape the typed-error boundary as a bare `RecursionError`**
  ([#213](https://github.com/luisgf/openvc/issues/213)). Found by the adversarial
  reviews of [#194](https://github.com/luisgf/openvc/pull/194) and of this change. On
  Python 3.14, `json.loads` accepts about 116k levels of nesting, but `repr()` of the
  result overflows at about 70k and `==` between two such values at about 43k. More
  than 40 sites formatted or compared an attacker-controlled value: error messages,
  status parsing, DID and JWK handling, issuer metadata. Each raised a bare
  `RecursionError`, which escaped `OpenvcError` and aborted a whole `verify_many` /
  `verify_many_async` batch. Several needed no valid signature: a `did:jwk` issuer's
  `kty`, a JWE protected header on the `direct_post.jwt` path, a DID document served by
  the attacker's own `did:web` host, the DC API audience peek. Others needed only a
  self-issued `did:key` signature, such as a `credentialStatus.statusListIndex`, which
  is parsed even with no status resolver.

  Rather than make each site safe, openvc now bounds the input:
  - every untrusted JSON parse goes through one loader that refuses nesting deeper than
    100 levels, the same bound the JCS canonicaliser and the SD-JWT unpacker already
    apply. That covers every JWS header and payload, SD-JWT disclosures, JWE headers,
    `vp_token`, enveloped credentials, `did:jwk`, `did:webvh` logs, fetched JSON,
    schemas, type metadata, LoTE lists and the EBSI registry client. The failure is the
    format's own typed parse error (`MalformedToken`, `SdJwtError`, `JweMalformed`,
    `VpTokenMalformed`, ...);
  - objects openvc receives already parsed are held to the same bound: a credential or
    `vp_token` dict, a Data Integrity suite's input, a DID document or JWT VC Issuer
    metadata from an injected fetch, and a relying party's DCQL query in
    `check_request_within_registration`;
  - `verify_credential`, `verify_credential_async` and `verify_vp_token` map any
    `RecursionError` that still reaches them to `UnknownCredentialFormat` /
    `VpTokenMalformed`, as a backstop.

  No real credential, DID document, status list or trust list nests anywhere near 100
  levels. The bound applies on every Python version, so the typed class no longer
  depends on the interpreter.
- **Error messages no longer quote an untrusted container or an unbounded string.**
  `safe_repr` (from [#212](https://github.com/luisgf/openvc/pull/212)) now cuts a
  string past 200 characters and names an int past 64 bits by its type (`repr()` of an
  int over 4300 digits raises `ValueError`). It is now used for a Data Integrity
  `proof.type` / `cryptosuite` (including `ecdsa-sd-2023`), the validity dates, the
  `challenge` / `domain` binding, the DC API audience, a VP-JWT `aud`, a VC-JWT's
  `vc.issuer` / `credentialSubject.id` / `vc.id`, a JWT VC Issuer's metadata `issuer`
  and `kid`, the `kid` and issuer DID in key-resolution errors (sync and async), and
  the `kty` / `crv` of a key that caller code supplies (a pinned JWK, a custom resolver,
  an OpenID4VCI `resolve_proof_key`). A multi-megabyte `did:jwk` used to be quoted in
  full.
- **`VpJwtProofSuite.peek_holder` rejects a non-string `kid` with `MalformedToken`**, as
  `VcJwtProofSuite.peek_issuer` already did.
- **The ML-DSA VC-JWT lane rejects a non-string `sub` or `jti`, as the PyJWT lane
  does**, so `_reconcile` never compares two attacker containers with `!=`. The lane is
  experimental and opt-in (`VcJwtProofSuite(allow_pq=True)`); the pipeline never
  enables it.

- **A VC-JWT with a malformed `exp`, `nbf` or `iat` no longer aborts a whole
  `verify_many` batch** ([#195](https://github.com/luisgf/openvc/pull/195)).
  openvc handed these claims to PyJWT, which casts them with `int()` and
  catches only `ValueError`. Under the default policy, a signed
  `"nbf": null`, `"iat": []` or `"exp": {}` raised a bare `TypeError` from
  `verify_credential`, `verify_credential_async` and `VcJwtProofSuite.verify`.
  `TypeError` is not an `OpenvcError`. `verify_many` and `verify_many_async`
  catch only `OpenvcError` per item, so the error escaped and took every other
  result in the batch with it. That broke the typed-error boundary of
  [#99](https://github.com/luisgf/openvc/issues/99). Anyone could mint such a
  token: a self-issued `did:jwk` is enough. Under `require_not_expired=False`,
  PyJWT skipped `exp` altogether, so an `exp` of `NaN`, `±Infinity`, `"abc"`,
  `1e400`, `null`, `[]` or `{}` verified. The SD-JWT VC and ML-DSA lanes
  already rejected these `exp` values, apart from `null`.

  The VC-JWT suite now checks the shape of `exp`, `nbf` and `iat` before PyJWT
  reads them. It uses `is_numeric_date`, the helper the SD-JWT lane already
  uses for `exp` / `nbf`. A present value that is not a finite JSON number is a
  `ClaimsInvalid` on both the classic and the ML-DSA lane, whatever the expiry
  policy, and `verify_many` reports it as that item's error while the rest
  still verify. The check runs on the payload before the signature, so a token
  that is both forged and malformed now reports `ClaimsInvalid` rather than
  `SignatureInvalid`. Either way it is rejected.

  The adversarial review of this fix found two more ways a signed VC-JWT could
  escape PyJWT untyped, both closed here. On Python 3.10 and 3.11 the JSON
  depth limit shrinks as the stack grows, and PyJWT parses the payload a few
  frames deeper than openvc does. A narrow band of nesting depths therefore
  passed openvc's parse and raised a bare `RecursionError` inside PyJWT. One
  batch carrying a ladder of depths always hit it, and `verify_vp_token` was
  exposed the same way. Separately, a lone surrogate in the signature segment
  raised a bare `UnicodeEncodeError`. A non-ASCII token is now a
  `MalformedToken` before anything is decoded. As a backstop, a `TypeError`,
  `ValueError` or `RecursionError` from PyJWT is now caught as
  `ClaimsInvalid`.

  Some tokens that used to verify are now rejected: a numeric string
  (`"exp": "1999999999"`), a bool (`"nbf": true`) and an integer too large for
  a float. PyJWT `int()`-cast the first two, and the third never expires.
  RFC 7519 §2 defines a NumericDate as a JSON number. On the ML-DSA lane,
  `null` is now rejected rather than read as absent, and the shape of `iat` is
  checked for the first time. That lane still does not reject a future `iat`,
  which the classic lane does.

### Added

- **The proof suites report the expiry they waived.** `VerifiedCredential`,
  `VerifiedSdJwt`, `VerifiedDataIntegrity` and `VerifiedSdCredential` gain
  `expired: bool = False`, appended with a default (the frozen return-object
  contract is updated; positional constructions keep working). Called with
  `check_temporal=False`, a suite sets it when an expiry check it skipped would
  have failed:
  - VC-JWT: the JWT `exp`, as PyJWT judges it, or the body's `validUntil` /
    `expirationDate`;
  - SD-JWT VC: `exp`;
  - Data Integrity: the credential's `validUntil` / `expirationDate`, or the
    proof's own `expires`.

  With `check_temporal=True` it is always `False`, because an expiry raises.
  `check_validity_window` and `check_jwt_temporal` (`openvc.proof._verify_common`)
  return the same verdict as a `bool`.

### Changed

- **An expired or revoked `JsonSchemaCredential` now fails under every
  policy.** The schema VC's inner verification copied `require_not_expired` /
  `require_not_revoked` from the outer policy, and kept only the credential from
  that result. Under the waiver an expired schema VC was therefore applied, with
  `schema.validated=True` and `expired=False`, while the default policy rejects
  it with `SchemaResolutionError`. The waivers concern the verified credential's
  own disposition. The schema VC is a trust input that credential depends on,
  like a status-list credential (which the blessed resolvers verify under the
  default policy) or an `x5c` chain, so it no longer inherits them. One helper
  now builds the inner policy for both pipelines.
- **Under the waiver, PyJWT still judges a VC-JWT's `exp`.** The suite used to
  switch PyJWT's `exp` check off when expiry was waived. It now decodes with the
  check on, and decodes again without it only after PyJWT reports an expiry, so
  every other claim check still runs and a waived `exp` is judged exactly as the
  default policy judges it. Malformed `exp` / `nbf` / `iat` shapes are refused
  before PyJWT under both policies
  ([#195](https://github.com/luisgf/openvc/pull/195)).
- `openvc.verify` no longer imports `CredentialExpired`, `ProofError`,
  `check_validity_window` or `check_jwt_temporal`. The removed helper had
  pulled them in since 1.27.0; they were never in its `__all__`. Import them
  from `openvc.proof.errors` and `openvc.proof._verify_common`.
- **A deeply nested input now fails with its format's parse-time error class.** On
  Python 3.14 a few deep inputs used to parse and fail at a later check, so a caller that
  matches on the class sees it change:
  - a deep dict passed to `verify_credential` now raises `UnknownCredentialFormat` (a
    `VerificationError`), where the Data Integrity suite used to raise a `ProofError`;
  - a deep LDP-VP raises `VpTokenMalformed`, not `UnsupportedPresentationFormat`;
  - a deep JWE header raises `JweMalformed`, not `UnsupportedJweAlgorithm`;
  - a deep LoTE header raises `TrustListParseError`, not `TrustListSignatureError`.

  All of them are still `OpenvcError`, and all still fail closed. JSON nested deeper than
  100 levels is rejected wherever openvc parses it.

### Fixed

- **`VerificationResult.expired` is now the default policy's verdict.**
  `VerificationPolicy(require_not_expired=False)` (1.27.0) reports a waived
  expiry as `expired=True`. `openvc.verify` computed the flag by re-deriving
  expiry with other clocks and fields than the proof suites enforce, so it could
  disagree with the verdict it stood in for. The values below were identical on
  the sync and async pipelines, which 1.28.0 had made agree:

  | Credential | Default policy | `expired` under the waiver in 1.29.2 |
  |---|---|---|
  | Data Integrity proof whose own `expires` passed (every suite, ecdsa-sd-2023 derived and P-384 included) | `CredentialExpired: proof expired` | `False` |
  | VC-JWT body `validUntil` passed at the current time, `policy.now` pinned before it | `CredentialExpired` | `False` |
  | VC-JWT body `validUntil` still ahead, `policy.now` pinned after it | accepted | `True` |
  | VC-JWT `exp` PyJWT coerces to a past date (`"1000"`, `true`, `-10**400`) | `ClaimsInvalid: Signature has expired` | `False` |
  | VC-JWT `exp` = `int(now) - leeway`, or a float PyJWT truncates past it | `ClaimsInvalid: Signature has expired` | `False` |
  | SD-JWT VC with a past VCDM `validUntil` / `expirationDate` claim | accepted | `True` |

  A `False` above is fail-open for a caller who acts on the flag. Each suite now
  reports the expiry check it skipped (see *Added*); both pipelines copy that
  verdict and `_expired_flag` is gone, along with its match on the error
  message's text. `expired` is now `True` exactly when the default policy would
  have rejected the credential for its own expiry. Found by the adversarial
  review of [#188](https://github.com/luisgf/openvc/pull/188).

- **A hostile `did:web`, `did:webvh` or https issuer host is a typed error, not a
  bare `ValueError`** ([#207](https://github.com/luisgf/openvc/issues/207)).
  Found by the adversarial review of
  [#202](https://github.com/luisgf/openvc/pull/202), which did not cause it. The
  host reached `urlparse`, `getaddrinfo` and `http.client` unchecked. A port out
  of range or not an integer, an unbalanced `[`, a host that NFKC-normalizes into
  a delimiter (`ex℀mple.com`), an IDNA label over 63 characters and a NUL each
  raised its own bare exception (`ValueError`, `UnicodeError`,
  `http.client.InvalidURL`). None is an `OpenvcError`, so one such credential
  aborted a whole `verify_many` / `verify_many_async` batch. This reached
  `verify_credential`, `VpJwtProofSuite.verify` (the holder key and the
  cascade), `verify_vp_token` (`jwt_vc_json` before the signature check, and the
  `ldp_vc` cascade), the async twins, and the opt-in `jwt_vc_issuer_fetch` lane.
  It failed closed before any TCP connection, so it was not an SSRF.

  Two layers now type it. `did:web` and `did:webvh` check the host before any
  fetch, the caller's own fetch included. It must be a domain name of RFC 1123
  labels with an optional port from 1 to 65535, or they raise
  `DidResolutionError` (`DidWebvhError` for did:webvh). A Unicode host is checked
  in its IDNA form and passed through unchanged. The SSRF-guarded fetch raises
  `UnsafeUrlError` for a URL it cannot parse or a host with a control character,
  before DNS, and `DidResolutionError` when the request line cannot be encoded
  (a non-ASCII path). That covers status-list, schema and well-known URLs too.
  `jwt_vc_issuer_metadata_url` raises `JwtVcIssuerError`, and an unparseable
  https `iss` is unbound in the x5c SAN check (`X5cError`).

  A did:web host that is not a domain name now fails before the fetch: a
  bracketed IP literal (the did:web spec forbids IP addresses), an empty port or
  port `0`, a trailing root dot, or an `@`, `/` or `#` decoded from the host.
  `did:web:evil.com%40example.com` used to fetch from `example.com`.

### Tests

- `tests/test_expired_flag_parity.py` gains a case per row above, all run
  through both pipelines. Each one requires `expired` to equal "the default
  policy rejected this for expiry":
  - a proof `expires` on all seven Data Integrity suite/curve combinations;
  - both clock directions of the VC-JWT body;
  - the PyJWT-coerced and boundary `exp`s;
  - the SD-JWT VCDM claims;
  - the expired and current schema VC.

  The coerced-`exp` cases assert only agreement with the default policy, so
  they hold whether those values are read as dates or refused as malformed. The
  shared helpers' `bool` is pinned too. 27 of the new tests fail on 1.29.2.

## [1.29.2] — 2026-10-13

### Security

- **A hostile status-list index is a typed `StatusListError`, not a bare
  `OverflowError` that aborts a whole batch.** `parse_status_entries` read
  `credentialStatus.statusListIndex` with `int()` and caught `TypeError` /
  `ValueError` but not `OverflowError`. A signed VC-JWT whose index was
  `Infinity`, `-Infinity`, `1e400` or `-1e400` (`json.loads` reads the last two
  as infinities) raised `OverflowError: cannot convert float infinity to
  integer`. That escaped `OpenvcError`, so it aborted `verify_many` /
  `verify_many_async` for every item, not just the bad one, and escaped
  `verify_credential` / `verify_credential_async` too. A self-issued `did:jwk`
  could mint one. `require_status=False` did not help: the entries are parsed
  before the resolver check. Both `BitstringStatusListEntry` and
  `StatusList2021Entry` were affected.

  The W3C `statusListIndex` and the IETF Token Status List `status.status_list.idx`
  (SD-JWT VC, or a VC-JWT's JWT payload) now share one index rule. A
  non-negative integer is accepted, and for the W3C index so is a string of ASCII
  digits, which is the form the REC requires. The rule now also rejects inputs
  that `int()` silently coerced into a different bit:
  - a `bool` (`true` was read as index 1);
  - any `float`, including `NaN` and an integral `5.0` (`3.7` was read as 3);
  - a sign, whitespace, an underscore or a non-ASCII digit in the string
    (`"+5"`, `" 5"`, `"5_0"` and `"٥"` were read as 5, 5, 50 and 5);
  - a negative index, or one at or past 2^27, the most statuses any list openvc
    decodes can hold (the 16 MiB decompression cap at one bit per status).
    Neither can address a bit. Both used to pass parsing and failed only once a
    list was fetched, so they passed outright under `require_status=False`.

  A W3C index that `int()` refused (`"abc"`) already failed this way, even under
  `require_status=False`. These shapes now do too, and in a batch they fail only
  their own item. The IETF parser already refused floats, bools and negatives;
  it now also refuses an `idx` past the cap. Error messages never `repr()` a
  container or an integer wider than 64 bits.

Fixed before merge, from this change's own adversarial review. Each item below
was also a bare exception that aborted a whole `verify_many` batch. The
"deeply nested" ones need Python 3.14: its `json.loads` accepts arrays nested
deeper than `str()` / `repr()` can render, so they raise `RecursionError`.
Older Pythons refuse such JSON up front with a typed `MalformedToken`.
- **A status entry's `statusListCredential` or `status_list.uri` must be a
  string.** Both were passed through `str()`, so a deeply nested array raised
  `RecursionError`. This reached `verify_credential` and the batch under
  `require_status=False`, with a self-issued `did:jwk`. A number or an object
  used to become a garbage URL; it is now a `StatusListError` too.
- **A W3C entry's `statusPurpose` must be a string.** An explicit `null` used to
  match no purpose, so a set bit was ignored when the list declared no purpose.
- **A corrupt `encodedList` is a `StatusListError`, not a bare `zlib.error`.**
  `decode_bitstring` caught `OSError` but not the `zlib.error` that `GzipFile`
  raises on a valid gzip header followed by bad DEFLATE data. An 18-byte list
  served by the credential's own issuer was enough, even with
  `require_status_issuer_binding=True`. The IETF decoder already caught it.
- **The status messages no longer `repr()` attacker values.** That covered:
  - a W3C list's `statusPurpose`, and its non-string `encodedList`;
  - an IETF list's `bits`;
  - a status-list token's `typ`, `sub` and `exp`, in `verify_status_list_token`
    (which the default token resolver runs);
  - the credential `id` in "credential … is revoked/suspended", in `verify`,
    `aio` and `openvc_ebsi`. A self-issued credential controls both that `id`
    and its own list's bit.
- **A resolver that returns something other than an object is a
  `StatusListError`**, not a bare `AttributeError`.
- **A status-list token's `exp` must be a finite number.** `NaN`, `±Infinity`
  and a bignum used to pass, and every comparison against them reads "not
  expired". This now follows the same rule as `check_jwt_temporal`.

## [1.29.1] — 2026-10-13

### Fixed

- **An unhashable `alg`, `typ`, `_sd_alg` or `cryptosuite` is a typed error, not a
  bare `TypeError`** ([#211](https://github.com/luisgf/openvc/issues/211)). Found
  by the adversarial review of [#194](https://github.com/luisgf/openvc/pull/194).
  Eight allow-list checks ran `value not in <set>` on a value read from the token
  without first checking that it was a string. A JSON array or object is
  unhashable, so the test raised a bare `TypeError` that escaped `OpenvcError`, and
  one such item aborted a whole `verify_many` / `verify_many_async` batch. None of
  them needs a trusted key. Most run before any signature check, and the rest need
  only a signature that any `did:key` can make:
  - the `alg` of a VC-JWT, and of every token verified through the shared
    compact-JWS layer: a VP-JWT (a `jwt_vc_json` presentation, or a VC-JWT nested in
    one), the IETF status-list token and the OpenID4VCI key proof;
  - the SD-JWT issuer JWT's `alg` and `typ`, and the Key Binding JWT's `alg`;
  - the SD-JWT `_sd_alg`;
  - the OpenID4VP `ldp_vc` holder proof's `cryptosuite`;
  - the OpenID4VCI key proof's `typ`.

  Each now raises the class that a well-formed but disallowed value already got:
  `UnsupportedAlgorithm` for an `alg`, `SdJwtError` for the SD-JWT `typ` and
  `_sd_alg`, `UnsupportedPresentationFormat` for the cryptosuite, and
  `ClaimsInvalid` for the key-proof `typ`.
- **The allow-list error messages name a rejected container by its type.** On
  Python 3.14 `json.loads` accepts an array nested deeply enough that `repr()` of it
  raises a bare `RecursionError`. A message that quoted the value with `repr()` then
  escaped `OpenvcError` from the very `raise` meant to report it. This covers the
  sites above, plus the JWE `alg` / `enc`, WRPRC `alg` and LoTE `alg` checks. Those
  already type-checked the value but still quoted it.

## [1.29.0] — 2026-10-12

### Security

- **`verify_vp_token` now enforces a DCQL query's `require_cryptographic_holder_binding`
  on the W3C presentation formats** (`jwt_vc_json`, `ldp_vc`)
  ([#196](https://github.com/luisgf/openvc/issues/196)). The flag defaults to
  `true` (OpenID4VP 1.0 §6.1), but only the `dc+sd-jwt` lane read it. A VP proved
  that *someone* signed for this exchange, and nothing tied that signer to the
  credentials inside. A verifier that had once received a victim's credential could
  wrap it in its own VP, correctly bound to another verifier, and present it there.
  The response verified, with `holder` = the attacker. This worked with a VC-JWT, a
  Data Integrity VC, or an SD-JWT VC with its KB-JWT stripped (`key_bound=False`),
  bare or enveloped. It held with the flag left at its default and with it set
  explicitly to `true`; only the opt-in `require_holder_binding=True` blocked it.

  When the query requires holder binding, every credential a W3C presentation embeds
  must now be bound to the authenticated holder, or the whole response is rejected
  (`ClaimsInvalid`). OpenID4VP §2 defines that binding as control of the key the
  credential was bound to, and §B.1 requires it for a presentation of a W3C VC.
  - A **VC-JWT** or **Data Integrity** VC must name the authenticated VP signer as
    its subject (`sub` / `credentialSubject.id`). The signer is the VP-JWT `iss`
    whose DID document holds the signing key, or the controller of the Data
    Integrity `verificationMethod`.
  - A nested **SD-JWT VC** must carry a KB-JWT bound to this exchange
    (`key_bound=True`). That is the `dc+sd-jwt` rule, and RFC 9901 §9.5 says the
    need for key binding is policy, never whether a KB-JWT arrived. One without a
    KB-JWT, or without `cnf`, is rejected. The VP signer never stands in for the
    `cnf` key, even when it is the same key.

  Fixed before merge, from this change's own adversarial review:
  - **A VC-JWT with a `credentialSubject` array no longer passes the subject rule on
    its `sub`.** `VcJwtProofSuite` reports the JWT `sub` as the subject whenever it
    is a string, and reconciles it only with a `credentialSubject` *object*. An
    array, even one naming someone else, slipped through when `sub` was the
    holder. Holder binding now needs a single subject; any array fails closed. The
    `sub` is issuer-signed, so this was not attacker-forgeable.
  - The review's other two findings had already shipped in 1.28.2
    ([#194](https://github.com/luisgf/openvc/pull/194)). An empty `jwt_vc_json` VP
    would otherwise meet the new binding vacuously; a junk
    `vp.verifiableCredential` raised a bare `TypeError`.
- **A non-boolean `require_cryptographic_holder_binding` is `VpTokenMalformed`** on
  every Credential Query, `dc+sd-jwt` included. The `dc+sd-jwt` lane coerced it with
  `bool()`, so a `null` or a `0` silently opted the query out of holder binding.

### Changed

- **Under a default DCQL query, `jwt_vc_json` / `ldp_vc` responses that used to verify
  are now rejected.** These are responses whose credentials are not bound to the
  presenter:
  - another party's credential;
  - a bearer credential with no subject id;
  - a credential whose `credentialSubject` is an array;
  - a credential issued to the same key under another DID method (subjects and
    signers are compared as DID strings);
  - a nested SD-JWT VC with no KB-JWT.

  The `verify_vp_token` docstring described subject binding as "off by default". That
  was true of `require_holder_binding`, but it ignored the query's own default. This
  ships as a security fix in a minor release: no parameter default changes, and the
  query has always asked for holder binding. To keep accepting such credentials, set
  `"require_cryptographic_holder_binding": false` in that Credential Query.
  OpenID4VP §14.1.1 describes the risk you then accept. Two limits remain:
  - §B.1 tells a conformant wallet to answer an opted-out query with a bare
    credential, and the W3C lanes still require a presentation (a separate gap).
  - `require_holder_binding=True` keeps its stricter meaning, whatever the query
    says: every embedded credential's subject, an SD-JWT VC's `sub` included, must
    be the holder.

  `VpJwtProofSuite.verify` takes no DCQL query and is unchanged. The semantics are
  written up in the wiki under *Presentations → Holder binding on the W3C formats*.

## [1.28.2] — 2026-10-12

### Security

- **A `jwt_vc_json` presentation must embed at least one credential**
  ([#193](https://github.com/luisgf/openvc/issues/193)). Found by the
  adversarial review of [#190](https://github.com/luisgf/openvc/pull/190),
  together with the typed-error fixes below. `verify_vp_token` accepted a VP-JWT
  whose `vp.verifiableCredential` was `[]` or missing and returned a verified
  presentation with zero credentials. The Credential Query counted as answered
  with nothing presented, and `require_holder_binding=True` held vacuously. That
  lane now raises `VpTokenMalformed`, as the `ldp_vc` lane already did.

  This guarantees that a credential was presented and verified, nothing more.
  For `jwt_vc_json` and `ldp_vc`, openvc does not match the DCQL
  `meta.type_values` and never judges the issuer: a credential the holder minted
  from their own `did:key` still answers the query. Check each result's `issuer`
  and `type` against what you trust. `VpJwtProofSuite.verify` still accepts a
  credential-less VP, which VCDM allows (DID Auth, for example). It returns an
  empty `credentials` tuple; a caller that needs a credential must check for one.

### Fixed

- **A dict credential whose `type` is not a string or an array is
  `UnknownCredentialFormat`, not a bare `TypeError`.** `detect_format` ran
  `"EnvelopedVerifiableCredential" in types` on a `type` of `null`, a number or a
  bool. This was reachable at the top level, inside an
  `EnvelopedVerifiableCredential`, and nested in `jwt_vc_json` and `ldp_vc`
  presentations. The exception escaped `OpenvcError`, so one such item aborted a
  whole `verify_many` / `verify_many_async` batch instead of becoming that item's
  `error`. A `type` that is a JSON object is rejected the same way. A missing
  `type` still classifies by the proof.
- **A signed VC-JWT whose `vc.type` is not a string or an array fails
  `expected_types` with a typed error.** The same membership test in
  `_check_types` crashed once `policy.expected_types` was set. The pipeline now
  raises `TypeMismatch`, and `VcJwtProofSuite.verify(expected_types=…)` raises
  `ClaimsInvalid`. Any `did:key` can issue, so the issuer signature does not make
  this shape trusted.
- **A VP-JWT `vp.verifiableCredential` of `5`, `null`, `true` or `1.5` is
  `ClaimsInvalid`, not a bare `TypeError`.** `VpJwtProofSuite.verify` ran
  `list(raw)` on any value that was not a string or an object. An explicit `null`
  counts as malformed, not as absent.

Fixed before merge, from this change's own adversarial review:
- **A `type` that is a JSON object no longer satisfies `expected_types` through
  its keys.** `{"UniversityDegreeCredential": true}` passed a check for
  `UniversityDegreeCredential`, on the VC-JWT and Data Integrity paths alike. It
  now fails (`TypeMismatch`, or `UnknownCredentialFormat` at detection). The
  issuer could have signed that type as an array, so this grants nothing an
  issuer could not already claim, but the shape is malformed.
- **A deeply nested `proof.cryptosuite` is `UnknownCredentialFormat`, not a bare
  `RecursionError`.** `detect_format` put the value's `repr()` in its error
  message. On Python 3.14 `json.loads` accepts nesting deep enough to overflow
  `repr()`. A non-string cryptosuite is now named by its type.
- A `tuple` `type`, from a Python caller that built the credential in-process,
  is still accepted as an array.

### Fixed (docs)

- **The expiry and revocation waivers have a wiki home.**
  `VerificationPolicy.require_not_expired` / `require_not_revoked` and
  `VerificationResult.expired` shipped in 1.27.0 with only a passing mention in
  the manual. Getting Started now has a *Waiving expiry or revocation* section.
  It covers what each knob waives and what still runs, and how to read the
  result (`expired`, `status.revoked`). It also notes that the sync and async
  pipelines compute `expired` identically since 1.28.0
  ([#188](https://github.com/luisgf/openvc/pull/188)), and carries a runnable
  offline example. The SD-JWT VC and Status lists pages link to it.

## [1.28.1] — 2026-10-12

### Security

- **An SD-JWT VC nested in a `jwt_vc_json` or `ldp_vc` presentation no longer
  reports `key_bound=True` for a Key Binding JWT made for another verifier**
  ([#189](https://github.com/luisgf/openvc/issues/189)). Found by the
  adversarial review of [#187](https://github.com/luisgf/openvc/pull/187).
  `verify_vp_token` and `VpJwtProofSuite.verify` verify every credential embedded
  in a W3C presentation, but built the nested policy with no audience or nonce.
  A nested KB-JWT therefore had its signature and `sd_hash` checked but its `aud`
  / `nonce` skipped. That is RFC 9901 §7.3 step 5.6, the step that makes a KB-JWT
  a binding at all. An SD-JWT + KB-JWT minted for verifier B, wrapped in a VP
  correctly bound to verifier A, verified at A with `key_bound=True`.

  A nested KB-JWT is now held to the presentation's own binding: the VP-JWT
  `aud` / `nonce`, the Data Integrity `domain` / `challenge`, or the DC API
  `origin:` openvc matched the presentation to. It is also held to the `iat`
  window from 1.28.0. A KB-JWT bound anywhere else rejects the whole response
  (`ClaimsInvalid`). This covers bare SD-JWTs and those inside an
  `EnvelopedVerifiableCredential`, at every depth the pipeline unwraps. A nested
  SD-JWT with no KB-JWT still verifies, with `key_bound=False`; the
  presentation's proof authenticates the presenter but never the credential's
  `cnf` key.

  Rejecting, rather than reporting `key_bound=False`, is deliberate. A KB-JWT is
  minted per presentation, so one bound elsewhere is a replayed holder proof.
  RFC 9901 §7.3 makes a presentation whose KB-JWT fails a step invalid, and
  OpenID4VP 1.0 §14.1.2 rejects the whole response for a presentation without
  the right nonce. No spec defines a nested KB-JWT's values (OpenID4VP §13.2 does
  not support nesting at all), so openvc uses the ones §B.3.6 gives every KB-JWT:
  the Client Identifier, or `origin:` over the DC API, and the request nonce. The
  binding applies to the KB-JWT only; a nested VC-JWT's own `aud` is still not
  pinned. This was a wrong flag, not a bypass: the presentation's own binding was
  always enforced. The semantics are written up in the wiki under
  *Presentations → SD-JWT VCs nested in a W3C presentation*.

  Fixed before merge, from this change's own adversarial review:
  - **A JWS typed as an SD-JWT or a KB-JWT is no longer accepted as a VC-JWT.**
    RFC 8725 §3.11 calls this explicit typing. An SD-JWT VC's issuer JWT with its
    `~` tail dropped verified as a VC-JWT whenever its payload carried a `vc`
    object. It reported `key_bound=None`, which got around a nested
    `require_key_binding=True` that this change had just made satisfiable.
    `VcJwtProofSuite.verify` now refuses a `typ` of `sd-jwt`, `*+sd-jwt` or
    `kb+jwt` (an `application/` prefix is optional) as `MalformedToken`, before
    any crypto runs.
  - The internal presentation binding is validated as two non-empty strings; a
    `(None, None)` would have switched the check off silently.

### Changed

- **A nested KB-JWT is bound to the presentation's own `audience` / `nonce`,
  not to any in the `policy` passed to `VpJwtProofSuite.verify`.** A caller who
  pointed nested KB-JWTs at other values through that `policy` is now rejected
  (#189). The `policy`'s `audience` still applies to a nested VC-JWT.

### Fixed

- **`VpJwtProofSuite.verify` can now require key binding on nested SD-JWT
  VCs.** A cascade `policy` with `require_key_binding=True` used to fail every
  time, because the nested verification had no `aud` / `nonce` to bind against.
  It now uses the presentation's.

## [1.28.0] — 2026-10-12

### Security

- **The SD-JWT Key Binding JWT's `iat` is now required and bounded**
  ([#186](https://github.com/luisgf/openvc/issues/186)). RFC 9901 §4.3 makes
  it REQUIRED and §7.3 step 5.5 has the verifier check it is "within an
  acceptable window"; openvc never read it, so a KB-JWT of any age — or with no
  `iat` at all — verified. Every self-made test minted a fresh KB-JWT and
  checked it at once. It was found by the third-party OpenID4VP capture that
  [@EgorKhaklin](https://github.com/EgorKhaklin) (polaris-id) contributed on
  [#121](https://github.com/luisgf/openvc/issues/121), through its "an hour
  later" control — thank you. Any KB-JWT that is present is now refused when
  its `iat` is missing, non-numeric or non-finite, older than `kb_max_age_s` plus
  the leeway, or future-dated beyond the leeway. Defence in depth, not a
  bypass: the enforced `nonce` + `aud` binding already stopped cross-transaction
  replay, but this window is the only freshness bound a stateless verifier can
  enforce, since only the caller knows how old its nonce is. A stale KB-JWT is a
  *binding* failure, never an `expired` verdict, so `require_not_expired=False`
  does not waive it.
- **A 400-digit `exp` / `nbf` / `iat` no longer escapes as a bare
  `OverflowError`.** `json.loads` turns such a literal into a Python `int`, and
  `math.isfinite` raised on it instead of answering — in the shared JOSE temporal
  check (SD-JWT VC, KB-JWT, VP-JWT, the ML-DSA VC-JWT lane) and in OpenID4VCI's
  key-proof and key-attestation timestamps. Anyone who can sign their own token
  (a `did:key` is enough) could abort a `verify_many` batch with it. Such a
  bignum is now read as not finite, the reading `openvc.rp_registration`
  already made, and fails closed as `ClaimsInvalid`.

- **Fixed before merge, from the adversarial review of PR #187** — none of them
  let a crafted `iat` through; they were in how the clock and the knobs are
  wired:
  - A **naive `now` was read as host-local time** in the new window, while
    `x5c`, `mdoc` and the Data Integrity validity window read it as UTC — one
    call evaluated two instants, and the KB window shifted by the host's UTC
    offset, accepting a stale KB-JWT and refusing a fresh one. The OpenID4VCI
    key proof carried the same reading since it shipped. Both now go through one
    `utc_epoch`, which also treats a `tzinfo` answering `utcoffset() = None` as
    naive and turns a non-`datetime` or a raising `tzinfo` into a typed error.
  - **`kb_max_age_s` did not reach SD-JWT VCs nested in `jwt_vc_json` or
    `ldp_vc` presentations**, nor the JsonSchemaCredential inner verifier (sync
    and async): they silently used the 300 s default.
  - **`leeway_s` was unvalidated** while added to both edges of the window: a
    `NaN` or infinite leeway switched it off, and `None` or a string raised a
    bare `TypeError`. `SdJwtVcProofSuite` and `verify_vp_token` now require a
    non-negative `int`, as they do for `kb_max_age_s`.

### Added

- **`kb_max_age_s`** — the KB-JWT freshness window, default
  `openvc.proof.sd_jwt.DEFAULT_KB_MAX_AGE_S` (300 s, the same budget as an
  OpenID4VCI key proof) — on `SdJwtVcProofSuite.verify`, `VerificationPolicy`
  (a new defaulted field, add-only), `verify_vp_token` and
  `verify_encrypted_vp_response`.
- **`now` on `SdJwtVcProofSuite.verify`**, and `VerificationPolicy.now` /
  `verify_vp_token(now=…)` now also pin the instant the KB-JWT window is
  evaluated at; a naive datetime is UTC. Re-verifying an archived presentation
  means pinning `now` to the receipt time you recorded — never to a value read
  from the presentation, whose own `iat` would switch the window off. The issuer
  JWT's `exp`/`nbf` still use the current time, as on every JOSE suite.

### Changed

- The freshness rule is single-sourced in `proof/_verify_common.py`
  (`check_iat_freshness`, `is_numeric_date`, `utc_epoch`,
  `non_negative_seconds`) and shared by the KB-JWT and the OpenID4VCI key proof;
  the key-proof error messages are unchanged. A naive `now` passed to
  `verify_credential_request` is now read as UTC, as everywhere else in openvc.

### Fixed

- **The async pipeline now sets `VerificationResult.expired`.** Since 1.27.0,
  `VerificationPolicy(require_not_expired=False)` waives the expiry failure and
  reports it on the result as `expired=True` — but only `verify_credential` did.
  The `openvc.aio` lanes (VC-JWT, SD-JWT VC, Data Integrity, and enveloped
  credentials through them) built their result without the flag, so
  `verify_credential_async` and `verify_many_async` returned `expired=False` for
  the same expired credential: an async caller that waived expiry in order to
  inspect it was told the credential was current. The async lanes now compute
  the flag with the sync helper, and both pipelines return equal results. The
  `VerificationResult` fields are unchanged. Found by the adversarial review of
  [#187](https://github.com/luisgf/openvc/pull/187).
- **Waiving expiry no longer rejects a credential the default policy
  accepts.** Computing the flag re-read dates the suite had not enforced:
  VCDM-named claims on an SD-JWT VC (`validFrom`, `expirationDate`, …, which
  the SD-JWT suite never reads) and a VC-JWT body at a pinned `policy.now`
  (the suite reads it at the current time). A future or malformed value there
  made the sync pipeline raise `CredentialNotYetValid` / `MalformedTimestamp`
  under `require_not_expired=False` only — contrary to the waiver's contract of
  stopping just the expiry failure. The flag now only observes, on both
  pipelines. Found by this fix's own adversarial review.

### Tests

- New `tests/test_sd_jwt_kb_freshness.py` crafts KB-JWTs with every hostile
  `iat` (missing, string, boolean, `NaN`, `±Infinity`, `±10**400`, stale,
  future-dated) and pins both edges of the window, the `now` pin, the expiry
  waiver, and that the window reaches the suite, `verify_credential`, the async
  pipeline and `verify_vp_token`.
- The two recorded OpenID4VP drift-alarm fixtures (#20) are now verified with
  `now` pinned to their 2026-07-07 recording instant. Unpinned, their KB-JWTs
  are — correctly — three months stale; they had only been passing because the
  claim was never read. The nonce-mismatch test now asserts *why* it fails, so it
  cannot pass on staleness instead.
- New `tests/test_expired_flag_parity.py` — the first tests of the flag. One
  expired credential per format (VC-JWT with a past `exp`, VC-JWT with only a
  past `validUntil`, SD-JWT VC, Data Integrity `eddsa-jcs-2022` and
  `eddsa-rdfc-2022`, an enveloped VC-JWT) goes through both pipelines under
  the waiver; both must report `expired is True` and return equal results.
  Controls: a current credential is not flagged, the same credentials still
  fail without the waiver, and a pinned `policy.now` decides the Data
  Integrity verdict on both pipelines. The edge cases above must verify under
  the waiver on both pipelines, as they do under the default policy.

## [1.27.1] — 2026-10-04

### Fixed

- **The JSON-LD document loader no longer tags caller-injected contexts
  `static`** (follow-up to
  [#183](https://github.com/luisgf/openvc/issues/183)). pyld promotes a
  document tagged `static` into a **process-global** resolved-context cache
  keyed by context URL (`pyld.jsonld._resolved_context_cache`, via
  `ContextResolver`). v1.27.0 tagged everything the loader served, so when two
  verifications in one process passed **different** documents under the **same**
  URL through `extra_contexts`, the second silently canonicalized with the
  first one's term definitions: a valid Data Integrity proof then fails to
  verify, and one caller's context influences another caller's processing.
  Only the bundled files are tagged now — they ship read-only, so every loader
  in the process serves identical bytes for a given URL — and the gate is
  **provenance, not URL membership**: a caller that shadows a bundled URL with
  its own document is not tagged either. Results for any single set of contexts
  are unchanged; injected contexts lose a caching shortcut they could never
  safely have had.

### Tests

- **The two features v1.27.0 shipped unpinned now have coverage.** The
  `jwt_vc_issuer_fetch` / `x5c_trust_anchors` passthrough on `verify_vp_token`
  ([#181](https://github.com/luisgf/openvc/issues/181)) is pinned on both the
  SD-JWT VC path and the VC-JWT cascade, with the negatives that carry the
  security weight: a DID issuer must never reach the https well-known hook, and
  an unrelated x5c anchor must be rejected. New `tests/test_contexts.py` covers
  the loader's tagging rules and fails closed on an unlisted URL; its last test
  reproduces the cross-caller context bleed end to end through pyld.

## [1.27.0] — 2026-09-12

### Added

- **`jwt_vc_issuer_fetch`, status resolvers and `x5c_trust_anchors` on
  `verify_vp_token` / `verify_encrypted_vp_response`**
  ([#181](https://github.com/luisgf/openvc/issues/181)). The SD-JWT path
  forwards them to `verify_credential`. `require_status` defaults to
  `False` (unchanged presentation-layer behaviour); pass `True` plus a
  resolver to fail-close on credential status.
- **`VerificationPolicy.require_not_expired` / `require_not_revoked`**
  (default `True`). Independent of authenticity: signature, issuer,
  holder-binding and status-list verification still run. Setting either
  to `False` only waives the matching *disposition*. `VerificationResult.expired`
  is add-only (default `False`).
- **`expected_issuer=` on the blessed status-list resolvers.** When both
  the fetched list's `iss`/`issuer` and the expected value are readable
  strings and differ, the resolver raises `StatusListError` *before*
  resolving the list issuer's key.
- The bundled JSON-LD `document_loader` now tags contexts `static` so
  pyld does not re-resolve term definitions on every canonicalization
  ([#183](https://github.com/luisgf/openvc/issues/183)).

### Security

- **SD-JWT VC key binding is verified even when the issuer JWT is expired**
  ([#182](https://github.com/luisgf/openvc/issues/182)). With
  `require_key_binding=True`, `SdJwtVcProofSuite.verify` (and
  `verify_credential`) checks the KB-JWT — signature, `aud`, `nonce`,
  `sd_hash` — **before** `exp`/`nbf`. A temporal failure then means the
  presentation was bound; a key-binding failure (wrong nonce, forged
  holder key, missing KB) is no longer hidden behind `ClaimsInvalid:
  expired`. The hosted path (`require_key_binding=False`) is unchanged.
  Non-ASCII junk in the compact presentation on that path is a typed
  `SdJwtError` (it used to be `UnicodeEncodeError` and would abort
  `verify_many`).

## [1.26.0] — 2026-08-14

### Added

- **`require_key_attestation=` on `verify_credential_request_proofs`**
  ([#178](https://github.com/luisgf/openvc/issues/178)). An issuer that
  publishes `key_attestations_required` can now refuse a proof whose header
  has no `key_attestation` with the structure rules — before the signature
  and before `check_nonce` runs. Without the flag the same proof verified,
  the nonce was spent, and the caller only then saw
  `VerifiedProof.key_attestation is None`: the wallet's §8.3.1 retry became
  a loop. Default `False`, so an issuer that does not advertise the
  requirement is unchanged. The policy is the caller's; the ordering is
  only available here.
- **`aka_vcts` shape check** (draft-ietf-oauth-sd-jwt-vc-18 §2.2.2.2,
  [#179](https://github.com/luisgf/openvc/issues/179)). When present, the
  claim must be a non-empty array of non-empty strings that does not
  contain the credential's `vct`. Absent stays accepted.
  `expected_vct` is **not** widened to match an alias — that pin stays
  exact; callers that want type-alias matching read `claims["aka_vcts"]`.

### Changed

- **SD-JWT VC pin is draft-18** (2026-08-03; IESG *Revised I-D Needed*).
  Type Metadata §4 is unchanged; the worked example is now Appendix A.2
  (was B.2 in -17). Historical CHANGELOG entries keep their draft-17
  wording. Not the RFC cite-swap (#127 still waits on a number).

### Tests

- **A key proof captured from `eudi-lib-jvm-openid4vci-kt` 0.12.2**
  ([#147](https://github.com/luisgf/openvc/issues/147)). The library the
  EUDI Android wallet speaks through, driven by the downstream issuer's
  wallet-harness, captured 2026-07-29. Header is
  `{alg, typ, kid: "0", key_attestation}` with no `jwk` — the form #150
  and #178 exist to handle. Verifies end to end with the clock frozen to
  its own `iat`. Provenance is sha256-enforced in the fixtures README.

## [1.25.0] — 2026-08-13

### Added

- **OpenID4VCI discovery parsers: untrusted Credential Offers and Issuer
  Metadata** ([#142](https://github.com/luisgf/openvc/issues/142)).
  `openvc.openid4vci.parse_credential_offer` (OID4VCI 1.0 §4.1.1) and
  `parse_credential_issuer_metadata` (§11.2.3) parse the third-party JSON a
  wallet — or an issuer checking its own deployment — receives, into the
  frozen dataclasses `CredentialOffer` and `CredentialIssuerMetadata`.
  Fail-closed per ADR-0007 D7 (parsers in, builders out): `credential_issuer`
  must be an absolute https URL (it feeds the key proof's `aud` comparison),
  `credential_configuration_ids` a non-empty array of distinct non-empty
  strings, every endpoint URL https and absolute when present, and
  `batch_credential_issuance.batch_size` an integer ≥ 2. Unknown `grants`
  members and every extension point are preserved verbatim (typed fields and
  `raw`), never silently dropped; nothing is ever fetched — a by-reference
  `credential_offer_uri` stays the caller's injected `Fetch`. New typed
  errors `CredentialOfferMalformed` and `IssuerMetadataMalformed`, plus the
  wire constants `GRANT_AUTHORIZATION_CODE` and `GRANT_PRE_AUTHORIZED_CODE`.
  pinned against the spec's own §4.1.1/§4.1.2/§11.2.3 examples and the
  recorded EU-reference-issuer artifacts from #147. URL validation is the
  adversarial-review-hardened one: control characters (which `urlparse`
  silently strips), userinfo, query/fragment and unparseable bracketed
  literals or ports are all rejected with the typed errors, so the stored
  `credential_issuer` is byte-for-byte the identifier the key proof's `aud`
  will be compared against and no raw `ValueError` escapes the module's
  taxonomy over attacker-controlled input.

### Fixed

- **A WRPRC that lists no claim paths no longer authorizes a DCQL query that
  names no claims** ([#152](https://github.com/luisgf/openvc/issues/152)).
  `check_request_within_registration` treated that pairing as an "equally
  unrestricted" grant and returned success, so an incomplete registration
  (omitted `claim`/`claims`) became a blanket entitlement for the matching
  `format`+`meta`. An empty grant already refused a *specific* path; it now
  refuses the unrestricted ask too. There is no encoding for "this RP may
  request every attribute" — list the paths.
- **A present-but-empty WRPRC `claim` no longer falls through to `claims`**
  ([#160](https://github.com/luisgf/openvc/issues/160)). Grant-side
  precedence used `_paths_under(claim) or _paths_under(claims)`, so
  `claim: []` / `[{}]` extracted as empty and the second spelling widened
  the grant — the #89 hole on the empty-first half. Presence of the spec
  key wins, even when the list is empty.
- **`openvc.fetch` blocks RFC 6598 CGNAT (`100.64.0.0/10`)**
  ([#156](https://github.com/luisgf/openvc/issues/156)). The SSRF guard
  enumerated `is_private` / loopback / link-local / reserved / multicast /
  unspecified; Python does not set `is_private` on shared address space, so
  a `did:web` / status / schema host resolving to `100.64.0.1` (or
  `::ffff:100.64.0.1`) was fetched. The guard now also rejects
  `not ip.is_global`.
- **A WRPRC or DCQL query with no string `format` no longer matches
  `None == None`** ([#161](https://github.com/luisgf/openvc/issues/161)).
  Missing, blank or non-string formats on both sides used to become a
  second grant bucket next to well-formed entries. An absent format is a
  failure, never a match.

### Fixed (docs)

- **`SECURITY.md` no longer describes a pre-1.0 `0.x` library or a two-alg
  allow-list** ([#158](https://github.com/luisgf/openvc/issues/158)).
  Supported versions are the latest 1.x; the JOSE allow-list is
  `{ES256, ES384, EdDSA, Ed25519}`.
- **README no longer claims every issuer-named URL is SSRF-guarded**
  ([#153](https://github.com/luisgf/openvc/issues/153)). Status/schema
  fetches are guarded only through the blessed `openvc.resolvers` defaults;
  a custom resolver opts out.
- **`docs.yml` no longer grants `id-token: write` to PR builds**
  ([#157](https://github.com/luisgf/openvc/issues/157)). Pages OIDC and
  `pages: write` are scoped to the deploy job, which never runs on a
  pull request.
- **Install tables name `[pq]` and count thirteen examples**
  ([#154](https://github.com/luisgf/openvc/issues/154)). README and
  Getting-Started omitted the extra; `[all]` now matches `pyproject.toml`;
  wiki Home lists the three pages that were already in the sidebar.
- **Threat-model I2/I15 citations re-anchored**
  ([#155](https://github.com/luisgf/openvc/issues/155)). Raw R‖S lives at
  `keys.py:575-589` (not `:493`); `verify_many` isolation tests are
  `test_hostile_input.py:104/155/211`. The pack README catalog span is
  I1–I19.
- **A COSE `crit` label that is not an integer is `CoseMalformed`, not
  `TypeError`** ([#170](https://github.com/luisgf/openvc/issues/170)).
  An array or map as a `crit` entry is legal CBOR and unhashable; the
  `in frozenset` test raised a bare `TypeError` before any crypto, which
  `mdoc` does not re-wrap.
- **TIR `attributes` and `href` hops are pinned to the listing origin**
  ([#172](https://github.com/luisgf/openvc/issues/172)). `links.next` already
  refused a port change on an allow-listed EBSI host; the HATEOAS
  `attributes` URL and each revision `href` did not. The HTTP client
  allow-list is hostname-only.
- **SD-JWT verification applies `exp`/`nbf` to the processed payload**
  (RFC 9901 §7.1 step 6). A selectively disclosed validity claim is now
  enforced when the holder presents it, not only when it stays in the
  issuer-JWT body.
- **A non-string JOSE `kid` is a typed error, not `AttributeError`**
  ([#175](https://github.com/luisgf/openvc/issues/175)). `peek_issuer`
  and `DidDocument.key_by_kid` now reject it, so `verify_many` isolates
  the item instead of aborting the batch.

## [1.24.0] — 2026-07-29

### Added

- **Key resolution sees the whole proof, and key attestations are parsed**
  ([#150](https://github.com/luisgf/openvc/issues/150),
  [ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md)
  1.24.0 addendum). In the attested-key form EU wallet stacks emit —
  `{typ, alg, kid, key_attestation}` — the key that signed the proof is *inside the
  header*, one of the attestation's `attested_keys`. `ResolveProofKey` sees only the
  `kid`, so a consumer had to base64url-decode the proof header itself before calling
  in: openvc decoding a header once and the caller decoding it again, with two notions
  of what a header is and one of them free to drift.
  `verify_credential_request_proofs` gains **`resolve_proof_key_in_context=`**, taking
  the new frozen `ProofKeyContext` (`kid`, `alg`, a read-only `header`, the parsed
  `key_attestation`, `credential_issuer`, `index`), so the resolver is one line of the
  caller's own mapping rule. Pass it *or* `resolve_proof_key`, never both — a
  precedence between two key resolvers is the same silent-preference defect the
  one-key-parameter rule exists to prevent.
  **`ResolveProofKey` is unchanged and not deprecated**: existing resolvers keep
  working untouched, and a context object grows without ever breaking them again.
  Also public: **`peek_key_attestation`** → the frozen `UnverifiedKeyAttestation`
  (`attested_keys`, `key_storage`, `user_authentication`, `certification`, `nonce`,
  `status`, `issued_at`, `expires_at`, `header`, `claims`), **`peek_proof_header`**,
  `KEY_ATTESTATION_TYP` and `MAX_KEY_ATTESTATION_BYTES`. Structure is validated, trust
  is not — the signature, the wallet-provider anchor and the assurance levels stay
  downstream (ADR-0007 D9), and *which* key in `attested_keys` a `kid` names stays the
  caller's, because the spec fixes no rule for it (its own example uses an index,
  wallets also use the JWK's `kid` member or a thumbprint). New runnable example
  `examples/13_oid4vci_key_attestation.py`, and the App. D vector in
  `tests/fixtures/openid4vci/spec/`.

### Changed

- **A key proof carrying a `key_attestation` must be signed by one of its
  `attested_keys`** (OID4VCI 1.0 App. D's MUST: *"the Credential Issuer MUST validate
  that the JWT used as a proof is signed by a key contained in the attestation in the
  JOSE Header"*), compared by RFC 7638 thumbprint, on every key source. Previously the
  header was captured verbatim and never looked at. Also, a malformed attestation now
  rejects the proof *before* any crypto, with the rest of the structure rules, rather
  than being read at the end.
  **This buys nothing against an attacker** and must not be read as if it did: nothing
  here verifies the attestation's signature, so whoever forges a proof simply attests
  their own key. It catches an honest wallet — or *your own* `resolve_proof_key` —
  handing over a key the wallet never claimed, which would otherwise mint a credential
  bound to the wrong key and verify cleanly. It can only reject, never accept.
  Who this breaks, all of them previously accepted: a proof whose `key_attestation` is
  not a parseable JWS, or whose `attested_keys` is missing/empty/not an array of JWK
  objects (now `MalformedToken` / `ClaimsInvalid`); an `x5c` or `kid` deployment whose
  attestation does not list the key the chain or the registry produced — including the
  RFC 7638 hazard where a JWK with **non-fixed-width coordinates** (non-conformant per
  RFC 7518 §6.2.1.2) thumbprints differently from the same key encoded correctly, which
  the rejection message names. No key proof that used to be rejected is now accepted.

## [1.23.1] — 2026-07-27

### Fixed

- **A `di_vp` Credential Request is refused as `UnsupportedProofType`, not
  `CredentialRequestMalformed`** ([#147](https://github.com/luisgf/openvc/issues/147)).
  OID4VCI 1.0 §8.2 lets each proof type define its own element type — `jwt` is a
  string, `di_vp` is a JSON object (App. F.2) — so the "entries must be non-empty
  strings" shape check fired before the proof type was ever consulted, and a
  perfectly valid `di_vp` request came back labelled malformed. That contradicted
  the module's own documented contract, and told a Credential Endpoint the wallet
  had sent garbage when it had sent a proof of a type openvc declines. Both paths
  fail closed and no request that used to be rejected is now accepted; what changes
  is the signal an endpoint maps to `invalid_proof`. Found by the spec's own §8.2
  example the moment it was added as a fixture — which is the argument for the
  fixtures.

### Added

- **OpenID4VCI vectors from outside this repo**
  ([#147](https://github.com/luisgf/openvc/issues/147),
  [ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md)
  D10). `tests/fixtures/openid4vci/` holds the spec's own App. F.1 key proof — a
  genuinely signed ES256 token that now verifies end-to-end under a clock frozen to
  its own `iat`, so the `typ` pin, the key↔`alg` binding, the signing-input assembly
  and the `aud`/`iat`/nonce checks are all pinned by a third party rather than by
  openvc's own minting — plus the three §8.2 Credential Request examples, and
  Issuer Metadata and two Credential Offers recorded live from the EU reference
  issuer (`eudi-srv-web-issuing-eudiw-py`), the offers in the deep-link form a
  wallet receives. Provenance is enforced: a test re-checks every recorded artifact
  against the `sha256` its README documents. Still self-made, and stated as such in
  that README: no key proof here came from a shipping wallet — that capture needs a
  live Credential Endpoint openvc does not ship.

## [1.23.0] — 2026-07-24

### Added

- **OpenID4VCI 1.0 wallet key-proof verification**
  ([#141](https://github.com/luisgf/openvc/issues/141)). A new
  `openvc.openid4vci` verifies the `openid4vci-proof+jwt` a wallet sends to a
  Credential Endpoint (OID4VCI 1.0 App. F.1) and returns the public key it
  demonstrated possession of — the value
  `SdJwtVcProofSuite.issue(holder_jwk=…)` binds the credential to.
  `parse_credential_request` pins the §8.2 wire contract;
  `verify_credential_request_proofs` runs the checks in a fixed order, structure and
  allow-lists **before** any crypto: the `typ` pin (so a KB-JWT, VP-JWT or
  status-list token cannot be replayed as a key proof), the algorithm allow-list,
  unknown `crit`, **exactly one** of the `jwk`/`kid`/`x5c`/`trust_chain` header key
  parameters, the key↔`alg` (kty, crv) binding, the signature, `aud` pinned to the
  Credential Issuer Identifier with a multi-valued `aud` rejected, and **`iat`
  freshness in both directions** — stale *and* future-dated, which is new logic
  because `check_jwt_temporal` reads `exp`/`nbf` and never `iat`. Across a batch:
  one shared nonce, no two proofs on the same key.

  **Nonce state is the caller's, injected as a required callable** (`ConsumeNonce`)
  rather than documented in prose — a plain `expected_nonce` string cannot express
  "consume once, atomically", and would make the fail-open path the ergonomic one.
  It is invoked exactly once per request and only *after* every signature has
  verified, so an unauthenticated attacker cannot burn nonces. Replay surfaces as a
  distinct `ProofReplayed` so an endpoint can answer `invalid_nonce` (fresh nonce,
  retry) rather than rejecting the wallet.

  Stateless and transport-free by design
  ([ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md)):
  no endpoint, no Authorization Server, no state store, and no response/offer/metadata
  builders — those belong to the issuing application. Key attestations are captured
  **unverified**; `di_vp` and OpenID Federation `trust_chain` proof keys raise a typed
  `UnsupportedProofType`. What this supports claiming is *OpenID4VCI 1.0 key-proof
  verification* — not "issuance", and not HAIP, which additionally requires DPoP, key
  attestations and client authentication. No new runtime dependency.

  The public surface is `verify_credential_request_proofs`,
  `parse_credential_request`, `CredentialRequest`, `VerifiedProof`, `ConsumeNonce`,
  `ResolveProofKey`, `OpenID4VCIError`, `CredentialRequestMalformed`,
  `UnsupportedProofType`, `ProofReplayed`, `PROOF_TYPE_JWT`, `PROOF_TYP`,
  `DEFAULT_PROOF_MAX_AGE_S` and `MAX_PROOF_BYTES`.

  Two obligations come with it, both load-bearing and both the integrator's
  ([ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md)).
  **`check_nonce` must be atomic** — a Redis `SET … NX` or a SQL
  `DELETE … RETURNING`, never a read-then-write, under which two concurrent requests
  both observe the nonce as unused and the replay window core cannot close on your
  behalf re-opens. `openvc.cache.TtlCache` is explicitly **not** suitable: it
  documents its own lack of single-flight, benign for a read cache and fatal for a
  single-use token. And **codes and identifiers are yours to mint** — core generates
  no pre-authorized code, `transaction_id` or `notification_id`; they are opaque
  values with no bytes for openvc to get right.

- **RFC 7638 JWK Thumbprint** ([#140](https://github.com/luisgf/openvc/issues/140)).
  `openvc.keys` grows `jwk_thumbprint` (base64url) and `jwk_thumbprint_bytes` (the
  raw digest), covering `EC`, `OKP`, `RSA` and `oct` keys. The canonical form is
  built from an explicit allow-list of the members RFC 7638 §3.2 (and RFC 8037 §2
  for `OKP`) declares required, so `kid`/`use`/`alg` — and every private member —
  are excluded *by construction* rather than filtered out: a private key and its
  public half produce the same thumbprint, and a member we have never heard of can
  never leak into a digest. Fails closed on an unknown `kty`, a missing required
  member, or a non-string member value. Pinned by the two published golden vectors
  (RFC 7638 §3.1 RSA, RFC 8037 §2 Ed25519), whose examples carry `alg`/`kid` and so
  double as the exclusion test. This is the identifier used as a `kid`, in `cnf`,
  and as a DPoP `jkt`; `jwk_thumbprint_bytes` is also what
  `openid4vp.dcapi_session_transcript` wants for an ISO 18013-7 handover, which
  callers previously had to compute themselves. Prerequisite for the OpenID4VCI
  key-proof verifier ([ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md)).

## [1.22.0] — 2026-07-22

### Added

- **ETSI TS 119 602 Lists of Trusted Entities (LoTE) — the JSON trusted-list
  lane** ([#135](https://github.com/luisgf/openvc/issues/135)). TS 119 602 is
  the successor data model to the TS 119 612 XML Trusted Lists, and its EU
  profiles are the EUDI wallet anchor lists: **Annex F** (WRPAC providers —
  who may issue relying-party *access* certificates) and **Annex G** (WRPRC
  providers — the registrar anchors `verify_rp_registration_certificate`
  consumes). One interface, two encodings: `openvc.trustlist` grows
  `parse_lote` / `consume_lote` / `walk_lote` plus the
  `EU_WRPAC_PROVIDERS_PROFILE` / `EU_WRPRC_PROVIDERS_PROFILE` conformance
  gates (`LoteProfile`, `LoteType`, `LoteServiceType`,
  `TrustListProfileError`), all distilling into the same `TrustAnchorSet`
  as `walk_lotl` — `.certificates` feeds the existing X.509 path unchanged.

  A JSON LoTE travels as a **compact JAdES baseline-B** JWS (clause 6.8 /
  Annex G.4), so verification runs on the library's own JOSE primitives — the
  `{ES256, ES384, EdDSA, Ed25519}` allow-list before any crypto, the WRPRC
  lane's allow-listed `crit`, the signer from `x5c` authenticated against
  **caller-pinned** certificates (byte-for-byte or by path validation), plus
  clause 6.8's DN binding (signing-certificate `organizationName` ↔
  `SchemeOperatorName`, `countryName` ↔ `SchemeTerritory`). Parsing is strict
  and fail-closed on every field that feeds a trust decision: unknown
  structural members reject (the official schema is
  `additionalProperties: false` throughout), date-times must be the UTC `Z`
  form, an unrecognised critical extension rejects the list, a malformed
  certificate blob is skipped rather than trusted, and a **closed** list
  (`NextUpdate` null) contributes zero anchors. The EU profiles enforce
  Tables F.1–G.3 — registered URIs (including the spec's literal
  `WRPRCrovidersList` StatusDetn typo, accepted alongside the corrected
  spelling), territory `EU`, the exclusive service-type pairs,
  `ServiceStatus`/`StatusStartingTime`/`HistoricalInformationPeriod` absent,
  and the ≤ 6-month update window. Self-made signed vectors pin the behaviour;
  the Commission's real EU lists become golden fixtures when published.

  The adversarial review hardened the lane before merge: a profiled
  `walk_lote` now defaults its selection to the profile's **issuance** service
  type (a provider's *revocation*-service certificates no longer anchor
  credential verification unless explicitly selected — the review proved a
  WRPRC signed under a revocation-service CA validated through the documented
  flow), only follows pointers whose `LoTEType` matches the profile (and
  consumes the pointed list under the same profile), fails closed instead of
  raising an uncaught `ValueError` on a far-future `ListIssueDateTime`,
  rejects a present-but-empty `ServiceStatus` under the profiles
  (presence is the violation), and pins date-times to the exact
  `YYYY-MM-DDThh:mm:ssZ` form clause 6.1.3 mandates.

## [1.21.0] — 2026-07-19

### Added

- **EUDI relying-party *registration* certificates (WRPRC, ETSI TS 119 475 V1.2.1
  clause 5.2)** — the other half of [#67](https://github.com/luisgf/openvc/issues/67)'s
  WRPAC. Where the access certificate authenticates *who is asking*, the registration
  certificate answers **"were they registered to ask for this?"**: it carries the
  relying party's entitlements and the credentials/attributes it may request. New
  module `openvc.rp_registration`, with the library's usual trusted/untrusted split —
  `parse_rp_registration_certificate` (UNTRUSTED, header-profile only) and
  `verify_rp_registration_certificate`, which anchors the signer's chain in
  caller-provided registrar roots. Both profiled forms are read: the **JWT**
  (`rc-wrp+jwt`) over the JOSE lane, the **CWT** (`rc-wrp+cwt`) over the
  dependency-free CBOR/COSE codec, sharing the `{ES256, ES384, EdDSA, Ed25519}`
  allow-list applied *before* any crypto and the `x5c` primitives now exported from
  `openvc.x5c` (`load_x5c_chain`, `load_der_chain`, `leaf_public_jwk`).

  Verification alone only proves a registrar signed *something*, so two cross-checks
  carry the authorization decision, both fail-closed:
  `check_matches_access_certificate` binds the WRPRC's `sub` to the WRPAC's
  `entity_identifier` (GEN-5.1.1-04 — without it an attacker pairs their own valid
  WRPAC with someone else's valid WRPRC and inherits that scope; an identifier absent
  on either side is a failure, never a match), and `check_request_within_registration`
  requires every DCQL credential query to match a registered `format` whose `meta`
  covers the requested one, with every requested claim `path` inside the registered
  paths. A registered container covers its members; a request naming no claims asks for
  everything and is refused against an enumerated registration.

  Only a *verify subset* of the JAdES baseline B-B profile GEN-5.2.1-04 mandates is
  implemented — the signed-header profile (`typ`, allow-listed `alg`, the `x5c` chain,
  a `crit` that fails closed on any parameter this verifier does not process) plus the
  chain validation. No signature-policy processing, timestamps, or augmentation.

  Three properties of the profile are easy to get wrong and are handled explicitly:
  one WRPRC carries **exactly one** intended use (clause 5.2.4 flattens TS5's nested
  `intendedUse[]`); **`exp` is optional** (Table 10), so the 12-month ceiling
  (GEN-5.2.4-08) binds only when it is present and `require_expiry=True` is opt-in; and
  the **CWT form has no claim-key mapping** in TS 119 475 — the envelope is fully
  specified (RFC 9052/9360) and implemented, while the claims map is read accepting both
  the RFC 8392 integer keys and text keys, which is the only reading available to an
  issuer today. That lane is provisional until a real artifact exists to pin. Two
  published spec defects are absorbed rather than inherited: `intermediary.sname`
  (Table 10) vs `intermediary.name` (Annex C), and `intermediary.sub` vs `act.sub`
  (GEN-5.2.4-09) — both spellings are read. The German BMI *Architekturkonzept*
  certificate (`rc-rp+jwt`) is a different profile and is refused by name rather than
  half-parsed under the wrong claim semantics.

  No official signed vectors exist (the deliverable ships one informative, unsigned
  Annex C example; the 2026 EAA Plugtests covered TS 119 472-1), so
  `tests/test_rp_registration.py` pins the **Annex C payload verbatim** and otherwise
  builds both forms over the library's own machinery — 106 tests, negative paths first.
  Recording a real third-party artifact stays a gated follow-up.

  An adversarial review of the verify and authorization paths found six issues, all
  fixed here with a regression test named for the attack. The one that mattered:
  the claim-path reader took `claim` before `claims` on **both** sides, which is
  correct for a registration (the spec's spelling) but on a *request* let a relying
  party hide a narrow decoy in `claim` and the real, broader ask in `claims` — openvc
  authorized the decoy while the wallet, following DCQL, answers `claims`, and unknown
  query members are ignored downstream so the escalating query stayed valid end to end.
  The request side now takes the **union** of both spellings; the registration side
  keeps precedence, since only there does a second spelling risk *widening* a grant.
  Also closed: a bare `OverflowError` escaping the `OpenvcError` family on a bignum
  `iat`/`exp`/`nbf` (`math.isfinite` casts to float, and `json.loads` yields such ints
  from the wire); an empty registered `{"path": []}` acting as a blanket grant over the
  whole credential (an empty tuple is a prefix of everything); a non-object `meta` being
  coerced to `{}`, which turned a malformed *constraint* into *no* constraint and
  widened the entry to every credential of that format; `meta` matching conflating
  `True` with `1`; and an entitlement floor that accepted any non-empty string while
  `ENTITLEMENT_URI_PREFIX` sat exported-but-unused — it now checks the clause-A.2
  namespace GEN-5.2.4-03 actually requires. The binding check, the algorithm allow-list,
  the chain handling and the CWT parser were probed and held.
  ([#89](https://github.com/luisgf/openvc/issues/89))

### Fixed

- **Documentation drift**: the WRPAC was attributed to ETSI TS 119 475 (it is
  **TS 119 411-8**; 475 is the WRPRC) in the wiki module map and the API reference,
  where it was also described as carrying "registered entitlements" — the WRPRC's job,
  not the WRPAC's.

## [1.20.4] — 2026-07-18

### Security

- **Unknown JWS `crit` extensions are now rejected on every JOSE verify lane**
  (RFC 7515 §4.1.11). openvc processes no JWS extension header parameters, so a
  token marking any as critical must fail closed — but the hand-rolled JWS lanes
  (the SD-JWT issuer JWT and KB-JWT, and the IETF status-list token) accepted
  them regardless of PyJWT version, and the VC-JWT lane inherited pre-2.13 PyJWT
  behaviour (CVE-2026-32597). All lanes — VC-JWT (the ML-DSA one included),
  SD-JWT, KB-JWT, status-list token — now reject through one shared check
  (`reject_unknown_crit`), matching the stance the COSE and JWE paths already
  took; regression tests per lane in `tests/test_jws_crit.py` — the ML-DSA lane,
  the public `verify_status_list_token` entry point and the error-precedence
  ordering included. An adversarial review (parser tricks incl. duplicate /
  unicode-escaped `crit` keys, lane completeness across every public entry
  point, precedence, hostile shapes, `verify_many` isolation, global state)
  found no bypass; its coverage recommendations are these tests.
  ([#125](https://github.com/luisgf/openvc/issues/125))
- **PyJWT floor raised to `>=2.13`** — 2.13.0 (2026-05-21) is a security release.
  The advisory-by-advisory reachability audit through openvc's usage is recorded
  in [`docs/audit/assurance.md` §5](https://github.com/luisgf/openvc/blob/main/docs/audit/assurance.md):
  the `PyJWK` / `PyJWKClient` / HMAC-confusion classes are structurally
  unreachable (allow-list before crypto, no `PyJWK(Client)`, SSRF-guarded JWKS
  fetch); the `crit` (CVE-2026-32597) and `b64=false` (CVE-2026-48525) classes
  were reachable pre-2.13 on the VC-JWT lane and are closed by the floor plus
  the openvc-side `crit` rejection above. `cryptography` 49.0.0 compatibility
  confirmed (full suite green; CI resolves the newest on every run).
  ([#125](https://github.com/luisgf/openvc/issues/125))

## [1.20.3] — 2026-07-18

### Changed

- **Documentation truth pass (2026-07 roadmap refresh).** `docs/ROADMAP.md` now
  points at the live milestones —
  [Q3–Q4 2026 — eIDAS deadline & ecosystem refresh](https://github.com/luisgf/openvc/milestone/12),
  [Conformance & production readiness](https://github.com/luisgf/openvc/milestone/11)
  and [Long term — PQ, BBS & 2.0](https://github.com/luisgf/openvc/milestone/8) —
  instead of the closed short/medium pair, and the long-term summary no longer
  lists shipped work (ML-DSA, DID 1.1 tolerance) as future. No code change.
  Follows the 2026-07-17 standards review that opened the Q3–Q4 milestone.
  ([#128](https://github.com/luisgf/openvc/issues/128))
- **pyld 3.x verified; the `[data-integrity]` floor stays `pyld>=2.0.4`, now tested
  at both edges.** PyLD came back to life (3.0.0 / 3.1.0, 2026-06-19, after two
  dormant years on 2.0.4) with JSON-LD 1.1 conformance fixes — exactly the class of
  change that could silently shift RDF canonicalization and break Data Integrity
  signatures, and fresh installs already resolve 3.x under the permissive floor. The
  full suite — the byte-for-byte `vc-di-eddsa` golden and the `ecdsa-sd`
  intermediates included — passes identically on 2.0.4 and 3.1.0 (1208 passed on
  each), so the floor is deliberately kept at `>=2.0.4` and CI now runs a
  `pyld==2.0.4` floor leg alongside the latest-resolving matrix. The bundled-context
  loader stays openvc's own rather than pyld 3's `FrozenDocumentLoader` /
  `BUNDLED_CONTEXTS`, so the exact context bytes feeding canonicalization ship
  vendored in this package (`openvc.proof.contexts`).
  ([#124](https://github.com/luisgf/openvc/issues/124))

## [1.20.2] — 2026-07-16

### Fixed

- **The XAdES trust-list verifier now accepts real EU trusted lists.** The
  1-reference pin shipped in v1.20.0 rejected every genuine XAdES-BASELINE
  signature — the EU LOTL and the national TLs carry **two** signed references
  (the enveloped document plus the signature's own qualifying
  `SignedProperties`), so `verify_xades_enveloped` failed closed against its
  primary real-world target (safe direction, but the `[trustlist]` feature was
  unusable in production; the round-trip test signed plain 1-reference XML-DSig
  and masked it). Reference coverage is now enforced **structurally** instead of
  by raw count: coverage is anchored on the **enveloped `URI=""` reference** — exactly
  one verified reference must be the whole-document (`URI=""`) reference resolving to
  the trust-list root, and the only extras accepted are the XAdES `SignedProperties`
  and a co-signed `ds:KeyInfo`. Anchoring on `URI=""` (not on the resolved element's
  tag) is what defeats XML-Signature-Wrapping: `URI=""` re-resolves to the current
  whole document, so a legitimately-signed subtree relocated under an attacker root of
  the same tag — a by-`Id` (`URI="#x"`) reference that a tag-equality check would have
  accepted — no longer matches. (An adversarial review of the initial fix caught that
  tag-equality gap; the regression is pinned by a by-`Id` wrapping test.)
  ([#114](https://github.com/luisgf/openvc/issues/114))
- **Bitstring Status List `encodedList` is now multibase-conformant (both sides).**
  The W3C VC Bitstring Status List v1.0 REC mandates the `encodedList` be a
  **multibase**-encoded base64url value (a leading `u`), but openvc's codec used bare
  base64url: `decode_bitstring` **could not consume** a spec-conformant list (or any
  real third-party one — e.g. Digital Bazaar's) because the `u` prefix broke base64url
  decoding, and `encode_bitstring` **issued non-conformant** lists that only
  interoperated with openvc itself (the verify round-trip passed precisely because both
  sides dropped the prefix — the same self-referential blind spot the third-party
  vectors below exist to catch). `decode_bitstring` now strips an optional leading `u`
  (a raw gzip stream base64url-encodes to `H4sI…`, never `u`, so legacy prefix-less
  lists still decode unambiguously) and `encode_bitstring` emits the conformant `u`.
  ([#115](https://github.com/luisgf/openvc/issues/115))

### Added

- **Real Commission-signed golden fixtures** (`tests/fixtures/trustlist/real/`):
  the EU LOTL (sequence 388) and the Spanish national TL (sequence 187), recorded
  2026-07-16 with their pinned signer certificates and verified end to end
  through `verify_xades_enveloped` / `consume_trust_list` — the XAdES conformance
  claim no longer rests on a self-referential round-trip. Tamper and
  wrong-signer negatives included; provenance (URLs, sequence numbers, hashes)
  in the fixture README. ([#114](https://github.com/luisgf/openvc/issues/114))
- **Third-party interop vectors** (`tests/fixtures/interop/`) — conformance pinned
  against artifacts produced by *others* instead of self-recorded round-trips: an
  SD-JWT VC from **RFC 9901** Appendix A.3 (verified against the published A.5 issuer
  key) and a real **EUDI reference-implementation PID** (ES256, issuer cert in `x5c`),
  both verified end to end through `SdJwtVcProofSuite`; and W3C **Bitstring Status
  List** `encodedList` decode vectors — the v1.0 REC's own Example 3 and a Digital
  Bazaar 100k list (which doubles as an MSB-first bit-order regression). Provenance
  (sources, retrieval date) in the fixture README.
  ([#115](https://github.com/luisgf/openvc/issues/115))

## [1.20.1] — 2026-07-13

### Added

- **External-audit pack** (`docs/audit/`) — audit-readiness groundwork for the
  funded external review: a code-cited
  [threat-model annex](https://github.com/luisgf/openvc/blob/main/docs/audit/threat-model.md)
  (per-suite and per-parser attack-surface tables, the fail-closed invariants
  catalog I1–I15, and a residual-risk register R1–R8), an
  [assurance report](https://github.com/luisgf/openvc/blob/main/docs/audit/assurance.md)
  (property-based fuzz coverage, the harden-next gap map, and the
  adversarial-review history), and a
  [reviewer index](https://github.com/luisgf/openvc/blob/main/docs/audit/README.md)
  with the suggested review scope and EU funding routes. No code change — the
  external audit itself stays gated on funding.
  ([#75](https://github.com/luisgf/openvc/issues/75))

### Security

- **Fail closed on hostile deeply-nested JSON across the verify pipeline.** A
  deeply-nested (but valid) JSON credential — an SD-JWT header/payload/disclosure, a
  **chain** of SD-JWT disclosures each carrying the next `_sd` digest, a VC-JWT
  header/payload, or an enveloped VC's `data:` payload — made `json.loads` (or the
  SD-JWT `_unpack` recursion) raise `RecursionError` (a `RuntimeError`, not an
  `OpenvcError`). On the untrusted peek/unwrap path that escaped `verify_many`'s
  per-credential isolation and **aborted the whole batch** (denial-of-service; not a
  wrong-accept) — reachable unauthenticated and, on CPython 3.10–3.13, with ~1 KB of
  input. SD-JWT `_unpack` now caps recursion at depth 100 (parity with `cbor`=64 /
  `_jcs`=100), the did:webvh genesis SCID walk (`_deep_replace_scid`) is depth-bounded
  too, and **every attacker-facing `json.loads`** — SD-JWT, VC-JWT peek/verify, `_jws`,
  the enveloped unwrap, `jwe`, and the `did:jwk` / `did:webvh` / fetch / status-resolver
  paths — now maps `RecursionError` to a typed error, so hostile input fails closed and
  `verify_many` isolates it across all formats. Resolves the **R1** residual risk from
  the audit pack. ([#117](https://github.com/luisgf/openvc/issues/117))

## [1.20.0] — 2026-07-10

Part of the [Depth — mdoc, status trust & parity](https://github.com/luisgf/openvc/milestone/10)
milestone — the second wave from the 2026-07-10 internal audit.

### Added

- **Opt-in status-list issuer binding ([ADR-0006](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0006-status-list-issuer-binding.md)).**
  `VerificationPolicy` gains `require_status_issuer_binding` — bind the resolved status
  list's issuer to the credential's issuer — and `status_issuer_allowlist` for trusted
  delegates. A status list is authenticated but its issuer was otherwise unconstrained, so
  a compromised status host serving a list signed by an attacker key could silently
  "un-revoke" a credential; enabling the binding closes that. Off by default (delegation is
  spec-legal — no behaviour change); a mismatch raises the new typed
  `StatusListIssuerUntrusted`. Enforced in both the sync and async pipelines.
  ([#106](https://github.com/luisgf/openvc/issues/106))

### Changed

- **Performance: the bundled JSON-LD context is parsed once, not per proof.** RDF Data
  Integrity canonicalization re-read and re-parsed the bundled `credentials/v2` context from
  disk on every sign/verify; it is now parsed once and shared read-only (still a fresh
  top-level dict per call, so an injected `extra_contexts` can't pollute the cache). The
  three whole-document DI suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, JCS) now share one
  proof-preamble helper (`_verify_common.prepare_di_proof`), so the fail-closed proof
  validation cannot drift between them — behaviour is byte-for-byte identical (pinned by the
  golden fixtures). `openvc.resolvers` documents `openvc.cache.cached_resolve` /
  `CachingDidResolver` for high-volume verifiers (`verify_many` already deduplicates status /
  DID resolution within a call). ([#110](https://github.com/luisgf/openvc/issues/110))

### Fixed

- **EBSI: the recursive trust-chain walk now accepts a wildcard accreditation, matching the
  single-level policy.** An accreditation with no `credentialType` restriction (an
  unrestricted delegation) was accepted by `openvc_ebsi.verify`'s single-level check but
  rejected at the leaf of the recursive `verify_trust_chain`; the two now agree — a wildcard
  delegates the credential's types. ([#109](https://github.com/luisgf/openvc/issues/109))

### Security

- **mdoc: the document-signer certificate profile is now enforced.** `resolve_mdoc_signer_key`
  requires the leaf to carry the ISO 18013-5 Annex B document-signer ExtendedKeyUsage
  (`1.0.18013.5.1.2`) — previously any certificate that chained to a trusted IACA anchor
  (a TLS leaf, a DS for another purpose) was accepted as an MSO signer. The MSO `validityInfo`
  must now carry `signed`, and `signed` must fall within the document-signer certificate's own
  validity window (ISO 18013-5 §9.3.1). Verified against the real Annex D reference certificate,
  which carries the EKU. ([#105](https://github.com/luisgf/openvc/issues/105))
- **XAdES trusted-list verification hardened.** A Trusted List's XAdES / XML-DSig signature
  is now verified with a pinned algorithm profile (RSA / ECDSA — including RSA-PSS — over
  SHA-256/384/512; HMAC, DSA, SHA-1 and SHA-224 rejected) and **exactly one Reference**, and
  the verified subtree must be the **document root** — an XML-Signature-Wrapping guard, so a
  signature valid over a fragment cannot leave unsigned `TrustServiceProvider` / certificate
  nodes outside the signed scope for the parser to harvest. The TL parser also enforces a
  **max element count** (ADR-0003 D4) alongside the existing byte cap.
  ([#107](https://github.com/luisgf/openvc/issues/107))

## [1.19.3] — 2026-07-10

Part of the [Correctness & fail-closed hardening](https://github.com/luisgf/openvc/milestone/9)
milestone — the 2026-07-10 internal-audit hardening wave.

### Fixed

- **Typed-error boundary on hostile input — a non-object JOSE header/payload no longer
  crashes untyped or aborts a batch.** A credential or `vp_token` whose JOSE header or
  payload is valid JSON but *not an object* (e.g. a bare array `[0]`) reached the
  untrusted *peek* path and raised a bare `AttributeError`, which escaped the
  `OpenvcError` family and — through `verify_many` — aborted the entire batch, breaking
  both the fail-closed typed-error contract and the documented per-item isolation.
  `peek_issuer` / `peek_claims` and the SD-JWT decoder now reject a non-object
  header/payload with a typed `MalformedToken`. The same pass closes sibling untyped
  escapes on attacker-controlled input: `ecdsa_sd.verify` (a hostile `proofValue` or an
  unknown `@context` now raise `ProofValueMalformed` / `ProofMalformed` instead of a raw
  pyld error), a malformed Ed25519 JWK (`ProofMalformed`), a lone surrogate in JCS
  (`JcsError`), and a non-JSON-object EBSI registry `200` (`MalformedRegistryResponse`).
  ([#99](https://github.com/luisgf/openvc/issues/99))
- **Verify-path consistency & fail-closed defaults across formats.** Several checks were
  hardened on one proof family but not its siblings: the JOSE temporal check is now
  single-sourced (`_verify_common.check_jwt_temporal`) and rejects a **non-finite**
  `exp`/`nbf` (`NaN`/`Infinity`, which `json.loads` accepts and which never expires) on
  the SD-JWT VC and VP-JWT paths too, not only VC-JWT; VC-JWT now **pins the EC curve to
  the alg** (an `ES256` header can no longer verify against a P-384 key), matching
  `keys.verify_signature`; `verify_vp_token`'s `jwt_vc_json` lane forwards
  `require_status=False` like the `dc+sd-jwt` and `ldp_vc` lanes, so an embedded VC that
  carries a `credentialStatus` is no longer wrongly rejected with `StatusUnavailable`;
  `did:web` now requires the resolved document's `id` to equal the requested DID (a
  missing `id` no longer skips the binding); and a malformed (non-string)
  `credentialSchema.digestSRI` fails closed instead of silently dropping the integrity
  pin. ([#101](https://github.com/luisgf/openvc/issues/101))

### Security

- **`did:webvh` witness-policy refusal is no longer bypassable via a non-integer
  threshold.** A log declaring a witness policy with a float or string `threshold`, or a
  `witnesses` list with no `threshold` at all, slipped past the integer-only fail-closed
  gate — so a single compromised `updateKey` could forge an entry and silently downgrade
  a witness-protected DID to the un-witnessed trust model. openvc still cannot verify
  witness co-signatures, so any *active* policy (a `threshold` of any type that is not an
  explicit `0`/`false`, or a non-empty `witnesses` list) is now refused.
  ([#100](https://github.com/luisgf/openvc/issues/100))
- **SD-JWT key binding is no longer accepted without a verifier nonce/aud to bind it.**
  When a verifier set `require_key_binding=True` but passed neither `nonce` nor
  `audience`, the KB-JWT's signature and `sd_hash` were checked but not its binding to a
  challenge/verifier — so a presentation built for verifier A satisfied verifier B
  (replay). Requiring key binding now also requires a non-null `nonce` and `audience`,
  matching VP-JWT's "no unbound mode". ([#101](https://github.com/luisgf/openvc/issues/101))
- **Codec strictness pass on attacker-controlled bytes.** Three hand-rolled decoders were
  tightened to their RFC/ISO contracts: the CBOR decoder now **rejects duplicate map keys**
  (RFC 8949 §5.6 / COSE + ISO 18013-5 deterministic encoding) instead of keeping the last;
  COSE reads the signature `alg` **only from the protected header** (RFC 9052 §3.1 — an
  `alg` in the unsigned unprotected header is no longer honoured; the `x5chain` unprotected
  fallback is unchanged) and **rejects a `crit` header** listing any label it does not
  process; and the JCS canonicalizer serialises integers beyond ±2^53 **as IEEE-754
  doubles** (RFC 8785 §3.2.2.3) so a JCS credential with a large integer canonicalizes
  identically to other implementations. ([#102](https://github.com/luisgf/openvc/issues/102))
- **Uniform resource limits on the network and codec surface.** The EBSI HTTP client now
  streams responses under a **size cap** and a **total wall-clock deadline** (it previously
  had only a per-socket timeout and no size bound, so a large or slow-drip body from an
  allow-listed host could exhaust memory or pin the client); the general `did:web` fetch
  gained the same wall-clock deadline (chunked `read1`); `jwe.decrypt_compact` bounds the
  token size before decoding; `multibase` caps the base58 input length (its decode is
  O(n²)) and the multicodec varint length; and the EBSI `Retry-After` header now honours
  the HTTP-date form as well as delta-seconds.
  ([#103](https://github.com/luisgf/openvc/issues/103))

## [1.19.1] — 2026-07-10

### Added

- **DID 1.1 / CID 1.0 document tolerance, pinned.** `parse_did_document` is context-agnostic
  (it reads the document *shape*, not `@context`), so DID 1.1 documents — rebased on CID 1.0,
  using the `https://www.w3.org/ns/did/v1.1` context, with `Multikey` verification methods —
  already resolve unchanged. Conformance tests now **pin** that tolerance (parse + end-to-end
  verification through the pipeline) so a future change cannot silently start rejecting DID 1.1
  the day issuers emit it. No behaviour change; the relationship-semantics diff is revisited when
  DID 1.1 reaches Proposed Recommendation. ([#76](https://github.com/luisgf/openvc/issues/76))

## [1.19.0] — 2026-07-10

### Added

- **ML-DSA (RFC 9964) post-quantum signing + verification — experimental opt-in.** New
  `openvc.keys.MLDSASigningKey` (parameter sets `ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87`) behind
  the same `SigningKey` protocol — seed-only private keys, the RFC 9964 **`AKP`** JWK key type,
  and external-mu (`sign_mu`) so an HSM keeps the private-key-never-in-process posture. VC-JWT and
  SD-JWT VC issue/verify ML-DSA when a suite is constructed with **`allow_pq=True`**; it is
  **never** in the default allow-list — the default suites reject `ML-DSA-*` before any crypto, and
  opting in adds only the three names, never the classic weak algs. Verification routes through the
  dependency-light `keys.verify_signature` (not PyJWT); `did:jwk` carries an `AKP` key unchanged.
  Gated behind the new **`[pq]`** extra (`cryptography>=48` built against OpenSSL ≥ 3.5; check
  `openvc.mldsa_available()`) — the core install is unchanged (`cryptography>=45` + `pyjwt`).
  **Experimental**: no golden-fixture conformance claim (no stable third-party ML-DSA VC vectors
  yet), Data Integrity PQ cryptosuites stay out (W3C FPWD), JOSE-only. Implements
  [ADR-0004](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0004-ml-dsa-design.md).
  Hardened by an adversarial review — no forgery, opt-in bypass or downgrade was achievable
  (the default suites reject `ML-DSA-*` before any crypto) — which also tightened two
  fail-closed contract gaps it found: a malformed `AKP` JWK now raises a typed `ProofError`
  (not a bare `InvalidKey`), and non-finite `exp` / `nbf` are rejected on both the ML-DSA and
  the PyJWT paths. ([#72](https://github.com/luisgf/openvc/issues/72))

## [1.18.0] — 2026-07-10

### Added

- **SD-JWT VC issuance can emit an `x5c` header.** `SdJwtVcProofSuite.issue(..., x5c=[…])` places
  an X.509 certificate chain (base64 DER, leaf first) in the issuer JWT header, closing the loop
  with the existing verify-side support: an issuer anchored on a trusted list (eIDAS / EUDI) can
  now be verified in **one call** — `verify_credential(sd_jwt, x5c_trust_anchors=[…])` chains the
  leaf to those anchors and binds it to `iss` (previously the anchoring needed a separate
  `resolve_x5c_key` step). The leaf's key must be the signing key and `iss` must be in its SAN, or
  verification fails closed. The `examples/11_spanish_university_credential.py` walkthrough now
  verifies the FNMT-anchored diploma in a single call.
  ([#94](https://github.com/luisgf/openvc/issues/94))

## [1.17.0] — 2026-07-10

Part of the [Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7) milestone.

### Added

- **`mso_mdoc` verification — verify a received ISO 18013-5 `DeviceResponse` (experimental).**
  Completes the EUDI two-format mandate (SD-JWT VC + mdoc, CIR (EU) 2024/2977): `verify_vp_token`
  now verifies an ISO 18013-5 `mso_mdoc` presentation over the **W3C Digital Credentials API**
  flow instead of fencing it off. Both ISO 18013-5 §9.1 authentications are checked, fail-closed:
  **issuer data authentication** — the `IssuerAuth` `COSE_Sign1` over the Mobile Security Object,
  the document-signer `x5chain` (COSE label 33) path-validated to a caller-provided **IACA**
  anchor, the MSO `docType` / `validityInfo`, and every disclosed `IssuerSignedItem` digest matched
  against `valueDigests`; and **device authentication (holder binding)** — the `DeviceSignature` /
  `DeviceMac` over the `DeviceAuthentication` built from the origin-bound `SessionTranscript`
  (OpenID4VP 1.0 Appendix B / ISO 18013-7). New `trust_anchors` (IACA roots) and
  `mdoc_jwk_thumbprint` parameters on `verify_vp_token` / `verify_encrypted_vp_response`, and a
  `dcapi_session_transcript()` builder; each verified document returns an
  `openvc.mdoc.VerifiedMdoc`. Direct entry points `openvc.mdoc.verify_device_response` (full) and
  `verify_issuer_signed` (issuer seal only) are exposed. Conformance is pinned to the **real
  ISO 18013-5 Annex D** `DeviceResponse` (byte-exact issuer-side vector) plus a real-crypto online
  fixture for device authentication and the negative paths. **No new runtime dependency** — COSE and
  the extended CBOR are hand-rolled. The redirect / `direct_post` mdoc handover is not yet wired; the
  surface ships experimental until interop-tested against the EUDI reference wallet. Hardened by an
  adversarial review — no forgery or replay was achievable (COSE alg allow-list before any crypto,
  digests over bytes-as-received, origin-bound `SessionTranscript`, fail-closed CBOR parsing) — which
  also tightened two contract gaps it found: DCQL `meta.doctype_value` is now enforced for `mso_mdoc`
  (the mdoc analogue of `vct_values`), and the CBOR codec rejects float / non-canonical simple values
  outright rather than aliasing them to `false`/`true`/`null`. ([#86](https://github.com/luisgf/openvc/issues/86))

- **VC-API conformance shim (test-only).** A stdlib `tests/tools/vc_api_shim.py` exposes the VC-API
  `/credentials/issue`, `/credentials/verify` and `/presentations/verify` endpoints backed by the Data
  Integrity suites (`eddsa-rdfc-2022` / `eddsa-jcs-2022` / `ecdsa-rdfc-2019` / `ecdsa-jcs-2019`, P-256
  and P-384), so openvc can be driven through the official **W3C test suites** (vc-data-model-2.0,
  vc-di-eddsa, vc-di-ecdsa, bitstring-status-list) and registered in the **public implementation
  reports** — third-party conformance evidence beyond the in-repo golden fixtures. Not a shipped API
  surface and **no runtime dependency** (stdlib `http.server`); see `tests/tools/README.md`.
  ([#69](https://github.com/luisgf/openvc/issues/69))

- **Walkthrough: a Spanish university credential end to end.** A runnable
  `examples/11_spanish_university_credential.py` and a wiki walkthrough verify a
  higher-education diploma with openvc alone — the issuer's document-signer chains to an
  **FNMT-RCM** anchor (the EU LOTL → Spanish TLv6 trusted list → `x5c`) and the diploma is an
  **SD-JWT VC** (DC4EU EUHED shape) verified with that FNMT-anchored key and the holder's key
  binding, offline. The walkthrough also maps the complementary EBSI TIR accreditation path
  (`verify_ebsi_badge`). Docs only. (Filed [#94](https://github.com/luisgf/openvc/issues/94) —
  emit an `x5c` header on SD-JWT VC issuance so `verify_credential` anchors it in one call.)
  ([#70](https://github.com/luisgf/openvc/issues/70))

### Changed

- **CBOR codec factored into a dependency-free `openvc.cbor` module** (ADR-0005 D4), extended to the
  COSE/mdoc profile — negative integers, tags (with the exact received bytes preserved for digest /
  signature recomputation), booleans/null, and deterministic (RFC 8949 §4.2.1) encoding. The
  `ecdsa-sd-2023` suite now imports the shared codec; its proof-value shape is a strict subset, so
  there is **no behaviour change** (the strict subset — no bool/negative/tag — is still enforced).
  New `openvc.cose` (COSE_Sign1 / COSE_Mac0 verify) and an mdoc `x5chain`→IACA adapter
  (`openvc.x5c.resolve_mdoc_signer_key`, sharing the path-validation core with the JOSE `x5c` path).

## [1.16.0] — 2026-07-10

Part of the [Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7) milestone.

### Added

- **OpenID4VP over the W3C Digital Credentials API — origin-bound `vp_token` verification.**
  `verify_vp_token` / `verify_encrypted_vp_response` gain an **`expected_origins`** parameter for
  the DC API flow (CIR (EU) 2025/1569 pins remote presentation to OpenID4VP + the DC API). A
  DC-API-delivered response binds to the **calling web origin**, so per OpenID4VP 1.0 Appendix A
  its audience is always **`origin:<origin>`**, never the `client_id`; a Presentation is accepted
  only if its signed `aud` is `origin:<o>` for an `o` in `expected_origins`. The two response
  modes map to the two calls: **`dc_api`** (unencrypted) → `verify_vp_token`, **`dc_api.jwt`**
  (encrypted JWE) → `verify_encrypted_vp_response`. `client_id` is now optional — pass **exactly
  one** of `client_id` (redirect / `direct_post`) or `expected_origins` (DC API); the `nonce`
  binding, formats and holder-binding are unchanged. Stateless consume-and-verify — building the
  DC-API request is browser/wallet plumbing, out of scope. Hardened by an adversarial review (no
  origin-binding or replay bypass was possible; fail-closed input validation on `expected_origins`
  and on the pre-verification `aud` peek). ([#66](https://github.com/luisgf/openvc/issues/66))

## [1.15.0] — 2026-07-10

Part of the [Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7) milestone.

### Added

- **`did:webvh` resolver (DIF Recommended DID Method v1.0), verify-side.** New
  `openvc.did.did_webvh` resolves a `did:webvh` DID by fetching its `did.jsonl` version log
  over the SSRF-guarded text fetch and **replaying it fail-closed**: the **SCID** (the
  identifier is the `base58btc(multihash-sha256(JCS(...)))` of the genesis entry), the
  **entryHash chain** (version numbers increment; an inserted/reordered/tampered entry
  breaks it), each entry's **`eddsa-jcs-2022`** Data Integrity proof by an authorized
  `updateKey`, and **key pre-rotation** (a rotated-in key must hash into the previous
  `nextKeyHashes`). A deactivated log fails closed, and a log that declares a **`witness`
  threshold policy is refused fail-closed** (verify-side witness verification is
  unsupported — openvc will not silently downgrade to the un-witnessed trust model).
  Registered in the default resolver (sync + async), so a `did:webvh` issuer verifies with
  no code change; the multihash / JCS / Ed25519 primitives are the in-tree ones, no new
  dependency. Conformance is pinned to **real v1.0 golden vectors** from the reference
  `didwebvh-rs` test suite, and the resolver was hardened by an adversarial review (no log
  forgery was possible; the witness downgrade and a pre-rotation crash-on-junk were fixed).
  Verify-side only — log creation / rotation / witnessing (issuer-side) is out of scope.
  ([#68](https://github.com/luisgf/openvc/issues/68))

### Changed

- **`parse_did_document` now reads `publicKeyMultibase` Multikey verification methods**
  (Ed25519 / P-256 / P-384), not only `publicKeyJwk` — the modern W3C encoding `did:webvh`
  and newer `did:web` documents use. Purely additive: a method without a decodable key is
  still skipped. New `openvc.did.base.multikey_to_jwk` helper. ([#68](https://github.com/luisgf/openvc/issues/68))

## [1.14.0] — 2026-07-09

Part of the [Medium term — EUDI completeness](https://github.com/luisgf/openvc/milestone/7) milestone.

### Added

- **EBSI production-launch readiness.** The `openvc_ebsi` plugin is ready for EBSI's
  **Q4 2026 business/production launch** (EUROPEUM-EDIC, `ebsi.eu` family): `for_ebsi` gains a
  **`production`** environment (`api.ebsi.eu`), seeding the https-only SSRF allow-list and
  `EBSI_BASE` for the cutover. The **TIR v5 `/attributes` listing is now walked across every
  page** — the adapter followed only the first page before, silently dropping an issuer's later
  accreditations (a fail-closed trust gap); pagination follows the JSON:API `links.next` cursor
  bounded by `total`, a same-origin check (host **and** port), a seen-page guard (EBSI returns a
  self-referential `next` on the last page — following it blindly looped forever), and hard page
  **and item** caps, all through the SSRF-guarded fetch. A malformed registry body (a `null` /
  array / string where an object is required) now fails closed as a typed `MalformedRegistryResponse`
  rather than leaking a bare `AttributeError` past the `EbsiError` family. `verify_ebsi_badge` is
  confirmed to verify the **VCDM 1.1 and 2.0 dual envelopes** Conformance v4 issues (2.0 keeps the
  JWT `vc` wrapper, with `validFrom`/`validUntil`), covered by a regression test. Read-only stays
  read-only. ([#64](https://github.com/luisgf/openvc/issues/64))
- **EUDI relying-party access certificate (WRPAC) parsing.** New `openvc.rp_cert` reads a
  **WRPAC** — the mandatory X.509 access certificate (CIR (EU) 2025/848, ETSI TS 119 411-8) that
  authenticates *who is asking* — over the existing `cryptography` X.509 machinery, with the same
  fail-closed posture as `openvc.x5c`. `verify_rp_access_certificate(cert, *, trust_anchors, …)`
  path-validates the chain to caller-provided **ACA** anchors (signatures, validity,
  `basicConstraints` — no non-CA-intermediate smuggling; only the TLS EKU is relaxed), optionally
  enforces a `required_eku`, and returns a typed `RelyingPartyAccessCertificate` (entity
  identifier, trade name, EKUs, certificate policies, and the Subject Information Access
  registration-record URLs) to gate on; `parse_rp_access_certificate` is the untrusted,
  inspection-only counterpart. The **registration certificate (WRPRC)** — the entitlements /
  intended-use artifact — is a signed JWT/CWT (ETSI TS 119 475), not X.509, with a claim mapping
  not yet finalised, and is deferred to its own issue ([#89](https://github.com/luisgf/openvc/issues/89)).
  Hardened by an adversarial review: identity attributes are enforced single-valued (a duplicate-RDN
  spoof fails closed) and mistyped trust parameters raise the typed `RpCertError`.
  ([#67](https://github.com/luisgf/openvc/issues/67))
- **ML-DSA (RFC 9964) design ADR** ([ADR-0004](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0004-ml-dsa-design.md)).
  The post-quantum spike concludes: `ML-DSA-44/65/87` VC-JWT / SD-JWT VC would land behind the
  existing `SigningKey` protocol as an **explicitly-experimental opt-in** — a `[pq]` extra pinning
  `cryptography>=48` plus a runtime capability guard (ML-DSA needs OpenSSL ≥ 3.5), a new
  `AKP`-keyed backend (the 32-byte seed private key, raw-bytes `sign`, external-mu `sign_mu` for the
  HSM path), verification through the dependency-light `keys.verify_signature` (PyJWT ships no
  ML-DSA), and a **separate PQ allow-list merged only when opted in** so the default alg-confusion
  defence is untouched. Data Integrity PQ suites, `did:key` multicodec (still draft), and composite
  signatures stay out of scope. **Design only; no code change** — the implementation is tracked in
  [#72](https://github.com/luisgf/openvc/issues/72). ([#71](https://github.com/luisgf/openvc/issues/71))
- **`mso_mdoc` verification scope ADR** ([ADR-0005](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0005-mso-mdoc-verification.md)).
  The mdoc spike concludes **verify-only `mso_mdoc` is in scope** — the second mandatory EUDI format
  (CIR 2024/2977), read-only server-side verification of an OpenID4VP-delivered `DeviceResponse`
  (IssuerAuth MSO `COSE_Sign1` + `x5chain`→IACA, `valueDigests` integrity, DeviceAuth over the
  OpenID4VP SessionTranscript). Strategy: a **hand-rolled COSE verifier with no new runtime
  dependency**, factoring the in-tree `ecdsa-sd` CBOR codec into a shared module and extending it
  (negative ints, tags), reusing `x5c` path-validation and `keys.verify_signature`. Device
  engagement / proximity / issuance / COSE **signing** stay out; the build is a dedicated follow-up
  issue sequenced with the Digital Credentials API work ([#66](https://github.com/luisgf/openvc/issues/66))
  and covered by the external audit ([#75](https://github.com/luisgf/openvc/issues/75)). Also
  refreshes the ROADMAP out-of-scope note. **Design only; no code change.**
  ([#65](https://github.com/luisgf/openvc/issues/65))

### Security

- **VC-JWT verification now also enforces the credential body's own validity window.**
  `VcJwtProofSuite.verify` checked only the JWT `exp`/`nbf` claims; it now *additionally* enforces
  the credential's VCDM 2.0 `validFrom`/`validUntil` (and VCDM 1.1 `issuanceDate`/`expirationDate`)
  with the same leeway. An issuer — EBSI's VCDM 2.0 envelopes among them — can encode expiry **only**
  in the credential body with no JWT `exp`; such an expired credential previously verified. Surfaced
  by the adversarial review of #64. Fail-closed, defence-in-depth; raises the existing
  `CredentialExpired` / `CredentialNotYetValid` (both `ProofError`). ([#64](https://github.com/luisgf/openvc/issues/64))

## [1.13.1] — 2026-07-08

Part of the [Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6) milestone.

### Changed

- **Post-1.0 documentation truth pass.** `docs/ROADMAP.md` is rewritten around the current
  Short / Medium / Long-term milestones (the shipped 0.8→post-1.0 framing is gone, and the
  out-of-scope list now points at the mdoc and BBS spikes); the PyPI **classifier** moves from
  `3 - Alpha` to `5 - Production/Stable`; the GitHub **topics** gain `sd-jwt-vc` / `openid4vp` /
  `eudi` / `eidas` / `trusted-list` / `did-key` / `es256`; the wiki gains a **Credential
  schemas** page (the `JsonSchema` and signed `JsonSchemaCredential` types + `digestSRI`
  pinning) and a fuller **Caching** section (`TtlCache` / `CachingDidResolver` / `cached_resolve`
  and the status-freshness TTL); and `docs/SESSION-HANDOFF.md` is banner-marked as a historical
  v0.1-era snapshot. No code change. ([#62](https://github.com/luisgf/openvc/issues/62))

## [1.13.0] — 2026-07-08

Part of the [Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6) milestone.

### Added

- **TLv6 (ETSI TS 119 612 v2.4.1) trusted-list conformance + EUDI service types.** Since
  **29 Apr 2026** the EU LOTL and every national Trusted List are TLv6 only.
  `openvc.trustlist` now parses `TSLVersionIdentifier` (new **`TrustList.version`** — `6`
  for TLv6) and tolerates the new optional elements (e.g. `ServiceSupplyPoints`) — verified
  against the real deployed TLv6 lists. `ServiceType` gains named constants for the qualified
  trust services TLv6 national lists carry beyond `CA/QC`: `EDS_Q`, `EDS_REM_Q`, `PSES_Q`,
  `QES_VALIDATION_Q`, `REMOTE_QSIGCD_MANAGEMENT_Q`, `REMOTE_QSEALCD_MANAGEMENT_Q`,
  `NATIONAL_ROOT_CA_QC`, `TSA`, `OCSP`, `ARCHIVING`. `Select` matches `ServiceTypeIdentifier`
  **verbatim**, so the EUDI-wallet trust services v2.4.1 introduces (issuance of QEAA / EAA /
  PuB-EAA, qualified electronic ledgers) are already selectable by their URI as national lists
  start carrying them — no library change needed. The golden fixtures are refreshed to TLv6
  shape. Purely additive. ([#58](https://github.com/luisgf/openvc/issues/58))

## [1.12.0] — 2026-07-08

Part of the [Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6) milestone.

### Added

- **Verify `ldp_vc` presentations in `verify_vp_token` (OpenID4VP 1.0 §B.1).** An `ldp_vc`
  DCQL query is answered with a **W3C Verifiable Presentation secured by a Data Integrity
  `authentication` proof**; `verify_vp_token` / `verify_encrypted_vp_response` now verify
  it beside `dc+sd-jwt` and `jwt_vc_json` (previously a typed `UnsupportedPresentationFormat`).
  The request binding maps onto the proof — `proof.challenge` = the `nonce`, `proof.domain`
  = the full, prefixed `client_id`, `proofPurpose: authentication` — the holder key is
  resolved from the proof's `verificationMethod` (and must be authorised for
  `authentication` in its DID document), and every embedded credential is **cascade-verified**
  through `verify_credential`. All four whole-document cryptosuites are accepted:
  `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` (need the `[data-integrity]` extra) and the pyld-free
  `eddsa-jcs-2022` / `ecdsa-jcs-2019`. The format is **pinned to the DCQL query** — a bare
  string or a bare credential with no VP wrapper is rejected, since the holder binding lives
  only on a presentation proof (the LDP analogue of the existing `dc+sd-jwt` "must be an
  SD-JWT" pin, closing the same unbound-credential smuggle). The reported `holder` is the
  **authenticated** identity — the DID that controls the signing `verificationMethod`, never
  a self-asserted `holder` field (a mismatch is rejected), so a caller's "did the presenter
  own this credential?" check cannot be spoofed. A new opt-in `require_holder_binding=`
  additionally requires every embedded credential's `credentialSubject.id` to equal that
  authenticated holder (for the W3C VP formats `ldp_vc` / `jwt_vc_json`). A new optional
  `extra_contexts=` threads custom JSON-LD contexts to the RDF path. `mso_mdoc` remains a
  typed `UnsupportedPresentationFormat`. ([#61](https://github.com/luisgf/openvc/issues/61))

## [1.11.1] — 2026-07-08

Part of the [Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6) milestone.

### Changed

- **Normative references refreshed, and the IETF Token Status List codec pinned to its
  current draft.** The SD-JWT mechanism openvc implements is now **RFC 9901** (Nov 2025,
  formerly draft-ietf-oauth-selective-disclosure-jwt) — docstrings updated. The Token
  Status List is at **draft-ietf-oauth-status-list-21** (IESG-approved, in the RFC Editor
  queue — no RFC number yet); a new `tests/test_conformance_status_list.py` drift alarm
  pins the codec **byte-for-byte** to the draft §4.1 1-bit and 2-bit worked examples
  (decoding each published `lst` reproduces the exact status array, and the encoder
  reproduces each `lst`), plus the token/reference wire contract (`typ: statuslist+jwt`,
  `status_list{bits,lst}`, `status.status_list{uri,idx}`, and the VALID/INVALID/SUSPENDED
  status types). No behaviour change — when the RFC publishes, the vectors and citations
  swap to it and any draft→RFC wire drift fires here first.
  ([#60](https://github.com/luisgf/openvc/issues/60))

## [1.11.0] — 2026-07-08

Part of the [Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6) milestone.

### Added

- **Accept the RFC 9864 fully-specified `Ed25519` JOSE algorithm name.** RFC 9864
  (Oct 2025) marks the polymorphic `EdDSA` **Deprecated** in the IANA registry and
  gives `Ed25519` as the fully-specified name for the same Ed25519 signature.
  `Ed25519` joins the algorithm allow-list — now `{ES256, ES384, EdDSA, Ed25519}`,
  still checked **before any crypto** — so a token with `alg: Ed25519` verifies
  exactly like an `EdDSA` one across VC-JWT, SD-JWT VC and the IETF status-list token
  (the SD-JWT / status paths already routed through `keys.verify_signature`; VC-JWT
  now decodes through a **private** PyJWT instance taught the name, with no
  process-global pyjwt-registry mutation). **Signing still emits `EdDSA` by default**
  — no wire change unless you ask for it — with an opt-in per key:
  `Ed25519SigningKey.generate(kid, alg="Ed25519")` (also `.from_jwk` / `.from_pem`).
  `RS*` / `HS*` / `alg:none` stay rejected before any crypto. `ES256`/`ES384` are not
  deprecated, so their `ESP256`/`ESP384` fully-specified names are deliberately **not**
  accepted yet (see the versioning guide). Because `Ed25519` is *fully-specified*, the
  VC-JWT verify path now **pins the OKP curve to Ed25519** (an Ed448 key/signature under
  `Ed25519` — or `EdDSA` — fails closed), matching `keys.verify_signature`. (Curve-pinning
  gap found in the #59 adversarial review.) ([#59](https://github.com/luisgf/openvc/issues/59))

## [1.10.0] — 2026-07-08

Part of the [Short term — TLv6 & spec-churn](https://github.com/luisgf/openvc/milestone/6) milestone.

### Added

- **The full key surface is re-exported from the package root.** Beside the existing
  `Ed25519SigningKey` / `P256SigningKey` / `SigningKey`, `openvc` now also exports
  `P384SigningKey`, the `KeyAgreementKey` protocol and its `P256KeyAgreementKey` (the
  HAIP `direct_post.jwt` decryption backend), the `signing_key_from_jwk` factory and
  the dependency-light `verify_signature` helper — so the signing/key primitives import
  symmetrically from `openvc` or from `openvc.keys` (they are the **same objects**).
  Purely additive; `openvc.keys` is unchanged. Backed by new dedicated unit floors for
  `openvc.keys`, `openvc.proof.vc_jwt` and `openvc.multibase` — the three lowest-level
  modules, previously covered only indirectly — asserting the negative paths first (the
  algorithm allow-list rejecting `none`/RS\*/HS\* before any crypto, VC-JWT envelope
  reconciliation, wrong-curve / malformed-JWK typed failures, ECDH peer-key rejection,
  and the base58/varint leading-zero and truncation edges).
  ([#63](https://github.com/luisgf/openvc/issues/63))

## [1.9.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Reference XAdES verifier for EU Trusted Lists (the `[trustlist]` extra).** New
  `openvc.trustlist.verify_xades_enveloped` — the batteries-included, fail-closed
  `verify_signature` callback that `walk_lotl` / `consume_trust_list` need: it checks a
  Trusted List's enveloped XAdES / XML-DSig signature verifies against **one of** the
  expected signer certificates (the ones the parent list vouched for), pinning trust to
  those certs — an authentic-but-unexpected signer, a wrong key, or tampered content all
  fail. Completes the LOTL→TL trust anchoring from [#26](https://github.com/luisgf/openvc/issues/26)
  (part 1 landed the parser + fail-closed walk with signature verification injected). It
  lives behind a new **`[trustlist]` extra** (`signxml`, which pulls `lxml` — kept out of
  core; loaded lazily, only when verifying); without it, verification raises
  `TrustListSignatureBackendUnavailable`. `signxml` forbids DTDs, so XXE / entity-expansion
  are rejected; input is size-bounded. Proven by a sign→verify round-trip and a full
  `walk_lotl` over a signed LOTL + national TL, incl. a forged-national-TL fail-closed
  case. ([#26](https://github.com/luisgf/openvc/issues/26))

## [1.8.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Consume EU Trusted Lists (LOTL → national TL) as a verifier trust-anchor source.**
  New `openvc.trustlist`: `walk_lotl(...)` turns the Commission's List of Trusted Lists
  and the national Trusted Lists it points at (eIDAS 2.0 / EUDI, ETSI TS 119 612) into a
  `TrustAnchorSet` whose `.certificates` feed the existing X.509 path directly —
  `verify_credential(vc, x5c_trust_anchors=anchors.certificates)` (and `.x509_hashes` for
  HAIP `x509_hash` roots). This closes *"the `x5c` chain is internally valid"* → *"the
  chain roots in an **EU-recognised** anchor, for the right service type, granted now"* —
  it adds **no** verification surface; `openvc.x5c` stays the path validator and trust
  lists are only the anchor source. **Trust is caller-pinned** (the LOTL signer certs —
  no implicit root), **fail-closed** (a TL that can't be fetched/verified/is expired
  contributes zero anchors and is recorded in `problems`, never silently trusted), and
  **selective** (default: `granted` qualified-CA services; `select=None` returns all).
  XML parsing is **hardened stdlib** (no DTD/DOCTYPE → no XXE or entity-expansion bombs,
  bounded size); **XML-signature (XAdES) verification is an injected `verify_signature`
  callback** kept out of core (a reference implementation behind a `[trustlist]` extra
  follows). Generic — not EBSI-coupled. See
  [ADR-0003](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0003-eu-trusted-lists.md).
  ([#26](https://github.com/luisgf/openvc/issues/26))
- **Async-friendly verification (`openvc.aio`).** New `verify_credential_async` /
  `verify_many_async` — the async counterparts of `verify_credential` / `verify_many`
  for asyncio servers (FastAPI/Starlette), so a handler `await`s verification instead of
  offloading the whole call to a thread pool, and a presentation cascade resolves its
  issuers/status-lists **concurrently** (`asyncio.gather`) instead of serialising N
  blocking fetches. Same formats, same `VerificationPolicy`, same `VerificationResult`,
  same fail-closed guarantees — the async path **reuses every proof suite, status/schema
  codec and binding check unchanged** and only re-expresses the I/O sequencing with
  `await` (no second implementation of any signature check; see
  [ADR-0002](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0002-async-verification.md)).
  New injection points mirror the sync ones with awaitables: an `AsyncDidResolver` /
  `AsyncDidResolverRegistry` (+ `as_async_resolver` to adapt any sync resolver), an
  `AsyncDidWebResolver`, `openvc.fetch.https_{json,text,bytes}_fetch_async`, and async
  default resolvers in `openvc.resolvers`. The batteries-included async fetch runs the
  **exact same** SSRF/DNS-rebind guard under `asyncio.to_thread` — identical guarantees,
  **no new dependency** (a caller may inject an `httpx.AsyncClient`-backed fetch instead).
  `verify_many_async` deliberately does not port the sync batch's cross-credential resolver
  cache (not concurrency-safe — ADR-0002 D4); overlapping the I/O is the win.
  ([#27](https://github.com/luisgf/openvc/issues/27))
- **`JsonSchemaCredential` — the schema-in-a-VC type.** `openvc.schema` now validates a
  `credentialSchema` entry of type `JsonSchemaCredential`, where the schema a credential
  points at is itself a **signed Verifiable Credential**. The pipeline fetches that VC,
  **verifies its proof** through the same `verify_credential` path — so every DID / x5c /
  status resolver the caller wired applies to it too, fail-closed — and applies the JSON
  Schema nested in its verified `credentialSubject.jsonSchema` to the outer credential.
  Recognised by `verify_credential(resolve_credential_schema=…)` and by standalone
  `openvc.schema.validate_credential_schema(…, verify_inner=…)`; the schema layer takes the
  verifier as an injected callable, so it stays free of an import cycle with the pipeline.
  **Bounded and fail-closed:** the schema-defining VC's *own* `credentialSchema` (the
  meta-schema) is not re-fetched, so a hostile chain of schema-VCs cannot loop; a `digestSRI`
  on the entry is enforced over the exact VC bytes before any parse/verify; the inner VC must
  actually carry the `JsonSchemaCredential` type, so a signature-valid but wrong-typed VC
  cannot stand in as the schema authority; and any inner-proof failure surfaces as a typed
  `SchemaResolutionError`. Previously such an entry raised `UnsupportedSchemaType`. Behind the
  `[schema]` extra; remote `$ref` resolution stays off.
  ([#28](https://github.com/luisgf/openvc/issues/28))

## [1.7.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Optional observability — stdlib logging + an injectable span hook.** New
  `openvc.observability`: a `logging.getLogger("openvc")` that emits structured events at
  the **resolve / fetch / status / verify** boundaries, plus `span()` / `set_span_hook()`
  — a no-op-by-default tracing hook an integrator wires to OpenTelemetry in one line
  (`set_span_hook(lambda name, attrs: tracer.start_as_current_span(name, attributes=attrs))`).
  Both are **off by default and dependency-free**: the logger carries only a `NullHandler`
  (so `import openvc` prints nothing until the app attaches a handler and lowers the level),
  and the hook is a no-op until installed — no tracing dependency enters core. Events and
  span attributes carry **public identifiers only** (format, issuer/subject DID, the DID or
  URL host, a check's outcome); private-key material, token bytes, `proofValue`, SD-JWT
  disclosures and claim contents are **never** logged. **Observability never changes a
  verification outcome:** a hook that errors — or one that tries to suppress an exception —
  can neither break a verification nor turn a fail-closed check (e.g. an unreachable status
  list) into a fail-open one. ([#25](https://github.com/luisgf/openvc/issues/25))

## [1.6.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Batch verification API.** New `openvc.verify_many(credentials, …)` verifies a list of
  credentials in one call, resolving each distinct issuer DID / status list / schema /
  issuer-metadata URL **once** — roughly O(distinct issuers), not O(credentials) — via
  the per-call caches of the new `openvc.cache.batch_resolvers`. Each credential is
  verified **independently and fail-closed**: a failure in one (bad signature, revoked,
  unresolvable key, …) becomes that item's `error` and never aborts the others. Returns a
  `BatchResult` (`index` / `ok` / `result` / `error`) per input credential, in order. The
  **VP-JWT cascade** now reuses the same dedup, so a presentation whose embedded
  credentials share an issuer resolves that DID once instead of once per credential — while
  staying fail-fast (a VP is valid only if every credential is). Composes with the core TTL
  cache ([#23](https://github.com/luisgf/openvc/issues/23)); no new dependency.
  ([#24](https://github.com/luisgf/openvc/issues/24))

### Fixed

- **`parse_status_entries` fails closed on a hostile `credentialStatus.type`.** A signed
  credential whose status entry's `type` was a non-iterable or a list carrying an
  unhashable member (e.g. `[{…}]`) raised a bare `TypeError` from the set intersection —
  escaping the `OpenvcError` contract (and, in `verify_many`, aborting the whole batch
  instead of failing that one credential). Such a `type` is now filtered to its string
  members and skipped like any unrecognized type. (Found in the #24 adversarial review.)

## [1.5.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **Core TTL cache for the resolution paths.** New `openvc.cache` — a thread-safe,
  bounded, pure-stdlib `TtlCache` plus two opt-in wrappers: `CachingDidResolver` (memoizes
  `resolve(did)` — skipping the `did:web` round-trip on a batch from one issuer) and
  `cached_resolve` (wraps any `resolve_status_list` / `resolve_credential_schema` / fetch
  `Callable[[str], …]`). Only successful results are cached — a transient failure is
  retried, never pinned. **Freshness is a security property for status:** a cached status
  list cannot see a revocation until it expires, so `cached_resolve` defaults to a short
  TTL (`DEFAULT_STATUS_TTL_S = 60s`) while DID docs tolerate a longer one
  (`DEFAULT_DID_TTL_S = 300s`). Caching stays opt-in (the pipeline default resolves
  uncached, like the guarded resolvers). The thread-safe `TtlCache` that previously lived
  only in `openvc_ebsi.http` is now this core primitive, which the EBSI client consumes
  downward. No new dependency. ([#23](https://github.com/luisgf/openvc/issues/23))

## [1.4.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **`ecdsa-rdfc-2019` Data Integrity cryptosuite (whole-document ECDSA over RDF).** New
  `openvc.proof.di_ecdsa_rdfc.EcdsaRdfcProofSuite` — the ECDSA analogue of
  `eddsa-rdfc-2022`: same RDF N-Quads canonicalization (RDFC-1.0 / URDNA2015 via `pyld`)
  and config-first `hashData`, but signs **P-256/SHA-256** (ES256) or **P-384/SHA-384**
  (ES384) — raw R‖S, multibase `proofValue` — the digest chosen by the key's curve,
  reusing the multi-curve ECDSA handling built for `ecdsa-jcs-2019`. Wired into the
  `verify_credential` pipeline (`detect_format` → `data-integrity:ecdsa-rdfc-2019`).
  Behind the `[data-integrity]` extra (needs `pyld`, unlike the JCS suite). Pinned to the
  W3C *vc-di-ecdsa* `TestVectors/ecdsa-rdfc-2019-p256` and `…-p384` golden vectors: both
  SHA-256/384 `hashData` halves reproduce the published hex and each published
  `proofValue` verifies end to end via `did:key` (ECDSA is randomised, so — like
  `ecdsa-sd-2023` — interop is shown by matching intermediates and verifying reference
  proofs, not a byte-for-byte re-sign). ([#48](https://github.com/luisgf/openvc/issues/48))

## [1.3.0] — 2026-07-07

Part of the [post-1.0 — Breadth](https://github.com/luisgf/openvc/milestone/4) milestone.

### Added

- **P-384 signing (ES384) + P-384 on the `ecdsa-jcs-2019` cryptosuite.** New
  `openvc.keys.P384SigningKey` (ES384 — raw R‖S 96 bytes over SHA-384), and `ES384` is
  now on the JOSE allow-list beside `ES256` / `EdDSA` — a **deliberate** widening;
  `RS*` / `HS*` / `alg:none` stay rejected before any crypto. The whole-document
  `EcdsaJcsProofSuite` (`ecdsa-jcs-2019`) is now curve-flexible: **P-256/SHA-256**
  (ES256) or **P-384/SHA-384** (ES384), the digest chosen by the key's curve. `did:key`
  resolution gains the P-384 multicodec (`0x1201`, `z82…`). Pinned byte-for-byte to the
  W3C *vc-di-ecdsa* Recommendation §A.6 P-384 `ecdsa-jcs-2019` example (both SHA-384
  hashes reproduced and its published **high-S** signature verified via `did:key`).
  The RDF `ecdsa-rdfc-2019` suite is a follow-up
  ([#48](https://github.com/luisgf/openvc/issues/48)).
  ([#22](https://github.com/luisgf/openvc/issues/22))

## [1.2.0] — 2026-07-07

Completes the [1.1 — EUDI verifier interop](https://github.com/luisgf/openvc/milestone/3)
milestone: HAIP `direct_post.jwt` response decryption and SD-JWT VC Type Metadata, plus
the recorded OpenID4VP/HAIP conformance drift alarm.

### Added

- **SD-JWT VC Type Metadata (verifier side).** New `openvc.type_metadata` with
  `validate_type_metadata(payload, *, vct, vct_integrity, resolve)` — resolves the Type
  Metadata a credential's `vct` points to (draft-ietf-oauth-sd-jwt-vc-17 §4), pins it
  with `vct#integrity` (a W3C Subresource-Integrity hash over the raw bytes), enforces
  `metadata.vct == credential.vct`, walks the `extends` chain (parent-before-child, each
  integrity-pinned, cycle-/depth-bounded), composes the inherited claim metadata, and
  validates the processed payload against it — the DCQL-style `path` engine plus
  `mandatory`. Fetch is opt-in (`openvc.resolvers.default_type_metadata_resolver`, over
  the SSRF-guarded https fetch) and every failure is fail-closed. Reuses the reviewed
  digestSRI check and the JSON-fetch guards from the `credentialSchema` work.
  (Scope note: the draft removed embedded JSON Schema in draft-12, so validation is via
  the `claims` array, not a JSON Schema; the per-claim `sd` constraint needs disclosure
  provenance and is a documented non-goal.) Pinned to the draft-17 Appendix B.2 worked
  example. ([#21](https://github.com/luisgf/openvc/issues/21))
- **Decrypt HAIP / OpenID4VP 1.0 encrypted responses (`direct_post.jwt`).** New
  `openvc.jwe` with `decrypt_compact(token, *, key)` — a **decrypt-only** JWE Compact
  path for the JWE that wraps a `vp_token` in a HAIP response. Exactly the
  HAIP-mandated shape is accepted, **allow-listed before any crypto**: direct
  `ECDH-ES` key agreement (empty encrypted key) + `A128GCM` / `A256GCM` content
  encryption over an ephemeral **P-256** key. The ECDH runs through a new
  `openvc.keys.KeyAgreementKey` backend (`P256KeyAgreementKey`), mirroring
  `SigningKey` so the recipient's private half can live in an HSM/Vault; the public
  NIST SP 800-56A Concat KDF (RFC 7518 §4.6) and AES-GCM decrypt are done in-library.
  `openvc.openid4vp.verify_encrypted_vp_response(...)` (also `openvc.verify_encrypted_vp_response`)
  bridges it to [#18](https://github.com/luisgf/openvc/issues/18): decrypt then verify
  the `vp_token` with the same `nonce` / `client_id` binding. Pinned byte-for-byte to
  RFC 7518 Appendix C (the Concat KDF), a real OpenID4VP 1.0 §8.3 `ECDH-ES`+`A128GCM`
  JWE, and the RFC 7520 §5.5 key agreement; fails closed on a disallowed `alg`/`enc`,
  an off-curve or non-P-256 ephemeral key, a bad shape, or a failed tag.
  ([#19](https://github.com/luisgf/openvc/issues/19))

## [1.1.0] — 2026-07-07

The first slice of the [1.1 — EUDI verifier interop](https://github.com/luisgf/openvc/milestone/3)
milestone: OpenID4VP 1.0 `vp_token` verification and the pyld-free JCS Data Integrity
cryptosuites. The remaining milestone items (HAIP JWE-response decryption, SD-JWT VC
Type Metadata) land in later releases.

### Added

- **OpenID4VP 1.0 `vp_token` verification (stateless).** New `openvc.openid4vp` with
  `verify_vp_token(vp_token, *, dcql_query, nonce, client_id, …)` (also exported as
  `openvc.verify_vp_token`) — a read/verify-only verifier for the presentation half of
  OpenID for Verifiable Presentations 1.0 (Final, 2025-07-09). It validates the
  response shape (a JSON object keyed by DCQL Credential Query `id`, values are arrays
  — §8.1), routes each Presentation to the matching suite by `format` (`dc+sd-jwt`
  SD-JWT VC + KB-JWT, and `jwt_vc_json` W3C VP-JWT), and enforces the holder binding:
  the transaction `nonce` and the **full, prefixed** Client Identifier as the audience
  (e.g. `x509_san_dns:client.example.org`, not the bare host — §14.2 / §15.11). It
  builds no Authorization Request and keeps no session; `ldp_vc` / `mso_mdoc` raise a
  typed `UnsupportedPresentationFormat` (follow-ups, not silently skipped), and any
  binding/shape failure fails closed. Adversarially reviewed — the format is pinned to
  the query's DCQL `format` so a VC-JWT cannot be smuggled under a `dc+sd-jwt` query to
  skip the KB-JWT nonce binding (a cross-session replay), and every hostile
  `vp_token`/`dcql_query` shape raises a typed error.
  ([#18](https://github.com/luisgf/openvc/issues/18))
- **JCS Data Integrity cryptosuites — `eddsa-jcs-2022` and `ecdsa-jcs-2019`.** A
  whole-document Data Integrity path that canonicalizes with **RFC 8785 JSON
  Canonicalization Scheme** instead of RDF N-Quads, so it needs **no `pyld`** — the
  hand-rolled canonicalizer (`openvc.proof._jcs`) is pure stdlib, including a
  correct ECMAScript `Number.prototype.toString` serializer and UTF-16 code-unit
  member ordering. New `openvc.proof.di_jcs` exposes `EddsaJcsProofSuite` (Ed25519)
  and `EcdsaJcsProofSuite` (ECDSA P-256 / SHA-256); the verify pipeline
  (`verify_credential`) detects and dispatches both. The canonicalizer is pinned
  byte-for-byte to the WebPKI/cyberphone RFC 8785 reference suite and the RFC 8785
  Appendix B number table, and the `eddsa-jcs-2022` suite is pinned to the W3C
  *Data Integrity EdDSA Cryptosuites v1.0* Recommendation worked example (both
  SHA-256 hashes reproduced, and its published Ed25519 `proofValue` verified end to
  end via `did:key`). Verification **fails closed** on hostile input — non-finite
  numbers (`json` accepts `NaN`/`Infinity` by default), deeply-nested documents, a
  cross-curve verification key, or a wrong-length signature all raise a typed
  `ProofError`, never a bare exception — hardened after an adversarial review and a
  differential number-serialization fuzz against the reference oracle. The RDF
  `eddsa-rdfc-2022` / `ecdsa-sd-2023` suites are unchanged.
  ([#17](https://github.com/luisgf/openvc/issues/17))

## [1.0.1] — 2026-07-07

### Security

- **Fail closed on hostile ecdsa-sd CBOR proof values.** `decode_cbor` — which
  parses attacker-controlled proof-value bytes — raised a bare `UnicodeDecodeError`
  on a text string of invalid UTF-8, and a `TypeError` on a map with an unhashable
  (map/list) key; both now fail closed as `ProofValueMalformed`. Uncovered by new
  property-based fuzzing of the hand-rolled codecs (CBOR, base58btc/multibase,
  bitstring, token status list) that asserts decode never raises outside the typed
  `OpenvcError` family, plus an explicit MUST-REJECT corpus (behind the `hypothesis`
  dev dependency). ([#11](https://github.com/luisgf/openvc/issues/11))

## [1.0.0] — 2026-07-07

The first stable release — a frozen, documented public surface. This heading
accumulates the [1.0 — Stabilize](https://github.com/luisgf/openvc/milestone/2)
milestone; it ships once that work is complete.

### Added

- **Demarcated public API surface.** Every public module now declares an explicit
  `__all__` — the frozen, SemVer-protected surface toward 1.0. The two signing
  backends and the `SigningKey` protocol join the package root
  (`from openvc import Ed25519SigningKey, P256SigningKey, SigningKey`, alongside
  `verify_credential` & co.). The shared policy errors (`CredentialExpired`,
  `ProofPurposeMismatch`, …) now have a canonical home in `openvc.proof.errors`
  (re-exported from `_verify_common` and the suites for back-compat), so the whole
  proof-error taxonomy imports from one place. `docs/CONVENTIONS.md` gains a
  "Public surface & stability" section documenting where to import stable names and
  which paths are internal. ([#6](https://github.com/luisgf/openvc/issues/6))
- **Frozen return-object contract.** `VerificationResult`, `VerificationPolicy` and
  the per-suite `Verified*` dataclasses now have their field set pinned as public,
  **add-only** API (a `tests/test_return_contract.py` drift alarm asserts the exact
  fields): a field may be added with a default, never removed/renamed/reordered
  without a major bump. Documented in CONVENTIONS.md.
  ([#7](https://github.com/luisgf/openvc/issues/7))
- **Versioning & deprecation policy** (`docs/versioning.md`) — a published SemVer
  contract: what MAJOR/MINOR/PATCH mean, what the stability guarantee covers (the
  `__all__` surface + the return-object contract), and the deprecation cycle
  (`DeprecationWarning` + a CHANGELOG note for ≥1 minor before removal at a major).
  ([#8](https://github.com/luisgf/openvc/issues/8))
- **`credentialSchema` `digestSRI` is enforced** (`openvc.schema`) — when a
  credential pins its schema with a `sha256-`/`sha384-`/`sha512-` subresource-
  integrity hash, the hash is verified over the raw schema bytes (constant-time,
  strongest algorithm wins) **before** the schema is parsed; a mismatch fails closed.
  An issuer can thus pin the exact schema so even a compromised schema host cannot
  swap it. A guarded `openvc.fetch.https_bytes_fetch` backs it.
  ([#10](https://github.com/luisgf/openvc/issues/10))
- **Threat model** (`docs/threat-model.md`) — assets (the verify decision, signing
  keys, trust anchors), trust boundaries (the credential, network dereferences, the
  SigningKey backend, injected resolvers), and an attacker-capability → control map
  (alg-confusion, issuer impersonation, SSRF, decompression bomb, replay, temporal,
  selective-disclosure) for audit readiness. ([#16](https://github.com/luisgf/openvc/issues/16))
- **Stricter typing of the shipped surface** — mypy now enforces
  `disallow_untyped_defs` / `disallow_incomplete_defs` / `no_implicit_optional`, and
  the remaining annotation gaps are filled, so a downstream type-checker consuming
  openvc's `py.typed` annotations is not degraded.
  ([#15](https://github.com/luisgf/openvc/issues/15))
- **Docstrings on the frozen surface** — the remaining undocumented public names
  (the `SigningKey` protocol + backends and their methods, the `ecdsa_sd` codec
  functions, the DID resolver/registry) now carry a one-line docstring, so the
  generated API reference is complete. ([#14](https://github.com/luisgf/openvc/issues/14))

### Changed

- **BREAKING: `resolve_credential_schema` now returns `bytes`**, not a parsed
  ``dict`` — so a `credentialSchema.digestSRI` can be verified over the exact
  response before parsing. The blessed `openvc.resolvers.default_credential_schema_resolver`
  is updated; a custom schema resolver must return the raw bytes.
  ([#10](https://github.com/luisgf/openvc/issues/10))
- **BREAKING: unified proof-error taxonomy** (openvc.proof.errors). `ProofError`
  moved out of the `openvc.proof.vc_jwt` format module into a new
  `openvc.proof.errors` module (still re-exported from `vc_jwt` for now), and the
  leaf errors that mean the same thing across suites — `SignatureInvalid`,
  `ProofMalformed`, `UnsupportedCryptosuite` (and `UnsupportedAlgorithm`,
  `MalformedToken`, `ClaimsInvalid`) — are now **single shared classes** there
  instead of one-per-suite, so `except SignatureInvalid` (imported from any suite
  path) catches whichever suite raised it. The suite roots `SdJwtError`,
  `EcdsaSdError` / `ProofValueMalformed` and `DataIntegrityError` stay for genuinely
  suite-specific failures. **Migration:** `except ProofError` and
  `except SignatureInvalid` are unaffected; `except DataIntegrityError` /
  `except EcdsaSdError` no longer catch a signature or proof-malformed failure (those
  are now shared under `ProofError`) — catch `ProofError` or the specific leaf.
  ([#4](https://github.com/luisgf/openvc/issues/4))

### Deprecated

- **Verb-last `openvc.proof.ecdsa_sd` codec names.** `cbor_encode`/`cbor_decode`,
  `serialize_base_proof`/`parse_base_proof` and
  `serialize_derived_proof`/`parse_derived_proof` are now deprecated aliases of the
  verb-first `encode_cbor`/`decode_cbor`, `encode_base_proof`/`decode_base_proof` and
  `encode_derived_proof`/`decode_derived_proof`. Accessing a deprecated name now
  emits a `DeprecationWarning`; they are removable at the next major.
  ([#5](https://github.com/luisgf/openvc/issues/5))

## [0.9.0] — 2026-07-06

### Added

- **Blessed SSRF-guarded default resolvers** (`openvc.resolvers`) — the status and
  schema fetch paths in `verify_credential` are caller-injected, so `openvc.fetch`'s
  SSRF guard protected them only if the integrator wired it. New factories make the
  secure path the easy path: `default_credential_schema_resolver`,
  `default_status_list_resolver` (W3C Bitstring) and `default_status_list_token_resolver`
  (IETF) fetch through the guarded https fetch and, for status, **verify** the fetched
  list through the pipeline before trusting it (a fetched-but-unverified status list
  would let a forged one clear revocation). A companion `openvc.fetch.https_text_fetch`
  adds a guarded text fetch for the JWS-shaped status resources. A custom resolver
  still opts out of the guard (documented in SECURITY.md).
  ([#3](https://github.com/luisgf/openvc/issues/3))

## [0.8.1] — 2026-07-06

### Security

- **Bounded status-list decompression (compression-bomb defense)** — `decode_bitstring`
  (gzip) and `decode_status_list` (zlib) now cap the decompressed output at 16 MiB and
  fail closed with `StatusListError` instead of inflating unbounded. A status list is
  fetched from an issuer-named URL through a **caller-injected** resolver, so
  `openvc.fetch`'s 1 MiB wire cap never protected this path (and that cap is on the
  *compressed* size); a ~1 KB `encodedList` / `lst` could inflate to gigabytes and OOM
  the verifier during the routine revocation check every credential's status
  dereferences. Decode now reads incrementally and never materialises past the ceiling.
  ([#2](https://github.com/luisgf/openvc/issues/2))

## [0.8.0] — 2026-07-06

### Added

- **`credentialSchema` validation (W3C VC JSON Schema)** (`openvc.schema`) — the
  verification pipeline can now validate a credential against the JSON Schema it
  declares. Pass `resolve_credential_schema=` to `verify_credential` (e.g.
  `openvc.fetch.https_json_fetch`) and each declared `JsonSchema` is fetched and the
  whole credential validated against it; a mismatch raises `SchemaValidationError`.
  It is **opt-in** — schema conformance is a data-shape check, not a revocation gate
  — so it runs only when a resolver is supplied; set
  `VerificationPolicy.require_schema=True` to reject a credential that *declares* a
  schema but is verified without one (symmetric with `require_status`). Once opted
  in, every sub-step is fail-closed: an unreachable schema, a resource that is not a
  valid JSON Schema, a resource without `$schema` (which the spec says MUST NOT be
  processed), or an unsupported type all raise. The JSON Schema processor is the new
  optional `[schema]` extra (`jsonschema>=4.18`), imported lazily; without it a
  credential that needs validation raises `SchemaBackendUnavailable`. Remote `$ref`
  resolution is off — a non-fetching `referencing` registry is wired, so a remote
  `$ref` fails closed with no network call instead of letting `jsonschema` fetch an
  attacker-named URL (SSRF). `JsonSchemaCredential` is recognised but raises
  `UnsupportedSchemaType` for now. Schemas are untrusted input: `pattern` keywords
  run on Python's backtracking regex, so point `resolve_credential_schema` at hosts
  you trust (documented in `openvc.schema`).

## [0.7.1] — 2026-07-06

### Fixed

- **Signing a VC-JWT for a credential without an `id` no longer emits a null `jti`**
  (which RFC 7519 / PyJWT reject on verification), so an id-less credential now
  round-trips.
- **`VpJwtProofSuite.verify` defaults its resolver** to the offline
  `did:key`/`did:jwk` + SSRF-guarded `did:web` registry (like `verify_credential`),
  instead of requiring a resolver when the holder key is not pinned.

## [0.7.0] — 2026-07-06

### Added

- **Presentation binding for Data Integrity** (`challenge` / `domain`).
  `DataIntegrityProofSuite.add_proof` accepts `challenge=` / `domain=` (for an
  `authentication`-purpose proof), and `verify` enforces them via
  `expected_challenge=` / `expected_domain=` (domain may be a string or a list),
  binding a presentation proof to a verifier session against replay. Both are part
  of the signed proof config, so they are tamper-proof.
- **VP-JWT holder presentations** (`openvc.proof.vp_jwt`) — a holder wraps
  credentials in a `vp` object and signs it, binding the presentation to a verifier
  (`aud`) and a one-time challenge (`nonce`). `VpJwtProofSuite.verify` checks the
  holder signature and temporal claims, enforces `aud`/`nonce` (replay protection),
  and **cascade-verifies every embedded credential** through
  `verify_credential` — so a presentation is accepted only when the holder is
  authentic and each credential in it verifies. The holder key is resolved via an
  injected resolver or pinned.
- **Library-wide `OpenvcError` root** (`openvc.errors`). Every error openvc raises
  now descends from `OpenvcError`, so one `except OpenvcError` catches any openvc
  failure; the EBSI plugin's errors share an `EbsiError` root (itself an
  `OpenvcError`). Purely additive — the per-area roots (`ProofError`, `DidError`,
  `StatusListError`, `VerificationError`, …) and every specific error still exist
  and are still catchable individually.

### Security

- **SD-JWT temporal check fails closed on a malformed `exp`/`nbf`.** A present but
  non-numeric `exp`/`nbf` was silently skipped; it now raises `ClaimsInvalid`,
  matching the Data Integrity and status-list temporal checks (a NumericDate per
  RFC 7519).

## [0.6.0] — 2026-07-06

### Added

- **`did:jwk` resolver** (`openvc.did.did_jwk`) — the self-contained method whose
  identifier is a base64url-encoded public JWK (common in EUDI / OID4VC stacks).
  Offline like `did:key`; a `did:jwk` encoding a private key (with `d`) is refused.
  Registered in the pipeline's `default_resolver`, so `verify_credential` resolves
  `did:jwk` issuers out of the box.
- **HTTPS issuer-key discovery** (`openvc.jwt_vc_issuer`) — for a JOSE credential
  whose `iss` is an https URL, the issuer's signing key is resolved from
  `/.well-known/jwt-vc-issuer` (draft-ietf-oauth-sd-jwt-vc), verifying the
  metadata's `issuer` equals the `iss` (anti-substitution), supporting inline
  `jwks` or a `jwks_uri`, and selecting the key by `kid`. Opt-in in the pipeline
  via `verify_credential(..., jwt_vc_issuer_fetch=https_json_fetch)` (pass the
  SSRF-guarded fetch); an https issuer without it fails closed. Private keys in the
  JWKS are refused.
- **X.509 `x5c` issuer trust** (`openvc.x5c`) — for a JOSE credential whose header
  carries an `x5c` certificate chain (eIDAS / EUDI document signers), validate the
  chain to caller-provided trust anchors and return the leaf's key. Path validation
  (signatures, validity, `basicConstraints`) is done by `cryptography`'s X.509
  verifier; only the TLS EKU is relaxed. The `iss` must be bound to the leaf via its
  Subject Alternative Name (URI or DNS-host match), closing a forge-any-issuer gap.
  Only an EC P-256 leaf is accepted. Opt-in in the pipeline via
  `verify_credential(..., x5c_trust_anchors=[roots])`.

### Changed

- **Minimum `cryptography` is now `>=45`** (was `>=42`) for the X.509
  path-validation `ExtensionPolicy` the `x5c` verifier relies on.

## [0.5.0] — 2026-07-06

### Added

- **Generic verification pipeline** (`openvc.verify`) — one call,
  `verify_credential`, that verifies a credential in any supported format against
  a `VerificationPolicy`, returning a unified `VerificationResult`. It detects the
  format (VC-JWT / SD-JWT VC / Data Integrity `eddsa-rdfc-2022` + `ecdsa-sd-2023` /
  an enveloped VCDM 2.0 credential, which it unwraps), resolves the issuer key via
  a `DidResolverRegistry` (JOSE formats peek the untrusted `iss`/`kid`; Data
  Integrity resolves the proof's `verificationMethod`), verifies through the
  matching suite, and applies policy: expected type(s)/`vct`, audience and
  holder-binding for SD-JWT, `proofPurpose`, and status. Exported from the package
  root (`openvc.verify_credential`). The EBSI glue becomes a specialisation of this
  shape.

### Security

- **Status checking in the pipeline is fail-closed and format-agnostic.** Both
  status conventions — the W3C `credentialStatus` and the IETF token `status`
  reference — are checked for every format, so a status declared in the shape that
  does not match the proof format is not silently skipped. A declared status with
  no resolver raises `StatusUnavailable` (opt out with `require_status=False`); a
  resolved *revoked* status raises `CredentialRevoked` and a *suspended* one the
  new `CredentialSuspended`.
- **Data Integrity issuer binding.** The pipeline accepts an embedded-proof
  credential only when the proof's `verificationMethod` is controlled by the
  credential's `issuer` (same DID), closing a forge-any-issuer gap where a signer
  could name an arbitrary issuer and sign with their own key (`IssuerBindingError`).
  Delegated cross-DID trust remains the job of a specialised verifier
  (`verify_ebsi_badge`).

## [0.4.0] — 2026-07-06

### Security

- **Data Integrity proofs now enforce the credential's validity window.** Both
  cryptosuites (`eddsa-rdfc-2022`, `ecdsa-sd-2023`) verified only the signature,
  so a signed-but-**expired** credential — or one not yet valid — verified as
  valid. `verify()` now checks `validFrom`/`validUntil` (VCDM 2.0) and
  `issuanceDate`/`expirationDate` (VCDM 1.1), plus the proof's optional
  `expires`, against the current time within a 60 s default leeway. **Behaviour
  change:** credentials outside their validity window that used to pass will now
  raise `CredentialExpired` / `CredentialNotYetValid`. A new `now=` parameter
  pins the evaluation instant (deterministic conformance / "as of" audits), and
  the leeway is configurable via the suite constructor (`leeway_s=`). A
  present-but-unreadable timestamp **fails closed** (`MalformedTimestamp`)
  instead of being skipped, and fractional seconds of any precision parse
  correctly (older Python's stricter `fromisoformat` no longer causes a silent
  expiry bypass). This brings Data Integrity to parity with the VC-JWT / SD-JWT
  suites, which already enforced `exp`/`nbf`.
- **Data Integrity proofs now enforce `proofPurpose` and DID
  verification-relationship binding.** `verify()` requires the proof's
  `proofPurpose` to match an expected value (default `assertionMethod`), and —
  when the key is resolved from a DID document rather than an injected JWK — that
  the `verificationMethod` is actually authorized by the document for that
  purpose. A `did:web` document that separates an assertion key from an
  authentication key now rejects a proof signed by the wrong one, instead of
  accepting any key it lists.

### Added

- **Injectable DID resolver for Data Integrity verification.** `verify()` takes a
  `resolver=` (a `DidResolver` / `DidResolverRegistry`), so `did:web` (and any
  registered method) now works with embedded proofs; offline `did:key` remains
  the no-argument fallback. `DidDocument` now captures the W3C verification
  relationships (`assertionMethod`, `authentication`, …) via `key_for_purpose`.
- **Status-list issuance** (`openvc.status`) — the issuer-side counterpart to the
  existing check side, so an issuer can revoke using only openvc.
  `build_status_list_credential` assembles an (unsigned) W3C
  `BitstringStatusListCredential` to sign with any suite;
  `build_status_list_token` / `verify_status_list_token` build and verify an IETF
  status-list token (`typ: statuslist+jwt`); `build_status_list_entry` and
  `build_token_status_reference` produce the pointer each issued credential/token
  carries; and `new_bitstring` allocates a zeroed W3C list (mirroring
  `new_status_list`). Round-trip tested both ways — build → sign → revoke an index
  → the check detects it — for VC-JWT and Data Integrity issuance.
- **Generic compact-JWS signer** (`openvc.proof._jws`) — the compact-JWS assembly
  was lifted out of `VcJwtProofSuite.sign` into `sign_compact` / `verify_compact`
  / `parse_compact`, so a non-VC token (the status-list token) signs through the
  same allow-listed `{ES256, EdDSA}` `SigningKey` path. `VcJwtProofSuite.sign` now
  delegates to it; its output is byte-for-byte unchanged.

## [0.3.1] — 2026-07-05

### Added

- **ecdsa-sd-2023 is now interop-validated against the official W3C `vc-di-ecdsa`
  test vectors** (`tests/fixtures/ecdsa_sd/`): `verify` accepts reference-produced
  derived proofs, and the issuer-side HMAC-relabeled canonical N-Quads and the
  `proofHash` / `mandatoryHash` match the recorded intermediates byte for byte.
  No code change from 0.3.0 — this ships the validation and drops the
  "interop pending" caveat from the docs (ECDSA is randomised, so interop is
  shown this way rather than by reproducing a fixed proof value).

## [0.3.0] — 2026-07-05

### Added

- **ecdsa-sd-2023 selective disclosure** (`openvc.proof.ecdsa_sd`) — the second
  Data Integrity cryptosuite (P-256) and the first with selective disclosure.
  `EcdsaSdProofSuite` covers the whole flow: an issuer `add_base_proof`
  (per-statement signatures under an ephemeral key, mandatory statements bound by
  the issuer key, HMAC-blinded blank nodes), a holder `derive_proof` (reveal only
  the chosen JSON pointers), and `verify`. The proof value is a hand-rolled CBOR
  blob checked against RFC 8949 — no new dependency. Round-trip and
  tamper/over-disclosure tested; byte-level interop against the official W3C
  vectors is tracked as a follow-up (ECDSA is randomised, so — unlike
  eddsa-rdfc-2022 — correctness cannot be shown by reproducing a fixed value).

## [0.2.1] — 2026-07-05

### Fixed

- **EBSI DID resolution and the TIR trust chain now work against the real v5
  API.** The HTTP client accepted only `application/json`, which the DID Registry
  rejects with `406` (it content-negotiates `application/did+ld+json`); it now
  accepts both. The TIR v5 adapter also read the accreditation from the wrong
  place — the signed body is nested under `attribute.body`, and
  `issuerType`/`tao`/`rootTao` sit on the `attribute` wrapper (not the
  `credentialSubject`, whose `accreditedFor` is a list of `{schemaId, types}`
  objects rather than type strings). Both were caught by new golden fixtures
  recorded verbatim from the pilot registry (`tests/fixtures/ebsi/`).

## [0.2.0] — 2026-07-05

### Added

- **IETF Token Status List** (`openvc.status.token_status_list`) — the second
  status-list encoding, behind the same `openvc.status` interface as the W3C
  Bitstring list: multi-bit statuses (1/2/4/8 bits, LSB-first) with DEFLATE/zlib
  compression, `status`-claim reference parsing, and `check_token_status`
  (VALID / INVALID → revoked / SUSPENDED → suspended) over an injected resolver.
- **SD-JWT VC** (`openvc.proof.sd_jwt`) — the third proof profile (the format
  EUDI/ARF converges on), alongside VC-JWT and Data Integrity. `SdJwtVcProofSuite`
  covers issuance (salted disclosures + `_sd` digests, decoys, `cnf` holder
  binding), holder presentation (a Key Binding JWT over `aud` / `nonce` /
  `sd_hash`), and verification (recursive unpacking of nested + array disclosures
  with the algorithm allow-list and unreferenced/duplicate/overwrite defences). A
  verified credential's `status` claim is checked via the Token Status List. Pure
  JOSE — no new dependency.

## [0.1.0] — 2026-07-05

First public release: a generic, HSM-friendly Verifiable Credentials core with an
optional read-only EBSI plugin.

### Added

- **Core** — VC-JWT proof suite (`VcJwtProofSuite`: peek / verify / sign) with a
  fixed `{ES256, EdDSA}` algorithm allow-list checked before any crypto;
  `Ed25519SigningKey` / `P256SigningKey` backends behind a `SigningKey` protocol
  (HSM/Vault drop-in; correct JOSE raw `R‖S` for ES256).
- **DID resolution** — `did:key` (offline), `did:web` (with an SSRF- and
  DNS-rebinding-safe stdlib fetch that pins the connection to the validated IP),
  the W3C DID-document model, resolver protocol and registry.
- **Data Integrity proof suite** — `eddsa-rdfc-2022` embedded proofs
  (`DataIntegrityProofSuite`), RDF canonicalization via `pyld`, offline bundled
  JSON-LD contexts; reproduces the official W3C vc-di-eddsa test vector byte for
  byte. Behind the `[data-integrity]` extra.
- **Status list** — W3C Bitstring Status List revocation/suspension
  (`openvc.status`): the bit codec plus `credentialStatus` parsing and checking.
- **EBSI plugin** (read-only, `[ebsi]` extra) — versioned DID Registry / TIR
  adapters, an HTTP client (TTL cache, status-aware retries, https-only host
  allow-list), the `verify_ebsi_badge` glue, and a recursive `TI → TAO → RootTAO`
  trust chain that verifies each accreditation's signature, enforces per-hop
  delegation scoping, and (optionally) status-list-checks the accreditations.

### Packaging

- PEP 561 typed (`py.typed`), single-source `openvc.__version__`, PEP 639 SPDX
  license metadata (LGPL-3.0-or-later). Core install depends only on
  `cryptography` + `pyjwt`; `httpx` and `pyld` are optional extras.
- Published on PyPI as the **`openvc-core`** distribution; the import package
  stays `openvc` (`pip install openvc-core`, then `import openvc`).

[1.32.2]: https://github.com/luisgf/openvc/releases/tag/v1.32.2
[1.32.1]: https://github.com/luisgf/openvc/releases/tag/v1.32.1
[1.32.0]: https://github.com/luisgf/openvc/releases/tag/v1.32.0
[1.31.3]: https://github.com/luisgf/openvc/releases/tag/v1.31.3
[1.31.2]: https://github.com/luisgf/openvc/releases/tag/v1.31.2
[1.31.1]: https://github.com/luisgf/openvc/releases/tag/v1.31.1
[1.31.0]: https://github.com/luisgf/openvc/releases/tag/v1.31.0
[1.30.5]: https://github.com/luisgf/openvc/releases/tag/v1.30.5
[1.30.4]: https://github.com/luisgf/openvc/releases/tag/v1.30.4
[1.30.3]: https://github.com/luisgf/openvc/releases/tag/v1.30.3
[1.30.2]: https://github.com/luisgf/openvc/releases/tag/v1.30.2
[1.30.1]: https://github.com/luisgf/openvc/releases/tag/v1.30.1
[1.30.0]: https://github.com/luisgf/openvc/releases/tag/v1.30.0
[1.29.2]: https://github.com/luisgf/openvc/releases/tag/v1.29.2
[1.29.1]: https://github.com/luisgf/openvc/releases/tag/v1.29.1
[1.29.0]: https://github.com/luisgf/openvc/releases/tag/v1.29.0
[1.28.2]: https://github.com/luisgf/openvc/releases/tag/v1.28.2
[1.28.1]: https://github.com/luisgf/openvc/releases/tag/v1.28.1
[1.28.0]: https://github.com/luisgf/openvc/releases/tag/v1.28.0
[1.27.1]: https://github.com/luisgf/openvc/releases/tag/v1.27.1
[1.27.0]: https://github.com/luisgf/openvc/releases/tag/v1.27.0
[1.26.0]: https://github.com/luisgf/openvc/releases/tag/v1.26.0
[1.25.0]: https://github.com/luisgf/openvc/releases/tag/v1.25.0
[1.24.0]: https://github.com/luisgf/openvc/releases/tag/v1.24.0
[1.23.1]: https://github.com/luisgf/openvc/releases/tag/v1.23.1
[1.23.0]: https://github.com/luisgf/openvc/releases/tag/v1.23.0
[1.22.0]: https://github.com/luisgf/openvc/releases/tag/v1.22.0
[1.21.0]: https://github.com/luisgf/openvc/releases/tag/v1.21.0
[1.20.4]: https://github.com/luisgf/openvc/releases/tag/v1.20.4
[1.20.3]: https://github.com/luisgf/openvc/releases/tag/v1.20.3
[1.20.2]: https://github.com/luisgf/openvc/releases/tag/v1.20.2
[1.20.1]: https://github.com/luisgf/openvc/releases/tag/v1.20.1
[1.20.0]: https://github.com/luisgf/openvc/releases/tag/v1.20.0
[1.19.3]: https://github.com/luisgf/openvc/releases/tag/v1.19.3
[1.19.1]: https://github.com/luisgf/openvc/releases/tag/v1.19.1
[1.19.0]: https://github.com/luisgf/openvc/releases/tag/v1.19.0
[1.18.0]: https://github.com/luisgf/openvc/releases/tag/v1.18.0
[1.17.0]: https://github.com/luisgf/openvc/releases/tag/v1.17.0
[1.16.0]: https://github.com/luisgf/openvc/releases/tag/v1.16.0
[1.15.0]: https://github.com/luisgf/openvc/releases/tag/v1.15.0
[1.14.0]: https://github.com/luisgf/openvc/releases/tag/v1.14.0
[1.13.1]: https://github.com/luisgf/openvc/releases/tag/v1.13.1
[1.13.0]: https://github.com/luisgf/openvc/releases/tag/v1.13.0
[1.12.0]: https://github.com/luisgf/openvc/releases/tag/v1.12.0
[1.11.1]: https://github.com/luisgf/openvc/releases/tag/v1.11.1
[1.11.0]: https://github.com/luisgf/openvc/releases/tag/v1.11.0
[1.10.0]: https://github.com/luisgf/openvc/releases/tag/v1.10.0
[1.9.0]: https://github.com/luisgf/openvc/releases/tag/v1.9.0
[1.8.0]: https://github.com/luisgf/openvc/releases/tag/v1.8.0
[1.7.0]: https://github.com/luisgf/openvc/releases/tag/v1.7.0
[1.6.0]: https://github.com/luisgf/openvc/releases/tag/v1.6.0
[1.5.0]: https://github.com/luisgf/openvc/releases/tag/v1.5.0
[1.4.0]: https://github.com/luisgf/openvc/releases/tag/v1.4.0
[1.3.0]: https://github.com/luisgf/openvc/releases/tag/v1.3.0
[1.2.0]: https://github.com/luisgf/openvc/releases/tag/v1.2.0
[1.1.0]: https://github.com/luisgf/openvc/releases/tag/v1.1.0
[1.0.1]: https://github.com/luisgf/openvc/releases/tag/v1.0.1
[1.0.0]: https://github.com/luisgf/openvc/releases/tag/v1.0.0
[0.9.0]: https://github.com/luisgf/openvc/releases/tag/v0.9.0
[0.8.1]: https://github.com/luisgf/openvc/releases/tag/v0.8.1
[0.8.0]: https://github.com/luisgf/openvc/releases/tag/v0.8.0
[0.7.1]: https://github.com/luisgf/openvc/releases/tag/v0.7.1
[0.7.0]: https://github.com/luisgf/openvc/releases/tag/v0.7.0
[0.6.0]: https://github.com/luisgf/openvc/releases/tag/v0.6.0
[0.5.0]: https://github.com/luisgf/openvc/releases/tag/v0.5.0
[0.4.0]: https://github.com/luisgf/openvc/releases/tag/v0.4.0
[0.3.1]: https://github.com/luisgf/openvc/releases/tag/v0.3.1
[0.3.0]: https://github.com/luisgf/openvc/releases/tag/v0.3.0
[0.2.1]: https://github.com/luisgf/openvc/releases/tag/v0.2.1
[0.2.0]: https://github.com/luisgf/openvc/releases/tag/v0.2.0
[0.1.0]: https://github.com/luisgf/openvc/releases/tag/v0.1.0
