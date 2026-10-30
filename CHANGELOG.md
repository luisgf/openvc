# Changelog

All notable changes to **openvc** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.38.0] — unreleased

### Security

- **The Trusted Issuers Registry role is an exact allow-list; `Revoked` was read as a live
  role on every lane** ([#358](https://github.com/luisgf/openvc/issues/358)).
  **Wrong-accept of a revoked accreditation, on real registry vocabulary.** Both registry
  APIs render the on-chain issuer type as a name: the legacy TIR API v5 OpenAPI
  (`https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/openapi.json`, `info.version`
  5.0.0) documents `attribute.issuerType` as "RootTAO, TAO, TI, Revoked or Undefined", and
  the EBSI Core API v1 OpenAPI (`/v1/openapi.json` on every node, served with
  `Accept: application/openapi+json`, `info.version` 1.0.0) enumerates `["undefined",
  "RootTAO", "TAO", "TI", "Revoked"]` ("`undefined` (lowercase) is returned for type 0");
  both read 2026-10-30. `Accreditation.is_revoked` compared with the lowercase `revoked`,
  which neither API emits, and nothing checked that the role is one of the three live ones.
  Measured on `main` at b0feaeb (CPython 3.14.10) with real P-256 signatures through
  `evaluate_issuer_trust` and `verify_trust_chain`, on v4, v5 and Core v1 alike: an
  accreditation whose attribute said **`Revoked`** was **trusted**, single-level and
  recursive; so was `undefined` (Core v1's value for an unset type), `Undefined`, an absent
  or empty `issuerType`, `RootTAO ` with a trailing space, `ti`, `Banana`; the only refused
  spelling was `revoked`. And the recursive walk accepted an accreditation signed by an
  accreditor whose own record said **`TI`** (a TI accrediting a TI), or `Revoked`,
  `undefined` or nothing, where EBSI's model lets only a TAO or a RootTAO accredit.
  **What changed.** An accreditation is eligible only if its `issuerType` is exactly
  `RootTAO`, `TAO` or `TI` (`models.TRUST_ROLES`; `Accreditation.has_trust_role`), and the
  accreditation read from an accreditor's record above the leaf only if its role is
  `RootTAO` or `TAO` (`models.DELEGATING_ROLES`; `Accreditation.can_accredit`): everything
  else is set aside, whatever it would authorise (the role rule runs before the type rule, so
  an unrestricted accreditation with a bad role authorises nothing). Nothing is compared
  case-insensitively or trimmed. `models.REVOKED_ROLE` now spells `Revoked`, the value both
  APIs send; `is_revoked` reads it and still reads the pre-1.38 lowercase `revoked`
  (`models.REVOKED_ROLES`). The adapters are unchanged: they copy the string the wire sends,
  and the decision lives in the two policies (`trust._pick_accreditation`,
  `verify.evaluate_issuer_trust`), where a revoked accreditation was already set aside. The
  "has no valid accreditation" messages keep their leading words and gain a bounded clause
  naming the roles set aside (`trust.ineligible_roles_note`: `safe_repr` per value, at most
  three). Not read: the anchor's own record (the caller pins the anchor DID and the walk stops
  at it; a check would cost a request per walk and guard a misconfiguration, not an attack).
  **Migration.** A registry record whose only accreditation carries a role outside the
  vocabulary, which 1.37 trusted, is now `IssuerNotTrusted` / `NoTrustedAnchor` (or
  `trusted=False` under `require_trust=False`); a record built by hand with a lowercase or
  other spelling of a live role must use the registry's exact spelling. The recorded fixtures
  (v5 pilot and Core v1 preprod / prod, all `RootTAO`) verify as before.
  The adversarial review of the PR (38 role spellings through every lane, a 3-hop position
  probe, a 20 000-record differential of the two policies, fail-open sweeps; no wrong-accept
  found) added two small fixes: the non-leaf refusal message now bounds the delegated type
  list with `bounded_text` (with a wildcard leaf accreditation that list is the credential's
  whole `type`, and a 500-type credential made a 1 002 163-character `NoTrustedAnchor` on
  `main`; the TI-above-the-leaf refusals route through that line), and the note de-duplicates
  roles linearly (the v4 inline lane caps no attribute count).
  Tests: `tests/test_ebsi_issuer_type_roles.py` (every lane, both policies, the two-hop
  delegation rule, the mixed record, the bounded messages at the leaf and above it, the model
  predicates; the negatives are TRUSTED on `main` and refused here).

### Changed

- **The `[trustlist]` extra now requires `signxml>=5.2.0`** (was `>=3.2`). signxml 5.2.0
  ([XML-Security/signxml#297](https://github.com/XML-Security/signxml/pull/297), fixing
  [#296](https://github.com/XML-Security/signxml/issues/296), which openvc reported on
  2026-10-14) writes the `ECKeyValue` point at the curve's field width; 5.1.0 and earlier
  dropped a leading zero byte from a short coordinate, so about 2 in 256 random P-256 keys
  produced a `KeyValue` that no longer matched the `X509Data` and signxml's own verifier
  refused the document. Only documents *signed* by signxml were affected, and openvc never
  signs XAdES: nothing in openvc's verify path changes, and a trust list signed by a real TSP
  verified before as it does now. The floor is raised so the test suite no longer has to
  steer around the bug (below), and so a consumer who signs test lists with the same extra
  gets the fixed signer. signxml 5.2.0 asks for Python 3.9 or later, `cryptography>=45` and
  `lxml>=5.2.1,<7`, all inside openvc's own floors. Verified against 5.2.0 before raising the
  floor: short X and short Y coordinates on P-256, P-384 and P-521 through `XMLSigner` and
  `XAdESSigner` give the SEC 1 point byte for byte, and 300 random P-256 keys sign and
  verify with no failure.

### Tests

- `tests/test_trustlist_xades.py`: the `_full_width_p256_key` helper (a key drawn until both
  coordinates filled 32 bytes, the workaround for the signxml bug above) is gone; the
  fixtures take any P-256 key. The file ran ten times in a row against signxml 5.2.0 with
  no failure.

## [1.37.0] — 2026-10-21

### Security

- **The v5 and Core v1 TIR walk reads the accreditation token fail-closed, and the trust walk
  binds every accreditation to the DID it was read for**
  ([#352](https://github.com/luisgf/openvc/issues/352) follow-ups, left open by the review of
  [#354](https://github.com/luisgf/openvc/pull/354), which closed them on the legacy v4 lane
  only). **Wrong-accept, conditional on a registry-side fault**: a registry answer that puts an
  accreditation in the wrong issuer's record (a bug, a steered or stale response, a dishonest
  listed node, which the Trusted Nodes List does not rule out, ADR-0009 D7). `for_nodes`
  defaults to the Core v1 adapters, so this is the production lane, and 1.36.0 on PyPI carries
  it. Measured on `main` at b1fd669 (CPython 3.14.8) with real P-256 signatures through
  `verify_trust_chain`, on v5 and on Core v1 separately, with a LEAF record holding one
  accreditation signed by ROOT, the anchor: (a) the walk read a `credentialSubject` that is not
  an object, a VCDM-legal **array of subjects** included, as `{}`, that is as an accreditation
  with no types, which is the **unrestricted** one; `credentialSubject: [{"id": OTHER,
  "accreditedFor": [OtherType]}]`, signed by ROOT for OTHER and for another type, was **trusted
  for LEAF** for the credential's type, and `"x"`, `7`, `null`, `true` the same; a `vc` that is
  not an object was `AccreditationInvalid` in recursive mode only because the suite's `verify`
  wants a `vc` object, and single-level trust, which verifies no signature, accepted every one of
  these shapes as the unrestricted accreditation. (b) `trust.py` compared the token's subject
  with the accredited DID only `if verified.subject`, so a ROOT-signed accreditation carrying
  neither `sub` nor `credentialSubject.id` was **trusted for LEAF** on every lane, v4 included;
  an **empty `sub`** over a `credentialSubject.id` of OTHER the same (the suite skips its
  `sub` / `id` comparison for an empty `sub` and reports `""`, which is falsy), and so was a
  `credentialSubject.id` of `""` or `7` with no `sub`. (c) the shared flattener dropped an
  `accreditedFor` it did not recognise: a single object, a bare string, `[{"types": ""}]`,
  `[7]`, `[null]`, `[["T"]]` and `[{"types": [7]}]` read as no types and were **trusted for
  every type** (the same accreditation as a list of objects: `NoTrustedAnchor`); `types` of `7`,
  `null`, `true` or `1.5` was a bare `TypeError` out of `issuer_record` and
  `verify_trust_chain`, past the `except EbsiError` of the node client's failover loop; a string
  `types` was split into one-character types. (d) a `body` that is not a compact JWS with a
  JSON-object payload escaped `issuer_record` and `verify_trust_chain` as the proof suite's
  `MalformedToken`, an `OpenvcError` that is not an `EbsiError`, on every lane; a token whose
  header alone is unreadable passed `issuer_record` (`peek_claims` reads the payload) and
  escaped `verify_trust_chain` from `peek_issuer` the same way.

  **What changed.** The token is read by one reader on every lane (`_types_from_token`, the
  #354 checks lifted out of `TirV4`): the claims must be an object, `vc` and `credentialSubject`
  objects when sent, `accreditedFor`, when sent, a list of type strings or objects whose `types`
  is a list of strings, else `MalformedRegistryResponse` with the member and the value (through
  `safe_repr`) in the message, never "no types"; the same shape gives the same message on v4,
  v5 and Core v1. A `body` the suite cannot read is `MalformedRegistryResponse` too, with the
  suite's `MalformedToken` as `__cause__` and its text bounded. In `trust.py` the JWT `sub` and
  the credential's `credentialSubject.id`, each one that is **sent**, must be exactly the
  accredited DID (`""`, `null` and a non-string are sent and wrong, never "absent"), at least
  one of the two must be sent, and a sent `credentialSubject` must be an object; anything else
  is `AccreditationInvalid`, the class the mismatch already had (a bad identity on the path),
  on every lane; that holds **across DIDs**, which is what a replay is (a RootTAO-signed
  credential for the *same* DID that carries no `accreditedFor`, an onboarding authorisation
  say, still reads as the unrestricted accreditation under the policy below). `peek_issuer`'s
  `MalformedToken` is `AccreditationInvalid` with the same `__cause__`. What the suite already
  refused (a `sub` that is not a string, a non-empty `sub`
  that disagrees with a non-empty `credentialSubject.id`) is refused as before, and an
  accreditation that names the accredited DID once (`sub` only, as the VCDM 1.1 JWT encoding
  does, or `credentialSubject.id` only) or twice is accepted as before.

  **Decision: one bad accreditation rejects the whole record** on v5 and Core v1, as on v4
  (the maintainer's 2026-10-20 decision for #352 and the #337 rule): nothing partial is
  returned, and a good accreditation beside a bad one does not close a chain. The walk fetches
  one revision per listing item and reads it as it goes, so it raises at the first malformed
  accreditation it reaches, after the revisions before it were fetched and decoded (v4's "every
  entry's shape before any token is decoded" is not available to a streaming walk); a revision's
  scalars (#337) are typed before its token is decoded, and the token's shape right after.
  **Decision: `MalformedToken` is wrapped.** A caller on `except EbsiError` (the node client's
  loop, anyone following the docs) never saw it and the bare `OpenvcError` escaped; now
  `issuer_record` and `verify_trust_chain` raise `MalformedRegistryResponse` for it, `except
  OpenvcError` still catches it, and only a caller catching `MalformedToken` around those two
  entry points changes. Under `for_nodes` the class is not a node failure (`classify` returns
  `None` for it), so it reaches the caller and is not failed over, like every other malformed
  200. One consequence worth saying: `MalformedRegistryResponse` is not a `TrustChainError`,
  so every shape this closes now raises out of `verify_ebsi_badge` even with
  `require_trust=False`, where `main` returned `trusted=True`; that is the stance #267 took
  (malformed input is not an untrusted issuer, so `require_trust=False` does not suppress it).

  **Found by the adversarial review of the PR** (Opus, runnable repros; all four are small and
  inside this change's surface). (1) `accreditedFor` was checked in one pass and then read by
  the old flattener in a second, so a list handed in by an injected `decode` that iterates
  differently the second time was checked as scoped and read as unrestricted (new on v5 and
  Core v1 with this change, on v4 since #354; a hostile `decode` is caller code and could return
  `{}` anyway): the flattener is gone and `_wire_accredited_for` checks and reads in **one
  pass**, returning the types. (2) The scalar readers (#337) kept a `str` subclass as sent, so a
  `body` from an injected `fetch` whose `.split` answered with another token made `peek_claims`
  read one token while the suite verified another, and a ROOT-signed scoped token read as
  unrestricted (pre-existing on every lane; moot for a hostile `fetch`, which also serves the
  DID documents): every scalar is now an exact `str` (`str.__str__`, as `_require_did_ebsi`
  does), types included. (3) The binding honours `credentialSubject.@id` as it does `id` (what
  `id` aliases in JSON-LD; the suite honours it for `issuer`): sent, it must be the accredited
  DID too. (4) A `credentialStatus` the status module refuses, on a ROOT-signed accreditation
  with `resolve_status_list` given, escaped `verify_trust_chain` as `StatusListError`, an
  `OpenvcError` that is neither an `EbsiError` nor a `TrustChainError` (pre-existing, every
  lane); it is now `AccreditationInvalid` with that error as `__cause__`. The review also
  confirmed, with repros, pre-existing gaps that are **not changed here** because each changes
  what trust means and is the maintainer's call: the leaf and hop type matching intersects the
  credential's whole `type` list with `accreditedFor.types`, and every recorded `accreditedFor`
  starts with `VerifiableCredential`, which every credential also carries, so on real EBSI data
  the intersection is never empty and the delegated scope collapses to the generic types (an
  issuer accredited for `TrustedNodesList` only is trusted for an `OpenBadgeCredential`);
  `issuerType` is compared with the lowercase `revoked` only, never allow-listed against the
  roles, and does not limit delegation (a `TI` can accredit); an accreditor whose DID document
  is a 404 is `HttpNotFound`, an `EbsiError` but not a `TrustChainError`.

  **Not changed.** The four recorded walks (the pilot's v5 response and the three Core v1
  nodes) parse to the same record. `vc`, `credentialSubject` and `accreditedFor` **absent**, an
  empty `accreditedFor`, an entry with no `types` and `"types": []` still read as "no types",
  the unrestricted accreditation: whether an accreditation without `accreditedFor` should deny
  is a policy question, and a ROOT-signed token for the right DID whose `vc` carries no
  `credentialSubject` (one that nests the real one under `vc.vc`, say) is still accepted under
  that policy. A listing item the walk cannot follow (not an object; `href` absent, not a
  string, empty or off the listing's origin) is still **skipped** (#172, #243), not rejected: a
  skipped item drops an accreditation and can only narrow trust (a record left with none is
  `NoTrustedAnchor` / untrusted), where a misread token widens it. Single-level trust still
  verifies no accreditation signature and no binding (its documented policy). Not touched: the
  v4 entry cap, `issuerType` against the trust roles, `verify.py`'s `_credential_types`, the
  dependencies and the public API. (`tests/test_ebsi_tir_walk_shape.py`)
- **The EBSI client's error-body read is bounded on the decoded size, and its cap and
  deadline hold for a body that decodes to nothing**
  ([#350](https://github.com/luisgf/openvc/issues/350); found by the review of
  [#348](https://github.com/luisgf/openvc/pull/348), which bounded the 200 read and left this
  one alone). Resource bound against an allow-listed host, the same class as #335; no
  wrong-accept: the change can lose a Problem Details `type`, never invent one.
  `EbsiHttpClient._read_problem_type` (#321) reads the body of a non-200 answer for its `type`
  with `iter_bytes` and checked its 16 KiB cap after appending, but `iter_bytes` yields a chunk
  httpx has already inflated. Measured on `main` at 3bd9e59 (CPython 3.14.8, httpx 0.28.1,
  `tracemalloc`): a 260 935-byte `gzip` body that inflates to 256 MiB, served as a 403, a 404
  or a 503 (retried three times), peaked at **557 MiB** every time, and the 260 923-byte
  `deflate` one the same; 8 MiB of zeros in about 8 KB, which is under the cap on the wire,
  peaked at 21 MiB as one chunk and at 2.4 MiB in 1 KiB chunks. The loop had a second gap with
  the same cause: a coded body that decodes to *nothing* (a gzip header, then empty stored
  deflate blocks) makes `iter_bytes` yield no chunk, so the loop body that held the cap and the
  deadline never ran for it. Measured: 4 MiB of it was read to the end under the 16 KiB cap,
  and 5 001 chunks were pulled past a deadline that had expired at the first, for as long as
  the host kept sending.

  The body is now read as the 200 path reads it (`_decoder_for` and the raw stream): the wire
  size and the decoded size are each checked against `MAX_ERROR_BODY_BYTES` before a chunk is
  held, one `gzip` or `deflate` coding is decoded with `zlib` asked for at most the room left
  plus one byte, and the deadline is checked for every chunk the wire delivers, whether or not
  it decodes to anything. Past either bound, or past the deadline, the response is closed
  instead of drained, as before. After the change the 256 MiB bombs peak at 0.0 MiB (they are
  over the cap on the wire, so `zlib` never runs), the 8 MiB ones at 0.1 MiB in one chunk or
  many, a retried 503 does not accumulate (six attempts: the same 0.1 MiB), and the empty-block
  body is dropped at the cap (4 KiB chunks: after 5 of 1 025) and at the first chunk past the
  deadline.

  **What did not change**, measured on `main` first (16 `Content-Encoding` / body shapes, each
  as a 403, a 404 and a 503, 48 outcomes) and pinned by
  `tests/test_ebsi_error_body_bound.py`: the status decides the class (403 `HttpError`, 404
  `HttpNotFound`, a retried 503 `HttpTransientExhausted`, three attempts) and a body the reader
  cannot use gives `problem_type=None`. A stream that does not decode, under a coding the
  client reads and within the bounds below (a body that is not gzip under `gzip`, garbage
  under `deflate`, a bad CRC trailer after a short body), is still
  `MalformedRegistryResponse`, not retried even as a 503, with `httpx.DecodingError` as its
  `__cause__` (itself caused by the `zlib` error) and the unchanged message: the new reader
  raises `httpx.DecodingError` for `_request` to map (#248), so the mapping and its message
  stay in one place. A truncated stream, bytes after its end, a second gzip member and a raw
  `deflate` stream (which httpx retried without the zlib wrapper) are read as they were and
  give the status's class and, when the document is intact, its `type`: the 200 reader refuses
  all four, and doing the same here would turn a retried 503 into a terminal
  `MalformedRegistryResponse` that does not fail over. Also unchanged: the 16 KiB cap
  (inclusive: a body of exactly that size still gives its `type`, one byte more does not), the
  `application/problem+json`-only rule and the shape of `type`, the wall-clock deadline, the
  retry and 404 handling, the 200 path, `get_bytes` and `probe` (which never read an error
  body), the public API and the dependencies. `Content-Length` is not consulted on this path.

  **Deliberate differences.** (1) A `Content-Encoding` the client does not decode (`gzip,
  gzip`, `br`, `zstd`, anything but one `gzip` or `deflate`; the request asks for `gzip,
  deflate` only) is not read at all: the response is closed and `problem_type` is `None`,
  where `main` decoded `gzip, gzip` twice and ignored an unknown coding, reading a `type` from
  a plain body labelled `zzz`. `HttpUnexpectedEncoding`, which carries status 200, never
  reaches an error answer. (2) The wire is bounded by the cap as well as the decoded body, so
  a coded body larger than 16 KiB on the wire (a stored or incompressible one; exactly 16 KiB
  is still read) is refused although `main` read it; the recorded Problem Details answers are
  150 to 190 bytes. (3) A body is refused for its size before the reader reaches damage
  further on.

  **Where a class does change.** For a *clean* body, (1) and (2) lose a `type` and keep the
  class. A *corrupt* body that the reader never decodes (`gzip, gzip` or `gzip, deflate` over
  garbage), or refuses for its size before the damage is reached (a bad CRC trailer behind more
  than 16 KiB of output, or behind a wire over the cap), was `MalformedRegistryResponse`, not
  retried, on `main` when it arrived whole, and the status's class when its trailer arrived in
  a later chunk (on `main` it depended on the chunking). It is now the status's class whatever
  the chunking: a 503 is retried to its attempt budget and fails over, a 403 is `HttpError`.
  Measured by the review of the PR; nothing is accepted that was refused, and the number of
  attempts stays bounded.
- **The EBSI client's allow-list matches an origin, not a host name**
  ([#318](https://github.com/luisgf/openvc/issues/318), follow-up D1 of
  [ADR-0009](docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)). Hardening; no
  wrong-accept: it narrows the SSRF guard. `EbsiHttpClient._guard_host` admitted any URL
  whose scheme was `https` and whose host name was in `allowed_hosts`, and never looked at
  the port, so a URL on an allow-listed host reached the socket on whatever port it named
  (measured on `main` at 1.36.0, CPython 3.14.8, httpx 0.28.1, `allowed_hosts={"api-pilot.ebsi.eu"}`:
  `:0`, `:80`, `:8443`, `:9200`, `:65535` and the empty `https://host:/x` were all admitted).
  The only thing that kept a registry walk off another port was the TIR v5 adapter's own
  origin pin (`versioning._origin`, #172, #253), which covers three hops of one adapter and
  nothing else: any other URL given to `get_json` (a status-list URL permitted through
  `for_ebsi(extra_hosts=...)`, a hand-written fetch) got host-only checking.

  The guard now admits **`https` on a listed host at port 443**, which is what the Trusted
  Nodes List publishes (every node URL a bare `https://` origin: no path, port or
  credentials; ADR-0009, "What the Trusted Nodes List is"). An absent port, an empty port
  (`https://host:/x`) and `:443`, `:0443`, `:00443` are 443. Every other port is
  `HttpForbiddenHost` (exact class), naming the port, before the cache lookup and before any
  I/O: `:0` is refused with the rest (`port is None`, never truthiness, so it does not fold
  into 443, the #253 trap). A URL that carries **userinfo** is `HttpForbiddenHost` too, the
  empty forms `https://@host/` and `https://:@host/` included: userinfo is outside an origin,
  the list publishes none, and httpx 0.28.1 sends `https://u:p@host/x` with
  `Authorization: Basic dTpw`, a header the caller never set. An `@` in a path, query or
  fragment is not userinfo and still passes. The userinfo refusal names the rule and carries
  no credentials: its message does not echo them and its `.url` is `None`. Every other
  refusal keeps `.url` as the URL given, a URL with userinfo included (an `http://` one, or
  one on another port, say), and the non-https rule's message quotes it as before. Every
  pre-existing refusal keeps its class and its message.

  `allowed_hosts` is **unchanged**: a set of host names, port 443 implied. `for_ebsi`,
  `EBSI_HOSTS` and `EBSI_BASE` keep their shape, so every existing caller that stays on 443
  works unchanged. An entry that spells a scheme or a port (`"host:8443"`, `"https://host"`)
  never matched and still does not.

  The guard and the adapter pin now read a URL through **one reader**, the private leaf
  module `openvc_ebsi._url` (`read_origin`, `carries_userinfo`), so a rule about scheme, host
  or port is written once and `_origin` returns exactly the strings it returned. The pin
  stays, with its own job: it keeps a walk on the node it started on once an allow-list holds
  several nodes (ADR-0009 D5), and it stays port-agnostic on purpose (the adapters take any
  injected `Fetch`). The 8 KiB cap stays in `_origin`; the guard still has none (httpx's own
  64 KiB backstop stays). Redirects stay off, pinned by a test per status and `Location`
  shape (same host on another port, relative, scheme-relative, a scheme downgrade, another
  host): each is one request, `HttpError`, never followed.

  Not changed: a resolved-address guard and DNS rebinding (the rest of threat-model R4, #322),
  origin strings in `allowed_hosts` (2.0, #74), the cookie jar (#317).
- **The EBSI client can now check where an allow-listed host name points**
  ([#322](https://github.com/luisgf/openvc/issues/322); ADR-0009, "Where each design can be
  attacked", row "DNS rebinding"). Low severity, defence in depth, **no wrong-accept**, and
  **opt-in: nothing changes unless you pass `address_guard=`**. `EbsiHttpClient` matched a
  host *name* and trusted DNS for it (threat model R4). That was accepted while the
  allow-list was three `*.ebsi.eu` names run by one party; a client built from the
  Trusted Nodes List allow-lists operator-run DNS names, so a listed name that resolves to
  a private, loopback or link-local address (a rebinding resolver, a lapsed or shared zone,
  a compromised operator zone) was connected to, and the client opened a TCP connection and
  started a TLS handshake against an address of the attacker's choosing. The HTTP request
  is only sent after the handshake verifies a certificate for the listed name, redirects are
  off and the path is a fixed registry path, so the realistic gain was probing the client's
  internal network (connect success, refusal and timing differ per address).

  `EbsiHttpClient(..., address_guard=AddressGuard())` (and `for_ebsi(...,
  address_guard=AddressGuard())`) resolves the host on every request that misses the cache
  and **refuses the host if any address in the answer is not globally routable**, in either
  order and however many public addresses sit beside the bad one (`HttpForbiddenAddress`, a
  subclass of `HttpForbiddenHost`, so a handler for the name guard catches it; never
  retried, never cached, no request sent). The rule is the one `openvc.fetch` applies to
  `did:web` (private, loopback, link-local, reserved, multicast, unspecified, the
  deprecated IPv6 site-local prefix `fec0::/10`, and anything that is not `is_global`,
  CGNAT included). It then connects to **one validated address**
  with the TLS server name, the certificate check and `Host` still the host **name**, so
  there is no window between the check and the connect: the request goes to
  `https://<validated literal>:<port>/path` with `Host: <name>` and the httpcore
  `sni_hostname` request extension set to the name. The name check runs first and is
  unchanged; the address check can only refuse, so the guard never admits a host the
  allow-list refuses. An allow-listed IP-literal host is classified directly, with no DNS.
  `did:web` still goes through `openvc.fetch` and never through this client.

  What was measured (step 0 of the issue; macOS arm64, httpx 0.28.1, httpcore 1.0.9; the
  address table on CPython 3.10.20, 3.11.15, 3.12.13, 3.13.16, 3.14.8 and 3.15.0rc3, the
  rest on 3.14.8):

  - **A pooled connection is keyed by the address, not the name.** Mechanism A (a
    request-level pin: the validated literal in the URL, `Host` and the `sni_hostname`
    extension carrying the name) completes TLS with SNI and the certificate checked against
    the name, and a certificate for another name is refused. But with one `httpx.Client`, a
    server whose certificate is valid for one name only and two allow-listed names that
    resolve to the same address, the second request reused the connection verified for the
    first name and was served with **no certificate check for its own name**. A guard that
    pinned the address and kept keep-alive would have weakened the control it is meant to
    add (any client with more than one host, which is the point of #322). Every pinned
    request therefore carries `Connection: close`: h11 then closes the connection when the
    response ends without it ever becoming idle, so there is no window in which a second
    thread could take it. The cost is a TCP and TLS handshake per request that misses the
    cache: 0.29 ms against 0.86 ms per request on loopback (what the handshake's round trips
    cost on a real network is not measured). `httpx.Limits(max_keepalive_connections=0)`
    closed the same hole in the sequential test but trims idle connections after the
    response, so it was not used.
  - Mechanism B (a validating `httpcore` network backend under a pool keyed by name) has no
    pooling problem and resolves only on new connections, but needs the private
    `HTTPTransport._pool`, a direct `httpcore` import (a transitive dependency, not
    declared in the `ebsi` extra) and a seam that bypasses the existing `MockTransport`
    tests; passing `transport=` also makes httpx ignore environment proxies silently.
  - Under `HTTPS_PROXY`, A sends `CONNECT <ip>:<port>` and then fails the certificate check
    against the IP (`IP address mismatch`); B ignores the proxy and connects directly.
  - `getaddrinfo("api-pilot.ebsi.eu")`: 25 ms cold, about 1 ms warm, three addresses, against
    a 10 s timeout. One read of the pilot DID document with the guard on completed (live,
    by hand, not in CI).
  - On macOS `getaddrinfo` reads `127.1`, `0x7f.1`, `2130706433`, `127.0.1`, `0x7f000001`
    and `017700000001` as `127.0.0.1`, and `0177.0.0.1` as `177.0.0.1`; `ipaddress` rejects
    all of them, so they reach the resolver and the guard sees the answer. glibc was not
    measured. The connection goes to the validated literal, so the name is never read a
    second time.
  - **Not measured locally:** the declared httpx floor (0.27); only 0.28.1 is installed
    and nothing was downloaded. The pinned request uses
    `Client.stream(..., headers=, extensions=)` and nothing else of httpx. CI now has a
    floor leg (`test (py3.10, httpx 0.27.0)`, in `.github/workflows/ci.yml`, built like
    the pyld floor leg) that installs `httpx==0.27.0` over `[all]` on CPython 3.10 and runs
    the whole suite, the loopback TLS tests included. Its first run was green with
    `httpx-0.28.1` uninstalled and `httpx-0.27.0` installed: 17582 passed, 39 skipped, all
    265 tests of `tests/test_ebsi_address_guard.py` among them.

  The classifier agreed on every class of the first 57 rows of the table on all six
  interpreters (private, loopback, link-local, cloud metadata, unique-local, unspecified,
  multicast, CGNAT, benchmarking, documentation, IPv4-mapped and IPv4-compatible, NAT64,
  6to4, Teredo); the two site-local rows added in the review round (below) were run on
  CPython 3.13.16, 3.14.8 and 3.15.0rc3, and the CI matrix runs the whole table on 3.10 to
  3.15. `is_global` alone is wrong for some of them (`224.0.0.1`, `ff0e::1`, `::808:808`,
  `64:ff9b::808:808` and `fec0::1` report `is_global=True`; the multicast, reserved and
  site-local flags catch them), which is why the union is kept. NAT64, 6to4, Teredo and
  the IPv4-compatible forms are refused **as whole prefixes**, whatever IPv4 they embed.
  Not pinned: `::ffff:8.8.8.8` (a
  mapped public address; threat model R5 records that the mapped-form classification varies
  across interpreter versions) and `192.88.99.1`, `192.0.0.9`, `192.0.0.10`, `2001:20::1`
  (allowed on every interpreter measured).

  **Defaults pending maintainer confirmation.** Each is the issue's recommendation and is
  implemented; the other option is what would change.

  - **D1 mechanism: A (request-level pin), with keep-alive off.** B would add `httpcore` as
    a direct import and use a private attribute, in exchange for keep-alive and one
    resolution per connection.
  - **D2 default: off** for `EbsiHttpClient` and `for_ebsi`. On would break split-horizon
    DNS and a private mirror of a node, and change public behaviour. Whether a client built
    from a verified Trusted Nodes List turns it on is #324's call.
  - **D3 environment proxy: refuse at construction** with `HttpAddressGuardUnavailable`
    (an `HttpError`, hence an `EbsiError`), when `urllib.request.getproxies()` (the
    variables, and on macOS and Windows the system settings) has an `https` or `all` proxy.
    Ignoring the proxy would silently change how the process reaches the network;
    documenting only would leave an opaque certificate error. **`NO_PROXY` is not an
    exemption**: httpx matches it against the host of the request URL, which is the pinned
    address, so with `HTTPS_PROXY` set and `NO_PROXY` naming the EBSI host the pinned
    request was still sent to the proxy (`CONNECT <ip>:<port>`) and then failed the
    certificate check against the IP (measured on a loopback proxy). A deployment that
    needs a proxy for other traffic builds this client in a process or environment
    without it, or without the guard.
  - **D4 several addresses: rotate**, one validated address per attempt in resolver order
    (the first this call has not used yet, so a resolver that reorders its answer cannot
    make a retry repeat the address that just failed), bounded by `RetryPolicy`. Any
    transport error (connect, TLS handshake, read or write timeout, protocol error), a 429
    or a 5xx moves to the next address; a 404 or other 4xx is not retried.
    First-address-only would turn one dead address of four into an outage. **The bound:**
    one address per attempt means the address at position *k* of the answer is reached
    only if the policy allows *k* attempts, so with the default `RetryPolicy` (3 attempts)
    only the first three addresses are ever tried. Measured with an IPv6-broken client
    (every IPv6 literal fails to connect) and a live IPv4 address after the dead ones:
    two dead addresses first succeed, three dead first are `HttpTransientExhausted` (the
    live one is never tried) and succeed with `RetryPolicy(attempts=4)`; four dead first
    need 5. A deployment that expects dead addresses sets `attempts` to at least the
    number of addresses it must be able to reach. A name-based connect does not have this
    bound (`socket.create_connection`, which httpcore uses, tries every address of the
    answer inside one attempt), so a host with three AAAA records on a client with no IPv6
    route works unguarded and is an outage guarded under the default policy. *The other
    option*, which is a maintainer decision and is not taken here: on a transport error try
    the remaining validated addresses of the same resolution before consuming the attempt,
    bounded by `attempts x addresses`, each under the per-socket connect timeout; it
    removes the bound above at the cost of up to that many connection attempts per
    `get_json`.
  - **D5 exemptions: none**, and the classifier is fixed (`AddressGuard` takes a resolver,
    never a rule). An operator who must reach an internal mirror builds a second client
    without the guard.
  - **Smaller choices of this change.** The pinned request carries no userinfo (a
    `user:pw@` in the URL would otherwise become an `Authorization` header); an IPv6
    address with a scope id is refused even when it is public; an answer that is not a
    string or does not parse as an address refuses the host, it is not retried.
  - **D6 (review round) `fec0::/10`: refused in the shared classifier.** The reviewer
    found that `ip_is_forbidden("fec0::1")` was false: `ipaddress` reports the deprecated
    IPv6 site-local prefix (RFC 3879) as `is_global=True` with no other flag, on the
    interpreters checked (3.13.16, 3.14.8 and 3.15.0rc3), so the docs' "not globally
    routable" was untrue for it and one internal-looking class was open, for `did:web` too.
    The change adds `IPv6Address.is_site_local` to the flag union (IPv4 has no such
    property). *The other option* is to leave the classifier alone and list `fec0::1`
    under "Not pinned" with `192.88.99.1`; it would keep `did:web` accepting a host that
    resolves to `fec0::/10`. See `### Changed`.

  **What it does not do.** It does not stop an attacker who also holds a valid certificate
  for a public address, a dishonest listed node, or anything about registry content; it is
  not certificate pinning, DNSSEC or DoH, and `getaddrinfo` has no deadline with or without
  the guard. The cache is consulted before the address check (a hit makes no connection),
  so a `cache` shared with a guard-off client is the consumer's choice. Threat model R4 is
  rewritten and keeps its id.

  **Behaviour change: none with the guard off**, which is the default; the constructor
  arguments of the pooled `httpx.Client` and every request are what they were. With the
  guard on: the request targets the validated address, carries `Connection: close` and no
  userinfo, and a host that resolves to a non-public address raises `HttpForbiddenAddress`
  where it used to be connected to.

- **Known limitations of EBSI trust evaluation, found by the adversarial review of #365 and
  NOT fixed in 1.37.0** (pre-existing in every released version; each is an open issue with a
  measurement step and a policy decision for the maintainer):
  [#367](https://github.com/luisgf/openvc/issues/367) the type match intersects the
  credential's whole `type` list with `accreditedFor.types`, and on real EBSI data both carry
  the generic `VerifiableCredential` / `VerifiableAttestation`, so an accreditation scoped to
  another type still authorises the credential (single-level and recursive);
  [#368](https://github.com/luisgf/openvc/issues/368) an accreditation token with no
  `accreditedFor` is the unrestricted one and `vc.type` is never checked against the role, so
  a RootTAO- or TAO-signed credential of another kind for the same DID reads as an
  accreditation; [#358](https://github.com/luisgf/openvc/issues/358) `issuerType` is compared
  with the lowercase `revoked` only and never limits delegation. Until they land, treat EBSI
  issuer trust as "accredited by a trusted chain", not as "accredited for this type".

### Added

- **`legacy-pilot`, a name for the legacy EBSI pilot lane**
  ([#325](https://github.com/luisgf/openvc/issues/325), Part 1 of 3; refs
  [#113](https://github.com/luisgf/openvc/issues/113)). `for_ebsi("legacy-pilot")` seeds
  exactly the allow-list `for_ebsi("pilot")` always did, `{"api-pilot.ebsi.eu"}`: the legacy
  per-service lane (the v5 adapters), the only place the recorded fixtures and the weekly
  smoke test are valid. `EBSI_HOSTS["legacy-pilot"]` and `EBSI_BASE["legacy-pilot"]` are a
  fourth key in each dict (same `dict[str, str]` type; the first three keep their keys, values
  and order). **Why a new name:** EBSI now also uses "pilot" for its Core API pilot, which
  ADR-0009 measured to be a different ledger (the legacy DID answers 404 on its nodes), so
  `pilot` no longer says which pilot is meant. `legacy-pilot` does.
- **`openvc_ebsi.environments`**, a new module that imports no HTTP library (it works
  without the `ebsi` extra, and `versioning.py` reads it). It holds the environment-name
  table as data: a frozen `EbsiEnvironment(name, fixed_host)` (`fixed_host=None` means an
  environment with no fixed host), the read-only `ENVIRONMENTS` mapping,
  `fixed_hosts()` and `LEGACY_PILOT_HOST` / `LEGACY_PILOT_BASE`. `http.EBSI_HOSTS` is now its
  fixed-host projection and `EBSI_BASE` derives from that, both still plain `dict`s under the
  same names. The table is data, never a version ladder: API-version specifics stay behind
  the adapters in `versioning.py`.
- **`UnknownEbsiEnvironment(EbsiError, ValueError)`** in `openvc_ebsi.errors`, raised by
  `for_ebsi` for a name the table does not hold: an unknown, wrong-case or empty string, or a
  value that is not a `str` (`None`, a number, `[]`, `{}`, `bytes`). It is the smallest typed
  form that keeps `except ValueError` working. The message names the accepted names and shows
  the offending value through the bounded `safe_repr`.
- **`preprod` and `prod`, the two node-derived EBSI environments, are in the name table, and
  `for_ebsi` refuses them with `NodeDerivedEnvironment`**
  ([#325](https://github.com/luisgf/openvc/issues/325), Part 3 of 3; refs
  [#113](https://github.com/luisgf/openvc/issues/113),
  [#324](https://github.com/luisgf/openvc/issues/324)). `openvc_ebsi.environments.ENVIRONMENTS`
  now names every environment: `EbsiEnvironment("preprod", None)` and
  `EbsiEnvironment("prod", None)` join the four fixed-host rows. They are the Trusted Nodes
  List's own spellings for EBSI Core API v1, whose hosts are the nodes of a signed list and not
  a name, so they have no fixed host (`fixed_host is None`, `.base is None`). `EBSI_HOSTS` and
  `EBSI_BASE` are **unchanged**: exactly their four keys, values and order, because
  `fixed_hosts()` filters out a row with no host (and `prod` is not `production`, `api.ebsi.eu`).
  `for_ebsi("preprod")` and `for_ebsi("prod")` raise the new
  **`NodeDerivedEnvironment(UnknownEbsiEnvironment)`** (so also an `EbsiError` and a
  `ValueError`) before any `httpx.Client` exists. Its message says the name has no fixed host
  and names `verify_node_list`, `for_nodes` and the wiki page "EBSI-Node-Trust", where a caller
  used to read "unknown EBSI environment". The match is the exact name, as for every row:
  `"Prod"`, `" prod"` or `UserString("prod")` is still a plain `UnknownEbsiEnvironment`, whose
  "known:" list names the four fixed-host names only. Which host each of the six names seeds:
  `legacy-pilot` and `pilot` `api-pilot.ebsi.eu` (`pilot` with its warning), `conformance`
  `api-conformance.ebsi.eu`, `production` `api.ebsi.eu`; `preprod` and `prod` none, they refuse.
  - **Behaviour change.** `for_ebsi("preprod")` and `for_ebsi("prod")` raised
    `UnknownEbsiEnvironment`; they raise its subclass. `except UnknownEbsiEnvironment`,
    `except EbsiError` and `except ValueError` keep catching them; code that compares the exact
    class (`type(exc) is UnknownEbsiEnvironment`) for these two names must compare
    `NodeDerivedEnvironment`. Nothing that built a client stops building one.
  - **The adapter pairing is not in the table.** The issue text proposed `didr_adapter` /
    `tir_adapter` fields on the row. They are dropped: `for_nodes(result, ..., didr="core-v1",
    tir="core-v1")` already takes both and validates them against `DID_REGISTRY_ADAPTERS` /
    `TIR_ADAPTERS`, and a second copy in `environments.py` would be a second source of truth
    for the same fact. The row stays a name and a `fixed_host`, and
    `openvc_ebsi.nodes._ENVIRONMENTS` (`pilot`, `preprod`, `prod`, the list's own spelling) stays
    where it is: the list's `pilot` is the node-derived ledger and the table's `pilot` is the
    deprecated alias of `legacy-pilot`, so the two cannot share one tuple before the MAJOR.
    `nodes.py` and `node_client.py` are untouched.
  - **There is no node-derived `pilot` row.** The name stays the deprecated alias of
    `legacy-pilot` until the next MAJOR release (2.0,
    [#74](https://github.com/luisgf/openvc/issues/74)). The 2.0 end state, recorded on #74:
    `pilot` changes meaning to the node-derived environment, so `for_ebsi("pilot")` refuses like
    `preprod` and `prod` do and the two tables can share one spelling; the `production` and
    `conformance` rows, kept in 1.x by decision 3a, leave `EBSI_HOSTS` / `EBSI_BASE` unless a
    measurement by then shows a host that completes a request. A caller who ignored the
    `pilot` warning then reads a different ledger (the legacy DID answers 404 there, ADR-0009).
  - Additive: no parser or verify path is touched, `environments.py` still imports no HTTP
    library, and there is no new dependency. `for_ebsi()` and `for_ebsi("legacy-pilot")` still
    warn nothing.
- **EBSI Core API v1 adapters: `DidRegistryCoreV1` and `TirCoreV1`**
  ([#321](https://github.com/luisgf/openvc/issues/321); design:
  [ADR-0009](docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)). `openvc_ebsi` could
  not read a single Core v1 node: the DID Registry and the Issuers Registry moved to
  `/v1/did-registry/identifiers/{did}` and `/v1/issuers-registry/issuers/{did}` on the
  *answering node's own origin*, and every `self`, `links`, `attributes` and `href` in a
  response names that node's host. Both adapters are registered as **`"core-v1"`**
  (`did_registry_adapter("core-v1")`, `tir_adapter("core-v1")`), not `"v1"`, which would
  collide with the older per-service `trusted-contracts-registry/v1` vocabulary. The
  defaults stay `"v5"`, so does `DidEbsiResolver`'s default `base`, and `EBSI_HOSTS` /
  `for_ebsi` are untouched: a Core v1 caller passes the node origin as `base`, and `didr`
  and `tir`, together, over a client that allow-lists that node's host (the node-based
  constructor is `for_nodes`, #324, later in this release; the node-derived names are #325
  part 3). The `/v1` belongs to the adapter, and the
  path never carries the registry key `core-v1`. The v5 lane (`DidRegistryV5`, `TirV4`,
  `TirV5`) and its fixtures are unchanged.
  - **One shared walk.** The v5 attribute walk (the page and item caps,
    `_iter_attribute_items`, `parse_issuer`) moved, as code motion alone, into a private
    base that `TirV5` and `TirCoreV1` both inherit, so the origin pin (host and port), the
    caps and the typed errors are written once; `TirCoreV1` is not a subclass of `TirV5`.
    `Accreditation.attribute_id` stays the list item's `id`: the recordings show that it is
    not the attribute's `hash` (`0dc6a111...` against `a1c4d9e9...`), and the repo's own v5
    recording shows the same.
  - **`contract_address`** (keyword only, on both adapters, default `None`). Core v1 really
    selects a registry instance by the address of its contract (`?contractAddress=`; the
    pilot ignored it), and each registry has its own: the preprod node publishes different
    ones on `/did-registry/details` and `/issuers-registry/details`. The value comes from
    configuration only, never from a response, a link or a token; it must be 1 to 128 of
    `A-Z a-z 0-9 . _ -`, checked with `fullmatch` on an exact `str` (`ValueError`
    otherwise: empty, blank, control or non-ASCII characters, any of `/ ? # & = %` or a
    space, over-long, not a `str`), so configuration cannot reshape the path or add a
    parameter. It is the only query component, so two resolvers with different addresses on
    one client never share a cached document.
  - **A configured walk stays on one registry instance.** The recorded nodes do not echo
    `contractAddress` in `self`, `links`, `attributes` or `href`, so a followed link names
    none and a node would read it against its *default* instance. With an address
    configured, `TirCoreV1` adds it as the last query parameter of the `attributes` link, of
    every `href` and of `links.next` when they name none, leaves one that names the
    configured address as `contractAddress`, and raises `MalformedRegistryResponse` for any
    other link that names the instance. A query parameter counts as naming it when its
    percent-decoded name, case-folded, *contains* `contractaddress`; only the exact name with
    the configured value is kept. So these are refused: another case, a percent-encoded
    name, a repeat, a bracket suffix (`contractAddress[]`, `contractAddress[0]`), a longer
    name (`contractAddress.x`, a trailing space, `%00`). A raw `;` anywhere in the link's
    query is refused whatever it names, because a server may read it as a separator. That
    is the list of spellings covered, not a claim about every way a server may read a name;
    the configured address is also on the issuer URL, and the node is the one registry the
    walk is already pinned to. The recorded links carry neither form (`page[after]` and
    `page[size]` only). The missing-`attributes` fallback is built from the path with the
    query last. With no address configured, links are followed as written.
- **`HttpError.problem_type`** (add-only, `None` by default). EBSI Core API v1 answers errors
  as RFC 9457 Problem Details with a stable `type` (`urn:ebsi:problems:<slug>`; ADR-0001 D7
  asked for it and `http.py` mapped by status alone). `get_json` now reads it from an error
  answer and hands it over opaque: `http.py` does not know the `urn:ebsi:problems:`
  vocabulary, and `title` and `detail` are neither read nor echoed. It is kept only when the
  answer is **`application/problem+json`** (what the recorded 400, 404 and 406 answers
  carry, so the gate is not widened), the body is a JSON object that passes the bounded
  loader, and `type` is a string of 1 to 256 visible ASCII characters; otherwise `None`. A
  node's firewall 403 is a 35 KB `text/html` page (ADR-0009) and is never read as Problem
  Details. The parse never raises: a body that cannot be used leaves `None` and the status
  error is raised as before. Messages and exception classes for every status are unchanged
  (404 is `HttpNotFound`; 429 and 5xx still retry and end as `HttpTransientExhausted`, which
  carries the last attempt's type; a corrupt gzip is still `MalformedRegistryResponse`,
  #248). Not every Core v1 error has a slug: the recorded 406 says `about:blank`.
- **Recorded Core API v1 vectors**, `tests/fixtures/ebsi/core-v1/` (24 recorded files, a
  `MANIFEST.json` and a `README.md`): plain read-only GETs of 2026-10-16 with the client's
  own `User-Agent` and `Accept`, vendored byte for byte, never edited. The preprod RootTAO
  `did:ebsi:zmaEptEHQRAmkJnFV6ki3io` read from two nodes (`api-preprod.ebsi.grnet.gr`,
  `api-preprod.ebsi.incm.pt`: the DID document with a `secp256k1` and a `P-256` key, the
  issuer, the attribute list, the attribute and the first issuers page), the one-issuer
  production seed (`api.ebsi.iti.gr`, shape only: its DID document has an empty
  `verificationMethod`; to be replaced when real operators onboard), the
  `application/did+json` negotiation variant, the 404 / 400 / 406 Problem Details bodies, and
  one walk read with and without a valid `contractAddress`. The manifest records, per file,
  the request URL, status, media type, node, retrieval time, headers sent and SHA-256. Not
  recorded, and said so in the README: **405** (it needs a non-GET request to a read path)
  and the OpenAPI contract (`gitlab.com` answered 503 to three attempts).
- **Decisions taken by default, for the maintainer to confirm** (each was open in the issue
  or the ADR; the other option is what a change would cost):
  1. *`parentAttributeId` on the model* — Option 1: `Accreditation` is unchanged and the field
     is only recorded in the fixtures (nothing reads it; the trust walks use `tao` and
     `rootTao`). Option 2 would add a defaulted `parent_attribute_id: str | None = None` at
     the end of the frozen dataclass.
  2. *Names* (ADR open question 4) — `"core-v1"` only; `EBSI_HOSTS` and `for_ebsi` are not
     touched (#325).
  3. *404* (ADR open question 5) — stays `HttpNotFound` by status; `problem_type` only
     describes it. Whether a 404 is authoritative for a node is #324's.
  4. *`contract_address` format* — the issue's bounded token. The OpenAPI contract could not
     be read, but every address the nodes publish is `0x` and 40 hexadecimal digits, which
     fits. Tightening it to that form is a one-line change to the pattern; the cost is
     rejecting any other form the contract may allow.
  5. *A link that names no `contractAddress`* — gets the configured one (above). The other
     option, following it bare, reads the node's default instance for every hop after the
     first whenever the configured address differs from it. A link whose query holds a `;`
     is refused even when it names no address, and a name that merely contains
     `contractaddress` is refused: the other option is to compare the name exactly and
     split on `&` alone, which lets `contractAddress[]` and a `;`-separated parameter
     through with the configured address appended after them.
  6. *Bounds on the error read* — 16 KiB for the body and 256 characters for `type`.
  7. *`TirCoreV1` takes `contract_address` too* — on the strength of the recorded 200s for
     the issuer, attribute list and attribute read with the Issuers Registry's own address
     (the contract itself could not be read). The other option is the DID Registry only.
  8. *The two walk-typing fixes reach the v5 lane* — a non-string attribute `body` and a
     revision without an `attribute` object are `MalformedRegistryResponse` on `TirV5` as
     well, although the issue left the v5 lane as it is: the walk is shared, so "v5
     unchanged" and "one walk" cannot both hold. The other option is a hook so that only
     `TirCoreV1` raises, which keeps a bare `AttributeError` and the read of a missing
     `attribute` object as an empty attribute on the legacy lane.
- **`EbsiHttpClient.get_bytes`, `for_tnl` and `get_tnl_files`: the fetch half of the
  Trusted Nodes List work** ([#320](https://github.com/luisgf/openvc/issues/320),
  [ADR-0009](docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md) D4). `get_json` cannot
  carry the list: it parses to a `dict`, caches it, and refuses the two binary `.sig` files,
  while `tnl.json.sig` covers exactly the bytes of `tnl.json`.
  - **`get_bytes(url, *, max_bytes=None, etag=None, deadline_s=None) -> BytesResponse`** returns
    the body verbatim (no text decoding, no `strip`, no cache) as `BytesResponse(body, etag)`;
    `body` is `None` exactly on a 304. It runs under the same host guard, redirects off, retry
    on 429 / 5xx / transport errors and `Retry-After` as `get_json`: both now call one private
    request loop, so the #246 and #248 behaviours cannot drift between them, and `get_json`'s
    observable behaviour is unchanged. It sends `Accept: */*` and `Accept-Encoding: identity`.
    A 404 is `HttpNotFound`; an unsolicited 304, any other 3xx, a 204, a 206 and a 403 are
    `HttpError` with `status`, not retried, and **the body of a non-200 response is never
    read** (a 403 body can be a firewall page). `max_bytes` can only lower the client's
    `max_response_bytes`. `deadline_s` (a number of seconds above 0 and at most 86 400, one
    day; anything else, a 400-digit `int` and `1e300` included, is `HttpError` before any I/O)
    is a budget over the attempts, the sleeps between them (a `Retry-After` or backoff sleep is
    clamped to what remains) and the body read, which checks the clock after every chunk it
    receives; a spent budget is a plain `HttpError`. **It is not a ceiling on the wait for one
    response's headers**: the connect, the TLS handshake and each socket read are bounded only
    by `timeout_s` each, so a server that sends its headers slowly enough to keep every read
    under `timeout_s` is not cut off (measured: a 16-line header drip of 0.5 s per line held a
    `deadline_s=1.0` call (`timeout_s=2.0`) for 8.1 s, then the late body was refused; the HTTP/1.1 stack's
    header-size limit is the only other bound, 100 KiB in httpcore 1.0.9, which is not a time
    bound). `get_json` has the same property. A caller that needs a hard wall-clock limit
    enforces it outside the call.
  - **The decoded size is bounded before it is allocated.** The body is read with
    `iter_raw()`, so httpx decodes nothing; the wire size and a `Content-Length` over the cap
    are refused before a chunk is appended; a single `gzip` or `deflate` coding is decoded
    with `zlib.decompressobj`, asking for at most `remaining + 1` bytes per call, so a
    decompression bomb is refused inside zlib. Measured with `tracemalloc` on a 260 935-byte
    gzip body that inflates to 256 MiB: about 2 MiB peak on the bytes path, against 557 MiB on
    `get_json` (see Not changed, below). Any other coding (`br`, `zstd`, `x-gzip`, a list such
    as `gzip, gzip`) is the new `HttpUnexpectedEncoding(HttpError)`; a corrupt or truncated
    stream, bytes after its end, or a raw-deflate body labelled `deflate` is
    `MalformedRegistryResponse` (the zlib error as `__cause__`), not retried.
  - **ETag in, ETag out, no state.** A supplied `etag` is opaque and sent verbatim as
    `If-None-Match`; it is only checked as a header value (1 to 256 characters of visible
    ASCII, not `*`), and one that fails, or is not a `str`, is `HttpError` before any I/O (a
    non-ASCII value would otherwise escape as a bare `UnicodeEncodeError`). A 304 is accepted
    only when an `etag` was sent and returns `BytesResponse(None, <the etag that was sent>)`:
    it means "re-use the bytes you stored and verify them again with a fresh `now`", so
    `expires` and rollback checks always run. A received `ETag` that fails the same check is
    dropped (`etag=None`) and the body is still returned, because the signature authenticates
    the body and the validator only saves bandwidth.
  - **`for_tnl(**kwargs)`** builds a client whose allow-list is `{tnl.ebsi.eu}` alone, never
    the node set a list names, so a poisoned list cannot widen where the list itself is
    fetched (`allowed_hosts` cannot be passed: `TypeError`). It keeps no cookies (only this
    client: `get_tnl_files` accepts any client whose allow-list is `{tnl.ebsi.eu}`, and one you
    build yourself keeps whatever its cookie jar accepts until #317), and its
    `max_response_bytes` defaults to 64 KiB. `EbsiHttpClient` gains a read-only
    `allowed_hosts` property (a `frozenset`).
  - **`get_tnl_files(client=None, *, etags=None, deadline_s=30.0) -> dict[str, BytesResponse]`**
    makes four sequential requests to `https://tnl.ebsi.eu/<name>` (`TNL_FILES`: `trusted-keys.json`,
    `trusted-keys.json.sig`, `tnl.json`, `tnl.json.sig`) sharing one `deadline_s` budget (what it
    bounds is stated above: not the wait for one response's headers), with a
    per-file cap (`TNL_MAX_BYTES`: 64 KiB for the JSON files, 4 KiB for the signatures). It takes no
    URL, refuses with `HttpForbiddenHost` before any request a `client` whose allow-list is
    not exactly `{tnl.ebsi.eu}`, and is all-or-nothing: a failure propagates with its class
    and a message that names the file, and nothing partial is returned. `etags` maps a file
    name to the validator of the copy the caller holds; a key that is not a file name is
    `HttpError` before any I/O, so a typo cannot silently disable conditional requests.
  - **What it does not do:** verify anything (the bytes are unauthenticated until the
    verifier of #319 checks them); poll (one round trip per file per call; the publisher's
    hourly guidance is the consumer's schedule); persist (the consumer keeps the bytes and
    the ETags); reconcile a mixed set (a new `tnl.json` beside a 304 for its signature); or
    fetch the pinned key-list key (`keylist-key.asc`), which the publisher says never to
    download at run time and which would turn the pin into trust-on-first-use of DNS and TLS.
  - **One live measurement of `tnl.ebsi.eu`** (2026-10-16, 8 GETs, certificate verification
    on, no redirects followed), recorded in `tests/fixtures/ebsi/tnl_response_headers.json`
    and replayed through `MockTransport`: (1) `openvc-core/1.36.0` is served a 200 on all
    four files; (2) `Accept-Encoding: identity` yields no `Content-Encoding`; (3) every file
    carries a strong `ETag` (quoted, no `W/`); (4) `If-None-Match` with it yields a 304 with
    no content on all four.
  - **Defaults pending maintainer confirmation** (none is a fact about EBSI; the PR body says
    for each what the other option would change):
    - the per-file caps and the 30 s `deadline_s` of `get_tnl_files` are proposals (ADR-0001
      D5's 10 s per-request `timeout_s` stays);
    - `deadline_s` is documented, not enforced, on the wait for one response's headers (the
      alternative clamps each request's httpx timeout to the remaining budget, and bounding a
      header drip needs a watchdog or a custom transport);
    - `deadline_s` has a ceiling of one day (`_MAX_DEADLINE_S`, as `MAX_LEEWAY_S` does for the
      leeway): without one, `deadline_s=1e300` reaches `time.sleep` through the clamp with a
      hostile `Retry-After` and raises a bare `OverflowError`;
    - a sleep is clamped to the budget and the call then fails, rather than failing at once;
      a spent budget is a plain `HttpError`, not a `HttpTransientExhausted`;
    - `for_tnl` defaults `max_response_bytes` to 64 KiB;
    - the no-cookie policy is the constructor's (#317), so `for_tnl` and `get_bytes` inherit it;
    - the argument checks (`etag`, `max_bytes`, `deadline_s`) run before the host guard, so a
      call that gets both wrong reports `HttpError`, not `HttpForbiddenHost` (no I/O either
      way);
    - an empty `Content-Encoding` is read as absent; a `Content-Length` that is not a plain
      number is ignored (the streamed cap still applies);
    - the validator check is only "1 to 256 visible ASCII characters, not `*`", so an `etag`
      with a comma is sent verbatim (a server may read it as a list);
    - `max_bytes=0` is accepted (any non-empty body is then over the cap);
    - `get_tnl_files` names the failing file by rewriting the exception message in place
      (`"<file>: <message>"`), keeping the class, `status`, `url` and `__cause__`;
    - a second gzip member is refused, not concatenated (bytes after the end of the first
      stream are `MalformedRegistryResponse`).
  - **Sync only:** the EBSI HTTP client has no async twin, so neither do `get_bytes`,
    `for_tnl` and `get_tnl_files`.
  - **Mocking note:** `get_bytes` reads the raw stream, so a test double must build its body
    as a stream (`httpx.Response(200, stream=httpx.ByteStream(b"..."))`);
    `httpx.Response(200, content=b"...")` is decoded eagerly by httpx and its stream marked
    consumed.
  - **Not changed:** `get_json` keeps its per-chunk inflation (`iter_bytes` yields an
    already-decoded chunk, so its cap fires after the allocation), its uncapped
    `resp.read()` drain of a non-200 body and its unbounded `Retry-After` sleep when no
    budget is given, which is a bare `OverflowError` once the header is longer than
    `time.sleep` takes (about 9.2e9 s, so any 11-digit value; measured; `get_bytes` without a
    `deadline_s` has it too, and `get_tnl_files` always passes one). They are outside this
    change and are tracked separately (the drain was bounded by #321, the other two by #335;
    see *Fixed*).
- **`openvc.fetch.ip_is_forbidden(address)`**
  ([#322](https://github.com/luisgf/openvc/issues/322)), the address rule `openvc.fetch`
  applies to `did:web`, public and in `__all__` so a caller with its own HTTP client applies
  the rule instead of a copy of it. `_ip_is_forbidden` is the same function object. Raises
  `ValueError` for a string that is not an IP address.
- **`openvc_ebsi.http.AddressGuard`**, `HttpForbiddenAddress`, `HttpAddressResolutionFailed`
  and `HttpAddressGuardUnavailable`, and the `address_guard=` argument of `EbsiHttpClient`
  and `for_ebsi`. `AddressGuard.addresses(host, port)` returns the validated addresses and
  raises `HttpForbiddenAddress` or `HttpAddressResolutionFailed` (a resolver `OSError`,
  `ValueError`, `TypeError` or an empty answer is handled like a connection failure:
  retried, then `HttpTransientExhausted`). That is the contract for the default resolver;
  an **injected** `resolver=` that raises anything else (a `RuntimeError`, a `KeyError`)
  has its exception propagate unchanged and unretried, so a bug in a caller's resolver is
  not hidden behind the retry loop.
- **`VcJwtProofSuite(allow_es256k=True)`: ES256K as an explicit, verification-only opt-in**
  ([#323](https://github.com/luisgf/openvc/issues/323); decision: [ADR-0009](docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md),
  open question 3, accepted 2026-10-16; refs [#113](https://github.com/luisgf/openvc/issues/113)).
  **Opt-in: nothing changes for a caller who does not pass it.** EBSI Core API v1 signs its
  RootTAO accreditation JWTs with `alg: ES256K` (RFC 8812: ECDSA over secp256k1 with SHA-256;
  the prod and the preprod ones, recorded 2026-10-16), which the allow-list refuses
  (`UnsupportedAlgorithm`), so recursive trust (`verify_trust_chain`,
  `verify_ebsi_badge(trust_anchors=...)`) failed closed on every Core v1 root. With the keyword
  the recorded preprod RootTAO verifies end to end; single-level trust, which reads the
  accreditation with `peek_claims`, was never affected. It widens a `CLAUDE.md` invariant (the
  allow-list is not widened casually), so it is a named, per-suite opt-in on the ADR-0004
  model, not a change of the list.
  - **The default list is untouched.** `ALLOWED_ALGS` is still `{ES256, ES384, EdDSA,
    Ed25519}`. The new `ALLOWED_ALGS_ES256K = frozenset({"ES256K"})` is exported, disjoint
    from `ALLOWED_ALGS` and `ALLOWED_ALGS_PQ`, and never merged into either. The suite's
    verify set is composed of three explicit terms (the default, plus the ML-DSA names when
    `allow_pq`, plus `ES256K` when `allow_es256k`), so the two flags are independent:
    `allow_pq=True` does not imply the new keyword and the reverse. The allow-list check still
    runs before `crit`, `typ`, the SD-JWT-marker gate and any crypto.
  - **Verification only.** `sign()` hands `sign_compact` the verify set minus `ES256K`, so no
    suite, opted in or not, signs with a third-party `SigningKey` whose `alg` is `ES256K`
    (`UnsupportedAlgorithm`, before the backend is asked). No secp256k1 signing backend is
    added; `signing_key_from_jwk` still refuses `crv: secp256k1`.
  - **The key is pinned by openvc, before PyJWT loads it.** `ES256K` verifies only with a
    `kty: EC`, `crv: secp256k1` JWK (exact strings; RFC 8812 says to check both) whose `x`
    and `y` are 43-character, canonical, unpadded base64url strings (RFC 7518 section
    6.2.1.2 asks for the full-width octet string: a coordinate written without its leading
    zero octet, or with one extra, is refused), below the field prime, and on the curve. The
    prime bound is load-bearing: measured on `cryptography` 49.0.0, `EllipticCurvePublicNumbers`
    accepts a genuine point written as `x + p`, on secp256k1 and on P-256 alike (the existing
    ES256/ES384 branches share that laxity; it is another spelling of the same key, not a
    forgery, and is untouched here). Every
    failure is a plain `ProofError`, never a `ValueError`/`KeyError`/`TypeError`, and never
    `ClaimsInvalid`: PyJWT's own `InvalidKeyError` for a P-256 key under `ES256K` would have
    been mapped to `ClaimsInvalid` by `_decode`, the wrong family for a key/alg mismatch. A
    JWK that is not an object is a `ProofError` too (the classic algorithms' branches still
    raised a bare `AttributeError` for `None` on the direct suite API at the time; #341, later in
    this release, made a JWK that is not an object a `ProofError` on every algorithm), and
    a private `d` member is ignored, never loaded. The reverse direction was already pinned and is now tested: `ES256`, `ES384`,
    `EdDSA` and `Ed25519` headers with a secp256k1 JWK are a `ProofError`. A DID document that
    holds a secp256k1 and a P-256 key (the recorded preprod RootTAO's) fails the same way when
    `kid` names the wrong one.
  - **RFC 8812 section 3.2's JWK checks are enforced for `ES256K`.** When the key carries
    them, `alg` must be `ES256K`, `use` must be `sig` and `key_ops` must be an array of strings
    that includes `verify`; a member that is present and wrong is a plain `ProofError`, and a
    `null` counts as present (a bare string `"verify"` would pass a substring test, so
    `key_ops` must be an array). Found in the adversarial review: on the first head of this PR
    a valid token verified against the same key carrying `use: enc`, `key_ops: ["sign"]` or
    `alg: "ES256"`. Enforced in the `ES256K` loader only: the ES256, ES384, EdDSA and Ed25519
    branches still ignore those members, as before (the issue puts JWK `alg` handling for the
    classic algorithms out of scope, and a default caller must see no change). The recorded
    EBSI DID-document keys carry none of the three members, so the golden is untouched.
  - **`allow_es256k` must be exactly `True` or `False`.** Any other value is a `ProofError`
    when the suite is built (the family of `leeway_s`, validated in the same constructor). The
    first head read the flag by truthiness: `allow_es256k="false"`, `"0"` and `1` all enabled
    `ES256K`, which a configuration file or an environment variable can hand over, and which
    silently widens the allow-list. The check is `type(flag) is not bool`, not `isinstance`, and
    the message names the type, never the value. `allow_pq` has the same laxity on
    `VcJwtProofSuite` and `SdJwtVcProofSuite`; it predates this change and tightening it would
    change what a default caller can pass, so it is left for a separate change. That change is
    #341, later in this release.
  - **One PyJWT path, one claim gate.** Verification runs through the same `_JWT.decode` as
    ES256, so `exp`/`nbf`/`aud`/`sub`/`jti`, the `iss` reconciliation, `crit`, `typ` and the
    SD-JWT-marker gates behave exactly as for ES256 (a 33-case claim matrix and a 15-shape
    signature table assert the same class for both algorithms). The signature is raw `R||S`,
    64 octets, never DER. PyJWT floor: `pyproject.toml` floors `pyjwt>=2.13`, and the
    environment these tests ran in resolves exactly `2.13.0`, the floor itself; its default
    registry carries `ES256K` as SHA-256 on `SECP256K1` (a test pins that on the suite's
    private instance, and openvc's own curve pin does not depend on PyJWT's `expected_curve`).
    CI had no PyJWT floor leg of its own until #340 (this release adds
    `test (py3.10, pyjwt 2.13.0)`, next to the pyld and httpx ones); until then it resolved only
    the newest PyJWT (2.15.1 on 2026-10-16), where the signature segment's encoding is judged
    more strictly than on 2.13.0 (invalid characters and `=` padding are refused); the parity
    tests assert that ES256K gets what ES256 gets on both.
  - **Every other lane keeps refusing the algorithm, twice.** SD-JWT VC (issuer JWT and
    KB-JWT, with and without `allow_pq`), VP-JWT, `verify_compact`, the status-list token,
    the OpenID4VCI key proof (also with `allowed_algs=ALLOWED_ALGS | {"ES256K"}`, which stops
    at `_check_key_binds_to_alg`), the LoTE verifier, the WRPRC lane, COSE (`-47` has no
    `COSE_ALG_TO_JOSE` entry) and `verify_credential`/`verify_many` and the `openvc.aio` twins
    (which build `VcJwtProofSuite(leeway_s=...)` and never opt in) are unchanged, and
    `openvc.keys.verify_signature` still has no secp256k1 branch (a widened `verify_compact`
    allow-list stops there, as `SignatureInvalid`). `openvc_ebsi` has no code change:
    `verify_trust_chain` and `verify_ebsi_badge` take the suite, so the opt-in rides on it;
    only the `trust.py` docstring and the docs say that a Core v1 root needs the keyword.
  - **Evidence that a default caller sees no change.** A differential of 4,346 cases (4 signer
    types x 18 header `alg` values x 6 key shapes through the VC-JWT, ML-DSA-opted VC-JWT,
    `verify_compact`, SD-JWT VC (plain and `allow_pq`), VP-JWT, status-token, OpenID4VCI
    key-proof (plain and widened) and `verify_credential`/`verify_many`/async lanes, plus the
    `keys.verify_signature` primitive, `signing_key_from_jwk`, COSE, WRPRC and LoTE `alg`
    checks) produced identical class and message output on this branch and on `9de784e`; as a
    sensitivity control, the same matrix with the opt-in on differed in exactly 48 rows, all of
    them the VC-JWT lane under header `ES256K`. That differential was a scratch script run once
    by the author, not kept in the repository (as the recorder of the EBSI fixtures is not), so
    the count is a measurement, not a reproducible artifact. What a reader can reproduce is the
    existing suite: every test of `9de784e` passes unchanged against this branch's source (the
    review ran the base corpus on the head source). The fix round that added the two checks
    above touched only the `ES256K` loader and the constructor's validation of the new flag.
  - **Decisions taken** (recommended option of the issue; pending maintainer confirmation, see
    the PR): (1) **lane: VC-JWT only, through the PyJWT path**, not an ML-DSA-style route
    through `keys.verify_signature`, which would duplicate a claim gate that has drifted on
    that lane before and would remove the second gate every other lane keeps. (2) **Low-s:
    both forms verify.** RFC 8812 says nothing about the range of `s` (it does not mention
    malleability), the ES256 path accepts the high-s twin today (tested), and a signer that does
    not normalise `s` emits high-s about half the time, so a refusal would be an availability
    failure on legitimate chains with no basis in the RFC. openvc keeps no state and keys
    nothing on signature bytes. A test pins the choice for ES256K and ES256. (3) **One suite
    for the leaf and the chain hops, no new parameter on `verify_ebsi_badge`.** A consequence:
    an opted-in suite also lets the leaf badge itself be ES256K-signed (tested); the
    alternative, a separate accreditation suite, is an API addition left to the maintainer.
    (4) **Not labelled experimental**: a real vector exists (the recorded RootTAO).
    (5) **No hint in the refusal message.** The issue lists a hint on `UnsupportedAlgorithm`
    for exactly `ES256K` as optional; it is not added, because it would make the refusal
    text differ for a default caller. The docs carry the pointer instead. (6) **A non-bool
    flag is a `ProofError`**, the family of `leeway_s` in the same signature, so a caller that
    catches `OpenvcError` around construction covers it; the alternative is a built-in
    `TypeError` (what the keyword-only rule already raises), which is idiomatic for a wrongly
    typed argument but sits outside the library's taxonomy. (7) **The three RFC 8812 JWK
    members are enforced** (for `ES256K` only) rather than recorded as intentionally ignored;
    the alternative is to leave them ignored, consistent with the classic algorithms, and
    say so.
  - **Evidence.** Golden: the preprod RootTAO accreditation recorded on 2026-10-16
    (`tests/fixtures/ebsi/core-v1/preprod-grnet/attribute_0dc6a111.json`, unedited) verifies
    against the recorded `secp256k1` method with the opt-in and is `UnsupportedAlgorithm`
    without it, through the suite and `verify_ebsi_badge` (through `verify_trust_chain` it is
    `AccreditationInvalid`, whose `__cause__` is that `UnsupportedAlgorithm`); the clock is
    pinned (the token is valid 2026-09-21 to 2031-09-20). The recording holds the RootTAO
    accrediting itself and no leaf under it, so the chain-level golden is the root hop through
    the real path (the walk verifies it and then meets the self-accreditation cycle:
    `TrustChainError`), and "reaches the anchor" is proved on a synthetic ES256K-root,
    ES256-hops chain. The prod seed root's DID document has no verification method, so a prod
    chain cannot close with or without this; the prod RootTAO accreditation also verifies
    under the preprod key (the same `kid` fragment), recorded as evidence of a second real
    ES256K signature, not as a trust path.
- **`openvc_ebsi.nodes.verify_node_list`: a pure Trusted Nodes List verifier**
  ([#319](https://github.com/luisgf/openvc/issues/319), ADR-0009 D2 and D3). EBSI stopped
  publishing a host to call; a client now picks a node from a JSON list signed with OpenPGP
  (`https://tnl.ebsi.eu`). Today an integrator pastes hostnames from a web page into
  `EbsiHttpClient(allowed_hosts=...)` and nothing authenticates them. The new function takes
  the four byte strings EBSI serves (`tnl`, `tnl_sig`, `keys`, `keys_sig`, keyword-only), the
  `environment` (`"pilot"`, `"preprod"` or `"prod"`, the list's own names) and a required
  `now`, authenticates the chain **anchor -> key list -> custodians -> node list** and returns
  a frozen `VerifiedNodeList` bound to that one environment (`nodes` as validated bare
  origins, `hosts` as the lower-case set `EbsiHttpClient` takes, `version`, `keys_version`,
  `issued`, `expires`, and the `accepted_list` / `accepted_keys` pairs to persist), or raises
  a typed `NodeListError`. It reads no clock, opens no socket and keeps nothing (ADR-0007);
  fetching, refreshing and persisting are the caller's. It imports nothing from the `ebsi`
  extra and adds no dependency (`cryptography` only).
  - **Authenticated before parsed.** The only bytes read before a signature is checked are the
    two detached-signature files (capped at 4 KiB). `trusted-keys.json` is parsed after the
    anchor's signature verifies, the custodian key blocks after that, and `tnl.json` only once
    `threshold` distinct custodians have signed it. A signature is attributed to its signer by
    the **hashed** issuer-fingerprint subpacket (type 33) alone: the unhashed area is walked
    for structure only and never used to identify the signer (a malformed one, or a
    critical-bit subpacket in it, rejects the file), a signature by an unknown key or by a
    custodian's *subkey* is ignored, one invalid signature by an allowed key rejects the whole
    file, and a custodian who signs twice counts once. Each custodian fingerprint is recomputed from the key material and must equal the
    listed one; a duplicate custodian is refused by fingerprint and by public point.
  - **The publisher's rules, enforced.** `expires` after `issued` and at most 90 days later
    (the live list is exactly 90.0 days); `now` at or after `expires` is expired; `issued`
    more than 300 s after `now` is not yet valid; `keysVersion` at most the key list's own
    `version`; the node-list `version` higher than the last accepted, or equal only for the
    same SHA-256; every `url` a bare ASCII `https://` origin with its environment's prefix,
    unique across the whole list; `organisation` and `country` as the published JSON Schema
    says. Validation is by hand, over the whole document even though one environment is
    requested, with `fullmatch` and explicit ASCII classes.
  - **Replay bounds, both lists.** The same pair rule applies to the key list as to the node
    list, against `trusted-keys.json`'s own `version` (which the anchor signs), never against
    the node list's `keysVersion`, which the custodians sign. `last_accepted_list` and
    `last_accepted_keys` are required keyword arguments (`Accepted(version, sha256)` or
    `None` on a first run). **`None` is always passable**, so the signature makes the
    obligation visible but cannot make a caller honest; what bounds a caller that persists
    nothing is two version floors shipped in the wheel (`LIST_VERSION_FLOOR` = 4,
    `KEYS_VERSION_FLOOR` = 1, both measured on 2026-10-16), the optional `max_age`
    (off by default) and `min_threshold` (default 2). **A floor can only reject, so it must
    never exceed a version EBSI has published; raise both floors to the newest published
    versions at each openvc release.** A test pins both to be at most the recorded
    versions, so a careless bump fails the suite instead of shipping an outage.
  - **The anchor.** `EUROPEUM_KEY_LIST_ANCHOR` is the key-list key served on 2026-10-16
    (v4, ECDSA P-256, fingerprint `ACCC82E5FC8902F114929481747CB65CFB7574F9`). What was
    checked is that the fingerprint agrees across `tnl.ebsi.eu`, the public TNL repository's
    README and copy of the key, GnuPG's own computation, and the issuer-fingerprint subpacket
    of `trusted-keys.json.sig`; all are Europeum's own channels, so this is consistency, not
    independent proof, and no out-of-band confirmation from Europeum has been sought.
    `Anchor.from_public_key_block(...)` builds your own from a block you obtained out of band
    and recomputes the fingerprint (the override seam the qualified-seal switch will need).
    The key is never downloaded at runtime and the wheel carries no list.
  - **`openvc_ebsi._openpgp`: a minimal, private OpenPGP reader.** It accepts exactly the
    profile the live chain uses: v4, ECDSA over NIST P-256 (the curve matched by its exact
    OID, a SEC1 uncompressed point validated on the curve), SHA-256, signature type 0x00,
    old-format packet headers of 1, 2 or 4 octets, and the one armor shape the recorded key
    blocks have. Everything else is an `OpenPgpError`. Key blocks: exactly one primary key,
    first; user IDs and subkeys are skipped without being read; a self-signature is not
    verified and is refused only if it is a revocation (0x20, 0x28, 0x30) or carries a hashed
    key- or signature-expiration subpacket. A signature file's signatures must each carry
    exactly one hashed creation-time subpacket (type 2, 4 octets; RFC 4880 section 5.2.3.4),
    whose value is not interpreted. Subpackets are never recursed into. Every size and count
    is capped (below). The digest is RFC 4880 section 5.2.4's, reproduced against the real
    signatures. GnuPG 2.5.24 accepts the real chain and a chain the test writer produced and
    rejects the tampered variants the reader rejects; that is **not an equivalence**: the three
    cases where the reader accepts what GnuPG rejects are stated in `docs/audit/assurance.md`
    section 4 and in item 5 below.
  - **Errors.** `openvc_ebsi.errors.NodeListError(EbsiError)` with `NodeListConfigError`,
    `NodeListMalformed` (and its `OpenPgpError`), `NodeListSignatureError`,
    `NodeListThresholdError`, `NodeListRollback`, `NodeListExpired` (also meant for the
    node-based client of #324), `NodeListNotYetValid`, `NodeListStale` and
    `NodeListEnvironmentMissing`. No attacker bytes are echoed beyond a bounded `safe_repr`.
- **`openvc._json.loads(..., reject_ambiguous=True)`.** An add-only, default-off keyword that
  also refuses a repeated object member name (`json` keeps the last) and `NaN` /
  `Infinity` / `-Infinity`. Behaviour without it is unchanged. The TNL verifier uses it, since
  more than one reader will interpret the same signed bytes.

#### Defaults pending maintainer confirmation

Each is one value or table away from the other option. None changes anything that exists.

1. **Profile width** (issue decision 1): P-256 and SHA-256 only, the one profile with a real
   vector. The publisher's own rule allows SHA-256, SHA-384 and SHA-512, so a legitimate
   SHA-384 signature fails closed as `OpenPgpError` (an outage until upgrade). Widening is a
   table entry in `_CURVES` / `_HASHES` plus synthetic vectors.
2. **The pin ceremony** (decision 2): the shipped anchor rests on consistency across
   Europeum's channels only, as worded above.
3. **Persistence shape** (decision 3a): required `last_accepted_*` pairs, not an injected
   store callable. A callable would wrap this function; neither can force an honest value.
4. **`min_threshold` default 2** (decision 3b), the live value: a key list whose `threshold`
   is 1 fails closed (`NodeListThresholdError`) until the caller passes `min_threshold=1`, or
   `None` for no minimum. The alternative is unset by default.
5. **Rules beyond the ADR** (decision 4), each fail-closed and able only to reject: a hashed
   signature-expiration (3) or key-expiration (9) subpacket is refused in signature files and
   key blocks; an unknown **critical** hashed subpacket is refused in signature files (only
   2 and 33 are understood) but **not** in key-block self-signatures, which are not
   interpreted at all beyond revocation and expiry (they are not verified, the key list's
   signature is what vouches for the custodian keys, and refusing one more shape there adds
   an outage risk without protecting anything); duplicate JSON member names
   and `NaN` / `Infinity` are refused; `expires` must be after `issued`; host names must be
   DNS names (labels of 1 to 63 characters, at most 253 in all, no leading or trailing
   hyphen, no trailing dot), which all 45 live hosts are. Two more, from the review of this
   PR (GnuPG 2.5.24 as the oracle: 27 hand-built signature cases and 2482 mutations of
   the two real `.sig` files; none of the 2482 is now accepted by the reader and rejected by
   GnuPG, and of the 27 two remain, the stated divergences of item 8):
   - **A creation time is required.** Every signature in a signature file must carry exactly
     one hashed creation-time subpacket of 4 octets; the real signatures each carry one.
     GnuPG rejects a signature without one (RFC 4880 section 5.2.3.4), so the reader no
     longer accepts it. A *second* one is also refused, although GnuPG accepts it: two values
     for one fact are ambiguous, and the recorded signatures each carry exactly one. The
     value is not interpreted.
     The other option is "at least one": it would accept a signature GnuPG accepts.
   - **A critical bit in the unhashed area is refused**, for any subpacket type. The area is
     walked for structure and nothing in it is interpreted, so the reader can honour no
     critical subpacket there; GnuPG calls a signature with an unknown critical subpacket
     there a bad signature (flipping `0xFF` into the type byte of the real unhashed issuer
     key ID gives GnuPG a bad signature, and used to give the reader the unchanged result).
     GnuPG accepts a critical bit on a type it knows (16, 2, 33) there, so on those the
     reader is stricter. The cost is that whoever can edit the unsigned area can make the
     file fail, which they could already do by corrupting any signed byte. The other option
     ignores the unhashed area entirely and leaves the reader more lenient than GnuPG by this
     case.
6. **Other choices made in the implementation:**
   - fingerprints (the anchor's and the key list's) must be 40 **upper-case** hex characters,
     as the publisher's own check compares gpg's upper-case output as strings;
   - `trusted-keys.json` must have exactly `version`, `threshold`, `keys`, each key exactly
     `fingerprint` and `publicKey`, as `tnl.json` must have its five members;
   - the same public key listed under two creation times (two fingerprints, one signer who
     could name either) is refused;
   - versions above 2**63 - 1 are refused;
   - `organisation` follows the published pattern `^\S(.*\S)?$` read as ECMAScript: first and
     last character not in ECMAScript's `\s`, no line terminator anywhere (the sets were
     measured with node over the whole code space, and a test pins them), at most 200
     characters, no lone surrogate;
   - **no low-`s` rule**: OpenPGP has none and two of the three recorded signatures have
     `s` above n/2, so such a rule would reject real signatures; a high-`s` malleation of a
     good signature verifies and yields the identical result;
   - armor: no header lines, LF only, base64 lines of 1 to 76 characters, the CRC-24 line
     optional but verified when present;
   - caps: `.sig` 4096 bytes, `tnl.json` 256 KiB, `trusted-keys.json` 64 KiB, an armored
     key block 12288 characters (8192 bytes once decoded), 32 packets per file or block, 64
     subpackets per area, 16 custodians, 512 nodes (live: 266 / 7068 / 1811 / 1152 bytes,
     7 packets at most, 2 custodians, 45 nodes);
   - `environment` must be exactly a `str` (a subclass is a `NodeListConfigError`);
   - the checks run schema, then rollback, then `keysVersion`, then the time rules, then the
     environment's presence, so a malformed list is reported as malformed whatever the clock.
7. **Fixtures.** `tests/fixtures/ebsi/tnl/` holds the live chain byte for byte plus the
   previous list (version 3), whose nodes are bare URL strings, the shape the hub's loader
   expects: it is real signed data from the same custodians, but the schema gate, not a floor,
   is what rejects it, so it is **not** a rollback vector (the real chain still has only one
   node-list shape in force). The three key blocks hold **3 OpenPGP User ID packets** shaped
   like a name and an e-mail address; they are covered by the signatures, so they stay, and
   they are not reproduced anywhere in the repository's prose. The upstream repository
   declares **no licence** for these files. Keeping the real chain, or replacing it by a
   synthetic one, is for the maintainer before release. 1.37.0 ships with the real chain; the sdist does
   not carry `tests/fixtures`, so PyPI does not redistribute it.
8. **Stated divergences from GnuPG** (nothing to decide; the reader is not a keyring). In the
   cases measured the reader accepts and GnuPG 2.5.24 rejects: (a) a signature whose
   creation time is 0 or earlier than the signing key's creation time; (b) a custodian key
   whose self-signature key flags lack the signing bit (0x02); (c) a custodian key whose
   self-signature carries a critical subpacket the reader does not know (not refused, by item
   5). Self-signatures are not interpreted beyond a revocation or an expiration subpacket,
   because the key list's signature is what vouches for the key block; closing (b) and (c)
   would add an outage risk without protecting anything, and (a) would need the anchor's
   creation time, which `Anchor` does not carry. A custodian or anchor key that is
   compromised, or a signer that is buggy, is the only way any of them matters, and none
   forges a signature.
9. **Open question 7 (qualified seal)** is not decided: the `Anchor` seam is where a second
   kind of root would attach, as a new class.
- **`RetryPolicy.retry_after_max_s`**
  ([#335](https://github.com/luisgf/openvc/issues/335); it delivers rows (a) and (b) of the
  request-path fixes of [#324](https://github.com/luisgf/openvc/issues/324)). The longest
  ONE sleep between attempts may be, whatever a server asks for with `Retry-After`: every
  sleep is `min(max(backoff, Retry-After), ceiling)`, and a caller's `deadline_s` can still
  only shorten it. `None`, the default, means `backoff_max_s`, looked up when a sleep is
  taken: a policy built with defaults sleeps at most 5 s, one built with `backoff_max_s=60`
  at most 60 s, `dataclasses.replace(policy, backoff_max_s=X)` follows `X`, and the attribute
  itself stays `None`. An explicit value must be a number of seconds from 0 to one day
  (`True`, a string, `nan`, `inf`, a negative and `10**400` are a `ValueError` when the
  policy is built); `backoff_max_s` is not validated, as it never was, and no sleep is longer
  than one day whatever it is, nor negative (a negative `backoff_max_s` sleeps 0 s). An
  add-only field: every existing `RetryPolicy(...)` call, and a `dataclasses.replace` of one,
  still builds. See *Changed* for what the default does to a node that asks for a long wait.
- **`openvc_ebsi.node_client.for_nodes`: a client bound to a verified Trusted Nodes List, with a
  health check and single-node failover**
  ([#324](https://github.com/luisgf/openvc/issues/324), ADR-0009 D5; refs
  [#113](https://github.com/luisgf/openvc/issues/113)). `verify_node_list` (#319) answers "which
  nodes, until when" once, and nothing made the answer last: a service that verified once kept
  trusting that node set indefinitely, and a registry walk that lost its node had nowhere to go.
  `for_nodes(result, *, clock, decode_jwt, ...)` returns an `EbsiNodeClient` for the result's one
  environment (a context manager that owns one pooled `EbsiHttpClient`):

  - **The allow-list is exactly the result's hosts.** There is no `extra_hosts`, no
    `allowed_hosts` (a `TypeError`), no way to merge two results, no `verify_tls`, and
    `EBSI_HOSTS` is never read; the environment label is the verifier's. The result is
    re-validated first, because a `VerifiedNodeList` can be built by hand: a non-empty tuple of
    bare ASCII `https://host` origins of its environment, none twice, each host the origin's,
    checked with the verifier's own rule (`nodes.check_node_origin`, new, which `verify_node_list`
    now calls too), else `NodeClientConfigError` before any `httpx.Client` exists. The client then
    admits `https` at port 443 of those hosts only (#318).
  - **The list's lifetime travels with the client.** The client carries the result's `expires`
    and an injected wall `clock`; at or after it every read raises `NodeListExpired` before the
    host guard, the cache lookup and any socket, and again before every retry (a backoff sleep can
    cross the instant). There is no grace and no refresh: rebuild the client before `expires`.
    A result already expired at the clock's reading is `NodeListExpired` at construction. The
    clock is read through `utc_instant` (a naive value is UTC; a `datetime` subclass cannot change
    the reading, #286), and a clock that returns `None`, a non-`datetime` or raises is
    `NodeClientConfigError`, never "now". The same gate is a general feature of
    `EbsiHttpClient(valid_until=..., clock=...)` (both or neither); without the pair a client is
    unbounded, as before.
  - **Single-node walks.** `run(walk)` calls `walk(session)` on one node from start to end and,
    when that node fails, calls it again, from its first read, on the next candidate. A
    `NodeSession` carries a fresh `DidEbsiResolver` on `base=origin` (adapters `"core-v1"` by
    default) whose only fetch refuses (`HttpForbiddenHost`, before any socket) a URL whose origin
    is not the session's node, with the TIR pin's own comparison (an absent port is 443), so a
    body served by node A cannot steer a read to node B whatever an adapter does with a link. A
    walk must be re-runnable. An attempt during which the session saw a node failure is discarded
    even if the walk caught the exception and returned a value; a swallowed expiry or off-node
    refusal is raised at the end.
  - **What fails over, in one table (`classify`, `node_client._FAILOVER`).** A transport error or
    timeout, a 429 or 5xx once retries are used up, a 403 whatever its body, a 3xx (never
    followed), a body past the size cap or the read deadline, and a failed health check go on to
    the next node, each recorded as a `NodeFailure(origin, kind, status)` with `kind` in
    `unreachable`, `unavailable`, `forbidden`, `redirect`, `limits`, `unhealthy` and nothing else
    (never a body, a header value, a `Location` or an exception message, in the object, the error
    or the log line: one `WARNING` on the `openvc` logger per failover). A node that *answers*
    does not fail over: a 404 is that node's answer (`HttpNotFound` naming it; it does not mark
    the node unhealthy, and confirming it on a second node is not built, ADR-0009 open question
    5), nor does any other 4xx, a malformed 200, an expired list, a configuration error, or an
    error about the content (`AccreditationInvalid`, `NoTrustedAnchor`, `IssuerNotTrusted`, ...).
    When every candidate fails, `NoHealthyNode` carries one `NodeFailure` per node examined.
  - **Health and selection.** `check_health(origin)` is `GET {origin}/v1/alive` through the new
    `EbsiHttpClient.probe(url)`: one attempt, no backoff, never read from or written to the
    response cache, every status returned instead of raised, the body of a non-200 not read,
    capped at 1 KiB. Healthy only on a 200 whose body is a JSON object with `health_global` the
    `int` 1 (not `true`, `1.0` or `"1"`); everything else is unhealthy. `run` probes a candidate
    lazily, one at a time, in the order `policy(origins)` gives (default `random_order`; its output
    is untrusted: a name not in the result, a case or slash variant, a duplicate, an empty
    answer, a non-iterable, a raising policy or a never-ending one is `NodeClientConfigError`
    before any request), remembers the verdict for `health_ttl_s` (a node that failed a real read
    is remembered unhealthy for as long), and lets at most `max_nodes` candidates cost a request
    per `run`; a node is tried at most once per `run`.
  - **`address_guard` is on by default** and `address_guard=None` opts out. The allow-list matches
    host *names*, and these are node operators' own domains (threat model R4), so each request
    resolves the name, refuses a node with any non-public address and connects to the validated
    one. A node whose name points at a private address is failed over from (`unreachable`). The
    guard cannot work behind an environment proxy: `for_nodes` then raises
    `HttpAddressGuardUnavailable` (the existing error of `EbsiHttpClient`) instead of quietly
    dropping the control; unset the proxy, or pass `address_guard=None` to go through it. The
    health probe is one attempt and the guard gives a request one address per attempt, so the
    probe reaches only a node's **first** validated address: a node whose first address this host
    cannot reach (an `AAAA` first, with no IPv6 route) is unhealthy for `health_ttl_s` although
    its reads, which retry, would use the second. It costs availability, not safety; it is said
    in `for_nodes`, `check_health`, `EbsiHttpClient.probe` and the wiki, and pinned by a test.
  - **Every argument is checked before a pooled client is built**, and one out of range is
    `NodeClientConfigError`: never `NoHealthyNode` for what is a configuration error
    (`RetryPolicy(attempts=0)` made no request and read as an outage; so did a negative
    `timeout_s` or `max_response_bytes`), and never a bare exception from the middle of a walk
    (a non-callable or non-numeric `health_clock` was a `TypeError` out of the health memo, a
    negative or `nan` backoff a `ValueError` from `time.sleep`, a `10**400` duration an
    `OverflowError`). `timeout_s`, `cache_ttl_s` and `health_ttl_s` are numbers of seconds above
    0 and at most 10**9; `max_response_bytes` an `int` of at least 1; `retry` a `RetryPolicy`
    with at least one attempt, backoffs of 0 or more and `retry_statuses` a set of `int`s;
    `user_agent` 1 to 256 characters of visible ASCII; `cache` something with `get` and `set`;
    `address_guard` an `AddressGuard` or `None`; `health_clock` a clock that returns a finite
    number, read once at construction and checked at every reading.

  New names: `openvc_ebsi.node_client` (`for_nodes`, `EbsiNodeClient`, `NodeSession`, `NodeFailure`,
  `NoHealthyNode`, `NodePolicy`, `random_order`, `classify`, `FAILURE_KINDS`, `NODE_RETRY`),
  `openvc_ebsi.errors.NodeClientConfigError` (an `EbsiError` and a `ValueError`),
  `EbsiHttpClient.probe` and `ProbeResponse`, `EbsiHttpClient.valid_until`,
  `openvc_ebsi.http.read_clock` and `openvc_ebsi.nodes.check_node_origin`.
  `NodeListExpired` is the existing class of the verifier, reused as its docstring said it would
  be. The issue's module name `nodes.py` is taken by the verifier, so the client is
  `node_client.py`.

  **What was measured** (on the code in this tree, with a virtual clock and the connect timeout
  at its 10 s default, jitter at its ceiling; `test_the_worst_case_walk_time_is_bounded_and_recorded`):
  with `for_ebsi`'s `RetryPolicy()` (3 attempts) a node that never answers costs a walk 30.75 s
  (3 x 10 s plus 0.25 s and 0.5 s of backoff), so a `run` over three dead nodes costs up to
  92.25 s; with `NODE_RETRY` (2 attempts, the `for_nodes` default) 20.25 s and 60.75 s; and a node
  that fails its probe costs one 10 s attempt, 30 s for three. `/v1/alive` was read once on
  2026-10-19 from `api.ebsi.iti.gr` and `api.ebsi.edelivery.lt`: both 200,
  `application/json; charset=utf-8`, the 19-byte body `{"health_global":1}`, no cache validators
  (`tests/fixtures/ebsi/alive/`); a third request, to `api-preprod.ebsi.grnet.gr`, got no
  connection in 20 s and was not repeated. The 503 `{"health_global":0}` the hub documents was
  not seen, so it is a synthetic input in the tests, labelled so.

  **Defaults taken, pending maintainer confirmation** (the issue left each to the
  implementation; each is one line to change):
  1. *The module is `node_client.py`.* The issue's `nodes.py` is the verifier (#319).
  2. *`address_guard` is on by default in `for_nodes`, with `address_guard=None` as the opt-out*
     (#322's recommendation for list-derived hosts). The other option, off by default, would
     leave the DNS-rebinding exposure of operator-run names to the caller's care. Behind an
     environment proxy `for_nodes` **raises** `HttpAddressGuardUnavailable` rather than build
     without the guard; the other option is to fall back silently, which this does not do.
  3. *`HttpForbiddenAddress` (a listed name resolving to a private address) is a failover*, kind
     `unreachable`, not a propagated `HttpForbiddenHost`. The issue's table lists
     `HttpForbiddenHost` as propagating, and an off-node URL still does; an address refusal is
     about one operator's DNS, and propagating it would let that operator's zone fail a `run`
     whenever the policy picks the node. The other option propagates it.
  4. *`for_nodes` retries twice, not three times* (`NODE_RETRY`, the measurement above);
     `for_ebsi`'s defaults are unchanged. `max_nodes=3`, `health_ttl_s=60` and the 1 KiB probe cap
     are the issue's proposals, not facts about EBSI.
  5. *Only a failure the session saw is the node's.* A walk's own fetches through some other client
     are not blamed on the node. Any `EbsiError` raised after the session saw a node failure fails
     over (the verdict was built on a failure), and a swallowed terminal error is re-raised.
  6. *`classify` also calls an unretried 429 or 5xx (a 501, a 507) `unavailable`*; every other 1xx,
     2xx and 4xx status propagates.
  7. *`check_health` always sends a fresh probe* and updates the verdict `run` reuses; a node
     failing a real read is memoised unhealthy only through `run`, not through a bare `session`.
  8. *A candidate known unhealthy inside its TTL is a free skip* and is listed in `NoHealthyNode`,
     so when every node is known bad the error costs no request until the TTL passes.
  9. *`NodeClientConfigError` is also a `ValueError`*, like `UnknownEbsiEnvironment`, so the
     issue's "`ValueError` for exactly one of the pair" and its "`NodeClientConfigError` for a
     bad clock" are one class.
  10. *The shipped client still reads a 403's body* (bounded, #321) for `HttpError.problem_type`,
      an opaque validated string; `run` does not surface it for a node it fails over from, and
      does for a node's *answer* (a 404 or another 4xx), as does a bare `session.get_json`. The
      issue's "the body is never parsed" row is therefore met on the failover path (nothing of a
      failing node's answer reaches a `NodeFailure`, a `NoHealthyNode` or the log line), not by
      changing the shared error path, which still parses it for `type`.
  11. *Not done here, on purpose:* the issue's three request-path fixes. The `Retry-After` bound
      and parsing (a, b) are #335's; the unbounded error-body read (c) already landed with #321.
      `docs/audit/assurance.md` section 4 got its entry at release time (from the review round of
      PR #349), and ADR-0009's status now records D5 as implemented.
  12. *`for_nodes` checks every argument, with bounds of its own* (review round). The bounds are
      mine: durations at most 10**9 s (about 31 years; it only keeps `float()` and a socket
      timeout in range), a `user_agent` of 1 to 256 characters of visible ASCII (measured with
      httpx on loopback: a CR, LF or NUL is a `LocalProtocolError` on every request, an outage to
      a walk, and a non-ASCII value a `UnicodeEncodeError` out of the constructor; the length
      bound and the refusal of an empty value are mine, httpx sends both), a
      `health_clock` reading within +-2**63, and `cache_ttl_s` above 0 (a `TtlCache` does not
      give a TTL of 0 the meaning "no caching": an entry read at the same instant is still
      fresh). The checks live in `for_nodes`, not in `RetryPolicy` (#335's), so a
      `RetryPolicy(attempts=0)` handed straight to an `EbsiHttpClient` is unchanged. The other
      option is to pass these through unchecked and narrow the docstring's "every argument is
      checked": a bad value is then an outage report or a bare exception, as before.
  13. *The health probe tests a node's first validated address only* (documented, not changed;
      review round). The other option lets a probe try the next validated address after a
      transport error, within one request per address: it changes "one attempt" and the shape of
      `_request`'s loop, which #335 also edits, and makes a dead dual-stack node cost
      `timeout_s` once per address. This takes the cheaper, documented option; how often it bites
      in practice is not measured.

### Changed

- **A URL on an allow-listed host with a port other than 443 is now `HttpForbiddenHost`**
  (#318). It used to be fetched. Who is affected: a caller that gives `for_ebsi(extra_hosts=...)`
  a status-list or other host and then fetches it on a non-default port (`:8443`), and a
  `DidEbsiResolver` whose `base` names a port (`https://api-pilot.ebsi.eu:8443`) used with
  the real `EbsiHttpClient`. Whether any consumer does either is not measurable from this
  repository. What to do instead: serve it on 443 (an absent port is 443; `:443` also works),
  or give the resolver or the status check a `Fetch` of your own for that host. There is no
  opt-in for another port, on purpose (see the decisions below).
- **A URL with userinfo is now `HttpForbiddenHost`** (#318), for example
  `https://user:password@api-pilot.ebsi.eu/x`, which used to be fetched with a Basic
  `Authorization` header. Drop the userinfo from the URL.

  **Decisions taken, pending maintainer confirmation** (#318 lists them with the other option
  of each):

  - *Other ports*: refused with no opt-in (ADR-0009 D1: "host and port 443"). The alternative,
    a per-entry `host:port` syntax, re-opens the hole.
  - *Empty port* (`https://host:/x`): admitted, for parity with `_origin`, which already folds
    it to 443, and because both parsers read it as no port. The alternative is to refuse it
    as stricter than httpx.
  - *Userinfo*: refused in the guard, since the list guarantees none. The alternative is to
    leave it and file it separately.
  - *Release placement*: a minor (1.37.0), the behaviour change stated here (precedent: #172,
    #253). Holding it for 2.0 (#74) is the alternative.
- **`EbsiHttpClient` keeps no cookie jar**
  ([#317](https://github.com/luisgf/openvc/issues/317); ADR-0009, "Where each design can
  be attacked", row "Cookie jar"). The pooled `httpx.Client` used httpx's default jar, so a
  `Set-Cookie` from an allow-listed host was stored and sent back on later requests from
  that client. The client has no use for that: `get_json` is a stateless GET reader whose
  only state is the TTL cache (ADR-0001 D2), and before this change nothing in `src/` or
  `tests/` read a cookie. The jar is now a bare `http.cookiejar.CookieJar` whose policy
  refuses every cookie in both directions, so a `Set-Cookie` is dropped and nothing is
  ever sent back: not on the next request, not on a retry after a 5xx that set one, not to
  a sibling host that the cookie's `Domain` would have reached. **This is a behaviour
  change:** a node's affinity cookie (the two `edelivery.lt` hosts of ADR-0009 set an
  `SRV_ID`) is no longer returned, so consecutive reads of one registry walk (issuer
  record, attribute pages, revisions) may reach different backends of one node. Nothing
  in `openvc_ebsi` reads a cookie or assumes same-backend reads, and the trust model
  already treats a node as one unauthenticated source; whether the backends behind one
  node disagree has not been measured. No new public name, constructor option, error
  class or dependency; every other `httpx.Client` argument, and every error class
  `get_json` raises, is unchanged.
  - **`set_ok` is the load-bearing method.** httpx copies the client's jar into a fresh
    default-policy one when it builds a request, so `return_ok` and the other two methods
    are never consulted on the send path (a policy that stored the cookie and refused only to
    return it still sent it). They are kept as defence in depth and pinned directly.
  - **The jar is a bare `CookieJar`, and must stay one.** httpx keeps only that as given; an
    `httpx.Cookies`, a dict or a list is rebuilt with the default policy, which would lose
    the refusal silently.
  - **Measured** on httpx 0.28.1 and CPython 3.14.8 (`httpx.MockTransport`, a synthetic
    `SRV_ID` cookie): the cookie came back on the next request, on the retry after a 503 that
    set it, and, with `Domain=ebsi.edelivery.lt`, on a request to the sibling host; twelve
    hostile `Set-Cookie` values (empty, `=`, bad `Expires` / `Max-Age`, a 5 000-digit
    `Max-Age`, non-ASCII bytes, 20 000 attributes, a 1 MB value, an unbalanced quote,
    `Domain=.`) neither raise nor warn and leave the jar empty. The floor `httpx>=0.27` was
    read, not run: `Cookies.__init__` keeps a non-dict, non-list, non-`Cookies` argument as
    the jar and `_merge_cookies` copies the client's jar into a new `Cookies` only when it is
    non-empty, identically in the 0.27.0 wheel (`_models.py`, `_client.py`). CI has no httpx
    floor leg.
  - **Defaults pending maintainer confirmation** (#317, "Decisions to take"; the
    recommended option was taken in each case): (1) *disable the jar* rather than leave it
    and document it; documenting it would keep affinity as an ambient property of the
    client. (2) *a cookie policy* rather than a null `CookieJar` subclass; the null jar never
    parses `Set-Cookie` but depends on httpx calling two methods on that attribute, the
    policy is the documented stdlib hook and leaves the jar an ordinary jar. (3) *no public
    switch to re-enable cookies*; a deployment that wants affinity expresses it in a node
    selection policy (#324), not in a client option.
- **`for_ebsi()` now defaults to `"legacy-pilot"`** (it was `"pilot"`), with the identical
  allow-list `{"api-pilot.ebsi.eu"}`: a bare `for_ebsi()` builds the same client as before and
  warns nothing. It is not a default that changes a security decision (the versioning
  policy's MAJOR case), so it ships in a MINOR. `DidEbsiResolver`'s default `base` now reads
  the same table (`openvc_ebsi.environments.LEGACY_PILOT_BASE`) instead of repeating the
  literal; the value, `https://api-pilot.ebsi.eu`, is unchanged. The opt-in weekly smoke
  (`test_live_resolve`) now defaults `OPENVC_EBSI_ENV` to `legacy-pilot`.
- **A name `for_ebsi` does not know is now `UnknownEbsiEnvironment`, which is a `ValueError`.**
  `except ValueError` keeps catching it, as the versioning policy's rule for a more specific
  subclass of the old class requires (MINOR). Code that compares the exact class
  (`type(exc) is ValueError`) must compare `UnknownEbsiEnvironment`, or catch `ValueError`.
  **One thing that used to succeed now raises:** a value that is not a `str` but hashes and
  compares equal to a name (`collections.UserString("pilot")`) was accepted by the old
  dictionary lookup; it is refused by the `str` type check. Pass `str(value)`. A
  `str` or a `str` subclass (a `(str, Enum)` member, say) that holds a name is unaffected.
- **Defaults taken, pending maintainer confirmation.** #325 leaves three switches to the
  maintainer; Part 1 ships only the unconditional one and takes the non-breaking option on the
  other two, so nothing is deprecated or removed here and each can still go either way (Part 2,
  later in this release, took 2b for `pilot`: see its entry):
  1. *Switch 1, add `legacy-pilot`:* done, as above.
  2. *Switch 2, `pilot`: 2a (taken)* leaves `pilot` silent and documents it as the same lane
     as `legacy-pilot`. The alternative, 2b, would emit a `DeprecationWarning` naming
     `legacy-pilot` from `for_ebsi("pilot")` (MINOR; the versioning policy's steps 1 to 3 would
     apply: `### Deprecated` here with the earliest removal, removal only at a MAJOR).
     A test pins that `pilot` is silent, so adding the warning later is a conscious edit (Part 2
     made that edit).
  3. *Switch 3, `production` and `conformance`: 3a (taken)* keeps both rows, with the same
     allow-list rule, and documents them plainly (`wiki/Trust.md`, `for_ebsi`'s docstring,
     `environments.py`). The alternatives: 3b, a `DeprecationWarning` from `for_ebsi` (there is
     no replacement to name for either until the node-based client of #324, so the message
     would have none); 3c, `for_ebsi` refuses, keeping the keys (a documented, pinned call that
     built a client would raise, which the versioning policy reads as MAJOR unless the
     CHANGELOG records a narrow decision, as 1.35.0 did for `did:key`); 3d, remove the keys
     (MAJOR, and `test_for_ebsi_production_environment_is_registered` pins them). A test pins
     that both are silent.

  **Migration notes, whichever option is chosen later.** (i) In 1.x the Core API pilot that the
  Trusted Nodes List calls `pilot` has no `for_ebsi` spelling, because `pilot` stays the legacy
  lane until a MAJOR release. The node-based constructor, `for_nodes` (#324, this release), takes
  the list's own spelling, so `for_ebsi` need not carry it; a 1.x spelling would be a new name for the
  maintainer to choose (ADR-0009's end state calls it `pilot`). (ii) At that MAJOR (the 2.0
  window, [#74](https://github.com/luisgf/openvc/issues/74); not decided), `pilot` may change
  meaning. A caller who ignored the warning (2b) or the documentation (2a) would then read a
  different ledger, where ADR-0009 measured the legacy DID to be a 404. Use `legacy-pilot`
  today to say which one you mean.
- **A TIR attribute response without an `attribute` object is `MalformedRegistryResponse`**
  (both lanes, `TirV5` and `TirCoreV1`). It used to be read as an empty attribute, which is
  an accreditation with no type restriction, and single-level trust
  (`evaluate_issuer_trust`) accepts such an accreditation for any credential. A registry
  that answers `{"did": ...}` or `{"attribute": null}` for an `href` is malformed, not
  unrestricted; there is nothing to pass instead, the walk now stops with a typed error.
  Recursive trust was unaffected (an accreditation with no token is refused).
  This is a shape check, not the end of the wildcard: an `attribute` object with no `body`,
  an empty `body`, or a `body` whose claims name no `accreditedFor` is still an
  accreditation with no type restriction, which single-level trust accepts for any
  credential (its documented policy: that mode trusts the node's list). Recursive trust
  refuses one that has no token (`AccreditationInvalid`) and otherwise needs a token that
  verifies. Pinned by `test_an_attribute_object_with_no_usable_body_is_still_a_wildcard_by_design`
  and its neighbour.
- **`openvc.fetch` refuses the deprecated IPv6 site-local prefix `fec0::/10`**
  ([#322](https://github.com/luisgf/openvc/issues/322), review round).
  `ip_is_forbidden` (and so `did:web` and every fetch that resolves through
  `_resolve_public_ips`) used to accept it: `ipaddress` reports `fec0::1` as
  `is_global=True`, `is_private=False` and sets only `is_site_local` (measured on CPython
  3.13.16, 3.14.8 and 3.15.0rc3), so nothing in the flag union caught it. RFC 3879
  deprecated the prefix and it is not globally routable. A `did:web` (or status-list or
  schema) host whose DNS answer includes a `fec0::/10` address now raises
  `UnsafeUrlError` where it used to connect. There is nothing to pass instead: a publicly
  reachable host does not resolve to this prefix; fix the DNS record. Only IPv6 has the
  property, so IPv4 classification is unchanged.
- **`allow_pq` must be exactly `True` or `False` on both JOSE suites**
  ([#341](https://github.com/luisgf/openvc/issues/341)). `VcJwtProofSuite(allow_pq=...)` and
  `SdJwtVcProofSuite(allow_pq=...)` read the flag by truthiness, so any truthy value switched
  the EXPERIMENTAL ML-DSA algorithms (RFC 9964) on. Measured on `main` at cf6d100 (CPython
  3.14.8): `allow_pq="false"`, `"0"`, `"x"` and `1` all constructed and put `ML-DSA-44`,
  `ML-DSA-65` and `ML-DSA-87` in the suite's allow-list, while `""`, `0`, `None` and `[]`
  silently meant off. A deployment that reads the flag from an environment variable or a
  configuration file as a string therefore enabled a post-quantum verify path it meant to
  disable. Anything but the `bool` `True` or `False` is now refused at construction: a
  `ProofError` on `VcJwtProofSuite`, a `SdJwtError` (a `ProofError`, like that constructor's
  other checks) on `SdJwtVcProofSuite`, with the message `allow_pq must be True or False, got
  str`, which names the type and never echoes the value. It is the rule `allow_es256k` has
  had since #323 (`type()`, not `isinstance()`, so an object whose `__class__` claims `bool`
  is refused too); on `VcJwtProofSuite` the two flags are checked in signature order, after
  `leeway_s`. **Who is affected:** a caller that passes a string, a number, `None` or any
  other non-bool, including the falsy values that used to mean off (`0`, `None`, `""`).
  **What to pass instead:** `True` or `False`, or leave the argument out (the default is
  `False`); parse a configuration string yourself before constructing the suite. `True`,
  `False` and the default behave exactly as before. The grep of every `allow_*` in `src/`
  found `allow_pq` on the two suites (fixed together, because both guard the same algorithm
  family), `allow_es256k` (strict since #323) and two private keywords, `allow_scalar` in
  `rp_registration._str_tuple` and `allow_string` in `status._index.status_index`, which every
  call site sets with a literal and which guard no algorithm family or trust decision: they are
  left alone (`allow_nan=False` in `_context_validation` is a `json.dumps` argument).
- **The TIR adapters check the JSON type of every scalar they copy into the model, and
  `hasAttributes` must be a JSON boolean**
  ([#337](https://github.com/luisgf/openvc/issues/337); found by the review of #332).
  Hardening; no wrong-accept was found against a node that follows its published schema.
  The adapters in `openvc_ebsi.versioning` copied registry members into `Accreditation` and
  `IssuerRecord` as sent. Measured on `cf6d100` (CPython 3.14.8) through
  `DidEbsiResolver.issuer_record`: `"hasAttributes": "false"` (and `"0"`, `"true"`, `1`) read
  as `has_attributes=True`, so the walk went on to fetch the listing and every revision,
  while `""`, `0`, `[]`, `{}` and `null` read as `False`; an `issuerType`, `tao`, `rootTao`
  or `hash` that was an object, an array, a number, a boolean or `null` was stored in the
  record as sent, on v4, v5 and Core v1 (a `hash` only where it was the value copied: always
  on v4, and on v5 and Core v1 only when the listing item had no usable `id`); a listing
  item `id` that was an object, an array, a
  number or `true` was stored as sent, while `0`, `false`, `[]`, `{}` and `null` fell through
  to the attribute's `hash`; and a v4 attribute `body` that was not a string reached the
  proof suite's `decode` and raised a bare `AttributeError` (v5 and Core v1 had typed it in
  #321). The consumers are few: the trust walk compares `tao` with the token's `iss` and
  fails with `AccreditationInvalid`, nothing in the library reads `rootTao` or `attribute_id`, and
  `is_revoked` is `issuer_type == "revoked"`, which is false for any value that is not that
  string, so an `issuerType` of the wrong type read as "not revoked".

  Each field is now checked against the type the model declares, and a wrong one is
  `MalformedRegistryResponse` (`TIR attribute tao is not a string: 7`; the value goes through
  `safe_repr`, so an attacker-sized one is bounded):

  | member | where | accepted | absent | `null` |
  | --- | --- | --- | --- | --- |
  | `hasAttributes` | v5, Core v1 issuer response | `true`, `false` only | `false` | raises |
  | `id` | v5, Core v1 listing item | string | `""` | raises |
  | `issuerType` | v4 attribute; v5, Core v1 `attribute` | string | `""` | raises |
  | `hash` | v4 attribute, always; v5, Core v1 `attribute`, only when the listing item's `id` is absent or empty | string | `""` | raises |
  | `tao`, `rootTao`, `body` | v4 attribute; v5, Core v1 `attribute` | string | `None` | `None` |

  `hasAttributes` is tested with `isinstance(value, bool)`, not by truth, so `"false"`, `0`
  and `[]` are wrong values and not falsy ones; a non-boolean raises after the one request
  for the issuer response, before the listing is fetched. A listing item's `id` is typed
  before it can fall back to the attribute's `hash`, so `0`, `false`, `[]` and `null` no
  longer fall through; on v5 and Core v1 the `hash` is read only when the `id` is absent or
  empty, which is the only case in which it is copied (a `hash` of any type next to a usable
  `id` parses, and the `id` is the attribute id; on v4, which has no listing, it is always the
  attribute id and always typed). Every scalar of an entry is typed before the proof suite's
  `decode` is handed its token, and one bad entry rejects the whole record, as a revision with
  no `attribute` object already did (a partial record would be a trust decision made on part
  of the registry's answer). The `body` message of v5 and Core v1 keeps its text and gains
  the value (`TIR attribute body is not a string: 7`).

  Who is affected: a node that sends what its schema says is not, and there is nothing to
  migrate. A differential over the four recorded walks (the pilot's v5 response, the two
  preprod Core v1 nodes and the production seed) gives the same `IssuerRecord`, as canonical
  JSON, on `cf6d100` and on this change (the script was a one-off and is not kept), and every
  existing EBSI test passes unchanged. What changes is a registry or a hand-written `Fetch`
  that sent a member with the wrong JSON type: `hasAttributes` as a number or a string, a
  number as the `hash` that is copied (see the table), `null` as `issuerType`. It used to be carried through (or, for
  `hasAttributes`, read by truth) and is now `MalformedRegistryResponse`; send the type the
  real registry sends (`true`, a string). There is no recorded TIR v4 response in this
  repository, so the v4 cases are synthetic, around a recorded accreditation token.

  SemVer: a wire value that used to be carried through now raises, so the entry is recorded
  as a change and not only as a fix; it rides in the unreleased 1.37.0 (a minor), so it needs
  no bump of its own. Alone it would be a patch: it narrows what the adapters accept to what
  the model already declared, and no shipped path turned the old behaviour into an accept.

  Defaults taken, for the maintainer to confirm: (1) `null` is wrong for the `str` and `bool`
  members and is `None` for the `str | None` ones, following the model; reading `null` as
  absent instead would carry `""` / `False` through for the first group. (2) An absent
  `hasAttributes` stays `false`, as before; making it a required member would turn a response
  without it into `MalformedRegistryResponse`. (3) A `hash` that is not copied is not read
  (v5 and Core v1 next to a usable `id`; on v4 it is always copied, so always typed); typing
  it always would reject a record for a member nothing uses. (4) One bad entry rejects
  the record; skipping it would hide an accreditation without saying so. (5) Not covered, and
  left as it was: a v4 `attributes` member that is not an array, or an entry of it that is not
  an object, is a bare `TypeError` / `AttributeError` (measured on `cf6d100`; v4 only, since
  the shared walk skips non-object items). It is a shape check and not a scalar.
- **The maintainer's decisions on #325's three switches, taken on 2026-10-19**
  ([#325](https://github.com/luisgf/openvc/issues/325), Part 2; recorded in ADR-0009 as the
  answer to open question 4). Part 1 had taken the non-breaking option on switches 2 and 3 as
  defaults pending this answer; the answer replaces them:
  1. *Switch 1, add `legacy-pilot`:* done, as above.
  2. *Switch 2, `pilot`: 2b.* `for_ebsi("pilot")` emits a `DeprecationWarning` naming
     `legacy-pilot` and keeps seeding the same allow-list; see **Deprecated** below. A bare
     `for_ebsi()` and `for_ebsi("legacy-pilot")` warn nothing. It is a MINOR: the versioning
     policy's steps 1 to 3 are followed (the name keeps working, the warning names the
     replacement, the entry below gives the earliest change). The alternative, 2a (leave
     `pilot` silent and re-mean it at 2.0), is not taken.
  3. *Switch 3, `production` and `conformance`: 3a.* Both rows are kept, unchanged, with the
     same allow-list rule, and documented plainly (`wiki/Trust.md`, `wiki/EBSI-Node-Trust.md`,
     `for_ebsi`'s docstring, `environments.py`). **No warning and no refusal.** A test pins that
     both are silent and still build a client. The alternatives are not taken: 3b, a
     `DeprecationWarning` (there is no replacement to name for either until the node-based
     client of #324); 3c, `for_ebsi` refuses, keeping the keys (a documented, pinned call that
     built a client would raise, which the versioning policy reads as MAJOR unless the CHANGELOG
     records a narrow decision, as 1.35.0 did for `did:key`); 3d, remove the keys (MAJOR, and
     `test_for_ebsi_production_environment_is_registered` pins them). So `for_ebsi("production")`
     does not raise `ValueError`; a request through it still fails closed, late, as
     `HttpTransientExhausted` when the connection fails (pinned with a stubbed `httpx.ConnectError`
     in `test_ebsi_environments.py`).

  **Migration notes.** (i) In 1.x the Core API pilot that the Trusted Nodes List calls `pilot`
  has no `for_ebsi` spelling, because `pilot` stays the legacy lane until the MAJOR release.
  The node-based constructor, `for_nodes` (#324, this release), takes the list's own spelling,
  so `for_ebsi` need not carry it; a 1.x spelling would be a new name for the maintainer to choose (ADR-0009's end
  state calls it `pilot`). (ii) At that MAJOR (the 2.0 window,
  [#74](https://github.com/luisgf/openvc/issues/74)) `pilot` changes meaning. A caller who
  ignored the warning would then read a different ledger, where ADR-0009 measured the legacy DID
  to be a 404. Use `legacy-pilot` today to say which one you mean.
- **A `Retry-After` above the policy's ceiling is no longer honoured in full**
  ([#335](https://github.com/luisgf/openvc/issues/335)). `get_json` and `get_bytes` used to
  sleep as long as a node asked, `attempts - 1` times: `Retry-After: 86400` on a 429 was two
  sleeps of a day. With the default `RetryPolicy` no sleep is longer than 5 s now
  (`retry_after_max_s`, which defaults to `backoff_max_s`, so the same holds for a policy you
  built: its `backoff_max_s` is its ceiling unless you set `retry_after_max_s`; measured:
  `RetryPolicy(backoff_base_s=0, backoff_max_s=0)` slept a `Retry-After: 30` for 30 s, twice,
  and now sleeps 0 s); the call still retries
  `attempts` times and then raises `HttpTransientExhausted` as before, so a rate-limiting node
  is asked again sooner than it said and may answer 429 again. What to pass instead: a policy
  with a higher ceiling, `RetryPolicy(retry_after_max_s=60.0)`, on the client (`retry=`), or
  a larger `attempts`. A `Retry-After` of 0 and the small values are still slept as asked, up
  to the ceiling. The value is also read more strictly (see *Fixed*): ten digits and more are
  ignored, where a value past about 9.2e9 s used to be an `OverflowError` and a smaller one a
  sleep of up to 292 years; and a delta-seconds written with another script's decimal digits
  (`١٢٣`, Devanagari, fullwidth) or padded with a no-break space or another Unicode space was
  read as that many seconds (measured: `١٢٣` slept 123 s, `5` and a no-break space slept 5 s)
  and is ignored now, so the client keeps its own backoff.
- **`get_json` accepts one `gzip` or one `deflate` coding and nothing else, and asks for
  those** ([#335](https://github.com/luisgf/openvc/issues/335)). It used to hand a 200 body to
  httpx, which decoded whatever it supports. Now a `Content-Encoding` of `br`, `zstd`,
  `x-gzip`, `compress`, a list of codings (`gzip, gzip`, `identity, gzip`) or anything else
  that is not `identity`, `gzip` or `deflate` is `HttpUnexpectedEncoding` (an `HttpError`,
  status 200, not retried, the body unread), as it already was for `get_bytes`; a `deflate`
  body must be the zlib format, what `zlib.compress` writes (httpx fell back to a raw deflate
  stream, which was accepted and is now `MalformedRegistryResponse`); and bytes after the end of a compressed stream (a
  trailing byte, a second gzip member) and a truncated stream are `MalformedRegistryResponse`
  where httpx dropped the bytes or accepted the body (measured: a gzip body missing its
  trailer, and `gzip.compress(b'{"ok": 1}' * 50)[:20]`, a stream cut after 20 bytes, came
  back as `{"ok": 1}`). The client now sends `Accept-Encoding: gzip, deflate`
  by default (httpx added `br` and `zstd` when their packages were installed, which this
  client cannot read inside a cap); `get_bytes` still sends `identity`. A corrupt 200 body is
  `MalformedRegistryResponse` with the `zlib.error` as its `__cause__` (it was an
  `httpx.DecodingError`; an error body still reports that one). The messages changed too:
  `response exceeds N bytes once decoded` for the decoded size and `read exceeded its deadline`.
  A compressed body whose wire size alone is over `max_response_bytes` is refused even if it
  would decode under it (only an incompressible body within a few bytes of the cap is
  affected). If a registry you read sends a coding other than these, the call now fails with
  `HttpUnexpectedEncoding`; there is no opt-in, so ask the operator to serve `gzip` or no
  coding.
- **Defaults pending maintainer confirmation** ([#335](https://github.com/luisgf/openvc/issues/335);
  for each, what the other option would change):
  - `retry_after_max_s` is a new field although #335's own scope line said "no change to
    `RetryPolicy`'s fields": the design is #324's, because that issue's acceptance needs the
    bound and two changes must not implement `Retry-After` twice. It is add-only;
  - its default is `backoff_max_s` (5 s), looked up when a sleep is taken: the field stays
    `None` and is not filled in when the policy is built, and it is not a literal 5.0. A literal
    would clamp the backoff of a policy that raised `backoff_max_s` alone, and so did a number
    filled in at construction for a policy derived with `dataclasses.replace(policy,
    backoff_max_s=X)` (measured: it kept the old 5 s and cut the backoff at it, and a
    `replace` of a policy built with `backoff_max_s=1e6` was a `ValueError`). The other option,
    filling it in at construction, makes the attribute read the effective number (5.0) at those
    two costs; a read-only property could give the number without them. A ceiling below
    `backoff_max_s` lowers the backoff's ceiling too, because the bound is on every sleep
    (`min(max(backoff, Retry-After), ceiling)`); capping only the `Retry-After` term
    (`max(backoff, min(Retry-After, ceiling))`) would differ only for such a policy;
  - a `Retry-After` that is not one to nine ASCII digits or an HTTP-date (a run of ten digits
    or more, which is 31 years and up) is ignored, so the client keeps its own backoff; clamping
    it to the ceiling instead would differ only when `retry_after_max_s` is above
    `backoff_max_s`, where it would wait longer;
  - only spaces and tabs around the value are dropped (HTTP optional whitespace), where
    `str.strip()` also dropped other Unicode whitespace (a no-break space around a number was
    read as seconds); an HTTP-date is tried only on a
    value of at most 64 ASCII characters (the three forms are 29, 33 at most, and 24);
  - an explicit ceiling outside 0 to one day is a `ValueError` at construction (one that
    follows `backoff_max_s` is not checked, as `backoff_max_s` never was); and no single sleep is
    ever above one day (`_MAX_DEADLINE_S`) whatever the policy, because a policy whose
    `backoff_max_s` is huge would otherwise let an HTTP-date in the year 9999 reach
    `time.sleep` as an `OverflowError` (it raises from about 9.2e9 s);
  - the default `Accept-Encoding` is `gzip, deflate`; `identity` (no compression at all) would
    be simpler and would cost bandwidth on large registry pages, and httpx's own default
    would keep advertising `br` and `zstd` when installed, which are then refused;
  - the codings above are refused rather than decoded: decoding `br` or `zstd`, a chain of
    codings, or a raw deflate stream inside the cap would need a decoder per coding that is
    bounded the way `zlib` is;
  - a response a test double built with `content=` and a `Content-Encoding` of `gzip` or
    `deflate` is read as httpx left it (decoded, in memory) under the same cap, by `get_json`
    and by `get_bytes`. `get_json` served it before this change, and `get_bytes` has raised a
    bare `httpx.StreamConsumed` on it since it was added (#331). Refusing it with a typed
    `HttpError` instead would have kept `get_bytes`'s outcome and turned every such downstream
    double into an error. No socket hands over a consumed stream, so nothing on the wire
    reaches this;
  - a negative ceiling sleeps 0 s (it raised from `time.sleep` before): `backoff_max_s` is
    not validated, so `RetryPolicy(backoff_max_s=-1)` can be built, and its ceiling bounds
    every sleep, which `time.sleep` refuses with a `ValueError` below zero. The sleep is
    `time.sleep(max(0.0, delay))`. Measured on `main` at cf6d100 (a 503, three attempts, the
    default `backoff_base_s`): with no `Retry-After` that policy was a bare `ValueError` out of
    `get_json`; with `Retry-After: 30` it slept 30 s twice and ended in
    `HttpTransientExhausted`, there being no ceiling, and it now sleeps 0 s twice and ends in
    the same exception. No wire value makes the delay negative (a parsed `Retry-After` is
    never negative and the caller's budget is clamped at 0), and an explicit
    `retry_after_max_s` is validated from 0, so only `backoff_max_s` reaches this. The other
    option, refusing a negative `backoff_max_s` with a `ValueError` when the policy is built,
    would make a policy that builds today fail at construction, and would validate a field
    that never was.
  - **Not changed, a finding:** the read of a non-200 body (#321) still decodes with
    `iter_bytes`, so one small `gzip` error body inflates a whole chunk before its 16 KiB
    check fires (measured: a 260 935-byte body that inflates to 256 MiB peaks at 557 MiB on a
    403). It is the same class as the 200 read fixed below and needs its own change: it must
    keep returning `None` for a body it cannot use and `HttpNotFound` for a 404 whatever the
    coding. Done in #350 (*Security*, above).
- **`HttpTransientExhausted.status` can now be set** (#324). It was always `None`; it is now the
  last attempt's HTTP status (a 429 or a 5xx) and is still `None` when that attempt never got an
  answer (a transport error, a timeout, an address the guard could not resolve), which is how the
  node client tells `unavailable` from `unreachable`. Who is affected: code that read
  `exc.status is None` to mean "retries exhausted" must compare the class instead. Nothing else
  of `get_json` or `get_bytes` changes for a caller that does not pass `valid_until` and `clock`
  (no gate, no clock read); `probe` is a new method on the shared request loop, not a change to
  the other two. An exhausted probe says "gave up after 1 attempts".
- **`openvc_ebsi.nodes` has a public origin rule** (#324): `check_node_origin(url, environment)`
  is what `verify_node_list` applied to every node, now named. `_node` calls it with the
  messages it always had (the Trusted Nodes List suites pass untouched). The issue asked for exactly this: a client built from a result that may be hand-built
  re-checks the nodes with the verifier's own rule instead of a copy of it.

### Deprecated

- **`for_ebsi("pilot")`: use `for_ebsi("legacy-pilot")`**
  ([#325](https://github.com/luisgf/openvc/issues/325), Part 2; decided by the maintainer on
  2026-10-19). Calling `for_ebsi("pilot")` now emits a `DeprecationWarning`
  (`stacklevel=2`, so it names the caller's own line). The message names the replacement,
  `legacy-pilot`, and says `pilot` will change meaning at the next MAJOR release, to the EBSI
  Core API pilot, a different ledger. It still builds exactly the client it built before, an
  allow-list of `{"api-pilot.ebsi.eu"}`, so nothing breaks in 1.x. **Earliest change: 2.0**
  ([#74](https://github.com/luisgf/openvc/issues/74)): the name is not removed but re-meant,
  and `wiki/Versioning-and-Deprecation.md` lists it under "Currently deprecated". The warning is
  raised before the client is built, so under `-W error::DeprecationWarning` no client is left
  open.
  - **What warns.** Only the call `for_ebsi("pilot")`, whether the name is a literal, a `str`
    subclass or a `(str, Enum)` member holding it. `for_ebsi()`, `for_ebsi("legacy-pilot")`,
    `"conformance"` and `"production"` are silent.
  - **What cannot warn.** `EBSI_HOSTS["pilot"]`, `EBSI_BASE["pilot"]` and
    `ENVIRONMENTS["pilot"]` are plain lookups on a `dict` and a read-only mapping; they keep
    working, silently, and are re-meant at the same time. Move them to `"legacy-pilot"` too.
  - **`OPENVC_EBSI_ENV`.** No code in openvc reads it. The opt-in weekly smoke test
    (`test_live_resolve`) reads it, defaulting to `legacy-pilot`, and passes the value to
    `for_ebsi`; a value of `pilot` warns there, in `for_ebsi`, like any other source of the
    name. There is no second code path to keep in step.
  - **Visibility.** Python shows a `DeprecationWarning` by default only when it is raised from
    `__main__` (measured: a call from `__main__` prints it, the same call from an imported
    module prints nothing, and `python -W default` prints it). Run your tests with
    `-W error::DeprecationWarning`, `-W default` or `-X dev` to find the calls.
  - **Migration.** `for_ebsi("pilot")` to `for_ebsi("legacy-pilot")` (the identical
    allow-list and the identical lane); an `OPENVC_EBSI_ENV=pilot` to `legacy-pilot`;
    `EBSI_HOSTS["pilot"]` and `EBSI_BASE["pilot"]` to `["legacy-pilot"]`. In this repository the
    tests that built `pilot` only to get a client (`test_ebsi_address_guard.py`,
    `test_ebsi_http_bytes.py`, `test_ebsi_guard_origin.py`) now say `legacy-pilot`; the ones
    that pin the old name, in `test_ebsi_environments.py`, assert the warning.
  - `conformance` and `production` are **not** deprecated (switch 3a above).

### Fixed

- **`for_ebsi` no longer lets bare exceptions escape for a name it does not hold**
  ([#325](https://github.com/luisgf/openvc/issues/325)). An unhashable name (`[]`, `{}`)
  was a bare `TypeError`; a `str` subclass whose `__hash__` raises was that exception, and an
  object whose `repr()` raises escaped from the very `raise` meant to refuse it; a long string
  was echoed in full (10 000 characters came back as a 10 028-character message, measured on
  v1.36.0). All of these are now `UnknownEbsiEnvironment` (an `EbsiError`, an `OpenvcError` and
  a `ValueError`): the name is checked against the value's real type (`type(value)` is a
  `str` subclass, so an object whose `__class__` claims `str` is refused too), a `str`
  subclass is read as the characters it holds (so what is checked is what is looked up, the
  #266 rule), and the message cuts the value through `safe_repr`. A `str` subclass that holds
  a known name, such as a `(str, Enum)` member, still selects its environment.
- **`EbsiHttpClient.get_json` no longer drains an error body unbounded**
  ([#321](https://github.com/luisgf/openvc/issues/321); it predates ADR-0009). The non-200
  branch called `resp.read()`: no size cap and no wall-clock deadline, where the 200 branch
  has both (`_read_capped`), so a hostile or flaky allow-listed host could send an unbounded
  or dripping error body. It is now a bounded read (`MAX_ERROR_BODY_BYTES`, 16 KiB, within
  the client's existing deadline); past either, the response is closed and the connection
  dropped instead of drained, and the status error is raised as before. A body small enough
  is read to the end, so its connection is still reused.
- **The TIR attribute walk no longer lets a node's wrong types escape the error family**
  (both lanes, `TirV5` and `TirCoreV1`; found while writing the fuzz tests of the new
  adapter, it predates it). An attribute whose `body` is a number, an array, an object or a
  boolean reached the proof suite's `decode` and raised a bare `AttributeError` (`'int'
  object has no attribute 'isascii'`) out of `issuer_record` and `verify_ebsi_badge`; it is
  now `MalformedRegistryResponse`.
- **`VcJwtProofSuite` turns a JWK that is not an object into a `ProofError`**
  ([#341](https://github.com/luisgf/openvc/issues/341)). `_jwk_to_key(jwk, alg)` read
  `jwk.get(...)` before looking at what it held, so a resolver or a caller that handed over
  `None`, a list, a string or a number got a bare `AttributeError` (`'NoneType' object has
  no attribute 'get'`) for `ES256`, `ES384`, `EdDSA` and `Ed25519`. That is no `OpenvcError`,
  so it escaped `verify_many` and `verify_many_async` and aborted the whole batch instead of
  becoming one item's `error` (measured on `main` at cf6d100, CPython 3.14.8, PyJWT 2.13.0).
  It is now `ProofError("ES256 requires a JWK object, got NoneType")`: the message names the
  algorithm and the type and never echoes the value. `ES256K` already did this since #323 and
  keeps its identical message; the ML-DSA lane never reached this function and was already a
  `SignatureInvalid` (a `ProofError`), which the tests now pin. A `dict` subclass is still a
  JWK object, and `{}` still reports the key-type pin ("requires an EC P-256 key"). A
  `Mapping` that is not a `dict` (`MappingProxyType`, `UserDict`) and an object that only has
  a `get` method are not JWK objects either: on `main` they were already a `ProofError`, but
  one that said something else ("Object of type mappingproxy is not JSON serializable", or a
  key-type pin naming `kty=None`) and, for the wrapper of a valid key, blamed the key; they now
  meet the same first message as every other non-object (measured at cf6d100). The parameter
  is typed `dict`, so this was a caller or resolver bug rather than attacker input.
- **`EbsiHttpClient.get_json` no longer materialises an inflated chunk larger than its cap**
  ([#335](https://github.com/luisgf/openvc/issues/335); found by the review of
  [#331](https://github.com/luisgf/openvc/issues/331), which bounded the new `get_bytes` and
  left this path alone). Hardening against an allow-listed host; no wrong-accept. `get_json`
  read a 200 body with `iter_bytes` and checked `len(body) > max_response_bytes` after
  appending, but `iter_bytes` yields a chunk httpx has already inflated, so one small
  `Content-Encoding: gzip` chunk could allocate its expansion ratio before the check: measured
  on `main` at cf6d100 (CPython 3.14.8, httpx 0.28.1), a 260 935-byte gzip body that inflates
  to 256 MiB, as one chunk, under a 1 MiB cap, peaked at **557 MiB** under `tracemalloc` before
  the `HttpError`. It now reads through the reader `get_bytes` has: the wire is read raw, the
  wire size and the decoded size are checked **before** a chunk is held, and one `gzip` or
  `deflate` coding is decoded with `zlib` asked for at most the room left plus one byte, so
  the same body is refused as the same `HttpError` ("response exceeds N bytes", status 200)
  at a peak of about **2 MiB**. A declared `Content-Length` over the cap is refused before the
  body is read. A well-formed answer, compressed or not, is returned exactly as before; see
  *Changed* for what else a body now has to be.
- **A hostile `Retry-After` no longer escapes as a bare exception or holds a walk**
  ([#335](https://github.com/luisgf/openvc/issues/335); rows (a) and (b) of
  [#324](https://github.com/luisgf/openvc/issues/324); the same class as #246 and #248).
  `_parse_retry_after` returned `float(value)` for any `str.isdigit()` value and
  `_sleep_before_retry` passed `max(delay, secs)` to `time.sleep`. Measured on `main`:
  `Retry-After: 99999999999` was `OverflowError: timestamp out of range for C PyTime_t`; 400
  digits parsed to `inf` and raised the same; `"²"`, which is a digit to `isdigit()`, was
  `ValueError: could not convert string to float` out of `get_json`, while `"١٢٣"` and
  fullwidth digits, which are digits to `isdigit()` and numbers to `float()`, were slept as
  123 s and 5 s; and a 429 asking for 86 400 s slept it, `attempts - 1` times. Delta-seconds is now one to nine ASCII digits
  (`isascii()` and `isdigit()`, so `²`, `٣`, `١٢٣` and fullwidth digits are not numbers, and a
  5 000-digit run never reaches `int()` and its conversion limit); the HTTP-date form is tried
  on a value of at most 64 ASCII characters, with every stdlib failure caught: for 300 000
  generated date-like strings `parsedate_to_datetime` raises only `ValueError` on CPython 3.13
  to 3.15 and `ValueError` or `OverflowError` on 3.10 to 3.12 (for example
  `01 Jan 99999999999 00:00:00 GMT`, measured on 3.10.20, 3.11.15 and 3.12.13), where the
  `(TypeError, ValueError)` the client caught before let a bare `OverflowError` out of
  `get_json`; CPython 3.9, which the package does not support, also raised `TypeError` and
  `IndexError`, which stay in the tuple. Two such dates are in the parametrized parser test,
  so the 3.10 to 3.12 lanes pin the `OverflowError` catch; anything else (`nan`,
  `inf`, `-1`, `+5`, `1e400`, a fraction, two numbers, the empty value) is ignored and the
  client keeps its own backoff. The result is `None` or a finite number of seconds, never
  negative, and the sleep is capped as described under *Added* and *Changed*, so `time.sleep`
  is never handed more than a day whatever the policy. Pinned by `test_ebsi_get_json_bounds.py`
  on the 429 path and on every retried 5xx.
- **The EBSI client no longer echoes an unbounded URL or host in an error message**
  ([#338](https://github.com/luisgf/openvc/issues/338); pre-existing, found by the review of
  the origin allow-list PR #330). `_guard_host` formatted the offending value straight into
  its message, against the rule that a value a remote party can influence goes through
  `safe_repr`. Measured on `main` at cf6d100 with `allowed_hosts={"api-pilot.ebsi.eu"}`: a
  70 000-character host gave a 70 032-character `host not in allow-list` message and a
  70 000-character `http://` URL a 70 033-character `non-https URL rejected` message; both
  are 243 characters now. The value is the caller's and, in practice, a DID document's, a
  registry link's or a Trusted Nodes List entry's. Five messages of `openvc_ebsi/http.py`
  echoed a URL or a host, and now cut it through `safe_repr` (the first 200 characters, then
  `... (N chars)`): `non-https URL rejected: …` and `host not in allow-list: …`
  (`_guard_host`), `registry returned a 200 with a non-JSON body: …` and `registry returned
  a 200 that is not a JSON object: …` (`get_json`; the URL's path and query are unbounded
  past the guard) and `registry returned a body that does not decode: …` (`_request`). The
  rest needed nothing: `URL rejected: not visible ASCII`, `does not parse` and `carries
  userinfo` echo nothing; `port N not allowed` prints a number `urlparse` has range-checked;
  the bytes path's messages (a body that does not decode, a truncated compressed stream,
  bytes after its end) and the unsupported `Content-Encoding` one already went through
  `safe_repr`, as do the address guard's; no message formats a `Location` (redirects are
  off).

  Only the text changed. Every exception class, the leading words of every message (so every
  `match=` keeps matching), and `.url` are as before, with one exception: a `str` subclass
  whose `__format__` raises, passed as the URL, escaped as that error from the four messages
  that format the URL (the non-https rule and the three refusals of a 200) and is now the typed
  `HttpForbiddenHost` or `MalformedRegistryResponse`, because `safe_repr` reads `str.__str__`
  and never the subclass's methods (one whose `__format__` returned 100 000 characters put
  them all in the message). A value now appears quoted, as the module's other `safe_repr`
  messages show theirs (`host not in allow-list: 'evil.example'`), so a caller that matched
  the bare host after the colon must match the quoted one, or read `.url`; an empty host is
  still `None`. Nothing that succeeded now raises.

  **Defaults pending maintainer confirmation.** Each is the smallest change that meets the
  issue; the other option is what would change.

  - **The bound is `safe_repr`'s 200 characters**, the helper this module's bytes path
    already uses for the same URL. A URL-specific bound (256 or 512, say) needs a
    module-local helper, because that constant is shared by every message in the library.
  - **A value is shown quoted**, because `safe_repr` returns the `repr`. An unquoted cut
    needs a new helper and differs from the module's other messages.
  - **`.url` is not bounded.** It holds the whole URL as given (`None` for the userinfo
    refusal), because callers may read it and the issue is about messages. Bounding it too
    would break a consumer that reads the whole URL back.
  - **`gave up after N attempts: …` is not touched.** It formats the last transport error's
    own text and is not a URL, host or `Location`. Measured through httpx 0.28.1 and h11
    0.16.0 against a local socket, a 5 000-byte malformed status line makes a 5 044-character
    `RemoteProtocolError`; a bound there is its own change. Two messages of
    `openvc_ebsi/verify.py` repeat an issuer-controlled value unbounded as well, and are not
    touched either (neither is a URL or host): `IssuerNotTrusted` formats the credential's
    type list (a 70 000-character `type` entry gave a 70 107-character message) and
    `CredentialRevoked` its `id`. The other option is a `safe_repr` on each, in its own change:
    that change is #351, later in this release.
  - **The #318 entry is superseded, not rewritten.** Its sentence that the non-https
    message "quotes it as before" is superseded by this entry: the message quotes the URL,
    cut past 200 characters.
  - **No wiki page is edited**: `wiki/Trust.md` and `wiki/EBSI-Node-Trust.md` describe the
    refusals by exception class, never by message wording.
- **The TIR v4 adapter types the shape it reads, not only its scalars**
  ([#352](https://github.com/luisgf/openvc/issues/352); legacy v4 lane only, it predates
  1.37.0). `TirV4.parse_issuer` iterated `raw.get("attributes", [])` and called `.get` on
  each entry, so a registry body whose `attributes` was `null` or a number escaped as a bare
  `TypeError`, and one whose `attributes` was a string or an object, or whose entry was not
  an object (`[1]`), as a bare `AttributeError`; none is an `EbsiError`, so none reached the
  handlers #248 and #337 describe for the other shapes (measured on `main` at 3bd9e59,
  `tir_adapter("v4").parse_issuer({"did": did, "attributes": X}, ...)`, all five rows of the
  issue's table). The same method read the decoded accreditation token as
  `decode(body).get("vc", {}).get("credentialSubject", {})`, the same bare `AttributeError`
  for a `vc` or `credentialSubject` that is sent and is a list, a string, a number or `null`
  (six shapes measured), a second gap found while checking this one. The adversarial review
  of this PR found a third, one level deeper, in the same token read: an `accreditedFor` of
  a shape the flattener does not recognise was dropped, and an accreditation with no types is
  the **unrestricted** one, which single-level and recursive trust both accept for any
  credential. Measured with real P-256 signatures through `verify_trust_chain`: a scoped
  accreditation whose `accreditedFor` was a single object instead of a list of them
  (`{"schemaId": ..., "types": ["OtherType"]}`), a bare string, or an entry with `"types": ""`
  read as `types=()` and was **trusted for every type** in recursive mode, where the same
  accreditation as a list of objects was refused as `NoTrustedAnchor`; an object whose `types`
  was `7`, `null`, `true` or `1.5` was a bare `TypeError` out of `issuer_record` (past every
  `except EbsiError`), and a `types` that was a string was split into one-character "types".

  `attributes` **absent** keeps meaning "no attributes" (`has_attributes` false, no
  accreditations, as before), and so does `[]`. **Present**, it must be a list, and each entry
  an object: `null`, `0`, `""`, `false` and `{}` are present and are not lists, so they are
  wrong whatever their truth value. Anything else is `MalformedRegistryResponse` (an
  `EbsiError`), shown through `safe_repr` (a 100 000-character string comes back as a message
  under 300 characters, and a value whose `repr()` raises does not raise from the `raise`).
  The entry's message carries its index (`attributes[1] is not an object`), and the shape of
  **every** entry is checked before any token is decoded, so a malformed token earlier in the
  list no longer wins and raises the proof suite's `MalformedToken` (an `OpenvcError`, not an
  `EbsiError`) in place of the shape error. Inside the token, `vc` and `credentialSubject`
  absent still read as "no types", and sent they must be objects; `accreditedFor` absent, `[]`,
  an object with no `types` and `"types": []` still read as "no types", and sent it must be a
  list whose entries are type strings or objects, an object's `types` a list of strings.
  `parse_issuer` also checks that the response it is handed is an object, as the v5 one does
  (the resolver already did, so this only types a direct call).

  **Decision, taken by the maintainer on 2026-10-20: one bad entry rejects the whole record**,
  `MalformedRegistryResponse` and not a skip, the rule #337 applies to scalars in the same
  adapter: a response whose shape is wrong is not a record to trust in part, and the good
  entries beside the bad one are not returned. The v5 and Core v1 walk skips a listing item
  that is not an object; a `vc` or `credentialSubject` that is not one *read* there as an
  accreditation with no type restriction until the follow-up under `### Security` above closed
  it, in this same release, with the same reader; v4 did neither from the start, because a
  skip here would turn a crash into the widest accreditation there is.

  Not changed: v5 and Core v1 (their walk is untouched, and so is the shared
  `_flatten_accredited_for`, which they call too: v4 checks the shape before calling it, so
  the same `accreditedFor` gaps stay open on those lanes); an empty `accreditedFor` is still
  the unrestricted accreditation (whether it should deny is a policy question);
  `has_attributes` is still `bool(accreditations)`, so an `{}` entry, which is an object, is
  still an accreditation of defaults (#337); `issuerType` is not checked against the trust
  roles (a separate question, not part of this fix). There is no recorded TIR v4 response in the repository: the v4 tests
  are synthetic bodies around the recorded v5 accreditation tokens, and the recorded
  responses of the other lanes parse as before.
- **An EBSI error message no longer shows the userinfo of a URL, and the text of a transport
  error, a credential type list and a credential `id` is cut**
  ([#351](https://github.com/luisgf/openvc/issues/351); pre-existing, found by the review of
  #343). Hardening; no wrong-accept. Measured on `main` at 3bd9e59 (CPython 3.14.8, httpx
  0.28.1, `allowed_hosts={"api-pilot.ebsi.eu"}`): `_guard_host("http://u:s3cret@api-pilot.ebsi.eu/x")`
  raised `HttpForbiddenHost("non-https URL rejected: 'http://u:s3cret@api-pilot.ebsi.eu/x'")`,
  so the password reached every log line that formats the exception. That rule was not the only
  door. `NodeSession.get_json` (`URL is not on this session's node: …`), the node client's
  `not a node of this client's … list` and `the node policy named a node …` messages and the
  Trusted Nodes List's `… is not a bare https origin: …` quoted a URL as given too, and so did `host not in allow-list` for a host written
  `user%3Apass%40host`. The refusal of a URL that `urlparse` cannot read chained `urlparse`'s own
  `ValueError` as `__cause__`, and that text quotes what it could not read: a URL written
  `https://user:s3cret%40api-pilot.ebsi.eu/x` has no `@` for a parser, so its password sits in the
  PORT slot and the cause read `Port could not be cast to integer value as
  's3cret%40api-pilot.ebsi.eu'` (a 70 000-character port made a 70 045-character cause). The
  other two items of the issue were unbounded echoes of wire text: `gave up after N attempts:
  …` formatted the last transport error's own text (a 16 000-character
  `httpx.RemoteProtocolError` gave a 16 026-character message), and `verify.py` repeated the
  credential's type list in `IssuerNotTrusted` (one 70 000-character `type` entry gave a
  70 107-character message, 70 000 short entries 898 969), its issuer in the same message and the
  credential `id` in `CredentialRevoked`, unbounded.

  **Changed.** A new private leaf module, `openvc_ebsi/_message.py`, holds what a value may look
  like inside a message: `redact_userinfo` / `url_repr` (the URL with its userinfo replaced by
  `***`, then `safe_repr`'s cut: the userinfo goes FIRST, so a 200-character cut cannot leave the
  start of a password showing) and `bounded_text` (the text cut past 200 characters with its
  length, and NOT quoted, so a message that read `gave up after 3 attempts: transient` reads the
  same). The userinfo is everything in the authority up to the last `@` (where `urlparse` and
  httpx both split), the user name included, the empty forms (`https://@host/`) included; a
  percent-encoded `@` (`%40`) counts as a delimiter too; an `@` in a path, query or fragment is
  not userinfo and stays; the authority is read after a run of `/` and `\` characters (one slash
  after a scheme, two without one) because a WHATWG parser reads `http:/u:p@h` and
  `http:///u:p@h` as `http://u:p@h`, and after an empty scheme (`://u:p@h`, which httpx reads as an
  authority); a reference with no slashes (`user:pass@host/x`) is read from its first
  character. It is linear in the length of the URL, reads a `str` subclass through `str.__str__`
  and never raises (a value it cannot read is `<url withheld>`). It is applied to every message
  of `openvc_ebsi/` that quotes a URL: the guard's non-https and allow-list rules, `get_json` /
  `get_bytes` / `probe` (past the guard, so no URL with userinfo reaches those, but the helper
  makes that true by construction), the node client and the node list. `_url._split` now chains
  a `ValueError` of fixed words (`the authority is not a valid host and port`) instead of
  `urlparse`'s own, raised outside the `except` so the original is not `__context__` either;
  `versioning._origin` reads through the same function and inherits it. `HttpTransientExhausted`
  cuts the last error's text through `bounded_text` (243 characters for the case above; a
  `__str__` that raises is `an object`). `IssuerNotTrusted` shows the issuer through `safe_repr`
  and the type list through `bounded_text` (296 and 297 characters for the two cases above),
  `CredentialRevoked` the `id` through `url_repr`.

  **Found by the review of this change, and fixed in it.** The first version of the helper looked
  for the authority after exactly `//`, and left the password showing for `http:/u:p@h`,
  `http:///u:p@h`, `ws:/\u:p@h` and the like: a WHATWG parser (a browser, Node) reads those as
  credentialed, urllib and httpx do not, so nothing was ever sent as Basic `Authorization`, but
  the password reached six messages (1 779 594 generated shapes: 38 940 left the userinfo showing
  to WHATWG, 0 to urllib and httpx, all with this one cause). Three smaller unbounded echoes
  were bounded: `for_nodes`'s `unknown adapter name: …` (`didr="x" * 70000` gave 70 052
  characters), `check_node_origin`'s `what` label in its three messages (70 032), and the
  address-guard path of `_open_stream`, which still chained `urlparse`'s own error for a `str`
  subclass that answers differently the second time it is read (it now chains the fixed words
  too). An object whose `__class__` claims `str` is `an object` in `url_repr`, as `safe_repr`
  says it.

  **Not changed.** Every exception class, the leading words of every message (so every `match=`
  keeps matching), and the text of a message whose value is short and has no userinfo, byte for
  byte (the type list of `IssuerNotTrusted` included). **`.url` keeps the whole URL as given**
  (`None` for the userinfo refusal), as #343 recorded: the caller who passed the URL already
  holds its password, and the message is what reaches a log. A caller that logs `exc.url` still
  logs it. The cause of the `does not parse` refusal is still a `ValueError`, without
  `urlparse`'s words. The userinfo refusal (`URL rejected: carries userinfo`) already named the
  rule only, and the port rule prints a range-checked number: neither moves. A host that
  `urlparse` reads out of a URL (the allow-list rule) is not userinfo and is shown as before,
  except for the `%40` form above. A reference with no slashes loses its scheme in the message
  (`mailto:a@b` is `***@b`): `user:` in `user:pass@host` cannot be told from a scheme, so
  keeping it is not safe. A secret in a query string (`?access_token=…`) is still shown, up to
  200 characters: the rule covers userinfo only. Not touched, for their own changes: the
  unbounded DIDs that `openvc_ebsi/trust.py` quotes with `!r` (not URLs, and not the issue's
  scope), and `versioning.py`, which echoes no URL (its `no DID Registry adapter for …`
  messages quote the adapter name unbounded; `for_nodes` now cuts it).

### Tests

- `tests/test_ebsi_guard_origin.py`: every port the issue lists (`:0`, `:00`, `:80`, `:444`,
  `:4430`, `:8443`, `:9200`, `:65535`) on a lower-case, an upper-case and a mixed-case host,
  with and without a path and query, through `get_json` and `_guard_host`, against a
  transport that records every request (none); a cached body is not served for a refused
  port; the userinfo forms (`.url` is `None` for each, and a recognisable credential is in
  none of the message, `.url`, args, repr or cause); the admitted forms (`:443`, `:0443`, `:00443`, the empty port,
  an upper-case scheme and host); the recorded pilot registry end to end through the real
  client; a resolver `base` on another port refused at the first fetch; trailing dot,
  IPv6 literals, an ASCII-only host policy (an `xn--` A-label listed and admitted, a
  U-label never converted), a scheme downgrade, the redirect matrix; a parity table between
  the guard and the pin; two Hypothesis properties (what the guard admits, httpx fetches from
  the listed host on 443 with no userinfo; guard and pin agree except on userinfo); and the
  reader's own contract. `test_guard_refuses_non_ascii_before_urlparse` and
  `test_origin_refuses_non_ascii_before_urlparse` now patch `openvc_ebsi._url.urlparse`, the
  one place the URL is parsed.
- `tests/test_ebsi_http_cookies.py` (#317). The client is built through its real constructor
  with the transport injected by patching `httpx.Client` for the constructor call, because
  the existing EBSI suites assign `client._client = httpx.Client(...)`, which discards the
  jar and would make a cookie test fail whatever the fix. It checks, through `get_json`,
  that no `Cookie` header is sent after a 200, on the retry after a 503, to a sibling host
  after a `Domain=` cookie, or after a 302 (not followed), that the jar stays empty, that
  `HttpTransientExhausted`, `HttpNotFound`, `HttpError` (403 and 302) are unchanged with
  and without the header, the hostile values above, a Hypothesis property over arbitrary
  and cookie-shaped `Set-Cookie` bytes, the exact constructor arguments and request
  headers, and the four policy methods. Controls show a plain `httpx.Client`, and the
  constructor's own arguments minus `cookies`, do send the cookie, so the negatives cannot
  pass vacuously. The real `SRV_ID` attributes were not recorded (two live GETs the
  maintainer has not approved); the tests use a stand-in cookie.
- `tests/test_ebsi_environments.py`: the baseline first (the three names and hosts, the
  default and `pilot` allow-lists, `extra_hosts`, a foreign host refused before any I/O, the
  bare `ValueError` / `TypeError` refusals, the resolver's default base, and the class a
  first request through `for_ebsi("production")` raises when the connection fails,
  `HttpTransientExhausted`, measured), written and green on v1.36.0; then the refusals
  (`UnknownEbsiEnvironment`, exact class, for seven inputs and twelve more shapes, a
  bounded message, a hostile `repr` and a hostile `str` subclass), the controls (`legacy-pilot`
  seeds the same allow-list, the default is pinned by the signature, the default,
  `legacy-pilot`, `conformance` and `production` are each silent under
  `warnings.simplefilter("error")`), the table (read-only, bare lower-case hosts, a row
  with no fixed host is not projected) and an import of `environments`, `errors` and
  `versioning` with `httpx` blocked. Part 2 adds the deprecation: the exact
  `DeprecationWarning` class (`category is`, not a subclass) naming `legacy-pilot`; the
  warning attributed to the calling file and line (`stacklevel=2`); the message saying that
  `pilot` changes meaning at the next MAJOR release; the same allow-list as `legacy-pilot`;
  the warning raised before any `EbsiHttpClient` exists; one warning per call; a hostile `str`
  subclass and a `(str, Enum)` member holding `pilot` warn by their characters; a refused name
  warns nothing; the tables cannot warn; a name read from `OPENVC_EBSI_ENV` warns like the
  literal. The tests that only needed a client moved to `legacy-pilot`; the ones that must
  still build `pilot` assert the warning through a helper that also makes every other name
  silent. Mutants killed by a named test: the warning removed, `stacklevel` 1 and 3, a warning
  on the default, on `legacy-pilot`, on `production`, on `conformance`, the check made on the
  caller's object instead of its characters, the warning after the client is built, the wrong
  category (`FutureWarning`), a message that does not name `legacy-pilot` or drops the MAJOR
  sentence.
- **`tests/test_ebsi_core_v1.py`** (426 tests): the manifest hashes every recorded file; the
  registry names and the defaults; the exact URLs; the `contract_address` bound (negatives
  first, a `str` subclass included) and the cache; hostile DIDs on the Core v1 pair with zero
  requests; wrong bodies; the origin pin per node (one node's issuer body read through
  another node's resolver, one node's attribute list served at another's route); the
  shared-walk guards (self-referential, off-origin and port-only `next` / `href` /
  `attributes`, `:443` against no port, an unparseable URL, `total: true`, the page and item
  caps, non-object listing items) run for **both** lanes by parametrisation; the
  contract-address walk, with a link naming another instance in a bracket, dotted, padded or
  `;` spelling refused; the attribute shapes that stay a wildcard under single-level trust
  (no body, an empty body, a body naming no `accreditedFor`); the ES256K
  RootTAO pinned as refused today (`UnsupportedAlgorithm`; `peek_claims`, the `IssuerRecord`
  and single-level trust still work; recursive trust is `AccreditationInvalid`; #323 flips
  it to a positive verification); the golden walk per recorded node, the cross-node
  equality, the prod seed; Hypothesis fuzzing of the issuer, attribute list, attribute and
  DID document responses.
- **`tests/test_ebsi_http_problem_type.py`** (95 tests): the recorded 404 / 400 / 406 and a
  synthetic 405 (labelled as such), the media-type gate, the bounds on `type`, unusable
  bodies (invalid, truncated, over-deep, over the cap), a 10 MiB body read only up to the cap
  with the response closed, the deadline, a compression bomb, a real local TLS server showing
  that an oversized error body drops the connection and a small one keeps it, and Hypothesis
  fuzzing of arbitrary bytes and content types.
- `tests/test_ebsi_http_bytes.py` (bytes-only rows, built through the real constructors with
  the transport injected, so `follow_redirects`, the default headers and the cookie policy
  are the shipped ones; Hypothesis properties on the bytes handed to zlib, the
  `Content-Encoding` and `ETag` values and the supplied validator), the `get_bytes` parity
  rows in `tests/test_ebsi_http.py`, and the recorded `tnl.ebsi.eu` header sets. The fix round
  adds rows for a `deadline_s` above a day or too large for a float, a client cap of `2**63`
  or more with a `gzip` / `deflate` body, a response that arrives after the budget, and a
  real loopback server that drips its headers past `deadline_s`.
- `tests/test_ebsi_address_guard.py`: the address table (59 forbidden, 6 allowed) through
  the classifier and through the guard, refusals with exact classes and zero requests, the
  ordering against the name guard, rebinding, port and IPv6 shape, userinfo, resolution
  failures, rotation and its bound under the default and a longer `RetryPolicy`, every
  transport error rotating, an injected resolver's own exceptions, the proxy decision,
  default-off parity, a Hypothesis property over arbitrary resolver answers, and a loopback
  TLS server that shows the SNI, the certificate check against the name, and that a
  connection is never reused across names. `tests/test_fetch.py::test_forbidden_ips`
  gains `fec0::1`. CI gains the httpx 0.27.0 floor leg described above.
- **`tests/test_docs_claims.py` pins the correction**
  ([#316](https://github.com/luisgf/openvc/issues/316)). A scanner over the current docs flags a
  *claim* that `api.ebsi.eu` is the production host or is "registered for" a launch, not the
  bare string, which the code, its tests and the threat model's host list legitimately name. A
  sample table proves it both ways (the stale `Trust.md` sentence and its variants are flagged;
  the corrected wording and the threat-model list are not), and a second test fails if
  `wiki/Trust.md` loses the correction or if the new page is no longer linked from `Trust`, the
  Spanish walkthrough and the sidebar.
- ES256K opt-in ([#323](https://github.com/luisgf/openvc/issues/323)), three feature-scoped
  files, each building its tokens by hand with `cryptography` (never through a `SigningKey`),
  negatives first, exact classes:
  - `tests/test_es256k_default_refused.py` (29 tests): one parametrised sweep of fifteen
    cases (every lane), each with a REAL ES256K token and the matching secp256k1 JWK, against a spy on
    every signature primitive (`openvc.keys.verify_signature` wherever it is bound, PyJWT's
    decode) that fails the test if `ES256K` ever reached one; the issuers resolve (`did:jwk`),
    so no refusal is an earlier `KeyResolutionFailed`. Also the constants, the primitive's
    `InvalidKey`, `signing_key_from_jwk`, COSE `-47`, the SD-JWT KB-JWT (also with `allow_pq`)
    refused after a genuine ES256 issuer JWT, `verify_many` and its async twin isolating the item, and
    `did:key` secp256k1 staying unsupported.
  - `tests/test_es256k_opt_in.py` (231 tests): near-miss names and non-string `alg`; foreign
    keys (P-256, P-384, OKP, AKP, RSA and `oct` shapes) and the reverse direction; a
    mislabelled but genuine secp256k1 key refused on its labels; 35 hostile JWK shapes (a real
    key with its leading zero octet stripped or padded, a non-canonical spelling, a
    coordinate at or above the field prime, a point written modulo `p`, off-curve, `(0, 0)`)
    asserted as `ProofError` with PyJWT replaced by a function that fails the test; signature
    shapes and claim handling as parity tables over `{ES256, ES256K}`; the gates after the
    allow-list; signing refused for all four suite configurations with `sign` never called;
    the two flags' independence; low-s and high-s; and Hypothesis properties (arbitrary
    signature segments, JWK members (`alg`, `use` and `key_ops` included) and JWK values
    never escape `OpenvcError`; any single octet change to the header, payload or signature is
    rejected). Added in the fix round: 21 non-bool values for `allow_es256k` (truthy and falsy,
    `"false"` and `"0"` among them) each a `ProofError` of the exact class that names the type
    and not the value, a `__class__`-spoofing object that `isinstance` would pass, 27 refused
    and 8 accepted shapes of `alg`/`use`/`key_ops` (a bare string `"verify"`, `null` members, a
    right `alg` with a wrong `use`) with PyJWT replaced by a function that fails the test, and
    one test pinning that ES256 is unchanged by the member checks. Mutation check of these
    tests: 16 of 17 mutants of the new code killed (the bool check removed, via `isinstance`,
    via equality, string-only; each member check removed, via `get()`, as a substring, with
    non-string entries allowed, inverted; the checks leaking to the classic algorithms); the
    survivor only swaps the order of the member and coordinate checks, which both end in a
    `ProofError`, so it is an equivalent mutant.
  - `tests/test_es256k_ebsi_chain.py` (25 tests): the golden (recorded RootTAO refused without
    and verified with the opt-in, clock pinned, a flipped octet refused, the P-256 method of
    the same document refused on its type, the prod accreditation under the preprod key),
    the golden through `verify_trust_chain` (with a spy) and `verify_ebsi_badge`, and a
    synthetic ES256K-root chain: reaches the anchor with the opt-in, `AccreditationInvalid`
    (cause `UnsupportedAlgorithm`) without it, high-s root signature, wrong key, a two-key
    DID document in both directions, an ES256K leaf badge, and single-level trust unchanged.
- `tests/test_ebsi_core_v1.py`: the two tests that pinned the recorded RootTAO as refused say
  that they pin the DEFAULT suite and point to the opt-in tests (no assertion changed).
- `tests/test_ebsi_tnl_golden.py`: the real chain verifies for all three environments (45
  nodes, version 4, `keysVersion` 1, `threshold` 2, the recorded SHA-256s, hosts pairwise
  disjoint and none under `*.ebsi.eu`), the vendored anchor equals the parsed
  `keylist-key.asc`, and every negative the ADR measured, now with exact classes: a changed
  host, a flipped bit in either document (first, middle, last byte) or inside a signature
  (`r`, `s` past the prefix check, the prefix, the hashed area), an appended newline, a wrong
  anchor, the wrong file for a signature, below threshold (one of two, the same one twice,
  `min_threshold=3`), rollback pairs and floors, each time boundary, authenticate-before-parse
  with a spy on the loader and the key-block reader, unknown signers, every argument error,
  a lying `bytes` subclass, import without `httpx`, the one-creation-time rule on the recorded
  signatures, and the critical bit set on the unhashed issuer key ID of each of the three
  recorded signature packets (refused, as GnuPG calls it a bad signature) next to the same
  bytes with an unknown non-critical type (accepted, identical result).
- `tests/test_ebsi_tnl_synthetic.py`: a test-only OpenPGP writer (`cryptography` only,
  throwaway keys, nothing committed) builds valid and then broken chains: thresholds 1-of-1
  to 3-of-3, subkey and unhashed-issuer attribution, the key-list replay after a rotation
  (named for the latent hole: accepted with neither floor nor pair, rejected by
  `keys_floor` and by `last_accepted_keys`), every row of the profile table, hostile key
  material and MPIs, framing lies, the creation-time and unhashed-area rules (rows in the
  profile table, their messages, and what GnuPG accepts there staying accepted), a packet
  flood bounded by the cap and by the number of ECDSA checks, a 4000-digit threshold whose
  error message stays short, 103 schema cases (among them unknown environment names inside the one-to-three
  bound) and 27 hostile JSON texts, and Hypothesis fuzzing
  (seeded, `derandomize=True`) of every reader entry point, of structure-aware mutations
  of the real files (an accepted mutation must give the identical result or a different
  fingerprint) and of the schema validators.
- Mutation check: 61 mutants of the new code, including each in the issue's list (unhashed
  issuer, packets counted for signers, a subkey as signer, a skipped invalid signature, the
  digest trailer, the 16-bit prefix, `>` for `>=` at the threshold and at `expires`, the
  90-day cap, the key-list floor against `keysVersion`, `match` for `fullmatch`, `bool` as
  an integer, the equal-hash rule, a floor, the fingerprint recompute, parsing before
  authenticating, the revocation, expiry and critical-subpacket rules) and the ten of the
  review round (the creation-time rule dropped, widened to any length or to a second one, the
  unhashed critical-bit rule dropped or narrowed to unknown types, a critical creation time not
  understood, the environment names unchecked, the threshold formatted whole, self-signatures
  interpreted like signature files), are each killed by at least one test, and by a named
  failing test: the real chain's baseline result is computed on first use, so a verifier
  regression no longer surfaces as one collection error of the whole module.
- `tests/test_vcjwt_input_hygiene.py` (#341, 255 tests, 36 of them ML-DSA controls that skip
  where `cryptography` is older than 48 or OpenSSL older than 3.5). `allow_pq` on both suites
  against twenty-two non-bool values (strings, `1`/`0`/`1.0`/`0.0`, `None`, containers, bytes,
  `object()`), each an exact class; no echo of a long value; an object whose `__class__` claims
  `bool`; the signature-order rule; the keyword-only rule; the controls. A non-object JWK on
  `ES256`, `ES384`, `EdDSA`, `Ed25519` and `ES256K`, both through `_jwk_to_key` and through
  `verify()` with a token a real key signed, and through `verify_many` and `verify_many_async`
  with a resolver that returns the bad key for one of three credentials; the allow-list still
  runs before the key is looked at; an empty object, a dict subclass and a wrong-curve key keep
  their old behaviour; the ML-DSA lane is pinned as a `SignatureInvalid`; a `MappingProxyType`,
  a `UserDict` and an object with only a `get` method, each holding a valid key, are refused
  with the object message (a reviewer's mutant, `hasattr(jwk, "get")` in place of
  `isinstance(jwk, dict)`, passed the first version of the file because it changes only the
  message); a fuzz of arbitrary JSON values as the JWK. Run against the sources at cf6d100,
  186 of the 255 fail and the controls pass; twenty-two targeted mutants of the change were
  applied to scratch copies, twenty-one killed and one survivor that is equivalent (the object
  check moved after the `ES256K` branch, which has the identical check of its own).
- `tests/test_ebsi_get_json_bounds.py` (#335): the bomb that inflates to 256 MiB, as one
  chunk and split over many, in `gzip` and `zlib`, is `HttpError` with status 200 at a
  `tracemalloc` peak under 16 MiB (557 MiB before); a decoded size at the cap passes and one
  over fails; a declared length over the cap is refused with the body unread; twelve codings
  `get_json` must refuse are `HttpUnexpectedEncoding` with the body unread; corrupt,
  truncated and over-long streams are `MalformedRegistryResponse`; a body the transport has
  already read (`httpx.Response(json=...)`) is still served; `Retry-After` through
  `_parse_retry_after` and through the client (429 and every retried 5xx, raw UTF-8 header
  bytes, a day-out date, the year 9999, a date with a huge offset): never a bare exception,
  every sleep at most the ceiling, `0` and small values still honoured; Hypothesis for the
  sleep (finite, in `[0, ceiling]`, where the ceiling is `retry_after_max_s`, or
  `backoff_max_s` when that is `None`, and exactly `min(max(backoff, Retry-After), ceiling)`
  for a digit run), for the parser and for arbitrary bytes under a coding; a negative
  `backoff_max_s` (with and without a `Retry-After`, after a transport error, under an
  explicit ceiling and under a caller's budget) sleeps exactly 0 s and ends in
  `HttpTransientExhausted`, never a bare `ValueError`, with the fake clock refusing a negative
  sleep as `time.sleep` does; the policy's default, a `dataclasses.replace` of it and its
  validation; a `gzip` or `deflate` body that a test double has already read into memory. Six
  existing tests changed with the behaviour: four
  in `test_ebsi_http_bytes.py` relied on an unbounded `Retry-After` (they now build a policy
  with a ceiling, and the one that used a 400-digit value uses the longest readable one),
  `test_ebsi_http.py` expects the `zlib` error as the cause of a corrupt 200 body, and
  `test_ebsi_http_cookies.py` pins the constructor headers with `Accept-Encoding` added.
- **`tests/test_ebsi_node_client.py`** (377 tests, new) and **86 new rows in
  `tests/test_ebsi_http.py`** (the file had 84): offline (`httpx.MockTransport` injected into the
  `httpx.Client` the real constructor builds, a fixed wall clock, a fake `time`), negatives first,
  exact classes, zero-request assertions. The expiry gate at every entry point (`run`, `session`,
  `check_health`, `session.get_json`, `get_json`, `get_bytes`, `probe`), at, a microsecond after
  and ten years after `expires`, a microsecond before, a cached success, a backoff sleep that
  crosses the instant, a clock that returns `None` / an `int` / a string / a date or raises, a
  naive clock, a `datetime` subclass that lies; the result re-validation (30 shapes), the
  allow-list (six foreign hosts, another environment's hosts, `extra_hosts` / `allowed_hosts` /
  `verify_tls` as `TypeError`); 15 hostile policy outputs and a Hypothesis property; the health
  matrix (31 unhealthy answers in one request, no sleep, cache untouched), the memo with an
  injected monotonic clock, two recorded healthy answers; every failover row twice (one node
  down, then all nodes down with the failures listed and the sentinel body, `problem+json` type
  and `Location` absent from the error, the failures and the log); 11 no-failover answers; a
  real signed three-hop `verify_ebsi_badge` walk that loses node A at each of its nine reads in
  turn; a session pin test through an adapter with no pin; the recorded preprod RootTAO through
  `run` with and without `allow_es256k`; the recorded Trusted Nodes List through `for_nodes`;
  the address guard (default on, opt-out, a proxy, a private address, a rebinding resolver, a
  probe that reaches the first address only); every argument out of range; the two
  expiry gates a fresh healthy verdict and an off-node URL would otherwise hide; a configuration
  error the walk swallowed; a cycling policy and a stray name after every member; eight
  threads on one client; the worst-case walk time on a virtual clock.
- **`tests/fixtures/ebsi/alive/`** (new, recorded 2026-10-19): the `GET /v1/alive` answers of
  `api.ebsi.iti.gr` and `api.ebsi.edelivery.lt`, body and head byte for byte, with a manifest and
  provenance. The test hashes every file. The 503 `{"health_global":0}` the hub documents and the
  firewall's 403 page are synthetic inputs, labelled so.
- **Mutation check** (the list is in the PR for #324): each mutant of the change fails at least
  one of these tests; the base commit `cf6d100` with the new tests laid over it fails to import
  them, and its own tests still pass.
- `tests/test_ebsi_guard_bounded_messages.py` (#338): every guard rule with a 70 000-character
  component (host, URL, path, userinfo, port), each through `_guard_host`, `get_json` and
  `get_bytes`, asserting the exact class, a message under 300 characters, the leading words,
  the start of the value still shown, its size reported and `.url` still the whole URL
  (`None` for userinfo); a short value shown whole and quoted, and an empty host still
  `None`; the three `get_json` refusals of a 200 and the `get_bytes` ones (controls: those
  already passed) with a 50 000-character path; a `str` subclass URL whose `__format__`
  raises, or returns 100 000 characters, through the four messages that format the URL
  (the typed refusal, the message equal to the quoted URL); and a Hypothesis property that no
  refusal of `_guard_host` reaches 500 characters.
- **Live EBSI workflow: a Core v1 preprod smoke and a Trusted Nodes List watch**
  ([#326](https://github.com/luisgf/openvc/issues/326)). CI and tests only: nothing under
  `src/` and no change to `ci.yml`. `.github/workflows/live-ebsi.yml` gains two jobs next
  to the legacy v5 one, on `schedule` and `workflow_dispatch` only, with
  `permissions: contents: read` unchanged. `core-v1` takes two healthy preprod nodes of
  different operators from the *verified* list, reads one DID document and one issuer
  record from each through the `"core-v1"` adapters and requires the two parsed results to
  agree. `tnl-watch` verifies the live list with the shipped anchor and floors and a real
  clock, and is red 14 days before `expires`, when `tnl.json` or `trusted-keys.json` is at
  a version other than the one last seen, or when the served `keylist-key.asc` is not the
  recorded file. The tests are in `tests/test_ebsi_live.py` (the two live ones skip unless
  `OPENVC_EBSI_LIVE=1`; the decisions, both lanes end to end on the recorded bodies of two
  preprod nodes, and the workflow text are tested offline). Defaults taken, pending the
  maintainer: preprod only (no prod read, no TNL `pilot` node); "version changed" is measured
  against two test-only constants, `LAST_SEEN_TNL_VERSION = 4` and
  `LAST_SEEN_KEYS_VERSION = 1` (live values on 2026-10-19), not against the shipped
  floors; a red job per cause and no issue opened from CI; a second, daily schedule
  (`17 6 * * 0,2-6`) that runs `tnl-watch` alone, the Monday entry running all three jobs
  (so `live` now runs weekly only); a `warn_days` dispatch input (a string, default `14`,
  passed through the environment as `OPENVC_TNL_WARN_DAYS`). The `core-v1` job reads no
  error response, so it does not watch the Problem Details `type`: the golden fixtures
  alone pin that. For a developer, `OPENVC_EBSI_LIVE=1 pytest` now also runs both live
  tests, needs the network and a real clock, and `tnl-watch` is red by design from
  2026-12-21T13:33:18Z, 14 days before the current list expires.

### Docs

- `wiki/Trust.md` says what each environment name means, from what ADR-0009 measured on
  2026-10-16, and no longer says `production` (`api.ebsi.eu`) is "registered for EBSI's Q4
  2026 business launch": the certificate that host presented did not cover its name, and none
  of the 45 node URLs in version 4 of the Trusted Nodes List is under `ebsi.eu`. A single
  fresh `GET https://api-conformance.ebsi.eu/` on 2026-10-16 (one attempt, one vantage point)
  again completed no TCP connection inside a 12-second limit (curl exit 28), so `conformance`
  is documented as not known to complete a request, and possibly transient. No code changed
  for either: both rows are kept (switch 3a above). `docs/audit/threat-model.md` lists the
  names; `docs/audit/assurance.md` has the row for the typed error. The stale docstring and
  heading in `tests/test_ebsi_verifier.py` that called the live smoke a "conformance" test,
  and the weekly workflow's job name, now say it resolves a DID on the legacy pilot lane.
  The outcome of ADR-0009's open question 4 is recorded since 2026-10-19 (see **Deprecated**
  and the Status line of the ADR).
- `wiki/Trust.md` (EBSI section), `README.md`, the `versioning.py` module docstring and its
  closing "adding a new version" comment name both lanes and the Core v1 footgun (select
  `base`, `didr` and `tir` together).
- `docs/audit/assurance.md` (the EBSI TIR coverage bullet, and section 4 entries for the
  unbounded error-body read and the two walk-typing findings) and
  `docs/audit/threat-model.md` (the EBSI client paragraph now covers both adapters, and R4:
  once Core v1 nodes are allow-listed their hosts are third-party operator domains, not only
  `*.ebsi.eu`).
- `docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md`: this issue is listed under
  "Proposed follow-up issues" and the recorded 400 and 406 results (and the 405 gap) are in
  the appendix. The Status line was left to the maintainer; it records the answer to open
  question 4 since 2026-10-19.
- `wiki/Trust.md` (EBSI section) documents `get_bytes`, `for_tnl` and `get_tnl_files` and says
  the list host is a second, separate allow-list; `docs/audit/threat-model.md` §7 and
  `docs/audit/assurance.md` §§1, 3 and 4 record the separate one-host client, the bounded
  decode, the unread error body and the Hypothesis properties.
- Threat model R4 and the EBSI bullet of section 7, `docs/audit/assurance.md` (sections 3
  and 4), `wiki/Trust.md`, `wiki/Security-Model.md`, and the "DNS rebinding" row of
  ADR-0009.
- **`wiki/EBSI-Node-Trust.md`: where EBSI reads go and whom to believe**
  ([#316](https://github.com/luisgf/openvc/issues/316), from
  [ADR-0009](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md); refs
  [#113](https://github.com/luisgf/openvc/issues/113)). No library behaviour changes. EBSI Core
  API v1 has no fixed production host: a client picks a node from the signed Trusted Nodes List
  (TNL), and the repo still told integrators the answer was `api.ebsi.eu`. The new page
  (sidebar entry under "Verifying in practice", and a row in the Guides table of
  `wiki/Home.md`) covers the two lanes (the legacy pilot lane on
  `api-pilot.ebsi.eu` with `v5` paths, and Core API v1 on per-node hosts), what the three
  `for_ebsi` names mean today, the TNL chain and its five files, the publisher's verification
  rules as a checklist, the `(version, sha256)` pair to persist for the list and for the key
  list, how to build a one-environment explicit allow-list from a verified list (an offline
  snippet that `tests/test_docs_blocks.py` runs, negatives first; every unexpected input,
  a list of the wrong shape included, is a `ValueError`), what a signed list does not
  authenticate (the operator, not the data), why `api.ebsi.*` must not be matched as a pattern,
  the known limits on Core v1, and what to watch. Every dated statement is ADR-0009's, as of
  2026-10-16; anything the ADR does not give reads *to be measured*. In particular
  `api.ebsi.eu` is described as it was observed (no HTTP response; the certificate it presents
  does not cover the name), not as self-signed.
- **`wiki/Trust.md`** no longer says `production` (`api.ebsi.eu`) "is registered for EBSI's Q4
  2026 business launch". It says that name is not a node, that `for_ebsi()` (default `legacy-pilot`, also spelled
  `pilot`) is the legacy pilot lane, and that the recursive walk (`trust_anchors=`) fails closed on Core v1
  today (the prod and preprod RootTAO accreditations are `ES256K`, which the JOSE allow-list
  rejects). `wiki/Spanish-University-Credential.md` points the same way from its `trust_anchors=`
  example.
- **The note on the `production` row in `src/openvc_ebsi/environments.py`** (docstring only)
  points at the page. No name, host or behaviour changed here; what to do with the names is
  [#325](https://github.com/luisgf/openvc/issues/325)'s question.
- **ADR-0009** is `Accepted in part (2026-10-16)`: direction C (the pure verifier on an
  ECDSA-only OpenPGP reader) and the ES256K opt-in. **ADR-0001** gains "Extended by ADR-0009"
  and a dated "Notes (2026-10-16)" block (its Evidence and Reproduce are the legacy lane; D1 and
  D2 hold on Core v1 responses; D7, D8 and D10 as ADR-0009 found); its decisions are not
  rewritten. `docs/ROADMAP.md` milestone 11 records what was accepted and links the follow-up
  issues.
- **`docs/audit/threat-model.md`**: one dated sentence on the EBSI client in section 7 (only
  `api-pilot.ebsi.eu` of the three registered hosts serves a registry as of 2026-10-16), and a
  new residual, **R12**: a signed node list authenticates the operator, not the registry's data
  (ADR-0009 D7). R4's wording was unchanged by this entry; #318 and #322, later in this release,
  rewrote it.
  `docs/audit/README.md` counts R1–R12. No `assurance.md` line: nothing in `src/` changed.
- **Maintainer decisions taken as defaults** (recorded here and in the PR; each can be
  reversed without touching the rest): the key-list key's fingerprint is quoted **as a dated
  observation** with the caveat that all three channels that agree on it are Europeum's and
  that a wiki page is not a channel to trust it from (the alternative is to omit the value and
  point to the TNL repository); the `src/` comment edit stays in this change (the alternative
  moves it to #325); the page describes what each environment name is today and prescribes
  nothing about multi-node agreement or the qualified-seal switch (ADR-0009 open questions 5
  and 7); on renaming it carries the maintainer's decision of 2026-10-19 (question 4, see
  **Deprecated**).
- **Not done here:** the `gpg` command sequence for the two detached signatures. The issue asked
  for the commands to be run against the then-live list, but also forbade a network request, so
  the page publishes only the two commands ADR-0009's appendix gives and marks the rest *to be
  measured*.
- ES256K opt-in ([#323](https://github.com/luisgf/openvc/issues/323)): `wiki/Keys-and-HSM.md`
  gains an "ES256K (EBSI interop opt-in)" section next to the ML-DSA one and a sentence in
  "The allow-list"; `wiki/Trust.md` and `wiki/EBSI-Node-Trust.md` say that a Core v1 root
  needs `VcJwtProofSuite(allow_es256k=True)` for recursive trust, that single-level trust is
  unaffected and that the prod seed root cannot close a chain; `wiki/VC-JWT.md` and
  `wiki/Security-Model.md` carry one sentence each. Every statement of the default list is
  still exactly `{ES256, ES384, EdDSA, Ed25519}`. `docs/audit/threat-model.md` (the
  forged/tampered row, I1, I2, and a new invariant I23) and `docs/audit/assurance.md`
  (sections 3 and 4) record the opt-in; ADR-0009 records open question 3 as decided, rewords
  D8, the migration plan's Stage 3 and one consequence (its overall status is unchanged: other
  questions remain open); `docs/ROADMAP.md` and the `vc_jwt.py` and `trust.py` docstrings say
  the same. Fix round: the `verify_ebsi_badge` docstring says that its one `proof_suite` also
  admits an ES256K leaf badge when opted in; `README.md` ("Fail-closed by construction") and
  `SECURITY.md` ("Signature verification") name the opt-in next to the allow-list, with the
  braces list unchanged; the fixtures README says that the DEFAULT allow-list refuses the
  RootTAO tokens; the wiki and the threat model (I23) carry the flag rule and the JWK members.
- **#325 Part 2, the deprecation of `pilot`**: `wiki/Trust.md` (the `pilot` bullet says it is
  deprecated, what changes at the MAJOR and why a `DeprecationWarning` may not be seen;
  `conformance` and `production` are documented as kept, without a warning),
  `wiki/EBSI-Node-Trust.md` (the names table and the paragraph that left the question open),
  `wiki/Versioning-and-Deprecation.md` ("Currently deprecated"), `docs/audit/threat-model.md`
  (the EBSI client bullet), `docs/audit/assurance.md` (the #325 row), and ADR-0009 (open question
  4 recorded as decided by the maintainer on 2026-10-19, with its Status line, the environment
  table paragraph of D6, Stage 3 and the follow-up list). The examples that said
  `for_ebsi("pilot", ...)` say `legacy-pilot`.
- `wiki/Trust.md` (EBSI section): "Bounded body reads and bounded waits", with the one-line
  recipe for a higher `retry_after_max_s`. `docs/audit/threat-model.md` (EBSI client
  paragraph: the residual of #320 is closed for the 200 read and the sleep, and the non-200
  decode is recorded as the one that remains) and `docs/audit/assurance.md` (section 3 row and
  section 4 entry).
- `wiki/EBSI-Node-Trust.md`: "Keep using the nodes: `for_nodes`" (the lifetime gate and "rebuild
  before `expires`", single-node walks, what fails over, "a 404 is one node's answer", health,
  the address guard and its proxy limit, the measured worst case, and what the list still does
  not authenticate); two sentences of the page say the same where they used to say "open".
  `wiki/Trust.md`: a pointer and a `no-run` snippet (verify, `for_nodes`, `run`) under "Which node?
  Verifying the Trusted Nodes List". `docs/audit/threat-model.md` (the EBSI client paragraph:
  an allow-list built from external data, the per-walk origin pin, the expiry gate, the
  residuals) and `docs/audit/assurance.md` section 3 (the new tests); section 4 got its entry at
  release time. ADR-0009's status now records D5 as implemented; the answer to open question 5
  and D5's acceptance stay with the maintainer.
- `wiki/Trust.md`: "Which node? Verifying the Trusted Nodes List" (the example is
  `no-run`: it needs the four files).
- `docs/audit/threat-model.md` (section 5 sentence, section 6 parser row) and
  `docs/audit/assurance.md` (sections 1, 2 and 4).
- `docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md`: the status line records what this
  implements (D2; D3's anchor and floors) and the defaults above.

## [1.36.0] — 2026-10-16

### Added

- **`RelyingPartyRegistrationCertificate.claimed_signing_time`**
  ([#134](https://github.com/luisgf/openvc/issues/134)). The JWS header `sigT` of a WRPRC
  (the JAdES V1.1.1 claimed signing time) as an aware UTC `datetime`, or `None` when the
  token carries none. **JWT form only**: `sigT` is a JAdES JOSE header parameter with no COSE
  meaning, so the property is gated on the form and is `None` for every CWT, whatever its
  COSE protected header holds. It is **surfaced, never trusted**:
  it sits in the protected header, so the registrar's key does vouch for it, but it is the
  registrar's own claim with no timestamp token behind it, and nothing in the module bases a
  validity decision on it. Validity still comes from the payload's `iat` / `exp` / `nbf` and
  the signing certificate's window.
- **Five real signed WRPRCs, vendored as PROVISIONAL goldens**
  ([#134](https://github.com/luisgf/openvc/issues/134)), in
  `tests/fixtures/rp_registration/` with a `PROVENANCE.md` (per file: source repository,
  commit, path, retrieval date, licence, SHA-256, who signs it, how it was verified), a
  `NOTICE.md` and the licence texts in `LICENSES/` (BSD-2-Clause, Apache-2.0 twice, CC0-1.0).
  They are the first WRPRCs to exist outside this repository: the German EUDI sandbox
  registrar (via Siros, `SUNET/vc`), the Hopae development registrar (two tokens, one
  intermediated; `openwallet-foundation-labs/axle`), the DIGG wallet ecosystem
  (`diggsweden/wallet-ecosystem`, the only one with a leaf-under-root chain) and an EU
  verifier-endpoint test resource (`eudi-srv-verifier-endpoint`). Each carries a genuine
  ES256 signature that verifies against its own `x5c`. **They are third-party-signed, not
  registrar-anchored**: none comes from a Member State production registrar and none chains
  to a LoTE anchor; the German and Hopae signers are self-signed CA certificates that are
  their own anchor, and the EU sample is signed with a throwaway `CN=test` certificate.
  They settle what producers emit; they do **not** close #134's end-to-end goal.
  Two licensing facts are recorded rather than smoothed over: the licence of the
  German sandbox's token itself is not stated (only the repository's BSD-2-Clause is), and
  `axle` had no `LICENSE` file at the pinned commit (2026-07-12) — its Apache-2.0 text is
  taken from the commit that added one two days later (`d40c55d`), with both token files
  unchanged since.

### Changed

- **The WRPRC lane understands two `crit` names, `sigT` and `b64`, and nothing else**
  ([#134](https://github.com/luisgf/openvc/issues/134); maintainer decision, 2026-10-16).
  The Hopae registrar's tokens carry `"crit": ["sigT", "b64"]` in their JWS header, and
  openvc 1.35.1 refused them (`RpRegistrationError: ... critical, which this verifier does
  not process`): its `crit` allow-list for this lane was `{alg, typ, x5c, iat}`. They now
  verify. **Why:** as #134 reads ETSI TS 119 182-1 (JAdES), V1.1.1 required every
  non-registered header parameter to be listed in `crit`, and V1.2.1 dropped that
  requirement and forbids `sigT` in favour of a header `iat`. Real registrars emit the
  V1.1.1 form, and refusing the registrar that exists today would make the lane unusable
  against it: this is interoperability with what producers emit, not an endorsement of the
  V1.1.1 form.

  The rules, all enforced and all tested:

  - `crit` must be a **non-empty array of unique strings** (RFC 7515 §4.1.11), every name in
    it must be **present in the header**, and the allowed names are exactly the lane's
    existing `{alg, typ, x5c, iat}` plus `sigT` and `b64`. A duplicate (`["sigT", "sigT"]`),
    a non-array, an empty array, a non-string member, an unknown name or a name the header
    lacks is `RpRegistrationError`.
  - **`b64` must be exactly the JSON boolean `true`** (RFC 7797). `b64: false` means an
    *unencoded* payload, a different signing input this verifier does not build, and is
    refused, as are the string `"true"`, `1`, `1.0`, `null`, an array and an object (the
    check is identity, not equality: `1 == True` in Python).
  - **`sigT` must be an RFC 3339 UTC time**, `YYYY-MM-DDThh:mm:ssZ` with optional fractional
    seconds (kept to microseconds). Stricter than RFC 3339 on purpose: a numeric offset
    (`+00:00`), lower-case `t` / `z`, a space separator, a leap second, a trailing newline or
    space, non-ASCII digits and any non-string are refused.
  - **`b64` and `sigT` are checked whether or not `crit` names them.** A `b64: false` that
    is not listed is read as an unencoded payload by a verifier that honours the parameter
    and as base64url by this one: a parser differential, refused wherever it appears. A
    `sigT` that is surfaced must be well-formed. This is the **JWT form** only: the CWT
    envelope does not read or value-check a text-labelled `sigT`, `b64` or `crit` entry in
    its COSE protected header (they have no meaning there; a critical COSE label still fails
    closed, as before) and `claimed_signing_time` is `None` for a CWT.
  - **Nothing else changes, in this lane or any other.** The shared
    `openvc.proof._verify_common.reject_unknown_crit` (VC-JWT, SD-JWT VC issuer JWT, KB-JWT,
    VP-JWT, the status-list token, OID4VCI key proofs), which refuses any `crit`, and the
    LoTE verifier's own allow-list, which is the JAdES set `{alg, typ, x5c, iat}` the WRPRC
    lane started from, are **not modified** in behaviour (`_verify_common.py` and `_jws.py`
    have no diff; `lote.py` differs in its module docstring and one comment only, which no
    longer say it matches the WRPRC lane), and tests now pin that each still refuses `crit` naming `sigT`, `b64` or
    both, with a header that is otherwise valid for the WRPRC lane. The WRPRC lane already kept
    its own `crit` check rather than calling the shared one, so no opt-in parameter was
    added to shared code: the exception lives in the one lane and cannot be reached from
    another. The CWT form (`crit` as a COSE label) is untouched.

  **Limits.** `sigT` is never used for a validity decision and is not a timestamp: there is
  no JAdES signature-timestamp, no policy processing, no augmentation (the lane is still a
  verify *subset* of B-B). `alg`, `typ` and `x5c` are still accepted in `crit` as before
  (RFC 7515 forbids producers from listing registered names there; the lane's earlier
  leniency, shared with the LoTE verifier, is kept, not widened). The decision is recorded
  in the threat model (I22), the assurance register and the wiki as the one documented
  exception: the only lane that honours an extension header parameter beyond the JAdES set.
  The LoTE verifier's `crit` check also accepts a name listed twice (`["iat", "iat"]`), as
  it did before; that is not touched here.

  **Behaviour changes.** Newly *accepted*: a WRPRC whose `crit` is a unique subset of
  `{alg, typ, x5c, iat, sigT, b64}` with `b64: true` and a well-formed `sigT`. Newly
  *refused*, each a tightening: a `crit` that repeats a name (`["iat", "iat"]` verified on
  1.35.1); a `b64` header with any value other than `true`, even when `crit` does not list it
  (1.35.1 ignored it); a `sigT` header that is not a UTC `Z` time, even when `crit` does not
  list it (1.35.1 ignored it). The refusals of an unknown or absent critical name keep their
  wording, except that the names in those messages are now shown one by one through the
  bounded `safe_repr` (no list brackets) instead of as a list `repr`.

- **What the real tokens settled in #134, and what they left open.** The three judgement
  calls #89 had to make from the specification alone:
  `intermediary.sname` is what producers emit, never `intermediary.name` (both are still
  read); `intermediary.sub` and `act.sub` are emitted **together** and agree (both are
  still read); and **no token carries a JWS header `iat`** (it stays surfaced and not
  required). `crit` does appear, on the Hopae tokens, hence the change above.
  `srv_description` is the nested `[[{lang, value}]]` in the German and Hopae tokens and the
  flat `[{lang, value}]` in the DIGG and EU ones; the parser already flattened both, so
  **no parsing change was needed**, and the field is display text read by no authorization
  check (a test replaces it and the verdict does not move). Digg adds a `service_identifier`
  claim that TS 119 475 does not define; it stays in `reg.claims`, with no typed field.
  Two real registrations also confirm the fail-closed reading: the Hopae `credentials`
  entry lists a format and a `meta` but no `claim` (an empty grant, which authorizes
  nothing), and the EU sample describes an issuer (`provides_attestations`, no
  `credentials`).
  **Still open:** #134's end-to-end goal (a WRPRC verified against the issuing registrar's
  *published* anchors, which waits for a Member State registrar going live; CIR (EU)
  2025/848 applies 2026-12-24) and the CWT form (no CWT artifact exists and TS 119 152-1
  allocates no claim keys). This work refs #134 and does not close it.

### Tests

- **`tests/test_rp_registration_real_artifacts.py`** (#134, 173 tests, self-contained). Each
  of the five tokens verifies end to end through `verify_rp_registration_certificate` with
  its **own** root as the trust anchor, the anchor a constant pinned by DER digest (never
  "whatever the token carries"; the German root file is checked to be the token's own
  `x5c[0]`), with the clock pinned inside every certificate window. The decoded facts are
  pinned: header parameters and `crit` per token, no header `iat` in any of the five,
  `sname` / `intermediary.sub` / `act.sub`, the nested and flat `srv_description`, `sigT`
  equal to the payload `iat` on the Hopae tokens, `x5t#S256` equal to the digest of
  `x5c[0]`, the CA-versus-leaf shape of each signer, `exp` (DIGG, 365 days) and its absence.
  Controls: one flipped payload byte, one flipped signature byte and an edited `sigT` are
  signature failures (the payload edit is checked to still parse, so the failure is the
  signature's); every other producer's root is refused (`did not validate to a trust
  anchor`); each certificate fails outside its validity window; and, with the genuine
  signature left stale, an `alg` outside the allow-list, an unknown or duplicated or
  malformed `crit`, a `b64` other than `true` (listed or not) and a malformed `sigT`
  (listed or not) are each refused by the pre-crypto check and never reach the signature.
  The scope cross-check runs on real grants (German and DIGG), including a requested
  `address` container refused because only its four members are registered, and on the two
  producers whose registration grants nothing. A fixture-integrity block pins the SHA-256 of
  every vendored file, fails on an unlisted file, checks that `PROVENANCE.md` quotes every
  digest, and that it keeps its "not registrar-anchored" statement.
- **`tests/test_rp_registration.py`** (+104 cases, to 233). The narrow rules with a **valid
  signature** on every accept path: `sigT` / `b64` listed in any order, alone and together;
  `b64` other than `true` (ten values) listed and not; `sigT` malformed (30 values) listed
  and not, including a 10 000-character string, non-ASCII digits, a trailing newline and
  each of the `T` and `Z` letters in lower case on its own; the accepted `sigT` forms and
  their fractional seconds; a `sigT` of 1970 or 2999 changing nothing the temporal gate
  decides; duplicates; a named parameter missing; the parse entry point enforcing the same
  rules; `claimed_signing_time` never raising on a hand-built header and `None` for a CWT
  whose protected header carries a valid, a malformed, a non-string or a null `sigT` (the raw
  entry is still in `header`, so the `None` is the form gate and not an absent key).
- **`tests/test_jws_crit.py`** (+40, to 49). The exception is one lane: for each of
  `["sigT"]`, `["b64"]` and both orders of `["sigT", "b64"]`, with a header otherwise valid
  for the WRPRC lane, the shared `reject_unknown_crit`, `verify_compact`, VC-JWT, the SD-JWT
  VC issuer JWT, the KB-JWT, the status-list token, VP-JWT, the OID4VCI key proofs and the
  LoTE verifier still refuse it, and the WRPRC lane alone accepts it.
- **Against `origin/main` (65e137f)**, the three files overlaid with their fixtures: 178 of
  the 455 cases fail and 277 pass (71 of the 173 in the real-artifact file, 103 of the 233 in
  `test_rp_registration.py`, 4 of the 49 in `test_jws_crit.py`). The failures are the Hopae
  verifications and the new `crit` / `sigT` / `b64` rules; every pre-existing case passes,
  as do the German, DIGG and EU verifications, the fixture-integrity block and every
  refusal that 1.35.1 already made.
  **Mutation check:** twenty runs against copies of the source, each with one edit or none;
  the unmutated copy passed all 447 cases of the first revision, and all nineteen mutants
  were killed — the `crit` check
  removed, the `b64` value check removed, the `sigT` check removed, the presence check
  removed, duplicates allowed, an empty `crit` allowed, the WRPRC allow-list widened by a
  name (`sigD`), the allow-list widened for the shared lanes, the allow-list widened for the
  LoTE verifier, `b64` compared by equality instead of identity, the value checks run only
  for a listed name, a numeric offset accepted in `sigT`, the `sigT` type check removed,
  Unicode digits accepted, `match` instead of `fullmatch`, lower-case `t` / `z` accepted, a
  leap second clamped, `claimed_signing_time` allowed to raise, and the value checks left
  out of the envelope. After the review of the PR, three more against the final tree (which
  passes all 455): the form gate on `claimed_signing_time` removed, `Z` accepted in either
  case with `T` unchanged, and `T` accepted in either case with `Z` unchanged — each is
  killed (the first revision's tests killed only the mutant that changed both letters).

## [1.35.1] — 2026-10-16

### Fixed

- **`build_status_list_credential` refuses an `issuer` or inline `@context` object nested
  past the loader's cap** ([#311](https://github.com/luisgf/openvc/issues/311), found by
  the review of #310; it predates it). Low severity, no wrong-accept: caller-side
  configuration. The VC-JWT lane reads the signed payload through the bounded loader
  (`openvc._json.loads`, #213), which refuses nesting past 100 levels in the whole payload,
  and the builder accepted an `issuer` or context object of any depth. So an `issuer`
  nested 99 levels (no marker, no cycle; depths up to 30 000 were measured) built, signed
  as a VC-JWT, and was then refused by `default_status_list_resolver` with `MalformedToken:
  header/payload is not valid base64url JSON`: the class #230, #269 and #309 closed,
  openvc minting what its own verifier refuses.

  The builder now raises `StatusListError` at build time, before anything is signed, for an
  `issuer` object nested past **98** levels or a `contexts` entry (`contexts[N]` in the
  message) nested past **97**, counting the object's own root as level 1. The message names
  the field and the cap, never the object. The test is the loader's own
  `openvc._json.nesting_exceeds`, so the two limits cannot drift, run in the place and on the
  snapshot of #309's marker check: the JSON the object encodes to, which is what the lane
  decodes. A `tuple` is an array there, and a `Mapping` the encoder cannot write is `null`,
  so a value that is deep as a Python object and shallow as JSON is judged by the JSON; the
  check never recurses, and a value nested past what the interpreter can encode (200 000
  levels) was already a typed error.

  - **Why the two limits differ by one.** The payload is `{"iss": ..., "vc": {"issuer": ...,
    "@context": [...]}}`: the issuer object is the third container (payload, vc, issuer) and a
    context entry the fourth (payload, vc, `@context`, entry), so each uses `MAX_DEPTH - 2`
    and `MAX_DEPTH - 3` of the loader's 100. Measured against the real lane (sign with
    `VcJwtProofSuite`, read back through `default_status_list_resolver`), for chains of dicts,
    lists, tuples and a mix of both: an `issuer` of up to 98 levels is accepted and one of 99
    is refused, a context entry of up to 97 is accepted and one of 98 is refused.
  - **Behaviour change.** An `issuer` object or a context entry nested past the cap used to
    build and sign and then be refused when read back. It is now a `StatusListError` at build
    time. Nothing nested that deep is a real issuer or context.
  - **Behaviour change, by decision (#309): the rule is the same on every lane.**
    `eddsa-jcs-2022` (the credential is the root of the document) takes exactly one more
    level in each field, 99 for the `issuer` and 98 for a context entry, and refuses the next
    one at `add_proof`. The builder cannot know which lane will secure the list and VC-JWT
    is the default, so it holds every lane to the VC-JWT limit and refuses exactly one level
    that JCS would accept, as it refuses the SD-JWT markers JCS would accept.
  - **Not changed:** the loader's cap, the marker rule (#309), the IETF Token Status List
    builder (it takes no caller-supplied object), a member that is not JSON (it builds and
    fails at sign), and the build-time-snapshot caveat of #309: a nested member stays the
    caller's own object, and one deepened afterwards can still produce a list the lane
    refuses.
  - The property test `test_property_whatever_the_builder_accepts_the_pipeline_accepts`,
    its model (`_model_issuer`, `_model_contexts`) and its strategies know the cap now: the
    accept-side strategies draw objects up to the cap on purpose and cannot draw one past
    it, and the refusal strategies draw on both sides.

### Tests

- **`tests/test_status_builder_nesting_cap.py`** (#311, 298 tests, self-contained). A
  parity table driven by the measured numbers: for dict, list, tuple and mixed chains at
  depths 95 to 102, in both fields, the builder refuses exactly when the real VC-JWT lane
  does, and the lane's refusal is the loader's (not the marker fence's), so the table
  cannot pass for the wrong reason; the same under Hypothesis with a random mix of levels.
  The `eddsa-jcs-2022` asymmetry pinned: at the first depth the builder refuses, JCS signs
  and reads the list back, and refuses one level further. Negatives against the exact class
  `StatusListError` with a key that fails the test if it is asked to sign and a 60 KB
  sentinel that must not reach the message: one level past the cap as dicts, lists, tuples,
  mixes and `dict` / `list` subclasses; a dict subclass whose `items()` hides the deep
  member from `values()`; depth together with a marker; every depth past the cap, not only
  the first; and 1 000, 30 000 and 200 000 levels. Controls that build, sign and verify on
  VC-JWT and `eddsa-jcs-2022`: objects at ordinary depths and AT the cap, a wide object,
  and a deep `Mapping` that is shallow JSON (a hostile one is never walked). In
  `tests/test_status_builders_inputs.py` the model and the strategies know the cap, and the
  refusal properties pin the cap and cap + 1 as `@example`s. Against `origin/main`
  (b19835f) 83 of the 298 cases fail (the negatives and the parity cases past the cap) and
  the other 215 pass, and the two refusal properties of the other file fail; on this branch
  the accept-side property passes on Hypothesis seeds 1 to 60 (example database cleared
  before each). Mutation check: seventeen mutants of the fix (each limit one too high and
  one too low, both together, the loader's own 100, the comparison off by one in both
  directions, the check removed, the check on the Python object instead of the JSON, the
  limit applied to the wrong field, either field unchecked, the probe parsed by the capped
  loader, the check disabled while the marker check stays) are each killed; the parity
  table alone kills fifteen of them, and the other two (the Python-object check and the
  capped-loader parse) are killed by the hostile-value tests and the message test.

## [1.35.0] — 2026-10-15

### Security

- **An SD-JWT VC whose issuer restricted it to another relying party no longer verifies
  for you** ([#227](https://github.com/luisgf/openvc/issues/227)). Low severity, a
  wrong-accept: an audience restriction that the issuer signed was ignored. The SD-JWT VC
  lane never read the issuer JWT's `aud`, so a credential with
  `aud: "https://other-rp.example"` verified for every verifier, with no audience given,
  under `VerificationPolicy(audience=ME)`, and for a holder who presented it to `ME` with a
  KB-JWT correctly bound to `ME`, `key_bound=True` included. The KB-JWT's `aud` binds the
  holder's presentation to a verifier (RFC 9901 §7.3 step 5.6); it says nothing about a
  restriction the issuer put on the credential. The VC-JWT lanes got this rule in 1.30.5
  (ADR-0008 D3), so the two credential formats disagreed on the same claim.

  **The fix** is RFC 7519 §4.1.3 on the issuer JWT, when it has an `aud`
  ([ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md) D4):

  - `aud` present: a string or an array of strings, else `ClaimsInvalid`, and the
    audience the lane receives must be one of them, else `ClaimsInvalid`. With no audience
    a credential that names one is refused (the message cites RFC 7519 §4.1.3), since the
    verifier cannot be one of them.
  - `aud` absent: **unchanged.** The credential verifies with or without an audience, and
    the audience is not inspected. This is the one asymmetry with VC-JWT, where a token
    without `aud` fails when an audience is expected. On this lane the caller's `audience`
    is primarily the KB-JWT's, and requiring an issuer-JWT `aud` would reject essentially
    every SD-JWT VC: neither third-party vector pinned in `tests/fixtures/interop`
    (RFC 9901 A.3 and the EUDI reference PID) nor the OpenID4VP capture has one.
  - **Which audience.** The one `SdJwtVcProofSuite.verify` already receives:
    `policy.audience` at the top level, the *presentation's* audience when the SD-JWT VC is
    nested in a `jwt_vc_json` or `ldp_vc` presentation (the one its KB-JWT is bound to), and
    the `client_id`, or `origin:<origin>` over the Digital Credentials API, on the OpenID4VP
    `dc+sd-jwt` lane. A credential addressed to the verifier that receives the presentation
    therefore verifies on every lane. The sync and async pipelines, `verify_many`,
    `verify_many_async`, the VP-JWT cascade and `verify_vp_token` all reach it through the
    suite; none needed a change.
  - **Where.** On the processed payload, after the KB-JWT when `require_key_binding` is set
    (so an `aud` failure from such a call means the presentation was bound, as for the
    issuer JWT's dates), and not as a temporal check: `require_not_expired=False` does not
    waive it, and its message ("issuer JWT aud does not include …", or "issuer JWT is
    restricted to an audience (aud) and no audience was given …") does not describe an
    expiry, which callers read as "bound, but the issuer JWT expired" (it quotes only the
    audience the verifier configured, so an audience that itself contains the word
    "expired" is the one way the word can appear). Reading the processed payload
    judges an `aud` the issuer made selectively disclosable once it is disclosed, and does
    not call malformed an `aud` array whose entries are `{"...": digest}` objects, which RFC
    9901 §9.7 lets an issuer do (the entries the holder discloses are what is matched; an
    array with every entry withheld is `aud: []` and names no one).
  - **A withheld `aud` disclosure is invisible**, the same limit as a withheld `exp`
    (residual R7). Issuers must never make the whole `aud` claim disclosable. `issue()` does
    not refuse it (the SD-JWT VC draft's non-disclosable list does not include `aud`);
    that is an issuer-side follow-up, out of scope here.
  - The `~`-appended W3C JWS with no `iss` and no `typ` that 1.34.0 (#290) lets reach this
    lane is held to the same rule, so an issuer's `aud` restriction on it is now enforced.
    The "known limit" that 1.34.0 recorded for it is closed.

  **Maintainer decisions** (taken on 2026-10-15, recorded in ADR-0008 D4): option 1 of the
  issue (enforce when present), over keeping the current behaviour and over an opt-in policy
  knob. A KB-JWT made for another verifier still reports `key_bound=True` when the caller
  passes neither `audience` nor `nonce`. That deviates from RFC 7519 §4.1.3 on purpose, was
  decided in #191 and is documented in *What `key_bound` attests*; changing it is a breaking
  change to a return field and belongs to 2.0 (#74). It is recorded in the ADR and not
  changed here.

  **Spec check.** `draft-ietf-oauth-sd-jwt-vc-19` does not mention the issuer JWT's `aud`
  in prose, and its examples carry none (checked against the text for this change; §2.2.2.3's list of
  claims that must not be disclosable omits it). RFC 9901 §9.7 names `aud` among the
  security-critical claims and allows individual entries of an `aud` array to be
  selectively disclosable. Nothing there overrides RFC 7519 §4.1.3.
- **`verify_vp_token` enforces the required `credential_sets`**
  ([#285](https://github.com/luisgf/openvc/issues/285)). The holder could leave out a
  credential the verifier had marked as required. Holder-reachable completeness gap; no
  unverified credential was accepted, because every Presentation that is returned still goes
  through the full pipeline (signature, holder binding, nonce and audience, type
  constraint, status) and an empty `vp_token` was always refused.

  With a `credential_sets` in the query, `_check_completeness` returned at once: any
  non-empty `vp_token` whose Presentations all verified was accepted, whatever `options`
  and `required` said. `result.presentations` was non-empty and `result.for_query("age")`
  was `()`, so a caller that relies on an exception to signal an incomplete response went
  ahead without the credential, and one that unpacks `(p,) = result.for_query(...)` got a
  bare `ValueError` in its own code. The `verify_vp_token` docstring called this "a
  follow-up" from the day the function landed (v1.1.0, #18); `wiki/Presentations.md`
  never said so.

  OpenID4VP 1.0 §6.4.2 says that with no `credential_sets` the Verifier requests every
  Credential Query, and otherwise presentations satisfying every Credential Set Query
  whose `required` is true or omitted (§6.2: default `true`), and optionally any of the
  others; a set is satisfied by presentations matching one of its `options`. §8.6 makes
  "the set of Presentations returned satisfies all requirements defined in the Verifier's
  request" (§6.4) the last validation step, and says the VP Token MUST be rejected when a
  check on the response fails. The text was read on openid.net (OpenID4VP 1.0 Final) while
  writing this entry.

  `_check_completeness` now reads the validated `credential_sets` (#284) and, for every
  set whose `required` is `true` or omitted, requires that at least one of its `options`
  has **every** Credential Query id answered as a key of the `vp_token`. When none does it
  raises `VpTokenIncomplete`: `vp_token does not satisfy credential_sets[N]: no option is
  answered in full; the closest is options[J], which lacks Credential Query id(s) [...]`.
  The set index is named; the caller's structure is never `repr()`-ed. The check reads the
  keys, before any Presentation is read, which is exact: openvc rejects the whole response
  when any Presentation fails and never discards one and keeps the rest. So an unsatisfied
  set is reported before an unknown `vp_token` key, a presentation list that is not an
  array or is empty, and a Presentation failure; a shape error in the `dcql_query`
  (including `credential_sets`) is still reported first, and an empty `vp_token` is still
  "contains no presentations". `verify_encrypted_vp_response` gets the same check through
  `verify_vp_token`.

  Unchanged: a set with `"required": false` may be left out; the no-`credential_sets` path
  (every query required); extra answers; `VpTokenVerification` and `for_query`, which still
  returns `()` for a query that was left out and is how the caller learns which option was
  answered.

  **Behaviour change.** A verifier whose `credential_sets` does not say what it actually
  needs, for example a mandatory set that should have been `required: false`, starts
  failing responses that passed before. A response that verified under 1.34.0 and is now
  refused is the intended effect: it left a required set unsatisfied.
- **Every pyld call gets a JSON-LD context resolver of its own, so one caller's contexts
  no longer reach the next caller's**
  ([#225](https://github.com/luisgf/openvc/issues/225)). Hardening, severity low; the
  follow-up to the 1.30.2 context-validation fix (the RDF suites advisory) and to the
  1.27.1 fix for tagged URL documents. pyld keeps a **process-global** resolved-context
  cache. It stores an inline (object) `@context` under its JSON, together with the
  processed result of any `@import` inside it, tagged `static` whatever the document
  loader said. openvc's loader is per
  call (`document_loader(extra_contexts)`), but the pyld calls shared that cache, so an
  inline context that `@import`s a URL was resolved once, with whichever caller's
  `extra_contexts` came first, and every later call in the process took the same result.
  The issue's repro gives the same output on pyld 2.0.4 and 3.1.0, and so do the new
  tests.
  - **A credential that carries the inline `@import` itself** was canonicalized with
    another caller's terms, or, with no `extra_contexts`, without the `DocumentLoaderError`
    its loader owed. The 1.30.2 inline-context rule refuses such a credential afterwards
    (`ProofMalformed`), so nothing was wrongly accepted this way: only the error it failed
    with depended on who had run first (a credential signed with another tenant's terms came
    back `ProofMalformed`, not `SignatureInvalid`).
  - **A context a caller *serves* that holds the inline `@import`** is trusted, so that
    rule does not refuse it, and there the leak reached the verdict. With two callers in
    one process serving the same two URLs with different definitions of a term, the second
    could not issue a credential of its own (`ProofMalformed`), and a credential signed
    under the first caller's definition of a *property* verified under the second caller's
    contexts, which define it as another IRI. Both callers' contexts are the verifier's own
    configuration, so no hostile document creates the situation; it is a verifier checking
    against terms it had not configured.
  - **A later call that failed only because of an earlier one.** pyld keys an inline
    context by its JSON, and the context a served URL holds by the same key, so when the two
    spell the same terms they were one entry, and what an `@import` stored on it was handed
    back as an active context. In one process, a call that imported a served context and
    a call whose inline context spelled the same terms could not both succeed, in either
    order, and neither could a call that referenced the URL itself followed by one that
    imported it. The second call failed with `DataIntegrityError` (`canonicalization
    failed`, from a `KeyError: 'mappings'` or a `NormalizeError` inside pyld, depending on
    the order), while each canonicalized alone in a fresh process. Nothing was accepted
    wrongly. The resolver per call removes the shared entry, so the outcome no longer
    depends on call order (checked on 1.34.0 and on this change, over every ordered pair
    of nine context shapes).
  - **The change.** `openvc.proof.contexts.pyld_options(loader, **options)` builds the
    options of one pyld call: the caller's options, the `documentLoader`, and a
    `ContextResolver` created for that call. Every call goes through it: the canonization
    in `data_integrity._canonize` (and so `ecdsa-rdfc-2019`), the four in `ecdsa-sd-2023`
    (`to_rdf`, `expand`, `compact`, `normalize`), the three in the context validation, the
    `missing_types` expansion behind `expected_types`, and the OpenID4VP `type_values`
    expansion (which already built its own resolver by hand). Both pyld lines accept the
    resolver (2.0.4 reads an incoming one with `setdefault`, as 3.x does). A new call site
    cannot leave it out: the source is scanned for pyld calls whose options do not come
    from the helper, a recorder checks every call openvc makes across all suites, and no
    other file may spell `documentLoader`, `contextResolver` or `ContextResolver`.
  - **Behaviour change:** see *Changed*, below. One caller with one set of contexts sees
    nothing different, and the W3C golden vectors are untouched.
  - **Decisions taken.**
    - *One resolver per pyld call*, not per verification: the three calls of the context
      validation each get their own, so no call can pick up what another resolved.
    - *A cache of the bundled contexts only, kept for the life of the process.* A resolver
      that starts from nothing also loses the processed form of the VC v2 context, which
      most of a verification's time goes to: with it, a verification of an
      `eddsa-rdfc-2022` credential took 7.0 ms instead of 2.1 ms (3.3 times, on both pyld
      lines). The issue allowed a module-level cache keyed by the bundled documents alone;
      with it the median is 2.2 ms (up to 9% over 1.34.0, see the table below). The window
      onto that store opens on a URL only when the loader serves the *bundled object* for
      it (the same identity test that gates the `static` tag, not URL membership), and any
      other key, an inline context included, is read as absent and written nowhere. The
      store holds the VC v2 resolution and nothing else; it is sound because a bundled
      document references no other URL, which a test now enforces for every bundled file.
      Sharing that one entry across threads is what pyld's own cache already did; no
      thread-safety claim is made beyond that.
    - *`pyld_options` fixes the two keys it sets:* a caller's `documentLoader` or
      `contextResolver` option is overridden, so a call cannot opt out through the helper.
    - *Not touched,* as the issue asks: the 1.30.2 inline-context rule, which contexts are
      bundled, and the network (nothing is fetched).
    - *This entry names the 1.30.2 advisory without its GHSA id:* `test_docs_claims` takes
      any GHSA id under an unreleased heading for an advisory fixed in that version.

    Median verify time, 300 runs on one machine (ms, `pyld 3.1.0` / `pyld 2.0.4`), before
    this change and after:

    | verify | 1.34.0 | with a resolver per call | this change |
    |---|---|---|---|
    | `eddsa-rdfc-2022` credential | 2.13 / 2.10 | 7.00 / 6.98 | 2.24 / 2.24 |
    | `ecdsa-rdfc-2019` credential | 2.09 / 2.05 | 6.92 / 6.94 | 2.14 / 2.07 |
    | `eddsa-rdfc-2022` presentation (holder proof + embedded credential) | 4.62 / 4.42 | 14.10 / 14.00 | 4.70 / 4.52 |
    | `ecdsa-sd-2023` derived credential | 2.19 / 2.12 | 7.03 / 7.08 | 2.29 / 2.31 |
- **`NaN`, `Infinity` or a huge `leeway_s` switched expiry off, and a string or `None`
  escaped as a bare `TypeError`**
  ([#228](https://github.com/luisgf/openvc/issues/228),
  [#232](https://github.com/luisgf/openvc/issues/232)). Every comparison against `NaN` is
  `False`, and an infinite or huge window never closes, so an expired or not-yet-valid
  credential verified. Measured on 1.34.0 with an item that lapsed an hour before: `NaN`
  switched the JWT `exp` / `nbf` / `iat` checks off on VC-JWT (the classic lane through PyJWT,
  and ML-DSA), VP-JWT, and `check_jwt_temporal` / `check_iat_freshness` (the OpenID4VCI key
  proof and the KB-JWT `iat` window); `Infinity` and a huge `int` such as `10**12` did the
  same on every lane, the status-list token and Data Integrity included (which saturated an
  oversized leeway to `timedelta.max`) and SD-JWT for the `int` (it already refused `NaN` and
  `Infinity`). A string or `None` was a bare
  `TypeError` on the ML-DSA VC-JWT, VP-JWT, the status-list token, `check_jwt_temporal` and
  `check_iat_freshness`, which `verify_many` / `verify_many_async` do not isolate, so one misconfigured policy aborted
  the batch. Both need the verifier's own misconfiguration (an attacker cannot set `leeway_s`),
  but it comes from config files and environment variables, where `float("inf")` and
  `json.loads('NaN')` both parse, and a silent fail-open is the worst way to find out. Found
  by the adversarial reviews of #218 and of the merge of #231.

  `leeway_seconds` (`openvc.proof._verify_common`) is now the single check, applied before an
  entry point reads anything else: `VerificationPolicy.__post_init__`, each proof suite's
  constructor (`VcJwtProofSuite` classic and ML-DSA, `VpJwtProofSuite`, `SdJwtVcProofSuite`,
  `DataIntegrityProofSuite`, `EcdsaRdfcProofSuite`, `EddsaJcsProofSuite`,
  `EcdsaJcsProofSuite`, `EcdsaSdProofSuite`), `verify_status_list_token` and the four
  `default_status_list*_resolver` factories, `verify_credential_request_proofs`,
  `verify_device_response` and `verify_issuer_signed`, `verify_rp_registration_certificate`,
  `verify_vp_token` and `verify_encrypted_vp_response`. Each raises its own family's error:
  `InvalidPolicy`, `ProofError` (`SdJwtError` for SD-JWT), `StatusListError`,
  `CredentialRequestMalformed`, `MdocError`, `RpRegistrationError`, `OpenID4VPError`.
  `check_jwt_temporal`, `check_iat_freshness` and `utc_window` call it as well, as a backstop:
  a caller that skipped the entry-point check fails closed there instead of reading `NaN` as
  "never expires".

### Added

- **`verify_vp_token` accepts a bare W3C Verifiable Credential when the query waives
  holder binding** ([#204](https://github.com/luisgf/openvc/issues/204)). This closes a
  conformance gap, not a vulnerability: openvc rejected input the spec says a wallet must
  send, and it accepts nothing it should refuse. OpenID4VP 1.0 §B.1 says a wallet answers
  a query that requires holder binding with a Verifiable Presentation, and otherwise with a
  Verifiable Credential without holder binding. The `jwt_vc_json` and `ldp_vc` lanes
  always required a presentation, so a verifier that set
  `require_cryptographic_holder_binding: false` (the documented way, since 1.29.0, to
  accept a bearer, delegated or claims-bound credential) got an error from a conformant
  wallet. Measured on 1.34.0:

  | The query's flag | The wallet returns | 1.34.0 |
  |---|---|---|
  | `false` | a bare VC-JWT under `jwt_vc_json` | `ClaimsInvalid: aud None != expected verifier …`: the VC-JWT reached `VpJwtProofSuite` as if it were a VP-JWT |
  | `false` | a bare Data Integrity VC under `ldp_vc` | `VpTokenMalformed: … must be a VerifiablePresentation` |

  Both now verify, over the redirect flow and over the Digital Credentials API. The result
  is `VerifiedPresentation(format=<the query's>, holder=None, credentials=(result,))`.
  With the flag `true` or absent a bare credential is still rejected on both lanes.

  Decided by the maintainer on 2026-10-15:
  1. **Which shapes, with the flag `false`:** a bare credential **or** a presentation. A
     presentation is what these lanes accepted before, so this is purely additive: a
     minor, not a behaviour change. A presentation still has to be bound to the request
     (`aud` + `nonce`, or `domain` + `challenge`); only its embedded credentials are
     exempt from holder binding, as since 1.29.0.
  2. **The routing is pinned.** A bare value under `jwt_vc_json` is verified as a VC-JWT
     and never as an SD-JWT or a VP-JWT, so it never reaches `VpJwtProofSuite`. Under
     `ldp_vc` it is a Data Integrity credential with no `VerifiablePresentation` type, of
     any suite `verify_credential` knows: `ecdsa-sd-2023` derived credentials included,
     which the presentation lane excludes as a holder proof. Each result is checked
     against the query's format afterwards (`_check_bare_format`), as the `dc+sd-jwt` lane
     does.
  3. **An `EnvelopedVerifiableCredential` is not accepted as a bare credential.** OpenID4VP
     §B.1 does not mention it for these formats (the 1.0 text does not contain the name),
     so the issue does not require it and this change leaves it out. It stays
     `VpTokenMalformed` under `ldp_vc` (the message now names it), and under `jwt_vc_json`
     an object is not a compact JWT string. An object typed `VerifiablePresentation` is a
     presentation whatever else its `type` lists, an `EnvelopedVerifiableCredential`
     among it: it goes to the presentation lane under every flag, as it did before.
     Decided in review of #307: the first draft tested the Enveloped type first and
     refused such a presentation, which verified on 1.34.0 (an `ldp_vc` presentation with
     a valid holder proof whose `type` is `[VerifiablePresentation,
     EnvelopedVerifiableCredential]`). The refusal is narrowed to an object that is not
     typed as a presentation, rather than documented as a fourth newly refused shape.
  4. **"Bare" is detected fail-closed, from the payload claim, with the JOSE `typ` as a
     cross-check.** A JWT is a credential when its payload has a `vc` object and no `vp`.
     Those are the claims `VcJwtProofSuite` and `VpJwtProofSuite` read, and OpenID4VP's own
     §B.1.3.1 example is a `vc` claim. The `typ` is not the signal: VC-JOSE-COSE makes it a
     SHOULD (`vc+jwt` / `vp+jwt`) and openvc itself signs both kinds as `JWT`. A JSON object
     is a credential when its `type` has `VerifiableCredential` and not
     `VerifiablePresentation`. A value is bare only on positive evidence. Anything that is
     not positively a credential, a token that does not parse included, goes to the
     presentation lane and its own typed error, unchanged. Anything positively ambiguous is
     refused with `VpTokenMalformed` (see Changed). The decision is made before the
     audience is read, because a bare credential carries no `aud` / `domain`.
  5. **The result.** `holder=None` (nothing authenticated a holder; the `mso_mdoc` lane
     reports `None` for the same reason), `credentials=(result,)`, and `raw=result.raw`,
     the suite's own result, as the `dc+sd-jwt` lane sets it. `credentials[0].subject` is
     the *issuer's* statement and nothing proves the presenter is that subject.
  6. **`state` (OpenID4VP §5.3) stays the caller's job.** Without a key-binding proof the
     response carries no `nonce`, so the verifier MUST bind request and response with a
     fresh, high-entropy `state`, unless the Digital Credentials API is used. openvc keeps
     no session and never sees `state`, so it documents this beside the nonce-freshness
     note instead of asserting it.

  A bare credential is verified in full by `verify_credential`: signature, issuer binding,
  validity window, status (when you pass a resolver), and `meta.type_values`. It has no
  audience, nonce, challenge or domain to check, so: a VC-JWT that carries an `aud` is
  rejected (`ClaimsInvalid`, RFC 7519 §4.1.3, since no `aud` can name this verifier;
  VCDM's JWT encoding defines `aud` for presentations only), and `require_holder_binding=True`
  cannot be met by a bare credential and is rejected (`ClaimsInvalid`), because there is no
  authenticated holder to bind its subject to. Neither is a regression: no bare credential
  was accepted before. Written up in the wiki under *Presentations → Bare credentials*.

  One documented limit now has a wider reach. An SD-JWT issuer JWT typed as one, or with
  SD-JWT markers, is still refused on the bare route by the VC-JWT lane's fence. A
  zero-disclosure one with no `typ`, a `vc` object and a `cnf` cannot be told from a VC-JWT
  (the residual of [#291](https://github.com/luisgf/openvc/issues/291), pinned in
  `test_vc_jwt_sd_fence.py`). With its `~` tail dropped it used to fail under `jwt_vc_json`
  on the missing `aud`; with the flag `false` it now verifies as a bare VC-JWT
  (`format='vc-jwt'`, `key_bound=None`, `holder=None`). That equals what the `dc+sd-jwt`
  lane accepts under a waived binding, and it takes an issuer who signed the hybrid, but a
  caller must not read `key_bound=None` as "binding was not needed". The new tests pin it.
- **`openvc.proof._verify_common.leeway_seconds(value, *, name="leeway_s", error=ProofError)`
  and `MAX_LEEWAY_S`** (86 400). `leeway_seconds` returns the leeway as a plain `int` and
  raises *error* for everything else; the message names the value through `safe_repr`, so a
  10 000-character string or a `10**400` stays short. An `int` subclass is read as the integer
  it holds, so an overridden comparison cannot change the verdict.
- **`openvc.InvalidPolicy`** (also `openvc.verify.InvalidPolicy`), a `ProofError` leaf raised
  when a `VerificationPolicy` knob is out of range. `ProofError` is the family root for
  verification knobs, as #232 proposed; a `VerificationError` would have put a configuration
  error outside the family every suite's constructor raises.

### Changed

- **A `datetime` subclass whose own methods lie is read as the plain `datetime` its fields
  describe, where 1.32.4 refused some of them. This is a maintainer decision (taken on
  2026-10-15, option A of #286: "read from the fields"), and it supersedes the #255 /
  1.32.4 line "a naive subclass whose `utcoffset()` answers something that is not a
  `timedelta` ... is now a `StatusListError`" and the three tests that pinned "a subclass
  that lies is refused".** The alternative, to keep refusing a subclass that contradicts
  itself, needs one comparison per overridable method and so keeps growing; reading the
  fields has no list of methods to keep current, and it matches "a naive datetime is UTC".
  - What changes: a subclass whose `astimezone()` returned something else (1.32.4: a
    `StatusListError` from both status builders, a `ProofError` from `utc_instant`)
    reads as the instant its fields and `tzinfo` hold; a naive subclass whose
    `utcoffset()` answered something that is not a `timedelta` (a `StatusListError`
    from both builders) reads as UTC. No genuine `datetime` (plain or a subclass) that
    was read before is refused now; the one exception is not a `datetime` at all, in the
    next bullet.
  - An object that is not a `datetime` but only answers `isinstance(x, datetime)` (a class
    that sets `__class__ = datetime`, a `MagicMock(spec=datetime)`) is now a typed error
    from `utc_epoch` too (`ProofError`, or the caller's `error=`): the snapshot is taken
    through the base class, which does not apply to it. `utc_epoch` used to read it
    through its own `utcoffset()` / `replace()` / `timestamp()` and return whatever they
    led to (a `MagicMock(spec=datetime)` gave `1`); `utc_instant` already refused it,
    with another message. Pass a real `datetime`. This is the only case found where
    something that succeeded before raises now.
  - A caller who passed such a subclass as `now=` and relied on the host-local reading
    (or compensated for it) sees the pin move by the host's UTC offset, to the value its
    fields say. A caller who wants the old refusal of a self-contradicting object must
    check it before passing it in.
  - The `ProofError` message `now cannot be read as an instant: astimezone(UTC) gave
    offset ...` no longer exists.
  - Nine existing cases were updated deliberately, each to assert the exact new reading
    rather than a refusal: `tests/test_status_builders_time.py::
    test_credential_refuses_a_datetime_with_no_utc_reading` and
    `::test_token_refuses_a_datetime_with_no_utc_reading` (the `astimezone-lies` and
    `naive-utcoffset-lies` rows, four each; now
    `test_credential_reads_a_lying_subclass_from_its_fields` and
    `test_token_reads_a_lying_subclass_from_its_fields`, which pin
    `validFrom` / `iat` to `2025-12-31T23:00:00Z` / `1767222000` and `2026-01-01T00:00:00Z`
    / `1767225600`) and `tests/test_typed_clock_pins.py::
    test_utc_instant_rejects_a_subclass_whose_utc_conversion_lies` (now
    `..._reads_a_subclass_whose_utc_conversion_lies_from_its_fields`: `05:00Z`,
    `1609477200`, and the window edge judged to the second).
- **A failed key resolution is one error family on every lane, sync and async**
  ([#283](https://github.com/luisgf/openvc/issues/283)). Nothing is accepted that was
  refused, and nothing that was refused is accepted: every case below failed closed before
  and fails closed now, and `verify_many` / `verify_many_async` isolate the item as before.
  What changes is the class, so a service can map "the issuer could not be resolved" with one
  handler.

  The same failed resolution was reported as one of two unrelated classes, by lane:
  `KeyResolutionFailed(VerificationError)` from the JOSE lanes, and
  `KeyResolutionError(ProofError)` from every Data Integrity suite. They shared no base
  below `OpenvcError`, so `except KeyResolutionFailed` caught a VC-JWT failure and missed a
  Data Integrity one, and `except ProofError` the reverse. The async Data Integrity lane
  raised both: `aio._preresolved_di_resolver` turned a fetch failure or a wrong-shaped
  document into `KeyResolutionFailed` before the suite ran, while a method not in the
  document, or a DID method with no resolver, stayed `KeyResolutionError`. And a proof
  whose `verificationMethod` is a malformed `did:key`, checked where the registry has no
  `did:key` resolver (or with `resolver=None` on a suite), raised a bare
  `DidResolutionError`, neither a `ProofError` nor a `VerificationError`.

  - **`KeyResolutionError` is also a `KeyResolutionFailed`.**
    `class KeyResolutionError(ProofError, KeyResolutionFailed)`, MRO `KeyResolutionError`,
    `ProofError`, `KeyResolutionFailed`, `VerificationError`, `OpenvcError`. `except
    KeyResolutionFailed` and `except VerificationError` now catch a key-resolution failure
    on every lane; `except KeyResolutionError` and `except ProofError` still catch the Data
    Integrity ones and still do **not** catch a JOSE one (`KeyResolutionFailed` is not a
    `ProofError`).
  - **The async Data Integrity lane raises `KeyResolutionError`**, as the sync one does.
    `verify_credential_async` and `verify_many_async` gave `KeyResolutionFailed` for a fetch
    that raised `DidResolutionError` and for a wrong-shaped document (`verificationMethod:
    null`, #219); they give `KeyResolutionError` now, with the same `__cause__`.
  - **The offline `did:key` fallback is typed.** `DidResolutionError` from
    `DidKeyResolver().resolve(did)` in `resolve_verification_key` is now a
    `KeyResolutionError` with the `DidResolutionError` as its cause, as the registry path
    above it already was. Only that call is inside the `try`, and only `DidResolutionError`
    is caught: the purpose check after it stays `ProofPurposeMismatch`, a method that is not
    in a resolved `did:key` document stays `KeyResolutionError` with no cause, and any other
    error from the resolver propagates as itself.
  - **The JOSE lanes are untouched**: VC-JWT and SD-JWT VC raise exactly
    `KeyResolutionFailed`, as before, through `verify_credential`, `verify_many`,
    `verify_credential_async` and `verify_many_async`. So does the VP-JWT holder key, whose
    `ClaimsInvalid` (cause `KeyResolutionFailed`) is a different decision and not part of
    this change.
  - **Where the classes live.** `VerificationError` and `KeyResolutionFailed` are now defined
    in `openvc.errors` (`openvc.proof` cannot import `openvc.verify`, which imports the
    proofs) and re-exported from `openvc.verify`, which keeps both names in `__all__`;
    `openvc.VerificationError` stays at the package root. They are added to
    `openvc.errors.__all__`. No name is removed or renamed. Each keeps `__module__ ==
    "openvc.verify"`, so a traceback line, a `repr` and a pickle name the class exactly as
    before. The API reference now lists both under `openvc.errors` as well as
    `openvc.verify`.

  **Behaviour changes to check.** The `except` clauses only gain matches, with one
  exception (the last bullet): every clause that caught one of these failures still catches
  it. What the first four bullets change are the checks that read the class itself, which a
  caller has to make: an exact-class comparison, a `not isinstance(...)` test, the order of
  handlers, and a `BatchResult.error` or a log line compared by class. The last bullet is the
  one case where an `except` clause stops matching.

  - Code that compares the exact class of a Data Integrity key-resolution failure
    (`type(exc) is KeyResolutionFailed`, `isinstance(exc, ProofError)` being false) must compare
    the new one: `KeyResolutionError`. On the async API that is a fetch failure or a
    wrong-shaped document; the sync API already raised it.
  - `not isinstance(exc, KeyResolutionFailed)` is no longer a way to tell a Data Integrity
    failure; use `isinstance(exc, KeyResolutionError)` (or `ProofError`).
  - An ordered handler can re-route. With `except VerificationError` before `except ProofError`,
    a synchronous Data Integrity key failure moves to the first branch. With `except ProofError`
    before `except KeyResolutionFailed`, an async Data Integrity failure moves to the first
    branch. Order the clauses most specific first.
  - The `verify_many_async` hostile item reports `KeyResolutionError` in `BatchResult.error`
    where it reported `KeyResolutionFailed`, and the INFO log line reads `error=KeyResolutionError`.
  - A malformed `did:key` proof, checked with a registry that has no `did:key` resolver (or
    `resolver=None` on a suite), is a `KeyResolutionError` where it was a bare
    `DidResolutionError`: `except ProofError` and `except VerificationError` now catch it, and
    `except DidError` / `except DidResolutionError` no longer does (the original is
    `exc.__cause__`). This is the one case where a clause stops matching (a maintainer
    decision, below). The default pipeline, whose registry has a `did:key` resolver, already
    raised `KeyResolutionError` there.

  **Maintainer decisions taken, and the reading of SemVer.**

  - **MINOR, not PATCH or MAJOR.** No name, signature, field or default changes, and every
    `except` clause on the pipeline's classes (`VerificationError`, `KeyResolutionFailed`,
    `ProofError`) that catches a failure today still catches it, so it is not MAJOR. The
    class a lane raises, and its bases, are observable (a handler can be ordered, and an
    exact-class comparison can be written), so it is not PATCH.
    `wiki/Versioning-and-Deprecation.md` now says what each level means for exception
    classes. The 1.33.0 (`HttpForbiddenHost` to `EbsiVerificationError`) and 1.32.4
    (`ClaimsInvalid` / `UnsupportedPresentationFormat` to `VpTokenMalformed`)
    re-classifications can stop a clause matching and shipped looser; they are not rewritten.
  - **The malformed `did:key` case is MINOR by exception, not by the rule.** It is the one
    place a clause stops matching: a bare `DidResolutionError` is a `DidError`, and
    `KeyResolutionError` is not, so `except DidError` and `except DidResolutionError` no
    longer catch it. Under the rule above that drops a base, which is the MAJOR case, and it
    is not the PATCH case either (typing a failure that escaped the library's own error
    family), because a bare `DidResolutionError` was already an `OpenvcError`. #283 proposed
    MINOR and its argument ("no `except` clause stops catching") overlooked this case; the
    maintainer decision here is to keep MINOR for this case only, because the failure stays
    an `OpenvcError` (and now a `VerificationError` and a `ProofError`), so a batch and a
    service-wide handler still isolate it; because it is the class the same input already
    raised when the registry has a `did:key` resolver, as the default registry does;
    because it needs a custom registry with no `did:key` resolver; and because the original
    `DidResolutionError` is the `__cause__`. It is recorded as an exception in
    `wiki/Versioning-and-Deprecation.md`, which keeps the rule itself strict. Considered and
    rejected: giving `KeyResolutionError` a `DidError` base (every Data Integrity key failure,
    including a method that is not in the document, would become a `DidError`), and a second
    class that is both a `KeyResolutionError` and a `DidResolutionError` (the exact class on
    every Data Integrity lane would no longer be one class, which is what this change gives).
  - **The Data Integrity class extends the pipeline class**, not the reverse (which would make
    JOSE failures `ProofError`s and leave Data Integrity outside `VerificationError`) and not
    one flat class (which would stop `except ProofError` or `except VerificationError`
    catching one lane; that is the 2.0 window, #74).
  - **`__module__` is pinned** to `openvc.verify` on the two moved classes, rather than letting
    it become `openvc.errors`, so log scrapers and tracebacks that match
    `openvc.verify.KeyResolutionFailed` keep working.
  - The released entries that state the old split (1.33.0 #279, 1.32.4 #256, 1.32.3 #219) are
    not rewritten; this entry supersedes the rule they give for the class.

  Docs: `wiki/Resolving-Issuer-Keys.md` (a table of the lanes and the handler guidance),
  `wiki/Security-Model.md`, `wiki/Async-Verification.md`, `wiki/Versioning-and-Deprecation.md`,
  `docs/CONVENTIONS.md` (Errors), `docs/audit/assurance.md` and the docstrings of
  `openvc.verify`, `openvc.errors`, `KeyResolutionError` and `aio._preresolved_di_resolver`.
- **Behaviour change: an SD-JWT VC whose issuer JWT carries an `aud` that does not name
  your audience is now rejected (`ClaimsInvalid`), and so is one that carries any `aud`
  when you pass no audience.** Before, both verified. What to pass: a credential whose
  issuer names you in `aud` verifies once you tell the verifier who you are.
  - Top level: `VerificationPolicy(audience="<the identifier your issuers name>")` (and
    `nonce` when a KB-JWT is present: the two bind it together, unchanged), or
    `audience=` on `SdJwtVcProofSuite.verify`.
  - Nested in a `jwt_vc_json` / `ldp_vc` presentation: nothing to set on the policy. The
    credential's `aud` must name the presentation's audience (the VP-JWT's `aud`, the
    proof's `domain`, or the matched `origin:<origin>`). That is the opposite of a nested
    VC-JWT, which is checked against `policy.audience` (ADR-0008 D3).
  - OpenID4VP `dc+sd-jwt`: the credential's `aud` must name the `client_id`, or the
    `origin:<origin>` form over the Digital Credentials API (a bare origin is not it).
  - An SD-JWT VC whose issuer JWT has no `aud`, which is nearly every one, is unaffected,
    with or without an audience, and an empty or non-string `audience` is still not
    inspected when there is no `aud` to match it against. When there is one, an
    audience that is not a non-empty string is refused with that message.
  - If you relied on an issuer-JWT `aud` being ignored, read `result.claims.get("aud")` and
    decide yourself, or have the issuer drop it. Nothing opts the check off.
  - `check_jwt_audience` (`openvc.proof._verify_common`, internal) gained a keyword
    `require_present` (default `True`, the VC-JWT behaviour); this lane passes `False`.
  - In `tests/test_sd_jwt_vcdm_typ_interop.py`, the control for #293 minted a VCDM
    *presentation* payload (with `aud: CLIENT_ID`) as a credential. It is such a case, so it
    now passes `VerificationPolicy(audience=CLIENT_ID)`. Read as a credential, a
    presentation addressed to one verifier no longer verifies for the others.
- **A naive `created` on a non-UTC host now yields its UTC reading: a different
  `created` string, and a different `proofValue` on the deterministic suites, for the
  same call** ([#287](https://github.com/luisgf/openvc/issues/287)). Unlike most of the
  changes in this release, this one does not fail closed: the call keeps succeeding and
  signs a different value. `datetime(2026, 1, 1, 12, 0)` was
  signed as `03:00:00Z` under `Asia/Tokyo` and `17:00:00Z` under `America/New_York`
  (under `America/New_York`, 2026-07-01 12:00 gave `16:00:00Z`: the host's DST rules
  applied); it is `12:00:00Z` on every host. A caller that passes `datetime.utcnow()`
  (deprecated since Python 3.12) on a non-UTC host is corrected. A caller that passes
  `datetime.now()` there had its local wall time converted correctly and is now shifted
  by the host's offset: pass an aware value instead, such as
  `datetime.now(timezone.utc)` or `datetime(..., tzinfo=ZoneInfo("Asia/Tokyo"))`. On a
  UTC host, for any aware value and for `created=None`, nothing changes. A `tzinfo`
  whose `utcoffset()` is `None` is naive by Python's definition and is read as UTC the
  same way.
- **A `datetime` subclass whose `astimezone(UTC)` does not answer a UTC instant is
  refused as `ProofMalformed`**, where `created` was signed from whatever its methods
  returned (a subclass answering `astimezone` with a `+03:00` year-2000 value signed
  `2000-01-01T00:00:00Z`). It is `utc_instant`'s existing rule, which this release does
  not change; whether it should is [#286](https://github.com/luisgf/openvc/issues/286).
- **The `could not canonicalize` message of `ecdsa-sd-2023` quotes at most 2000
  characters of the `pyld` text**, `verify`'s `could not canonicalize the derived
  credential` included ([#281](https://github.com/luisgf/openvc/issues/281)). Class,
  prefix and accept-set are unchanged; a longer text ends in `... (N chars)`. It
  changes `verify`'s message only for the longest `pyld` 2.0.4 refusals (traceback
  tail) and for a hostile oversized `@context`. Code that reads the tail of that message
  should read `__cause__`, which keeps the whole error.
- **`except (AttributeError, OverflowError, ValueError)` around `add_proof` /
  `add_base_proof` for a bad `created` no longer catches it**: it is `ProofMalformed`
  (an `OpenvcError` and a `ProofError`).
- **A present `credential_sets` is validated, not read by truthiness**
  ([#284](https://github.com/luisgf/openvc/issues/284)). `verify_vp_token` read
  `credential_sets` in one place, as an on/off switch for the completeness check, and read
  none of its members: `required: "false"` and `required: true` were the same thing, and an
  option naming no query was accepted. The `dcql_query` is the verifier's own input, so
  this is a fail-safe and a conformance fix, not an attacker-reachable bypass (same family
  as #224, #254 and #268).

  `_index_dcql` now checks, after the query walk (so a query's own shape error is still
  reported first) and before any Presentation is read, for every set, answered or not, and
  only when the key is present (an absent one still means "every query is required"):
  `credential_sets` is a non-empty array; each entry is an object; `options` is a
  non-empty array of non-empty arrays of strings, each the `id` of a Credential Query in
  `credentials`; `required`, when present, is a JSON boolean (`0`, `1` and `1.0` are not).
  Anything else raises `VpTokenMalformed` naming the path, for example
  `dcql_query.credential_sets[1].options[0] names Credential Query 'zzz', which is not in
  dcql_query.credentials`. `purpose`, unknown members and duplicate ids inside one option
  are not read.

  **What changes for a caller.** A `dcql_query` whose `credential_sets` is not a
  well-formed non-empty array used to verify and now raises `VpTokenMalformed` on every
  response, including one that answers every query. Two groups: a truthy junk value
  (`true`, `1`, `"x"`, `"false"`, `{"a": 1}`, `[null]`, `[[]]`, an option naming no query,
  a non-boolean `required`) used to switch the per-query completeness check off; a falsy
  one (`null`, `false`, `0`, `""`, `[]`, `{}`) used to read as absent, with every query
  required. To get "every query is required", leave the key out; to say "any one of", pass
  `[{"options": [["a"], ["b"]]}]`; to make a query optional, give it a set with
  `"required": false`. The arrays must be lists, as `credentials` already has to be: a
  `dcql_query` built in Python with a tuple for `credential_sets`, for an `options` or for
  an option (it used to read as truthy, and so switched the check off) raises
  `VpTokenMalformed` too; pass lists. A well-formed `credential_sets` is unchanged by #284
  alone; #285 (above) is what makes it bite.

- **Maintainer decisions (#284, #285).** Each takes the option the issue proposed.
  1. **`null` and `[]` are rejected (#284).** Both used to read as absent. A present
     `credential_sets` is a non-empty array in the spec (§6.2) and a present `null` was
     never "absent" in #224 or #268; the cost is that a template that always emits
     `"credential_sets": []` now fails on every response. The alternative (treating them as
     absent and keeping the accidental fail-safe on those two) was not taken.
  2. **A query that no set references is optional (#285).** §6.4.2 defines the request as
     "all of `credentials`" only when `credential_sets` is absent; otherwise it is whatever
     satisfies the required sets, plus optionally the others, so a query no set names is not
     requested and its absence is not an error. The stricter reading (keep it required) would
     refuse responses a conforming wallet sends. A `dcql_query` with such a query is not
     rejected as malformed either: the spec does not forbid it.
  3. **The error class is a new `VpTokenIncomplete(VpTokenMalformed)` (#285).** Raised for
     both completeness failures: a missing query when there is no `credential_sets`, and an
     unsatisfied required set. An unsatisfied set is a requirements failure, not a shape
     failure, but the missing-query message already raised `VpTokenMalformed` and callers
     catch it; a subclass keeps every `except VpTokenMalformed` working. The exact class of
     the missing-query error changes from `VpTokenMalformed` to `VpTokenIncomplete`: a
     caller that tests `type(exc) is VpTokenMalformed` stops matching it (the message is
     unchanged). `VpTokenIncomplete` is exported from `openvc.openid4vp` and listed in
     `__all__`.
  4. **Extra answers are accepted (#285).** A wallet that answers several options of one
     set, or a query outside every option, is not refused and each Presentation is verified
     in full, as before. Minimisation is the wallet's duty (§6.4.2); rejecting extra answers
     is a separate policy question.
  5. **SemVer: minor (1.35.0).** A response that verified is now refused, which the
     precedents for "the verifier now enforces a request requirement it used to skip"
     (#196, v1.29.0; #221, v1.31.0) shipped as minors under `### Security`, and the new
     public exception class is an API addition anyway. #224, #254 and #268 were patches
     because they refused only a malformed `dcql_query`. The issue proposed 1.34.0 as the
     number; 1.34.0 has shipped since.
- **A bare credential under a query that requires holder binding is
  `VpTokenMalformed`, naming the flag, on both lanes and in both flows.** It was rejected
  before and is still rejected; only the error changes, and nothing is verified first. In
  the redirect flow a bare VC-JWT raised `ClaimsInvalid` (`aud None != expected verifier …`)
  from the VP-JWT suite, which was misleading, and a bare Data Integrity credential raised
  `VpTokenMalformed` (`must be a VerifiablePresentation`), the same class as now. Over the
  Digital Credentials API both raised `ClaimsInvalid` (`DC API presentation audience None
  …`). To accept one, set `require_cryptographic_holder_binding` to `false` in that query.
- **A `jwt_vc_json` token that looks bare but is hostile is `VpTokenMalformed` under a
  query that requires holder binding.** A token whose payload has a `vc` object and no
  `vp`, and whose header names a disallowed `alg` (`none`, `RS256`) or an unknown `crit`,
  raised `UnsupportedAlgorithm` or `MalformedToken` from the VP-JWT suite in 1.34.0, because
  that suite read the header first. With the flag `true` or absent it is now refused as a
  bare credential before the header is read, so the class is `VpTokenMalformed`. With the
  flag `false` the bare route verifies it as a VC-JWT and raises the same class as before.
  It was rejected before and still is. `VpTokenMalformed` is an `OpenID4VPError`, not a
  `ProofError`: a caller that caught `UnsupportedAlgorithm` or `MalformedToken`
  specifically for such a token should catch `OpenID4VPError` (or `OpenvcError`) as well.
  The new tests pin each class under each flag.
- **Three shapes that verified as a presentation are now `VpTokenMalformed`, whatever the
  flag**, because the value is positively both a presentation and a credential, or says it
  is one thing and carries the other. Each was a malformed answer that happened to verify,
  because the presentation lane ignored the extra member. Nothing this layer reports
  changes for a well-formed presentation:
  - a `jwt_vc_json` VP-JWT whose payload also carries a top-level `vc` claim. Remove the
    stray claim;
  - a `jwt_vc_json` token whose `typ` says the other kind than its claim: a `vp` claim
    typed `vc+jwt` (with or without `application/`, any case), or a `vc` claim typed
    `vp+jwt`. Type a VP-JWT `vp+jwt` or `JWT`, a VC-JWT `vc+jwt` or `JWT`;
  - an `ldp_vc` presentation whose `type` also lists `VerifiableCredential`. Drop the
    extra type.
- **A `jwt_vc_json` answer that is not a compact JWT with a `vp` or a `vc` object is
  unchanged** (`MalformedToken`, or `ClaimsInvalid` for a token with neither claim): the
  detection leaves it to the presentation lane, and the new tests pin those classes.
- **A call that another caller's cache used to answer now raises**
  ([#225](https://github.com/luisgf/openvc/issues/225), above). It concerns a process in
  which two callers pass different `extra_contexts` for the same URLs, one of them through
  a context that holds an inline `@import`:
  - A credential verified there under contexts that differ from the ones it was signed
    under now fails with `SignatureInvalid`. It used to verify when the term was a
    property, and to fail with `ProofMalformed` when it was a type. Pass the contexts the
    credential was signed under.
  - A call that reached an `@import` only because an earlier call had cached it now raises
    `DocumentLoaderError`, as its loader says. Pass the imported context in
    `extra_contexts`.
Every bullet below is something that used to succeed, or fail differently, and now raises.

- **A float leeway is refused everywhere.** `60.5`, `60.0` and `1.5` were accepted by VC-JWT,
  VP-JWT, Data Integrity, mdoc, the WRPRC verifier and the status-list token (SD-JWT and
  `verify_vp_token` already refused them). Pass an `int`.
- **A negative leeway is refused everywhere.** Data Integrity, mdoc, WRPRC and the status-list
  token clamped it to 0, and the classic VC-JWT lane handed it to PyJWT, which then rejected
  even a *fresh* token (it read `iat` as in the future). Pass `0` for no tolerance.
- **A `bool` is refused everywhere.** `True` was read as one second by most lanes. Pass an
  `int`.
- **A leeway over one day (`86_400`) is refused everywhere.** SD-JWT and `verify_vp_token`
  took any non-negative `int`, and the other lanes any number, which `utc_window` saturated.
  `MAX_LEEWAY_S` is generous for clock skew; to verify as of another date, pin `now`, and to
  accept an older KB-JWT, raise `kb_max_age_s`, which is not capped.
- **A `Decimal`, a `Fraction` or a numpy scalar is refused** (a numpy `float64` is a `float`;
  a numpy `int64` is not an `int`). Pass `int(x)`.
- **A string or `None`** now raises the entry point's own error up front on the lanes that
  raised a bare `TypeError`; the lanes that already typed it are unchanged.
- **`VerificationPolicy` checks `leeway_s` and `kb_max_age_s` when it is built.**
  `VerificationPolicy(leeway_s=float("nan"))` raises `InvalidPolicy` at construction. Before,
  an SD-JWT verified under it raised `SdJwtError` and every other lane ran with the bad value.
  `kb_max_age_s` must be a non-negative `int`, with no upper bound; a bad one was `SdJwtError`
  at verify time on the SD-JWT lane and silently ignored on every other. The suites keep
  their own check, because suites are public and built directly. `dataclasses.replace` runs
  the check again.
- **The status-list resolver factories check the leeway when they are built.**
  `default_status_list_resolver` and its token and async twins raise `StatusListError` at the
  call, not on the first status fetch.
- **`verify_encrypted_vp_response` checks `leeway_s` before it decrypts**, so a bad leeway
  with an undecryptable response is an `OpenID4VPError`, no longer a `JweMalformed` (a
  `JweError`).
  `verify_vp_token` checks it before the nonce.
- **`verify_credential_request_proofs`** raises `CredentialRequestMalformed` for a bad leeway
  before it reads `credential_issuer`. The message changed: it was `max_age_s and leeway_s
  must not be negative`, it is now `leeway_s must be a whole number of seconds from 0 to
  86400, got ...` and, for `max_age_s` alone, `max_age_s must not be negative`.
  `max_age_s` itself is unchanged and still unvalidated beyond that sign test.
- **`utc_window`, `check_jwt_temporal` and `check_iat_freshness` no longer clamp or
  saturate.** They are private helpers (`openvc.proof._verify_common`); `utc_window` counted
  a negative or `NaN` leeway as 0 and an oversized one as `timedelta.max`, and now raises its
  `error` like the entry points do.

### Fixed

- **The status-list issuer binding accepts a list its own issuer signed with no `issuer`
  in the body** ([#226](https://github.com/luisgf/openvc/issues/226), found by the
  adversarial review of #221; it predates it). `VerificationPolicy(
  require_status_issuer_binding=True)` (ADR-0006) reads the list's issuer from its body.
  A legitimate list secured as a VC-JWT in the VCDM 1.1 JWT encoding may carry its
  issuer only in the JWT `iss`, which leaves `vc.issuer` absent or an object with no
  `id` such as `{"name": "Example University"}`. The pipeline had authenticated that
  issuer, but the default resolvers returned the body as it was, so the binding refused
  with `StatusListIssuerUntrusted` ("has no issuer to bind against"). It failed closed,
  so this was interop, not a vulnerability; it also contradicted #221, which accepts the
  same two shapes on a credential. `default_status_list_resolver` and its async twin now
  fill in the issuer the pipeline verified the list for (`result.issuer`) where the body
  names no one: `issuer` is set to it when absent, and `id` is added to an id-less
  object, which keeps its other members. The change is made on a copy;
  `result.credential` (shared with `result.claims` on an SD-JWT) is never written to.
  What the binding decides:

  - a list signed by the credential's issuer is accepted, so the bit is read
    (`CredentialRevoked`, or `status.revoked is True` under `require_not_revoked=False`);
  - a list an attacker signed gets the **attacker's** id and is refused with
    `StatusListIssuerUntrusted` naming the attacker, as before, unless the attacker is in
    `status_issuer_allowlist`; a list signed by an allow-listed delegate is accepted;
  - a list whose body names an issuer other than its signer is refused (#221); the class
    depends on the lane. A VC-JWT or `vc+sd-jwt` list has its `iss` reconciled with its
    `issuer` by the pipeline before the resolver sees it, so it raises `ClaimsInvalid`
    from the inner verification. A `dc+sd-jwt` list has no such reconciliation, so
    `_authenticated_list` raises `StatusListError`. Both are `OpenvcError`s, but a caller
    that catches one class only misses the other lane.
    A custom `resolve_status_list` that returns an issuer-less body still fails closed
    with `StatusListIssuerUntrusted`, the IETF Token Status List path (bound on the
    token's `iss`) is unaffected, and a Data Integrity list cannot be issuer-less
    (`IssuerBindingError` earlier).

  Without the binding nothing changes: the bit is read as before. A caller of a default
  resolver who reads the returned dict itself now sees an `issuer` where the body had
  none. A custom `resolve_status_list` that wants the same interop must fill in the
  `result.issuer` of the `verify_credential` call that checked the list; see
  [Status lists](https://github.com/luisgf/openvc/wiki/Status-Lists) and the 1.35.0
  amendment to ADR-0006.

  *Decisions.* The fill-in lives in the default resolvers' shared `_authenticated_list`, not
  in the pipeline: `_enforce_status_issuer` and the `resolve(url) -> dict` contract of a
  custom resolver are not relaxed, and no richer return type is introduced. It fills in
  only from `result.issuer` and only when that is a non-empty string; a present
  identifier is never rewritten. Copies are shallow: nothing downstream writes to a
  resolved list.

  *Known gap, left on purpose.* An issuer object that names the signer only by `@id`
  (`{"@id": <signer>}`) is not filled in, and under the binding it is still refused with
  `StatusListIssuerUntrusted` ("no issuer to bind against"), as it was before this change.
  It is not the issuer-less shape #226 fixes: it names someone, so `_authenticated_list`
  has nothing to fill in. Copying a signer-matching `@id` into `id` there would admit
  nothing the signature did not already prove, but how the binding reads an issuer object
  (`_enforce_status_issuer` reads `id` only, for every resolver) is a separate decision,
  and reading `@id` in `_enforce_status_issuer` itself would widen what a custom
  resolver's body can bind on. Neither is taken here. Spell the issuer `<id>` or
  `{"id": <id>}`, or leave it out and let the signer be filled in.
  `test_an_at_id_only_issuer_is_still_refused_under_the_binding` pins this on every lane,
  so a later change to it has to be deliberate.
- **A `datetime` subclass can no longer change how openvc reads a clock pin or a
  builder time** ([#286](https://github.com/luisgf/openvc/issues/286)). Hardening;
  caller-only, no wrong-accept from remote input. openvc's rule is "a naive `datetime`
  is UTC, whatever zone the host is in" (#187, #255), but `utc_instant` and `utc_epoch`,
  the two readers behind the `now=` of every lane and the status builders' times, decided
  "naive" by asking the caller's own object (`now.utcoffset() is None`). A subclass that
  answered `timedelta(0)` with no `tzinfo` was not naive, so `now.astimezone(UTC)` read
  its fields as the **host's local time**, and the post-check that was meant to catch it
  called `utcoffset()` on the same subclass and passed. `datetime(2026, 1, 1, 12)` of such
  a class was `11:00Z` on a UTC+1 host and `03:00Z` on a UTC+9 one. Hosts east of UTC read
  the pin earlier, so an expired credential, status list, certificate or mdoc MSO was
  accepted 15 minutes after its window closed and a fresh KB-JWT was refused as
  future-dated; west of UTC the reverse. The same object as `valid_from` / `issued_at`
  signed a different `validFrom` / `iat` per host. The other overrides the helpers
  consulted were wrong too: a naive subclass whose `utcoffset()` answered `+5 h`
  (`utc_epoch`: shifted, silent), an aware `+09:00` one whose `utcoffset()` answered
  `None` (`utc_epoch`: the `+09:00` dropped, 9 h wrong, silent; `utc_instant`: a
  `ProofError` by accident) and a naive one whose `timestamp()` answered `86400.0`
  (`utc_epoch`: `86400`).

  Both helpers now read the value from its fields and `tzinfo` **through the base
  class** (`datetime.date` and `datetime.timetz`, called on the class), once, and run the
  same logic on the plain `datetime` that returns. No method of the caller's object is
  called, so no override of `utcoffset`, `astimezone`, `replace`, `timestamp` or a field
  property can change the reading, in either direction; `fold` is kept. The error class,
  the `name=` keyword, the typed handling of a `tzinfo` that raises or that has no UTC
  form, and `utc_epoch`'s range (a pin at year 1 or 9999 is still a number, not routed
  through `utc_instant`) are unchanged. The post-check on `astimezone(UTC)` is gone: on a
  plain value it cannot fail. One fix covers every entry point that reads a pin or a
  builder time: `VerificationPolicy.now` (`verify_credential`, `verify_many` and their
  async twins), every Data Integrity suite's `verify(now=)`, the SD-JWT KB-JWT window,
  `verify_vp_token` / `verify_encrypted_vp_response`, `mdoc.verify_device_response` /
  `verify_issuer_signed`, `x5c.validate_cert_chain` / `resolve_x5c_key` /
  `resolve_mdoc_signer_key`, `rp_cert.verify_rp_access_certificate`,
  `rp_registration.verify_rp_registration_certificate`, `trustlist.walk_lotl` /
  `walk_lote` / `consume_lote`, `openid4vci.verify_credential_request_proofs`,
  `status.verify_status_list_token`, and `status.build_status_list_token` /
  `build_status_list_credential`. A plain `datetime` (naive or aware), a subclass that
  overrides nothing (the pendulum / pandas shape), an aware subclass whose `utcoffset()`
  answers `timedelta(0)`, a `tzinfo` that answers `None` (naive, so UTC) and a `None` pin
  read exactly as before.

  `created=` on the Data Integrity issuers goes through its own `_iso`, not these
  helpers; it is left to [#287](https://github.com/luisgf/openvc/issues/287).
- **The helpers that turn a value into error-message text are total for a caller's object**
  ([#282](https://github.com/luisgf/openvc/issues/282)). Hardening, caller-only, no
  wrong-accept: nothing a JSON, CBOR or XML parser returns can carry a custom dunder, so no
  credential, token or response reaches this, and every path that failed was a refusal (the
  one false refusal is the `did:web` case below). One message in this change does echo wire
  data, the `id` of a fetched `did.json` in the `did:web` mismatch refusal, and it is cut now
  (also below). `brief()` (`openvc.status`, 32 call sites), `safe_repr()`
  (`openvc.proof`, 91 call sites in 20 modules, `openvc_ebsi` included) and `_brief()` (the
  Data Integrity context check, 6 call sites) exist so that reporting a bad value cannot itself
  fail. They bounded the length and named a container by its type, which settled deep nesting
  (#213) and huge ints, but not a value whose own class answers `repr()`, `len()` or
  `bit_length()` badly: the exception that method raised, the `ValueError` of the int-to-str
  limit (an `int` subclass of 5000 digits whose `bit_length()` says 1) or a megabyte of `repr`
  text came out of the `raise` that was meant to report the problem. #269 closed the `str` side
  of `brief`; this is the rest. Two public effects:
  - **The status builders and codec.** Every parameter whose error path formats the caller's
    object (`ttl`, `valid_from`, `valid_until`, `issued_at`, `issuer`, `id`, `subject_id`,
    `contexts` and its entries, `bitstring`, `status_list`, `status_purpose`, an entry or reference
    `index` / `uri`, `bits`, `size`, the `get_status*` / `set_status*` arguments, and what a
    resolver hands back to `check_credential_status` / `check_token_status`) raised the
    hostile method's exception: `build_status_list_credential(ttl=BadInt(0))` with a
    raising `__repr__` was that `RuntimeError`, and `id=Mock(spec=int)` a bare `TypeError`
    (`'>' not supported between 'Mock' and 'int'`). They are `StatusListError`, as the same
    value as a plain `int` always was. A job that publishes lists on a schedule and wraps the
    build in `except OpenvcError` sees a typed error again; a caller that caught a builtin
    exception there catches `OpenvcError` instead.
  - **A success path.** `did_web._check_host` formatted the DID with `safe_repr()` before any
    check, so `DidWebResolver.resolve` and `AsyncDidWebResolver.resolve` failed on a *valid* DID
    given as a `str` subclass whose `__repr__` raises. They resolve it; an invalid one is a
    `DidResolutionError`. The refusal for a document whose `id` is not the requested DID (or
    has none) formatted both values with a raw `!r`, so a hostile DID gave the dunder's
    exception there and the document's `id`, which is wire data, came back whole: a 5,000,000
    character `id` made a 5,000,049 character `DidResolutionError`. Both go through
    `safe_repr()` now (`_validated_document`, shared by the sync and async resolvers); a plain
    DID and an `id` of 200 characters or fewer read as before.

  `non_negative_seconds` (`SdJwtVcProofSuite(leeway_s=...)`, `SdJwtVcProofSuite.verify(
  kb_max_age_s=...)`, `verify_vp_token(leeway_s=..., kb_max_age_s=...)`) formatted its value
  with a raw `{value!r}`: `-(10**5000)` was a bare `ValueError` and `BadInt(-1)` the dunder's
  exception, instead of `ProofError` / `SdJwtError` / `OpenID4VPError`. This is a one-line
  change to the message; the leeway semantics (#228, #232) are untouched.

  Each helper now reads a value only through the built-in's unbound methods, never its own
  (`str.__str__`, `int.bit_length`, `int.__repr__`, `float.__repr__`; the `int` size is read
  before any decimal conversion), and catches `Exception` as the last resort, so a value that
  still cannot be read (a test double that claims to be an `int`, a type whose metaclass
  `__name__` raises or is not a string) is `an object`. `_brief` also cuts before `repr()`
  now: it is reached from RDF credential JSON (`@id`, `@type` or a property name), and the
  helper's transient peak on a 16 MB string of NULs was 64 MB (four times the string); it is
  below 1 MiB.

  **Behaviour change, message text only.** Plain values render byte for byte as before
  (pinned by controls that pass on the unfixed tree). What changes:
  - A subclass is shown as the number or characters it holds (cut, or named by its size,
    when long, as a plain value is), not by its own `repr()`, the stance `plain_int` /
    `plain_str` already take: `brief(E.A)` for an `IntEnum` was
    `<E.A: 1>` and is `1`; `safe_repr(S.A)` and `_brief(S.A)` for a `StrEnum` were
    `<S.A: 'a'>` and are `'a'`.
  - `non_negative_seconds` cuts a string longer than 200 characters (`got 'xxxx...'...
    (500 chars)`, where it used to print all 500) and names a container or an int past 64
    bits by its type, as `safe_repr` does everywhere else: `leeway_s must be a non-negative
    int (seconds), got list`, where it used to print the list; `got int` for `-(2**64)`.
  - `_brief` cuts a string to 100 characters *before* `repr()`, so on a string longer than
    100 characters the quote style (`'` or `"`) is chosen from its first 100 characters, not
    from the whole string. Diagnostic text only.
  - A type name longer than 64 characters is cut and ends in `...` (`brief`: `a NNNN...`).
  - The `did:web` id-mismatch message prints the DID and the document `id` through
    `safe_repr()`: the same text for a plain value of up to 200 characters, a longer one cut
    with its length (`'xxxx...'... (5000000 chars)`).

  **Maintainer decisions taken in this change:**
  - The fallback word is `an object`, in all three helpers, although `brief` says
    `a <type>` and `safe_repr` says `<type>` elsewhere: when the type's name cannot be read
    there is no type to name.
  - A type whose `__name__` is not a `str` falls back to `an object` too, so the three
    helpers return a `str` whatever a metaclass says (the issue named only a `__name__` that
    raises).
  - A type name is cut to 64 characters and ends in `...` in all three helpers (one number,
    not each helper's own value limit: it is a name, not a value, and a class name is far
    shorter), because a metaclass can return any string from `__name__`; a 5,000,000 character
    one gave a 5,000,002 character message. A class name of 64 characters or fewer prints as
    before.
  - The `did:web` id-mismatch message is in scope although the other raw `!r` sites are not:
    the claim that `resolve()` handles a hostile `str` subclass for a valid DID holds only if
    that refusal is total too, and the document `id` it echoes is wire data.
  - The three helpers stay three. Their limits differ (32, 200 and 100 characters) and `status`
    cannot import from `proof`.
  - Left as it is, out of this issue's scope (the `did:web` id-mismatch message, above, is
    the one exception): the raw `!r` fields and the inline
    `type(x).__name__` sites besides these helpers (a mechanical sweep with no accept-set
    change, its own issue); data-path consumers of a `str` subclass, such as `_did_web_url`
    slicing the DID through the subclass's own `__getitem__` (a question of which bytes are
    used, not of a message); and a `Mock(spec=int)` passed as a *numeric* argument (`index`,
    `ttl`, `size`), which `plain_int` still turns into a bare `TypeError` before any message
    is built.
- **`ecdsa-sd-2023` `add_base_proof` and `derive_proof` raise `ProofMalformed` when the
  credential cannot be canonicalized**
  ([#281](https://github.com/luisgf/openvc/issues/281)). Hardening; no wrong-accept, and
  nothing was signed or derived on the failing path. An `@context` that `pyld` cannot
  process (an unknown URL, a typo'd one, a value that is neither an array nor a string,
  an inline object with a bad term definition) let a bare `pyld.jsonld.JsonLdError`
  escape from both methods since `ecdsa-sd-2023` landed (v0.3.0); so did a body `pyld`
  refuses (a `type` holding an integer, a numeric `credentialSubject.id`), but from
  `derive_proof` only: `add_base_proof` already typed those through `validate_document`
  (`cannot validate the document's JSON-LD form`, and `the document uses @reverse` for a
  `@reverse`), and keeps that message. The bare error is not an `OpenvcError`, so an
  `except OpenvcError` around issuance or derivation missed it. `verify` already turned
  the same failures into `ProofMalformed`, and so did the two RDF siblings' issuers.
  `derive_proof` reads a credential a third-party issuer chose, so a hostile or
  misconfigured issuer could make a wallet's call raise a type its handler does not
  cover.

  - **Decision (class and message):** `ProofMalformed`, the class `verify` and
    `_utf8_nquads` already use for a canonicalization failure, with the prefix
    `could not canonicalize the credential` (`verify` keeps `the derived credential`) and
    the `pyld` error chained as `__cause__`. The message tail is the `pyld` error text, as
    in `verify`. The escaping class changes from `pyld.jsonld.JsonLdError` to
    `ProofMalformed`; it was never documented. No accept-set changes.
  - **Decision (message length):** the `pyld` text in the message is cut at 2000
    characters, with the full length shown (`... (1000000 chars)`), in all three arms,
    `verify`'s included. `pyld` quotes the context it refused, so a 1 000 000-character
    `@context` string made a message of about 1 000 000 characters in all three arms, and
    a 1 000 000-character URL in `derive_proof` (`derive_proof` and `verify` read a
    credential a third party chose). An ordinary `pyld` 3.x refusal is 130 to 470
    characters and is kept whole. `pyld` 2.0.4, the floor, appends the traceback of its
    inner error (133 to 2577 characters, measured on eight of the issue's `@context`
    values in the three arms), so its longest are cut after the message, the `Type` and
    the head of the `Cause`: `verify`'s message changes for those, and only those. The
    cause keeps the full text, and the class, the prefix and the accept-set do not
    change. `safe_repr` was not used: it cuts at 200 and would add quotes around the text.
  - **Decision (RDF siblings' messages, left as they were):** the two RDF siblings'
    issuers carry the same unbounded text, in their `DataIntegrityError`
    (`canonicalization failed: ...`) and `DocumentLoaderError` messages (1 000 076 and
    1 000 110 characters for the same two inputs). Cutting them means changing
    `data_integrity._canonize` and the document loader, and choosing one bound for the
    whole family; `_canonize` is kept byte-identical here so that
    [#225](https://github.com/luisgf/openvc/issues/225) merges without a conflict there.
    It is a follow-up.
  - **What is guarded.** `add_base_proof`: `_proof_config_hash` through the mandatory
    hash. `derive_proof`: `_transform` through `_reveal_view`. A `ProofError` raised
    inside (a bad JSON pointer, a `validate_document` refusal) keeps its own class and
    message. The signing calls are outside the guard, so a signing-backend error (an
    HSM or Vault failure) surfaces as itself, for `signing_key` and for the ephemeral
    key alike.
  - **Decision (left as it was):** the lane still raises `ProofMalformed`, not
    `DocumentLoaderError`, for an unbundled context (the RDF siblings raise the latter);
    `derive_proof` still does not run `validate_document`; and `derive_proof` still
    reads `proof["proofValue"]` before the guard (a base proof with no `proofValue` is a
    bare `KeyError`, one with `proofValue: 5` an `AttributeError`). Each is a separate
    decision.

- **The Data Integrity issuers read `created` the one way openvc reads a time, and type
  what they cannot read**
  ([#287](https://github.com/luisgf/openvc/issues/287)). `DataIntegrityProofSuite`,
  `EcdsaRdfcProofSuite`, `EddsaJcsProofSuite`, `EcdsaJcsProofSuite` (`add_proof`) and
  `EcdsaSdProofSuite.add_base_proof` rendered `created=` with a private `_iso` (two
  copies) that called `astimezone`, which reads a naive `datetime` as the host's local
  time. `created` now goes through `utc_instant(..., error=ProofMalformed,
  name="created")` and `isoformat`, via one shared helper, `utc_iso`, beside
  `utc_instant` in `openvc.proof._verify_common`; both `_iso` copies are gone.
  `utc_instant` and `utc_epoch` are untouched, so no verify path changes. Before:

  | `created=` | Result |
  |---|---|
  | a string, an `int` / `float` epoch, `NaN`, `inf`, `True`, a `date`, a `timedelta`, `[]`, `b"x"` | bare `AttributeError` |
  | an aware value whose UTC form leaves year 1..9999 | bare `OverflowError` |
  | naive `datetime.min` / `datetime.max` | bare `ValueError`, even under `TZ=UTC` |
  | a `tzinfo` that raises | that exception |
  | a `datetime` subclass | its own `astimezone` / `strftime` chose the signed string |

  All of these are `ProofMalformed` now (`created must be a datetime or None, not
  <type>`, or `created cannot be read as an instant: ...`), raised after the `alg`,
  `@context` and existing-proof checks and before any canonicalization or signing. The
  suite reads the plain `datetime` that returns, never the caller's object. A naive
  `datetime.min` / `datetime.max` is signed (`0001-01-01T00:00:00Z`,
  `9999-12-31T23:59:59Z`). For every aware value that rendered before and for `None`
  (the current UTC time) the output is byte for byte what it was; microseconds are
  truncated, not rounded, as before.

  - **Decision (error class):** `ProofMalformed` for all five, the class these methods
    already raise for a bad credential and the only class the five share. The issue
    offered each suite's own `DataIntegrityError` / `EcdsaSdError` as the alternative;
    "the suite's own typed error" is read here as `ProofMalformed`.
  - **Decision (naive datetimes):** a naive `created` is UTC, the rule everywhere else in
    openvc ([#187](https://github.com/luisgf/openvc/issues/187),
    [#218](https://github.com/luisgf/openvc/issues/218),
    [#255](https://github.com/luisgf/openvc/issues/255)), rather than refused. It is a
    behaviour change on a non-UTC host (see Changed).
  - **Not changed:** no verifier reads `created` back (a proof dated in the year 2999
    verifies), `created` stays `datetime | None` (no string or epoch), the JOSE issuers
    take no datetime, and the status builders keep their own `_iso`, which raises
    `StatusListError` ([#255](https://github.com/luisgf/openvc/issues/255)).
- The bare `TypeError` from a string or `None` leeway on the ML-DSA VC-JWT lane, VP-JWT, the
  status-list token, `check_jwt_temporal` and `check_iat_freshness` (#228): a typed error, so `verify_many` and
  `verify_many_async` no longer abort the batch on it. With the policy checked at
  construction, a bad leeway cannot reach a batch at all; one that bypasses the dataclass
  (`object.__setattr__`) still fails each item typed, with the batch intact.
- An object that only *claims* to be an `int` escaped `leeway_s` (and `kb_max_age_s`) as a
  bare `TypeError`. `isinstance()` honours a `__class__` property, so a stand-in with
  `__class__ = property(lambda self: int)`, `Mock(spec=int)` and `MagicMock(spec=int)` passed
  the type test and then failed inside `int.__index__` (or in a `< 0` comparison for
  `kb_max_age_s`), from `leeway_seconds`, `VerificationPolicy` and every suite constructor.
  Nothing was ever accepted, but the error was not typed and would have aborted `verify_many`
  had it got past the policy. The type is now read with `type()`, and the message names such
  an object by its real type without asking it anything. Only the verifier's own code can
  pass one, so this is a typed-error fix, not a security one.
- `kb_max_age_s` is read the same way `leeway_s` is: as the plain integer it holds. A
  negative `int` subclass whose `__lt__` lies used to pass `VerificationPolicy` and
  `verify_vp_token`; it is refused now. The `InvalidPolicy` message for a bad `kb_max_age_s`
  went through `repr` and grew with the value (a 100 000-character string gave a 100 KB
  message); it is bounded through `safe_repr` like the leeway one. This is the `kb_max_age_s`
  half of the bounded-message rule only; #282 still owns the rest of that class.

- **`build_status_list_credential` refuses an `issuer` or inline `@context` object that
  the VC-JWT lane would refuse** ([#309](https://github.com/luisgf/openvc/issues/309),
  found by the integration gate of #307; it predates it). Low severity, no wrong-accept:
  caller-side configuration. `VcJwtProofSuite.verify` refuses a payload with a member named
  `_sd`, `_sd_alg` or `...` at any depth (it is an SD-JWT issuer JWT, not a VC-JWT: #189,
  #291), and the builder accepted any member of an `issuer` object or an inline context
  object. So `issuer={"...": None, "id": did}` (also `{"_sd": []}` and
  `{"_sd_alg": "sha-256"}`, and the same inside a nested object) built, signed as a
  VC-JWT, and was then refused by `default_status_list_resolver` with `MalformedToken`: the
  class #230 closed for the index and the strings, openvc minting what its own verifier
  refuses. The marker as a *value* (`{"name": "..."}`) is not one and still builds: the
  fence reads member names only.

  The builder now raises `StatusListError` at build time, before anything is signed, for an
  `issuer` object or a `contexts` entry (`contexts[N]` in the message) that carries one of
  the three names at any depth, on every lane: it cannot know which lane will secure the
  list, and VC-JWT is the default for status lists. The message names the field and the
  three reserved names, never the object. The test is the lane's own predicate
  (`vc_jwt._carries_sd_jwt_marker`, imported, not copied, so the two rules cannot drift),
  run on the JSON the object encodes to, which is what the lane decodes: a marker held in
  a `tuple` (an array on the wire, which the predicate does not walk as a Python object)
  is found too.

  - **Behaviour change, narrow.** An `issuer` or context object that stdlib `json` cannot
    encode at all (a cycle, nesting past the interpreter's limit, a key that is not a
    string, number, boolean or `None`) is now a `StatusListError` at build time, because
    it cannot be checked; it could not be signed either (`ValueError`, `RecursionError` or
    `TypeError` at sign). A *member* that is not JSON (`bytes`, a `set`) is unchanged: it
    builds and fails at sign.
  - **Behaviour change, by decision (#309): the rule is the same on every lane.** An
    `issuer` or context object with a marker member that built and verified on
    `eddsa-jcs-2022` or `ecdsa-jcs-2019` is refused at build time too. The builder cannot
    know which lane will secure the list, and VC-JWT, the default, refuses it.
  - **Not changed:** the fence itself and the zero-disclosure SD-JWT residual it
    documents, the verify side, and the IETF Token Status List builder (it takes no
    caller-supplied object). The check is a build-time snapshot of the object the builder
    copies: a nested member stays the caller's own object, and one changed afterwards
    can still produce a list the lane refuses. Data Integrity lists with such members
    were never a documented shape.
  - The property test `test_property_whatever_the_builder_accepts_the_pipeline_accepts`
    failed now and then on a clean `main`: its strategy drew a marker name from
    `text(max_size=6)` rarely, and its model called that issuer valid. That was this
    inconsistency, not a flaky test. The model and the strategies now exclude the marker
    names, and the refusal properties pin the counterexample.

### Tests

- `tests/test_status_issuer_binding_issuerless.py` runs every case through the sync and
  async default resolvers and pipelines, and `verify_many` / `verify_many_async` (two
  credentials, two status URLs, both orders): the shapes that must still be refused, the
  shapes now accepted, delegation, the shape and non-mutation of the returned body,
  hostile `issuer` values, a custom resolver, the IETF token path, the Data Integrity
  lane, and no binding. The refusal of a foreign body issuer is pinned per lane
  (`ClaimsInvalid` on VC-JWT and `vc+sd-jwt`, `StatusListError` on `dc+sd-jwt`), and a
  victim-signed list whose issuer is `{"@id": <victim>}` is pinned as still refused
  under the binding on every lane.
- `tests/test_clock_reading_subclass.py` (694 cases): `utc_instant` and `utc_epoch` of 13
  lying subclasses and 6 controls, each at 4 pinned host zones (`UTC`, POSIX UTC+9,
  UTC+1 and UTC-5 with DST, which need no tzdata, with a check that the pin took effect);
  the status builders, `verify_status_list_token`, `verify_credential` on
  `eddsa-jcs-2022`, the SD-JWT KB-JWT window through `verify_vp_token` and
  `x5c.validate_cert_chain` at an instant inside the window, 15 minutes after it closes
  and 15 minutes before it opens, for 10 kinds of pin; a tripwire subclass that records
  every attribute read off it; `fold`; the typed error for an object that only claims
  `isinstance(x, datetime)` (a `__class__ = datetime` class, a `MagicMock(spec=datetime)`);
  and the unchanged year-1 / year-9999 range, error class and `name=` of the helpers.
  Every expectation is an exact value or an exact class.
  Against the code before this change (`65c1e03`) the negatives fail and the controls
  pass; with a mutant of the fix that puts `now.utcoffset()` back in either helper, asks
  `now.replace()` / `now.timestamp()`, drops `fold` or `tzinfo`, routes `utc_epoch`
  through `utc_instant`, reads the fields through instance methods, or takes the snapshot
  outside the `try`, each is killed.
- **`tests/test_message_helpers_total.py`** (#282). 164 tests, self-contained (`tests/` is not
  a package), with the hostile objects built inside the tests because pytest builds a
  parameter id by calling `str()`, which on an `int` subclass calls its `__repr__`. The helper
  matrix runs 15 objects (an `int` and a `float` subclass with a raising `__repr__`; a `str`
  subclass with a raising `__repr__`, `__len__` and `__getitem__`; an `int` subclass with a
  raising `bit_length`; one of 10**5000 whose `bit_length` returns 1; an `int` and a `float`
  subclass whose `__repr__` returns a non-`str`; an `int` and a `str` subclass whose `__repr__`
  returns 1 MB; a type whose metaclass `__name__` raises, and one whose `__name__` is not a
  string; a type name of 5 million characters, from a metaclass and from `type(name, ...)`)
  through each of the three helpers, asserting the exact text; a separate test pins the 64
  character edge (63, 64 and 65 characters). 46 status entry points
  (the builders, the codecs and the checks, one hostile object per parameter that reaches
  `brief`) assert the exact class `StatusListError` and the message. `did:web` resolves a
  valid DID given as a hostile `str` subclass (sync and async), refuses an invalid one with
  exactly `DidResolutionError`, and refuses a document whose `id` is another DID, missing or
  not a string with exactly `DidResolutionError` and the exact message, for a DID that is a
  hostile `str` subclass (sync and async), and cuts a 5-million-character `id`. `non_negative_seconds`, `SdJwtVcProofSuite(leeway_s=...)`,
  `SdJwtVcProofSuite.verify(kb_max_age_s=...)` and `verify_vp_token(leeway_s=..., kb_max_age_s=...)`
  raise exactly `ProofError`, `SdJwtError` and `OpenID4VPError` with the exact message. Controls
  that pass before and after pin the plain-value text of all three helpers and of
  `non_negative_seconds`. Against `65c1e03` 143 fail and 21 pass (the 6 controls, the structural
  check and 14 cells that were already total: the `str` cells of `brief`, the numeric cells of
  `_brief`, a lying `str.__getitem__` on `safe_repr`); 24 targeted mutants of the fix (each
  call of a method of the value restored, each `try` / `except` and `str`-name guard removed,
  each limit moved by one) are each killed, and so are 14 more for the type-name cut and the
  `did:web` message (each of the three cuts removed, moved by one either way and its `...`
  dropped; each of the two `safe_repr()` calls in `_validated_document` put back as `!r`,
  which fails 14 tests when both are).
- `tests/test_key_resolution_error_family.py` (new, 218 cases): the lane-by-scenario map
  (VC-JWT, SD-JWT VC, `eddsa-jcs-2022`, `eddsa-rdfc-2022` through the four entry points, plus
  the suite called directly and the three ECDSA suites) with a control for every row that
  verifies the same credential against the good document; the handlers; the hierarchy,
  `__module__`, traceback and pickle pins; the malformed `did:key` cases (including that the
  `KeyResolutionError` that replaces the bare `DidResolutionError` is not a `DidError`, the
  recorded exception) and the limits of the new `try`; batch isolation; and the `ldp_vc`
  holder proof and embedded credentials.
- The 28 existing cases that pinned the old split (`test_did_document_shape_typed.py`,
  `test_did_reference_exact_match.py`, `test_did_webvh_state_envelope.py`,
  `test_lone_surrogate_typed.py`) now assert the new exact class and the new `isinstance`
  relations; none was loosened.
- **`tests/test_sd_jwt_issuer_aud.py`** (#227, 327 tests, negatives first, each pinning
  the exact class and that the message does not describe an expiry). Every rejection runs under
  the default policy and `require_not_expired=False`, sync and async: `aud` naming someone
  else as a string, an array, `""` and `[]`, with no audience, with a different audience,
  and with a KB-JWT correctly bound to you on both the required-binding and the hosted
  path; the six malformed shapes (`null`, a number, `{}`, `true`, `[ME, 5]`, `[[ME]]`) with
  and without an audience; `verify_many` / `verify_many_async` isolating the one item;
  the near-miss audiences (trailing slash, case, prefix); an `aud` made disclosable
  (disclosed and mismatched, disclosed and matching, withheld pinned as the limit) and one
  made of digests per entry (one entry disclosed, only someone else's, none, never called
  malformed); the expiry waiver not waiving it; the KB-JWT failing first under
  `require_key_binding`; nested in a VP-JWT, bare and enveloped, and in a Data Integrity
  presentation, with a mixed set and the policy audience having no say; the OpenID4VP
  `dc+sd-jwt` lane and the DC API origin form; the helper's `require_present` modes;
  and the unchanged cases (no `aud` with and without an audience, the two third-party
  vectors and the OpenID4VP capture still verifying with an audience, a forged `aud`
  failing on the signature). A final section pins the W3C VCDM payloads the first
  version of the file never minted: a hand-minted credential with `typ` absent,
  `vc+sd-jwt`, `vc+ld+json+sd-jwt` (each with and without `iss`, #290) and `dc+sd-jwt`,
  `aud` naming someone else rejected with no audience, with a different one and behind a
  correct KB-JWT, `aud` naming the verifier (alone or in an array) verifying with
  `vcdm` true, and no `aud` unchanged.
- **Mutation check.** Run on 65c1e03 (`git archive`), the new file has 224 failures and 103
  passes, the 103 being the accept-side controls. Thirteen targeted mutants of the change
  (checking the signed body instead of the processed payload, requiring `aud`, no check,
  no audience accepted, a message that says "expired", an unvalidated expected audience,
  the present-only mode returning on a present `aud`, an unvalidated shape, the waiver
  skipping the check, a substring or case-insensitive match, a mismatch ignored, and the
  body checked before the KB-JWT) are each killed. Five more (skipping the check for a VCDM
  payload, for a token with no `typ`, for one with no `iss`, or for `vc+sd-jwt` or
  `vc+ld+json+sd-jwt`) survived the first version of the file and the 1974 tests around
  it, which is why the VCDM section exists; each is killed by it.
- `tests/test_ecdsa_sd_issuer_context_typed.py` (#281): the ten `@context` values of the
  issue on `add_base_proof` and on `derive_proof` (a genuine base proof with its
  `@context` swapped), plus, on `derive_proof`, the bodies `pyld` refuses (a `type`
  holding an integer, a numeric `credentialSubject.id` / `@id`, a `@reverse` that expands
  but does not compact, and a nested node spelled `urn:bnid:c14n0`, which ended in a bare
  `KeyError` in the last guarded step), each asserted as exactly `ProofMalformed` with the
  prefix; the message cut in all three arms (a synthetic error text around the 2000
  boundary, up to 1 000 000 characters, and a real 1 MB `@context` and URL, with the
  oversized text shown to reach the cause); controls for the round trip, the
  `validate_document` refusals that keep their message (the `add_base_proof` body
  refusals included), a signing-backend and an ephemeral-key error that surface as
  themselves, a bad pointer that stays `EcdsaSdError`, a context served through
  `extra_contexts`, the verify side (`verify`, `verify_credential`, `verify_many`,
  `verify_many_async`) and the RDF siblings' unchanged classes.
- `tests/test_proof_created_time.py` (#287): the five entry points against eleven values
  that are not a `datetime`, three with no UTC reading, the order of the checks, the
  host zone pinned by `TZ` + `tzset` (five zones; winter, DST summer, `datetime.min` /
  `max`, a `tzinfo` with no offset), the same `proofValue` on any host for the
  deterministic suites, round trips for years 1, 2999 and 9999 (and
  base / derive / verify for `ecdsa-sd-2023`), and a Hypothesis differential against the
  old `astimezone(...).strftime(...)` for aware datetimes in years 1001 to 9998 (the
  edges and years before 1000 have their own cases).
- **`tests/test_dcql_credential_sets_shape.py`** (#284). Negatives first, each pinning the
  exact class and a `match` on the field (and the set or option index), so none can pass
  on the "missing required Credential Query id(s)" message or on another failure: the
  twelve non-conforming top-level values, each with the wallet answering a subset and every
  query; the non-object entries; the missing, `null`, string, empty, object and number
  `options`; the empty and flat options; an option holding a number, `null`, a bool, an
  array (the unhashable case) or an object beside the answered `a` and the unanswered `b`;
  an unknown, empty or near-miss id; a good set or option followed by a bad one, and the last
  of several; the nine non-boolean `required` values. Ordering: a malformed `multiple`,
  `meta`, `require_cryptographic_holder_binding` or a later query with no `id` is reported
  before a malformed `credential_sets`, which is reported before an unknown `vp_token` key,
  a non-array and an empty presentation list and a junk Presentation; an empty `vp_token`
  is still reported first. Controls that pass before and after: the absent key, a
  well-formed set answered in part and in full, `required` `true` and `false`, `purpose` as
  a string, number, object and `null`, unknown members, a duplicate id in an option.
- **`tests/test_dcql_credential_sets_enforced.py`** (#285). The issue's rows B to F, a
  required set followed by an optional one and the reverse, three required sets with the
  first, middle and last left out, a two-id option answered by either id alone, and the
  same through `verify_encrypted_vp_response`, each pinning `type(exc) is VpTokenIncomplete`
  and the set index. Ordering: an unsatisfied set is reported before an unknown key,
  `{"pid": "notalist"}`, `{"pid": []}` and a junk Presentation (built on `pid`, so the bad
  entry cannot satisfy the required set `[["age"]]`), and after a malformed
  `credential_sets` and a malformed query member. Controls: the issue's rows G, H, I and J,
  every set optional, a set satisfied by its second option, extra answers returned by
  `for_query`, the omitted `required` meaning `true`, a complete response with no
  `credential_sets`, and an unsatisfied response still caught by `except VpTokenMalformed`.
- **`tests/test_dcql_meta_upfront.py`, `tests/test_dcql_multiple_boolean.py`** (#285). The
  `missing-required-query-id` case of `LATER_CHECKS` pins the exact class of the
  missing-query error, which is now `VpTokenIncomplete` (decision 3 above); the other three
  cases keep `VpTokenMalformed`. No other existing test changed.
- `test_openid4vp_bare_w3c_vc.py` (new): the positive cases on both lanes and over the DC
  API (VC-JWT; `ecdsa-jcs-2019`, `eddsa-jcs-2022`, `ecdsa-rdfc-2019`, a derived
  `ecdsa-sd-2023`); a presentation still accepted and still bound with the flag `false`;
  the flag `true` / absent rejecting a bare credential without reaching the VP-JWT suite
  or the pipeline; a bare SD-JWT, a tail-dropped SD-JWT issuer JWT, a VP-JWT, a
  `VerifiablePresentation`-typed object and an enveloped credential not mis-routed; each
  ambiguity (both claims, `typ` contradicting the claim in both directions, both types);
  everything unparseable left to the presentation lane with its exact class; a tampered or
  wrongly signed bare VC-JWT, a tampered Data Integrity VC, an issuer-binding mismatch, an
  expired token, an `aud`-restricted token, a presentation-purpose proof on a credential;
  `require_holder_binding`; `meta.type_values`; `require_status`; and the format pin
  (`_check_bare_format`). The negatives fail on 1.34.0 and the controls pass there.
  - **Every argument the caller supplies is pinned to reach the pipeline** (section G,
    after a mutation run found eight that no test noticed being dropped). The resolver, the
    W3C status-list resolver (revoked and not revoked, with `require_status` left `False`,
    on both lanes: a dropped resolver would otherwise skip revocation silently), the IETF
    token status resolver, `jwt_vc_issuer_fetch`, `x5c_trust_anchors`, `extra_contexts` (for
    the RDF proof and for `meta.type_values` separately), `leeway_s` (a wider and a zero
    window against the default) and `now` (a pinned Data Integrity window and an x5c chain
    check). Dropping or hard-coding any of them in `_verify_bare_w3c_vc` now fails a test.
    The one argument left unpinned is `kb_max_age_s`: a string with a `~` is never routed
    here, and `detect_format` calls only such a string an SD-JWT, so no Key Binding JWT can
    reach the bare route and the argument is inert.
  - A presentation typed `[VerifiablePresentation, EnvelopedVerifiableCredential]`
    verifies under every flag; one also typed `VerifiableCredential` is still ambiguous.
  - A hostile token that looks bare (`alg` `none` or `RS256`, an unknown `crit`) keeps the
    suite's own class with the flag `false` and is `VpTokenMalformed` otherwise.
- `tests/test_pyld_context_isolation.py` runs the issue's repro through the real pipeline,
  in one process and in the order that exposes the cache (tenant A's contexts, then tenant
  B's for the same URLs, then none), for an inline `@import` in the credential, a served
  context that holds one (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `ecdsa-sd-2023`), the
  `expected_types` pin, and the cross-caller property case; each call must see only its
  own loader, and each assertion names the exact exception class; one more runs the forms
  that collided in pyld's entry (inline `@import`, the same terms inline, the URL itself)
  in several orders and requires one dataset. They name no new API and fail on 1.34.0.
  `tests/test_pyld_options.py` pins the structural half (the source scan
  and its own tests, the run-time recorder, the bundled-only store and its window, and the
  rule that bundled documents reference no other URL). Both run on the pyld 2.0.4 floor.
- **`tests/test_leeway_validation.py`** (new). The value matrix (`NaN`, `±inf`, `-1`, `-60`,
  `True` / `False`, `"60"`, `None`, `[]`, `b"60"`, `1j`, `60.0`, `60.5`, `1.5`, `10**12`,
  `10**400`, `MAX_LEEWAY_S + 1`, `Decimal`, `Fraction`, a float subclass, an `__index__`-only
  object, a lying `int` subclass, an object whose `__class__` claims `int`, `Mock(spec=int)`
  and `MagicMock(spec=int)`) against every suite constructor, every function entry point
  (each fed garbage everywhere else, so the match on `leeway_s` proves the check runs first),
  `VerificationPolicy`, `dataclasses.replace`, the three backstop helpers, and the pipeline
  through `verify_credential`, `verify_credential_async`, `verify_many` and `verify_many_async`
  over VC-JWT, SD-JWT and Data Integrity with a corrupted policy. Each case asserts the exact
  error class, never a bare exception, and that an expired item is not accepted; the
  fail-open rows run an expired and a not-yet-valid item under `NaN`, `inf`, `"60"`, `None`,
  `10**12` and `10**400`. Controls: `0` and `60` reject an item that lapsed an hour ago, `60`
  absorbs one that lapsed 30 s ago (and `0` does not), `MAX_LEEWAY_S` absorbs an hour but not
  a day and an hour, on VC-JWT, VP-JWT, SD-JWT, the status-list token and Data Integrity.
- Existing tests rewritten for the new range: `test_interop_vectors.py`,
  `test_rp_registration.py`, `test_sd_jwt_vcdm_validity.py`, `test_jose_temporal_claims.py`,
  `test_typed_clock_pins.py`, `test_sd_jwt_kb_freshness.py` and `test_openid4vci.py` (see the
  decisions above).
- **`tests/test_status_builder_sd_markers.py`** (#309, 181 tests, self-contained). The
  three marker names at the top of an `issuer`, nested, in a list, in a tuple, in a `dict`
  subclass, under a `str`-subclass key, and in an inline context object, each against the
  exact class `StatusListError` with a key that fails the test if it is asked to sign and a
  60 KB sentinel that must not reach the message; controls that build, sign and verify on
  VC-JWT and `eddsa-jcs-2022` (the marker as a value, near-miss names, a tuple, ordinary
  objects); cycles, nesting past the limit and non-scalar keys; a parity test that the
  builder refuses an object exactly when the default resolver refuses the same object
  signed around the builder; and a Hypothesis property with the counterexample of #309
  pinned as an `@example`. In `tests/test_status_builders_inputs.py` the model and the
  strategies now exclude the marker names, and the refusal properties pin the
  counterexamples. Against `origin/main` the old property fails on Hypothesis seeds 36 and 56
  (`MalformedToken`; Hypothesis 6.156.1, example database cleared) and passes on 1 to 5; on this branch the updated one passes on seeds 1
  to 150. Mutation check on `origin/main`: 121 of the 477 cases in the two files fail and the
  controls pass; seven mutants of the fix (no issuer check, no context check, the
  predicate never true, top level only, the predicate on the Python object, no typed error
  for a value that cannot be encoded, no `default=` hook) are each killed.

### Docs

- `wiki/Getting-Started.md` states the range once (new *Clock skew: `leeway_s`* section);
  `VC-JWT`, `SD-JWT-VC`, `Presentations`, `Status-Lists` and `Data-Integrity` point to it, and
  the Data Integrity page no longer says a negative or `NaN` leeway counts as 0.
  `docs/CONVENTIONS.md` records the rule for new knobs, `docs/audit/threat-model.md` R10 closes
  the caller-configuration class it left open, and `docs/audit/assurance.md` §4 cites #228
  and #232.

## [1.34.0] — 2026-10-15

**Upgrading from 1.33.2.** Five things can change what a caller sees (each is detailed in
the entry for the issue it names, below):

1. A `vc+sd-jwt` whose VCDM base `@context` is not first, or whose `type` is absent,
   withheld or not a credential, is now refused with `SdJwtError` (#275). It replaces
   `TypeMismatch`, `CredentialExpired`, `CredentialRevoked` and `StatusUnavailable` for such
   payloads.
2. A non-conforming SD-JWT nested in a `jwt_vc_json` or `ldp_vc` presentation fails the
   whole `verify_vp_token` call (#275).
3. VCDM SD-JWTs with no `typ` or with the draft-era `vc+ld+json+sd-jwt` now verify (#288,
   #289).
4. An SD-JWT with no `iss` and a VCDM `issuer` now verifies (#290), so
   `result.claims['iss']` can raise `KeyError`: use `result.issuer`. `verify()` also
   refuses an empty `iss`.
5. The VC-JWT lane refuses a payload with SD-JWT markers, and the VP-JWT lane refuses
   SD-JWT-typed JWS and the same markers (#291).

### Security

- **The VC-JWT lane refuses a JWS whose payload carries SD-JWT markers, and the VP-JWT
  lane refuses an SD-JWT issuer JWT**
  ([#291](https://github.com/luisgf/openvc/issues/291)). Hardening; no wrong-accept was
  found, because it needs an issuer that signs a hybrid no spec defines. **This is a
  behaviour change:** a payload that carries these markers and verified as a VC-JWT is
  now refused (`MalformedToken`). A VP-JWT typed `sd-jwt`, `*+sd-jwt` or `kb+jwt`, or whose
  payload carries such markers, is refused the same way. No real VC-JWT carries these
  markers, but one that uses such a member name for its own data (a JSON Schema that
  describes an SD-JWT payload, say) is refused too.

  Explicit typing (RFC 8725 §3.11, #189) works only while the issuer sets a `typ`. An
  SD-JWT issuer JWT with none, or with one the typ filter does not know, whose payload
  holds a `vc` object verified as a VC-JWT once its `~` tail was dropped, shedding key
  binding: the holder sent the issuer JWT alone, and the lane that read it as a VC-JWT
  asked for no KB-JWT. Before 1.34.0 that was so in every release; #189 closed only the
  typed case.

  - **VC-JWT lane.** `VcJwtProofSuite.verify` walks the decoded payload, iteratively and
    at any depth, objects and arrays, and raises `MalformedToken` when some object has a
    member named `_sd`, `_sd_alg` or `"..."` (RFC 9901 §4.1 item 7 and §4.2.4.2: `_sd`
    and `...` are reserved, and `...` is the array-element digest object; §4.1.1: `_sd_alg`,
    top level only, refused here at any depth). It runs before the signature is checked
    and before the suite loads its verification key (the `verify_credential` pipeline
    resolves the issuer first), on the classic and the ML-DSA lane, sync and async. An issuer
    JWT that holds a `vc` object keeps its disclosable claims inside it, so a top-level
    test would miss exactly that shape. The stripped form of a token with disclosures is
    now refused whatever its `typ`.
  - **VP-JWT lane.** `VpJwtProofSuite.verify` never read `typ`. It now refuses a JWS typed
    as an SD-JWT issuer JWT or a KB-JWT (the VC-JWT lane's filter) and a payload with the
    same markers, before the holder key is resolved. The walk covers the whole payload,
    so an embedded Data Integrity credential object is scanned; a nested VC-JWT is a
    string there and meets the same fence when the cascade verifies it. The algorithm
    allow-list and the `crit` check also run before the holder key is resolved now (before,
    `verify_compact` ran them after the resolver), so a VP-JWT with a disallowed `alg` or
    any `crit` fails with `UnsupportedAlgorithm` / `MalformedToken` without a resolver call,
    where an unresolvable holder used to report `KeyResolutionFailed` first.
  - **What this does not cover.** A zero-disclosure SD-JWT issuer JWT with no `typ`, a
    `vc` object and a `cnf` carries none of `_sd`, `_sd_alg`, `...` (an `_sd_alg` alone,
    or a decoy digest, is already refused), so it cannot be told from a VC-JWT that
    carries a `cnf`, and it still verifies as a VC-JWT. The VC-JWT lane never enforces
    `cnf`. This is a documented limitation, pinned in `tests/test_vc_jwt_sd_fence.py`.

### Added

- **A W3C VCDM credential secured with SD-JWT verifies when its issuer JWT has no `typ`,
  or the draft-era `vc+ld+json+sd-jwt`**
  ([#288](https://github.com/luisgf/openvc/issues/288),
  [#289](https://github.com/luisgf/openvc/issues/289)). Found by the spec-pin check of
  2026-10-14. This accepts input that was refused before.

  W3C VC-JOSE-COSE (Recommendation of 13 October 2026) makes the SD-JWT `typ` a SHOULD
  (§3.2.1), and its verification algorithm (§5.2) takes the media type as an input, not
  from the header. Its own examples show it: Examples 4 and 5 carry the header
  `{"kid", "alg"}` with no `typ`, and Example 21 carries `typ: vc+ld+json+sd-jwt`, the
  media type name that the 2023 Working Drafts and the First Candidate Recommendation
  (25 April 2024) of VC-JOSE-COSE gave it, before the rename to `vc+sd-jwt`. openvc refused both before any crypto (`unexpected issuer JWT
  typ`). The Recommendation publishes no key for them, so the new tests pin the real
  tokens through the `typ` gate, which they now pass, and they fail only at the signature
  check. The credentials of Examples 4 and 5 carry no `iss` claim either, which the SD-JWT
  lane needed to select the issuer key; the next entry
  ([#290](https://github.com/luisgf/openvc/issues/290)) lets such a credential name its
  issuer in `issuer` alone. A VCDM SD-JWT with an `iss` and no `typ` verified with this
  entry alone.

  An issuer JWT with no `typ` member, and one typed exactly `vc+ld+json+sd-jwt`, are now
  treated like `vc+sd-jwt` (#264):
  - they are accepted only for a payload with a VCDM base `@context` (a conforming one:
    [#275](https://github.com/luisgf/openvc/issues/275), under Changed), and get the VCDM
    validity window and the issuer / id / subject checks;
  - otherwise they raise `SdJwtError` ("needs a W3C VCDM @context"), a `vct`-bearing IETF
    payload included: an IETF SD-JWT VC is typed `dc+sd-jwt`;
  - a token with no `typ` must not carry a `vc` or `vp` claim (VC-JOSE-COSE §1.1.2.1,
    restated in §3.1.3). With
    a `vc` object it would be an SD-JWT VC here and, with its `~` tail dropped, a VC-JWT in
    the VC-JWT lane, which has no `typ` to refuse: the holder could shed key binding. A
    token accepted here has no `vc` claim, so that lane refuses its stripped form ("no
    embedded `vc` object"). That lane also refuses a payload that carries SD-JWT markers
    (`_sd`, `_sd_alg`, `"..."`), whatever its `typ` (#291, under Security above);
  - a token with no `typ` must say it is a credential: its `type` has to include
    `VerifiableCredential` and not `VerifiablePresentation` (VCDM 2.0 §4.5, §4.13;
    [#293](https://github.com/luisgf/openvc/issues/293)). The `typ` is what tells the two
    apart, and a VCDM 2.0 presentation secured with SD-JWT has the same `@context` as a
    credential and no `vp` claim to ban, so without this check a holder-signed
    presentation with no `typ` would be read as a credential issued by the holder. The
    check is positive: a `type`, or its `VerifiableCredential` entry, that is missing or
    withheld is refused, and so is one that spells the term as a full IRI or a prefixed
    name. Here it applies to a missing `typ`; #275 (under Changed) extends it to the
    typed W3C cases.

  A `typ` that is present and anything else is still refused, `null` and any non-string
  included, and matching stays exact: no case folding, no `application/` prefix.
  `dc+sd-jwt` is unchanged. `VerifiedSdJwt.typ` is `None` for a token with no `typ`, and
  the OpenID4VP `dc+sd-jwt` lane still refuses both new cases (#272).

  This drops an explicit-typing guard (RFC 9901 §9.11) for VCDM payloads. What stands in
  for it: the signed VCDM `@context`; the `type` check; the ban on `vc` and `vp`, which
  keeps a token accepted here from also being a valid VC-JWT; and key binding (`require_key_binding`
  still needs a KB-JWT). The older gap in the VC-JWT lane, an issuer JWT with no `typ` and
  a `vc` object verifying there with its `~` tail dropped, is closed by
  [#291](https://github.com/luisgf/openvc/issues/291) (Security, above) for every token
  that has a disclosure; a zero-disclosure token carries none of `_sd`, `_sd_alg`, `...`
  and is its documented limit. The validity window and the issuer / id / subject checks still count
  a VCDM base URL anywhere in `@context` as VCDM; being read as a credential at all takes
  a conforming payload (#275, under Changed).

- **A W3C credential secured with SD-JWT verifies when its issuer JWT has no `iss` and its
  VCDM `issuer` names the issuer**
  ([#290](https://github.com/luisgf/openvc/issues/290)). This accepts input that was
  refused before; it is not hardening.

  Until now the SD-JWT lane chose the issuer key from `iss` alone, on every lane:
  `peek_issuer` raised `MalformedToken` ("no iss in the issuer-signed JWT") and `verify()`
  raised `ClaimsInvalid` ("iss claim is missing or not a string"). W3C VC-JOSE-COSE
  (Recommendation of 13 October 2026) makes `iss` optional: §4.1.2 says that `iss`, if
  present, MUST match `issuer` (or `issuer.id`), and §4.2 says that when `iss` is absent
  and the issuer is a URL, the `kid` MUST be an absolute URL to a verification method in
  the issuer's controlled identifier document or DID document. openvc takes the identifier
  from `issuer` and resolves it with the same paths as `iss`. Its own SD-JWT credential,
  Examples 4 and 5, has an `issuer` and no `iss`. So #288 and #289 let those examples'
  headers through and their payloads still stopped at the issuer.

  **The rule.** The issuer is the `iss` claim. When the issuer JWT has none, it is the VCDM
  `issuer` of its body, under four conditions that all have to hold:
  - the `typ` is a W3C state: absent, `vc+sd-jwt` or `vc+ld+json+sd-jwt`. A `dc+sd-jwt`
    keeps requiring `iss`, with the old texts. A header `"typ": null` is a `typ` that is
    present, not an absent one, and is not a state: no fallback (and `verify()` refuses it
    as a `typ`);
  - the issuer JWT has no `iss` member at all. A present `iss` that is `null`, a number, a
    bool, an object or `""` is still refused, and is not replaced by `issuer`;
  - the `issuer` is in the body of the issuer JWT. One in a disclosure is never used, so a
    holder cannot supply the identifier that selects the key, and a token whose only `issuer`
    is disclosed is refused as before;
  - it is a non-empty string, or an object whose `id` and `@id` members that are present
    (`id` aliases `@id` in JSON-LD) are all the same non-empty string. An object with
    neither, one whose two members disagree, and any other value are refused.

  `peek_issuer` returns that identifier, which is what the pipeline resolves the key from,
  and `verify()` uses it as the issuer (`VerifiedSdJwt.issuer`) and as the `iss` the
  `issuer` / `jti` / `sub` reconciliation (#221) runs with. When the token has both an `iss`
  and an `issuer`, they must still agree (`ClaimsInvalid`, as on the VC-JWT lane).
  `VerifiedSdJwt.issuer` is the identifier whose key verified. There is no new key
  resolution path: the same DID methods, `/.well-known/jwt-vc-issuer` metadata and `x5c`
  binding run on the identifier, sync and async. The identifier is unauthenticated until the
  signature verifies, exactly as `iss` is: it only selects the key to try.

  **What it does not do.** It does not derive the issuer from the `kid`: a token with no
  `iss` and no usable `issuer` is refused even when its `kid` is a DID URL, and §4.2's rule
  that the `kid` be an absolute URL is not enforced. It does not relax `dc+sd-jwt`, so an
  IETF SD-JWT VC that names its issuer only in an `x5c` header is still refused. It does not
  change `issue()`.

  **Messages.** The two old texts and their classes are kept. They gain a clause only when
  the fallback was available, that is, when the issuer JWT has no `iss` member and its `typ`
  is a W3C state:
  ``no iss in the issuer-signed JWT (and no usable VCDM `issuer` for a W3C credential)``
  (`MalformedToken`, from `peek_issuer`) and
  ``iss claim is missing or not a string (and no usable VCDM `issuer` for a W3C credential)``
  (`ClaimsInvalid`, from `verify()`). A present but unusable `iss` (`null`, `""`, a number, a
  bool, an object), a `dc+sd-jwt`, a `"typ": null` and any other `typ` get the bare old text
  (from `peek_issuer`; `verify()` refuses a `"typ": null` or any other unaccepted `typ`
  earlier, at the `typ` gate).

  **What a caller sees.** For a token verified through the fallback:
  - `result.claims`, `result.credential` and `VerifiedSdJwt.claims` have no `iss` key, so
    code that reads `claims["iss"]` gets a `KeyError`. Before this release every SD-JWT that
    verified had a string `iss` there. The issuer is `result.issuer` (`result.raw.issuer`),
    the identifier whose key verified.
  - An https `issuer` resolves its key through `jwt_vc_issuer_fetch`, as an https `iss`
    does, and without that argument the pipeline raises `KeyResolutionFailed` ("pass
    jwt_vc_issuer_fetch", or "pass an async jwt_vc_issuer_fetch" on the async pipeline).
    For Example 5 as published that is the first thing a caller sees; it used to be
    `MalformedToken` at the peek. Likewise a payload with no `typ`, a
    `vct` and a claim called `issuer` (an IETF-shaped payload that forgot its `typ`) now has
    a key resolved, and for an https `issuer` its metadata fetched, and is then refused at
    `verify()` as `SdJwtError` ("needs a W3C VCDM @context; an IETF SD-JWT VC is typed
    'dc+sd-jwt'"), where it used to be refused at the peek as `MalformedToken`.
  - `verify()` refuses an empty-string `iss` too (`ClaimsInvalid`, the bare text), for every
    `typ`, a `dc+sd-jwt` included. Only the pipeline's `peek_issuer` did before: a caller of
    the suite directly got `issuer == ""` back (a W3C body that also had an `issuer` failed
    the `iss` / `issuer` reconciliation instead).

  **The Recommendation's examples.** Example 5 as published gets past the issuer.
  Through `verify_credential`, `peek_issuer` now returns its `issuer` (it raised
  `MalformedToken` before) and the pipeline fetches
  `https://university.example/.well-known/jwt-vc-issuer/issuers/565049` for it through your
  `jwt_vc_issuer_fetch`, or raises `KeyResolutionFailed` when you passed none. The
  Recommendation publishes no key, so with any other key it fails only at the signature
  (`SignatureInvalid`). On the suite directly a stranger key fails the same way, because
  `verify()` checks the signature before the issuer. Re-signed under a key of our own, with
  its header, payload and disclosures as published and no `iss` added, it verifies: `issuer` is
  `https://university.example/issuers/565049`, `typ` is `None` and `vcdm` is true. A
  credential issued by a DID verifies end to end through `verify_credential` and
  `verify_credential_async`, as a string `issuer` or as an object with an `id`, with no
  `typ` or with `vc+sd-jwt`. The guard for Example 5 is
  `test_example_5_as_published_verifies_without_adding_an_iss` in
  `tests/test_sd_jwt_issuer_fallback.py` (with the pipelines, the stranger key and the missing
  fetch in the tests beside it), and `test_example_5_verifies_end_to_end_under_a_key_of_our_own`
  in `tests/test_sd_jwt_vcdm_typ_interop.py` runs the same unamended payload through the
  pipeline and the suite; the rest of the first file pins the other cases.

  **Behaviour change.** A token that has a usable `iss` is read as before. A W3C-typed token
  that has none and names its issuer in the body, which raised `MalformedToken` or
  `ClaimsInvalid`, now verifies if its signature does: a caller that read that error as "the
  credential has no issuer" no longer gets it. That includes a credential whose issuer made
  `iss` selectively disclosable, when the holder withholds the disclosure and the body
  carries an `issuer`; a presented `iss` disclosure is still refused (`SdJwtError`). The
  other changes are the ones under "What a caller sees": no `iss` in the claims, a key
  resolved before an IETF-shaped payload with no `typ` is refused, and the empty `iss` that
  `verify()` now refuses.

  **Known limits.** The issuer JWT's own `aud` is not checked on the SD-JWT lane (an open
  item of ADR-0008), and this entry lets a W3C JWS with no `iss` and no `typ`, refused as a
  bare JWS on the VC-JWT lane, reach the SD-JWT lane by appending `~`, so an audience
  restriction its issuer put in `aud` is not enforced there; the `kid` rule of §4.2 is not enforced
  either (the `kid` only picks a key inside the issuer's own document, and one naming
  another DID never makes the resolver look at that DID); and an SD-JWT result's `subject`
  is its `sub`
  alone, so `require_holder_binding` on a `jwt_vc_json` or `ldp_vc` presentation refuses a
  fallback token that names its subject only in `credentialSubject.id` (as it did for every
  SD-JWT result, and it fails closed).

### Changed

- **An SD-JWT issuer JWT is read as a W3C credential only when it conforms; one that
  verified before and does not is now refused with `SdJwtError`**
  ([#275](https://github.com/luisgf/openvc/issues/275)). Until now a VCDM base context
  (`https://www.w3.org/ns/credentials/v2`, or the VCDM 1.1 `…/2018/credentials/v1`)
  *anywhere* in `@context` was enough. A `vc+sd-jwt` with the base URL in second place, or
  with no `type` at all (an `issuer` or `credentialSubject` is still not required), verified
  as a W3C credential.
  Hardening: no wrong-accept was found. The payload still had to be signed by the issuer,
  the signature check is unchanged, and a holder cannot change signed plaintext, so what
  was accepted is what the issuer signed. A pin did not close the gap: `expected_types`
  checked that the pinned type was among the `type` entries, never where the context
  starts or whether `VerifiableCredential` is there, so a policy pinned to
  `ExampleAlumniCredential` accepted a `vc+sd-jwt` whose `@context` started with another
  URL, and one whose `type` was `ExampleAlumniCredential` alone. The impact is a payload
  that is not a conforming credential read as one.

  An issuer JWT in any of the three W3C states (typed `vc+sd-jwt`, typed with the
  draft-era `vc+ld+json+sd-jwt`, or with no `typ`) now has to pass two tests on its
  processed payload, or `verify()` raises `SdJwtError`:
  - the **first** `@context` entry is a VCDM base context (VCDM 2.0 §4.3: the context is
    an ordered set whose first item is the base URL, and a string `@context` is its own
    first item). An object, a number, an empty array or any other URL in first place
    fails, whatever follows;
  - the `type` includes `VerifiableCredential` and not `VerifiablePresentation` (VCDM 2.0
    §4.5, §4.13; the compact term only). This was the rule for a token with no `typ`
    (#293, above); it now holds for the typed cases as well.

  Nothing else is tested. A `type` that lists `VerifiableCredential` next to an entry that
  is not a string (`["VerifiableCredential", 7]`) passes, a `VerifiablePresentation` spelled
  as a full IRI is not recognised, both base contexts (`[…/v1, …/v2]`) are accepted, the
  second and later `@context` entries are not checked, and `issuer` and `credentialSubject`
  are still not required.

  The refusals before these keep their order and their text: no VCDM base context
  anywhere ("needs a W3C VCDM @context; an IETF SD-JWT VC is typed 'dc+sd-jwt'"), then a
  `vc` or `vp` claim on a token with no `typ`. The new ones name the requirement that
  failed, so a caller can tell a misplaced context from a missing `type`: "issuer JWT
  typ 'vc+sd-jwt' needs a VCDM base context as the first `@context` entry (VCDM 2.0 §4.3),
  not just somewhere in it" (or "without a typ" in place of the typ) and "… needs a `type`
  that includes VerifiableCredential and not VerifiablePresentation (VCDM 2.0 §4.5,
  §4.13)". The context test runs first. `dc+sd-jwt` is unchanged: it follows the IETF
  rules (`vct` required, no `type` rule, no context-position rule).

  The lax test stays for the rest, on purpose. A base URL anywhere in `@context` still
  turns on the VCDM validity window (`validFrom` / `validUntil`, `issuanceDate` /
  `expirationDate`), the issuer / id / subject checks, the refusal in `issue()` to make
  those claims selectively disclosable, and `VerifiedSdJwt.vcdm`, for every `typ`, a
  `dc+sd-jwt` included. So a `dc+sd-jwt` with a base URL in second place still gets the
  window, and a holder that withholds a disclosable `type` cannot turn it off.

  The Recommendation's own examples still pass the gate once they carry a signature that
  verifies. The issuer JWTs of Example 5 (no `typ`) and Example 21 (`vc+ld+json+sd-jwt`)
  start `@context` with the v2 base context, and their `type` is a selectively disclosable
  claim that the token presents, so the processed payload says credential. The gate runs
  after the signature, and the Recommendation publishes no key, so the `SignatureInvalid`
  a stranger key gets from either token proves nothing about it. Re-signed under a key of
  our own, Example 21 as published passes, with its own `exp` (2024-10-14) waived through
  `check_temporal=False` / `VerificationPolicy(require_not_expired=False)` (`vcdm` is true,
  `expired` is true). Example 5 as published names its issuer only in `issuer`, which the
  entry under Added
  ([#290](https://github.com/luisgf/openvc/issues/290)) lets select the key, so it passes
  too, with no `iss` added. Withhold the `type` disclosure and both are refused. The
  guards are `test_example_21_verifies_end_to_end_under_a_key_of_our_own` and
  `test_example_5_verifies_end_to_end_under_a_key_of_our_own` in
  `tests/test_sd_jwt_vcdm_typ_interop.py`, both on the payload as published, and
  `test_example_5_as_published_verifies_without_adding_an_iss` in
  `tests/test_sd_jwt_issuer_fallback.py`.

  **Behaviour change.** Each case fails closed with `SdJwtError`, and in `verify_many` it
  fails only its own item.
  - A `vc+sd-jwt` that verified before this release is refused when its `@context` has the
    base URL only in second place or later, or when its `type` is absent, withheld or not
    a credential. (A token with no `typ`, or with the draft-era `vc+ld+json+sd-jwt`, was
    refused before #288 and #289 anyway, so for them the gate only bounds what those
    accept.)
  - A holder that withholds a selectively-disclosable `type` now gets a refusal for a
    typed token too. Before this release a typed token whose `type` was withheld verified, or
    failed with `TypeMismatch` under `expected_types`. The
    Recommendation's own Example 4 makes `type` disclosable, so an issuer should leave
    `@context` and `type` in the clear, with the v2 base context first.
  - Under `VerificationPolicy.expected_types` the gate runs before the pin looks, which
    moves more than hostile types. A `type` on a `vc+sd-jwt` that is a number, a bool, an
    object, or a string or array without `VerifiableCredential` used to reach the type
    check. If it did not name a pinned type it raised `TypeMismatch`; if it did (a `type`
    of `ExampleAlumniCredential` alone, with that type pinned) it **verified**. Both now
    raise `SdJwtError`, so for the second an accept becomes a refusal and is not a move
    between classes. A `vc+sd-jwt` whose `@context` has the base URL only in second place,
    with a pin its `type` does not meet, raised `TypeMismatch` and now raises `SdJwtError`.
    Both are `OpenvcError`; a caller that catches `TypeMismatch` for such input has to
    catch `SdJwtError` too. A conforming credential that lacks an expected type is still
    `TypeMismatch`.
  - The gate also runs before the checks that follow it, so a non-conforming W3C payload
    reports `SdJwtError` for each of them. Through `verify_credential`: an expired
    `validUntil` (`CredentialExpired`, and with `require_not_expired=False` a result with
    `expired=True`, which is now refused), a future `validFrom` (`CredentialNotYetValid`),
    an `issuer` that conflicts with `iss` (`ClaimsInvalid`), an `expected_vct` mismatch or
    an `aka_vcts` error (`ClaimsInvalid`), a KB-JWT `aud` or `nonce` error when
    `require_key_binding` is false (`ClaimsInvalid`), a revoked status (`CredentialRevoked`)
    and a missing status resolver (`StatusUnavailable`). All still fail closed and are
    still `OpenvcError`, but a caller that branches on `CredentialExpired`,
    `CredentialRevoked` or `StatusUnavailable` sees `SdJwtError` for such a token. What
    comes first is unchanged: the signature, a JWT `exp` or `nbf`, a missing `iss`, and,
    with `require_key_binding=True`, the KB-JWT.
  - In OpenID4VP a non-conforming SD-JWT nested in a `jwt_vc_json` or `ldp_vc`
    presentation, bare or enveloped, used to verify. It now fails the whole
    `verify_vp_token` call with the `SdJwtError` itself (not `VpTokenMalformed`), and with
    `multiple: true` the other credentials of the response go with it. The lane already
    did this for the typ-less rule of #293 and for a payload with no VCDM `@context`.
  - The gate judges the processed payload. An issuer that makes an array element of
    `@context` or `type` selectively disclosable (not the whole claim: a withheld one is
    refused) lets the verdict depend on what the holder presents; a flip to accepted needs
    the signer to have made that element disclosable, and `vcdm` stays true, so the
    validity window still runs.
  - The new refusals name the requirement that failed, so tell them apart by their text,
    not by the class. The two older refusals keep theirs.

### Fixed (docs)

- **A W3C query does not choose what is nested**
  ([#277](https://github.com/luisgf/openvc/issues/277)). The Presentations page now says
  what the code does by design. A `jwt_vc_json` or `ldp_vc` query without
  `meta.type_values` is answered by a presentation that nests an IETF SD-JWT VC
  (`dc+sd-jwt`) or a W3C credential secured as `vc+sd-jwt`, because the nesting is part of
  the W3C data model and a query without `type_values` constrains nothing. `type_values` is
  the control, and a nested SD-JWT never satisfies it: openvc reads no types from one, since
  its holder could reshape `type` by withholding disclosures. The `dc+sd-jwt` lane stays the
  strict one (#272). No behaviour changes.

## [1.33.2] — 2026-10-14

### Fixed

- **1.33.1 was tagged but never published to PyPI; 1.33.2 ships its fixes
  unchanged** (GHSA-h9rq-wxcw-4rjc). The CI leg pinned to the oldest supported pyld
  (2.0.4) failed on `test_injected_alias_for_a_core_iri_is_rejected[statusRef-*]`,
  which pinned the refusal *message*: pyld 2.x compacts the injected alias so that
  the compacted-form check fires before the term-spelling one. The credential was
  refused with `ProofMalformed` on every pyld version; only the message differed.
  The test now accepts either message. No library code changed.

## [1.33.1] — 2026-10-14

### Security

- **The RDF Data Integrity suites refuse an array nested in an array, a member a
  trusted context defines that is not spelled by its term, a status entry described
  outside `credentialStatus` (an exact copy aside) and an `ecdsa-sd-2023` derived proof
  that merges blank nodes, and match `expected_types` by IRI** (GHSA-h9rq-wxcw-4rjc).
  All are wrong-accepts left by the context validation of 1.30.2, on `eddsa-rdfc-2022`,
  `ecdsa-rdfc-2019` and `ecdsa-sd-2023`, sync and async. Affected: every release up to
  and including 1.33.0.
  - **A holder could hide a revoked status entry.** JSON-LD expansion flattens an
    array nested directly in an array (outside `@list`), so `credentialStatus:
    [S1, [S2]]` signs the same dataset as `[S1, S2]`. The compacted-form comparison
    folded a one-element array into its element at any depth, so it accepted that
    spelling. The status parser kept only the top-level objects and never read S2's
    bit. Re-wrapping the issuer's genuine credential needed no new signature, and it
    verified under the default policy while S2 was revoked. `[[S]]` left no entry at
    all: under `require_status` it failed with `StatusUnavailable` by luck, and with
    `require_status=False` and a status resolver it verified unchecked. On a derived
    `ecdsa-sd-2023` credential the same held for a mandatory `credentialStatus`.
  - **A holder could also move a status entry out from under `credentialStatus`.** RDF
    lets a node be described wherever it is referenced. When the issuer's credential
    also named a status entry from another property (`relatedResource`, say), the
    holder could move the entry's description there, again without re-signing, and
    leave `{"id": X}` under `credentialStatus`: JSON-LD signs that exactly as the bare
    reference `X`. The status parser skipped the typeless object as an unrelated status
    type, so the revoked entry was never read. An entry that also had an unrelated type
    could be left behind with only that type, and the destination could be another
    node's own `credentialStatus` (a subject typed `VerifiableCredential`, or a context
    defining the term at the top level), which the status check never reads either.
  - **On `ecdsa-sd-2023`, a holder could make two JSON nodes one signed node.** The
    verifier took blank-node identity for the signature from the holder's label map,
    which it never required to be injective, and it turned every `urn:bnid:` IRI in the
    presented document into a blank node. Everything after the signature reads the
    JSON, where those are separate nodes. VCDM 2.0 makes a status entry's `id`
    optional, so an issuer that also names its entry from another property labels it
    (`_:s`). The holder mapped two JSON blank nodes to that entry's one HMAC label, or
    wrote the left-behind node as `urn:bnid:b0` (pyld's own label for the other node).
    Then it described the entry under `relatedResource` and left only its unrelated
    type under `credentialStatus`. The move check above saw two different ids, so the
    move went through, and with `require_status=False` and a status resolver the
    revoked credential verified. The default policy failed closed with
    `StatusUnavailable`. The same deskolemization let a holder put an IRI id of its
    choosing (`urn:bnid:` plus anything) on any node the issuer signed as a blank
    node. On the W3C reference vectors the verified subject became `urn:bnid:alice`.
    That part affects every release with `ecdsa-sd-2023`, from 0.3.0.
  - **A holder could drop a context the verifier serves and spell its terms through an
    inline `@vocab`.** Only the contexts the document listed were checked for term
    spelling, and that list is the holder's to edit. On the issuer's genuine credential,
    a holder replaced an injected status-list context with `{"@vocab":
    "https://w3id.org/vc/"}` and re-keyed the `StatusList2021Entry` as `"type":
    "status-list#StatusList2021Entry"`, `"status-list#statusPurpose"` and so on. The
    dataset, the signature and the compacted round trip stayed the same, and the status
    parser skipped the entry as an unrelated type. With a clear
    `BitstringStatusListEntry` beside it, the credential verified under the default
    policy while the other entry was revoked. A verifier that also serves the VC 1.1
    context was exposed the same way with a plain `BitstringStatusListEntry`: the holder
    moved the credential onto the 1.1 base, which has no term for it.
  - **A holder could re-compact a credential onto the bundled VC 2.0 base alone.** The
    term rule covered only IRIs a served context defines a term for. `issuanceDate` and
    `expirationDate` have a term only in the VC 1.1 context, and `StatusList2021Entry`
    and its members only in the StatusList2021 context, and openvc serves neither by
    default. A holder expanded an issuer's VC 1.1 credential and re-compacted it under
    `["https://www.w3.org/ns/credentials/v2"]`. The dataset and the signature stayed the
    same, compaction wrote both dates under their full IRIs (or as
    `cred:expirationDate` beside a served `cred` prefix), and a default verifier, which
    could not even load the original, verified an expired or not-yet-valid credential,
    on all three RDF suites, sync and async. Dropping an unserved StatusList2021 context
    the same way left the entry's type and members as full IRIs, and with
    `require_status=False` the revoked entry was skipped. A served context that gave one
    of those IRIs a term of its own (`"expiry"` for `…/credentials#expirationDate`) hid
    it too, whether or not the verifier also served VC 1.1, because the base-context
    rule applied only to IRIs the base context defines.
  - **An issuer could sign a credential that never expired.** A term that coerces a
    datatype (`validFrom` / `validUntil`: `xsd:dateTime`; the proof's `expires`) or
    takes a node (`credentialStatus`) cannot carry a value that does not match. JSON-LD
    compaction keeps such a value under the property's full IRI, a compact IRI or an
    `@vocab` suffix, and that spelling is the compacted form, so the round trip matched.
    The validity window and the status check read only the term. A `validUntil` in the
    past written as an untyped string under
    `https://www.w3.org/2018/credentials#validUntil` (or as `Until` under
    `{"@vocab": "…/credentials#valid"}`) verified as never expiring, and the proof's
    `expires` was skipped the same way. A context injected through `extra_contexts`
    that gave a core IRI a second term did the same, at any length: `"until":
    ".../credentials#validUntil"` took an untyped date, and a `statusRef` coerced like
    `credentialStatus` but shorter was what compaction itself chose, so the status was
    never checked. openvc's own `add_proof` and `add_base_proof` ran the same check, so
    they signed these documents too.
  - **A holder could make `expected_types` match a type the issuer never signed.** The
    term rule asked only which defined IRIs a spelling may stand for, and the policy
    compared `type` as JSON text. An issuer typed its credential through its own
    published context (`"AlumniDegreeCredential"` for
    `https://vendor.example/vocab#AlumniDegreeCredential`). The holder replaced that
    context with `{"@vocab": "https://vendor.example/vocab#Alumni"}`, an inline `@vocab`
    ending inside the signed IRI, and wrote the type as `"DegreeCredential"`. The
    dataset, the signature and the compacted round trip stayed the same, and
    `VerificationPolicy(expected_types=["DegreeCredential"])` passed: on a default
    verifier, which could not even load the original, and on one serving a context that
    defines `"DegreeCredential"` as another IRI. Any suffix of a signed type IRI could be
    written this way.

  Now a one-element array folds into its element only as a member's value, never inside
  another array, so any array directly in an array that compaction does not emit is
  refused. A term declared `"@container": "@list"` may still carry a list of lists,
  since compaction writes it back nested. A key, or a `type` value, that stands for an
  IRI any context the verifier's loader serves defines a term for must be that term.
  That covers the bundled contexts and `extra_contexts`, whether or not the document
  lists them, at the top level or in a type- or property-scoped context. When the VC
  base context defines a term for the IRI, it must be the base context's term, so an
  injected alias is refused. An IRI the policy reads after the proof (`validFrom`,
  `validUntil`, `issuanceDate`, `expirationDate`, the proof's `expires`,
  `credentialStatus`, `credentialSchema`, and the entry types and members of
  `BitstringStatusListEntry` and `StatusList2021Entry`) must be the one key the policy
  reads it under, whatever the loader serves and whatever term another context gives
  it. Those IRIs are indexed, not the contexts: VC 1.1 and StatusList2021 are still not
  served by default. A node under the top-level `credentialStatus` whose `@id` is also
  described anywhere else in the document, another node's `credentialStatus` included,
  is refused, unless that description is an exact copy of an entry with that `@id`
  (equal expanded node objects). An embedded credential, such as an OB 3.0
  endorsement, may repeat the outer `credentialStatus` verbatim, and RDF merges a copy
  into the entry's own statements. Moving any member out of the entry makes the two
  differ. On `ecdsa-sd-2023`, `decode_derived_proof` refuses a label map that gives two
  blank nodes one label (`ProofValueMalformed`). `verify` canonicalizes the document as
  presented, as VC-DI-ECDSA's verifier does, and no longer turns `urn:bnid:` IRIs into
  blank nodes; `derive_proof` computes its label map the same way. Blank-node identity
  for the signature is then the identity the JSON-LD checks see, which the move check
  and its exact-copy exception rely on. The keys inside an `@json` value (`_sd`, `cnf.jwk`) are data and are not
  checked, and any other IRI no served context defines a term for is left alone. A term
  with no `@id` is indexed under the vocabularies the served contexts set and the inline
  `@vocab` in effect where the document lists a context (and the last one), so piling up
  inline `@vocab` objects grows neither the index nor the work per key. The loader
  returned by `document_loader()` now exposes what it serves as a read-only `contexts`
  mapping, which the check reads. All of these fail with `ProofMalformed` when verifying
  and when signing. The status parser now raises `StatusListError` for a
  `credentialStatus` array member that is not an object (an array, a string reference,
  `null`) and for an entry with no `type` (`{"id": X}`, an `@list` object), as
  `credentialSchema` already did, instead of skipping it, even with
  `require_status=False`. That covers VC-JWT, the JCS suites and direct callers of
  `parse_status_entries` / `check_credential_status`, where only an issuer could produce
  the shape.

  A top-level `type` value that is a term a served context defines must stand, in the
  document, for one of the IRIs that term is defined as (`ProofMalformed`, when
  verifying and when signing). On the three RDF suites `expected_types` is now matched
  by IRI against the expanded types of the credential (or presentation), never as JSON
  text: a name a served context defines stands for its IRIs, any other bare name for
  each served `@vocab` plus it, and a full or compact IRI for itself. The credential's
  own `@context` never resolves a name. The JCS suites, VC-JWT and SD-JWT still compare
  the strings the issuer signed. A missing type is still `TypeMismatch`, and its message
  names the remedies below.

  **What this rejects that used to be accepted.** A document with an array nested in an
  array outside a `@list` term, including an `@json` value whose top-level array holds
  arrays (pyld compacts that lossily: `[["x"]]` comes back as `"x"`). A defined property
  keyed by its IRI, a compact IRI or an `@vocab` suffix because its value does not fit
  the term. A term an injected context defines for an IRI the VC base context has its
  own term for. An issuance or expiry date, or a `StatusList2021Entry` type or member,
  spelled by full IRI, compact IRI or `@vocab` suffix, even where no served context
  defines a term for it, and a term any served context gives one of the IRIs the policy
  reads, in a VC 1.1-based document too. A `StatusList2021Entry` spelled by its IRIs
  under `require_status` now fails with `ProofMalformed` instead of the
  `StatusUnavailable` of "no recognised entry". A status entry also described under
  another property, a nested `credentialStatus` included, other than as an exact copy
  of the entry, and a `credentialStatus` member that is not an object or has no `type`.
  On `ecdsa-sd-2023`, a derived proof whose label map repeats a label, and a reveal
  document that writes as a `urn:bnid:` IRI a node the issuer signed as a blank node.
  openvc's own `derive_proof` wrote such an IRI in one case: a blank node the issuer
  labelled `_:bN` and also referenced from a second property, with both disclosed. It
  now refuses that selection with `EcdsaSdError` instead of emitting a proof only the
  old verifier accepted. The term rule is a deliberate
  superset. It does not track which served contexts a document uses, so a full IRI,
  compact IRI or `@vocab` suffix (as a key or a `type` value) for an IRI any served
  context defines a term for is refused even in a document that never lists that
  context. A verifier with a large `extra_contexts` set
  may see new refusals of such extension spellings. Every served context is now read on
  every validation, so one in `extra_contexts` that cannot be read (JSON text that does
  not parse, or scoped contexts nested past the walk's bound of 16) refuses every RDF
  credential, not only those that list it. Nor does the rule track where a scoped term
  is in effect, so an IRI a served context defines in any scope must be written through
  a term everywhere, even at a node where no term for it is active and the IRI is what
  compaction emits. A `credentialSubject` property written `dcterms:created` or
  `https://w3id.org/security#nonce` is refused, because the VC base context defines
  `created` and `nonce` inside its `DataIntegrityProof` scope. For an IRI only your own
  context defines, add a term of your own for it to `extra_contexts`. An IRI the VC base
  context defines has no other accepted spelling, so use another property. The W3C
  vectors are unaffected.

  **A behaviour change for `expected_types` on the RDF suites.** A type that only an
  inline `@vocab` names (`"ExampleDegreeCredential"` under `{"@vocab":
  "https://www.w3.org/ns/credentials/examples#"}`) no longer meets a bare-name pin,
  because the holder can move that `@vocab` boundary. Serve a context that gives it
  that name (the published one, or one holding just that `@vocab`) through
  `extra_contexts`, which the credential need not list, or pin the full type IRI. A
  top-level type written with the name of a term a served context defines, while it
  stands for another IRI, is refused outright. Not changed: code that reads `type` from
  the JSON, for a name no served context defines, can still be shown such a suffix;
  compare expanded IRIs there, or let `expected_types` do it.

- **A hostile `ecdsa-sd-2023` derived proof value raises `ProofValueMalformed`, not a
  bare `TypeError` / `AttributeError`.** Found by the adversarial review of
  GHSA-h9rq-wxcw-4rjc. Pre-existing: `decode_derived_proof` checked only that the CBOR
  was a five-element array. A text-string, integer or map `public_key` raised
  `TypeError` before the issuer's key was resolved, so it needed no key and no
  signature; an array or text-string label map raised `AttributeError`, which the
  `except` around the decode did not list; an integer `signatures` raised `TypeError`
  once the genuine base signature verified. Each escaped the suite's `verify`,
  `verify_credential` and `verify_credential_async`, and aborted a whole `verify_many` /
  `verify_many_async` batch (threat model I14, I15): the #279 / #208 class. No
  wrong-accept: every case failed closed, untyped. `decode_derived_proof` now requires
  `base_signature` and `public_key` byte strings, `signatures` an array of byte
  strings, the label map a map of unsigned integers to byte strings and
  `mandatory_indexes` an array of unsigned integers, and raises `ProofValueMalformed`
  otherwise, before anything is hashed; `AttributeError` joined the backstop around it.
  Shapes that were already typed later (a text-string base signature, statement
  signature or index) now fail the same way, at decode, and a label map with a text
  key, which no genuine proof writes and which used to be ignored, is refused. So is a
  label map that repeats a label, which was a wrong-accept (see above).

### Tests

- **Nested arrays and term spelling are pinned on every RDF suite**
  (GHSA-h9rq-wxcw-4rjc). Sections 11 and 12 of `test_di_context_validation.py` drive
  `verify_credential` and `verify_credential_async` with a status-list resolver whose
  second list has the entry's bit set: `credentialStatus` re-spelled as `[S1, [S2]]`,
  `[[S1, S2]]`, `[[S1], [S2]]` and `[[S]]`, under `require_status` on and off, on
  `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and a derived `ecdsa-sd-2023` credential, each
  with a control that is `CredentialRevoked`; the suites' own `verify` is checked too.
  `validate_document` refuses an array in an array at `credentialSubject`, `type`,
  nested objects and literals, `validUntil`, `credentialSchema`, `issuer` and the proof,
  still folds a one-element member array, and a `@list` of lists from an injected
  context still signs and verifies. A low-level issuer signs an untyped `validUntil` /
  `validFrom` (full IRI, IRI under `@vocab`, `@vocab` suffix, compact IRI,
  language-tagged), a literal `credentialStatus` and an untyped proof `expires`; each is
  refused when verifying and by `add_proof` / `add_base_proof`, and extension IRIs and
  `@json` content still verify. Section 13 moves a revoked entry the issuer also named
  from `relatedResource` there, leaving `{"id": X}`, the bare `X` or only an unrelated
  type under `credentialStatus` (both RDF suites and a derived `ecdsa-sd-2023`
  credential), shows the status parser alone still refuses what is left when the
  structural rule is switched off, and re-spells an issuer-signed bare reference as
  `{"id": X}`. It also moves the entry under another node's `credentialStatus` (a
  subject typed `VerifiableCredential`, a nested node typed so, and a context defining
  the term at the top level, plus a derived `ecdsa-sd-2023` credential), leaving only
  its unrelated type behind, and checks that a nested node's own distinct status entry
  still verifies. Section 14 injects contexts that alias `validUntil`, `validFrom`,
  `credentialStatus` and the proof's `expires`, and checks that a context restating a
  core term still verifies. Section 15 pins the intended refusals of the superset: a
  base-context IRI at a subject (compact IRI, full IRI, alias) and an `@json` array of
  arrays. Section 16 drops an injected status-list context in favour of an inline
  `@vocab` on the issuer's genuine credential (a mixed and a single
  `StatusList2021Entry`, both RDF suites and a derived `ecdsa-sd-2023` credential,
  `require_status` on and off), moves a v2 credential onto a VC 1.1 base the verifier
  also serves, respells a credential type the same way, checks that a loader which does
  not list what it serves is refused, and that the index does not grow with inline
  `@vocab` objects. Section 17 re-compacts an issuer's VC 1.1 credential (expired, or
  not yet valid) onto the VC 2.0 base alone, by full IRI and by compact IRI, on both RDF
  suites and a derived `ecdsa-sd-2023` credential; drops an unserved StatusList2021
  context from a credential with a revoked entry (`require_status` on and off, both RDF
  suites and a derived `ecdsa-sd-2023` credential); renames both dates through a served
  alias context, with and without VC 1.1 served; checks that each IRI the policy reads
  is refused by full IRI, alias and `@vocab` suffix under the default loader while its
  key is not, that no other VC 1.1 term is indexed and VC 1.1 is still not served, and
  that an unexpired VC 1.1 credential and a clear `StatusList2021Entry` still verify
  where their contexts are served. `test_status.py` pins `StatusListError` for each
  non-object array member and each typeless entry, with the resolver never called, and
  `test_contexts.py` the loader's read-only `contexts`. On v1.33.0, 201 of these tests
  fail: 177 on the attack (it verifies or is signed, or `StatusUnavailable` stands in
  for the refusal), 4 on the issuer-signed bare reference of section 13, which pins the
  status parser change itself, and 20 that read internals this fix adds. Every other
  control passes.
- **A signed type re-spelled through an inline `@vocab` boundary is pinned on every RDF
  suite** (GHSA-h9rq-wxcw-4rjc). Section 18 of `test_di_context_validation.py` re-spells
  an issuer's vendor-typed credential with an inline `@vocab` that ends inside the
  signed type IRI, on `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and a derived
  `ecdsa-sd-2023` credential, sync and async: as a term a served context defines for
  another IRI (`ProofMalformed`, with or without a pin, and from the suite's own
  `verify`), and as a suffix no served context names (`TypeMismatch` under the pin; it
  still verifies without one, and by its full IRI). Controls show the original is an
  `AlumniDegreeCredential`, not a `DegreeCredential`, and cannot be loaded without its
  context. It also pins the behaviour change (an inline-`@vocab` type meets a bare name
  only when the verifier serves a context naming it, or by full IRI), the remedy in the
  `TypeMismatch` message, the unchanged JCS lane, `missing_types` (served terms,
  compact IRIs, served `@vocab` only, a presentation's own node), and that a served type
  term spelling its own IRI, under either of two served definitions, still validates
  while `add_proof` refuses one standing for another IRI. On v1.33.0, 13 of its 14 tests
  fail; the JCS control passes.
- **Blank-node merges on `ecdsa-sd-2023` and exact status copies are pinned**
  (GHSA-h9rq-wxcw-4rjc). Section 19 of `test_di_context_validation.py` signs a base
  proof whose revoked status entry is a blank node also named from `relatedResource`,
  and has the holder craft a full-disclosure derived proof the old verifier accepted.
  The left-behind node is id-less or `_:a` with both JSON nodes mapped to the issuer's
  one label (`ProofValueMalformed`), or `urn:bnid:bN` (`SignatureInvalid`), under
  `require_status` on and off, sync and async, and from the suite's own `verify`. A
  control with one JSON label in both places is `ProofMalformed`, an honest reveal is
  `CredentialRevoked`, a genuine derived id-less entry still verifies, and
  `derive_proof` never yields a proof the verifier refuses. Section 20 repeats a status
  entry verbatim in an embedded credential and under `relatedResource`, signed by
  openvc and by a third-party signer, on both RDF suites: a clear entry verifies and a
  revoked one is `CredentialRevoked` under either `require_status`. A derived
  `ecdsa-sd-2023` credential with the embedded copy does the same. A copy that is no
  longer exact (a member deleted from the top-level entry, or the section-13 shape) is
  still `ProofMalformed`. `test_ecdsa_sd_interop.py` gives the W3C reference reveal's
  blank-node credential and subject a `urn:bnid:alice` id (`SignatureInvalid`). On
  v1.33.0, 17 of these 27 tests fail: the eight section-19 attacks, the four
  inexact-copy tests and the derived-copy test (v1.33.0 had no move check at all), and
  the four interop cases. The eight exact-copy cases pass there; they fail on the
  stricter move check this release first drafted.
- **`tests/test_ecdsa_sd_derived_proof_shape.py`**. `decode_derived_proof` gets a wrong
  CBOR type for each part, or a label map that repeats a label (19 cases). A genuine
  derived credential carries eight of them through the suite's `verify` (with the
  issuer's key and with an unrelated one),
  `verify_credential`, `verify_credential_async`, and `verify_many` /
  `verify_many_async` between two genuine credentials that still verify; a decode
  monkeypatched to raise each of five exception types checks the backstop. On v1.33.0,
  28 of its 34 tests fail; the six that pass are the genuine shapes and the backstop for
  the four exception types the `except` already listed.
- **`tests/test_docs_claims.py`** checks that the unreleased CHANGELOG section names a
  version with no release link, no dated heading and above `openvc.__version__`, and
  that the audit docs file each advisory that section names under that version. The
  GHSA-h9rq-wxcw-4rjc write-up had been filed under 1.33.0, which shipped without it.

## [1.33.0] — 2026-10-14

### Security

- **`vc+sd-jwt` is accepted only for a payload with a VCDM base `@context`**
  ([#264](https://github.com/luisgf/openvc/issues/264)). Found by the spec-pin
  freshness check of 2026-10-14. **This is a behaviour change:** an SD-JWT that
  verified before can now be refused.

  `draft-ietf-oauth-sd-jwt-vc-19` dropped the -18 sentence that let verifiers accept
  both `vc+sd-jwt` and `dc+sd-jwt` "for a reasonable transitional period". An IETF
  SD-JWT VC is typed `dc+sd-jwt` (§2.2.1). W3C VC-JOSE-COSE §6.1.3 registers
  `vc+sd-jwt` for a payload conforming to the VCDM, and the VCDM requires `@context`.

  openvc used to read `typ: vc+sd-jwt` with no `vct` as a VCDM payload on the typ
  alone. That defeated the REQUIRED `vct` of draft-19 §2.2.2.3. A `vc+sd-jwt` with
  no `vct` and no `@context` verified as `vcdm=True, vct=None`, and so did one whose
  issuer made `vct` disclosable and whose holder withheld it. Typed `dc+sd-jwt`, the
  same payload is refused. In OpenID4VP such a token answered a `dc+sd-jwt` DCQL query
  with no `meta.vct_values`, labelled `format='dc+sd-jwt'`. No check the caller had
  configured was bypassed: an `expected_vct`, `vct_values` or `expected_types` pin
  refused it. Status, KB-JWT / `cnf` and the disclosure refusals still ran.

  `SdJwtVcProofSuite.verify` now raises `SdJwtError` when the issuer `typ` is
  `vc+sd-jwt` and the payload carries no VCDM `@context`. That includes a
  `vct`-bearing IETF payload from a pre-draft-06 issuer: re-issue it as `dc+sd-jwt`.
  VCDM classification reads only `@context`. A presented `@context` disclosure is
  refused, so the verdict never reads a holder-supplied one. A withheld one leaves the
  payload not VCDM, and a `vc+sd-jwt` is then refused. A `vc+sd-jwt` with a VCDM
  `@context`, with or without `vct`, verifies as before, with the VCDM validity window
  and consistency checks.

  The other direction, that a `dc+sd-jwt` always means an IETF SD-JWT VC, is the next
  entry (#272). "VCDM" still means a VCDM base URL anywhere in `@context`; requiring
  a conforming payload (the base context first, and `type` containing
  `VerifiableCredential`) is #275.

- **A `dc+sd-jwt` always means an IETF SD-JWT VC: it needs a `vct`, and only it
  answers an OpenID4VP `dc+sd-jwt` query**
  ([#272](https://github.com/luisgf/openvc/issues/272)). The other direction of #264,
  found by the same cross-check. **This is a behaviour change:** an SD-JWT that
  verified before can now be refused.

  draft-19 §2.2.1 says `typ: dc+sd-jwt` means the payload follows the SD-JWT VC rules,
  and §2.2.2.3 makes `vct` REQUIRED. openvc skipped the `vct` gate for any payload
  with a VCDM `@context`, whatever the `typ`. So a `dc+sd-jwt` with a VCDM `@context`
  and no `vct`, or with a `vct` the holder withheld, verified as `vcdm=True,
  vct=None`. Separately, the OpenID4VP `dc+sd-jwt` lane checked only that the
  Presentation verified as an SD-JWT, and the pipeline calls every SD-JWT
  `sd-jwt-vc`. A W3C VCDM credential secured as `vc+sd-jwt` therefore answered a
  `dc+sd-jwt` DCQL query, reported as `format='dc+sd-jwt'`. With no
  `meta.vct_values`, nothing refused it.

  `SdJwtVcProofSuite.verify` now raises `ClaimsInvalid` for a `dc+sd-jwt` with no
  non-empty string `vct`, whatever its `@context`. One that carries both a `vct` and
  a VCDM `@context` still verifies, and the VCDM validity window and consistency
  checks still apply to it. `VerifiedSdJwt` gains a `typ` field, the verified issuer
  JWT `typ`: an additive field that defaults to `None`. `verify_vp_token` refuses a
  `dc+sd-jwt` Presentation whose issuer JWT is not typed `dc+sd-jwt`, raising
  `VpTokenMalformed`.

  One exception class changes. A `vct`-less `dc+sd-jwt` with a VCDM `@context` past
  its `validUntil` now raises `ClaimsInvalid`, because the `vct` gate runs before the
  VCDM window; it used to raise `CredentialExpired`. Under
  `require_not_expired=False` it is refused instead of returned with `expired=True`.
- **The EBSI plugin validates the DID before it puts it in a registry URL**
  ([#266](https://github.com/luisgf/openvc/issues/266)). Found by the review of
  [#251](https://github.com/luisgf/openvc/pull/251) (issue #219) and listed as out of
  scope by #257. Hardening and contract; no wrong-accept was found.

  `DidRegistryV5.identifiers_url`, `TirV4.issuer_url` and `TirV5.issuer_url` interpolate the
  DID into the path verbatim, and `DidEbsiResolver.resolve` / `.issuer_record` passed them
  whatever string they were given. `verify_ebsi_badge` takes that string from an unsigned
  token (`iss`) and the trust walk from the registry (`accreditedBy`), so no key was needed to
  choose the path and query of a GET to an allow-listed EBSI host: `/` started a new path
  segment, a `..` segment was collapsed by httpx (three of them reach the host root, so any
  path on the host was addressable), `?` started a query that swallowed the TIR `/attributes`
  suffix, `#` was dropped, `%2f` / `%2e%2e` were forwarded as written, another DID method or a
  whole URL stayed inside the path, and a 60,000-character `iss` went out as a 60 KB request
  line. Host, scheme and port never changed, and the signature still had to verify under a key
  in the fetched document, so no impersonation was found. What it did produce: a verified
  `issuer` that was not a DID with `trusted=True` (an accredited issuer behind a dot segment),
  and, once this check types the failure, a 60,301-character error message for a 60,010-character
  `iss` if the message were not cut.

  Both methods now validate the identifier first and raise `DidResolutionError` before any
  URL is built. Maintainer decisions, recorded here:
  - **The pattern** is `did:ebsi:z` followed by 22 or 23 base58btc characters
    (`[1-9A-HJ-NP-Za-km-z]`), matched with `re.fullmatch` and an explicit ASCII class (never
    `\w` or `\d`, never `match` + `$`, which accepts a trailing newline). Alphabet and length
    only: nothing is decoded, so the version byte is not checked and a future version byte
    cannot make the check fail. Case-sensitive, no normalisation, no percent-decoding. The
    length is the legal-entity form of the method as the EBSI DevHub page
    ["The did:ebsi DID method"](https://hub.ebsi.eu/docs/onboarding/legal-entity/did-ebsi-method)
    defines it (read 2026-10-14): `z` and the base58btc of a version byte (`1`) plus 16 random
    bytes, 17 bytes in all. That value lies in [2^128, 2^129), which needs 22 digits below
    58^22 and 23 above it, never 21 or 24, and the page's two example DIDs and the recorded
    pilot DID are all `z` plus 22. The page also defines an optional `did:ebsi:[network]:`
    segment, "fully omitted for the EBSI blockchain", which is what the DID Registry and TIR
    APIs this plugin reads serve; a network-qualified DID is **not** accepted.
  - **The error** is `DidResolutionError` from both methods, with the value cut by `safe_repr`.
    `verify_ebsi_badge` reports it as `EbsiVerificationError`, and wraps one raised by
    `issuer_record` the same way although a token cannot reach it (`issuer_record` is public).
    In `verify_trust_chain` a malformed walk subject is `NoTrustedAnchor`, the class a 404 gave
    before, with a message that says it is not a `did:ebsi` identifier rather than "not in the
    registry"; a hostile `accreditedBy` that equals the accreditation's signed `iss` is
    `AccreditationInvalid` through the existing wrapper, and no request names it.
  - **No `supports()`** is added: `DidEbsiResolver` still does not satisfy the `DidResolver`
    protocol or sit in a `DidResolverRegistry`. That is its own issue.
  - **The adapters stay wire-only**: `identifiers_url` and `issuer_url` keep no validation of
    their own (their docstrings now say they expect a validated DID), so a new API version
    inherits the check, and `_guard_host` is unchanged: it still guards the TIR `attributes`,
    `next` and `href` URLs, which never pass through the DID check.
  - **Messages are bounded**: the `safe_repr` cut now also covers the walk's last-resort
    message and the accreditation-subject mismatch.
  - **A `str` subclass is read as its characters**, not refused: the check normalises the
    argument with `str.__str__` (the plain slot; `str(did)` can be overridden) to an exact
    `str` and uses that one for the pattern, the URL, the document-`id` comparison and the
    message. Before, a subclass that overrode `__format__` matched the pattern and then
    steered the URL, because the adapters build it with an f-string (not new in this change).
    Reachable only from in-process code: a JSON-decoded `iss` or `accreditedBy` is an exact
    `str`.

- **The TIR issuer response is bound to the DID that was asked for**
  ([#267](https://github.com/luisgf/openvc/issues/267)). Found by the write-up of
  [#257](https://github.com/luisgf/openvc/issues/257). A conditional wrong-accept: the
  condition is a registry-side fault.

  `DidEbsiResolver.issuer_record` handed the registry body to the adapter and returned what
  came back; neither adapter read the response's own `did`, and `IssuerRecord.did` was filled
  from the *request*. So a record about another issuer, or with no `did` at all, was accepted
  and relabelled. In single-level mode (no `trust_anchors`), which verifies no accreditation
  signature and reads only `has_attributes`, `issuer_type` and `credential_types`, that is the
  trust decision: a badge signed by an issuer with no accreditation verified as `trusted=True`
  on another issuer's record, with no error. Reachable through a registry fault, an injected
  `Fetch`, a wrong `base` or a cache keyed on less than the URL (the built-in `TtlCache` is
  keyed by the full URL); an operator who wants to lie can serve a matching `did`, so this adds
  nothing against a compromised registry (still out of scope, threat model §10).

  `TirAdapter` gains a **non-abstract** `response_did(raw)` hook (default: the top-level `did`,
  as found and unchecked), so a third-party adapter written before it still instantiates and a
  version that moves the field overrides one method. The **resolver** compares what it returns
  with the requested DID, exactly, **before the adapter follows any link**, and raises
  `MalformedRegistryResponse`, with both values cut by `safe_repr`, on any difference: another
  DID, or an absent, `null`, non-string or empty `did`. A rejected record costs one request
  (the issuer), not the `attributes` page and a revision per accreditation. The policy lives
  once, in the resolver, with no `if version == ...`. `IssuerRecord.did` is now the DID the
  registry named. Maintainer decisions, recorded here:
  - **An absent `did` is refused for `TirV4` too**: one rule across versions. `TirV4` has no
    recorded response in this repository, so its tests use synthetic inline bodies; if a real
    v4 registry omits `did`, the override is one line in `TirV4.response_did` and the v5 rule
    does not change.
  - **The class is `MalformedRegistryResponse`**, not a trust error: nothing wraps
    `issuer_record`, and a mismatched body is malformed input, not an "untrusted" issuer, so
    `require_trust=False` does not suppress it either.
  - `_require_object` moved up into the resolver for this body, so a non-object issuer body
    (`null`, a list, a string, a number) is a `MalformedRegistryResponse` on `TirV4` as well
    (it was a bare `AttributeError`). `TirV5.parse_issuer` keeps its own call: it is tested
    directly.

  Not changed: the `attributes` URL and each revision `href` are still pinned to the
  listing's origin (#172), not to `.../issuers/{did}/`, so a record with the right `did` whose
  `attributes` URL points into another issuer's listing is still read (a test documents it);
  the revision's own `did` is not read; and single-level mode still verifies no accreditation
  JWT, which is the documented policy of the default mode.

- **A lone UTF-16 surrogate is refused with the lane's own error, not a bare
  `UnicodeEncodeError`** ([#279](https://github.com/luisgf/openvc/issues/279)). Found by the
  adversarial review of [#273](https://github.com/luisgf/openvc/pull/273). Pre-existing: the
  Data Integrity site dates from v0.1.0, the `did:webvh` one from #90, the OpenID4VCI ones from
  #144. Every site failed closed, but untyped; no wrong-accept was found. **Not a behaviour
  change for a valid input:** these inputs raised a bare `UnicodeEncodeError` and now raise the
  lane's typed error (one exception, below).

  JSON allows `"\ud800"`, an escape for a lone surrogate. `json.loads` and
  `openvc._json.loads` both accept it and return a `str` holding the code point, and no UTF-8
  form of it exists. Wherever openvc ran `.encode("utf-8")` on attacker text outside a guarded
  block, the result was a `UnicodeEncodeError`, which is not an `OpenvcError`, so
  `verify_many` / `verify_many_async` did not isolate it and the whole batch aborted (threat
  model I15). Most of the rows needed no valid signature from anyone.

  Only a statement about a **named** node reaches the unguarded encode. pyld's URDNA2015 hashes
  every quad that mentions a blank node, inside `jsonld.normalize`, which the suites already
  wrap, so a surrogate under a subject without an `id` was a `DataIntegrityError` all along. A
  credential with `credentialSubject.id` (or a credential `id`, or an `issuer` object with an
  `id`) was the bare exception. Eight sites, each now typed with its lane's class:
  - **The Data Integrity canonicaliser** (`_canonize`, shared by `eddsa-rdfc-2022` and
    `ecdsa-rdfc-2019`) raises `DataIntegrityError`, the class the blank-node shape already got.
    The hash is computed before the key is resolved and before the signature is checked, so
    `proofValue: "z1111"` behaved like a real signature. Reached through `verify_credential`,
    `verify_credential_async`, `verify_many`, `verify_many_async`, the two suites' `verify`,
    `verify_vp_token` on an `ldp_vc` presentation (no key), a VP-JWT carrying an `ldp_vc`
    (the holder's own key), the issuer side (`add_proof` on both suites) and
    `default_status_list_resolver`: any issuer whose credential has a `credentialStatus` could
    serve a status-list credential that aborted the batch.
  - **`ecdsa-sd-2023` verify** raises `ProofMalformed`: a statement listed in `mandatory_indexes`
    (the holder chooses them, and the hash is computed before the base signature is checked, so
    a made-up `base_signature` is enough), and a non-mandatory disclosed statement edited after
    derivation (reached once the base signature verifies, so a self-issued credential suffices).
    The proof configuration's N-Quads are guarded the same way: a proof with an `id` is a named
    node. `add_base_proof` raises `ProofMalformed` for a mandatory or a non-mandatory statement.
  - **`did:webvh` pre-rotation**: an `updateKeys` entry holding a surrogate was hashed to check
    the previous entry's `nextKeyHashes` before the entry's own proof was looked at. A multikey is
    base58btc, ASCII by definition, so an `updateKeys` entry that is not an ASCII string is now a
    `DidWebvhError` in the shape check that already refused a non-string one. The pipeline
    reports it as `KeyResolutionFailed` on the JOSE lanes and the async API and
    `KeyResolutionError` on the synchronous Data Integrity lane, as for any resolution failure.
  - **OpenID4VCI**: a `proofs` entry holding a surrogate raised from the byte-length check in
    `parse_credential_request` (and so `verify_credential_request_proofs`), including when the
    body is the JSON string with the escape; `peek_proof_header` and `peek_key_attestation`
    (and `verify_credential_request_proofs` with a `key_attestation` header string holding one)
    did the same. A compact JWS is ASCII by definition, so each now refuses a non-ASCII string
    first: `CredentialRequestMalformed` from `_parse_proofs`, `MalformedToken` from both peeks.
  - **`jwk_thumbprint` / `jwk_thumbprint_bytes`** raise `InvalidKey` for a member holding one,
    as the docstring promised. `verify_credential_request_proofs` reaches it for the proof
    header's `jwk` and for an attested key, both before any signature check, and
    `openid4vci._thumbprint` already maps `InvalidKey` to `ClaimsInvalid`.

  The encode lives in one stdlib-only helper, `openvc._json.utf8(text, *, error, what)`, beside
  the bounded loader: it takes the lane's own error class, so `keys.py` (which cannot import
  from `openvc.proof`) and the three proof suites share it. The message names the code point and
  its index and never the text, which is attacker-controlled and can be any length. **The string
  is never repaired**: `errors="replace"` would make two different inputs hash alike (`"\ud800"`
  and `"?"` are both `b"?"`), and `"surrogatepass"` is lossless but emits bytes that are not UTF-8
  (`ED A0 80` through `ED BF BF`): a strict decoder rejects them and a conformant encoder in
  another implementation never produces them (a WHATWG `TextEncoder` writes U+FFFD), so the hash
  would not match what that implementation computes. Checked and already typed, so unchanged: `eddsa-jcs-2022` and `ecdsa-jcs-2019`
  (`ProofMalformed`), VC-JWT, VP-JWT and SD-JWT VC (`MalformedToken`, `SdJwtError`), every DID
  method's key resolution, status lists, JWE, the trust lists, the schema and Type Metadata
  lanes, EBSI, and mdoc / COSE / CBOR (a CBOR text string is strict UTF-8, so one never holds a
  surrogate).

  The one change for input that is not a surrogate: OpenID4VCI `parse_credential_request`
  now refuses a `proofs` entry that is not ASCII (`CredentialRequestMalformed`), where a
  non-ASCII one used to pass this parse and fail later in `parse_compact`
  (`MalformedToken`). It was never a valid compact JWS. The `peek_*` functions raised
  `MalformedToken` for it before and still do.

  Maintainer decisions, recorded here:
  - **Per site, not at the loader.** Per-site typing keeps today's accept set and is the
    smaller change. Refusing a lone surrogate in `openvc._json.loads`, plus a walk for a value
    handed over already parsed (as `nesting_exceeds` does), would cover every current and
    future site at once, but it changes the JOSE lanes, which accept a signed surrogate today
    and verify what the issuer signed; and a dict a caller parsed with plain `json.loads`
    bypasses the loader, so these rows would still need their typing. The loader rule could be
    added as well, not instead; it is not part of this change.
  - **The JOSE lanes are untouched.** `VcJwtProofSuite.sign` and `SdJwtVcProofSuite.issue`
    still accept a surrogate (`json.dumps` escapes it) and the result still verifies. Not a
    wrong-accept: the verified bytes are what the issuer signed.
  - **`ecdsa-sd-2023` encodes where it hashes**, not once up front inside the canonicalisation
    `try`: the class is the same (`ProofMalformed`, the one that `try` raises) and the bytes
    hashed and signed are identical, so the W3C vc-di-ecdsa vectors are unchanged.
  - **pyld 2.0.4 (the CI floor) drops a `type` IRI holding a surrogate** from the N-Quads, so it
    never reaches the encode; the context validation then refuses the document as
    `ProofMalformed` ("the document has a type the signed dataset drops"). That placement is
    a negative on pyld 3.x only; the floor has its own test.

### Changed

- **Behaviour changes in `openvc_ebsi`, from the two fixes above.**
  - `DidEbsiResolver.resolve` / `.issuer_record` now raise `DidResolutionError` for a DID URL
    (`did:ebsi:zX#key-1`, which worked by accident because httpx drops the fragment), for any
    string that is not a `did:ebsi` identifier, for `resolve("")` (v1.32.4 refused it only
    when the document had no usable `id`; it is now refused on syntax, before any request),
    for a network-qualified DID, and for a **placeholder DID** of another length or alphabet
    (`did:ebsi:zLeafIssuerAAAA` has `I`, `l`, `O` and `0`, which are not base58btc). Test
    code that used such placeholders needs well-formed ones, for example
    `"did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)`.
  - A control character or an over-long `iss` through `verify_ebsi_badge` was
    `HttpForbiddenHost` and is now `EbsiVerificationError`. Both are `EbsiError`, but code that
    catches the first class by name must catch the second. `HttpForbiddenHost` is still what
    the HTTP client raises for a TIR URL it refuses.
  - `verify_trust_chain` on a malformed subject raises `NoTrustedAnchor` (a direct call used
    to reach the registry and get its 404, mapped to the same class).
  - A TIR response whose `did` is another DID, or is absent, `null`, a non-string or empty,
    used to resolve and now raises `MalformedRegistryResponse` from `issuer_record`, from
    `verify_ebsi_badge` (with or without `require_trust`) and from `verify_trust_chain`.
  - **Recursive mode, a misrouted record:** `MalformedRegistryResponse`, at the first
    `issuer_record` call and before the accreditor is resolved. For another issuer's genuine
    record (its signed accreditation names another subject) it replaces
    `AccreditationInvalid`, so the class changes. With `require_trust=True` the outcome
    (refused) does not; with `require_trust=False` a returned `trusted=False` result becomes
    a `MalformedRegistryResponse` raise, because `verify_ebsi_badge` swallowed the trust error
    of the later refusal and does not swallow this one (malformed input, not an untrusted
    issuer: the same rule as in single-level mode). A record whose own `did` alone is wrong,
    with the walked DID's `attributes` behind it, was accepted before this change and is now
    refused too. The walk already let `MalformedRegistryResponse` escape for other malformed
    TIR bodies.
  - Unchanged: a matching `did` resolves (the golden fixture, 3 accreditations, 5 fetches);
    the origin pin on `attributes`, `href` and `links.next`; the single-level and recursive
    trust policies.
- **A Credential Query's `multiple` must be a JSON boolean, answered or not**
  ([#268](https://github.com/luisgf/openvc/issues/268)). Found while probing for the
  review of [#249](https://github.com/luisgf/openvc/pull/249) and left out of
  [#254](https://github.com/luisgf/openvc/issues/254) as out of scope. A `dcql_query`
  whose `multiple` is any non-boolean used to verify and now raises `VpTokenMalformed`
  on every response, naming the query. Defence in depth: every Presentation was still
  fully verified, and the `dcql_query` is the verifier's own input, so no attacker can
  set `multiple`.

  OpenID4VP 1.0 §6.1 defines `multiple` as OPTIONAL, a boolean, default `false`, and
  §8.1 requires exactly one Presentation per query when it is omitted or `false`.
  openvc read it in one place, `_presentation_list`, by truthiness, and
  `_index_dcql` already checked `require_cryptographic_holder_binding` on every query
  but nothing about `multiple`. So a non-boolean was neither rejected nor read the way
  the spec does, in both directions:

  - **A truthy non-boolean opened the query to several Presentations.** `"false"` (a
    non-empty string), `"true"`, `"0"`, `1`, `1.0`, `2`, `[0]` and `{"a": 1}` all
    behaved as `true`: a wallet could return N Presentations, and all N were verified
    and returned. A consumer written for one Presentation per query got several from
    `for_query`: `(p,) = result.for_query("q")` raised a bare `ValueError` in its own
    code, and `result.for_query("q")[0]` silently took whichever the wallet put first.
    `"false"` is the plausible one: a templating, environment-variable or form-field
    bug that reads as "no" to a person and as `true` to `bool()`.
  - **A falsy non-boolean was read as `false` by accident.** `null`, `""`, `0`, `0.0`,
    `[]` and `{}` landed on the single-valued side without being validated, and were
    never reported as malformed. With one Presentation they verified; only a response
    with several was rejected, as "single-valued", which hid the cause.
  - **A query the wallet did not answer** (allowed by `credential_sets`) never had its
    `multiple` read, so every value was accepted there.

  `_index_dcql` now requires `multiple`, when present, to be a boolean
  (`isinstance(..., bool)`, so `0`, `1` and `1.0` are not accepted) on every query of
  the `dcql_query`, right after the same check on `require_cryptographic_holder_binding`
  and before any Presentation is read, for every format and for a format openvc does
  not know. The message is `Credential Query 'q': multiple must be a boolean`.
  `_presentation_list` is unchanged: it has one caller, after `_index_dcql`, so the
  value it reads is a `bool` by construction.

  What changes for a caller:
  - A `dcql_query` with a non-boolean `multiple`, on any query, is `VpTokenMalformed`
    on every response. A truthy one (`"true"`, `1`) used to return several
    Presentations, a falsy one (`null`, `0`, `""`, `[]`, `{}`) used to read as `false`;
    both now raise, so a verifier that templated the flag has to emit `true` or
    `false`. No unverified credential was ever accepted: the Presentations went
    through the full pipeline either way.
  - A malformed `multiple` also wins over a malformed `meta` on the same query (the
    constraint reader of [#254](https://github.com/luisgf/openvc/issues/254) runs right
    after it), over a *later* query's own shape error (an entry that is not an object,
    a missing or duplicate id, a format that is not a string, a malformed `meta`:
    `_index_dcql` walks the queries in order and raises on the first), and over a
    missing required query id, an unknown `vp_token` key and a presentation list that is
    not an array or is empty (these run after `_index_dcql`). All of them are
    `VpTokenMalformed` already, so only the message changes. If
    `require_cryptographic_holder_binding` is malformed on the same query, that error
    still comes first, and so does a shape error that `_index_dcql` itself raises on an
    earlier query (its id, format, duplicate id, either flag or `meta`) or on this
    query's own id or format. An earlier query's *Presentation* failing does not: all
    queries are indexed before any Presentation is read.

  Unchanged: an absent `multiple` is `false` (it is not required); `"multiple": true`
  still allows several Presentations; a boolean `false` still rejects a response with
  several as "single-valued but returned N Presentations"; the `meta` constraints and
  the format dispatch. The `verify_vp_token` docstring, the wiki ("OpenID4VP 1.0:
  `verify_vp_token`", where `multiple` was not documented) and `assurance.md` state the
  rule. `verify_encrypted_vp_response` delegates to `verify_vp_token`, so it follows.
  Same family, not covered here: `_check_completeness` still reads `credential_sets`
  by truthiness.
- **The status-list builders type the strings an artefact names, and calls that used
  to build now raise `StatusListError`**
  ([#269](https://github.com/luisgf/openvc/issues/269)). Found while probing for
  [#255](https://github.com/luisgf/openvc/issues/255), where it was listed as out of
  scope: #250 (#230) typed the index, the pointer strings, `bits`, `size` and the list,
  and #255 the time inputs and `ttl`. This is the rest. Hardening and consistency: every
  input is the issuing application's own call, not attacker data, and no wrong
  revocation state was accepted. What was wrong is that openvc minted what its own
  pipeline refuses, and the verdict depended on the proof lane, so no single place
  failed: `subject_id=5` was rejected on VC-JWT, accepted on `eddsa-jcs-2022` and refused
  at `add_proof` on `eddsa-rdfc-2022`, and `contexts="https://x/"` was accepted by both
  pipeline lanes. The builder is the one place that can decide for all of them. The
  issue probed 74 builder calls on `main`: 68 minted, 5 raised a bare exception, 1 the
  typed `UnsupportedAlgorithm`, and none raised `StatusListError`; its repro gives the
  same output on `ff59357`. Each now raises it, before anything is signed, with the same
  `brief()` text the other builders use (a 60 KB value never reaches a message).

  The rules mirror what the verifier requires and add no policy. What raises, and what to
  pass instead:
  - **`issuer` of `build_status_list_credential`**: anything but a non-empty string or an
    object whose `id` is a non-empty string and which has no `@id`: `5`, `True`, `None`,
    `""`, `[]`, `["did:…"]`, `{}`, `{"id": 5}`, `{"id": ""}`, `{"@id": did}` and
    `{"id": did, "@id": did}` (equal or not). `VcJwtProofSuite.sign` writes only
    `issuer["id"]` into `iss`, the status-list issuer binding and the JOSE
    reconciliation compare every identifier they find (`id` and `@id`), and
    `eddsa-rdfc-2022` refuses the `@id` spelling, so `id` alone is the one form every lane
    reads the same. Pass the DID string, or `{"id": did, "name": "…"}`; other members of
    the object ride along and are not read.
  - **`subject_id`**: `None` (the default, `<id>#list`) or a non-empty string. `5`,
    `True`, `["a"]` and `{"id": "x"}` raise. Pass the string, or leave it out.
  - **`contexts`**: `None` (the default, the VC 2.0 context) or a non-empty `list` or
    `tuple` whose first entry is a VC base context and whose others are a non-empty
    string or an object. A bare string (it was read one character at a time:
    `'h', 't', 't', 'p', …`), a `dict` (read as its keys), an iterator, a `set` and
    `bytes` raise, and so do an entry that is `5`, `None`, `""` or a list and a first
    entry that is not a VC base context. Pass `[VC2, "https://example.org/ctx"]`, or
    leave it out.
  - **`id` of `build_status_list_entry`**: `None` (no `id`) or a non-empty string.
    `5`, `True`, `0`, `""`, `[]` and `{}` used to be copied into the entry.
  - **`issuer` of `build_status_list_token`**: `None` (no `iss`) or a non-empty string.
    `5`, `True`, `""`, `[]`, `["did:…"]`, `{}`, `{"id": "did:…"}` and `NaN` were signed
    into the token, where `default_status_list_token_resolver` then refused it (and
    `verify_status_list_token` reads no `iss`, so it accepted it). A token without an
    `iss` is still allowed and still refused by that resolver
    (`tests/test_resolvers.py` pins it): pass the issuer unless the key is resolved some
    other way. The docstring now says so.

  Decisions, recorded as asked:
  - **(a) A falsy value that is not `None` is an error, not the default.**
    `subject_id` in (`""`, `0`, `[]`, `{}`) and `contexts` in (`[]`, `""`, `0`, `{}`)
    used to be replaced by `<id>#list` and `[VC2]` without a word (`subject_id or …`,
    `contexts if contexts else …`): a caller who passed `contexts=[]` to say "none" got
    the VC context. #250 already made `status_purpose=""` an error, and the default is
    `None`, so `None` is now the only way to ask for it. A caller that relied on the
    fallback passes `None` or leaves the argument out.
  - **(b) The first `@context` entry must be a VC base context**
    (`VC_BASE_CONTEXTS`: the VC 2.0 or the VC 1.1 context), the rule the RDF suites apply.
    Without it `contexts=["https://x/"]` still minted a list the RDF suites refuse and the
    other lanes accept. The entries after the first are checked for shape only (a
    non-empty string or an object), the common ground of every lane; the RDF suites go
    further and accept only `@vocab` objects, and say so themselves. This is a shape
    rule, not a promise that the list verifies on every lane: only the VC 2.0 context
    defines the `BitstringStatusListCredential`, `encodedList` and `statusPurpose` terms,
    and only it is bundled. A list that starts with the VC 1.1 context builds and is read
    by VC-JWT and `eddsa-jcs-2022`, which load no context, and is refused by
    `eddsa-rdfc-2022` at `add_proof` with a typed `DocumentLoaderError` (the 1.1 document
    is not bundled). The docstring and the wiki say to pass the VC 2.0 context first.
  - **(c) No URI-shape check.** `"not a uri"` still builds as an issuer, a subject or an
    entry `id`, and so does a 100 000-character string: the JOSE and JCS lanes and the
    check side have no shape rule (key resolution refuses an unresolvable issuer), and
    only the RDF suites require an IRI, refusing with a typed error at `add_proof`. If a
    predicate is wanted it is one rule for every string identifier, #250's included, and
    a separate issue.

  The artefact no longer shares its top-level containers with the call: an `issuer` object
  and the `contexts` list are shallow-copied, the checks read the copy, and the copy is what
  is emitted (nested objects, such as an `image` member or an inline context, are still the
  caller's), so a `dict` or `list` subclass cannot be checked as one thing and signed as another.
  A container that cannot be copied is a `StatusListError`. `dict()` copies a `dict`
  subclass straight from its storage unless it overrides `__iter__` (an override of
  `keys()` alone or of `__getitem__` alone is never consulted); one that does is read
  through its own `keys()` and `__getitem__`, which may raise or answer differently from
  the storage, and a `list` is copied through its `__iter__`. Either way the copy is what
  is checked and emitted. The same holds for a string:
  every string the builders test is copied to an exact `str` first (`plain_str` in
  `status/_index.py`, the counterpart of `plain_int`) and the copy is what is emitted, so a
  `str` subclass whose `__len__`, `__bool__`, `__getitem__`, `__eq__` or `__hash__` raises
  or lies is read by the characters it holds, as the JSON encoder reads it, and neither
  escapes as that exception nor passes as another value (an empty string that claims a
  length is refused; a `contexts` entry that claims to be the VC 2.0 context is not).
  This covers the strings #250 added too (`id`, `status_purpose`, `status_list_credential`
  and `uri`), which went through the same `_text` helper, and the keys of an `issuer`
  object, so that a key whose hash hides it cannot slip an `@id` past the check. A `tuple` of
  contexts is accepted and written as a list. The `contexts` annotation now says
  `list | tuple`. Exposure is small: across `tests/`, `examples/` and `src/` none of the
  23 builder calls passes `contexts`, `subject_id` or an entry `id`, and every `issuer`
  is a string (`None` for the token in one test).

Not changed, by design: `signing_key` of `build_status_list_token` (a duck-typed
`SigningKey` protocol; `None` is still a bare `AttributeError`, and the algorithm
allow-list is already typed); the members of an `issuer` object besides `id` and `@id`, and
the members of an inline context object (a non-JSON member, `{"id": b"x"}`, still builds
and fails at sign with a bare `TypeError`); a length cap on identifiers; the codec
primitives (`set_status_bit(bits, 3, "0")` still sets the bit); whether the token `issuer`
should become required; and the verifier-side
leniency this issue noted, that the VC-JWT and `eddsa-jcs-2022` lanes accept a list whose
`@context` is a character list and `eddsa-jcs-2022` a non-string `credentialSubject.id`.
That is a separate question; this only stops the builder from producing such a list.

### Fixed

- **A bare `TypeError` out of the status-list builders is a `StatusListError`**
  ([#269](https://github.com/luisgf/openvc/issues/269)). `contexts=5` was
  `TypeError: 'int' object is not iterable`, and a `bytes` or `object()` credential
  `issuer` was a bare `TypeError` at `VcJwtProofSuite.sign` (a typed `ProofMalformed` at
  `add_proof` on `eddsa-jcs-2022`), as a `bytes` token `issuer` was inside `json.dumps` in
  `sign_compact`. They are now `StatusListError`, an `OpenvcError`, raised at build time,
  so a job that publishes lists on a schedule can `except OpenvcError` around the build.
  A caller that caught a builtin exception there catches `OpenvcError` instead.
- **A `str` subclass no longer escapes the status-list builders as the exception its own
  method raises, or passes a check it should fail**
  ([#269](https://github.com/luisgf/openvc/issues/269), found by the review of the PR).
  `_text` tested `not value`, and `brief()` sliced the value, so a subclass whose
  `__len__`, `__bool__` or `__getitem__` raised was that `RuntimeError` out of `issuer`,
  `subject_id`, an entry `id` or a token `issuer` (and of #250's `id`, `status_purpose`,
  `statusListCredential` and `uri`); one whose `__len__` answered `5` for the empty string
  was minted as `""`; and a `contexts` entry whose `__eq__` and `__hash__` claimed to be
  the VC 2.0 context passed the base-context test with another URL, which the encoder then
  wrote. Every string is now copied to an exact `str` before it is tested and the copy is
  emitted; see the paragraph on containers above. The inputs are the issuing application's
  own (a hostile subclass is a bug in its code), so this is hardening, the same as `plain_int`
  for an `int` subclass in #250.

- **The EBSI TIR origin pin reads an absent https port as 443**
  ([#253](https://github.com/luisgf/openvc/issues/253)). Found by the adversarial
  review of #244. The pin (#172) compared `scheme://host:port` with the port as
  written, so `https://api-pilot.ebsi.eu` and `https://api-pilot.ebsi.eu:443` were
  different origins, although httpx sends both to port 443. It failed closed, as a
  false negative. A resolver whose `base` carried `:443` skipped every revision `href`
  the registry wrote without a port, refused its `attributes` URL and stopped at its
  `links.next`. With the default base, a registry that wrote `:443` hit the same
  wall. Either way the issuer appeared to hold no accreditation (`IssuerNotTrusted`,
  or `trusted=False`). An absent https port is now 443 (RFC 3986 §6.2.3). Only an
  absent one is filled in, so an explicit `:0` stays off-origin, and so does any
  other port. The `EBSI_BASE` hosts carry no port, so a default deployment was not
  affected.

### Tests

- **`tests/test_dcql_multiple_boolean.py`** (#268). Negatives first, each pinning the
  query it names and the exact class, so none can pass on the "single-valued" message
  or on a later failure: the fourteen non-booleans (`"false"`, `"true"`, `""`, `"0"`,
  `0`, `0.0`, `1`, `1.0`, `2`, `[]`, `[0]`, `{}`, `{"a": 1}`, `null`) on an answered
  query with one and with two Presentations, on an unanswered query (listed second and
  first), and, for `"false"`, `1` and `null`, beside an earlier junk Presentation;
  `"false"` on `mso_mdoc`, `ldp_vc`, `jwt_vc_json` and on an unanswered query of an
  unknown format; and a malformed `multiple` against each later shape check. The
  ordering is pinned too: a malformed `multiple` (`"false"`, `1`, `null`) beside a
  malformed `meta` on the same query, for all four known formats, and in front of each
  of five shape errors on a later query (an entry that is not an object, a missing id,
  a non-string format, a duplicate id, a malformed `meta`). Controls that pass before
  and after: `true` allows two Presentations, `false` and an absent `multiple` accept
  one and reject two as "single-valued" (also for the three string formats), a boolean
  `multiple` on an unanswered query, an unknown format with `multiple: true`, the
  holder-binding flag still reported first, the later shape checks firing on their own,
  and the same two orderings with `multiple` absent, `false` or `true`, where the
  `meta` / the later query's error is the one reported. Mutation-checked against
  `origin/main` at 45b28be: 84 negatives fail and the 46 controls pass; removing the
  new check fails the same 84; accepting an `int`, accepting a `float`, reading
  `multiple` without its `false` default, checking only `dc+sd-jwt` queries, moving the
  check below the `meta` reader and moving it into a second pass after the walk each
  fail their own rows (17, 8, 45, 13, 12 and 17).
- **`tests/test_status_builders_inputs.py`** pins every row of the tables in the issue
  against the exact class `StatusListError`, with each negative signing through a key whose
  `sign` fails the test, which proves the error comes before the key is asked: the
  credential `issuer` (including every `@id` spelling and `bytes` / `object()`), `subject_id`,
  `contexts` (the string, the `dict`, the iterator, the entries, the first-entry rule and
  decision (b)), the entry `id` and the token `issuer`. The falsy values of decision (a)
  are named, and `None` is shown to still give `<id>#list` and `[VC2]`. Controls: a string
  issuer, an object issuer with extra members, an absent and an explicit `subject_id`,
  `contexts` = `None`, `[VC2]`, `(VC2,)`, the VC 1.1 context, `[VC2, {"@vocab": …}]` and
  `[VC2, "https://x/ctx"]`, an absent and an explicit entry `id`, and a token without an
  `iss` (still refused by the default resolver). Lane agreement: the controls that use
  bundled contexts are built, signed and verified through `default_status_list_resolver`
  on VC-JWT, `eddsa-jcs-2022` and `eddsa-rdfc-2022` (and `verify_credential`), the shape-only
  ones on the two lanes that load nothing, `[VC2, "https://x/ctx"]` on the RDF lane through
  `extra_contexts`, and the token through `default_status_list_token_resolver`. Hypothesis
  properties check each parameter against a model written in the test, and that whatever
  the builder accepts is JSON and is accepted by the VC-JWT and `eddsa-jcs-2022` pipelines
  with a registry that serves the key for any `did:` string. Container subclasses (a
  `dict` / `list` that lies through its accessors or whose iteration raises, a `dict` that
  overrides `keys()`, `__iter__` or `__getitem__` alone and is copied from its storage, one
  that overrides `__iter__` and is read through its `keys()` and `__getitem__`, an
  `issuer` key whose hash hides an `@id`), `str` subclasses (the eleven ways a string
  reaches an artefact, six of this change and five of #250's: a `__len__`, `__bool__`,
  `__getitem__` or `__eq__` / `__hash__` that raises, one that lies about the characters,
  an empty string that claims a length, a `contexts` entry that claims to be the VC 2.0
  context) and the 60 KB message bound are covered.
  Mutation-checked in scratch copies, with `openvc.__file__` asserted inside each: against
  the `ff59357` tree 244 of the 296 cases fail (the 52 that pass are the controls), and
  against the PR head before this round (`fb97dae`) 74 do (the string and key cases). On
  the fixed code, 38 mutants of `issue.py` and `_index.py`: 35 are killed, by 1 to 74
  cases each (a falsy `contexts` made the default again fails 11, decision (b) 18, `subject_id or …`
  with its guard tested by truthiness 14, no `plain_str` copy 58 or 74).
  The counts come from one Hypothesis run and move by one or two between runs. Three
  mutants survive and are equivalent: restoring `subject_id or …` while keeping the
  new guard in front of it changes nothing, because the guard has already refused every
  value the old expression would have replaced; and the token's `uri` and `issuer` are only
  read by `json.dumps`, which writes the characters, so emitting the copy or the original
  is the same token.

- **`tests/test_lone_surrogate_typed.py`** (#279). 361 tests, self-contained. **The fixture shape
  is part of each test:** every RDF and `ecdsa-sd` negative is a named-node document
  (`credentialSubject.id` present, no anonymous nested object), because a subject without an
  `id` is hashed by pyld inside the guarded `normalize` and passed on `main`. Each negative has
  a control of the same shape with a benign string that reaches the next check
  (`SignatureInvalid` for Data Integrity, the base and per-statement signatures for `ecdsa-sd`,
  the pre-rotation commitment for `did:webvh`, the thumbprint then the signature for a key
  proof), so a negative cannot pass on a class that fires first; one blank-node case per suite
  is pinned as the shape that was already typed. Issuers are always resolvable (`did:key`, or a
  stub `did:webvh` fetch of the recorded `pre-rotation-consume.jsonl`). Every assertion is on
  the exact class. Per site, a high and a low surrogate, at the start, middle and end of a
  value, and in an array, a nested `@value` object, a property key, a credential with an `id`,
  an `issuer` object with an `id` and a `type` entry: rows 1, 1a (`verify_vp_token`), 1b (the
  VP-JWT), 1c (the status-list second hop, sync and async) and 1d (`add_proof`, both suites),
  with `proofValue` `z1111` and with a real signature copied from the untampered credential;
  row 2 with a fabricated `base_signature` (`bytes(64)`) and attacker-chosen
  `mandatory_indexes`, row 3 with a self-issued, derived, then edited credential, row 3a on
  `add_base_proof` (a mandatory and a non-mandatory statement), and the proof-configuration
  encode; row 4 from `DidWebvhResolver` and `AsyncDidWebvhResolver` and through
  `verify_credential` / `verify_credential_async` on the JOSE and Data Integrity lanes; rows
  5-7 for a body given as an object and as the JSON string with the escape; row 8 for every
  required member of `EC`, `OKP`, `RSA` and `oct`, and through `verify_credential_request_proofs`
  for the proof header's `jwk` and an attested key. `verify_many` and `verify_many_async`
  isolation is pinned for rows 1, 1c, 2, 3 and 4 (and a per-presentation loop for 1a, since
  `verify_vp_token` is one presentation). Controls that pass before and after: the good
  credential on every suite, a surrogate **pair** (`😀` on the wire, one code point)
  signing and verifying on `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `eddsa-jcs-2022`,
  `ecdsa-jcs-2019`, `ecdsa-sd-2023` (disclosed and mandatory), VC-JWT and SD-JWT VC, a signed
  lone surrogate still verifying on the two JOSE lanes, and a non-BMP JWK member still
  thumbprinting. Mutation-checked against `origin/main` at d2f2d11: every named-node negative
  fails there with exactly `UnicodeEncodeError` (272 of them; of the other twelve, seven
  need the helper, four are the proof-configuration case, which the generic `ecdsa-sd` wrapper
  already typed and which fails on the message, and one is the OpenID4VCI refusal), and reverting each site on its own fails its
  own rows (the canonicaliser 160, `ecdsa-sd` mandatory hash 22, per-statement loop 6,
  `add_base_proof` signing 10, proof configuration 4, `updateKeys` 12, `proofs` entry 9,
  `peek_proof_header` 6, `peek_key_attestation` 8, thumbprint 40). Also run on the pyld 2.0.4
  floor (the `type`-entry placement skips there, see above).

## [1.32.4] — 2026-10-14

### Security

- **The EBSI DID Registry document is bound to the DID that was asked for**
  ([#257](https://github.com/luisgf/openvc/issues/257)). Found by the adversarial
  review of [#251](https://github.com/luisgf/openvc/pull/251) (issue #219), where it was
  listed as a follow-up. Hardening and contract consistency; no wrong-accept was found.

  `DidEbsiResolver.resolve` returned whatever `parse_did_document` made of the registry
  body and compared nothing, so a document whose `id` was another DID, a number, `null`,
  a list, empty or absent still resolved, bare or inside a `didDocument` wrapper, and
  `key_by_kid` found its keys. `did:web` and `did:webvh` reject the same document, and
  `did:key` / `did:jwk` derive it from the DID, so the EBSI resolver was the only
  built-in one that did not hold to the `DidResolver` contract: `resolve(did)` returns
  the document of `did`. A consumer reading `DidDocument.id` got a document about
  another subject, and a misrouted response (a registry bug, a cache keyed wrongly, a
  `base` pointing at the wrong environment) was accepted silently.

  `resolve` now compares the parsed document's `id`, after the `didDocument` wrapper is
  unwrapped, with the requested DID, exactly and with no normalisation (a `did:ebsi`
  method-specific id is case-sensitive base58btc), and raises
  `openvc.did.base.DidResolutionError` on any difference. A missing, empty or
  non-string `id` never matches, whatever was asked: the parser reads all three as `""`,
  which is refused outright, so not even `resolve("")` accepts a document with no usable
  `id`. The message shows both values through `safe_repr`, so a 60 KB DID is cut to 200
  characters. The check is in the resolver, not in `DidRegistryV5`: it is
  version-agnostic domain logic, so a future registry adapter inherits it. `DidResolutionError` is what every caller already
  handles: `verify_ebsi_badge` wraps it in `EbsiVerificationError`,
  `verify_trust_chain` in `AccreditationInvalid`, and the generic pipeline maps
  `DidError` to `KeyResolutionFailed`. The golden registry fixture has `id` equal to its
  DID, so the real registry is unaffected.

  This also closes a reachable steering path, though not its cause. `identifiers_url`
  puts the DID into the registry path unvalidated, so an unsigned token whose `iss` is
  `did:ebsi:zA/../did:ebsi:zB` made the client request B's resource (httpx collapses
  the dot segment) and B's document resolved. B's `id` is not the string that was asked
  for, so it is now refused. No impersonation was possible before: B's key still had to
  verify the token. Validating the DID before it is put in a URL is a separate gap and
  is not changed here.
- **`did:webvh` refuses a log state that carries a `didDocument` member**
  ([#256](https://github.com/luisgf/openvc/issues/256), severity low). Found by the
  adversarial review of [#251](https://github.com/luisgf/openvc/pull/251); the gap
  predates it. The resolver compared `state["id"]` with the requested DID on the raw
  log state, then returned `parse_did_document(state)`, and that parser unwraps a
  `didDocument` member when there is one. The `id` that was checked was not the `id` of
  the document that came back. The controller signs the whole state, wrapper included,
  so such a log passes the SCID, entryHash, proof and pre-rotation checks. A state
  `{"id": DID, "didDocument": {"id": "did:web:other.example", …}}` resolved to a
  document whose `id`, `raw["id"]` and method ids were `did:web:other.example`, and a
  state with its own `verificationMethod` beside a same-`id` `didDocument` resolved to
  the inner methods only. `did:web` was not affected, since it compares the `id` after
  parsing.

  The wrapper does not cross the controller boundary: every key it yields is one the log
  controller published, and no verification lane reads `doc.id`, `doc.raw` or a method's
  `controller`. Each lane binds to the DID string it asked the resolver for. What it
  broke is the resolver's own contract, for code that calls `DidWebvhResolver.resolve`
  and trusts `doc.id`, and agreement with other did:webvh resolvers, for which the log
  state *is* the DID document (did:webvh v1.0, "The DID Log File"). The spec defines no
  `didDocument` member in it, so there is nothing to unwrap.

  `_WebvhReplay._replay`, shared by `DidWebvhResolver` and `AsyncDidWebvhResolver`, now
  raises `DidWebvhError` when the returned state carries a `didDocument` member, whatever
  its value (a `null` counts), before the parser runs; the message names the member. It
  also checks the parsed `doc.id` against the requested DID, as `did:web` does, as
  defence in depth. Only the returned (last) state is looked at, because earlier states
  are never parsed. A credential whose issuer is such a DID fails with
  `KeyResolutionFailed` on the JOSE lanes and on the async API, and with
  `KeyResolutionError` on the synchronous Data Integrity lane, the cause being the
  `DidWebvhError`; a good neighbour in a `verify_many` / `verify_many_async` batch still
  verifies. A state with no wrapper resolves exactly as before, and every
  `tests/fixtures/didwebvh` golden log resolves unchanged. `did:web` and the EBSI DID
  Registry keep tolerating the `didDocument` envelope, which is what the shared parser's
  unwrapping is for.
- **A Data Integrity key is selected, and authorized for its purpose, by exact DID
  URL** ([#258](https://github.com/luisgf/openvc/issues/258)). Found by the
  adversarial review of [#251](https://github.com/luisgf/openvc/pull/251); the gap
  predates it. `DidDocument.key_for_purpose` compared only the text after the first
  `#`. A relationship entry granted a method whenever its fragment matched, whatever
  came before the `#`: a method of another DID (`did:web:other.example#auth`, as a
  string or as an embedded method), one version of the document (`?versionId=1#auth`),
  a path (`/path#auth`), an `https:` URL, or a bare `auth`. Method selection used the
  same rule and took the first match in document order, so a same-fragment method
  listed before the exact one shadowed it: a correctly signed proof failed with
  `SignatureInvalid` and a proof signed by the shadowing method's key verified. All
  five Data Integrity suites were affected, sync and async, on the credential lane
  (`assertionMethod`, or `policy.proof_purpose`) and on the OpenID4VP `ldp_vc`
  holder proof (`authentication`).

  No key from outside the issuer's own document was ever admitted: the key always
  comes from the resolved document, `did:web` / `did:webvh` bind the document `id`,
  and the proof's DID is bound to the credential `issuer` (or is the VP holder). What
  broke was purpose separation inside one document. A key the document lists for
  `authentication` only could sign credentials accepted as assertions whenever the
  controller had written an `assertionMethod` entry with the same fragment that
  points elsewhere.

  The rule now follows DID Core 1.0 §3.2.2 and CID 1.0 §3.3 (steps 9 and 11). A
  method `id` and a relationship reference are compared as absolute DID URLs: a
  `did:` URL as written, a `#fragment` resolved against the document `id` when that
  `id` is a DID (§3.1 syntax), and anything else as resolving to nothing. The proof's
  `verificationMethod` selects the one method whose absolute `id` equals it, else
  `KeyResolutionError` (`resolve_verification_key` now decides that with the same
  strict lookup, never the fragment-tolerant `key_by_kid`). A declared relationship
  grants it only through a reference that resolves to the same `id`, compared as a
  plain case-sensitive string, else `ProofPurposeMismatch`. In the lookup the
  document `id` is checked a fixed number of times, and only the selected method's
  own relative `id` is resolved; no other method id or reference is: each is compared
  with the spellings of the one absolute `id` it must name, so the cost stays linear
  in the document size, however long the DID and however many entries it lists. A
  resolver that returns its own document type instead of a `DidDocument` keeps the
  previous classification of a refusal (by its `key_by_kid`), so it still gets a typed
  error rather than an `AttributeError` that would abort `verify_many`.
  Unchanged: an undeclared relationship stays lenient, a declared but empty one grants
  nothing, and a `kid` of `None` still falls back to the document's sole method (which
  must then pass the exact-reference grant). The JOSE lanes keep `key_by_kid`, which
  tolerates a bare or `#`-relative `kid` (a JWS `kid` is a hint); they check no
  verification relationship, which is a separate policy question. The recorded
  vectors (W3C vc-di-eddsa, vc-di-ecdsa, ecdsa-sd-2023, the EBSI DID Registry capture,
  the did:webvh logs) all use absolute ids and verify unchanged.

### Changed

- **A DID URL passed to `DidEbsiResolver.resolve` is now refused.** `did:ebsi:zX#key-1`,
  for example as a token's `iss`, resolved by accident: httpx drops the fragment, so the
  registry answered with `zX`'s own document. It now raises `DidResolutionError`, as
  `did:web` does, and `verify_ebsi_badge` reports `EbsiVerificationError`. `iss` and
  `accreditedBy` are DIDs, not DID URLs, so a conforming credential is unaffected. The
  same applies to any other input whose registry document `id` is not that exact string.
- **`resolve("")` against a document with no usable `id` is now refused.** An absent,
  empty or non-string `id` is read as `""`, so a bare `doc.id != did` accepted it for the
  empty DID. It now raises `DidResolutionError`. The shipped callers already reject an
  empty `iss` before they resolve, so only a direct call with `""` is affected.
- **Every Credential Query's `meta` is validated up front, answered or not**
  ([#254](https://github.com/luisgf/openvc/issues/254)). Found by the review of the
  fix for [#224](https://github.com/luisgf/openvc/issues/224) (see its `### Security`
  entry under 1.32.3). A `dcql_query` that carries a malformed `meta` on a query the
  wallets never answer used to verify and now raises `VpTokenMalformed` on every
  response. Defence in depth: nothing was ever accepted under a malformed constraint,
  and the `dcql_query` is the verifier's own input, so no attacker can reach this.

  #224 made a malformed `meta.vct_values`, `meta.doctype_value` or `meta.type_values`
  fail safe, but `verify_vp_token` read a query's `meta` only when that query's own
  Presentation came up. So a query the wallet did not answer (allowed by
  `credential_sets`) was never checked. An earlier query's presentation failure was
  reported before a later query's malformed `meta`. And the order inside one query
  depended on the format: `dc+sd-jwt` read the constraint before the "must be a
  compact string" check, `mso_mdoc` read it after `expected_origins`,
  `trust_anchors` and the "must be a base64url string" check. A verifier with one
  broken alternative passed every test whose wallet answered the other one, and
  failed in production the day a wallet answered the broken one.

  `_index_dcql` now checks every query's constraint, after the per-query checks it
  already made (`id`, `format`, duplicate ids, `require_cryptographic_holder_binding`)
  and before any Presentation is read: `vct_values` for `dc+sd-jwt`, `doctype_value`
  for `mso_mdoc`, the shape of `type_values` for `jwt_vc_json` and `ldp_vc`. The
  readers are unchanged and still run when a Presentation is verified. The 1.32.3
  wording "whatever the wallet sent for that query" is now stronger: it holds for
  every query of the `dcql_query`, answered or not.

  What changes for a caller:
  - An unanswered query with a malformed `meta`, or an earlier failure ahead of
    one, is `VpTokenMalformed: Credential Query 'b': meta …`, naming the query.
  - For `mso_mdoc` the constraint comes first. A malformed `doctype_value` beside a
    missing `expected_origins` was `UnsupportedPresentationFormat`, beside a missing
    `trust_anchors` was `ClaimsInvalid`, and now both are `VpTokenMalformed`. With a
    presentation that is not a string and a `meta` that is not an object, both
    formats now give the same message; a malformed `doctype_value` and a malformed
    `vct_values` keep their own messages.
  - A malformed `meta` also wins over a missing required query id, an unknown
    `vp_token` key and a presentation list that is not an array or is empty. These
    run after `_index_dcql` and are `VpTokenMalformed` already, so only the message
    changes.
  - The `pyld` requirement of `type_values` moved from the shape parser to the point
    of use. A well-formed `type_values` on an unanswered query needs no `pyld`, as
    before; an answered one still raises `OpenID4VPError` before its Presentation is
    verified. Nothing else about `pyld` changes.

  Unchanged: an absent `meta`, or one without the key, is still no constraint; the
  match against the verified `vct` / `docType` / types; a query of a format openvc
  does not know is `UnsupportedPresentationFormat` when answered and ignored when
  not, its `meta` unread; and the keys of another format are not read (a
  `vct_values` on an `mso_mdoc` query is ignored). The `verify_vp_token` docstring
  and the wiki ("Type constraints in the query") state the rule.
  `verify_encrypted_vp_response` delegates to `verify_vp_token`, so it follows. The
  `multiple` flag is still read by truthiness, which is a separate gap (#268).
- **A `did:webvh` log whose last state has a `didDocument` member no longer resolves**
  (#256). It used to resolve, to the inner document. No golden log and no known
  implementation produces one. A wrapper that was not an object (`null`, a list, a
  string, a number) was already a plain `DidResolutionError` from the parser; it is now
  a `DidWebvhError`, which is a `DidResolutionError`, so code that catches the parent is
  unaffected. The wrapper is refused where the state's `id` is checked, before the
  `deactivated` flag: a deactivated log whose last state is wrapped now fails with the
  wrapper message, not "is deactivated". Both are a `DidWebvhError`, and a deactivated log
  with a bare last state still reports the deactivation.

- **A naive `datetime` is UTC in both status-list builders, so a non-UTC host now mints
  a different `validFrom` / `validUntil`**
  ([#255](https://github.com/luisgf/openvc/issues/255)). This is the one change in this
  release that alters what a successful call returns rather than refusing an input: the
  call still succeeds and signs a different string. Decision: a naive value is *read as UTC* rather than refused, the one rule
  every openvc clock check uses (the
  [#187](https://github.com/luisgf/openvc/issues/187) precedent).

  `build_status_list_credential` called `astimezone`, which reads a naive value as the
  **host's local time**, while `build_status_list_token` already read it as UTC. The same
  `datetime(2026, 1, 1, 12, 0)` minted `validFrom = 2026-01-01T03:00:00Z` under
  `TZ=Asia/Tokyo` and `17:00:00Z` under `America/New_York`, and `iat = 12:00:00Z` in the
  token on both: a host west of UTC kept a list valid for hours longer than intended, one
  east of it expired the list early. Both builders now agree and the result no longer
  depends on the host's zone: `12:00:00Z` everywhere. A caller that relied on the local
  reading passes an aware `datetime` instead (`datetime(..., tzinfo=ZoneInfo("Asia/Tokyo"))`).
  On a host already on UTC nothing changes, and neither does anything for an aware value:
  `valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc)` is still `"2026-01-01T00:00:00Z"`,
  byte for byte. Two edge inputs follow the same rule: a `tzinfo` whose `utcoffset()` is
  `None` (naive by Python's own definition) is UTC in both builders, where it was a bare
  `TypeError` in the token builder and local time in the credential one; and a naive
  `datetime.min` / `datetime.max` builds (`0001-01-01T00:00:00Z`, `9999-12-31T23:59:59Z`),
  where it was a bare `ValueError`.

- **`ttl` is `None` or a positive `int`, on both builders**
  ([#255](https://github.com/luisgf/openvc/issues/255)). Decision: an `int` only, never a
  `bool`, rather than "also a finite float" (the IETF draft's "positive number"), which
  matches the signature, and a CWT `ttl` is an unsigned integer. Anything else raises
  `StatusListError`.
  - `"5"`, `True`, `1.5`, `300.0`, `0`, `-1`, a `list`, a `dict` and `10**400` were
    minted as given; `NaN` and `inf` were signed as non-JSON. Pass a positive `int`.
  - a `timedelta`, a `Decimal`, a `Fraction` (pass `int(x)`) and `10**5000` were a bare
    `TypeError` / `ValueError` in the token builder, and in the credential builder a
    credential that failed later at `VcJwtProofSuite.sign`.
  - `ttl=300` is unchanged. The IETF `ttl` is seconds and the W3C one milliseconds; the
    builders do not convert.

- **`issued_at` / `expires` take a `datetime` or a finite number**
  ([#255](https://github.com/luisgf/openvc/issues/255)): the same NumericDate gate
  (`is_numeric_date`) that `verify_status_list_token` applies to `iat` / `exp` / `nbf`.
  A digit string (`"1700000000"`, which `int()` coerced), a `bool` (minted as `1` / `0`),
  a `Decimal` or `Fraction` (pass `int(x)`) now raise `StatusListError`. `time.time()`
  and any finite `float` still work and are truncated to whole seconds as before. A
  `datetime` whose UTC form is outside years 1 to 9999 (year 1 at `+01:00`,
  `9999-12-31T23:00` at `-05:00`) is refused too, as `valid_from` / `valid_until` already
  refuse it; the token used to sign an epoch for it (see Fixed).

- **`valid_from` / `valid_until` are a `datetime` or `None`**, as the signature says
  ([#255](https://github.com/luisgf/openvc/issues/255)). A string, an epoch number or a
  `date` was a bare `AttributeError` and is now a `StatusListError`.

- **Callers that caught a builtin exception around a builder catch `OpenvcError`.** The
  inputs that already raised now raise `StatusListError` (an `OpenvcError`) instead of
  `ValueError` / `TypeError` / `OverflowError` / `AttributeError`.

- `openvc.proof._verify_common.utc_instant` and `utc_epoch` gain an add-only `name=`
  keyword (default `"now"`), so a caller that reads some other datetime the same way gets
  an error that names its parameter. The default messages are unchanged.
- **Behaviour change: DID documents that relied on the fragment match now fail**
  ([#258](https://github.com/luisgf/openvc/issues/258)), on the Data Integrity lanes
  only. Each fails closed with a typed error, and in `verify_many` /
  `verify_many_async` only its own item fails.
  - A relationship entry that is not a DID URL for the method, such as
    `"assertionMethod": ["key-1"]`, no longer grants `#key-1`: `ProofPurposeMismatch`.
    Such a document does not conform to DID Core (an entry must be a DID URL, and a
    bare `key-1` is a relative path reference). `"#key-1"` and the full
    `did:…#key-1` still grant it.
  - A method whose `id` is not a DID URL for the proof's `verificationMethod` (a bare
    `key-1`, another DID's `#key-1`, a `#key-1` in a document whose `id` is not a DID)
    is no longer selected: `KeyResolutionError`.
  - Two methods whose `id`s resolve to the same absolute DID URL (`#key-1` and
    `did:…#key-1`, or the same `id` twice) are ambiguous, and neither is selected:
    `KeyResolutionError`. Document order used to pick the first.
  - `DidDocument.key_for_purpose` called directly with a bare or `#`-relative `kid`
    returns `None`; it takes the absolute DID URL a proof carries. `key_by_kid` is
    unchanged.
  - A `#fragment` resolves only against a document `id` that is a DID by DID Core 1.0
    §3.1 syntax. `did:web` fetches some DIDs that are not: a path segment with `~`,
    `+`, `!`, `@` or an invalid `%`-escape (`did:web:example.com:~alice`). Their
    documents must use absolute method ids and references
    (`did:web:example.com:~alice#key-1`); a `#key-1` in them selects and grants
    nothing (`KeyResolutionError`, or `ProofPurposeMismatch` for a reference).

### Fixed

- **The EBSI verifier's error messages no longer echo an attacker-sized DID or `kid`
  in full** (#257). `verify_ebsi_badge` and `verify_trust_chain` wrap the resolver's
  error in a message of their own, and those interpolated the token's `iss`, the
  accreditation's `iss` and `accreditedBy`, and the JWS `kid` with a bare `!r`. They are
  read before any signature is checked, so a 60 KB `iss` made a 60 KB exception message
  even when the resolver's own text was cut. Five messages now go through `safe_repr`
  (a `str` past 200 characters is cut and its length shown; shorter values read as
  before): `could not resolve issuer DID` and `no verification method for kid` in
  `verify_ebsi_badge`, and `accreditation issuer`, `cannot resolve accreditor` and
  `no verification method` for an accreditor in `verify_trust_chain`. The other messages
  in those two modules name a DID taken from a verified credential or from the
  registry's own response, and are unchanged.

- **The status-list builders' time inputs and `ttl` fail at build time, typed, and the
  one signed value they could get wrong is fixed**
  ([#255](https://github.com/luisgf/openvc/issues/255)). Found by the review of
  [#250](https://github.com/luisgf/openvc/pull/250); #250 had narrowed its docs to say
  these inputs were not covered. 140 builder calls probed on `main`: 66 raised a bare
  exception and none a `StatusListError`.
  - `build_status_list_token(issued_at=…, expires=…)`: a string, `NaN`, `±inf`, a
    `date`, a `timedelta`, a list, a `bool` and an integer no float holds all raise
    `StatusListError`. `10**400` was the one pure "minted what the verifier rejects" row
    (`verify_status_list_token` refuses the token as not a finite numeric timestamp), and
    `10**5000` died with a bare `ValueError` from `json.dumps` inside `sign_compact` (the
    4300-digit limit). A `datetime` whose `tzinfo` raises is typed too.
  - `build_status_list_token` reads a `datetime` the way the credential builder does:
    `utc_instant` rebuilds a plain aware `datetime`, and the epoch is taken from that,
    never from the caller's object. Before, the token asked the object for `timestamp()`,
    so a `datetime` subclass answering a 5000-digit integer died with the same bare
    `ValueError`, one answering `10**400` was minted as a 1329-bit `iat` / `exp` (which
    `verify_status_list_token` refuses as not a finite NumericDate), and one answering the
    string `"1700000000"` was coerced by `int()`. All three now mint the instant the
    object holds, and `timestamp()` is not called. A naive subclass whose `utcoffset()`
    answers something that is not a `timedelta` was read in the host's local zone (an
    hour off on a UTC+1 host) and is now a `StatusListError`.
  - Both builders now refuse the same `datetime`s: exactly those with no UTC form in years
    1 to 9999. The token used to mint year 1 at `+01:00` as `iat = -62135600400` and
    `9999-12-31T23:00` at `-05:00` as `253402315200`, which the credential builder
    refused. A caller that relied on those two edge values passes the UTC instant
    (`datetime(1, 1, 1, tzinfo=timezone.utc)`) or the epoch number; no other `datetime`
    changes, and an aware or naive value in years 1 to 9999 mints the same `iat` / `exp`
    byte for byte.
  - `build_status_list_credential(valid_from=…, valid_until=…)`: besides the non-`datetime`
    values above, an aware value whose UTC form leaves years 1 to 9999 (year 1 at
    `+01:00`, `9999-12-31T23:00` at `-05:00`) was a bare `OverflowError`; it and a
    `datetime` whose `tzinfo` raises are now a `StatusListError`. The error names the
    parameter (`valid_from cannot be read as an instant: date value out of range`).
  - a non-finite `ttl` was signed as `"ttl":NaN` (not JSON, RFC 8259): the JOSE verifiers
    accepted it while `eddsa-jcs-2022` and `eddsa-rdfc-2022` refused the same credential
    at `add_proof`. The builder, the one place that can decide for every lane, now
    refuses it before `sign_compact` is reached.
  - `validFrom` / `validUntil` are rendered with `isoformat`, not `strftime("%Y")`, which
    does not pad a year below 1000 on glibc (`999-01-01T00:00:00Z`, which the verifier
    refuses as a `MalformedTimestamp`). The string for every aware-UTC input is the
    same one the builder emitted before.
  - An `int` or `float` subclass is reduced to the plain number it holds before it is
    checked and signed (`int.__index__` / `float.__float__`), so the value checked is the
    value emitted; the same rule #250 applies to an index.

  Not changed, by design: the order of a window (a past `expires`, an `issued_at` in the
  future, `expires` before `issued_at`, `valid_until` before `valid_from`) is still the
  verifier's call at read time, and building such a list stays legitimate. `leeway_s` on
  `verify_status_list_token` is [#228](https://github.com/luisgf/openvc/issues/228), and
  the non-time string parameters (`contexts`, `issuer`, `subject_id`, an entry `id`) are
  separate.

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

- **`resolve("")` and the callers' messages are pinned** (#257).
  `test_ebsi_verifier.py` asks for the empty DID against a document whose `id` is
  absent, `""` or a number, bare and in a `didDocument` wrapper, and requires exactly
  `DidResolutionError`; a control shows the route answered. The 60 KB cases go through
  `verify_ebsi_badge` (the resolve wrapper, and a document without the token's `kid`)
  and, in `test_trust_chain.py`, through an accreditation whose `iss`, `accreditedBy` or
  `kid` is attacker-sized, each asserting the exact cut message and the exact class.
  Mutation-checked: dropping the empty-`id` guard fails the six `resolve("")` rows, and
  reverting any one of the eight `safe_repr` swaps fails the test for its message.
- **The binding is pinned for every wrong `id`** (#257). `test_ebsi_verifier.py` serves
  a registry document that is otherwise good (it holds the signing key under the right
  `kid`) with `id` set to another DID, a number, `null`, a list, an object, a bool,
  `""`, no `id` at all, a case-folded DID, a DID with a trailing space, a DID URL and
  another method's DID, each bare and in a `didDocument` wrapper. `resolve` raises
  exactly `DidResolutionError`, and `verify_ebsi_badge` exactly `EbsiVerificationError`
  with that cause; each case is paired with a control carrying the right `id`, which
  resolves and verifies. `test_trust_chain.py` serves the mismatched document as the
  accreditor's, at the middle and the root hop, and requires exactly
  `AccreditationInvalid`. The DID-URL and dot-segment cases go through the real
  `EbsiHttpClient` on an `httpx.MockTransport`, so httpx does the URL handling, and
  assert the registry was in fact asked. The recorded pilot document still resolves.
  Mutation-checked: 59 of these cases fail against the previous code, each with
  `DID NOT RAISE`, and the controls pass; a check that skips an empty `id`, and one
  that ignores case or surrounding space, each fail their own rows.
- **`tests/test_dcql_meta_upfront.py`** (#254). Negatives first, each pinning the
  query it names and the exact class: an unanswered query with a malformed `meta`
  in every format (the issue's shapes, plus falsy and non-string ones); the same
  with an earlier junk presentation; the malformed query listed first; the
  `mso_mdoc` order against a missing `expected_origins`, a missing `trust_anchors`
  and a presentation that is not a string; both formats agreeing on a `null`
  `meta`; and a malformed `meta` against each later shape check. Controls that pass
  before and after: an unanswered query with an absent, empty or other-format-key
  `meta` (malformed or not), an unknown format, a sound constraint, a well-formed
  `type_values` with `pyld` hidden, an answered one without `pyld` still
  `OpenID4VPError`, and the sound `mso_mdoc` order unchanged. Mutation-checked
  against `origin/main` at 886774f: 95 negatives fail and the 44 controls pass;
  removing the new call fails the same 95; putting the `pyld` check back in the
  shape parser fails the two `pyld` controls.
- **`test_did_webvh_state_envelope.py`** (#256). Ten wrapped states (a foreign `id`, a
  same-`id` wrapper that replaces the state's own methods, one beside the same methods,
  one alone, and a `null`, empty, list, string, number and `false` member) are refused
  by the sync and async resolvers with the exact class. Each is also run through
  `verify_credential`, `verify_credential_async`, `verify_many` and
  `verify_many_async` with a VC-JWT and an `eddsa-jcs-2022` credential signed by the
  log controller's own key, so before the fix the four rows whose wrapper holds a
  document verified. A good neighbour in each batch still verifies, and the same
  credentials verify against a log without the wrapper. The earlier states of a log are
  not looked at and the last one is, and the `did:web` and EBSI envelope tolerance is
  pinned as a control. A deactivated log with a wrapped last state reports the wrapper,
  and one with a bare last state still reports the deactivation. Mutation-checked
  against `origin/main`: 61 cases fail there, the 24 controls pass.
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

- **`tests/test_status_builders_time.py`** pins every row of the three tables in the issue
  (the time inputs of each of `issued_at`, `expires`, `valid_from` and `valid_until`, and
  every `ttl` on both builders) against the exact class `StatusListError`, with the token
  negatives signing through a key whose `sign` raises. A naive `datetime` is
  checked with `TZ` pinned to UTC, to a POSIX UTC+9 and UTC-5 (DST) zone and to
  `Asia/Tokyo` and `America/New_York`, and the check is made to fail if the pin did not
  take effect. Build, sign, verify round trips cover an aware UTC, `+09:00` and `-05:00`
  value, a naive one and years 1 and 9999. Hypothesis properties cover the accepted
  `datetime`s (exactly those with a UTC form in years 1 to 9999, for the token as for the
  credential, with the edge values pinned as `@example`s), a window the builders accept and
  the verifier reads inside it, the token's time inputs, and `ttl`. A `datetime` subclass
  whose `timestamp()` raises, answers `10**5000`, `10**400`, a digit string, `NaN` or a
  negative number is built for each of an aware UTC, an aware `+09:00` and a naive value,
  in `issued_at` and `expires`, and must mint the instant it holds; a naive subclass whose
  `utcoffset()` is not a `timedelta` is refused by both builders.
  Mutation-checked in a scratch copy of `src`: 223 of the 256 cases fail against the code
  before this PR (`a815089`). The 33 that pass are the controls, the naive-`datetime` cases
  on a UTC host (the bug is invisible by construction) and the year-padding rows on a host
  whose `strftime` pads, such as macOS (glibc fails them). The token's `datetime` reading
  is checked separately: with `_epoch` back on `utc_epoch`, 49 cases fail (the 36
  `timestamp()` rows, the 10 no-UTC-reading rows, the token control that used to expect
  `iat = -62135600400`, the error-class test and the token property).
- **`tests/test_did_reference_exact_match.py`** (#258). Every row of the issue's
  table on the `assertionMethod` lane through `verify_credential` and
  `verify_credential_async`, and on the `authentication` lane through the suite call
  the `ldp_vc` holder proof makes, plus one `verify_vp_token` `ldp_vc` case; two
  grants and three refusals on each of the five suites; relative method ids and references
  that resolve; a `#fragment` reference, and a relative method id, in documents
  whose `id` is not a DID; methods with another DID's, a bare or a versioned `id`
  that must not be selected; a same-fragment method listed first that must not
  shadow the exact one; duplicate absolute ids; the `kid`-less fallback; a
  `[good, bad, bad, good]` batch on `verify_many` and `verify_many_async`; the
  JOSE lanes' unchanged `kid` tolerance; a resolver that returns its own document
  type, refused with a typed error on `verify_credential`, `verify_credential_async`,
  `verify_many` and `verify_many_async` beside good neighbours; `did:web` documents
  whose `id` fails the §3.1 syntax, where only absolute ids verify; and a linear-cost
  pin. For a 100 000-character `did:web` with 200 extra methods and 2 000 references,
  against one method and one reference, the DID syntax check runs the same fixed
  number of times (both lanes, the `assertionMethod` one sync and async), no entry
  copies the document `id`, and the prefix checks made on the selected method's
  resolved `id` stay the same fixed number; with 10 000 references,
  `verify_credential` stays under a loose wall-clock bound. The adversarial review of
  this fix found its first version re-checking the `id` once per reference: about 30 s
  for that document, and minutes near the 1 MiB fetch cap. Each hostile row uses a
  resolvable issuer (an injected `did:web` fetch, or a stub resolver where the point is
  a document `id` `did:web` would refuse) and asserts the exact class. Run against the
  previous code: 100 fail, and the 43 that pass are the grants, the controls, the four
  rows with a resolver's own document type (the previous code refused those with a
  typed error too) and the two wall-clock rows (the previous lookup was linear).

## [1.32.3] — 2026-10-14

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

### Changed

- **The status-list builders and codec refuse inputs outside their documented
  types** ([#230](https://github.com/luisgf/openvc/issues/230)). Each of these calls
  used to succeed and now raises `StatusListError`, with what to pass instead.

  Inputs that built an artefact openvc's verifier refuses, or read the wrong bit:
  - an `index` that is a `bool`, a `float` or `NaN`, or past 2^27, on the builders (pass
    an `int` below 2^27); a `bool` `index` on the codec, which read the bit of index 0
    or 1 (pass the `int`);
  - a `bits` that is a `bool` or a `float` on `build_status_list_token` (pass the
    `int`: 1, 2, 4 or 8);
  - a list longer than 16 MiB (split the statuses across lists);
  - a non-string or empty `statusListCredential` or `status_purpose` on
    `build_status_list_entry`, a truthy non-string `status_purpose` (`5`) on
    `build_status_list_credential` (the verifier compares it with the entry's and
    refuses the list: `status-list purpose 5 != entry purpose 'revocation'`), and a
    non-string or empty `uri` on `build_token_status_reference` (pass the string); the
    check side refuses an empty or non-string one, and an empty `status_purpose` never
    matches a normal list's.

  Inputs that built a working artefact but fall outside the documented types:
  - anything `bytes()` accepted that is not a buffer, as the list on
    `build_status_list_credential` or `build_status_list_token`: a `list`, `tuple`,
    `range`, generator, `dict` (its keys) or an object with `__bytes__`. Pass
    `bytes(values)`;
  - an integral `Decimal` or `Fraction` (a database `NUMERIC` column, say) as the
    `index` of `build_status_list_entry`: pass `int(index)`. On
    `build_token_status_reference` it put an object into the claim that `json.dumps`
    cannot serialise;
  - a `bool` `bits` on `get_status`, `set_status` and `new_status_list`, and a `bool`
    `size` on `new_bitstring` and `new_status_list` (each read as 1): pass `1`. A
    `Fraction` `size` on those two, and `Fraction(1)` as `bits` on `new_status_list`,
    worked by comparing equal to the number: pass the `int`. A `size` past the 16 MiB
    cap allocated a list the verifier cannot read back;
  - a falsy `status_purpose` (`""`, `None`, `0`) on `build_status_list_credential`: the
    verifier skips the purpose match against a falsy list purpose, so entries still
    revoked off it, and an entry with an empty purpose too could never revoke. Pass the
    purpose (`"revocation"` is the default);
  - an `int` as the list, a zeroed list of that many bytes (pass `bytes(n)` if that is
    what you meant), and an empty or non-string list credential `id` (pass the URL
    string);
  - a non-string or empty `uri` on `build_status_list_token`: the token verifies, but
    no reference can name it, because the check side refuses an empty or non-string
    `uri`. Pass the URL string.

  A `str`, `None` or a bad `size` / `bits` type used to be a bare `TypeError` or
  `ValueError` and is now the typed error. Well-formed calls are unchanged, and the
  codec keeps its messages, in the order it reported them (`set_status`: `bits`, a bad
  or negative `index`, the `value`, an `index` past the data). The builders'
  negative-index message now names the field (`statusListIndex must be non-negative`,
  `status_list idx must be non-negative`), where it said `status index must be
  non-negative`.

### Fixed

- **The status-list builders no longer mint what openvc's own verifier refuses**
  ([#230](https://github.com/luisgf/openvc/issues/230)). Found by the adversarial
  review of #215, which gave the verifier one rule for a status index
  (`status_index`: an `int`, never a `bool` or `float`, below 2^27) but left the
  issuer side alone. `build_status_list_entry` and `build_token_status_reference`
  emitted `True`, `3.7`, `NaN` and `2**27` as an index, and a string index raised a bare
  `TypeError`; an issuer found out only when every credential pointing at it failed
  verification. Now:
  - both builders check `index` with the verifier's own `status_index` and raise
    `StatusListError` at build time. The W3C entry still emits the base-10 string, the
    IETF `idx` stays an integer. `status_index` reads the integer through
    `int.__index__` before it compares anything and returns that plain `int`, so an
    `int` subclass that overrides `__int__`, `__str__`, `__repr__`, `__format__` or a
    comparison (an `IntEnum` on Python 3.10 prints `'E.FIVE'`) cannot pass the checks as
    5 and be written, compared or addressed as something else. `size`, `bits` and the
    `value` of `set_status` get the same treatment;
  - `status_list_credential`, `status_purpose` (also on `build_status_list_credential`),
    the IETF `uri` and the list credential `id` must be non-empty strings;
  - `build_status_list_credential` and `build_status_list_token` take a `bytes`,
    `bytearray`, `memoryview` or `array.array` (the annotations say exactly these; wrap
    any other buffer in `memoryview()`) and refuse anything else (an `int`, a `str`,
    `None`, a `list`; `bytes(1024)` used to be a silent zeroed list) and a list longer
    than the 16 MiB the verifier inflates. A non-contiguous `memoryview` (`view[::2]`)
    is the bytes it exposes (`view.tobytes()`), not the memory behind it, and a buffer
    whose export raises is a `StatusListError`, not the caller's exception;
  - `new_bitstring(size)` and `new_status_list(size, bits=...)` refuse a `size` that is
    not an `int` (a `bool` or `float` too) or whose packed list would exceed those
    16 MiB: 2^27 one-bit statuses, 2^24 at 8 bits;
  - `get_status_bit`, `set_status_bit`, `get_status` and `set_status` refuse a `bool`
    or non-`int` `index` (`get_status_bit(b"\x40", True)` returned bit 1; a `float` was
    a bare `TypeError`). `get_status`, `set_status`, `new_status_list` and
    `build_status_list_token` also refuse a `bits` that is a `bool`, a `float` or
    unhashable, and `set_status` a `value` that is not an `int` (a `bool` still counts
    as 0 or 1). `set_status_bit` keeps reading its `value` for truthiness. A huge index
    no longer escapes as a bare `ValueError`: the error text does not render it.

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

[1.37.0]: https://github.com/luisgf/openvc/releases/tag/v1.37.0
[1.36.0]: https://github.com/luisgf/openvc/releases/tag/v1.36.0
[1.35.1]: https://github.com/luisgf/openvc/releases/tag/v1.35.1
[1.35.0]: https://github.com/luisgf/openvc/releases/tag/v1.35.0
[1.34.0]: https://github.com/luisgf/openvc/releases/tag/v1.34.0
[1.33.2]: https://github.com/luisgf/openvc/releases/tag/v1.33.2
[1.33.1]: https://github.com/luisgf/openvc/releases/tag/v1.33.1
[1.33.0]: https://github.com/luisgf/openvc/releases/tag/v1.33.0
[1.32.4]: https://github.com/luisgf/openvc/releases/tag/v1.32.4
[1.32.3]: https://github.com/luisgf/openvc/releases/tag/v1.32.3
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
