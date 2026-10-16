# Trust anchors: X.509, EU Trusted Lists, EBSI

A verified signature only proves *someone* signed — trust is deciding **who
may vouch**. openvc keeps that decision **caller-pinned**: you hand it the
anchors; it never ships an implicit root.

## X.509 (`x5c`) anchors

For tokens that carry their certificate chain, pass the roots you trust;
openvc validates the path and **binds the leaf's SAN to the `iss`**, so a
valid-but-unrelated certificate cannot vouch for an arbitrary issuer:

<!-- docs: no-run -->
```python
result = verify_credential(token, x5c_trust_anchors=my_trusted_roots)
```

## EU Trusted Lists (eIDAS / EUDI)

`openvc.trustlist` turns the European Commission's **List of Trusted Lists**
and the national Trusted Lists it points at (ETSI TS 119 612) into X.509
anchors for that same `x5c` path — closing the gap between *"the chain is
internally valid"* and *"the chain roots in an **EU-recognised** anchor,
granted now, for the right service type"*:

<!-- docs: no-run -->
```python
from openvc import verify_credential
from openvc.trustlist import verify_xades_enveloped, walk_lotl   # [trustlist] extra

anchors = walk_lotl(
    LOTL_URL,
    lotl_signer_certs=commission_certs,       # caller-pinned: the Commission's keys
    verify_signature=verify_xades_enveloped,  # XAdES check on every list (fail-closed)
)
result = verify_credential(token, x5c_trust_anchors=anchors.certificates)
```

Properties worth knowing:

- **Trust is caller-pinned** — you supply the LOTL signer certificates; there
  is no implicit root.
- **Fail-closed** — a national TL that cannot be fetched, verified, or is
  expired contributes **zero** anchors and is recorded in `anchors.problems`,
  never silently trusted.
- **Selective** — the default selection keeps `granted` qualified-CA services
  (the ones that issue EUDI issuer certs); pass `select=None` for everything, or a
  `Select(service_types=…)` over `ServiceType`. Beyond `CA_QC`, the named types cover
  the qualified trust services **TLv6** national lists carry (`EDS_Q`, `PSES_Q`,
  `QES_VALIDATION_Q`, `REMOTE_QSIGCD_MANAGEMENT_Q`, `REMOTE_QSEALCD_MANAGEMENT_Q`,
  `TSA_QTST`, …). `Select` matches the `ServiceTypeIdentifier` **verbatim**, so the
  EUDI-wallet trust services v2.4.1 adds (issuance of QEAA / EAA / PuB-EAA, qualified
  electronic ledgers) are selectable by their URI as national lists start carrying them.
- **TLv6** — since **29 Apr 2026** the LOTL and every national TL are ETSI TS 119 612
  **v2.4.1** (TLv6) only. The parser reads `TSLVersionIdentifier` (`TrustList.version`
  — `6` for TLv6) and tolerates the new optional elements (e.g. `ServiceSupplyPoints`);
  the `[trustlist]` XAdES verifier accepts the mandated **XAdES-BASELINE-B** signatures
  (document + `SignedProperties` references) and is pinned by golden fixtures recorded
  from the real Commission-signed EU LOTL and the Spanish national TL.
- **Hardened XML** — stdlib parsing with DTD/DOCTYPE rejected (no XXE, no
  entity-expansion bombs), size-bounded input; XAdES verification lives behind
  the `[trustlist]` extra (`signxml`) and pins the signer to the certs the
  parent list vouched for.

Design rationale: [ADR-0003](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0003-eu-trusted-lists.md).

## EU Lists of Trusted Entities (LoTE, TS 119 602)

**ETSI TS 119 602** is the successor trusted-list data model: the same
information as a TS 119 612 list, serialized as **JSON** and signed as a
**compact JAdES baseline-B** JWS whose payload is the list. Its EU profiles are
the EUDI wallet anchor lists — **Annex F**: providers of relying-party *access*
certificates (WRPAC), **Annex G**: providers of relying-party *registration*
certificates (WRPRC, the registrar anchors
[`verify_rp_registration_certificate`](Relying-Party-Certificates) consumes).
One interface, two encodings — `walk_lote` distils into the same
`TrustAnchorSet` as `walk_lotl`:

<!-- docs: no-run -->
```python
from openvc.rp_registration import verify_rp_registration_certificate
from openvc.trustlist import EU_WRPRC_PROVIDERS_PROFILE, walk_lote

anchors = walk_lote(
    WRPRC_PROVIDERS_LOTE_URL,                  # the Commission's Annex G list
    lote_signer_certs=commission_certs,        # caller-pinned: no implicit root
    profile=EU_WRPRC_PROVIDERS_PROFILE,        # Annex G conformance gate, fail-closed
)
reg = verify_rp_registration_certificate(wrprc, trust_anchors=anchors.certificates)
```

Properties worth knowing:

- **JOSE, no extra needed** — a LoTE verifies on the library's own JWS
  primitives: the `{ES256, ES384, EdDSA, Ed25519}` allow-list runs **before**
  any crypto, `crit` is allow-listed (`{alg, typ, x5c, iat}`, the JAdES stance the
  WRPRC lane started from; the WRPRC lane has since added `sigT` and `b64: true`
  for the registrars that emit them, a widening the LoTE verifier does **not**
  share), and the signer comes from `x5c`, authenticated against the
  pinned certificates byte-for-byte or by path validation to them.
- **Clause 6.8 DN binding** — the signing certificate's `organizationName`
  must match a `SchemeOperatorName` value and its `countryName` the
  `SchemeTerritory`, so a certificate pinned for one scheme cannot vouch for a
  list claiming another operator.
- **Strict, fail-closed parsing** — unknown structural members reject (the
  official JSON schema is `additionalProperties: false` throughout), date-times
  must be the UTC `Z` form, an unrecognised **critical** scheme/service
  extension rejects the list (clause 6.3.17), and a certificate blob that does
  not load is skipped, never silently trusted.
- **Profiles are conformance gates** — `EU_WRPAC_PROVIDERS_PROFILE` /
  `EU_WRPRC_PROVIDERS_PROFILE` enforce Tables F.1–G.3: the registered
  `LoTEType` / StatusDetn / schemerules URIs, territory `EU`, the exclusive
  service-type pair, `ServiceStatus` / `StatusStartingTime` /
  `HistoricalInformationPeriod` **absent** (under these profiles, *listing* is
  the status — removal is revocation), and the ≤ 6-month update window.
  Note: the WRPRC StatusDetn URI is spelled `…/WRPRCrovidersList/StatusDetn/EU`
  (sic) in the spec and the EUDI reference implementation; the profile accepts
  both that literal and the corrected spelling.
- **Same walk discipline, least privilege by default** — pointed lists verify
  against the certificates their pointer vouched for (one hop, like LOTL→TL);
  in a *profiled* walk a pointer is only followed when its qualifier `LoTEType`
  matches the profile, and the pointed list must conform to the **same**
  profile — a foreign list type can never leak anchors in. A list that cannot
  be fetched, verified, or is expired — or is **closed** (`NextUpdate` null) —
  contributes zero anchors and lands in `problems`. Under a profile, `select`
  defaults to the profile's **issuance** service type only: a provider's
  *revocation* service is a legitimate list entry, but its certificates must
  not anchor credential verification (pass an explicit `Select`, or
  `select=None` for every admitted anchor, to widen deliberately). With no
  profile the default keeps everything — the EU profiles forbid
  `ServiceStatus`, so the 119 612 lane's granted-status default would drop
  every anchor.

The Commission had not yet published the EU LoTE instances when this lane
shipped; conformance is pinned by self-made vectors against TS 119 602 V1.1.1,
and the real lists become golden fixtures when they go live.

## EBSI (read-only plugin)

`openvc_ebsi` resolves `did:ebsi` and reads the **Trusted Issuers Registry**,
then verifies the full accreditation chain — TI → TAO → RootTAO — recursively,
with per-hop delegation scoping and revocation of the accreditations
themselves:

<!-- docs: no-run -->
```python
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import for_ebsi
from openvc_ebsi.versioning import DidEbsiResolver
from openvc_ebsi.verify import verify_ebsi_badge

suite = VcJwtProofSuite()
with for_ebsi("legacy-pilot") as http:
    resolver = DidEbsiResolver(http.get_json, decode_jwt=suite.peek_claims)
    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                               expected_types=["VerifiableAttestation"])
    print(result.trusted, result.issuer)
```

On the Core API v1 the node is yours to choose (and to verify), so the lane is built
explicitly:

<!-- docs: no-run -->
```python
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import EbsiHttpClient, HttpError
from openvc_ebsi.versioning import DidEbsiResolver, DidRegistryCoreV1, TirCoreV1

suite = VcJwtProofSuite()
# `node_origin` is one verified node's bare origin ("https://<host>"), `node_host` its host
with EbsiHttpClient(allowed_hosts={node_host}) as http:
    resolver = DidEbsiResolver(
        http.get_json, decode_jwt=suite.peek_claims, base=node_origin,
        didr=DidRegistryCoreV1(), tir=TirCoreV1())
    try:
        record = resolver.issuer_record(issuer_did)
    except HttpError as exc:
        print(exc.status, exc.problem_type)   # e.g. 404 and an opaque `type`, or None
```

- **Read-only by design**: resolve DIDs, read the registries. Onboarding /
  writing (JSON-RPC + OID4VP) is out of scope.
- **SSRF-guarded**: the EBSI HTTP client is https-only with an origin
  allow-list (a listed host **and port 443**), short client-side TTL caching, and bounded retries
  ([ADR-0001](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0001-ebsi-http-client.md)).
  A listed host on any other port (`:80`, `:8443`, `:0`), a URL that carries userinfo
  (`https://user@host/`), a URL that is not visible ASCII, and one that does not parse (port
  included) are refused as `HttpForbiddenHost` before any request. An absent or empty port,
  `:443` and `:0443` are 443. `allowed_hosts` still holds host names, so a caller on 443
  changes nothing. The DID itself is checked before it is put in a registry URL: anything but `did:ebsi:z` plus 22 or 23 base58btc
  characters (a path, a `..`, a query, a fragment, a percent escape, another method) is a
  `DidResolutionError` from `resolve` / `issuer_record`, so an unsigned token's `iss`
  cannot choose the request path (`verify_ebsi_badge` reports `EbsiVerificationError`).
  The client keeps no cookies: a `Set-Cookie` from a node is dropped and nothing is sent
  back, so consecutive reads may reach different backends of one node.
  Never resolve `did:web` through it — `did:web` has its own guarded fetch
  (see [Resolving issuer keys](Resolving-Issuer-Keys)).
- **Optional resolved-address guard** (v1.37.0): the allow-list matches a *name* and, by
  default, trusts DNS for it. Pass `address_guard=AddressGuard()` to `EbsiHttpClient` or
  `for_ebsi` and every request that misses the cache resolves the host, refuses it with
  `HttpForbiddenAddress` if **any** address is not globally routable (the rules
  `openvc.fetch` applies to `did:web`: private, loopback, link-local, cloud metadata,
  multicast, CGNAT, site-local `fec0::/10`, NAT64, 6to4, Teredo and the rest), and
  connects to one validated
  address while the TLS name, the certificate check and `Host` stay the host name. It is
  **off by default** (a deployment with split-horizon DNS or a private mirror would
  break), it sends `Connection: close` (no keep-alive: a reused connection would answer
  for a second name with no certificate check for it), it rotates through the validated
  addresses on a retry (one address per attempt, so under the default `RetryPolicy` only
  the first three addresses of an answer are ever tried; set `RetryPolicy(attempts=...)`
  to at least the number of addresses you must reach), and it refuses to be built behind an
  environment proxy
  (`HttpAddressGuardUnavailable`) because the proxy would resolve and connect by itself.
  It does not stop an attacker who also holds a valid certificate for a public address, a
  dishonest listed node, or anything about registry content. There are no exemptions: to
  reach an internal mirror, build a second client without the guard. Use it as
  `for_ebsi("pilot", address_guard=AddressGuard())`, with `AddressGuard` from
  `openvc_ebsi.http`.
- **The document must be for the DID asked**: `DidEbsiResolver.resolve(did)` raises
  `DidResolutionError` unless the registry document's `id` is exactly `did`, as `did:web`
  does (a missing, empty, non-string or differently-cased `id`, and a DID URL such as
  `did:ebsi:zX#key-1`, are refused). The Trusted Issuers Registry record is held to the
  same rule: `issuer_record(did)` raises `MalformedRegistryResponse` unless the response
  names exactly `did` (another DID, or an absent, `null`, non-string or empty `did`, on
  every API version), before any `attributes` page or revision is fetched, so
  `IssuerRecord.did` is the DID the registry answered for. The `attributes` / `href` path
  is still pinned to the registry's origin, not to the issuer.
- **Environment-aware**: `for_ebsi(environment)` seeds the allow-list from the host of a
  named EBSI environment, `"legacy-pilot"` by default. The names mean this, as measured and
  recorded on 2026-10-16
  ([ADR-0009](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)):
  - `legacy-pilot` is `api-pilot.ebsi.eu`, the legacy per-service lane (the v5 adapters), and
    the only place the recorded fixtures and the weekly smoke test are valid.
  - `pilot` is the same host and the same lane, kept as it was and not deprecated. EBSI now
    also uses "pilot" for its Core API pilot, which is a different ledger that this name does
    not reach; `legacy-pilot` says which one you mean. ADR-0009's planned end state gives
    `pilot` the Core API meaning, at the earliest in the 2.0 window
    ([#74](https://github.com/luisgf/openvc/issues/74); not decided yet), so prefer
    `legacy-pilot` in code that will outlive a major upgrade.
  - `conformance` (`api-conformance.ebsi.eu`) and `production` (`api.ebsi.eu`) are kept as
    they were, with the same allow-list rule, but a client built from either is not known to
    complete a request today. One 12-second probe of the conformance host (a single attempt
    from one place, so possibly transient) completed no TCP connection; the certificate the
    production host presented did not cover its name, and none of the 45 node URLs in version
    4 of the Trusted Nodes List is under `ebsi.eu`. A request through such a client fails
    closed.
  - Any other name (another case, an empty string, a value that is not a string) raises
    `UnknownEbsiEnvironment`, which is also a `ValueError`.

  Pass `extra_hosts` (host names, port 443 only) to also permit an issuer's status-list host; a
  status list on another port is refused. The v5 Trusted Issuers
  Registry `/attributes` listing is paginated, and openvc walks every page (bounded, and
  immune to EBSI's self-referential `next` cursor) so an issuer with many accreditations is
  read in full.
  The Trusted Nodes List host (`tnl.ebsi.eu`, below) is a second, separate allow-list that
  is never merged with this one.
- **Two lanes, selected together**: the legacy pilot (one API per service,
  `"v5"`, the default of `did_registry_adapter()` / `tir_adapter()`, host
  `api-pilot.ebsi.eu`) and the **EBSI Core API v1** (`"core-v1"`:
  `DidRegistryCoreV1` and `TirCoreV1`, paths `/v1/did-registry/...` and
  `/v1/issuers-registry/...` on the answering *node's own origin*, so every
  `self`, `links` and `href` names that node). A Core v1 caller passes the node's
  bare origin as `base` and `didr` and `tir` **together**, over a client whose
  allow-list holds that node's host; nothing infers one from the others, and
  `for_ebsi(...)` still builds a client for the legacy hosts. The allow-list should come from a
  node list you have *verified* (the Trusted Nodes List is signed), not from
  hostnames pasted off a web page: issue
  [#316](https://github.com/luisgf/openvc/issues/316) has the recipe, and
  [ADR-0009](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)
  the reasoning (a signed list authenticates the *operator*, not the content a node
  serves). `contract_address="0x..."` on either adapter selects a registry instance
  (each registry has its own address, published on its `/details`); a walk
  configured with one stays on it.
- **Core v1 error types**: an error answer of `application/problem+json` (RFC 9457)
  puts its `type` on `HttpError.problem_type` (`None` for any other answer, a
  `text/html` firewall page included, and for a `type` that is not 1 to 256 visible
  ASCII characters). It is opaque: match on it, never on a message, and do not
  expect a `urn:ebsi:problems:` slug on every error (the recorded 406 says
  `about:blank`). An error body is read at most 16 KiB; a larger one is dropped
  with its connection.
- **Exact bytes and the Trusted Nodes List host**: `EbsiHttpClient.get_bytes(url)` returns a
  response body verbatim as a `BytesResponse(body, etag)` (no JSON parse, no cache, no text
  decoding), under the same host guard, redirects-off and retry rules as `get_json`. The
  body is read raw against a hard cap on the wire size **and** on the decoded size of a
  single `gzip` / `deflate` coding (any other coding is `HttpUnexpectedEncoding`); the body
  of a non-200 response is never read; and an `etag` you pass is sent as `If-None-Match`
  (a 304 comes back as `BytesResponse(None, etag)`, which means "re-use what you stored").
  `deadline_s` (up to a day) is a budget over the attempts, the sleeps and the body read; it
  is **not** a ceiling on the wait for one response's headers, which only `timeout_s` bounds,
  per socket operation, so run the call under your own timeout if you need a hard limit. The
  EBSI client is synchronous: there is no async twin.
  `for_tnl()` builds a client that allow-lists `tnl.ebsi.eu` **alone**, and
  `get_tnl_files()` fetches the four signed Trusted Nodes List documents through it. **The
  bytes are unauthenticated**: the helper verifies nothing, polls nothing, stores nothing
  and never fetches the pinned key-list key; keep the bytes and the ETags yourself and
  hand the bytes to a verifier ([ADR-0009](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)
  D4).

<!-- docs: no-run -->
```python
from openvc_ebsi.http import get_tnl_files

files = get_tnl_files()                      # four GETs to https://tnl.ebsi.eu/, nothing verified
# ... verify files["tnl.json"].body against files["tnl.json.sig"].body, keep them, then
# on the next refresh ask only for what changed:
etags = {name: r.etag for name, r in files.items() if r.etag}
files = get_tnl_files(etags=etags)           # a 304 is BytesResponse(None, <the etag sent>)
```

- **Version drift, contained**: every EBSI API version specific lives behind
  one adapter in `openvc_ebsi.versioning` and the two TIR lanes share one walk, so
  the origin pin and the caps are written once; the trust logic never sees wire
  formats. Conformance is pinned by recorded fixtures for both lanes: the pilot
  (`tests/fixtures/ebsi/`) and the Core API v1 (`tests/fixtures/ebsi/core-v1/`, two
  preprod nodes and the one-issuer production seed, with a hash manifest), plus an
  opt-in live smoke test (`OPENVC_EBSI_LIVE=1 pytest`, today against the legacy
  pilot host).
