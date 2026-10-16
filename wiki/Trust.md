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
with for_ebsi("pilot") as http:
    resolver = DidEbsiResolver(http.get_json, decode_jwt=suite.peek_claims)
    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                               expected_types=["VerifiableAttestation"])
    print(result.trusted, result.issuer)
```

- **Read-only by design**: resolve DIDs, read the registries. Onboarding /
  writing (JSON-RPC + OID4VP) is out of scope.
- **SSRF-guarded**: the EBSI HTTP client is https-only with a host
  allow-list, short client-side TTL caching, and bounded retries
  ([ADR-0001](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0001-ebsi-http-client.md)).
  A URL that is not visible ASCII, or that does not parse (port included), is
  refused as `HttpForbiddenHost` before any request. The DID itself is checked before
  it is put in a registry URL: anything but `did:ebsi:z` plus 22 or 23 base58btc
  characters (a path, a `..`, a query, a fragment, a percent escape, another method) is a
  `DidResolutionError` from `resolve` / `issuer_record`, so an unsigned token's `iss`
  cannot choose the request path (`verify_ebsi_badge` reports `EbsiVerificationError`).
  Never resolve `did:web` through it — `did:web` has its own guarded fetch
  (see [Resolving issuer keys](Resolving-Issuer-Keys)).
- **The document must be for the DID asked**: `DidEbsiResolver.resolve(did)` raises
  `DidResolutionError` unless the registry document's `id` is exactly `did`, as `did:web`
  does (a missing, empty, non-string or differently-cased `id`, and a DID URL such as
  `did:ebsi:zX#key-1`, are refused). The Trusted Issuers Registry record is held to the
  same rule: `issuer_record(did)` raises `MalformedRegistryResponse` unless the response
  names exactly `did` (another DID, or an absent, `null`, non-string or empty `did`, on
  every API version), before any `attributes` page or revision is fetched, so
  `IssuerRecord.did` is the DID the registry answered for. The `attributes` / `href` path
  is still pinned to the registry's origin, not to the issuer.
- **Environment-aware**: `for_ebsi("pilot" | "conformance" | "production")` seeds
  the allow-list from the chosen EBSI environment — `production` (`api.ebsi.eu`) is
  registered for EBSI's Q4 2026 business launch. Pass `extra_hosts` to also permit an
  issuer's status-list origin. The v5 Trusted Issuers Registry `/attributes` listing
  is paginated, and openvc walks every page (bounded, and immune to EBSI's
  self-referential `next` cursor) so an issuer with many accreditations is read in full.
- **Version drift, contained**: every EBSI API version specific lives behind
  one adapter in `openvc_ebsi.versioning`; the trust logic never sees wire
  formats. Conformance is pinned by recorded pilot fixtures, plus an opt-in
  live smoke test (`OPENVC_EBSI_LIVE=1 pytest`).

### Which node? Verifying the Trusted Nodes List

EBSI no longer publishes a host to call. A client picks a *node* from the **Trusted Nodes
List (TNL)** at `https://tnl.ebsi.eu`: a JSON document signed with OpenPGP by a threshold of
*custodians*, whose keys are in a second document signed by one Europeum **key-list key**.
`openvc_ebsi.nodes.verify_node_list` checks that chain **offline**, from the four files
exactly as served, and returns the nodes of **one** environment (`"pilot"`, `"preprod"` or
`"prod"`, the list's own names). It fetches nothing, reads no clock, opens no socket and
keeps nothing
([ADR-0009](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)).
It needs only `cryptography`, so it works without the `ebsi` extra.

<!-- docs: no-run -->
```python
from datetime import datetime, timezone

from openvc_ebsi.errors import NodeListError
from openvc_ebsi.http import EbsiHttpClient
from openvc_ebsi.nodes import verify_node_list

# the four files, byte for byte as tnl.ebsi.eu served them: do not decode, re-save or
# re-format them (a str is refused)
try:
    result = verify_node_list(
        tnl=tnl_bytes, tnl_sig=tnl_sig_bytes, keys=keys_bytes, keys_sig=keys_sig_bytes,
        environment="prod",
        now=datetime.now(timezone.utc),            # required: the function reads no clock
        last_accepted_list=saved_list,             # Accepted(version, sha256), None on a first run
        last_accepted_keys=saved_keys,             # the same for trusted-keys.json
    )
except NodeListError:
    ...  # keep using the last list you accepted until its own `expires`, and alert

saved_list, saved_keys = result.accepted_list, result.accepted_keys   # persist once YOU accept
print(result.version, result.expires, [node.origin for node in result.nodes])
with EbsiHttpClient(allowed_hosts=set(result.hosts)) as http:   # lower-case hosts, ONE environment
    ...
```

The chain, in the order it is checked (a stage never reads bytes the previous one did not
authenticate):

1. the arguments and the size caps (a `.sig` file is capped at 4 KiB);
2. `trusted-keys.json.sig` must carry a valid signature by the **anchor**, and only then is
   `trusted-keys.json` parsed (its version is checked against the floor and your
   `last_accepted_keys`; `threshold` must be between 1 and the number of custodians);
3. each custodian's key block is read and its v4 fingerprint is **recomputed** and compared
   with the listed one (a duplicate custodian is refused, by fingerprint and by key);
4. `tnl.json.sig` must carry valid signatures by at least `threshold` **distinct custodian
   primary keys**; a signature is attributed to its signer by the *hashed*
   issuer-fingerprint subpacket only (the unhashed area is not covered by the signature and
   is never read), a signature by an unknown key or by a custodian's *subkey* is ignored,
   one invalid signature by an allowed key rejects the whole file, and the same custodian
   twice counts once;
5. only now is `tnl.json` parsed and checked by hand against the published schema (exactly
   five members; `version` / `keysVersion` integers of at least 1; `Z` timestamps;
   `expires` after `issued` and at most 90 days later; every node `url` a bare `https://`
   origin, ASCII, unique, starting with its environment's prefix; two-letter upper-case
   `country`; a non-empty `organisation` without leading or trailing whitespace), then the
   version against its floor and your `last_accepted_list`, `keysVersion` against the key
   list's own `version`, and the time rules.

**What it gives, and what it does not.**

- The list authenticates the **operator** of each node, not the **content** it serves: a
  dishonest listed node can still serve another key for a DID or a forged accreditation,
  and openvc will verify what it is given. The real root of the chain is the single anchor
  key.
- **Persistence is yours.** `last_accepted_list` and `last_accepted_keys` are required
  arguments so the obligation is in the signature, but `None` ("first run") is always
  passable, so the function cannot tell an honest `None` from a convenient one. What bounds
  a caller that persists nothing is two version floors shipped in the wheel
  (`LIST_VERSION_FLOOR`, `KEYS_VERSION_FLOOR`), the optional `max_age`, and `min_threshold`
  (default **2**, the live value; pass `None` for no minimum, or a lower number for a key
  list whose threshold is 1). A floor can only reject, so it is raised to the newest
  version EBSI has published **at each openvc release**; one that falls behind only weakens
  the replay bound of a stateless caller.
- **The list expires, at most 90 days after it was issued.** `now` at or after `expires` is
  `NodeListExpired`; a client that outlives its list must re-verify (a list issued more than
  300 s in the future is `NodeListNotYetValid`). Keep fetching about every hour, with
  `If-None-Match`; that part is yours too.
- **The anchor.** `EUROPEUM_KEY_LIST_ANCHOR` is the key-list key as served on 2026-10-16
  (fingerprint `ACCC82E5FC8902F114929481747CB65CFB7574F9`). What was checked is that the
  fingerprint agrees across `tnl.ebsi.eu`, the public TNL repository and the hub
  documentation, which are all Europeum's own channels; nothing independent confirms it.
  Pass your own with `Anchor.from_public_key_block(armored)` after you have verified the key
  out of band; never download it at runtime. Europeum has announced that a qualified
  electronic seal will replace this key, at which point a shipped anchor stops verifying
  new key lists and strict clients fail closed until they upgrade or override the anchor.
- **A narrow OpenPGP profile, on purpose.** OpenPGP v4, ECDSA over NIST P-256, SHA-256,
  binary signatures, old-format packet headers. Anything else (another curve or hash, a
  v5/v6 packet, a new-format header, an armored `.sig`) is `OpenPgpError`, and a signature
  or key carrying an expiration subpacket, a revocation or an unknown critical subpacket
  is refused rather than ignored. Self-signatures and subkey bindings are not verified:
  the key list's signature is what vouches for the custodian keys.

The errors are all `openvc_ebsi.errors.NodeListError` (an `EbsiError`):

| Raised | When |
|---|---|
| `NodeListConfigError` | a bad argument: unknown environment, `now` missing, a `str` instead of bytes, a malformed `Accepted`, anchor, floor, `max_age` or `min_threshold` |
| `NodeListMalformed` (`OpenPgpError`) | a size cap, JSON or schema rule, a duplicate or mislisted custodian; `OpenPgpError` for anything outside the OpenPGP profile |
| `NodeListSignatureError` | a signature by an allowed key does not verify, or the key list is not signed by the anchor |
| `NodeListThresholdError` | fewer distinct custodians signed than `threshold`, or `threshold` is below `min_threshold` |
| `NodeListRollback` | a version below its floor or your last accepted one, the same version with different bytes, or a `keysVersion` above the key list's version |
| `NodeListExpired` / `NodeListNotYetValid` / `NodeListStale` | `now` at or after `expires`; `issued` more than 300 s ahead; `issued` older than `max_age` |
| `NodeListEnvironmentMissing` | the verified list has no node for the requested environment |
