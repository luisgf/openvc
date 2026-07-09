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
  the `[trustlist]` XAdES verifier accepts the mandated **XAdES-BASELINE-B** signatures.
- **Hardened XML** — stdlib parsing with DTD/DOCTYPE rejected (no XXE, no
  entity-expansion bombs), size-bounded input; XAdES verification lives behind
  the `[trustlist]` extra (`signxml`) and pins the signer to the certs the
  parent list vouched for.

Design rationale: [ADR-0003](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0003-eu-trusted-lists.md).

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
  Never resolve `did:web` through it — `did:web` has its own guarded fetch
  (see [Resolving issuer keys](Resolving-Issuer-Keys)).
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
