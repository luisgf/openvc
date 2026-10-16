# EBSI Core API v1 fixtures (recorded)

Real responses of the **EBSI Core API v1** (`/v1/...`), recorded once on 2026-10-16 for
[#321](https://github.com/luisgf/openvc/issues/321) (design:
[ADR-0009](../../../../docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)). They are the
drift alarm for `DidRegistryCoreV1` and `TirCoreV1` in `src/openvc_ebsi/versioning.py`, the
way `../*.json` is for the legacy pilot (v5) lane. Nothing here is hand-written or edited:
ids, hrefs and host names are part of the evidence, and a different node answers with its own
host in every link.

`MANIFEST.json` lists, per file, the request URL (query included), the HTTP status, the
`Content-Type` the node sent, the node host name, the retrieval time (UTC), the
`User-Agent` and `Accept` sent, the size and the SHA-256. `tests/test_ebsi_core_v1.py` hashes
every file in this directory against it, so an edit, a re-encode or a stray file fails the
suite. The only two files not listed in the manifest are the manifest itself and this README.

## How they were recorded

- **Plain read-only GETs**: no credentials, no cookies, no `POST`, no redirects followed,
  TLS verification on, one request at a time with a pause of about 0.6 s between them (the
  documented limit is 20 requests per second per client IP).
- **The client's own request headers**: `User-Agent: openvc-core/1.36.0` and
  `Accept: application/json, application/did+ld+json, */*;q=0.1`, which is what
  `EbsiHttpClient` sends (ADR-0009 measured a node's firewall refusing curl's default
  `User-Agent`). Two files override `Accept` on purpose: `negotiation/` (`application/did+json`)
  and `errors/preprod-grnet_406_*` (`application/xml`, which no DID Registry route accepts).
- **Bodies are written exactly as received** (after HTTP transfer decoding), with no
  pretty-printing and no trailing newline added. The recorder was a scratch script that is not
  part of the repository, as the ADR's probe scripts are not.
- **24 requests to EBSI hosts in total.** Three attempts to read the OpenAPI contract
  (`website/api/core/openapi.yaml`, `gitlab.com`, not an EBSI host: the raw file, then the GitLab
  API twice) were all answered `503` and were not tried again; see "Not recorded".

## What is in each directory

| Directory | Node | Content |
|---|---|---|
| `preprod-grnet/` | `api-preprod.ebsi.grnet.gr` | for `did:ebsi:zmaEptEHQRAmkJnFV6ki3io` (the preprod RootTAO): the DID document (a `secp256k1` and a `P-256` key), the issuer record, the attribute list and attribute `0dc6a111...`; plus the first page of the issuers list (evidence only, no adapter reads it) |
| `preprod-incm/` | `api-preprod.ebsi.incm.pt` | the same five reads from a second node, to show which fields are host-free and which carry the answering node's own host |
| `prod-iti/` | `api.ebsi.iti.gr` | **a seed snapshot, shape only**: the one issuer the production environment held that day (`did:ebsi:z262SoSjWAqmXpaGmzqGnJoc`), whose DID document has an empty `verificationMethod`; replace it when real operators onboard |
| `negotiation/` | `api-preprod.ebsi.grnet.gr` | the preprod DID document with `Accept: application/did+json` (the form without `@context`), next to the `application/did+ld+json` one in `preprod-grnet/` |
| `errors/` | a pilot node and a preprod node | a `404` (`urn:ebsi:problems:identifier-not-found`), a `400` for a contract address with no contract behind it, and a `406` for an unsatisfiable `Accept`; all `application/problem+json` |
| `contract-address/` | `api-preprod.ebsi.grnet.gr` | the two registries' `/details` (where each registry's `contractAddress` is published), and one walk (DID document, issuer, attribute list, attribute) requested **with** a valid `contractAddress`, to be compared byte-for-byte with the walk without it |

## What the recording showed (and the tests pin)

- The DID document, issuer, attribute list and attribute keep the legacy v5 shapes; the attribute
  carries one field the legacy recording lacks, `parentAttributeId` (all zeros on a RootTAO).
- The list item `id` is **not** the attribute's `hash` (`0dc6a111...` against `a1c4d9e9...` here,
  `030c5a3d...` against `02476d49...` on the prod seed).
- `self`, `links.*`, `attributes` and every `href` carry the host of the node that answered
  (`api-preprod.ebsi.grnet.gr` against `api-preprod.ebsi.incm.pt`). With the host replaced, the
  two nodes' bodies are equal; the issuers list and attribute list differ only by that host.
- Error bodies are RFC 9457 Problem Details with `Content-Type: application/problem+json`. The
  `406` body's `type` is `about:blank`, not a `urn:ebsi:problems:` slug: do not expect a slug on
  every error.
- **`contractAddress` is not echoed.** The DID document, issuer, attribute list and attribute read
  with a valid address are byte-identical to the ones read without it: `self`, `links`, `attributes`
  and `href` never carry the query. The two registries have **different** addresses
  (`/did-registry/details` and `/issuers-registry/details`). Every address in the two `/details`
  bodies is `0x` followed by 40 hexadecimal digits.
- The preprod and prod RootTAO accreditation JWTs (`attribute.body`) are signed `ES256K`
  (`alg` in the protected header), which the DEFAULT JOSE allow-list refuses (only
  `VcJwtProofSuite(allow_es256k=True)` verifies them, #323); the key named by `kid` is the
  DID document's `secp256k1` method.
- The `credentialSchema.id` and `accreditedFor[].schemaId` hosts inside the JWTs
  (`api-test.ebsi.eu`, `api-prod.ebsi.eu`) are in no node list; no test fetches them.

## Not recorded

- **`405`.** It needs a non-GET request to a read path, which neither the library nor the ADR's
  probes sent, so it is not recorded here and no fixture stands in for it. The client treats it like
  any other non-retryable status; the test that exercises it builds a Problem Details body by hand
  and says so.
- **The OpenAPI contract** (`website/api/core/openapi.yaml`) could not be read (see above), so the
  `contractAddress` format used by the adapters comes from the values the nodes themselves publish,
  not from the contract.
- Revisions (`/attributes/{id}/revisions`), `valid-at`, the full issuers list and `/alive` are out of
  scope for #321.

## Re-recording

Do not edit a file here. To refresh a vector, record it again with the same headers, replace the file
and its `MANIFEST.json` entry together (request URL, status, media type, node, retrieval time and
SHA-256), and say in the commit why. A recorded body that changes under the same request is itself a
finding: it is the drift this directory exists to catch.
