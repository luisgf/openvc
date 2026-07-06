# openvc roadmap

Distilled from `SESSION-HANDOFF.md`, re-scoped for the independent `openvc`
project (Open Badges / image-baking items stay in the downstream badge library,
not here).

## Done

- Core proof suite (`VcJwtProofSuite`), key backends (`Ed25519SigningKey`,
  `P256SigningKey`), DID resolution (`did:key`, `did:web`), the DID document
  model + registry.
- EBSI plugin: versioned DID Registry / TIR adapters, the HTTP client (TTL cache,
  retries, SSRF allow-list), the version-agnostic domain model.
- **SSRF-guarded stdlib https fetch** for `did:web` (`openvc.fetch`) — https-only,
  blocks private/loopback/link-local/reserved ranges, refuses redirects.
- **`verify_ebsi_badge`** glue — peek → resolve → key select → signature/temporal
  verify → issuer trust over the TIR accreditations.
- **Recursive trust chain** (`openvc_ebsi.trust`) — walk `TI → TAO → RootTAO`,
  verifying every accreditation's signature against the accreditor's resolved
  key, up to a caller-supplied trusted RootTAO anchor. Wired into
  `verify_ebsi_badge` via `trust_anchors`. Enforces **per-hop delegation
  scoping** (each accreditor's `accreditedFor` must be a superset of the
  delegated scope) and, with a `resolve_status_list`, **status-list revocation of
  the accreditations** themselves (a revoked accreditation breaks the chain).
- **Status-list revocation** (`openvc.status`) — W3C Bitstring Status List bit
  codec (gzip + base64url, MSB-first) + `credentialStatus` parsing +
  `check_credential_status`. Wired into `verify_ebsi_badge` via
  `resolve_status_list` (a set revocation bit raises `CredentialRevoked`).
- **DNS-rebinding-safe `did:web` fetch** — the connection is pinned to the
  validated IP (resolve → validate → connect to that IP) while TLS SNI, cert
  validation and Host use the hostname, closing the TOCTOU window.
- **Data Integrity proof suite** (`openvc.proof.data_integrity`) —
  eddsa-rdfc-2022 embedded proofs (RDF canonicalization via pyld, offline
  bundled contexts), the second profile alongside VC-JWT. Verified byte-for-byte
  against the official W3C vc-di-eddsa test vector.
- **IETF Token Status List** (`openvc.status.token_status_list`) — the second
  status encoding behind the same `openvc.status` interface: 1/2/4/8-bit
  LSB-first statuses with DEFLATE/zlib, `status`-claim reference parsing, and
  `check_token_status` (VALID / INVALID → revoked / SUSPENDED → suspended).
- **SD-JWT VC** (`openvc.proof.sd_jwt`) — the third proof profile (EUDI/ARF's
  format): `SdJwtVcProofSuite` issuance (disclosures + `_sd` digests, decoys,
  `cnf` binding), holder Key Binding JWT presentation, and verification with
  recursive nested/array unpacking and the selective-disclosure defences.
- **Recorded golden EBSI fixtures** — real pilot DID Registry v5 + TIR v5
  responses recorded verbatim (`tests/fixtures/ebsi/`) drive the adapter tests,
  and a recorded accreditation's ES256 signature verifies against the recorded
  DID document. Recording them caught (and fixed) a `406` content-negotiation bug
  and a wrong TIR v5 `attribute.body` mapping.
- **CI hardening** — a coverage gate (`--cov-fail-under=80`), a scheduled
  live-EBSI drift alarm (`.github/workflows/live-ebsi.yml`), Dependabot (pip +
  actions), and Node-24 action versions. Published to PyPI as `openvc-core`.
- **ecdsa-sd-2023 selective disclosure** (`openvc.proof.ecdsa_sd`) — the P-256
  Data Integrity cryptosuite with selective disclosure: issuer base proof →
  holder derived proof (reveal chosen JSON pointers) → verify, with HMAC-blinded
  blank nodes and a hand-rolled CBOR proof value (checked against RFC 8949).
  Round-trip + tamper/over-disclosure tested, and **interop-validated against the
  official W3C `vc-di-ecdsa` vectors** (`tests/fixtures/ecdsa_sd/`): `verify`
  accepts reference-produced derived proofs, and our issuer-side canonical N-Quads
  and `proofHash`/`mandatoryHash` match the recorded intermediates byte for byte.
- **Downstream OB 3.0 consumer** — `openbadgeslib` consumes `openvc-core` from
  PyPI in its own repository. That work (Open Badges models, image baking, and
  the API feedback that hardens the core toward 1.0) is tracked there, not here.
- **Data Integrity validity + purpose enforcement** (`openvc.proof`) — the two
  Data Integrity suites verified only the signature; `verify()` now also enforces
  the credential's validity window (`validFrom`/`validUntil`,
  `issuanceDate`/`expirationDate`, proof `expires`, with configurable leeway and a
  `now` pin) and `proofPurpose`, and binds the key to the DID document's
  verification relationship. An injectable `resolver=` makes `did:web` work with
  embedded proofs. Shared checks live in `openvc.proof._verify_common`; a
  present-but-unparseable timestamp fails **closed**.
- **Status-list issuance** (`openvc.status`) — the issuer-side counterpart to the
  existing check side: `build_status_list_credential` (unsigned W3C Bitstring VC),
  `build_status_list_token` / `verify_status_list_token` (IETF `statuslist+jwt`),
  the `build_status_list_entry` / `build_token_status_reference` pointers, and
  `new_bitstring`. A generic compact-JWS signer (`openvc.proof._jws`) was lifted
  out of `VcJwtProofSuite.sign` so a non-VC token signs through the same
  allow-listed path.
- **Generic verification pipeline** (`openvc.verify`) — one `verify_credential(...)`
  + `VerificationPolicy` that detects the format (VC-JWT / SD-JWT VC / Data
  Integrity / enveloped VCDM 2.0), resolves the issuer key via a registry, verifies
  through the matching suite, and applies status/type/purpose policy — the one-call
  verifier and the surface to stabilise toward 1.0. Status is fail-closed and checks
  both the W3C and IETF conventions for every format; Data Integrity binds the
  proof key to the issuer DID. The EBSI glue is a specialisation of it.
- **EUDI issuer-key discovery** — `did:jwk` (`openvc.did.did_jwk`), SD-JWT VC issuer
  keys via `/.well-known/jwt-vc-issuer` (`openvc.jwt_vc_issuer`, anti-substitution +
  SSRF-guarded fetch), and X.509 `x5c` chain trust (`openvc.x5c`, path validation +
  SAN issuer binding, EC P-256 leaf). The last two are opt-in in the pipeline.
  *(Raised the `cryptography` floor to `>=45`.)*
- **W3C Verifiable Presentations** — **VP-JWT** (`openvc.proof.vp_jwt`): a holder
  signs a `vp` bound to a verifier (`aud`) and challenge (`nonce`), and verify
  cascade-verifies each embedded credential through the pipeline, with opt-in
  holder binding — plus **`challenge`/`domain`** on Data Integrity
  (`authentication` proofs).
- **Library-wide `OpenvcError` root** (`openvc.errors`) — one base above every
  error family, so `except OpenvcError` catches any openvc failure (additive; the
  per-area roots are unchanged).
- **`credentialSchema` validation (W3C VC JSON Schema)** (`openvc.schema`) — the
  pipeline validates a credential against the `JsonSchema` it declares when the
  caller opts in with `resolve_credential_schema=` (a mismatch raises
  `SchemaValidationError`); `policy.require_schema` makes a declared-but-unchecked
  schema fail-closed. The `jsonschema` processor is the optional `[schema]` extra.
  Remote `$ref` is off and `JsonSchemaCredential` is not yet validated (raises
  `UnsupportedSchemaType`).

## Next

The queued proof / status / EBSI / interop / presentation work is done and the
downstream consumer lives in its own repository. What remains is demand-driven:

1. **ecdsa-sd-2023 P-384** and further cryptosuites, if demand appears.

## Deliberately out of scope

- EBSI **write/onboarding** (JSON-RPC + OID4VP presentation tokens): this is a
  verifier/issuer library, not a node operator.
- **Open Badges** models and **image baking**: those belong in the downstream
  badge library that consumes `openvc`.
