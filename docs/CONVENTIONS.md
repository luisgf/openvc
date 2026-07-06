# openvc — API naming conventions

The public surface of `openvc` follows a small set of naming patterns so it stays
predictable: given a name you should be able to guess what a thing is and what it
does. New code must follow the rules below; the **Known deviations** at the end are
grandfathered and tracked for normalisation toward 1.0.

This is the naming contract. For the architecture invariant (core imports nothing
upward) and the commit convention, see
[`CONTRIBUTING.md`](https://github.com/luisgf/openvc/blob/main/CONTRIBUTING.md).

## Casing (PEP 8)

- Classes and type aliases: `PascalCase` (`VcJwtProofSuite`, `ResolveStatusList`).
- Functions, methods, variables, parameters: `snake_case`.
- Constants: `UPPER_SNAKE` (`ALLOWED_ALGS`, `DEFAULT_LEEWAY_S`, `STATUS_VALID`).
- Private/internal: a single leading underscore (`_verify_common`, `_parse_ts`).

## Classes — role by suffix/prefix

| Role | Pattern | Examples |
|---|---|---|
| Proof suite (sign/verify a format) | `*ProofSuite` | `VcJwtProofSuite`, `DataIntegrityProofSuite`, `EcdsaSdProofSuite`, `SdJwtVcProofSuite` |
| DID resolver / registry | `Did*Resolver`, `*Registry` | `DidKeyResolver`, `DidWebResolver`, `DidEbsiResolver`, `DidResolverRegistry` |
| Private-key handle | `*SigningKey` | `Ed25519SigningKey`, `P256SigningKey`, `SigningKey` (Protocol) |
| Version adapter (anti-corruption) | `*Adapter` (ABC) + `*V<N>` (concrete) | `DidRegistryAdapter` → `DidRegistryV5`; `TirAdapter` → `TirV4`/`TirV5` |
| Result of a successful `verify()` | `Verified*` | `VerifiedCredential`, `VerifiedDataIntegrity`, `VerifiedSdCredential`, `VerifiedSdJwt`, `VerifiedEbsiBadge` |
| Immutable value object (`@dataclass(frozen=True)`) | `*Result` / `*Entry` / `*Ref` / `*Record` / domain noun | `StatusResult`, `StatusEntryResult`, `TokenStatusRef`, `IssuerRecord`, `TrustHop` |
| Protocol (structural interface) | named for the role, **no** `Protocol` suffix | `SigningKey`, `DidResolver` |
| Callable type alias | `PascalCase`, `Resolve*` for resolver callbacks | `ResolveStatusList`, `ResolveStatusListToken` |

## Functions & methods — verb first

A public function or method starts with a verb naming what it does. The verb
families in use (prefer these before inventing a new one):

| Verb | Meaning | Examples |
|---|---|---|
| `build_*` | construct and return an artifact (dict/token) | `build_status_list_credential`, `build_status_list_token`, `build_status_list_entry` |
| `check_*` | evaluate and **return** a result (does not raise on a "bad" state) | `check_credential_status`, `check_token_status`, `check_validity_window` |
| `verify_*` | verify and **raise** on failure | `verify_signature`, `verify_status_list_token`, `verify_ebsi_badge`, `verify_trust_chain` |
| `parse_*` | turn wire input into typed objects | `parse_did_document`, `parse_status_entries`, `parse_token_status_ref` |
| `encode_*` / `decode_*` | a codec pair (verb **first**) | `encode_bitstring` / `decode_bitstring`, `encode_status_list` / `decode_status_list` |
| `get_*` / `set_*` | read/write an element | `get_status_bit` / `set_status_bit`, `get_status` / `set_status` |
| `new_*` | allocate a zeroed container | `new_bitstring`, `new_status_list` |
| `resolve_*` | look something up (possibly out-of-process) | `resolve_verification_key` |
| `peek_*` | read a token **without verifying** — the result is UNTRUSTED | `peek_issuer`, `peek_claims` |
| `from_*` / `*_from_*` | alternative constructor | `SigningKey.from_jwk`, `from_pem`, `signing_key_from_jwk` |
| `is_*` | boolean predicate | `Accreditation.is_revoked` |
| `<src>_to_<dst>` | pure conversion | `p256_multikey_to_jwk` |

`peek_*` is a load-bearing convention: it marks the "inspect before you trust"
step (read `iss`/`kid` to decide which key to fetch) and its output must never
drive a trust decision.

## Errors

- **One root error per module**, subclassing `Exception` (or a shared family root):
  `DidError`, `StatusListError`, `KeyBackendError`, `MultibaseError`,
  `DocumentLoaderError`, and — shared across every proof suite — `ProofError`.
- **Leaf errors describe the failure condition** as a noun phrase, not always with
  an `*Error` suffix: `SignatureInvalid`, `CredentialExpired`,
  `CredentialNotYetValid`, `MalformedToken`, `ProofPurposeMismatch`,
  `AccreditationRevoked`.
- A caller can always catch a whole family by its root (`except ProofError`,
  `except DidError`).

## Constants for wire values

Protocol string/int literals are module constants, not inline strings:
`CRYPTOSUITE`, `PROOF_TYPE`, `STATUS_LIST_JWT_TYP`, `STATUS_VALID` /
`STATUS_INVALID` / `STATUS_SUSPENDED`, `PURPOSE_REVOCATION`.

## Known deviations (grandfathered)

Real inconsistencies in the current surface. New code should follow the rules
above, not these; they are tracked for normalisation toward 1.0.

1. **Issuance verb differs per suite** — producing a secured credential is `sign`
   (VC-JWT), `add_proof` / `add_base_proof` (Data Integrity / ecdsa-sd) and
   `issue` (SD-JWT). Partly justified by each format's idiom, but it is three
   names for one conceptual operation.
2. **A codec pair is verb-last** — `cbor_encode` / `cbor_decode` in
   `proof/ecdsa_sd` break the verb-first `encode_*` / `decode_*` rule; the
   proof-value codec also uses the asymmetric `serialize_*` / `parse_*`.
3. **`build_*` vs `make_*`** — status issuance uses `build_*`; SD-JWT disclosure
   construction uses `make_object_disclosure` / `make_array_disclosure`.
4. **Some factories are noun-first** — `did_registry_adapter`, `tir_adapter`,
   `default_did_web_resolver`, `document_loader`, `bundled_contexts`, `for_ebsi`
   read as noun accessors rather than `build_*` / `make_*`.
5. **Leaf-error suffix is mixed** — `Unsupported*` (`UnsupportedAlgorithm`,
   `UnsupportedCryptosuite`, `UnsupportedDidMethod`) coexists with `*Error`
   (`KeyResolutionError`, `DidResolutionError`, `UnsafeUrlError`).
6. **Error class names are duplicated across modules** — `SignatureInvalid`,
   `ProofMalformed` and `UnsupportedCryptosuite` are each defined separately in
   `vc_jwt`, `data_integrity` and `ecdsa_sd`. They share the `ProofError` base, so
   `except ProofError` catches all — but `except data_integrity.SignatureInvalid`
   will **not** catch the `ecdsa_sd` one. Catch by the shared base, or by a
   suite's own class deliberately.
7. **No library-wide root exception** — there is no umbrella `OpenvcError`, and the
   EBSI plugin's families (`EbsiVerificationError`, `TrustChainError`, `HttpError`)
   descend straight from `Exception` with no shared `EbsiError` root (unlike
   `ProofError` in the core).
