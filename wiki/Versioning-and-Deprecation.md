# Versioning & deprecation policy

openvc follows [Semantic Versioning](https://semver.org). This page is the contract:
what "stable" covers, and how change is signalled. It has been in full effect
since **1.0.0** (during `0.x`, minor versions could break — each break was
called out in the [CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md)).

## What a version bump means

Given a released `MAJOR.MINOR.PATCH`:

- **MAJOR** — a backwards-incompatible change to the stable public API (a name
  removed/renamed, a signature or return-object field changed incompatibly, a
  default that changes a security decision).
- **MINOR** — backwards-compatible additions (a new function, a new module, a new
  optional parameter, a new *defaulted* field on a result/policy dataclass).
- **PATCH** — backwards-compatible bug and security fixes with no API change.

## What the guarantee covers

The **stable public API** is every name in a public module's `__all__`, reached from
its documented import path (see *Public surface & stability* in
[CONVENTIONS](https://github.com/luisgf/openvc/blob/main/docs/CONVENTIONS.md)).
Concretely:

- the package-root re-exports (`from openvc import verify_credential, …`);
- every non-underscore module and the names in its `__all__`;
- the **return-object contract** — the fields of `VerificationResult`,
  `VerificationPolicy` and the per-suite `Verified*` dataclasses, which are
  **add-only** (a field may be added with a default; never removed, renamed or
  reordered without a MAJOR bump). `tests/test_return_contract.py` pins them.

**Not** covered (may change in any release, no deprecation cycle): any
leading-underscore module or name (`openvc.proof._verify_common`,
`openvc.status._decompress`, every `_name`), and behaviour explicitly documented as
unspecified.

## Deprecation policy

A stable name is not removed abruptly. To remove or rename one:

1. The old name keeps working for **at least one MINOR release**, emitting a
   `DeprecationWarning` that names the replacement.
2. The deprecation is recorded under **Deprecated** in the [CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md),
   with the replacement and the earliest version that may remove it.
3. Removal happens only in a subsequent **MAJOR** release, noted under **Removed**.

Currently deprecated (removable at the next MAJOR): the verb-last
`openvc.proof.ecdsa_sd` codec aliases — `cbor_encode`/`cbor_decode`,
`serialize_base_proof`/`parse_base_proof`,
`serialize_derived_proof`/`parse_derived_proof` — each warns and forwards to its
verb-first replacement (`encode_cbor`/`decode_cbor`, `encode_base_proof`/…).

## Algorithm names (RFC 9864)

[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) (Oct 2025) marks the polymorphic
`EdDSA` **Deprecated** in the IANA JOSE registry and introduces the fully-specified
name `Ed25519` for the same Ed25519 signature. openvc tracks this without breaking
anyone:

- **Verify accepts both.** `Ed25519` joined the `{ES256, ES384, EdDSA}` allow-list
  (so it is now `{ES256, ES384, EdDSA, Ed25519}`); a token with `alg: Ed25519`
  verifies exactly like an `EdDSA` one across VC-JWT, SD-JWT VC and the status-list
  token. RS\*/HS\*/`alg:none` stay rejected before any crypto.
- **Signing still emits `EdDSA` by default** — no wire change unless you ask for it.
  Opt into the fully-specified name per key: `Ed25519SigningKey.generate(kid,
  alg="Ed25519")` (also on `.from_jwk` / `.from_pem`).
- **`ES256`/`ES384` are not deprecated**, so their fully-specified `ESP256`/`ESP384`
  names are **not** accepted yet — deferred until forward-looking signers actually
  emit them, to keep the allow-list narrow (the EBSI/EUDI world is ES256-centric).
