# Credential schema validation

A credential can declare a `credentialSchema` — a JSON Schema its shape must satisfy.
openvc validates it as an **opt-in** verification step behind the `[schema]` extra
(`pip install "openvc-core[schema]"`, which pulls `jsonschema`). It is a data-shape
check, not a revocation gate, so it runs only when you wire a resolver.

<!-- docs: no-run -->
```python
from openvc import verify_credential, VerificationPolicy
from openvc.resolvers import default_credential_schema_resolver
from openvc.fetch import https_bytes_fetch

result = verify_credential(
    credential,
    policy=VerificationPolicy(require_schema=True),   # reject a declared-but-unchecked schema
    resolve_credential_schema=default_credential_schema_resolver(https_bytes_fetch),
)
print(result.schema)   # the SchemaValidationResult
```

`require_schema=True` is symmetric with `require_status`: a credential that *declares*
a schema but is verified without a resolver fails closed. Every sub-step is
fail-closed too — an unreachable schema, a resource that is not a valid JSON Schema, a
resource without `$schema` (which the spec says MUST NOT be processed), or an
unsupported type all raise. Remote `$ref` resolution is **off** (a non-fetching
registry is wired), so a hostile `$ref` cannot turn schema validation into an SSRF.

## The two schema types

- **`JsonSchema`** — the `credentialSchema.id` points at a plain JSON Schema document;
  the whole credential is validated against it.
- **`JsonSchemaCredential`** — the schema a credential points at is *itself a signed
  Verifiable Credential*. openvc fetches that VC, **verifies its proof through the same
  `verify_credential` path** (so every DID / `x5c` / status resolver you wired applies
  to it too, fail-closed), and applies the JSON Schema nested in its verified
  `credentialSubject.jsonSchema` to the outer credential. It is bounded and
  fail-closed: the schema-defining VC's own `credentialSchema` (the meta-schema) is not
  re-fetched, so a hostile chain of schema-VCs cannot loop; the inner VC must actually
  carry the `JsonSchemaCredential` type, so a signature-valid but wrong-typed VC cannot
  stand in as the schema authority; and any inner-proof failure surfaces as a typed
  `SchemaResolutionError`.

## Pinning the schema (`digestSRI`)

When a `credentialSchema` entry carries a `digestSRI` (a `sha256-` / `sha384-` /
`sha512-` subresource-integrity hash), openvc verifies it over the **raw** fetched
bytes — constant-time, strongest algorithm wins — **before** the schema is parsed. An
issuer can thus pin the exact schema so even a compromised schema host cannot swap it;
a mismatch fails closed. The same check backs the `JsonSchemaCredential` fetch.

Schemas are untrusted input: a JSON Schema `pattern` keyword runs on Python's
backtracking regex engine, so point `resolve_credential_schema` at hosts you trust
(documented in `openvc.schema`). The standalone entry point is
`openvc.schema.validate_credential_schema(…, verify_inner=…)`.
