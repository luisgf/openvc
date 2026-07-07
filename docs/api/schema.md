# Credential schema

Opt-in `credentialSchema` (W3C VC JSON Schema) validation for the verification
pipeline: fetch the JSON Schema a credential declares and validate the whole
credential against it. Both W3C schema types are handled — a raw `JsonSchema`, and
a `JsonSchemaCredential` (the schema wrapped in its own signed VC, whose proof is
verified through the pipeline before its embedded schema is applied). Wired into
[`verify_credential`](verification.md) via `resolve_credential_schema=`.

::: openvc.schema

## SD-JWT VC Type Metadata

Resolve the Type Metadata a credential's `vct` points to, pin it with `vct#integrity`
(W3C SRI), walk the `extends` chain, and validate the disclosed claims against the
type's `claims` metadata. Opt-in fetch via
[`openvc.resolvers.default_type_metadata_resolver`](discovery.md).

::: openvc.type_metadata
