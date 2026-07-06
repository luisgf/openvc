# Credential schema

Opt-in `credentialSchema` (W3C VC JSON Schema) validation for the verification
pipeline: fetch the JSON Schema a credential declares and validate the whole
credential against it. Wired into
[`verify_credential`](verification.md) via `resolve_credential_schema=`.

::: openvc.schema
