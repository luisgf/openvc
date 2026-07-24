# OpenID4VCI key proofs

Verify the key proof a wallet sends to a Credential Endpoint, and get back the public
key it demonstrated possession of — the value
`SdJwtVcProofSuite.issue(holder_jwk=...)` binds the credential to.

Stateless and transport-free: no endpoint, no Authorization Server, no nonce store.
Nonce single-use is injected as a required callable. See
[ADR-0007](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0007-oid4vci-issuer-side.md)
for the boundary and the [Issuing with OpenID4VCI](https://github.com/luisgf/openvc/wiki/Issuing-with-OpenID4VCI)
guide for the flow.

::: openvc.openid4vci
