# OpenID4VP presentation verification

A stateless, read/verify-only verifier for an OpenID4VP 1.0 `vp_token`: validate the
response shape, route each Presentation to the matching suite, and enforce the holder
binding (the request `nonce` and the full, prefixed `client_id`).

::: openvc.openid4vp

## JWE decrypt (HAIP `direct_post.jwt` responses)

Decrypt the JWE that wraps a `vp_token` in a HAIP encrypted response (direct
`ECDH-ES` + `A128GCM`/`A256GCM` on P-256), then feed the plaintext to the verifier
above. The recipient key-agreement backend lives in [`openvc.keys`](dids-keys.md)
(`KeyAgreementKey` / `P256KeyAgreementKey`).

::: openvc.jwe
