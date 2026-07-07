# OpenID4VP presentation verification

A stateless, read/verify-only verifier for an OpenID4VP 1.0 `vp_token`: validate the
response shape, route each Presentation to the matching suite, and enforce the holder
binding (the request `nonce` and the full, prefixed `client_id`).

::: openvc.openid4vp
