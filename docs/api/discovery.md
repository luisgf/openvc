# Issuer-key discovery

Beyond DIDs, an issuer key can be discovered from an https URL or an X.509 chain.

## `/.well-known/jwt-vc-issuer`

::: openvc.jwt_vc_issuer

## X.509 `x5c`

::: openvc.x5c

## EUDI relying-party certificates (WRPAC)

Parse an EUDI relying-party access certificate (ETSI TS 119 475) to read its
registered entitlements — verify-side only.

::: openvc.rp_cert
