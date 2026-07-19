# Issuer-key discovery

Beyond DIDs, an issuer key can be discovered from an https URL or an X.509 chain.

## `/.well-known/jwt-vc-issuer`

::: openvc.jwt_vc_issuer

## X.509 `x5c`

::: openvc.x5c

## EUDI relying-party certificates (WRPAC)

Parse an EUDI relying-party access certificate (ETSI TS 119 411-8) to read *who is
asking* — entity identifier, service identifier, trade name — verify-side only.

::: openvc.rp_cert

## EUDI relying-party certificates (WRPRC)

Parse and verify an EUDI relying-party *registration* certificate (ETSI TS 119 475) —
the signed JWT/CWT carrying the registered entitlements and requestable attributes — and
cross-check it against a WRPAC and a presentation request.

::: openvc.rp_registration
