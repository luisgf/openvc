# ISO mdoc (`mso_mdoc`)

Server-side **verification** of an OpenID4VP-delivered ISO 18013-5 `mso_mdoc`
(*experimental*) — read-only IssuerAuth (a `COSE_Sign1` MSO with an `x5chain` → IACA
anchor and `valueDigests`) plus DeviceAuth over the W3C Digital Credentials API
SessionTranscript. The COSE/CBOR is hand-rolled, so this adds no runtime dependency.
Engagement, proximity, issuance and COSE *signing* stay out of scope
([ADR-0005](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0005-mso-mdoc-verification.md)).

## mdoc verification

::: openvc.mdoc

## COSE (`COSE_Sign1` / `COSE_Mac0`)

::: openvc.cose
