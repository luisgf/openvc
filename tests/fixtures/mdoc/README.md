# mdoc fixtures — ISO/IEC 18013-5 Annex D golden vector

The **real** ISO/IEC 18013-5:2021 **Annex D** worked example (the "utopia" mDL), used as
the byte-exact golden vector for `mso_mdoc` **issuer data authentication** conformance
(`tests/test_mdoc.py`) — the project's drift-alarm discipline (recorded real vectors, not
synthetic shapes; ADR-0005 D8).

## Files

- `annex_d_device_response.hex` — the full `DeviceResponse` CBOR (3562 bytes), hex.
  `docType` `org.iso.18013.5.1.mDL`; namespace `org.iso.18013.5.1` with 6 disclosed
  `IssuerSignedItem`s (family_name=Doe, issue_date, expiry_date, document_number=123456789,
  portrait, driving_privileges); `IssuerAuth` is a `COSE_Sign1` with protected `{1: -7}`
  (**ES256**); MSO `digestAlgorithm` **SHA-256**; validity 2020-10-01 … 2021-10-01. Its
  `DeviceAuth` is a proximity **DeviceMac** (out of scope for the online verifier), so the
  vector exercises `verify_issuer_signed` (issuer seal), not device authentication.
- `annex_d_iaca_root.pem` — the IACA root (`CN=utopia iaca`), the trust anchor.
- `annex_d_document_signer.pem` — the document-signer leaf (`CN=utopia ds`); also carried
  in the DeviceResponse `x5chain`, kept here for reference.

## Provenance

- **DeviceResponse** — `openwallet-foundation/multipaz` (formerly Google's
  `identity-credential`), `multipaz/src/commonTest/kotlin/org/multipaz/mdoc/TestVectors.kt`,
  constant `ISO_18013_5_ANNEX_D_DEVICE_RESPONSE`. Reproduced identically across multipaz,
  walt.id, a-sit-plus/vck, nl-wallet and sphereon.
- **IACA root** — `MinBZK/nl-wallet`, `wallet_core/lib/crypto/src/examples.rs`
  (`iaca_trust_anchors()`); multipaz ships only the DS leaf, so the root is sourced from a
  second repo. The join is proven **cryptographically**, not by trust: the DS certificate's
  signature verifies under this IACA, `DS.AKI == IACA.SKI`, and the IACA's static device key
  equals the MSO `deviceKey` — the same Annex D "utopia" PKI.

Both are public ISO 18013-5 Annex D static test data (a fixed PKI and a fixed mDL), not
production credentials.
