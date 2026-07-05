# ecdsa-sd-2023 interop fixtures

Recorded **verbatim** from the official W3C test vectors at
[`w3c/vc-di-ecdsa`](https://github.com/w3c/vc-di-ecdsa/tree/main/TestVectors/ecdsa-sd-2023)
(`TestVectors/ecdsa-sd-2023/{prc,employ}/`), plus the non-bundled
`https://w3id.org/citizenship/v4rc1` JSON-LD context needed to canonicalize them
offline.

Per example:

- `derivedRevealDocument.json` — a reference-produced **derived (disclosed) proof**;
  `EcdsaSdProofSuite.verify` must accept it (the verifier-side interop check).
- `addSignedSDBase.json` — the reference **base proof** document; our issuer-side
  transform (HMAC-relabeled canonical N-Quads) and `proofHash` / `mandatoryHash`
  must match the recorded intermediates.
- `addBaseDocHMACCanon.json` — the expected HMAC-relabeled canonical N-Quads.
- `addHashData.json` — the expected `proofHash` and `mandatoryHash`.

Why not a byte-for-byte proof-value match (as with the eddsa-rdfc-2022 vector)?
ECDSA signatures are randomised, so a base/derived proof value is not
reproducible. Interop is instead proven by (a) verifying a reference proof and
(b) matching the deterministic intermediates (canonical N-Quads and hashes).
