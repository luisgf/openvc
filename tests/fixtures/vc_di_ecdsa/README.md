Official W3C `ecdsa-rdfc-2019` test vectors, taken verbatim from the vc-di-ecdsa
Recommendation's TestVectors directory
(https://github.com/w3c/vc-di-ecdsa/tree/main/TestVectors), captured 2026-07-07
from commit `00781de52c036723bbd88d89b07818a2914a6b9e`:

- `rdfc-2019-p256/` — TestVectors/ecdsa-rdfc-2019-p256/ (P-256 / SHA-256)
- `rdfc-2019-p384/` — TestVectors/ecdsa-rdfc-2019-p384/ (P-384 / SHA-384)

and within each:

- `signedECDSA{P256,P384}.json`      — the signed credential (proof + `proofValue`)
- `proofConfigECDSA{P256,P384}.json` — the proof options (proof without `proofValue`)
- `docHashECDSA{P256,P384}.txt`      — SHA-256/384 of the canonical unsecured document
- `proofHashECDSA{P256,P384}.txt`    — SHA-256/384 of the canonical proof config
- `combinedHashECDSA{P256,P384}.txt` — `hashData` = proofConfigHash ‖ documentHash

The `@context` these credentials name is the W3C `credentials/examples/v2` term set,
reused from `../vc_di_eddsa/credentials-examples-v2.json` and injected into tests via
`extra_contexts` (deliberately NOT part of the library's bundled allow-list, which
ships only the stable VC 2.0 context — examples stay test-only).

ECDSA signing is randomised, so — unlike the byte-for-byte `eddsa-rdfc-2022` pin —
`test_di_ecdsa_rdfc.py` shows interop the way the `ecdsa-sd-2023` suite does: it
reproduces each vector's intermediate `hashData` and *verifies* the published
`proofValue` end to end (resolving the `did:key`), rather than re-signing byte for byte.
