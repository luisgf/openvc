Official W3C `eddsa-rdfc-2022` test vectors, taken verbatim from the vc-di-eddsa
Recommendation's TestVectors directory
(https://github.com/w3c/vc-di-eddsa/tree/main/TestVectors), captured 2026-07-05:

- `signedDataInt.json`      — TestVectors/eddsa-rdfc-2022/signedDataInt.json
- `keyPair.json`            — TestVectors/keyPair.json (Ed25519, multibase)
- `docHashDataInt.txt`      — TestVectors/eddsa-rdfc-2022/docHashDataInt.txt
- `proofHashDataInt.txt`    — TestVectors/eddsa-rdfc-2022/proofHashDataInt.txt

`credentials-examples-v2.json` is the https://www.w3.org/ns/credentials/examples/v2
context the vector's `@context` names. It is injected into tests via
`extra_contexts` and is deliberately NOT part of the library's bundled allow-list
(that ships only the stable VC 2.0 context; examples are test-only).

`test_data_integrity.py` asserts the implementation reproduces this vector's
intermediate hashes and its `proofValue` byte for byte.
