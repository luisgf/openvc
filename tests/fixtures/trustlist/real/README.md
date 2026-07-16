# Real (Commission-signed) Trusted List golden fixtures

Recorded **production artifacts**, vendored byte-for-byte so the XAdES verifier is
held to actual eIDAS signatures instead of our own round-trip (issue #114 — the
synthetic fixtures one directory up only prove "we agree with ourselves"; these
proved the point by exposing that the v1.20.0 1-reference pin rejected every real
EU list). Do not edit them: any byte change breaks the signatures by design.

Retrieved **2026-07-16** over plain HTTPS GET:

| file | source | sequence | issued | NextUpdate | sha256 |
|---|---|---|---|---|---|
| `eu-lotl-seq388.xml` | <https://ec.europa.eu/tools/lotl/eu-lotl.xml> | 388 | 2026-05-22 | 2026-11-18 | `c3a48c8cbc8007639e31c0b56f26076290dbd43d37980485a4a937e627cabf73` |
| `es-tl-seq187.xml` | <https://tsl.digital.gob.es/TSL.xml> | 187 | 2026-07-01 | 2026-12-28 | `082281d180f7ad8b608eb2de78fa881e726f91c9a9183922861d50218275c187` |

Both signatures are XAdES-BASELINE, RSA-SHA512 over SHA-512 digests with exclusive
C14N, carrying the two References every real XAdES signature has: the enveloped
document (`URI=""`) and the signature's own qualifying `SignedProperties`.

Signer certificates (`*-signer.pem`) were extracted from each artifact's own
`ds:KeyInfo` **at retrieval time** and pinned separately, so the golden claim is
"the recorded bytes verify under the recorded signer" — tampering with either side
trips the tests:

- `eu-lotl-signer.pem` — `CN=EUROPEAN COMMISSION, O=EUROPEAN COMMISSION, C=LU`
  (DIGIT, qualified organization certificate, LEI `254900ZNYA1FLUQ9U393`),
  serial `0x73c21c494b5510a00c32f1e6f50594d39917b0f5`, valid 2023-11-17 → 2027-11-17.
  Production LOTL trust would come from the OJ-published certificate set
  (2019/C 276/01 + pivots); for the golden fixture the recorded signer is the pin.
- `es-tl-signer.pem` — `CN=SPANISH TRUST SCHEME OPERATOR, O=MINISTRY OF ECONOMIC
  AFFAIRS AND DIGITAL TRANSFORMATION, C=ES`, serial `0xba18458bd4b73d1e`,
  valid 2023-10-31 → 2028-10-29.

The goldens exercise signature verification and parsing only (list expiry is
`walk_lotl`'s clock-dependent concern), so the suite stays offline and
deterministic forever. To refresh after a list rollover: re-fetch the two URLs,
re-extract the `KeyInfo` leaf certs, update this table (sequence, dates, hashes)
and the filenames' sequence numbers.
