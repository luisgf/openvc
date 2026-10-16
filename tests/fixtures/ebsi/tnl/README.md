# Real EBSI Trusted Nodes List (TNL) golden fixtures

Recorded **production artifacts**, vendored byte-for-byte so the TNL verifier
(`openvc_ebsi.nodes`, issue #319, ADR-0009) and its hand-written OpenPGP reader are held to
what Europeum actually signs instead of to our own round-trip (the synthetic chains in
`tests/test_ebsi_tnl_synthetic.py` only prove "we agree with ourselves"). **Do not edit
them:** the signatures cover the exact bytes, so any change breaks the chain by design, and
`tests/test_ebsi_tnl_golden.py` pins the SHA-256 of every file below.

Retrieved **2026-10-16** (HTTP `date` headers 16:06:16 to 16:06:17 GMT) with five plain
HTTPS `GET`s on `tnl.ebsi.eu` (`curl -fsS --proto =https`, no authentication, no
redirects). Every response was `200`, `cache-control: public, max-age=300, must-revalidate`,
and its `ETag` is the SHA-256 of the body.

| file | source | bytes | sha256 |
|---|---|---|---|
| `tnl.json` | <https://tnl.ebsi.eu/tnl.json> | 7068 | `ebff3ba5b210806d1bd0b302222d81e383312b3cdf068525a143d7a2a7d2fcb1` |
| `tnl.json.sig` | <https://tnl.ebsi.eu/tnl.json.sig> | 266 | `1d0438b2c82493786cd026a74db9b6b8f7d6c300b124cab00781ef639c1f7ff5` |
| `trusted-keys.json` | <https://tnl.ebsi.eu/trusted-keys.json> | 1811 | `2e0f5f1bca81acebb602786137021f86a6a41fa4d6bfa40686c7dc37211f22ea` |
| `trusted-keys.json.sig` | <https://tnl.ebsi.eu/trusted-keys.json.sig> | 147 | `db1200d9f8d2cfeb8a47e9960245be3457d47c9ae94de850b61926cc2e2ceff0` |
| `keylist-key.asc` | <https://tnl.ebsi.eu/keylist-key.asc> | 1152 | `a222771cb519abd48df677519caa7c3614219b9a15885c6ca232ad05f65908e5` |
| `tnl.v3.json` | GitLab API, `public/tnl.json` at commit `17f57983f49232a5cd494844f635671c6caa3d25` | 4498 | `62dc15d78416c15093f64314e99a841e00dac3e7e1c5f12e414e794e84e33b60` |
| `tnl.v3.json.sig` | the same commit, `public/tnl.json.sig` | 266 | `d130f29387bb55c4a57a73e17ea532b8f0867127043c5c52c2bdef423d436105` |

## What the live chain says

- `tnl.json`: `version` **4**, `keysVersion` **1**, `issued` `2026-10-06T13:33:18Z`,
  `expires` `2027-01-04T13:33:18Z` (exactly 90.0 days). `pilot` 23, `preprod` 12, `prod` 10
  nodes: 45 in all, none under `*.ebsi.eu`. Nodes are `{url, country, organisation}` objects.
- `trusted-keys.json`: `version` **1**, `threshold` **2**, two custodians (their `fingerprint`
  members and the armored key blocks).
- `tnl.json.sig`: two v4 binary signatures (ECDSA, SHA-256), one per custodian primary key.
  `trusted-keys.json.sig`: one, by the key-list key. Two of the three recorded `s` values
  are above n/2 (a "canonical s" rule would reject real signatures; the verifier has none).
- `keylist-key.asc`: v4 ECDSA over NIST P-256, created `2026-09-30T09:13:54Z`, fingerprint
  **`ACCC82E5FC8902F114929481747CB65CFB7574F9`** (the anchor the wheel ships). The two
  custodian keys were created 2026-09-27 and 2026-09-30.

## The anchor, and how far its pin is checked

The fingerprint was compared, on 2026-10-16, across:

1. the recomputed v4 fingerprint of `keylist-key.asc` (SHA-1 of `0x99`, the length and the
   key packet; `openvc_ebsi._openpgp`), and GnuPG 2.5.24's own value for the same file
   (`IMPORT_OK` status line, scratch keyring);
2. the hashed issuer-fingerprint subpacket of `trusted-keys.json.sig`, which names it;
3. the `README.md` of the public repository
   <https://gitlab.com/europeum/public/trusted-nodes-list> (read at commit `dbc87dbb`),
   which prints it as the value `gpg --show-keys` must show and says Europeum publishes it
   in two places, itself and the EBSI documentation on hub.ebsi.eu;
4. that repository's own copy of `keylist-key.asc`, which is byte-identical to this one.

**This is consistency across Europeum's own channels, not independent authentication.**
ADR-0009 (open question 2) records the same agreement with the hub repository, which was not
re-read here; an out-of-band confirmation from Europeum would be stronger and has not been
sought. Whoever changes the pinned anchor must redo this comparison.

## Cross-check against the public repository

All five live files are `cmp`-identical to `public/` in
<https://gitlab.com/europeum/public/trusted-nodes-list> at commit
`dbc87dbbdac3d9cdaca023db030f6439be7836ed` (`main` on 2026-10-16, "update readme"). The
node list and its signatures were last changed there by the version-4 commits
`becfd98c3ed87c41277a53644a43be74beeadf76` ("build tnl v4") to
`6fb3c055dc0f8d82be7a24ce3eb14011acb3fa3a` ("sign tnl v4"), 2026-10-06, merged by
`4da87e5ee84fe921298c0b8fcc38cdef38ffc3bf`. Both channels are Europeum's.

## The version-3 pair (beyond the live chain)

`tnl.v3.json` and `tnl.v3.json.sig` are the previous list (`version` 3, `keysVersion` 1,
issued `2026-10-05T13:16:59Z`, expires `2026-12-15T13:16:59Z`, 71 days), read from that
repository's history at commit `17f57983f49232a5cd494844f635671c6caa3d25` ("sign tnl v3",
2026-10-05), whose signing commit holds both custodian signatures. It was kept for two
reasons, and it is **not** a rollback vector:

- it is a second set of real signatures, over different bytes, by the same two custodians,
  and the reader verifies them (`verified_signers`);
- its nodes are bare URL strings (`pilot` 23, `preprod` 13, `prod` 10), the shape the hub's
  `tnl.mjs` loader expects, while version 4 switched to `{url, country, organisation}`
  objects. So the schema gate, not a version floor, is what rejects it: a verifier tolerant
  of both shapes, run with `list_floor=1`, would accept it. The test pins that it is
  `NodeListMalformed`.

## Things a maintainer should know before merging

- **Personal data.** The three key blocks (the two custodian blocks inside
  `trusted-keys.json` and `keylist-key.asc`) each hold one OpenPGP User ID packet, **3 in
  all**, each shaped like a name and an e-mail address. They are public, signed by
  Europeum and covered by the signatures, so they cannot be removed without breaking the
  chain. They are deliberately not reproduced here, in any test or in the changelog.
  Replacing the real chain by a synthetic one is a decision for the maintainer.
- **Licence.** The repository declares none (GitLab reports no licence and the tree has no
  licence file; its README states none). The files are public artifacts served for
  clients to verify; their licence is therefore unknown, not permissive.
- **Clock-window trap.** `tnl.json` expires `2027-01-04T13:33:18Z`. Every test injects its
  own `now` inside the window (usually `2026-10-16T12:00:00Z`), so the suite does not go
  red on that day; a test that reads the wall clock would.
- **Refreshing.** Re-fetch the five URLs, re-check the anchor fingerprint above, update this
  table and the digests pinned in `tests/test_ebsi_tnl_golden.py`, and keep the old files
  if a real rollback vector is wanted. Raise `LIST_VERSION_FLOOR` only to a version EBSI has
  published (a floor above the live version is an outage).
