# Trusted List fixtures

ETSI TS 119 612 v2.4.1 (**TLv6**) **-shaped** fixtures for `openvc.trustlist` —
**not** the live EU LOTL. They pin the parser and the fail-closed LOTL→TL walk.
Both lists carry `TSLVersionIdentifier = 6` (TLv6, mandatory since 29 Apr 2026).

- `eu-lotl.xml` — a List of Trusted Lists (`TSLType` = `EUlistofthelists`) with two
  `OtherTSLPointer`s: one to the DE national TL (`EUgeneric`, territory `DE`, with
  its signer cert), and one **pivot** pointer to another LOTL (must be skipped by
  the walk).
- `de-tl.xml` — a national TL with one TSP and four services: two `CA/QC` (one
  `granted`, one `withdrawn`, so status selection is testable), one granted `EDS/Q`
  (qualified e-delivery, carrying a TLv6 `ServiceSupplyPoints` element the parser
  must tolerate), and one granted `RemoteQSealCDManagement/Q` — the qualified trust
  services TLv6 national lists actually carry.
- `commission.pem` — the self-signed cert a test pins as the LOTL signer
  (`lotl_signer_certs`). The DE-TL signer and the two CA certs are embedded in the
  XML and recovered by the parser.

All certs are self-signed EC P-256 with a 2026→2099 validity window; the lists'
`NextUpdate` is 2099 so they never expire in tests (expiry is tested by pinning a
future `now`). The **real** XAdES signature is not exercised here — that is the
`[trustlist]` extra's own recorded test (ADR-0003, PR 2). Regenerate from the repo
root with `python tests/fixtures/trustlist/generate.py` if the shape must change.
