# Third-party notices — `tests/fixtures/rp_registration`

The files in this directory are **third-party works**, recorded as test data and used under the
licence of the repository each one comes from. They are not part of openvc's source, are not
installed with the package, and are not covered by openvc's own licence (LGPL-3.0-or-later,
Luis González Fernández). Where each came from, at which commit, and its SHA-256 is in
[`PROVENANCE.md`](PROVENANCE.md). The full licence texts are in [`LICENSES/`](LICENSES/).

| files | work | holder, as the source states it | licence | text |
|---|---|---|---|---|
| `german-sandbox/german-sandbox-wrprc.jwt`, `german-sandbox/german-sandbox-registrar-root.pem` | `SUNET/vc` | "Copyright (c) 2023, Magnus" (repository `LICENSE.md`) | BSD-2-Clause (the repository's licence). **The licence of the token and certificate issued by the German sandbox registrar is not stated.** | [`LICENSES/BSD-2-Clause.SUNET-vc.md`](LICENSES/BSD-2-Clause.SUNET-vc.md) |
| `hopae-dev/wrprc.jwt`, `hopae-dev/wrprc_intermediated.jwt` | `openwallet-foundation-labs/axle` | none named in the licence file (the standard Apache-2.0 appendix); no `NOTICE` file | Apache-2.0 | [`LICENSES/Apache-2.0.axle.txt`](LICENSES/Apache-2.0.axle.txt) |
| `digg/registration_certificate.jwt`, `digg/registration_certificate.jwt.license` | `diggsweden/wallet-ecosystem` | "2026 Digg - Agency for Digital Government" (the sidecar's `SPDX-FileCopyrightText`) | CC0-1.0 (the sidecar's `SPDX-License-Identifier`) | [`LICENSES/CC0-1.0.txt`](LICENSES/CC0-1.0.txt) |
| `eudi-verifier-endpoint/wrprc.jwt` | `eu-digital-identity-wallet/eudi-srv-verifier-endpoint` | "Copyright (c) 2023-2026 European Commission" (the repository's `FileHeader.txt`) | Apache-2.0 | [`LICENSES/Apache-2.0.eudi-srv-verifier-endpoint.txt`](LICENSES/Apache-2.0.eudi-srv-verifier-endpoint.txt) |

Notes:

- **axle:** the repository carried no licence file at the commit the tokens are pinned to
  (2026-07-12); the Apache-2.0 `LICENSE` text vendored here is from the commit that first added
  one (2026-07-14), and the token files are unchanged since. See `PROVENANCE.md`.
- **Apache-2.0 section 4:** the files were not modified (they are signed, so they could not be
  without breaking the signature the tests rely on); no `NOTICE` file exists in either Apache-2.0
  repository to carry forward.
- **BSD-2-Clause:** the licence text is reproduced as the licence requires for redistribution in
  source form.
- The REUSE sidecar `digg/registration_certificate.jwt.license` is vendored with the token it
  describes, as that convention requires.
