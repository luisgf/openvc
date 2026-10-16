# Provenance of the WRPRC fixtures

Five signed EUDI Wallet-Relying-Party **registration certificates** (WRPRC, ETSI TS 119 475
V1.2.1 clause 5.2, JWT form), recorded for issue #134 and pinned by
`tests/test_rp_registration_real_artifacts.py`. Every file was retrieved on **2026-10-16** from
the repository and commit named below, at that exact commit, and is vendored **byte-for-byte**
(the trailing newline of the German and Hopae tokens is part of the bytes; the Digg and EU
tokens have none). Nothing here is edited, re-signed, truncated or re-encoded: a recorded
artifact stops being evidence of "what the ecosystem actually sends" the moment we change it, and
the test re-checks every SHA-256 below.

## What this evidence is, and is not

These are **provisional goldens: third-party-signed, NOT registrar-anchored.**

- Each token carries a genuine ES256 signature that verifies against its own `x5c` certificate.
  Each was minted by software this repository did not write.
- **None comes from a Member State production registrar, and none chains to a LoTE anchor.** Each
  is verified in the tests against its **own** root, a certificate pinned by digest (below), which
  proves the signature and the profile parse and nothing about whether a real registrar vouched for
  anyone. The German and Hopae signers are self-signed *CA* certificates that sign directly and are
  also the anchor; the EU sample's signer is a throwaway `CN=test` certificate.
- Issue **#134** asks for one real WRPRC verified end to end against the issuing registrar's
  *published* anchors. That goal is **still open** and waits for a Member State registrar going
  live (CIR (EU) 2025/848 applies 2026-12-24; Art. 8 makes registration certificates optional per
  Member State). The CWT form is also still open: no CWT artifact exists and TS 119 152-1
  allocates no claim keys. These fixtures narrow the gap (what producers emit) without closing it.

## The files

| file here | source repository | commit (date) | path in the source | licence | SHA-256 of the file as vendored |
|---|---|---|---|---|---|
| `german-sandbox/german-sandbox-wrprc.jwt` | `SUNET/vc` | `a6b8e05a7184d762096e479892c9d8d92293f5e8` (2026-08-28) | `pkg/model/testdata/german-sandbox-wrprc.jwt` | repository: BSD-2-Clause. **The licence of the sandbox-issued token itself is not stated.** | `4fed10eacaa2349da3ab6122b66064421042c20a06db27799061b8925a0a772f` |
| `german-sandbox/german-sandbox-registrar-root.pem` | `SUNET/vc` | `a6b8e05a7184d762096e479892c9d8d92293f5e8` (2026-08-28) | `pkg/model/testdata/german-sandbox-registrar-root.pem` | repository: BSD-2-Clause (the licence of the certificate itself is not stated) | `d955c23dc172db423abfd216578ddf84d66fb9df04986f85df15b6dab7ee7d83` |
| `hopae-dev/wrprc.jwt` | `openwallet-foundation-labs/axle` | `667e5ce0e0ca001f4d878195c14ec365e39e8a33` (2026-07-12) | `kotlin/trust/src/test/resources/wrprc.jwt` | Apache-2.0 (see the note on the licence date below) | `e77bc0afed1914e98cf4d7ddcfe9f4a6453897f2ed79c9bc9a454a672a102e0b` |
| `hopae-dev/wrprc_intermediated.jwt` | `openwallet-foundation-labs/axle` | `667e5ce0e0ca001f4d878195c14ec365e39e8a33` (2026-07-12) | `kotlin/trust/src/test/resources/wrprc_intermediated.jwt` | Apache-2.0 (as above) | `5c4233504b475b934da088b388f24adaf6bff706cc723f5c6172ee426f072377` |
| `digg/registration_certificate.jwt` | `diggsweden/wallet-ecosystem` | `f4e0cfcf01016b4facc35cd4e3a7529e1fbfe7c4` (2026-10-02) | `config/certificates/verifier-registration-certificate/registration_certificate.jwt` | CC0-1.0, declared by the sidecar below | `8e593fcdf05f22b8d2d028f16ba4703bd2135e50a87bab5127ac95d84eabd0aa` |
| `digg/registration_certificate.jwt.license` | `diggsweden/wallet-ecosystem` | `f4e0cfcf01016b4facc35cd4e3a7529e1fbfe7c4` (2026-10-02) | `config/certificates/verifier-registration-certificate/registration_certificate.jwt.license` | the REUSE sidecar itself: `SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government`, `SPDX-License-Identifier: CC0-1.0` | `80b9cadc15d92cb6838d1e2da47f069464b79d53e4e6a1ff3e9e70e090848ea9` |
| `eudi-verifier-endpoint/wrprc.jwt` | `eu-digital-identity-wallet/eudi-srv-verifier-endpoint` | `21425e00eb8478c21e653050428fb9a09f9e8b9c` (2026-07-24) | `src/test/resources/wrprc.jwt` | repository: Apache-2.0 | `128a731d54c04eab1e4f7aeeba35104d1835137a1c1c4c7d8a8c04d6473da74f` |

For each of the seven files the pinned commit was, on 2026-10-16, the **only** commit in the
default branch's history for that path.

Licence texts, vendored verbatim from the same repositories, are in `LICENSES/`; who holds what
is in `NOTICE.md`.

| licence file here | taken from | SHA-256 |
|---|---|---|
| `LICENSES/BSD-2-Clause.SUNET-vc.md` | `SUNET/vc` `LICENSE.md` @ `a6b8e05a7184d762096e479892c9d8d92293f5e8` | `f2877a81ccd055186daf9b690f2fad786583ff64832cdeb8ca3e5ed4d3ad7194` |
| `LICENSES/Apache-2.0.axle.txt` | `openwallet-foundation-labs/axle` `LICENSE` @ `d40c55d68541fa02ff43ccde01c772c6cbfda0ac` (**not** the pinned commit, see below) | `c4b4a1bc54721eb916e05b8471da8c11184c752507b905c76ff330a08bfdc65f` |
| `LICENSES/Apache-2.0.eudi-srv-verifier-endpoint.txt` | `eu-digital-identity-wallet/eudi-srv-verifier-endpoint` `LICENSE` @ `21425e00eb8478c21e653050428fb9a09f9e8b9c` | `30251107b55133e6090ac2ef94d7d925cddfbb7fbe5301793739f52ac3c59f20` |
| `LICENSES/CC0-1.0.txt` | `diggsweden/wallet-ecosystem` `LICENSES/CC0-1.0.txt` @ `f4e0cfcf01016b4facc35cd4e3a7529e1fbfe7c4` | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |

**The axle licence post-dates the pinned commit.** At `667e5ce` (2026-07-12) the repository had no
`LICENSE` or `NOTICE` file anywhere in its tree and its README states no licence. The Apache-2.0
`LICENSE` was added two days later by `d40c55d68541fa02ff43ccde01c772c6cbfda0ac` (2026-07-14,
"docs: Apache-2.0 license, Axle rebrand ..."), and neither token file has changed since. The text
vendored here is therefore the repository's own licence file from the first commit that carries
one, and the repository is Apache-2.0 on its default branch. There is no `NOTICE` file at either
commit.

## Who signs each token, and what it carries

Facts decoded from the bytes (the test pins every one of them):

- **German sandbox** (`german-sandbox-wrprc.jwt`). The German EUDI sandbox registrar, as recorded
  by the Siros wallet team (`SUNET/vc`). Header `{typ: rc-wrp+jwt, x5c, alg: ES256}`: one
  certificate, `CN=German Registrar, C=DE`, **self-signed**, `CA:TRUE pathlen 0`, keyUsage
  `keyCertSign|cRLSign` only, valid 2026-01-16 to 2028-01-16, DER SHA-256
  `7421221cb1da97b3edb4ad2ccb4d00cbdced1e1316bf6768e677218cdb246d3e`. It is also the anchor:
  `german-sandbox-registrar-root.pem` is that same certificate (identical DER). Payload `sub`
  `NTRDE-BD7070256AF93987`, `name` "Siros Foundation", one `Service_Provider` entitlement, a
  `credentials` entry for `eu.europa.ec.eudi.pid.1` registering `birth_date`, `family_name` and
  `given_name`; **no `iat`, no `exp`**; `srv_description` in the nested `[[{lang, value}]]` shape.
- **Hopae** (`wrprc.jwt`, `wrprc_intermediated.jwt`). The Hopae S.A. development registrar, as
  shipped in the test resources of the OpenWallet Foundation `axle` wallet. Header
  `{alg: ES256, typ: rc-wrp+jwt, x5c, x5t#S256, sigT, b64: true, crit: ["sigT", "b64"]}`: one
  certificate, `CN=Hopae S.A. Registrar CA, O=Hopae S.A., C=LU`, **self-signed**, `CA:TRUE
  pathlen 0`, keyUsage `keyCertSign|cRLSign` only, valid 2026-07-12 to 2028-07-11, DER SHA-256
  `0f138b93443b0b6dda73e3a1914c0e3b7d02469e70d9d02d7c83934ca4466d10`; `x5t#S256` is the digest of
  that certificate. `sigT` equals the payload `iat` to the second in both tokens. These are the
  tokens openvc 1.35.1 **rejected**, because `crit` names `sigT` and `b64`; accepting them is the
  maintainer decision recorded in the CHANGELOG (v1.36.0). Both carry `srv_description` in the
  nested shape, no `exp`, and a `credentials` entry in `wrprc.jwt` **without** `claim` (an empty
  grant). The intermediated token adds `intermediary {sub: LEIXG-INTERMEDIARY01, sname: Mediator}`
  **and** `act {sub: LEIXG-INTERMEDIARY01}`.
- **Digg** (`registration_certificate.jwt`). The DIGG (Swedish Agency for Digital Government)
  wallet-ecosystem demo. Header `{typ: rc-wrp+jwt, alg: ES256, x5c}` with two certificates: a
  leaf `CN=Verifier Backend (Ecosystem), organizationIdentifier=VATSE-12345678` (`CA:FALSE`,
  `digitalSignature`, valid 2026-09-29 to 2029-01-01) signed by `CN=DIGG Wallet Verifier
  Registration Certificate CA, O=DIGG, C=SE` (self-signed, valid 2026-09-24 to 2036-09-21, DER
  SHA-256 `728112a9744640161b6bed7039db06001de5c07ab2a474bd0352f7fd3f97e198`), which is the
  anchor. The only fixture with a real two-certificate chain. Payload has `iat` (2026-09-29) and
  `exp` (exactly 365 days later), `srv_description` in the **flat** `[{lang, value}]` shape, a
  `service_identifier` claim TS 119 475 does not define, and `intended_use_id` "1". Its
  `issuer_wrprc.jwt` (same directory upstream) is **not** a usable WRPRC and is not vendored.
- **EU verifier endpoint** (`eudi-verifier-endpoint/wrprc.jwt`). A test resource of the EU
  reference verifier endpoint, signed by a throwaway self-signed `CN=test` certificate with no
  extensions (valid 2026-07-10 to 2027-07-10; DER SHA-256
  `fa822676c43fd0647f885af6fb6147c8bbcc57bb39980d10250ff895ac532344`). It is a sample from a
  different producer, **not registrar evidence**: it describes an *issuer* (`provides_attestations`,
  three entitlements, no `credentials`), has `srv_description` in the flat shape and no `exp`.

Across all five: `typ` is `rc-wrp+jwt`, `alg` is `ES256` (64-byte raw R‖S signature), there is
**no JWS header `iat`**, no producer emits `intermediary.name`, and the key material is public
certificates only; no private key is present in any file.

## How each was verified

By `tests/test_rp_registration_real_artifacts.py`, offline, with the clock pinned to
2026-10-16T12:00:00Z (inside every certificate window):
`verify_rp_registration_certificate(token, trust_anchors=[<its own root>])` succeeds on all five;
one flipped payload byte, one flipped signature byte and an edited `sigT` fail the signature;
every other producer's root is refused as a trust anchor; and each certificate fails outside its
validity window. The anchor is a constant pinned by DER digest, never "whatever the token
carries". An independent check outside this repository's tests, on 2026-10-16, found the same
ES256 signatures valid against `x5c[0]` in all five.

## Not vendored, on purpose

- `hopae-official/registrar`: no licence, and a CA private key committed to the repository.
- The `swift/Tests/TrustTests/Resources/wrprc*.jwt` copies in `axle`: byte-identical to the Kotlin
  ones (same SHA-256), so they add nothing.
- The EU reference registrar's own output: defective (out of scope for #134).

## When these are replaced

When a Member State registrar publishes a WRPRC, record it here with its published anchor, verify
it against that anchor (not a self-pinned one), and drop the "provisional" label from whichever
fixture it supersedes. Until then do not describe these tokens as registrar-issued.
