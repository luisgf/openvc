# CLAUDE.md — openvc

Guidance for Claude Code working in this repository.

## What this project is

`openvc` is a standalone, dependency-light **Verifiable Credentials core** for
Python. It signs and verifies credentials in three proof formats — **VC-JWT**
(JOSE), **SD-JWT VC** (selective disclosure), and **Data Integrity**
(`eddsa-rdfc-2022` + the selective-disclosure `ecdsa-sd-2023`) — resolves **DIDs**
(`did:key`, `did:web`, `did:ebsi`), and checks **status-list** revocation (W3C
Bitstring + IETF Token Status List), all HSM-friendly. Plus an optional read-only
**EBSI** plugin. It is *not* an Open Badges library; a badge issuer is a
downstream consumer.

**Distribution vs import:** published on PyPI as **`openvc-core`** (bare `openvc`
collides with `opencv` under PyPI's typo guard); the import package stays
**`openvc`** — `pip install openvc-core`, then `import openvc`.

`docs/ROADMAP.md` tracks what is done/next;
`docs/adr/ADR-0001-ebsi-http-client.md` records the EBSI HTTP/caching decisions.
`docs/SESSION-HANDOFF.md` is an early, now-historical design snapshot.

Two packages, one repo:

- `openvc/` — generic core (proof suites, key backends, DID resolution, an
  SSRF-guarded https fetch). Knows nothing about EBSI or badges.
- `openvc_ebsi/` — optional EBSI plugin (did:ebsi resolution, Trusted Issuers
  Registry client, versioned adapters, HTTP client, the verify glue). Depends on
  `openvc`.

**Dependency rule, do not break:** `openvc` imports nothing upward. `openvc_ebsi`
imports from `openvc`, never the reverse.

## Conventions / invariants (do not break)

- **VC-JWT + ES256** is the EBSI/EUDI-compatible path; **EdDSA (Ed25519)** is the
  general default. Both stay supported. RS*/HS*/`alg:none` are rejected by the
  allow-list *before* any crypto runs — do not widen it casually.
- **JOSE signatures are raw R‖S for ES256** (64 bytes), never DER. See `keys.py`.
- **Private keys sign via the `SigningKey` protocol** so an HSM/Vault backend can
  drop in; never require a raw private key in-process on the signing path.
- **EBSI is read-only** (resolve DID, read TIR). Onboarding/writing (JSON-RPC +
  OID4VP) is out of scope.
- **API-version specifics live behind adapters** in `versioning.py`; the domain
  model and trust logic never see wire formats. A new EBSI version = one new
  adapter class + a golden fixture. Never scatter `if version == …`.
- **Caching is a short client-side TTL** (EBSI sends no cache headers — ADR-0001).
- **SSRF guards stay.** The EBSI client uses an https-only host allow-list;
  `did:web` uses the separate general fetch in `openvc.fetch`, which blocks
  private/loopback/link-local ranges. Never resolve `did:web` through the EBSI
  client (its allow-list would reject every legitimate host).
- **Three proof suites, one key layer.** VC-JWT and SD-JWT VC are JOSE (they share
  the `{ES256, EdDSA}` allow-list and the `SigningKey` backends); Data Integrity
  has two cryptosuites — `eddsa-rdfc-2022` (Ed25519, whole document) and
  `ecdsa-sd-2023` (P-256 selective disclosure). A new proof format is one module
  behind the same key/verify primitives, not a fork.
- **Status lists: two encodings, one interface.** `openvc.status` exposes the W3C
  Bitstring and the IETF Token Status List codecs behind one shape.
- **Golden fixtures are the drift alarm.** Conformance is pinned by recorded real
  vectors (W3C vc-di-eddsa / vc-di-ecdsa, EBSI pilot), not synthetic shapes. eddsa
  reproduces a fixed proof byte-for-byte; ecdsa-sd is randomised, so its interop
  is shown by verifying reference proofs and matching the intermediates.
- **Dependency-light stays.** Core is `cryptography` + `pyjwt` only; `pyld` and
  `httpx` live behind extras and CBOR is hand-rolled (`ecdsa_sd`) — do not add a
  runtime dependency casually.

## Running tests

```bash
pip install -e ".[all]"
pytest                       # offline: deterministic, no network
OPENVC_EBSI_LIVE=1 pytest    # also the opt-in live EBSI smoke test
flake8 && mypy               # lint + type-check
```

## Author / license

Copyright © 2026 Luis González Fernández. LGPL-3.0-or-later. This project has a
single copyright holder; do not add other authors to headers or metadata.
