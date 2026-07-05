# CLAUDE.md — openvc

Guidance for Claude Code working in this repository.

## What this project is

`openvc` is a standalone, dependency-light **Verifiable Credentials core**:
VC-JWT proofs, key backends (HSM-friendly), and DID resolution — plus an optional
read-only **EBSI** plugin. It is *not* an Open Badges library; a badge issuer is a
downstream consumer. Read `docs/SESSION-HANDOFF.md` for the design history and
`docs/adr/ADR-0001-ebsi-http-client.md` for the EBSI HTTP/caching decisions and
the live evidence behind them. `docs/ROADMAP.md` tracks what is next.

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
