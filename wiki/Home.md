# openvc

A dependency-light, HSM-friendly **Verifiable Credentials core** for Python:
sign and verify W3C VCs in the three mainstream proof formats — **VC-JWT**,
**SD-JWT VC**, and **Data Integrity** — resolve issuer keys, check status-list
revocation, and verify wallet presentations (VP-JWT, OpenID4VP 1.0, HAIP),
**fail-closed by default**. Published on PyPI as
[`openvc-core`](https://pypi.org/project/openvc-core/); the import package is
`openvc`.

```sh
pip install openvc-core
```

## Where things are documented

- **This wiki** is the manual: task-oriented guides with runnable code. Start
  with [Getting Started](Getting-Started).
- **The [API reference](https://luisgf.github.io/openvc/)** is generated from
  the docstrings — every module, class, and function.
- **[`examples/`](https://github.com/luisgf/openvc/tree/main/examples)** are
  ten self-contained offline scripts, executed by CI on every push.

Every `python` block in this wiki is also executed by CI (`tests/test_docs_blocks.py`),
so the snippets you read here are guaranteed to run against the current release.

## Guides

| Guide | Covers |
|---|---|
| [Getting Started](Getting-Started) | install, extras, your first issue + verify |
| [VC-JWT](VC-JWT) | the JOSE suite: sign / verify / peek, the algorithm allow-list |
| [SD-JWT VC](SD-JWT-VC) | selective disclosure, Key Binding, Type Metadata |
| [Data Integrity](Data-Integrity) | the five cryptosuites, JCS without `pyld`, `ecdsa-sd-2023` |
| [Presentations & OpenID4VP](Presentations) | VP-JWT, `vp_token` + DCQL, HAIP encrypted responses |
| [Resolving issuer keys](Resolving-Issuer-Keys) | `did:key` / `did:jwk` / `did:web`, well-known, caching |
| [Status lists](Status-Lists) | revocation — check *and* issue, both encodings |
| [Trust anchors](Trust) | X.509 `x5c`, EU Trusted Lists, the EBSI plugin |
| [Async verification](Async-Verification) | `verify_credential_async` for asyncio servers |
| [Keys & HSM backends](Keys-and-HSM) | the `SigningKey` protocol, KMS / Vault / PKCS#11 |
| [Security model](Security-Model) | assets, trust boundaries, attacker capabilities → controls |
| [Versioning & deprecation](Versioning-and-Deprecation) | the SemVer contract and what "stable" covers |

## How the code is laid out

```
src/openvc/                 core — knows nothing about EBSI or badges
    verify.py               verify_credential / verify_many: the one-call pipeline
    aio.py                  verify_credential_async / verify_many_async
    openid4vp.py            verify_vp_token: stateless OpenID4VP 1.0 verifier
    jwe.py                  decrypt_compact: JWE ECDH-ES decrypt (HAIP responses)
    proof/                  the proof suites (vc_jwt, sd_jwt, vp_jwt, data_integrity,
                            di_ecdsa_rdfc, di_jcs, ecdsa_sd) + shared error taxonomy
    did/                    did:key, did:jwk, did:web resolvers + registry
    keys.py                 Ed25519 / P-256 / P-384 SigningKey backends
    fetch.py                SSRF- and DNS-rebinding-safe https fetch
    resolvers.py            blessed SSRF-guarded status / schema / type-metadata resolvers
    cache.py                opt-in TTL caching for DID resolution
    jwt_vc_issuer.py        issuer keys via /.well-known/jwt-vc-issuer
    x5c.py                  X.509 x5c chain trust + SAN issuer binding
    trustlist/              EU Trusted Lists (LOTL → TL) → X.509 anchors
    status/                 W3C Bitstring + IETF Token Status List (check + issue)
    schema.py               credentialSchema validation (opt-in)
    type_metadata.py        SD-JWT VC Type Metadata
    multibase.py            base58btc multibase + multicodec varint
    errors.py               OpenvcError — the root of every error family
    observability.py        opt-in logging + injectable span hook
src/openvc_ebsi/            optional EBSI plugin (read-only); depends on openvc only
```

**Dependency rule:** `openvc` imports nothing upward; `openvc_ebsi` depends on
`openvc`, never the reverse.

## Scope

`openvc` is the generic VC machinery a badge issuer, an EBSI verifier, or a
EUDI wallet backend builds on. It is intentionally **not** an Open Badges
library, a wallet, or a node operator; EBSI support is **read-only**
(onboarding/writing via JSON-RPC + OID4VP is out of scope).

## Project

[Changelog](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) ·
[Roadmap](https://github.com/luisgf/openvc/blob/main/docs/ROADMAP.md) ·
[Contributing](https://github.com/luisgf/openvc/blob/main/CONTRIBUTING.md) ·
[Security policy](https://github.com/luisgf/openvc/blob/main/SECURITY.md) ·
[Design decisions (ADRs)](https://github.com/luisgf/openvc/tree/main/docs/adr)
