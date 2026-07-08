# openvc

[![PyPI](https://img.shields.io/pypi/v/openvc-core)](https://pypi.org/project/openvc-core/)
[![Python versions](https://img.shields.io/pypi/pyversions/openvc-core)](https://pypi.org/project/openvc-core/)
[![CI](https://github.com/luisgf/openvc/actions/workflows/ci.yml/badge.svg)](https://github.com/luisgf/openvc/actions/workflows/ci.yml)
[![License: LGPL-3.0-or-later](https://img.shields.io/pypi/l/openvc-core)](https://github.com/luisgf/openvc/blob/main/COPYING.LESSER)

A dependency-light, HSM-friendly **Verifiable Credentials core** for Python:
sign and verify W3C VCs in the three mainstream proof formats, resolve issuer
keys, check revocation, and verify wallet presentations — **fail-closed by
default**, with private keys that never have to enter the process.

| Capability | What is covered | Spec |
|---|---|---|
| **Sign & verify** | VC-JWT (`ES256` / `ES384` / `EdDSA`) | [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) |
| | SD-JWT VC — selective disclosure, Key Binding, Type Metadata | [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) |
| | Data Integrity — `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `eddsa-jcs-2022` / `ecdsa-jcs-2019` (stdlib JCS, no `pyld`), and selective-disclosure `ecdsa-sd-2023` | [vc-di-eddsa](https://www.w3.org/TR/vc-di-eddsa/) / [vc-di-ecdsa](https://www.w3.org/TR/vc-di-ecdsa/) |
| **Verify presentations** | VP-JWT, Data Integrity `challenge`/`domain`, and stateless [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) `vp_token` — incl. HAIP `direct_post.jwt` JWE-encrypted responses | OpenID4VP / HAIP |
| **Resolve issuer keys** | `did:key`, `did:jwk`, `did:web` (+ `did:ebsi` via plugin), `/.well-known/jwt-vc-issuer`, X.509 `x5c` chains with SAN issuer binding | [DID](https://www.w3.org/TR/did-core/) |
| **Revocation** | Bitstring Status List and Token Status List — check **and** issue | [W3C](https://www.w3.org/TR/vc-bitstring-status-list/) / [IETF](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) |
| **Trust anchors** | Caller-pinned X.509 anchors, [EU Trusted Lists](https://github.com/luisgf/openvc/wiki/Trust) (LOTL → national TL), EBSI Trusted Issuers Registry (read-only plugin) | ETSI TS 119 612 / [EBSI](https://hub.ebsi.eu/) |
| **Keys** | The `SigningKey` protocol — an HSM / KMS / Vault backend is a drop-in; ES256 signatures are raw JOSE `R‖S`, never DER | — |

## Install

The PyPI distribution is **`openvc-core`** (the import package stays `openvc`):

```sh
pip install openvc-core
```

The core needs only `cryptography` and `pyjwt`. Everything heavier is an extra:

| Extra | Adds | Pulls in |
|---|---|---|
| `openvc-core[data-integrity]` | RDF-canonicalized suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `ecdsa-sd-2023`) | `pyld` |
| `openvc-core[ebsi]` | the EBSI registry client | `httpx` |
| `openvc-core[schema]` | `credentialSchema` (W3C VC JSON Schema) validation | `jsonschema` |
| `openvc-core[trustlist]` | XAdES signature verification for EU Trusted Lists | `signxml` |
| `openvc-core[all]` | everything above + the dev tools | |

## Quick start

Issue a VC-JWT and verify it with the one-call pipeline. `verify_credential`
detects the format (VC-JWT / SD-JWT VC / Data Integrity / enveloped), resolves
the issuer key, verifies the proof, and applies policy — types, audience, and
**fail-closed** status:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import VerificationPolicy, verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite

# An issuer key addressed by did:key, so the whole flow runs offline.
private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)   # multicodec ed25519-pub
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

token = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:2f3a-example",
    "type": ["VerifiableCredential", "ExampleCredential"],
    "issuer": f"did:key:{mb}",
    "credentialSubject": {"id": "did:example:alice", "name": "Ada Lovelace"},
}, signing_key=issuer)

result = verify_credential(
    token, policy=VerificationPolicy(expected_types=["ExampleCredential"]))
print(result.format, result.issuer, result.subject)
```

Selective disclosure with SD-JWT VC — issue, present with a Key Binding JWT,
verify; the holder proves possession of the `cnf` key and the verifier sees
only what was disclosed:

```python
from openvc.keys import Ed25519SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite

issuer = Ed25519SigningKey.generate(kid="https://issuer.example#key-1")
holder = Ed25519SigningKey.generate(kid="holder-key-1")
suite = SdJwtVcProofSuite()

sd_jwt = suite.issue(
    {"iss": "https://issuer.example", "given_name": "Ada", "age": 36},
    signing_key=issuer, disclosable=["given_name", "age"],
    holder_jwk=holder.public_jwk(), vct="https://credentials.example/identity")

presentation = suite.create_presentation(
    sd_jwt, holder_key=holder, audience="https://verifier.example", nonce="n-123")

result = suite.verify(
    presentation, public_key_jwk=issuer.public_jwk(),
    audience="https://verifier.example", nonce="n-123", require_key_binding=True,
    expected_vct="https://credentials.example/identity")
print(result.claims["given_name"], result.key_bound)
```

Every flow — Data Integrity proofs, VP-JWT and OpenID4VP presentations, status
lists, remote HSM signing, EU Trusted Lists, EBSI — has a guide in the
[wiki](https://github.com/luisgf/openvc/wiki) and a runnable script in
[`examples/`](https://github.com/luisgf/openvc/blob/main/examples/).

## Why openvc

- **HSM-first.** Signing goes through the `SigningKey` protocol (`alg` / `kid`
  / `sign`), so a PKCS#11, AWS KMS, or Vault Transit backend drops in and the
  private key never enters the process. ES256 signatures are the correct raw
  JOSE `R‖S` form — the classic reason a locally-produced token fails elsewhere.
- **Fail-closed by construction.** The `{ES256, ES384, EdDSA, Ed25519}` allow-list
  runs *before* any crypto (`alg:none`, RS\*, HS\* never reach a verifier); a
  declared credential status without a resolver rejects; an unparseable
  timestamp rejects; the JWT envelope is reconciled with the embedded credential.
- **SSRF-guarded network.** Every issuer-named URL (`did:web`, well-known,
  status lists, schemas) goes through an https-only fetch that blocks
  private/loopback/link-local ranges, refuses redirects, and pins the
  connection to the validated IP (no DNS rebinding).
- **Dependency-light.** The core imports `cryptography` and `pyjwt`, nothing
  else; JSON canonicalization (RFC 8785) and the `ecdsa-sd-2023` CBOR codec are
  hand-rolled on the stdlib, and `pyld` / `httpx` stay behind extras.
- **Conformance pinned by real vectors.** `eddsa-rdfc-2022` reproduces the
  official W3C test vector byte-for-byte; `ecdsa-rdfc-2019` / `ecdsa-sd-2023`
  verify the official vc-di-ecdsa vectors and match their intermediates; the
  EBSI client is verified against recorded pilot responses. Golden fixtures are
  the drift alarm.

## Documentation

- **[Manual (wiki)](https://github.com/luisgf/openvc/wiki)** — installation,
  a guide per proof format, presentations & OpenID4VP, issuer-key resolution,
  status lists, trust (EU Trusted Lists, EBSI), HSM integration, the security
  model, and the versioning contract.
- **[API reference](https://luisgf.github.io/openvc/)** — generated from the
  docstrings, per module.
- **[`examples/`](https://github.com/luisgf/openvc/blob/main/examples/)** —
  ten runnable, offline scripts covering every flow (they run in CI, so they
  cannot rot).

## Scope

`openvc` is the generic VC machinery a badge issuer, an EBSI verifier, or a
EUDI wallet backend builds on — intentionally **not** an Open Badges library, a
wallet, or a node operator. EBSI support is **read-only** (resolve `did:ebsi`,
read the trust registries); onboarding/writing is out of scope. The
`openvc_ebsi` plugin depends on `openvc`, never the reverse.

## Project

- [Changelog](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) —
  every release, with the spec/security reasoning
- [Roadmap](https://github.com/luisgf/openvc/blob/main/docs/ROADMAP.md)
- [Versioning & deprecation policy](https://github.com/luisgf/openvc/wiki/Versioning-and-Deprecation)
- [Contributing](https://github.com/luisgf/openvc/blob/main/CONTRIBUTING.md) —
  dev setup, checks, commit convention
- [Security policy](https://github.com/luisgf/openvc/blob/main/SECURITY.md) and
  the [threat model](https://github.com/luisgf/openvc/wiki/Security-Model)

```sh
pip install -e ".[all]"       # from a checkout
pytest                        # offline: deterministic, no network
OPENVC_EBSI_LIVE=1 pytest     # + the opt-in live EBSI smoke test
```

## License

LGPL-3.0-or-later. Copyright © 2026 Luis González Fernández.
See [COPYING.LESSER](https://github.com/luisgf/openvc/blob/main/COPYING.LESSER)
and [COPYING](https://github.com/luisgf/openvc/blob/main/COPYING).
