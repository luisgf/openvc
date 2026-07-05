# openvc

A small, dependency-light **Verifiable Credentials core** for Python: sign and
verify **VC-JWT** credentials, resolve **DIDs** (`did:key`, `did:web`), and — via
an optional plugin — read the **EBSI** registries (DID Registry + Trusted Issuers
Registry). Designed so private keys can live behind an **HSM/Vault** and never
enter the process.

It is intentionally *not* an Open Badges library: `openvc` is the generic VC
machinery that a badge issuer (or an EBSI verifier, or a EUDI wallet backend)
builds on. It never imports anything upward.

## Why

- **VC-JWT first, HSM-friendly.** Signing delegates the raw signature to a
  `SigningKey` backend, so a PKCS#11 / Vault Transit key is a drop-in — the
  private key never has to be in-process. ES256 signatures are the correct JOSE
  raw `R‖S` form (the classic reason a locally-produced token fails elsewhere).
- **Safe by construction.** The verifier pins an algorithm allow-list
  (`ES256`, `EdDSA`) *before* any crypto runs, and reconciles the JWT envelope
  with the embedded credential. The `did:web` fetch and the EBSI client both
  guard against SSRF.
- **Version drift, contained.** EBSI ships versioned registries whose response
  shapes change; every version specific lives behind one adapter, so the domain
  model and trust logic never see wire formats.

## Layout

```
src/openvc/                core — knows nothing about EBSI or badges
    keys.py                Ed25519 (EdDSA) & P-256 (ES256) SigningKey backends
    multibase.py           base58btc multibase + multicodec varint
    proof/vc_jwt.py        VcJwtProofSuite: peek / verify / sign
    proof/data_integrity.py DataIntegrityProofSuite: eddsa-rdfc-2022 (needs pyld)
    proof/contexts/        bundled JSON-LD contexts + offline document loader
    did/base.py            DidDocument, resolver protocol, W3C parser, registry
    did/did_key.py         offline did:key (Ed25519, P-256)
    did/did_web.py         did:web -> https -> fetch (fetch is injected)
    fetch.py               SSRF- + DNS-rebinding-safe https JSON fetch for did:web
    status/                W3C Bitstring Status List (revocation/suspension)
src/openvc_ebsi/           optional EBSI plugin (read-only); depends on openvc only
    http.py                EbsiHttpClient: TTL cache, retries, host allow-list
    versioning.py          DID Registry / TIR version adapters + DidEbsiResolver
    trust.py               recursive TI->TAO->RootTAO trust-chain verification
    verify.py              verify_ebsi_badge: signature + trust + revocation
    models.py              Accreditation, IssuerRecord (version-agnostic domain)
```

**Dependency rule:** `openvc` imports nothing upward. `openvc_ebsi` depends on
`openvc`, never the reverse.

## Install

```sh
pip install openvc                    # core: VC-JWT, did:key, did:web, status list
pip install "openvc[ebsi]"            # + the EBSI registry client (httpx)
pip install "openvc[data-integrity]"  # + eddsa-rdfc-2022 Data Integrity (pyld)
pip install -e ".[all]"               # everything + dev tools (from a checkout)
```

## Quick start

Issue and verify a VC-JWT with an in-process key (swap for an HSM backend in
production):

```python
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite

sk = P256SigningKey.generate(kid="did:web:issuer.example#key-1")
suite = VcJwtProofSuite()

credential = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:...",
    "type": ["VerifiableCredential"],
    "issuer": "did:web:issuer.example",
    "credentialSubject": {"id": "did:key:z6Mk..."},
}
token = suite.sign(credential, signing_key=sk)

verified = suite.verify(token, public_key_jwk=sk.public_jwk())
print(verified.issuer, verified.subject)
```

Resolve a `did:web` with the SSRF-guarded fetch, then verify against its key:

```python
from openvc.fetch import default_did_web_resolver

resolver = default_did_web_resolver()          # https-only, blocks private ranges
doc = resolver.resolve("did:web:issuer.example")
vm = doc.key_by_kid("did:web:issuer.example#key-1")
verified = suite.verify(token, public_key_jwk=vm.public_key_jwk)
```

EBSI (read-only) — resolve a `did:ebsi` and check issuer trust:

```python
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.http import for_ebsi
from openvc_ebsi.versioning import DidEbsiResolver
from openvc_ebsi.verify import verify_ebsi_badge

suite = VcJwtProofSuite()
with for_ebsi("pilot") as http:
    resolver = DidEbsiResolver(http.get_json, decode_jwt=suite.peek_claims)
    result = verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                               expected_types=["VerifiableAttestation"])
    print(result.trusted, result.issuer)
```

## Status

Alpha. Both proof suites (VC-JWT and eddsa-rdfc-2022 Data Integrity — the latter
verified byte-for-byte against the official W3C vc-di-eddsa vector), the key
backends, DID resolution (`did:key`, `did:web`, `did:ebsi` read), the EBSI
registry client, the recursive TI→TAO→RootTAO trust chain, and W3C Bitstring
Status List revocation are implemented and tested offline; an opt-in live EBSI
smoke test runs against the pilot/conformance environments. See
[docs/ROADMAP.md](docs/ROADMAP.md) for what is next (recorded golden fixtures,
Token Status List, per-hop delegation scoping, PyPI publish).

`did:ebsi` write/onboarding (JSON-RPC + OID4VP) is **out of scope** — this is a
verifier/issuer library, not a node operator.

## Tests

```sh
pip install -e ".[all]"
pytest                        # offline: deterministic, no network
OPENVC_EBSI_LIVE=1 pytest     # also the opt-in live EBSI smoke test
```

## License

LGPL-3.0-or-later. Copyright © 2026 Luis González Fernández.
See [COPYING.LESSER](COPYING.LESSER) and [COPYING](COPYING).
