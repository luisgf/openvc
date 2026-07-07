# openvc

A small, dependency-light **Verifiable Credentials core** for Python: sign and
verify credentials in three proof formats — **VC-JWT** (JOSE), **SD-JWT VC**
(selective disclosure), and **Data Integrity** (`eddsa-rdfc-2022` and the
selective-disclosure `ecdsa-sd-2023` over RDF, plus `eddsa-jcs-2022` /
`ecdsa-jcs-2019` over RFC 8785 JCS with no `pyld`) — resolve issuer keys by **DID**
(`did:key`, `did:jwk`, `did:web`), by **`/.well-known/jwt-vc-issuer`**, or by
**X.509 `x5c`** chain — issue and check
**status-list** revocation, verify a stateless **OpenID4VP 1.0** presentation
(`vp_token`, incl. **HAIP** `direct_post.jwt` JWE-encrypted responses), and — via an
optional plugin — verify against the **EBSI** trust registries. Designed so private
keys can live behind an **HSM/Vault** and never enter the process.

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
    proof/sd_jwt.py        SdJwtVcProofSuite: issue / present (key binding) / verify
    proof/data_integrity.py DataIntegrityProofSuite: eddsa-rdfc-2022 (needs pyld)
    proof/ecdsa_sd.py      EcdsaSdProofSuite: ecdsa-sd-2023 selective disclosure
    proof/di_jcs.py        Eddsa/EcdsaJcsProofSuite: eddsa-jcs-2022 / ecdsa-jcs-2019 (RFC 8785 JCS, no pyld)
    proof/_jcs.py          RFC 8785 JSON Canonicalization Scheme (hand-rolled, stdlib)
    proof/vp_jwt.py        VpJwtProofSuite: holder presentations (VP-JWT) + cascade
    proof/contexts/        bundled JSON-LD contexts + offline document loader
    did/base.py            DidDocument, resolver protocol, W3C parser, registry
    did/did_key.py         offline did:key (Ed25519, P-256)
    did/did_jwk.py         offline did:jwk (public-JWK identifier)
    did/did_web.py         did:web -> https -> fetch (fetch is injected)
    fetch.py               SSRF- + DNS-rebinding-safe https JSON fetch for did:web
    jwt_vc_issuer.py       https issuer keys via /.well-known/jwt-vc-issuer
    x5c.py                 X.509 x5c chain trust + SAN issuer binding
    status/                status lists — W3C Bitstring + IETF Token Status List (check + issue)
    schema.py              credentialSchema validation (W3C VC JSON Schema, opt-in)
    errors.py              OpenvcError — the root of every error family
    verify.py              verify_credential: one-call pipeline over every format
    openid4vp.py           verify_vp_token: stateless OpenID4VP 1.0 vp_token verifier
    jwe.py                 decrypt_compact: JWE ECDH-ES decrypt for HAIP responses
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

The PyPI distribution is **`openvc-core`**; the Python import package is
**`openvc`** — so `pip install openvc-core`, then `import openvc`.

```sh
pip install openvc-core                    # core: VC-JWT, did:key, did:web, status list
pip install "openvc-core[ebsi]"            # + the EBSI registry client (httpx)
pip install "openvc-core[data-integrity]"  # + eddsa-rdfc-2022 Data Integrity (pyld)
pip install -e ".[all]"                    # everything + dev tools (from a checkout)
```

## Quick start

Verify a credential in **any** format with the one-call pipeline — the format is
detected (VC-JWT / SD-JWT VC / Data Integrity / enveloped), the issuer key resolved
(`did:key`, `did:web`), and the policy enforced. Status is **fail-closed** by
default: a credential that declares a status is rejected unless you supply a
resolver (or opt out with `require_status=False`).

```python
from openvc import verify_credential, VerificationPolicy

# `credential` is a VC-JWT / SD-JWT string, or a Data Integrity / enveloped dict
result = verify_credential(
    credential,
    policy=VerificationPolicy(expected_types=["VerifiableCredential"]),
    resolve_status_list=fetch_verified_status_list,   # needed if it declares status
)
print(result.format, result.issuer, result.subject)
```

Or drive a single suite directly. Issue and verify a VC-JWT with an in-process key
(swap for an HSM backend in production):

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

SD-JWT VC — issue with selective disclosure, then verify a holder presentation
(the holder proves possession of the `cnf` key and reveals only what it chooses):

```python
from openvc.keys import Ed25519SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite

issuer = Ed25519SigningKey.generate(kid="did:web:issuer.example#key-1")
holder = Ed25519SigningKey.generate(kid="did:key:zHolder#0")
suite = SdJwtVcProofSuite()

sd_jwt = suite.issue(
    {"iss": "did:web:issuer.example", "vct": "https://credentials.example/id",
     "given_name": "Ada", "age": 36},
    signing_key=issuer, disclosable=["given_name", "age"],
    holder_jwk=holder.public_jwk(),
)
presentation = suite.create_presentation(
    sd_jwt, holder_key=holder, audience="https://verifier.example", nonce="n-123")

result = suite.verify(
    presentation, public_key_jwk=issuer.public_jwk(),
    audience="https://verifier.example", nonce="n-123", require_key_binding=True)
print(result.claims["given_name"], result.key_bound)
```

## Status

Alpha. The proof suites (VC-JWT, SD-JWT VC, and Data Integrity —
`eddsa-rdfc-2022`, verified byte-for-byte against the official W3C vc-di-eddsa
vector, plus the selective-disclosure `ecdsa-sd-2023`, interop-validated against
the official W3C vc-di-ecdsa vectors), the key
backends, issuer-key resolution by DID (`did:key`, `did:jwk`, `did:web`,
`did:ebsi` read), by `/.well-known/jwt-vc-issuer`, and by X.509 `x5c` chain (with
SAN issuer binding), the EBSI
registry client (verified against recorded pilot fixtures and a live smoke test),
the recursive TI→TAO→RootTAO trust chain (with per-hop delegation scoping and
revocation of the accreditations themselves), and status-list revocation in both
the W3C Bitstring and IETF Token Status List encodings — checked *and* issued —
are implemented and tested offline. Data Integrity verification also enforces the
credential's validity window and `proofPurpose`, not just the signature. A generic
`verify_credential` pipeline ties them together — format detection, key resolution,
and fail-closed status/type policy in one call. Holder presentations are covered by
VP-JWT (`aud`/`nonce` binding + cascade verification of each credential) and Data
Integrity `challenge`/`domain`. Every error descends from a single `OpenvcError`
root. See
[the roadmap](https://github.com/luisgf/openvc/blob/main/docs/ROADMAP.md) for
what is next.

`did:ebsi` write/onboarding (JSON-RPC + OID4VP) is **out of scope** — this is a
verifier/issuer library, not a node operator.

## Tests

```sh
pip install -e ".[all]"
pytest                        # offline: deterministic, no network
OPENVC_EBSI_LIVE=1 pytest     # also the opt-in live EBSI smoke test
```

## Project

- [Examples](https://github.com/luisgf/openvc/blob/main/examples/) — runnable
  scripts for the main flows (pipeline, SD-JWT, Data Integrity, status lists, VP-JWT)
- [Roadmap](https://github.com/luisgf/openvc/blob/main/docs/ROADMAP.md)
- [Changelog](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md)
- [Contributing](https://github.com/luisgf/openvc/blob/main/CONTRIBUTING.md)
  (dev setup, checks, and the commit convention)
- [Security policy](https://github.com/luisgf/openvc/blob/main/SECURITY.md)

## License

LGPL-3.0-or-later. Copyright © 2026 Luis González Fernández.
See [COPYING.LESSER](https://github.com/luisgf/openvc/blob/main/COPYING.LESSER)
and [COPYING](https://github.com/luisgf/openvc/blob/main/COPYING).
