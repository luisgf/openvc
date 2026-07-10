# openvc

A small, **dependency-light Verifiable Credentials core** for Python. It signs and
verifies credentials in three proof formats — **VC-JWT** (JOSE), **SD-JWT VC**
(selective disclosure), and **Data Integrity** (`eddsa-rdfc-2022` / `ecdsa-rdfc-2019`
and the selective-disclosure `ecdsa-sd-2023` over RDF, plus `eddsa-jcs-2022` /
`ecdsa-jcs-2019` over RFC 8785 JCS with no `pyld`) — resolves issuer keys by **DID**
(`did:key`, `did:jwk`, `did:web`, `did:webvh`), by **`/.well-known/jwt-vc-issuer`**, or
by **X.509 `x5c`** chain (with **EU Trusted List** anchors), issues and checks
**status-list** revocation, verifies **holder presentations** (VP-JWT, `ldp_vc`, and a
stateless **OpenID4VP 1.0** `vp_token` — including experimental ISO 18013-5 **`mso_mdoc`**
over the W3C Digital Credentials API and **HAIP** JWE-encrypted responses), and — via an
optional plugin — verifies against the **EBSI** trust registries. Post-quantum **ML-DSA**
(RFC 9964) signing and verification is available behind an explicit opt-in. Private keys
can live behind an **HSM/Vault** and never enter the process.

```sh
pip install openvc-core                    # core
pip install "openvc-core[data-integrity]"  # + eddsa-rdfc-2022 / ecdsa-rdfc-2019 (pyld)
pip install "openvc-core[ebsi]"            # + the EBSI registry client (httpx)
```

## The one-call verifier

```python
from openvc import verify_credential, VerificationPolicy

# `credential` is a VC-JWT / SD-JWT string, or a Data Integrity / enveloped dict.
result = verify_credential(
    credential,
    policy=VerificationPolicy(expected_types=["VerifiableCredential"]),
    resolve_status_list=fetch_verified_status_list,   # needed if it declares a status
)
print(result.format, result.issuer, result.subject)
```

`verify_credential` detects the format, resolves the issuer key, verifies the
proof, and applies policy (types, audience, **fail-closed** status). This site
is the **API reference**, generated from the docstrings; the task-oriented
manual — guides per proof format, presentations, status lists, trust, HSM
integration, the security model — lives on the
[project wiki](https://github.com/luisgf/openvc/wiki), and the
[examples](https://github.com/luisgf/openvc/blob/main/examples/) are runnable
scripts of every flow.

## How it fits together

| Layer | Modules |
|---|---|
| One-call verifier | [`openvc.verify`](api/verification.md) |
| Presentations | [OpenID4VP 1.0 `vp_token`](api/openid4vp.md), [ISO mdoc `mso_mdoc`](api/mdoc.md) |
| Proof suites | [VC-JWT, SD-JWT VC, Data Integrity, VP-JWT](api/proofs.md) |
| Issuer keys | [DIDs & signing keys](api/dids-keys.md), [well-known / x5c / WRPAC discovery](api/discovery.md) |
| Trust anchors | [EU Trusted Lists](api/trustlist.md) |
| Revocation | [status lists](api/status.md) |
| Errors | [one `OpenvcError` root](api/errors.md) |

Every error descends from a single `OpenvcError`, so `except OpenvcError` catches
any openvc failure.
