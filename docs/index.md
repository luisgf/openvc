# openvc

A small, **dependency-light Verifiable Credentials core** for Python. It signs and
verifies credentials in three proof formats — **VC-JWT** (JOSE), **SD-JWT VC**
(selective disclosure), and **Data Integrity** (`eddsa-rdfc-2022` and the
selective-disclosure `ecdsa-sd-2023`) — resolves issuer keys by **DID**
(`did:key`, `did:jwk`, `did:web`), by **`/.well-known/jwt-vc-issuer`**, or by
**X.509 `x5c`** chain, issues and checks **status-list** revocation, verifies
**holder presentations** (VP-JWT), and — via an optional plugin — verifies against
the **EBSI** trust registries. Private keys can live behind an **HSM/Vault** and
never enter the process.

```sh
pip install openvc-core                    # core
pip install "openvc-core[data-integrity]"  # + eddsa-rdfc-2022 (pyld)
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
proof, and applies policy (types, audience, **fail-closed** status). See the
[API reference](api/verification.md) for the full surface, and the
[examples](https://github.com/luisgf/openvc/blob/main/examples/) for runnable
scripts of every flow.

## How it fits together

| Layer | Modules |
|---|---|
| One-call verifier | [`openvc.verify`](api/verification.md) |
| Proof suites | [VC-JWT, SD-JWT VC, Data Integrity, VP-JWT](api/proofs.md) |
| Issuer keys | [DIDs & signing keys](api/dids-keys.md), [well-known / x5c discovery](api/discovery.md) |
| Revocation | [status lists](api/status.md) |
| Errors | [one `OpenvcError` root](api/errors.md) |

Every error descends from a single `OpenvcError`, so `except OpenvcError` catches
any openvc failure.
