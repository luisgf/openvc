# Async verification

For asyncio servers (FastAPI / Starlette), `openvc.aio` provides
`verify_credential_async` and `verify_many_async` — the async counterparts of
the pipeline, so a handler `await`s verification instead of offloading the
whole call to a thread pool, and a presentation cascade resolves its issuers
and status lists **concurrently** instead of serializing N blocking fetches.

Same formats, same `VerificationPolicy`, same `VerificationResult`, same
fail-closed guarantees: the async path reuses every proof suite and codec
unchanged and only re-expresses the I/O sequencing
([ADR-0002](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0002-async-verification.md)
— no second implementation of any signature check).

```python
import asyncio

from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import VerificationPolicy, verify_credential_async
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite

private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

token = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "credentialSubject": {"id": "did:example:alice"},
}, signing_key=issuer)


async def main() -> None:
    result = await verify_credential_async(
        token, policy=VerificationPolicy(expected_types=["VerifiableCredential"]))
    print(result.format, result.issuer)


asyncio.run(main())
```

Notes:

- Async resolver counterparts exist for the network paths —
  `openvc.fetch.default_async_did_web_resolver` and the `*_async` factories in
  `openvc.resolvers` — and the async registry composes them exactly like the
  sync one.
- `verify_many_async` batches like `verify_many` (each distinct issuer DID and
  status list resolved once), with the resolution itself under
  `asyncio.gather`.
- CPU-bound work (the signature checks) still runs inline; if you verify large
  batches on a hot loop, measure — the win here is the I/O concurrency.
