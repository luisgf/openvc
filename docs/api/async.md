# Async verification

`openvc.aio` is the **async** counterpart of the sync
[verification pipeline](verification.md), for asyncio servers (FastAPI /
Starlette): a handler `await`s `verify_credential_async` instead of offloading the
whole call to a thread pool, and `verify_many_async` verifies a presentation
cascade **concurrently** instead of serialising N blocking fetches.

It reuses every proof suite, status/schema codec and binding check of the sync path
unchanged — only the I/O sequencing is re-expressed with `await`, so there is no
second implementation of any signature check to drift. The batteries-included async
fetch (`openvc.fetch.https_json_fetch_async`) runs the **exact same** SSRF /
DNS-rebind guard as the sync fetch under `asyncio.to_thread`; a caller may inject an
`httpx.AsyncClient`-backed fetch instead. See
[ADR-0002](../adr/ADR-0002-async-verification.md) for the design and its trade-offs.

```python
import asyncio
from openvc import verify_credential_async
from openvc.aio import default_async_resolver

async def main():
    result = await verify_credential_async(token, resolver=default_async_resolver())
    print(result.issuer)

asyncio.run(main())
```

::: openvc.aio

## Async resolvers & fetch

The async DID-resolution and fetch primitives the pipeline awaits.

::: openvc.did.base.AsyncDidResolver

::: openvc.did.base.AsyncDidResolverRegistry

::: openvc.did.base.as_async_resolver

::: openvc.did.did_web.AsyncDidWebResolver

::: openvc.fetch.https_json_fetch_async

::: openvc.fetch.https_text_fetch_async

::: openvc.fetch.https_bytes_fetch_async

::: openvc.fetch.default_async_did_web_resolver
