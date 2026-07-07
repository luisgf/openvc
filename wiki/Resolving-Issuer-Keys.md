# Resolving issuer keys

To verify a credential you need the issuer's public key. The pipeline resolves
it automatically from the credential's `issuer` / `iss`; this page is about
where keys can come from and how to control that.

## The default resolver

Out of the box, `verify_credential` resolves three DID methods — all with no
key server of your own:

| Method | How it works | Network |
|---|---|---|
| `did:key` | the key **is** the identifier (multicodec + base58btc) | none |
| `did:jwk` | the identifier embeds a base64url JWK | none |
| `did:web` | `did:web:example.com` → `https://example.com/.well-known/did.json` | SSRF-guarded https |

`did:jwk`, fully offline:

```python
import base64
import json

from openvc.did.did_jwk import DidJwkResolver
from openvc.keys import Ed25519SigningKey

jwk = Ed25519SigningKey.generate(kid="_").public_jwk()
did = "did:jwk:" + base64.urlsafe_b64encode(
    json.dumps(jwk).encode()).rstrip(b"=").decode()

doc = DidJwkResolver().resolve(did)
print(doc.id == did, len(doc.verification_methods))
```

`did:web`, resolved through the SSRF-guarded fetch:

<!-- docs: no-run -->
```python
from openvc.fetch import default_did_web_resolver

resolver = default_did_web_resolver()      # https-only, private ranges blocked
doc = resolver.resolve("did:web:issuer.example")
vm = doc.key_by_kid("did:web:issuer.example#key-1")
```

## What the SSRF guard guarantees

Every issuer-named URL (`did:web` documents, well-known metadata, status
lists, schemas) is attacker-influenced input. `openvc.fetch` — and the blessed
defaults in `openvc.resolvers` built on it — enforce: **https only**, private
/ loopback / link-local / reserved ranges blocked, **redirects refused**, and
the connection **pinned to the validated IP** so DNS rebinding cannot swap the
host after the check. Details in the [Security model](Security-Model).

## Beyond DIDs

- **`/.well-known/jwt-vc-issuer`** (`openvc.jwt_vc_issuer`) — an https issuer
  (`iss: "https://issuer.example"`) publishes its JWKS at a well-known path;
  the pipeline fetches it through the same guarded fetch.
- **X.509 `x5c`** (`openvc.x5c`) — the token carries its certificate chain;
  openvc validates the path to **caller-pinned trust anchors** and binds the
  leaf's SAN to the `iss` value, so a valid-but-unrelated certificate cannot
  vouch for an arbitrary issuer. Where those anchors come from (including EU
  Trusted Lists) is the [Trust](Trust) page.
- **`did:ebsi`** — via the read-only plugin; see [Trust](Trust).

## Plugging in your own

Any object with `resolve(did)` / `supports(did)` works as a resolver; register
it in a `DidResolverRegistry` (from `openvc.did.base`) and pass it to
`verify_credential(..., resolver=...)`. That is exactly how the EBSI plugin
adds `did:ebsi`:

<!-- docs: no-run -->
```python
from openvc.did.base import DidResolverRegistry
from openvc.did.did_key import DidKeyResolver
from openvc.did.did_jwk import DidJwkResolver
from openvc.fetch import default_did_web_resolver

registry = DidResolverRegistry(
    [DidKeyResolver(), DidJwkResolver(), default_did_web_resolver(),
     my_did_ebsi_resolver])
result = verify_credential(token, resolver=registry)
```

A custom resolver is inside the trust boundary: if it skips verification or
the SSRF guard, that protection is gone — prefer composing the shipped pieces.

## Caching

DID documents rarely change; network resolvers can be wrapped in an opt-in
TTL cache (`openvc.cache`) — `CachingDidResolver` wraps a resolver,
`cached_resolve` wraps a bare resolve function. `did:key` / `did:jwk` never
need it (they never touch the network).
