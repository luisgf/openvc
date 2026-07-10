# Resolving issuer keys

To verify a credential you need the issuer's public key. The pipeline resolves
it automatically from the credential's `issuer` / `iss`; this page is about
where keys can come from and how to control that.

## The default resolver

Out of the box, `verify_credential` resolves four DID methods — all with no
key server of your own:

| Method | How it works | Network |
|---|---|---|
| `did:key` | the key **is** the identifier (multicodec + base58btc) | none |
| `did:jwk` | the identifier embeds a base64url JWK | none |
| `did:web` | `did:web:example.com` → `https://example.com/.well-known/did.json` | SSRF-guarded https |
| `did:webvh` | `did:web` + a hash-chained `did.jsonl` version log, **replayed and verified** | SSRF-guarded https |

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

### `did:webvh` — did:web with verifiable history

[`did:webvh`](https://identity.foundation/didwebvh/v1.0/) (a DIF **Recommended** DID
Method) is `did:web` plus a self-certifying, hash-chained **version log**. Instead of a
single `did.json`, the controller publishes a `did.jsonl` whose every entry is bound to
the one before it, so resolving means **verifying history** — openvc replays the log
fail-closed: the **SCID** (the identifier is the hash of the genesis entry), the
**entryHash chain** (an inserted / reordered / tampered entry breaks it), each entry's
**`eddsa-jcs-2022` proof** by an authorized `updateKey`, and **key pre-rotation** (a
rotated-in key must have been pre-committed). A deactivated log fails closed. It is
registered in the default resolver, so no code change is needed to verify a credential
from a `did:webvh` issuer — or resolve one directly:

<!-- docs: no-run -->
```python
from openvc.fetch import default_did_webvh_resolver

resolver = default_did_webvh_resolver()    # fetches + replays did.jsonl, SSRF-guarded
doc = resolver.resolve("did:webvh:QmSCID…:issuer.example")
```

Verify-side only: openvc resolves and validates a log; creating, rotating or witnessing
one (issuer-side tooling) is out of scope.

### DID 1.1 / CID 1.0 documents

`parse_did_document` is **context-agnostic** — it reads the document *shape*
(`verificationMethod` / relationships), never `@context`. So **DID 1.1** (Candidate
Recommendation, rebased on **CID 1.0**, `https://www.w3.org/ns/did/v1.1`) documents resolve
unchanged the day issuers emit them — the `Multikey` verification method and the standard
relationships are already handled. The DID 1.1 relationship-semantics diff is revisited
when it reaches Proposed Recommendation (nothing speculative before then).

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

Network resolution is opt-in cacheable through `openvc.cache`, a thread-safe,
bounded, pure-stdlib `TtlCache` with two wrappers:

- `CachingDidResolver` memoises `resolve(did)` — so a batch from one `did:web`
  issuer skips the repeat round-trip; `did:key` / `did:jwk` never need it (they
  never touch the network).
- `cached_resolve` wraps any `resolve_status_list` / `resolve_credential_schema`
  / fetch `Callable[[str], …]`.

Only **successful** results are cached — a transient failure is retried, never
pinned. **Freshness is a security property for status:** a cached status list
cannot see a revocation until it expires, so `cached_resolve` defaults to a short
TTL (`DEFAULT_STATUS_TTL_S = 60 s`) while DID documents tolerate a longer one
(`DEFAULT_DID_TTL_S = 300 s`). Caching stays opt-in — the pipeline default resolves
uncached. For a one-shot batch, `verify_many` (and the VP-JWT cascade) already
dedupes each distinct issuer / status list / schema per call, so you often do not
need a standing cache at all.
