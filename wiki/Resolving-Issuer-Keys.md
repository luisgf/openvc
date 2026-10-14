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
rotated-in key must have been pre-committed). A deactivated log fails closed. The resolved
document is the final log state itself: its `id` must equal the requested DID, and a
`didDocument` member in it is refused with `DidWebvhError` rather than unwrapped (the spec
defines no such member, and unwrapping would return a document other than the one whose
`id` was checked). A `did:web` document or an EBSI registry response may still carry the
`didDocument` envelope. It is registered in the default resolver, so no code change is
needed to verify a credential from a `did:webvh` issuer — or resolve one directly:

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

### A DID document of the wrong shape

A document comes from the issuer a token names, and openvc resolves it before the
signature is checked, so its *shape* is untrusted too. `parse_did_document` is the one
parser behind `did:web` (sync and async), the resolved state of a `did:webvh` log and the
EBSI DID Registry. It raises `DidResolutionError` for a `didDocument` wrapper that is not
an object, and for a `verificationMethod` or a relationship (`assertionMethod`,
`authentication`, …) that is present but not an array. A `null`, a number, a string or an
object there is never read as "not declared": an undeclared relationship leaves the key
purpose unenforced, and a bare string would otherwise be read one character at a time.
The parser does not know which lane is asking, so a relationship that is not an array
rejects the whole document, JOSE lanes that never read relationships included.
A method whose `id` is not a string, and a relationship entry that is neither an id string
nor an object with a string `id`, are dropped, so they select no key and grant no purpose.
A method dropped this way is not counted when a token with no `kid` falls back to the
document's sole key, as a method with an undecodable Multikey never was.
In `verify_many` the credential fails with a typed error and the rest of the batch still
verifies: `KeyResolutionFailed` on the JOSE lanes and on `verify_many_async`,
`KeyResolutionError` (a `ProofError`) on the synchronous Data Integrity lane. In both
cases the cause is the `DidResolutionError`.

## What the SSRF guard guarantees

Every issuer-named URL (`did:web` documents, well-known metadata, status
lists, schemas) is attacker-influenced input. `openvc.fetch` — and the blessed
defaults in `openvc.resolvers` built on it — enforce: **https only**, private
/ loopback / link-local / reserved ranges blocked, **redirects refused**, and
the connection **pinned to the validated IP** so DNS rebinding cannot swap the
host after the check. Details in the [Security model](Security-Model).

A malformed host never gets that far. A `did:web` / `did:webvh` host must be an
ASCII domain name (RFC 1123 labels, at most 253 characters), with an optional
`%3A`-encoded port from 1 to 65535. Anything else raises `DidResolutionError`
before any fetch, your own fetch included: a bad port, an IP address (dotted,
numeric, hex or bracketed; the spec forbids them), a control character, or an
`@`, `/` or `#` decoded from the host. The guarded fetch
raises `UnsafeUrlError` for any URL it cannot parse. Both are `OpenvcError`s, so in
`verify_many` a hostile issuer becomes that credential's `error` and the rest of
the batch still verifies.

Write an internationalized host as its A-label: `did:web:xn--mnchen-3ya.de`, not
`did:web:m%C3%BCnchen.de`. The guarded fetch goes further and refuses any non-ASCII
https URL, host or path.
A Unicode host is refused, not converted, because Python's IDNA codec is IDNA2003.
It maps `faß.de` to `fass.de`, where IDNA2008 and browsers use `xn--fa-hia.de`, a
different domain.

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

The well-known and `x5c` lanes derive a host from an https `iss`, so they refuse
any `iss` that lets Python and a browser name different hosts or paths. These are
refused:

- userinfo and a backslash;
- a control character or whitespace;
- params, a query or a fragment;
- a non-ASCII character (write an IDN host as its `xn--` A-label);
- a percent-encoded host;
- port 0;
- a `.` or `..` segment.

For example, `https://trusted.example\@attacker.example` names `attacker.example`
to Python but `trusted.example` to a browser, and `https://faß.de` is `fass.de` to
one and `xn--fa-hia.de` to the other. The metadata lane raises `JwtVcIssuerError`
(`KeyResolutionFailed` in the pipeline). The x5c lane binds a `dNSName` only to a
clean https `iss`; a `uniformResourceIdentifier` still has to equal the `iss`
exactly.

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
