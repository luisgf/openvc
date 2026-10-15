# SD-JWT VC (selective disclosure)

[SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) lets
an issuer mark claims as *selectively disclosable*: the holder later presents
only the claims it chooses, and proves possession of the key the credential
was bound to (`cnf`) with a **Key Binding JWT** over the verifier's `aud` +
`nonce`.

## Issue → present → verify

```python
from openvc.keys import Ed25519SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite

issuer = Ed25519SigningKey.generate(kid="https://issuer.example#key-1")
holder = Ed25519SigningKey.generate(kid="holder-key-1")
suite = SdJwtVcProofSuite()

# Issue: given_name and age are selectively disclosable; cnf binds the holder key.
sd_jwt = suite.issue(
    {"iss": "https://issuer.example", "given_name": "Ada",
     "family_name": "Lovelace", "age": 36},
    signing_key=issuer, disclosable=["given_name", "age"],
    holder_jwk=holder.public_jwk(), vct="https://credentials.example/identity")

# Present: the holder signs a KB-JWT over this verifier's aud + nonce.
presentation = suite.create_presentation(
    sd_jwt, holder_key=holder, audience="https://verifier.example", nonce="n-123")

# Verify: issuer signature, disclosure digests, KB-JWT, aud/nonce, vct.
result = suite.verify(
    presentation, public_key_jwk=issuer.public_jwk(),
    audience="https://verifier.example", nonce="n-123", require_key_binding=True,
    expected_vct="https://credentials.example/identity")
print(result.vct, result.key_bound, result.claims["given_name"])
```

When `require_key_binding=True`, the KB-JWT (signature, `iat` window, `aud`,
`nonce`, `sd_hash`) is verified **even if** the issuer JWT is expired or
not-yet-valid. A temporal failure on the issuer JWT (`ClaimsInvalid`: `token has
expired`, `token is not yet valid` or `token iat is in the future`) from that call
therefore means the presentation was **bound**; a key-binding failure (wrong
`aud`/`nonce`, a stale or future-dated KB-JWT, a KB-JWT outside its own `exp`/`nbf`,
missing KB-JWT, or `SignatureInvalid` on the KB) means it was unbound. Every KB-JWT
failure names the KB-JWT. Do not treat `EXPIRED` as proof of holder binding. The hosted path (`require_key_binding=False`) is unchanged: expiry
still fails before any KB check.

**KB-JWT freshness.** RFC 9901 makes the KB-JWT `iat` REQUIRED (§4.3) and has the
verifier check it is "within an acceptable window" (§7.3 step 5.5). openvc requires
it, refuses a non-numeric or non-finite one, and refuses a KB-JWT older than
`kb_max_age_s` — default `DEFAULT_KB_MAX_AGE_S`, 300 seconds — plus the leeway, or
dated in the future beyond the leeway. Any KB-JWT that is present is held to it,
whether or not binding was required. A KB-JWT's own `exp`/`nbf`, which RFC 9901
does not define, are held to the same rule when present: finite numbers (`null`
included), judged at the same instant. These are binding failures (`KB-JWT is too
old`, `KB-JWT iat is in the future`, `KB-JWT is outside its own exp/nbf window`),
never an `expired` verdict, so
`require_not_expired=False` does not waive them
([what the waiver covers](Getting-Started#waiving-expiry-or-revocation)). The
`nonce` binds a KB-JWT to one transaction, but only you know how old that nonce
is; this window is the freshness bound a stateless verifier can enforce itself.

`now` — on `SdJwtVcProofSuite.verify`, `VerificationPolicy` and `verify_vp_token` —
pins the instant the window is evaluated at; a naive datetime is UTC, as everywhere in
openvc. To re-verify an archived presentation, pin `now` to the **receipt time your
system recorded**, and do not widen the window. Never pin it to a value read from the
presentation itself: its own `iat` would make every KB-JWT fresh and switch the window
off. The window also covers SD-JWT VCs nested inside `jwt_vc_json` and `ldp_vc`
presentations. (The issuer JWT's `exp`/`nbf`/`iat` still use the current time, as on
every JOSE suite.)

**Issuer JWT dates.** The issuer JWT's `exp`, `nbf` and `iat` must each be a finite
JSON number (RFC 7519 NumericDate) when present. `null`, a string, a bool,
`NaN`/`Infinity`, a container or an integer too large for a float is a
`ClaimsInvalid`. An `iat` more than the leeway in the future is rejected. The same
rule covers the processed payload, so an `iat` the issuer made selectively
disclosable is checked once it is disclosed. `require_not_expired=False` waives only
an expired `exp`, never a malformed date, a future `nbf` or a future `iat`. Before
1.30.5 this lane read `"exp": null` / `"nbf": null` as absent and never looked at
`iat`. The issuer JWT's `aud` is **not** checked: an issuer JWT addressed to another
relying party still verifies. Whether RFC 7519 §4.1.3 should apply to it is left open
in [ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md).

`aka_vcts` (draft-18) is an optional array of *additional* types the issuer asserts
the credential also is. When present it must be a non-empty list of non-empty
strings that does not contain `vct`; when absent, nothing changes.
`expected_vct` stays an exact pin of `vct` — it does **not** match an alias, so a
verifier that asked for `urn:example:eudi:pid` and received
`urn:example:eudi:pid:aendgard:1` with that URN in `aka_vcts` still has to make
that comparison itself.

The pipeline also accepts SD-JWT presentations directly —
`verify_credential(presentation, ...)` detects the format and resolves the
issuer key from `iss` (see
[Resolving issuer keys](Resolving-Issuer-Keys)). A W3C credential that has no `iss` is
resolved from its VCDM `issuer` instead
([below](#the-issuer-when-a-w3c-credential-has-no-iss)).

**What `key_bound` attests.** `key_bound=True` means a KB-JWT was present,
verified against the credential's `cnf` key over the disclosures you received, and
within the freshness window above. Its `aud` and `nonce` are checked against the
values **you pass**, and they bind it only **together** (RFC 9901 §7.3 step 5.6).
With the default `require_key_binding=False`:

| you pass | a KB-JWT is present | no KB-JWT |
|---|---|---|
| `audience` **and** `nonce` (non-empty strings) | both must match, else `ClaimsInvalid`; `key_bound=True` means bound to you | verifies, `key_bound=False` |
| only one of them, or an empty one | **`ClaimsInvalid`**, before any KB-JWT crypto runs | verifies, `key_bound=False` |
| neither | `key_bound=True`, but that is **possession only**: the key signed for *some* verifier, not a binding to you | verifies, `key_bound=False` |

With `require_key_binding=True`, every cell except the first one fails with
`ClaimsInvalid`: it refuses to run without both values, and it refuses a presentation
with no KB-JWT.

A single value is not a binding. `aud` alone accepts a KB-JWT from another of
your own sessions, and `nonce` alone accepts one made for another verifier. An empty
value binds nothing either: `nonce=""` would accept any KB-JWT the holder signed with
an empty nonce. So openvc refuses rather than report a half-checked `key_bound=True`,
and a KB-JWT is never checked against just one of the two values. With no KB-JWT,
`audience` alone stays a valid policy, which matters because
`VerificationPolicy.audience` also pins a VC-JWT's `aud`.

That refusal stops a misleading flag; it does not make the KB-JWT **required**. A
presentation with its KB-JWT stripped still verifies with `key_bound=False`, whatever
you passed. If you need the holder binding, set `require_key_binding=True` (with both
values) or check `key_bound is True`. An SD-JWT VC nested in a `jwt_vc_json` / `ldp_vc`
presentation gets its `aud` / `nonce` from that presentation. A KB-JWT bound
anywhere else rejects the whole response — see
[SD-JWT VCs nested in a W3C presentation](Presentations#sd-jwt-vcs-nested-in-a-w3c-presentation).

### X.509 (`x5c`) issuer trust

An issuer anchored on a trusted list (eIDAS / EUDI) can carry its certificate chain in the
SD-JWT VC header — `suite.issue(..., x5c=[<base64 DER>, …])`, leaf first — so a verifier
chains it to its anchors and binds the leaf to `iss` in one call:

<!-- docs: no-run -->
```python
sd_jwt = suite.issue(
    {"iss": "https://issuer.example", ...}, signing_key=issuer, vct=VCT, x5c=x5c_chain)
result = verify_credential(sd_jwt, x5c_trust_anchors=[root])   # chains x5c -> root, binds iss
```

The leaf certificate's key must be the issuer's signing key and `iss` must appear in the
leaf's Subject Alternative Name, or verification fails closed (see [Trust anchors](Trust)).

## Type Metadata (`vct` + `vct#integrity`)

An issuer can pin the credential type's published
[Type Metadata](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
document with `vct#integrity`; the verifier resolves the document, checks the
hash, and validates the disclosed claims against the type's `claims` metadata
(paths + `mandatory`):

```python
import base64
import hashlib
import json

from openvc.keys import Ed25519SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.type_metadata import validate_type_metadata

VCT = "https://credentials.example.com/education_credential/v1"
type_metadata = {
    "vct": VCT,
    "name": "Example Education Credential",
    "claims": [
        {"path": ["name"], "sd": "always", "mandatory": True},
        {"path": ["degree"], "sd": "always"},
    ],
}
metadata_bytes = json.dumps(type_metadata).encode()
integrity = "sha256-" + base64.b64encode(hashlib.sha256(metadata_bytes).digest()).decode()

issuer = Ed25519SigningKey.generate(kid="https://issuer.example#key-1")
holder = Ed25519SigningKey.generate(kid="holder-key-1")
suite = SdJwtVcProofSuite()
issued = suite.issue(
    {"iss": "https://issuer.example", "vct#integrity": integrity,
     "name": "Ada Lovelace", "degree": "Mathematics"},
    signing_key=issuer, vct=VCT, disclosable=["name", "degree"],
    holder_jwk=holder.public_jwk())

verified = suite.verify(issued, public_key_jwk=issuer.public_jwk())
result = validate_type_metadata(
    verified.claims, vct=verified.vct,
    vct_integrity=verified.claims.get("vct#integrity"),
    resolve=lambda url: {VCT: metadata_bytes}[url])   # in-memory; real: fetch by URL
print(result.documents[0]["name"], [c["path"] for c in result.claims])
```

In production, resolve Type Metadata over the network with the SSRF-guarded
default — `openvc.resolvers.default_type_metadata_resolver` — instead of the
in-memory lambda above.

## W3C credentials secured as SD-JWT (`vc+sd-jwt`)

The same suite verifies a W3C VCDM credential secured with SD-JWT, as defined by
[VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) §3.2, either bare or inside an
`EnvelopedVerifiableCredential` (`data:application/vc+sd-jwt,…`). Such a credential
**is** the JWT claim set, with `@context`, `issuer`, `validFrom` and so on at the top
level. Its `exp` dates the signature, not the data: §3.1.3 says so for the JOSE
encoding SD-JWT builds on. An issuer may therefore
put the expiry only in `validUntil`, and openvc enforces it just as the VC-JWT lane
does:

- `validFrom` / `validUntil`, or the VCDM 1.1 `issuanceDate` / `expirationDate`, are
  checked on the processed payload, with the current time and the suite leeway. They
  must not be selectively disclosable: a presented disclosure of one is refused
  (`SdJwtError`), because a holder could just as well have withheld it (see
  [below](#validity-claims-are-never-disclosable)).
- A past `validUntil` raises `CredentialExpired`, and a future `validFrom` raises
  `CredentialNotYetValid`. A present but unparseable value raises
  `MalformedTimestamp`.
- `require_not_expired=False` (or `check_temporal=False` on the suite) waives only
  the expiry, and the result reports `expired=True`.
- The JWT `exp` / `nbf` are still enforced as well.
- With `require_key_binding=True`, the window is checked after the KB-JWT, so an
  expiry verdict still means the presentation was bound.

Its body must also agree with the JWT claims, with the same rules as the VC-JWT lane.
VC-JOSE-COSE §4.1.2 says `iss`, if present, MUST match `issuer` (or `issuer.id`). For
`jti` / `id` and `sub` / `credentialSubject.id`, §3.1.3 (non-normative) only advises
against conflicts, but openvc enforces them as policy, as it does on VC-JWT. A
conflict raises `ClaimsInvalid`. Every identifier a present `issuer` carries must be
`iss`: the string itself, or an object's `id` and `@id`. A null, empty or non-string
one is rejected, not skipped. An object with no `id` identifies no one, and is
accepted like an absent `issuer` when the token has an `iss`. A token with no `iss` is
different: its `issuer` is then the issuer, and an object that names no one leaves
nothing to resolve, so it is refused
([below](#the-issuer-when-a-w3c-credential-has-no-iss)). Without this check, an attacker
could sign with its own key (`iss` = the attacker) and name a university as `issuer`. `result.issuer` would then
be the attacker and `result.credential["issuer"]` the university. The check reads the
processed payload, so a disclosed `issuer` counts too. Neither the expiry waiver nor
key binding changes it.

`VerificationPolicy.expected_types` applies as well. It works as on VC-JWT and Data
Integrity, and is required by §5.4 ("claims that are understood MUST be evaluated").
A missing type raises `TypeMismatch`, and so does a withheld or malformed `type` on a
`dc+sd-jwt` with a VCDM `@context`, which has no type rule of its own. A `vc+sd-jwt`, a
`vc+ld+json+sd-jwt` or a token with no `typ` never gets that far with a `type` that is
missing, withheld or malformed, or with a `@context` that does not start with a base
context: the two tests below refuse it first, as `SdJwtError`, even when its `type` names
the pinned type. So `TypeMismatch` there means a payload that passed both tests and lacks
the expected type. That is less than a validated credential: the tests below list what
they leave out.

openvc applies the VCDM rules to a payload when the issuer signed a VCDM base context
into it, and only then:

| Signal | Example |
|---|---|
| The payload's `@context` names a VCDM base context, as a string or anywhere in the array | `"@context": ["https://www.w3.org/ns/credentials/v2", …]` (or `…/2018/credentials/v1`) |

That signal is deliberately lax. It is what turns on the validity window and the
`issuer` / `id` / `sub` checks above, and what `result.raw.vcdm` reports, whatever the
`typ`. For a `dc+sd-jwt` it is the only test: a base URL in second place switches the
window on, and a holder who withholds a disclosable `type` cannot shape the payload out
of it. For the three W3C rows below it is only the first step, since **being read as a
W3C credential** takes more, and the `typ` is not part of it either. `verify()` takes a
closed set of issuer JWT `typ` values, matched exactly, and a token with no `typ` at all:

| Issuer JWT `typ` | Accepted for |
|---|---|
| `dc+sd-jwt` | an IETF SD-JWT VC, which needs a `vct` (below) |
| `vc+sd-jwt` | a payload that conforms to the VCDM (below), and nothing else (VC-JOSE-COSE §6.1.3) |
| `vc+ld+json+sd-jwt` | the same: the draft-era name of that media type |
| none (no `typ` member) | the same, and the token must not carry a `vc` or `vp` claim |

The last two rows exist because the W3C Recommendation (13 October 2026) makes the
SD-JWT `typ` a SHOULD (§3.2.1), and its verification algorithm (§5.2) takes the media
type as an input rather than reading it from the token. Its own examples show it:
Examples 4 and 5 carry no `typ`, and Example 21 carries `vc+ld+json+sd-jwt` inside a
`data:` URI typed `application/vc+sd-jwt`. That is the name the 2023 Working Drafts and
the First Candidate Recommendation (25 April 2024) gave the media type before the rename
to `vc+sd-jwt`. Before 1.34.0 `verify()` refused both at the `typ` check (`unexpected
issuer JWT typ`), so a credential built like those examples could not verify. (Example
5's payload also carries no `iss`, and `verify()` used to require one. It no longer does
for a W3C credential:
[below](#the-issuer-when-a-w3c-credential-has-no-iss).)

All three W3C rows are accepted **only** for a payload that conforms to the VCDM, and
that payload gets the VCDM validity window and the `issuer` / `id` / `sub` checks above.
Two tests decide it, on the processed payload (the issuer-signed claims plus the
disclosures presented), and a payload that fails either raises `SdJwtError`:

1. **The first `@context` entry is a VCDM base context**, `https://www.w3.org/ns/credentials/v2`
   or the 1.1 `https://www.w3.org/2018/credentials/v1` (VCDM 2.0 §4.3: an ordered set whose
   first item is the base URL). A string `@context` is its own first item. A base URL in
   second place or later, an object, a number or an empty array in first place, and any
   other URL in first place all fail. The error reads ``issuer JWT typ 'vc+sd-jwt' needs a
   VCDM base context as the first `@context` entry (VCDM 2.0 §4.3), not just somewhere in
   it``.
2. **The `type` says credential**: a string or an array that includes
   `VerifiableCredential` and not `VerifiablePresentation` (§4.5, §4.13). Only the compact
   term counts, and an entry that is not a string is ignored. A `type` that is missing,
   withheld, or spelled as a full IRI or a prefixed name fails. The error reads ``issuer JWT
   typ 'vc+sd-jwt' needs a `type` that includes VerifiableCredential and not
   VerifiablePresentation (VCDM 2.0 §4.5, §4.13)``.

These are the only two tests, and "conforms" on this page means them and nothing more. The
gate does **not** check that:

- a `type` that lists `VerifiableCredential` next to an entry that is not a string
  (`["VerifiableCredential", {"a": 1}]`, `["VerifiableCredential", 7]`) is well formed: the
  entry is ignored, and the `type` passes;
- a `VerifiablePresentation` spelled as a full IRI is a presentation: only the compact term
  is recognised;
- the second and later `@context` entries are known contexts: both base contexts
  (`[…/v1, …/v2]`) are accepted, and so is any URL or object after the first entry;
- `issuer` or `credentialSubject` is there (a present `issuer` is reconciled with `iss`, as
  above).

A payload that passes was signed by the issuer with a base context first and a credential
`type`. It is not a validated VCDM credential.

For `vc+ld+json+sd-jwt` the message shows `typ 'vc+ld+json+sd-jwt'`, and for a token with
no `typ` it shows `without a typ`. The context test runs first, so a payload that fails
both reports the context. Two older refusals come before the two tests, in this order. A
payload with no base context anywhere gets `issuer JWT typ 'vc+sd-jwt' needs a W3C VCDM
@context; an IETF SD-JWT VC is typed 'dc+sd-jwt'` (and `issuer JWT without a typ needs a
W3C VCDM @context` for a token with no `typ`). Then, for a token with no `typ` only, a `vc`
or `vp` claim gets its own message: ``issuer JWT without a typ must not carry a `vc` or
`vp` claim (VC-JOSE-COSE §3.1.3)``. Before 1.34.0 the base URL anywhere in `@context` was
the whole test for a typed token, so a `vc+sd-jwt` with it in second place, or with no
`type`, verified as a W3C credential (#275). `dc+sd-jwt` is unchanged by
this: it has no `type` rule and no context-position rule (below). An IETF SD-JWT VC is
typed `dc+sd-jwt`.

The tests run after the signature, the JWT `exp` / `nbf`, the issuer identifier (the
`iss` claim, or the `issuer` that stands in for it when there is none) and, with
`require_key_binding=True`, the KB-JWT, and before the later checks: the VCDM validity
window, the `issuer` reconciliation, `expected_vct` and
`aka_vcts`, a KB-JWT checked on the optional path, and, through `verify_credential`,
status and `expected_types`. So a payload that fails them reports `SdJwtError` where a
conforming one would report `CredentialExpired`, `CredentialNotYetValid`, `ClaimsInvalid`,
`CredentialRevoked`, `StatusUnavailable` or `TypeMismatch`, and an expired `validUntil` is
refused even under `require_not_expired=False`. In OpenID4VP such a token nested in a
`jwt_vc_json` or `ldp_vc` presentation fails the whole `verify_vp_token` call with that
`SdJwtError`, as the older refusals above already did.

The IETF drafts used `vc+sd-jwt` until draft-06 renamed it, but
draft-ietf-oauth-sd-jwt-vc-19 dropped the transitional acceptance of it, so a
`vct`-bearing IETF payload still typed `vc+sd-jwt` is refused too, and so is one with the
draft-era name or no `typ`: re-issue it as `dc+sd-jwt`. Before 1.33.0 the typ alone made
a payload with no `vct` VCDM, which let a token without the REQUIRED `vct`, or one whose
`vct` the holder had withheld, verify as a W3C credential.

A `typ` that is **present** and anything else raises `SdJwtError` (`unexpected issuer
JWT typ …`) before the signature is checked: `null` or any other non-string, a string
outside the table, or another spelling of one in it (a different case, surrounding
whitespace, an `application/` prefix). Only a missing member counts as "no `typ`"; an
explicit `null` does not.

A token with no `typ` must also not carry a `vc` or `vp` claim, a presented disclosure
of one included (`SdJwtError`). VC-JOSE-COSE §1.1.2.1 (restated in §3.1.3) forbids both
names in a JWT Claims Set, and for `vc` there is a second reason. The VC-JWT lane refuses any JWS typed `*+sd-jwt`
(#189), so it never takes a typed SD-JWT issuer JWT for a VC-JWT, but it has no `typ` to
refuse in a token without one: one whose payload held a `vc` object would also verify
there once its `~` tail is dropped, with no key binding. Refusing it here keeps the two
lanes apart, since without a `vc` claim the VC-JWT lane rejects the stripped token
(`ClaimsInvalid`: no embedded `vc` object). The ban applies to a missing `typ` only. A
token typed `vc+sd-jwt` or `vc+ld+json+sd-jwt` that carries a `vc` claim is not refused
by it.

The ban cannot help a token this lane never sees, and the VC-JWT lane does not rely on
it. Since 1.34.0 (#291) that lane refuses a JWS whose payload carries an SD-JWT marker at
any depth (`MalformedToken`): a member named `_sd` or `_sd_alg`, or an array-element
digest object `{"...": …}`. So an issuer JWT with no `typ` and a `vc` object, which
before 1.34.0 verified as a VC-JWT with its tail dropped, is refused there whenever it
has a disclosure, since a disclosure needs a digest and a digest is a marker.
**Limit:** a zero-disclosure issuer JWT with no `typ`, a `vc` object and a `cnf` carries
none of `_sd`, `_sd_alg` or `"..."` (an `_sd_alg` alone, or a decoy digest, is already
refused), so it cannot be told from a VC-JWT that carries a `cnf`. It still verifies there,
and that lane never enforces `cnf` ([VC-JWT](VC-JWT)).

The `type` test (second above) has two reasons. With no `typ` it is what tells a
credential from a presentation: a VCDM 2.0 presentation secured with SD-JWT has the same
`@context` as a credential and no `vp` claim to ban, so without it a holder-signed
presentation with no `typ` would be read as a credential issued by the holder (#293). With
`vc+sd-jwt` or `vc+ld+json+sd-jwt` the `typ` does say credential, but since 1.34.0 the
payload has to agree (#275): before, a typed token with no `type` verified as a W3C
credential. The test is positive: a `type`, or its
`VerifiableCredential` entry, that is missing or withheld is refused, and so is one that
spells the term as a full IRI or a prefixed name (only the compact `VerifiableCredential`
counts).

**Who must not do what.** The W3C Recommendation's Example 4 makes `type` a selectively
disclosable claim, and a verifier cannot tell a withheld disclosure from a decoy (RFC 9901
§9.7). So a holder that withholds the `type` disclosure of a W3C token gets `SdJwtError`,
typed or not: the credential no longer says what it is. An issuer should leave `@context`
and `type` in the clear, with the v2 base context first, and keep `type` out of
`disclosable`. `issue()` does not refuse a disclosable `type`, as it does `@context`: it
mints only `dc+sd-jwt`, where no `type` rule applies, so this advice is for issuers that
mint W3C-typed tokens with other tools. A `dc+sd-jwt` is untouched: it needs no `type`.

The tests judge the processed payload, so an array element of `@context` or `type` that
the issuer made selectively disclosable (not the whole claim: a withheld `type` or
`@context` is refused) lets the verdict depend on what the holder presents. A withheld
`VerifiablePresentation` element leaves a `type` that passes, and a withheld
`VerifiableCredential` element one that fails. A presented element of `@context` is itself
refused (a sub-claim of `@context` is selectively disclosed), while a withheld one can
leave a first entry that passes. Every flip to accepted needs the signer to have made that
element disclosable. `vcdm` stays true either way, so the validity window and the
consistency checks still run.

**What this gives up.** A token with no `typ` has no explicit-typing guard (RFC 9901
§9.11): for a VCDM payload the header no longer says the JWT is an SD-JWT. What stands in
for it is the VCDM `@context` the issuer signed (a disclosed one is refused, and a
withheld one leaves the payload not VCDM, so the token is refused), the `type` check, the
`vc` / `vp` ban, `require_key_binding=True` still needing a KB-JWT, and the VC-JWT lane's marker fence. An
IETF SD-JWT VC is unaffected: it is recognised by `dc+sd-jwt` alone, and a token with no
`typ` is never read as one. If your issuers always set a `typ` and you want to insist on
it, reject an `sd-jwt-vc` result whose `result.raw.typ` is `None` (`result.raw` is a
`VerifiedSdJwt` only for that format).

A `dc+sd-jwt` always needs a non-empty string `vct` (`ClaimsInvalid` otherwise),
**even when its payload carries a VCDM `@context`**. draft-ietf-oauth-sd-jwt-vc-19
§2.2.1 says that typ means the payload follows the SD-JWT VC rules, and §2.2.2.3 makes
`vct` REQUIRED. One that carries both a `vct` and a VCDM `@context` still verifies, and
the VCDM validity window and the `issuer` / `id` / `sub` consistency checks above apply
to it as well (`vcdm=True`), with the base URL anywhere in `@context`. It needs no
`type`: the conformance tests above are not applied to it. A `vc+sd-jwt` or
`vc+ld+json+sd-jwt` token, or one with no `typ`, needs no `vct`: it is typed by `type`.
Before 1.33.0 a VCDM `@context` waived the `vct` whatever the typ, so a `dc+sd-jwt`
with no `vct`, or with one the holder had withheld, verified as `vcdm=True, vct=None`.

A `dc+sd-jwt` with no VCDM `@context` is an IETF SD-JWT VC pure and simple. Its claims
are the issuer's own vocabulary, so a claim that happens to be named `validUntil` is
not a validity bound: it is not enforced and not reported as `expired`. Its `exp` /
`nbf` remain the temporal gate. The `data:` media type of an enveloping credential is
not consulted either, because it sits outside the issuer's signature.

Likewise, an IETF SD-JWT VC's claims named `issuer`, `id` or `credentialSubject` are
not reconciled with `iss`, `jti` or `sub`. Such a credential may legitimately name,
say, the authority behind an underlying document. On every lane, the authenticated
issuer is **`result.issuer`**, the verified `iss` (or, for a W3C credential with no `iss`,
the `issuer` whose key verified). Never read it from `result.credential`.
`result.raw.vcdm` (`VerifiedSdJwt.vcdm`) tells you which rules the suite applied. It is the lax base-URL test, so it says nothing about the position of
the base URL, and it is always `True` for a token that passed under a W3C `typ`.
`result.raw.typ` (`VerifiedSdJwt.typ`) is the issuer JWT `typ` that was verified:
`dc+sd-jwt`, `vc+sd-jwt` or `vc+ld+json+sd-jwt`, or `None` when the token
had no `typ` (and on an object that did not come from `verify()`). Check it when you
must tell an IETF SD-JWT VC from a W3C credential: `vcdm` alone does not, because a
`dc+sd-jwt` with a VCDM `@context` is `vcdm=True` too. `dc+sd-jwt` is the IETF SD-JWT
VC, and anything else `verify()` returns passed the two tests above (a base context
first, a credential `type`), which is less than a validated VCDM credential. The OpenID4VP
`dc+sd-jwt` lane reads it for you, and refuses the draft-era name and a missing `typ` as it does
`vc+sd-jwt` ([Presentations](Presentations#openid4vp-10-verify_vp_token)).

**`expected_types` rejects an IETF SD-JWT VC.** Such a credential is typed by `vct`,
so a policy that sets `expected_types` raises `TypeMismatch` that points at
`expected_vct`. It no longer verifies as if the pin were met. Before 1.31.0 the SD-JWT
lane ignored `expected_types` entirely: a policy that asked for a
`UniversityDegreeCredential` accepted any SD-JWT VC. Rejecting is also what keeps the
pin holder-proof. If a third-party issuer makes the `@context` of a `dc+sd-jwt` VCDM
credential disclosable (openvc refuses to, and rejects a presented one), a holder who
withholds it turns the payload into a non-VCDM one, and ignoring the pin there would
bypass it. To verify both kinds under one pin, use one
policy per format: `expected_types` for W3C credentials and `expected_vct` for IETF
SD-JWT VCs. An empty or unset `expected_types` constrains nothing, as on every lane.
A presentation verified under one policy, such as `VpJwtProofSuite.verify(...,
policy=...)`, applies that policy to every credential it carries. So if the policy sets
`expected_types` and the presentation mixes an IETF SD-JWT VC with a W3C credential,
the whole presentation is rejected. Leave `expected_types` unset there and check each
`result.credentials` entry yourself.

### The issuer when a W3C credential has no `iss`

VC-JOSE-COSE makes the JWT `iss` claim optional. §4.1.2 says that `iss`, if present, MUST
match `issuer` (or `issuer.id`), and §4.2 says that when `iss` is absent and the issuer
is a URL, the `kid` MUST be an absolute URL to a verification method in the issuer's
controlled identifier document or DID document. openvc takes the identifier from `issuer`
and resolves it with the same paths as `iss`. The Recommendation's own SD-JWT credential
(Examples 4 and 5) has an `issuer` and no `iss`. Before 1.34.0 every SD-JWT lane needed an `iss` to
choose the issuer key, so such a credential was refused before any key was looked up.

Now the issuer is taken from `issuer` when all of these hold, and in no other case:

- the issuer JWT's `typ` is one of the three W3C states (none, `vc+sd-jwt`,
  `vc+ld+json+sd-jwt`). A `dc+sd-jwt` keeps requiring `iss`. A header `"typ": null` is a
  `typ` that is *present*, not an absent one, and it is not a state: no fallback, and
  `verify()` refuses it as a `typ` anyway;
- the issuer JWT has **no `iss` member at all**. A present `iss` that is `null`, a number,
  a bool, an object or an empty string is still refused, never replaced by `issuer`;
- the `issuer` is in the issuer JWT's own signed claims. A disclosure is never consulted,
  so an `issuer` the holder reveals cannot choose the key, and a token whose only `issuer`
  is a disclosure is refused;
- the `issuer` is a non-empty string, or an object whose `id` and `@id` members, the ones
  that are present (`id` is an alias of `@id`), are all the same non-empty string. An
  object with neither, one whose two members disagree, a number and an empty string name
  no one, and the token is refused.

`peek_issuer` then returns that string as its first item, and the pipeline resolves the key
from it exactly as it does from `iss`: the DID methods, the `/.well-known/jwt-vc-issuer`
metadata of an https issuer, or an `x5c` chain bound to it. There is no new resolution path.
`result.issuer` is that identifier, the one whose key verified. When the token has both, they
must still agree (`ClaimsInvalid`, as above).

What a caller sees for such a token:

- **There is no `iss` in the claims.** `result.claims`, `result.credential` and
  `result.raw.claims` (`VerifiedSdJwt.claims`) hold the signed claims and the disclosures
  as they are, so they have no `iss` member, and code that reads `result.claims["iss"]`
  gets a `KeyError`. Before 1.34.0 every SD-JWT that verified had a string `iss` there.
  The issuer is `result.issuer` (or `result.raw.issuer`), the identifier above, as it is for
  every other token.
- **An https `issuer` goes through `jwt_vc_issuer_fetch`, as an https `iss` does.** Without
  that argument the pipeline raises `KeyResolutionFailed` (`pass jwt_vc_issuer_fetch`). For
  the Recommendation's Example 5 as published, whose issuer is an https URL, that is the first
  thing a caller sees: it used to be `MalformedToken` ("no iss in the issuer-signed JWT") at
  the peek. A payload with no `typ`, a `vct` and a claim that happens to be called `issuer`
  (an IETF-shaped payload that forgot its `typ`) changes in the same way. It is still
  refused, but at `verify()` as `SdJwtError` ("needs a W3C VCDM @context; an IETF SD-JWT VC
  is typed 'dc+sd-jwt'") and no longer at the peek as `MalformedToken`, so a key is resolved
  first, and for an https `issuer` its metadata is fetched, before the refusal.
- **`verify()` refuses an empty `iss` too.** Until now only the pipeline's `peek_issuer` did,
  so the suite called on its own accepted `iss: ""` and reported `issuer == ""` (a W3C body
  with an `issuer` failed the `iss` / `issuer` reconciliation instead). It is now a
  `ClaimsInvalid` ("iss claim is missing or not a string") for every `typ`, a `dc+sd-jwt`
  included.

Like `iss`, the `issuer` is **unauthenticated until the signature verifies**. Whoever builds
a token names whatever issuer they like; the key resolved for that name has to verify the
signature, and `result.issuer` is the name of that key. Read the issuer from `result.issuer`
here too, not from `result.credential`.

A token like Example 5 verifies offline when its issuer is a DID (the token is minted by hand
here because `issue()` writes a `dc+sd-jwt` that needs an `iss`):

```python
import base64
import json

from openvc import verify_credential
from openvc.keys import P256SigningKey


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


key = P256SigningKey.generate(kid="issuer-key")
did = "did:jwk:" + b64(json.dumps(key.public_jwk()).encode())

# The issuer is named in `issuer` only: no `iss` claim, and no `typ` header.
claims = {"@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:123"}}
header = {"alg": "ES256", "kid": f"{did}#0"}
signing_input = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
token = signing_input + "." + b64(key.sign(signing_input.encode("ascii"))) + "~"

result = verify_credential(token)
assert result.format == "sd-jwt-vc" and result.issuer == did
assert "iss" not in result.claims            # the issuer is result.issuer, not claims["iss"]
```

The Recommendation's Example 5 itself is issued by `https://university.example/issuers/565049`.
`verify_credential` fetches the issuer metadata for that URL
(`https://university.example/.well-known/jwt-vc-issuer/issuers/565049`), through your
`jwt_vc_issuer_fetch`, and looks the key up by the token's `kid`. The Recommendation publishes
no key, so a stranger's key fails at the signature (`SignatureInvalid`), and the token verifies
only under a key of your own, with its header, payload and disclosures as published and no
`iss` added.

What this does not do:

- It does not take the issuer from `kid`. A token with no `iss` and no usable `issuer` is
  refused even when its `kid` is a DID URL.
- It does not relax `dc+sd-jwt` (an IETF SD-JWT VC still needs `iss`, and an issuer named
  only by an `x5c` header is still refused), and it does not change `issue()`.
- The refusals keep their classes (`MalformedToken` from `peek_issuer`, `ClaimsInvalid` from
  `verify()`) and their texts. The clause ``(and no usable VCDM `issuer` for a W3C
  credential)`` is appended to them, giving
  ``no iss in the issuer-signed JWT (and no usable VCDM `issuer` for a W3C credential)`` and
  ``iss claim is missing or not a string (and no usable VCDM `issuer` for a W3C credential)``,
  **only when the fallback was available**: the issuer JWT has no `iss` member and its `typ`
  is a W3C state, so that the clause tells the caller that `issuer` was tried. A present
  but unusable `iss` (`null`, `""`, a number, a bool, an object), a `dc+sd-jwt`, a
  `"typ": null` and any other `typ` get the bare text.

Known limits of the fallback:

- **The issuer JWT's own `aud` is not checked on this lane.** That is an open item of
  [ADR-0008](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0008-jose-temporal-and-audience.md)
  (RFC 7519 §4.1.3 on SD-JWT VC): a token with `aud=https://other-rp.example` verifies for
  any verifier, and for a caller that passes `policy.audience` too. What the fallback adds
  is a way in: a W3C credential secured as a plain JWS (VC-JOSE-COSE) that has no `iss`
  and no `typ` is refused as a bare JWS on the VC-JWT lane (no issuer to resolve), but
  verifies here once `~` is appended, so an audience restriction its issuer put in `aud`
  is not enforced. (With an `iss` that was already so for a JWS with no `typ`.) If you
  rely on it, read `result.claims.get("aud")` and compare it yourself.
- **The `kid` rule of §4.2 is not enforced.** The Recommendation says that for an `iss`-less
  token the `kid` is an absolute URL to a verification method. Example 5's `kid` is a bare
  thumbprint, and it is used as before, to pick the key out of the issuer's own document
  (a DID's verification methods, matched by id or by fragment) or published JWKS. That is
  fail-safe: the resolver is only ever asked about the issuer, and a `kid` that names
  another DID selects nothing of that DID. It is matched, by its fragment, against the
  issuer's own keys. Signed with the other DID's key the token fails with
  `SignatureInvalid`, and a fragment the issuer lacks, or an absolute URL without one, is a
  `KeyResolutionFailed`.
- **The subject comes from `sub` alone.** For an SD-JWT result, `result.subject` is the
  `sub` claim, never `credentialSubject.id`. So `require_holder_binding=True` on a
  `jwt_vc_json` or `ldp_vc` presentation ([Presentations](Presentations)) refuses a
  fallback token that names its subject only in `credentialSubject.id`, because
  `result.subject` is `None`. That is how every SD-JWT result already behaved, with or
  without `iss`, and it fails closed.

## Validity claims are never disclosable

A holder can withhold any disclosure, and a verifier cannot tell a withheld
disclosure from a decoy (RFC 9901 §9.7). So a disclosable `exp` or `status` lets
the holder present an expired or revoked credential as one that never expires and
has no status. `issue()` therefore raises `SdJwtError`, before it signs anything,
when `disclosable` names one of these claims:

| Refused in `disclosable` | Why |
|---|---|
| `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status` | draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: they, "including any of their sub-claims", MUST NOT be selectively disclosed |
| `credentialStatus` | openvc enforces a W3C status pointer on SD-JWT too, exactly like `status` |
| `@context` | it is what makes the payload VCDM, which switches on the VCDM validity window and the `issuer` / `id` / `sub` consistency checks |
| `validFrom`, `validUntil`, `issuanceDate`, `expirationDate` | only when `@context` makes the payload VCDM: the validity window openvc enforces there |

`sub`, `iat` and every other claim stay disclosable, and the issued token is
byte-for-byte what it was before. The guard covers what `disclosable` produces:
digests you write into `claims` yourself (an `_sd` array of your own) are signed
as given. On an IETF SD-JWT VC a claim merely *named*
`validUntil` means nothing, so it may be disclosed.

<!-- docs: no-run -->
```python
suite.issue(claims, signing_key=issuer, disclosable=["given_name", "exp"])
# SdJwtError: claim 'exp' must not be selectively disclosable (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3): ...
```

### Credentials from other issuers

`verify()` rejects (`SdJwtError`) a presentation that **presents** a disclosure
of one of those claims, or of any sub-claim of one: `cnf.jwk` under a plaintext
`cnf`, `status.status_list`, an element of `aka_vcts` or `credentialStatus`. A
non-conformant issuer then fails visibly instead of only failing open.

It cannot catch the disclosure a holder **withholds**. A credential whose issuer
made `exp` or `status` disclosable still verifies as never-expiring, or with no
status, when the holder leaves that disclosure out. The exceptions are `iss`, which a
token needs in its signed body (a W3C credential may instead carry an `issuer` there to stand
in for it, see [above](#the-issuer-when-a-w3c-credential-has-no-iss)), and `vct`: it is REQUIRED, so a `dc+sd-jwt` that
has no `vct` is rejected (`ClaimsInvalid`), whoever left it out and whatever its
`@context` (a `vc+sd-jwt` or `vc+ld+json+sd-jwt` token, or one with no `typ`, that is not
a conforming VCDM payload is refused outright, as above).
`issue()` likewise requires `vct` to be a non-empty string. One consequence of the `issuer`
fallback: a W3C credential whose issuer made `iss` disclosable, and whose signed body carries
an `issuer`, verifies when the holder withholds the `iss` disclosure, and is identified by that
`issuer`, which the signer wrote into the signed body. A presented `iss` disclosure is still
refused (`SdJwtError`). If you accept SD-JWT VCs
from issuers you do not control and rely on expiry or status, check that the verified
`claims` actually carry them.

The same limit applies to a third-party W3C credential whose `@context` was
disclosable and is withheld (including a VCDM entry that is itself an
array-element disclosure). It no longer counts as VCDM, since the `@context` is the
only signal for the VCDM rules. If it is typed `vc+sd-jwt` or `vc+ld+json+sd-jwt`, or has no `typ`,
`verify()` raises `SdJwtError`, because those need a VCDM `@context`. If it is typed
`dc+sd-jwt`, it needs a `vct` whatever its
`@context`, so one that carries none is rejected (`ClaimsInvalid`). Typed `dc+sd-jwt`
with a `vct`, it verifies as an IETF SD-JWT VC: its window and its `issuer` / `id` /
`sub` consistency are not checked, and a policy that sets `expected_types` rejects it.

A selectively-disclosable `type` is the same case, and the Recommendation's own Example 4
makes one. A holder that withholds it leaves a `vc+sd-jwt`, a `vc+ld+json+sd-jwt` or a
token with no `typ` unable to say it is a credential, so `verify()` raises `SdJwtError`
(#275; it is not skipped, whatever the issuer's `@context` says). A `dc+sd-jwt` has no
`type` rule, and under `expected_types` its withheld `type` is a `TypeMismatch`.

Two claims are deliberately **not** refused:

- `credentialSchema`. Schema validation is opt-in data-shape checking, not a
  gate: `require_schema` fails closed when the resolver is missing, never when
  the schema is. If you need it validated, keep it out of `disclosable` yourself.
  `ecdsa-sd-2023`'s mandatory pointers follow the same logic (see the
  [Security model](Security-Model)).
- `aud`. RFC 9901 §9.7 names it, but the SD-JWT VC draft does not, and this suite
  never reads the issuer JWT's `aud`, so refusing it would enforce nothing.
