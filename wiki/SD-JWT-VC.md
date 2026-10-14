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
[Resolving issuer keys](Resolving-Issuer-Keys)).

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
accepted like an absent `issuer`. Without this check, an attacker could sign with its own key
(`iss` = the attacker) and name a university as `issuer`. `result.issuer` would then
be the attacker and `result.credential["issuer"]` the university. The check reads the
processed payload, so a disclosed `issuer` counts too. Neither the expiry waiver nor
key binding changes it.

`VerificationPolicy.expected_types` applies as well. It works as on VC-JWT and Data
Integrity, and is required by §5.4 ("claims that are understood MUST be evaluated").
A missing type raises `TypeMismatch`, and so does a withheld or malformed `type`.

openvc treats the payload as a VCDM credential when the issuer signed a VCDM base
context into it, and only then:

| Signal | Example |
|---|---|
| The payload's `@context` names a VCDM base context, as a string or anywhere in the array | `"@context": ["https://www.w3.org/ns/credentials/v2", …]` (or `…/2018/credentials/v1`) |

The `typ` is not a signal. `verify()` takes a closed set of issuer JWT `typ` values,
matched exactly, and a token with no `typ` at all:

| Issuer JWT `typ` | Accepted for |
|---|---|
| `dc+sd-jwt` | an IETF SD-JWT VC, which needs a `vct` (below) |
| `vc+sd-jwt` | a payload with a VCDM base `@context`, and nothing else (VC-JOSE-COSE §6.1.3) |
| `vc+ld+json+sd-jwt` | the same: the draft-era name of that media type |
| none (no `typ` member) | the same, and the token must not carry a `vc` or `vp` claim, and its `type` must include `VerifiableCredential` and not `VerifiablePresentation` |

The last two rows exist because the W3C Recommendation (13 October 2026) makes the
SD-JWT `typ` a SHOULD (§3.2.1), and its verification algorithm (§5.2) takes the media
type as an input rather than reading it from the token. Its own examples show it:
Examples 4 and 5 carry no `typ`, and Example 21 carries `vc+ld+json+sd-jwt` inside a
`data:` URI typed `application/vc+sd-jwt`. That is the name the W3C Working Drafts of
August and September 2023 gave the media type before the rename to `vc+sd-jwt`. Before
1.34.0 `verify()` refused both at the `typ` check (`unexpected issuer JWT typ`), so a
credential built like those examples could not verify. (Example 5's payload carries no
`iss`, which `verify()` requires, so that token still cannot verify as published.)

All three W3C rows are accepted **only** for a payload with a VCDM base `@context`, and
that payload gets the VCDM validity window and the `issuer` / `id` / `sub` checks above.
Without one, `verify()` raises `SdJwtError` (`issuer JWT typ 'vc+sd-jwt' needs a W3C
VCDM @context`; likewise for `'vc+ld+json+sd-jwt'`, and `issuer JWT without a typ needs
a W3C VCDM @context` for a token with no `typ`). An IETF SD-JWT VC is typed `dc+sd-jwt`.
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
of one included (`SdJwtError`). VC-JOSE-COSE §3.1.3 forbids both names in a JWT Claims Set, and
for `vc` there is a second reason. The VC-JWT lane refuses any JWS typed `*+sd-jwt`
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
**Limit:** a zero-disclosure issuer JWT with no `typ`, a `vc` object and a `cnf` has no
marker, so it cannot be told from a VC-JWT that carries a `cnf`. It still verifies there,
and that lane never enforces `cnf` ([VC-JWT](VC-JWT)).

A token with no `typ` must also say it is a **credential**: its processed `type` (a string
or an array) has to include `VerifiableCredential` and not `VerifiablePresentation`
(VCDM 2.0 §4.5 and §4.13), or `verify()` raises `SdJwtError` (``issuer JWT without a typ
needs a `type` that includes VerifiableCredential …``). The `typ` is what tells a credential
from a presentation, and a VCDM 2.0 presentation secured with SD-JWT has the same
`@context` as a credential and no `vp` claim to ban, so without this check a holder-signed
presentation with no `typ` would be read as a credential issued by the holder (#293). The
check is positive: a `type`, or its `VerifiableCredential` entry, that is missing or
withheld is refused, and so is one that spells the term as a full IRI or a prefixed name
(only the compact `VerifiableCredential` counts). It applies to a missing `typ` only;
`vc+sd-jwt` and `vc+ld+json+sd-jwt` already name a credential.

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
to it as well (`vcdm=True`). A `vc+sd-jwt` or `vc+ld+json+sd-jwt` token, or one with
no `typ`, needs no `vct`: it is typed by `type`.
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
issuer is **`result.issuer`**, the verified `iss`. Never read it from
`result.credential`. `result.raw.vcdm` (`VerifiedSdJwt.vcdm`) tells you which rules
the suite applied. `result.raw.typ` (`VerifiedSdJwt.typ`) is the issuer JWT `typ` that
was verified: `dc+sd-jwt`, `vc+sd-jwt` or `vc+ld+json+sd-jwt`, or `None` when the token
had no `typ` (and on an object that did not come from `verify()`). Check it when you
must tell an IETF SD-JWT VC from a W3C credential: `vcdm` alone does not, because a
`dc+sd-jwt` with a VCDM `@context` is `vcdm=True` too. `dc+sd-jwt` is the IETF SD-JWT
VC, and anything else `verify()` returns is a VCDM payload. The OpenID4VP `dc+sd-jwt`
lane reads it for you, and refuses the draft-era name and a missing `typ` as it does
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
| `@context` | it makes the payload a W3C VCDM credential, which switches on the VCDM validity window and the `issuer` / `id` / `sub` consistency checks |
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
status, when the holder leaves that disclosure out. The exceptions are `iss`,
without which nothing verifies, and `vct`: it is REQUIRED, so a `dc+sd-jwt` that
has no `vct` is rejected (`ClaimsInvalid`), whoever left it out and whatever its
`@context` (a `vc+sd-jwt` or `vc+ld+json+sd-jwt` token, or one with no `typ`, that is not
a VCDM payload is refused outright, as above).
`issue()` likewise requires `vct` to be a non-empty string. If you accept SD-JWT VCs
from issuers you do not control and rely on expiry or status, check that the verified
`claims` actually carry them.

The same limit applies to a third-party W3C credential whose `@context` was
disclosable and is withheld (including a VCDM entry that is itself an
array-element disclosure). It no longer counts as VCDM, since the `@context` is the
only signal. If it is typed `vc+sd-jwt` or `vc+ld+json+sd-jwt`, or has no `typ`,
`verify()` raises `SdJwtError`, because those need a VCDM `@context`. If it is typed
`dc+sd-jwt`, it needs a `vct` whatever its
`@context`, so one that carries none is rejected (`ClaimsInvalid`). Typed `dc+sd-jwt`
with a `vct`, it verifies as an IETF SD-JWT VC: its window and its `issuer` / `id` /
`sub` consistency are not checked, and a policy that sets `expected_types` rejects it.

Two claims are deliberately **not** refused:

- `credentialSchema`. Schema validation is opt-in data-shape checking, not a
  gate: `require_schema` fails closed when the resolver is missing, never when
  the schema is. If you need it validated, keep it out of `disclosable` yourself.
  `ecdsa-sd-2023`'s mandatory pointers follow the same logic (see the
  [Security model](Security-Model)).
- `aud`. RFC 9901 §9.7 names it, but the SD-JWT VC draft does not, and this suite
  never reads the issuer JWT's `aud`, so refusing it would enforce nothing.
