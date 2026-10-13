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
not-yet-valid. A temporal failure (`ClaimsInvalid` matching `expired` / `not yet
valid`) from that call therefore means the presentation was **bound**; a key-binding
failure (wrong `aud`/`nonce`, a stale or future-dated KB-JWT, missing KB-JWT, or
`SignatureInvalid` on the KB) means it was unbound — do not treat `EXPIRED` as proof
of holder binding. The hosted path (`require_key_binding=False`) is unchanged: expiry
still fails before any KB check.

**KB-JWT freshness.** RFC 9901 makes the KB-JWT `iat` REQUIRED (§4.3) and has the
verifier check it is "within an acceptable window" (§7.3 step 5.5). openvc requires
it, refuses a non-numeric or non-finite one, and refuses a KB-JWT older than
`kb_max_age_s` — default `DEFAULT_KB_MAX_AGE_S`, 300 seconds — plus the leeway, or
dated in the future beyond the leeway. Any KB-JWT that is present is held to it,
whether or not binding was required. These are binding failures (`KB-JWT is too
old`, `KB-JWT iat is in the future`), never an `expired` verdict, so
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
presentations. (The issuer JWT's `exp`/`nbf` still use the current time, as on every
JOSE suite.)

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
  checked on the processed payload. That is after the disclosures are applied, so a
  disclosed `validUntil` counts. The check uses the current time and the suite
  leeway.
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

openvc treats the payload as a VCDM credential when the issuer signed either of
these:

| Signal | Example |
|---|---|
| The payload's `@context` names a VCDM base context, as a string or anywhere in the array | `"@context": ["https://www.w3.org/ns/credentials/v2", …]` (or `…/2018/credentials/v1`) |
| The `typ` is `vc+sd-jwt` and the payload has no `vct` (a non-empty string) | a W3C issuer that omitted `@context`, or made it disclosable and the holder withheld it |

An **IETF SD-JWT VC is not affected**: a `dc+sd-jwt` one, or one with the legacy
`vc+sd-jwt` typ and a `vct`. Its claims are the issuer's own vocabulary, so a claim
that happens to be named `validUntil` is not a validity bound: it is not enforced
and not reported as `expired`. Its `exp` / `nbf` remain the temporal gate. The
`vc+sd-jwt` typ alone is not enough, because the IETF drafts used it until draft-06
renamed it `dc+sd-jwt`, and openvc still accepts it. The `data:` media type of an
enveloping credential is not consulted either, because it sits outside the issuer's
signature.

Likewise, an IETF SD-JWT VC's claims named `issuer`, `id` or `credentialSubject` are
not reconciled with `iss`, `jti` or `sub`. Such a credential may legitimately name,
say, the authority behind an underlying document. On every lane, the authenticated
issuer is **`result.issuer`**, the verified `iss`. Never read it from
`result.credential`. `result.raw.vcdm` (`VerifiedSdJwt.vcdm`) tells you which rules
the suite applied.

**`expected_types` rejects an IETF SD-JWT VC.** Such a credential is typed by `vct`,
so a policy that sets `expected_types` raises `TypeMismatch` that points at
`expected_vct`. It no longer verifies as if the pin were met. Before 1.31.0 the SD-JWT
lane ignored `expected_types` entirely: a policy that asked for a
`UniversityDegreeCredential` accepted any SD-JWT VC. Rejecting is also what keeps the
pin holder-proof. If an issuer makes the `@context` of a `dc+sd-jwt` VCDM credential
disclosable, a holder who withholds it turns the payload into a non-VCDM one, and
ignoring the pin there would bypass it. To verify both kinds under one pin, use one
policy per format: `expected_types` for W3C credentials and `expected_vct` for IETF
SD-JWT VCs. An empty or unset `expected_types` constrains nothing, as on every lane.
A presentation verified under one policy, such as `VpJwtProofSuite.verify(...,
policy=...)`, applies that policy to every credential it carries. So if the policy sets
`expected_types` and the presentation mixes an IETF SD-JWT VC with a W3C credential,
the whole presentation is rejected. Leave `expected_types` unset there and check each
`result.credentials` entry yourself.

## Caveat: keep enforcement pointers non-disclosable

If a credential's `credentialStatus` (or `credentialSchema`) must be
enforceable, do **not** list it in `disclosable`: a holder could simply omit
the disclosure and the verifier would never see the pointer. Fail-closed
status only works for claims the holder cannot withhold — the same applies to
`ecdsa-sd-2023`'s mandatory pointers (see the
[Security model](Security-Model)). RFC 9901 §9.7 likewise forbids making
`exp` / `nbf` / `iss` / `cnf` / `aud` selectively disclosable: a withheld
`exp` cannot be distinguished from an absent one, so an expired credential
would verify. The same holds for a W3C credential's `validUntil` / `validFrom` and
its `@context`. VC-JOSE-COSE §3.2.1 says properties needed for validation SHOULD
NOT be selectively disclosable. A holder can withhold a disclosable `validUntil`.
A holder can also withhold a disclosable `@context`, including a VCDM entry that is
itself an array-element disclosure. The credential then counts as VCDM only if it is
typed `vc+sd-jwt` and has no `vct`. If it is `dc+sd-jwt`, or carries a `vct`, its
window and its `issuer` / `id` / `sub` consistency are no longer checked, and a policy
that sets `expected_types` rejects it.
