# Presentations & OpenID4VP

A *presentation* is what a **holder** sends a **verifier**: one or more
credentials, bound to that verifier (`aud` / `client_id`) and to a one-time
challenge (`nonce`), signed with the holder's key so it cannot be replayed
elsewhere. openvc verifies three shapes: **VP-JWT**, **OpenID4VP 1.0
`vp_token`** responses (including HAIP-encrypted ones), and Data Integrity
presentations with `challenge` / `domain`.

## VP-JWT

The holder wraps issued credentials in a signed JWT; `verify` checks the
holder signature, the `aud` + `nonce` binding, and **cascade-verifies every
embedded credential** through the pipeline:

```python
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

# An issuer and a holder, each addressed by did:key so the flow runs offline.
ipriv = ec.generate_private_key(ec.SECP256R1())
iraw = P256SigningKey(ipriv, kid="_").public_key_raw(compressed=True)
imb = encode_multibase(bytes([0x80, 0x24]) + iraw)          # multicodec p256-pub
issuer, issuer_did = P256SigningKey(ipriv, kid=f"did:key:{imb}#{imb}"), f"did:key:{imb}"

hpriv = ed25519.Ed25519PrivateKey.generate()
hraw = Ed25519SigningKey(hpriv, kid="_").public_key_raw()
hmb = encode_multibase(bytes([0xED, 0x01]) + hraw)          # multicodec ed25519-pub
holder, holder_did = Ed25519SigningKey(hpriv, kid=f"did:key:{hmb}#{hmb}"), f"did:key:{hmb}"

# The issuer issues a credential ABOUT the holder.
vc = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"], "issuer": issuer_did,
    "credentialSubject": {"id": holder_did, "role": "member"},
}, signing_key=issuer)

# The holder presents it, bound to this verifier and a one-time nonce.
vp = VpJwtProofSuite().sign(
    [vc], holder_key=holder, audience="https://verifier.example", nonce="chal-42")

# require_holder_binding also asserts the credential was issued TO this holder.
result = VpJwtProofSuite().verify(
    vp, audience="https://verifier.example", nonce="chal-42",
    require_holder_binding=True)
print(result.holder, len(result.credentials), result.credentials[0].subject)
```

A VP-JWT with no `verifiableCredential` is valid VCDM (DID Auth, for example):
`verify` accepts it and returns an empty `credentials` tuple, so if you need a
credential, check that one is there. `verify_vp_token` does this for you. A
`verifiableCredential` that is neither a credential nor an array (a number, a
bool, `null`) is rejected with `ClaimsInvalid`.

## OpenID4VP 1.0: `verify_vp_token`

For an [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
verifier, `verify_vp_token` checks a wallet's response **statelessly**: you
pass the `nonce` and `client_id` your Authorization Request used and the DCQL
query it carried; openvc validates the response shape against the query and
the holder binding of each presentation:

```python
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import verify_vp_token
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.sd_jwt import SdJwtVcProofSuite

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"     # the full, prefixed Client Identifier
VCT = "https://credentials.example.com/identity_credential"


def did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


issuer, issuer_did = did_key_p256()
holder, holder_did = did_key_p256()

# Issuer -> holder: an SD-JWT VC bound to the holder key (cnf) …
issued = SdJwtVcProofSuite().issue(
    {"iss": issuer_did, "given_name": "Ada", "sub": holder_did},
    signing_key=issuer, vct=VCT, disclosable=["given_name"],
    holder_jwk=holder.public_jwk())
# … then holder -> verifier: a KB-JWT bound to this verifier's nonce + client_id.
presentation = SdJwtVcProofSuite().create_presentation(
    issued, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)

# The OpenID4VP response: an object keyed by DCQL Credential Query id.
vp_token = {"my_credential": [presentation]}
dcql_query = {"credentials": [
    {"id": "my_credential", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}}]}

result = verify_vp_token(vp_token, dcql_query=dcql_query,
                         nonce=NONCE, client_id=CLIENT_ID)
(p,) = result.for_query("my_credential")
print(p.format, p.holder, p.raw.claims["given_name"])
```

## HAIP encrypted responses (`direct_post.jwt`)

Under the High Assurance Interoperability Profile the wallet encrypts the
whole response object into a JWE against the verifier's key-agreement key.
`verify_encrypted_vp_response` decrypts (ECDH-ES) and verifies in one call:

<!-- docs: no-run -->
```python
from openvc import verify_encrypted_vp_response
from openvc.keys import P256KeyAgreementKey

# The verifier's key-agreement key; publish public_jwk() (use: "enc") to wallets.
verifier_key = P256KeyAgreementKey.generate(kid="verifier#enc")

result = verify_encrypted_vp_response(
    response_jwe,                       # the wallet's direct_post.jwt body
    key=verifier_key, dcql_query=dcql_query, nonce=NONCE, client_id=CLIENT_ID)
```

The full round-trip — including a stand-in wallet encryptor — is runnable in
[`examples/09_haip_encrypted_response.py`](https://github.com/luisgf/openvc/blob/main/examples/09_haip_encrypted_response.py).
openvc only **decrypts** (a verifier act); producing JWEs for wallets is out
of scope.

## W3C Digital Credentials API (origin-bound)

CIR (EU) 2025/1569 pins remote presentation to OpenID4VP **plus the W3C Digital
Credentials API** (Chrome 141 / Safari 26 ship it). A DC-API-delivered response
binds to the **calling web origin** rather than a redirect URI, so per OpenID4VP 1.0
Appendix A its audience is always `origin:<origin>`, **never** the `client_id`. Pass
`expected_origins` (the origins your verifier serves) instead of `client_id` — a
Presentation is accepted only if its signed `aud` is `origin:<o>` for an `o` in the
list:

<!-- docs: no-run -->
```python
result = verify_vp_token(
    vp_token, dcql_query=dcql_query, nonce=NONCE,
    expected_origins=["https://verifier.example.com"])   # not client_id
```

The two response modes map to the two calls: **`dc_api`** (unencrypted) →
`verify_vp_token`, **`dc_api.jwt`** (an encrypted JWE) → `verify_encrypted_vp_response`
— both take `expected_origins`. Pass **exactly one** of `client_id` (redirect /
`direct_post`) or `expected_origins` (DC API); the `nonce` binding is unchanged. This
is stateless consume-and-verify — building the DC-API request is browser/wallet
plumbing, out of scope.

## Data Integrity presentations

A Data Integrity presentation binds with `challenge` / `domain` instead of
`nonce` / `aud`; the pipeline enforces both plus cascade verification of the
embedded credentials. See the
[API reference](https://luisgf.github.io/openvc/) for the exact call surface.

### `ldp_vc` over OpenID4VP

When a DCQL Credential Query uses `format: "ldp_vc"`, the wallet answers with a
**W3C Verifiable Presentation secured by a Data Integrity `authentication`
proof** (OpenID4VP 1.0 §B.1). `verify_vp_token` verifies it exactly like the
JOSE formats, mapping the request binding onto the Data Integrity proof:
`proof.challenge` must equal the `nonce` and `proof.domain` the full, prefixed
`client_id`, with `proofPurpose: authentication`. The holder key is resolved
from the proof's `verificationMethod` (and must be authorised for
`authentication` in its DID document), and every credential the VP embeds is
cascade-verified through `verify_credential`. All four whole-document
cryptosuites are accepted — `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` (need the
`[data-integrity]` extra) and `eddsa-jcs-2022` / `ecdsa-jcs-2019` (pyld-free).
A bare string or a bare credential (no VP wrapper) under an `ldp_vc` query is
rejected: the holder binding lives only on a presentation proof. A W3C
presentation under an `ldp_vc` or `jwt_vc_json` query must also embed at least
one credential, or it is rejected with `VpTokenMalformed`. When the query
carries `meta.type_values`, every embedded credential must also have the
requested type; see
[Matching the credential type](#matching-the-credential-type-metatype_values)
below. openvc never judges the issuer: any `did:key` can issue a credential
that verifies, so check each result's `issuer` against the issuers you trust.
`mso_mdoc` is verified over the Digital Credentials API flow — see
[ISO mdoc](#iso-mdoc-mso_mdoc) below.

The reported `holder` is the **authenticated** identity — the DID that controls
the `verificationMethod` that signed the proof, not a self-asserted `holder`
field (a `holder` that disagrees with the signer is rejected). Every credential the
presentation carries must also be bound to that holder, unless the query opts out — see
[Holder binding on the W3C formats](#holder-binding-on-the-w3c-formats).

### Matching the credential type: `meta.type_values`

A DCQL query for `jwt_vc_json` or `ldp_vc` lists the credential types it
accepts in `meta.type_values` (OpenID4VP 1.0 §B.1.1). The value is an array of
alternatives, and each alternative is an array of type IRIs. A credential
matches when its types contain every IRI of one alternative; order does not
matter and extra types are allowed. `verify_vp_token` checks **every**
credential the presentation embeds. If any of them matches no alternative, the
whole response is rejected with `ClaimsInvalid`. This is the W3C counterpart of
`vct_values` for `dc+sd-jwt` and `doctype_value` for `mso_mdoc`.

The comparison uses the credential's **fully expanded** types, not the strings
written in its `type`. openvc expands each credential's `type` with JSON-LD,
using that credential's own `@context`:

- **A term the context defines becomes its IRI.** Under VCDM 1.1 and 2.0,
  `VerifiableCredential` expands to
  `https://www.w3.org/2018/credentials#VerifiableCredential`. A query that asks
  for the bare `"VerifiableCredential"` therefore matches no VCDM credential.
- **A term no context defines stays as written.** The VCDM 2.0 context has no
  `@vocab`, so an undefined `UniversityDegreeCredential` matches the query
  value `"UniversityDegreeCredential"`.
- **A term the issuer maps in its own context** (for example
  `{"UniversityDegreeCredential": "https://example.org/examples#UniversityDegreeCredential"}`)
  matches that IRI and nothing else. An absolute `@base` in the context applies
  to undefined terms, as in JSON-LD.

The types are read from the credential's JSON. This works for VC-JWT and for
every Data Integrity suite. The RDF-canonicalized suites (`eddsa-rdfc-2022`,
`ecdsa-rdfc-2019`, `ecdsa-sd-2023`) have required, since 1.30.2, that the JSON
is exactly what their proof signs (context validation,
[GHSA-vrxg-57v4-85mc](https://github.com/luisgf/openvc/security/advisories/GHSA-vrxg-57v4-85mc)).
Their types must therefore be defined by a trusted context; an inline `@vocab`
is allowed.

Expanding needs the `[data-integrity]` extra (pyld), plus every context the
credential cites. openvc bundles only the VCDM 2.0 context and never fetches
one. Pass any other context through `extra_contexts`, including the VCDM 1.1
context (`https://www.w3.org/2018/credentials/v1`) that most `jwt_vc_json`
credentials use. Failures are typed and fail closed:

- An unknown context raises `DocumentLoaderError`.
- A credential whose types cannot be expanded raises `ClaimsInvalid`.
- An SD-JWT nested in the presentation never matches.
- Without pyld, a query that carries `type_values` raises `OpenID4VPError`
  before anything is verified.
- A malformed constraint raises `VpTokenMalformed`: a `type_values` that is not
  a non-empty array of non-empty string arrays (a flat list included), or a
  `meta` that is not an object.

A query without `type_values` puts no constraint on the type.

The check selects the right **type** of credential, not a trusted issuer.
Anyone can issue a credential of any type from a `did:key`, so still check each
result's `issuer` against the issuers you trust.

<!-- docs: needs=pyld -->
```python
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import verify_vp_token
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

NONCE, CLIENT_ID = "n-0S6_WzA2Mj", "x509_san_dns:verifier.example"
V2 = "https://www.w3.org/ns/credentials/v2"

priv = ec.generate_private_key(ec.SECP256R1())
raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
mb = encode_multibase(bytes([0x80, 0x24]) + raw)               # did:key, P-256
key, did = P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def present(types):
    """A holder presenting a credential they issued themselves, typed *types*."""
    vc = VcJwtProofSuite().sign(
        {"@context": [V2], "type": types, "issuer": did,
         "credentialSubject": {"id": did}}, signing_key=key)
    return VpJwtProofSuite().sign([vc], holder_key=key, audience=CLIENT_ID, nonce=NONCE)


dcql_query = {"credentials": [{
    "id": "degree", "format": "jwt_vc_json",
    "meta": {"type_values": [[
        "https://www.w3.org/2018/credentials#VerifiableCredential",   # defined: an IRI
        "UniversityDegreeCredential",                                 # undefined: as-is
    ]]}}]}

ok = verify_vp_token({"degree": [present(["VerifiableCredential",
                                          "UniversityDegreeCredential"])]},
                     dcql_query=dcql_query, nonce=NONCE, client_id=CLIENT_ID)
assert len(ok.for_query("degree")[0].credentials) == 1

try:                                       # the right holder, the wrong credential
    verify_vp_token({"degree": [present(["VerifiableCredential"])]},
                    dcql_query=dcql_query, nonce=NONCE, client_id=CLIENT_ID)
except ClaimsInvalid as exc:
    print("rejected:", exc)
else:
    raise AssertionError("an unrelated credential answered the query")
```

## ISO mdoc (`mso_mdoc`)

> **Experimental.** ISO 18013-5 mdoc is the second mandatory PID/QEAA format (CIR
> (EU) 2024/2977), alongside SD-JWT VC. openvc verifies a received `mso_mdoc` over the
> **W3C Digital Credentials API** flow; the surface ships behind an experimental label
> until it is interop-tested against the EUDI reference wallet (ADR-0005).

A wallet answering a `format: "mso_mdoc"` query returns a **base64url `DeviceResponse`**
(ISO 18013-5 CBOR). `verify_vp_token` checks the two authentications ISO 18013-5 §9.1
defines:

- **Issuer data authentication** — the `IssuerAuth` `COSE_Sign1` over the Mobile
  Security Object; the document-signer `x5chain` (COSE label 33) path-validated to a
  caller-provided **IACA** trust anchor; the MSO `docType` and `validityInfo` window;
  and, for every disclosed element, the recomputed digest matched against the MSO
  `valueDigests`.
- **Device authentication (holder binding)** — the `DeviceSignature` over the
  origin-bound `SessionTranscript` (OpenID4VP 1.0 Appendix B / ISO 18013-7). openvc
  builds the transcript from your `expected_origins` and the request `nonce`, and tries
  each expected origin (the binding is cryptographic, so only the right origin verifies).

Pass `trust_anchors` (the IACA root `x509.Certificate` objects — e.g. from
[`openvc.trustlist`](Trust)) and `expected_origins`. Each verified document comes back
as an `openvc.mdoc.VerifiedMdoc` in `credentials`:

<!-- docs: no-run -->
```python
from openvc.openid4vp import verify_vp_token

result = verify_vp_token(
    vp_token,                                        # {"mdl": ["<base64url DeviceResponse>"]}
    dcql_query={"credentials": [{"id": "mdl", "format": "mso_mdoc"}]},
    nonce=NONCE,
    expected_origins=["https://verifier.example.com"],
    trust_anchors=iaca_roots)                        # IACA x509.Certificate anchors

mdl = result.for_query("mdl")[0].credentials[0]      # a VerifiedMdoc
assert mdl.device_signed                             # holder binding verified
name = mdl.elements("org.iso.18013.5.1")["family_name"]
```

To verify the **issuer seal alone** of an mdoc at rest (no holder binding),
`openvc.mdoc.verify_issuer_signed(document, trust_anchors=…)` returns the disclosed
elements without device authentication. **Out of scope** (unchanged): device
engagement, NFC/BLE/QR proximity, issuance/provisioning, and any COSE *signing* surface
— openvc consumes and verifies. The redirect / `direct_post` mdoc handover is not yet
wired; use the Digital Credentials API flow.

## Holder binding on the W3C formats

A `jwt_vc_json` VP-JWT or an `ldp_vc` presentation proves that *someone* signed for
this exchange: its `aud` / `domain` and `nonce` / `challenge` are yours. On its own it
says nothing about the credentials inside. A verifier that once received your
credential could wrap it in its own presentation, correctly bound to another verifier,
and present it there. OpenID4VP calls the missing link **Cryptographic Holder Binding**:
the holder proves control of the key the credential was bound to at issuance (§2). A
Credential Query requires it unless it sets `require_cryptographic_holder_binding` to
`false`; the default is `true` (§6.1, §B.1).

`verify_vp_token` enforces it on every credential a W3C presentation embeds. If any
credential fails, the whole response is rejected (`ClaimsInvalid`):

| Embedded credential | Bound to the holder when… |
|---|---|
| VC-JWT, Data Integrity VC | its subject (`sub` / `credentialSubject.id`) is the **authenticated** VP signer: the VP-JWT `iss` whose DID document holds the signing key, or the controller of the Data Integrity `verificationMethod` |
| SD-JWT VC, bare or enveloped | it carries a Key Binding JWT bound to this exchange (`key_bound=True`), signed by its `cnf` key; see the [next section](#sd-jwt-vcs-nested-in-a-w3c-presentation) |

So these are all rejected under a default query:
- another party's credential;
- a bearer credential with no subject id;
- a credential whose `credentialSubject` is an array, even when the presenter is one of
  its subjects or the issuer signed a `sub` naming them;
- an SD-JWT VC with its KB-JWT stripped, or with no `cnf` at all.

Subject and signer are compared as DID strings, never by key. A VP signed as
`did:jwk:<key>` does not bind a credential issued to `did:key:<same key>`; issue to the
DID the wallet presents with.

The VP signer never stands in for an SD-JWT's `cnf` key, even when it is the same key:
SD-JWT key binding is the KB-JWT (RFC 9901), which also covers the disclosures you
received (`sd_hash`) and the KB-JWT's freshness (`iat`). Conversely, a nested SD-JWT
with a KB-JWT bound here is accepted whoever signed the outer presentation. That is the
same guarantee the `dc+sd-jwt` format gives.

When the presenter legitimately is not the subject, opt that query out. Examples are a
bearer ticket, a parent presenting a child's credential, or a credential bound by
claims rather than by a key (§5.3). OpenID4VP §14.1.1 spells out what you accept then:
"the Holder may not be the subject of the Credential".

<!-- docs: no-run -->
```python
dcql_query = {"credentials": [
    {"id": "ticket", "format": "jwt_vc_json",
     "require_cryptographic_holder_binding": False}]}
```

The flag must be a JSON boolean; anything else is `VpTokenMalformed`, so a `null` or a
`0` cannot switch the binding off by accident. Note that §B.1 tells a conformant wallet
to answer such a query with a bare credential and no presentation. The W3C formats
still require a presentation, so today an opted-out query accepts a VP whose
credentials are not bound to its signer, but not a bare credential.

`require_holder_binding=True` is the stricter, caller-side switch, and it ignores the
query. Every embedded credential's subject must be the authenticated holder, *including*
an SD-JWT VC's `sub`. `VpJwtProofSuite.verify` knows nothing of DCQL. There, use
`require_holder_binding` for the subject rule and
`policy=VerificationPolicy(require_key_binding=True)` for nested SD-JWTs.

## SD-JWT VCs nested in a W3C presentation

A `jwt_vc_json` VP-JWT or an `ldp_vc` presentation can embed an SD-JWT VC — bare in
`verifiableCredential`, or as a VCDM 2.0 `EnvelopedVerifiableCredential`
(`data:application/dc+sd-jwt,…`). OpenID4VP 1.0 itself only defines an SD-JWT VC as
its own `dc+sd-jwt` format, where the `vp_token` value *is* the SD-JWT + KB-JWT; the
nested shape comes from the W3C data model, and openvc cascade-verifies it like any
other embedded credential. Such a nested SD-JWT may carry **its own** Key Binding
JWT, separate from the presentation's proof, and the rule for it is:

| The nested SD-JWT VC… | Result |
|---|---|
| has no KB-JWT | **rejected** under a query that requires holder binding (the default). With `require_cryptographic_holder_binding: false` it verifies, `key_bound=False` — the presentation's proof authenticates the presenter, never the credential's `cnf` key |
| has a KB-JWT bound to this exchange — same `aud` and `nonce` as the presentation | verifies, `key_bound=True` |
| has a KB-JWT bound anywhere else — another verifier, another nonce, the bare host | **the whole response is rejected** (`ClaimsInvalid`) |

"Same exchange" means the presentation's own binding. For a VP-JWT that is its `aud`
and `nonce`. For an `ldp_vc` presentation it is the proof's `domain` and `challenge`.
Over the Digital Credentials API it is the `origin:<origin>` that openvc matched this
presentation to: the first of its `aud` / `domain` values that is one of your
`expected_origins`. No other origin qualifies, even one the presentation also lists. So a nested
`key_bound=True` now means what it says. A KB-JWT signed by the credential's `cnf`
key was made for *this* verifier and *this* request, its `sd_hash` covers the
disclosures you received, and its `iat` falls within `kb_max_age_s` (see
[SD-JWT VC](SD-JWT-VC)). It passed RFC 9901 §7.3 step 5.6, which is the step that
makes a KB-JWT a binding at all. `VpJwtProofSuite.verify` applies the same rule
with its own `audience` / `nonce`, which take precedence over any `audience` / `nonce`
in a `policy` you pass to it. The rule is scoped to the KB-JWT: a nested VC-JWT is a
credential, and its own `aud` is never pinned to you.

**What the specs say.** No spec defines what a nested KB-JWT's `aud` and `nonce`
should be. RFC 9901 §4.3 leaves both to the protocol, and OpenID4VP 1.0 does not
support a presentation nested inside another at all (§13.2). In OpenID4VP's terms an
SD-JWT + KB-JWT *is* a presentation (Appendix B.3). openvc still accepts the nesting,
because VCDM 2.0 and VC-JOSE-COSE use it to envelope an SD-JWT. But it holds a nested
KB-JWT to the only values OpenID4VP defines for any KB-JWT (§B.3.6): the Client
Identifier, or `origin:<origin>` over the DC API, and the request `nonce`. Those are
exactly what the presentation itself is bound to.

**Why reject rather than report `key_bound=False`.** Earlier releases checked a nested
KB-JWT's signature and `sd_hash` but had no `aud` / `nonce` to check it against, so
they reported `key_bound=True` for a KB-JWT minted for another verifier.
That flag vouched for a holder proof made for someone else. Downgrading the result to
`key_bound=False` would have been the wrong fix, for three reasons:

- A KB-JWT is minted per presentation, so one bound elsewhere, arriving inside a
  response to you, is a replayed or relayed holder proof. That is evidence of an
  attack, not a weaker binding.
- The specs treat a failed binding as fatal. Under RFC 9901 §7.3, a KB-JWT that fails
  any step makes the presentation invalid, and "processing MUST be aborted".
  OpenID4VP 1.0 §14.1.2 rejects the whole response when any presentation in it lacks
  the right nonce.
- A lenient mode inside a signature check is surface we would rather not add.

Refusing nested SD-JWTs altogether would break legitimate VCDM 2.0 enveloped
credentials, whose specification examples carry no KB-JWT.

**A stripped KB-JWT is rejected by default.** Without a KB-JWT, nothing proves that the
presenter holds the credential's `cnf` key, and anyone who cannot satisfy the binding
can simply drop the KB-JWT. So the decision is the query's, made before anything
arrives (RFC 9901 §9.5): under the default `require_cryptographic_holder_binding`, a
nested SD-JWT with no KB-JWT fails the response, exactly as a bare `dc+sd-jwt` one
does. Only a query that opts out accepts it, with `key_bound=False`. Earlier releases
accepted it under every query (see the [CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md),
1.29.0). With `VpJwtProofSuite.verify`, which takes no query,
`policy=VerificationPolicy(require_key_binding=True)` enforces the same for every
nested SD-JWT.

This holds only for credentials nested in a presentation, where you have no way to
pass the binding yourself. At the top level — `verify_credential`,
`verify_credential_async` or `SdJwtVcProofSuite.verify` — the KB-JWT's `aud` /
`nonce` are checked against the values *you* pass, and a KB-JWT checked against only
one of them is rejected (see [SD-JWT VC](SD-JWT-VC)). A nested `key_bound=True` also does
not mean that the presentation's signer controls the credential's `cnf` key. To
require that the presenter is also the credential's `sub`, use `require_holder_binding`.

## Replay: what the bindings buy you

`aud`/`domain` pins the presentation to *your* verifier; `nonce`/`challenge`
pins it to *one run* of your protocol. Always generate the nonce server-side,
one per authorization request, and reject reuse — openvc checks the binding,
but only you can guarantee freshness.
