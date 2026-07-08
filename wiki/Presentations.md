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
rejected: the holder binding lives only on a presentation proof. `mso_mdoc`
stays unsupported.

The reported `holder` is the **authenticated** identity — the DID that controls
the `verificationMethod` that signed the proof, not a self-asserted `holder`
field (a `holder` that disagrees with the signer is rejected). So to check the
presenter actually owns a credential, compare its subject to `p.holder`, or pass
`require_holder_binding=True` to `verify_vp_token` — which enforces, for the W3C
VP formats (`ldp_vc`, `jwt_vc_json`), that every embedded credential was issued to
the authenticated holder. It is off by default because a holder may legitimately
present a third party's credential.

## Replay: what the bindings buy you

`aud`/`domain` pins the presentation to *your* verifier; `nonce`/`challenge`
pins it to *one run* of your protocol. Always generate the nonce server-side,
one per authorization request, and reject reuse — openvc checks the binding,
but only you can guarantee freshness.
