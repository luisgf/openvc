"""
08 — OpenID4VP: verify a wallet's `vp_token` response. A holder presents an SD-JWT VC
(with a Key Binding JWT bound to the verifier's `nonce` + `client_id`); the verifier
checks the response shape against its DCQL query and the holder binding — statelessly.

Run:  python examples/08_openid4vp_verify.py
"""
from _common import did_key_p256

from openvc import verify_vp_token
from openvc.proof.sd_jwt import SdJwtVcProofSuite

# What the verifier put in its Authorization Request (it owns these; no session needed).
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"          # the full, prefixed Client Identifier
VCT = "https://credentials.example.com/identity_credential"

issuer, issuer_did = did_key_p256()
holder, holder_did = did_key_p256()

# Issuer -> holder: an SD-JWT VC bound to the holder's key (cnf).
issued = SdJwtVcProofSuite().issue(
    {"iss": issuer_did, "given_name": "Ada", "sub": holder_did},
    signing_key=issuer, vct=VCT, disclosable=["given_name"], holder_jwk=holder.public_jwk())

# Holder -> verifier: attach a KB-JWT bound to this verifier's nonce + client_id.
presentation = SdJwtVcProofSuite().create_presentation(
    issued, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)

# The OpenID4VP 1.0 response: an object keyed by the DCQL Credential Query id, arrays.
vp_token = {"my_credential": [presentation]}
dcql_query = {"credentials": [
    {"id": "my_credential", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}}]}

result = verify_vp_token(vp_token, dcql_query=dcql_query, nonce=NONCE, client_id=CLIENT_ID)
(p,) = result.for_query("my_credential")
print("format :", p.format)
print("holder :", p.holder)
print("given_name (disclosed):", p.raw.claims["given_name"])
print("bound to nonce + client_id:", CLIENT_ID)
