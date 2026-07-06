"""
05 — VP-JWT: a holder wraps an issued credential in a presentation bound to a
verifier (aud) and a one-time nonce; verify checks the holder signature and
cascade-verifies every embedded credential through the pipeline.

Run:  python examples/05_vp_jwt_presentation.py
"""
from _common import did_key_ed25519, did_key_p256

from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

issuer, issuer_did = did_key_p256()
holder, holder_did = did_key_ed25519()

# The issuer issues a credential ABOUT the holder.
vc = VcJwtProofSuite().sign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"], "issuer": issuer_did,
    "credentialSubject": {"id": holder_did, "role": "member"},
}, signing_key=issuer)

# The holder presents it to a verifier, bound to aud + nonce.
vp = VpJwtProofSuite().sign(
    [vc], holder_key=holder, audience="https://verifier.example", nonce="chal-42")

# The verifier checks the holder signature, aud/nonce, and every embedded credential;
# require_holder_binding also asserts the credential was issued to this holder.
result = VpJwtProofSuite().verify(
    vp, audience="https://verifier.example", nonce="chal-42",
    require_holder_binding=True)

print("holder     :", result.holder)
print("credentials:", len(result.credentials))
print("vc issuer  :", result.credentials[0].issuer)
print("vc subject :", result.credentials[0].subject, "(== holder)")
