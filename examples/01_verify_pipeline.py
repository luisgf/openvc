"""
01 — Issue a VC-JWT and verify it with the one-call pipeline.

`verify_credential` detects the format, resolves the issuer key (here a did:key,
offline), verifies the signature, and applies policy (expected type, status).
Run:  python examples/01_verify_pipeline.py
"""
from _common import did_key_p256

from openvc import VerificationPolicy, verify_credential
from openvc.proof.vc_jwt import VcJwtProofSuite

issuer, issuer_did = did_key_p256()

credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:2f3a",
    "type": ["VerifiableCredential", "ExampleCredential"],
    "issuer": issuer_did,
    "credentialSubject": {"id": "did:example:alice", "name": "Ada Lovelace"},
}

token = VcJwtProofSuite().sign(credential, signing_key=issuer)
print("VC-JWT:", token[:48] + "…")

result = verify_credential(
    token, policy=VerificationPolicy(expected_types=["ExampleCredential"]))

print("format :", result.format)
print("issuer :", result.issuer)
print("subject:", result.subject)
print("name   :", result.credential["credentialSubject"]["name"])
