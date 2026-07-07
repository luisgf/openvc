"""
07 — JCS Data Integrity without pyld: embed an eddsa-jcs-2022 (Ed25519) and an
ecdsa-jcs-2019 (P-256) proof, then verify each through the pipeline. Unlike the
eddsa-rdfc-2022 / ecdsa-sd-2023 suites (example 03), the JCS suites canonicalize
with RFC 8785 — pure stdlib, **no [data-integrity] extra needed**.

Run:  python examples/07_jcs_no_pyld.py
"""
import sys

from _common import did_key_ed25519, did_key_p256

from openvc import verify_credential
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite


def _credential(issuer_did):
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:7c5a",
        "type": ["VerifiableCredential"],
        "issuer": issuer_did,
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "role": "member"},
    }


for label, (issuer, issuer_did), suite in [
    ("eddsa-jcs-2022", did_key_ed25519(), EddsaJcsProofSuite()),
    ("ecdsa-jcs-2019", did_key_p256(), EcdsaJcsProofSuite()),
]:
    signed = suite.add_proof(
        _credential(issuer_did), signing_key=issuer, verification_method=issuer.kid)
    result = verify_credential(signed)          # format auto-detected from the cryptosuite
    print(f"{label}: format={result.format}  issuer={result.issuer}  subject={result.subject}")

print("verified with pyld imported:", "pyld" in sys.modules)   # -> False
