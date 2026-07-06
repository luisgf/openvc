"""
03 — Data Integrity: embed an eddsa-rdfc-2022 proof in a credential's JSON, then
verify it through the pipeline (the proof survives re-serialization).

Needs the [data-integrity] extra (pyld):  pip install 'openvc-core[data-integrity]'
Run:  python examples/03_data_integrity.py
"""
from _common import did_key_ed25519

from openvc import verify_credential
from openvc.proof.data_integrity import DataIntegrityProofSuite

issuer, issuer_did = did_key_ed25519()

credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:9c1e",
    "type": ["VerifiableCredential"],
    "issuer": issuer_did,
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:alice"},
}

signed = DataIntegrityProofSuite().add_proof(
    credential, signing_key=issuer, verification_method=issuer.kid)
print("proofValue:", signed["proof"]["proofValue"][:40] + "…")

result = verify_credential(signed)          # format detected as data-integrity:eddsa
print("format :", result.format)
print("issuer :", result.issuer)
print("subject:", result.subject)
