"""
02 — SD-JWT VC: issue with selective disclosure, then a holder presents only some
claims and proves possession of its key (Key Binding JWT).

Run:  python examples/02_sd_jwt_presentation.py
"""
from _common import did_key_ed25519

from openvc.proof.sd_jwt import SdJwtVcProofSuite

issuer, issuer_did = did_key_ed25519()
holder, holder_did = did_key_ed25519()
suite = SdJwtVcProofSuite()

# Issue: given_name and age are selectively disclosable; cnf binds the holder key.
sd_jwt = suite.issue(
    {"iss": issuer_did, "given_name": "Ada", "family_name": "Lovelace", "age": 36},
    signing_key=issuer, disclosable=["given_name", "age"],
    holder_jwk=holder.public_jwk(), vct="https://credentials.example/identity")

# Present: the holder reveals nothing extra here and signs a KB-JWT over aud + nonce.
presentation = suite.create_presentation(
    sd_jwt, holder_key=holder, audience="https://verifier.example", nonce="n-once-1")

result = suite.verify(
    presentation, public_key_jwk=issuer.public_jwk(),
    audience="https://verifier.example", nonce="n-once-1", require_key_binding=True,
    expected_vct="https://credentials.example/identity")

print("issuer   :", result.issuer)
print("vct      :", result.vct)
print("key_bound:", result.key_bound)
print("disclosed:", {k: v for k, v in result.claims.items()
                     if k in ("given_name", "family_name", "age")})
