"""
12 — OpenID4VCI: verify a wallet's key proof, then issue bound to the key it proved.

The wallet POSTs a Credential Request carrying an `openid4vci-proof+jwt`; the issuer
verifies it and gets back the wallet's public key, which is exactly what
`SdJwtVcProofSuite.issue` binds the credential to via `cnf`.

openvc does the cryptography. The endpoint, the OAuth grant and the nonce store are
YOURS — here the store is a set, in production it must be atomic (see ADR-0007).

Run:  python examples/12_oid4vci_key_proof.py
"""
import time

from _common import did_key_p256

from openvc import verify_credential
from openvc.keys import P256SigningKey
from openvc.openid4vci import verify_credential_request_proofs
from openvc.proof._jws import sign_compact
from openvc.proof.sd_jwt import SdJwtVcProofSuite

CREDENTIAL_ISSUER = "https://issuer.example"
VCT = "https://credentials.example/university-degree"

issuer, issuer_did = did_key_p256()
wallet = P256SigningKey.generate(kid="wallet-key-1")

# --- the issuer's nonce store. Yours. Must be ATOMIC in production: a Redis SET NX or
# a SQL DELETE ... RETURNING — a read-then-write lets two concurrent requests both win.
issued_nonces = {"c_nonce_from_the_nonce_endpoint"}


def consume_nonce(nonce: str) -> bool:
    """Mark the nonce used and report whether it was valid — in ONE step.

    `set.remove` either removes and returns, or raises: there is no window between
    the check and the removal. Writing this as `if n in store: store.discard(n)` is
    the bug that re-opens the replay window under concurrency.
    """
    try:
        issued_nonces.remove(nonce)
        return True
    except KeyError:
        return False


# --- wallet side: mint the key proof (App. F.1) ------------------------------------
key_proof = sign_compact(
    {"typ": "openid4vci-proof+jwt", "alg": wallet.alg, "jwk": wallet.public_jwk()},
    {"aud": CREDENTIAL_ISSUER,                       # this issuer, and only this one
     "iat": int(time.time()),                        # freshness, checked both ways
     "nonce": "c_nonce_from_the_nonce_endpoint"},
    signing_key=wallet,
)
credential_request = {
    "credential_configuration_id": "UniversityDegree",
    "proofs": {"jwt": [key_proof]},
}

# --- issuer side: verify, then issue -----------------------------------------------
proof, = verify_credential_request_proofs(
    credential_request,
    credential_issuer=CREDENTIAL_ISSUER,
    check_nonce=consume_nonce,                       # state: injected, never stored here
)
print("proof verified — key source:", proof.key_source, "| thumbprint:", proof.thumbprint)

sd_jwt = SdJwtVcProofSuite().issue(
    {"iss": issuer_did, "degree": "BSc Computer Science"},
    signing_key=issuer, vct=VCT, disclosable=["degree"],
    holder_jwk=proof.public_jwk,                     # <- the key the proof demonstrated
)

# --- the credential verifies, and is bound to the wallet key -----------------------
result = verify_credential(sd_jwt)
assert result.raw.confirmation == {"jwk": wallet.public_jwk()}
print("issued and bound to the wallet key:", result.format)

# --- replay: the nonce is single-use, so the same proof cannot be redeemed twice ----
try:
    verify_credential_request_proofs(
        credential_request, credential_issuer=CREDENTIAL_ISSUER,
        check_nonce=consume_nonce)
except Exception as exc:
    print("replay rejected:", type(exc).__name__)
