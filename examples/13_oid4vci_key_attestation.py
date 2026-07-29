"""
13 — OpenID4VCI: the attested-key proof, where the key lives inside the header.

The form EU wallet stacks emit: the proof header carries a `kid` and a `key_attestation`
(App. D), and the key the proof was signed with is one of the attestation's
`attested_keys`. There is nothing for a registry to look up — so `resolve_proof_key`,
which sees only the `kid`, cannot answer. `resolve_proof_key_in_context` gets the whole
context, attestation already parsed, and the caller applies its own mapping rule.

Which rule that is, is NOT specified: the spec's example uses `kid` as an index, other
wallets use each JWK's own `kid` or a thumbprint. openvc refuses to guess and hands you
the material instead. What it does enforce is App. D's MUST — the proof must be signed
by a key the attestation carries — which catches an honest wallet, or your own resolver,
producing the wrong key. It stops no attacker: nothing here verifies the attestation's
signature, so a forger just attests their own key. Deciding the attestation is genuine
is YOUR job, with a wallet-provider anchor openvc does not model.

Run:  python examples/13_oid4vci_key_attestation.py
"""
import time

from openvc.keys import P256SigningKey
from openvc.openid4vci import peek_key_attestation, verify_credential_request_proofs
from openvc.proof._jws import sign_compact
from openvc.proof.errors import ClaimsInvalid

CREDENTIAL_ISSUER = "https://issuer.example"
NONCE = "c_nonce_from_the_nonce_endpoint"

wallet_provider = P256SigningKey.generate(kid="wallet-provider")
device_keys = [P256SigningKey.generate(kid=f"device-{n}") for n in range(3)]

# --- wallet side: the provider attests a batch of device keys ----------------------
key_attestation = sign_compact(
    {"typ": "key-attestation+jwt", "alg": wallet_provider.alg},
    {"iss": "https://wallet-provider.example",
     "iat": int(time.time()),
     "exp": int(time.time()) + 3600,                 # REQUIRED with the jwt proof type
     "key_storage": ["iso_18045_high"],              # the wallet's claim about itself
     "attested_keys": [k.public_jwk() for k in device_keys]},
    signing_key=wallet_provider,
)

signing_key = device_keys[1]                         # the wallet signs with the second
key_proof = sign_compact(
    {"typ": "openid4vci-proof+jwt", "alg": signing_key.alg,
     "kid": "1",                                     # ... and names it by position
     "key_attestation": key_attestation},
    {"aud": CREDENTIAL_ISSUER, "iat": int(time.time()), "nonce": NONCE},
    signing_key=signing_key,
)
credential_request = {"credential_configuration_id": "UniversityDegree",
                      "proofs": {"jwt": [key_proof]}}


# --- issuer side: your mapping rule, in one function -------------------------------
def resolve(ctx):
    """`kid` -> the attested key it names. This ecosystem's rule; not openvc's."""
    return ctx.key_attestation.attested_keys[int(ctx.kid)]


proof, = verify_credential_request_proofs(
    credential_request,
    credential_issuer=CREDENTIAL_ISSUER,
    check_nonce=lambda nonce: nonce == NONCE,        # atomic in production
    resolve_proof_key_in_context=resolve,
)
assert proof.public_jwk == signing_key.public_jwk()
print("attested proof verified — thumbprint:", proof.thumbprint)

# --- the attestation is yours to judge, and openvc parsed it for you ---------------
attested = peek_key_attestation(proof.key_attestation)      # UNVERIFIED, by design
print("wallet claims key storage:", attested.key_storage,
      "| keys attested:", len(attested.attested_keys))
print("your call: is", attested.claims["iss"], "an anchor you trust?")

# --- App. D's MUST: a key the attestation does not carry is refused ----------------
stranger = P256SigningKey.generate(kid="stranger")
try:
    verify_credential_request_proofs(
        credential_request,
        credential_issuer=CREDENTIAL_ISSUER,
        check_nonce=lambda nonce: nonce == NONCE,
        resolve_proof_key_in_context=lambda ctx: stranger.public_jwk(),
    )
except ClaimsInvalid as exc:
    print("unattested key rejected:", str(exc)[:52], "...")
