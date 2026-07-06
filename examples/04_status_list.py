"""
04 — Status lists: an issuer publishes a Bitstring status list, stamps a
credentialStatus entry into a credential, then revokes it by flipping the bit.

Run:  python examples/04_status_list.py
"""
from _common import did_key_p256

from openvc.status import (
    build_status_list_credential,
    build_status_list_entry,
    check_credential_status,
    new_bitstring,
    set_status_bit,
)

issuer, issuer_did = did_key_p256()
LIST_URL = "https://issuer.example/status/1"
INDEX = 17

# A credential the issuer hands out, pointing at bit 17 of the list.
credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"], "issuer": issuer_did,
    "credentialStatus": build_status_list_entry(
        status_list_credential=LIST_URL, index=INDEX),
    "credentialSubject": {"id": "did:example:alice"},
}


def status_list(revoked: bool):
    """The (unsigned) status-list credential a resolver would fetch + verify."""
    bits = new_bitstring(1024)
    if revoked:
        set_status_bit(bits, INDEX, 1)
    return build_status_list_credential(id=LIST_URL, issuer=issuer_did, bitstring=bits)


live = status_list(revoked=False)
revoked = status_list(revoked=True)

print("before revocation:",
      check_credential_status(credential, resolve_status_list=lambda _u: live).revoked)
print("after  revocation:",
      check_credential_status(credential, resolve_status_list=lambda _u: revoked).revoked)
