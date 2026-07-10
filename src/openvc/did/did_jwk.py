"""
openvc.did.did_jwk — offline resolver for the did:jwk method.

did:jwk is self-contained like did:key: the public key *is* the identifier, a
base64url-encoded JSON JWK, so resolution is pure decoding — no network. Format:

    did:jwk:<base64url-nopad( utf8( JSON public JWK ) )>

The verification method fragment is always ``#0``, and it is referenced by every
signing verification relationship. Common in EUDI / OID4VC test stacks.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from .base import DidDocument, DidResolutionError, VerificationMethod

# did:jwk exposes its single key for every assertion-style relationship (keyAgreement
# is omitted — it is only for encryption keys, which this library does not sign with).
_RELATIONSHIPS = (
    "assertionMethod", "authentication", "capabilityInvocation", "capabilityDelegation",
)


class DidJwkResolver:
    def supports(self, did: str) -> bool:
        return did.startswith("did:jwk:")

    def resolve(self, did: str) -> DidDocument:
        encoded = did[len("did:jwk:"):]
        if not encoded:
            raise DidResolutionError("did:jwk has no encoded JWK")
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            jwk: Any = json.loads(raw)
        except (ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise DidResolutionError(f"did:jwk is not valid base64url JSON: {exc}") from exc
        if not isinstance(jwk, dict) or "kty" not in jwk:
            raise DidResolutionError("did:jwk did not decode to a JWK object")
        if "d" in jwk:              # a did:jwk must encode a PUBLIC key, never a private one
            raise DidResolutionError("did:jwk encodes a private key (has 'd')")

        vm_id = f"{did}#0"
        vm = VerificationMethod(
            id=vm_id, type="JsonWebKey2020", controller=did, public_key_jwk=jwk)
        relationships = {rel: [vm_id] for rel in _RELATIONSHIPS}
        raw_doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [
                {"id": vm_id, "type": "JsonWebKey2020", "controller": did,
                 "publicKeyJwk": jwk}],
            **relationships,
        }
        return DidDocument(
            id=did, verification_methods=[vm], raw=raw_doc, relationships=relationships)


__all__ = [
    "DidJwkResolver",
]
