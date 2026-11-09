"""
openvc.did.did_key — offline resolver for the did:key method (Ed25519, P-256).

did:key is self-contained: the public key is encoded in the identifier itself, so
resolution is pure decoding — no network. Format:

    did:key:z<base58btc( <multicodec-varint> || <raw-public-key> )>

Supported multicodecs:
    0xed   Ed25519 public key   -> OKP / Ed25519 JWK
    0x1200 P-256   public key   -> EC  / P-256  JWK (from the compressed point)

The identifier is attacker-controlled (a VC-JWT ``iss``, a Data Integrity
``verificationMethod``) and nothing upstream bounds its length, so the decoding is
:mod:`openvc.multibase`'s: its base58 decode (O(n²) big-integer work) is capped at
``_MAX_B58_LEN`` characters and its varint reader at ``_MAX_VARINT_BYTES`` bytes, and an
oversized identifier is refused before any big-integer work (#386).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric import ec

from ..multibase import MultibaseError, b58btc_decode, read_varint
from .base import DidDocument, DidResolutionError, VerificationMethod

# multicodec codes (unsigned-varint encoded in the key bytes)
_MC_ED25519_PUB = 0xED
_MC_P256_PUB = 0x1200
_MC_P384_PUB = 0x1201


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class DidKeyResolver:
    def supports(self, did: str) -> bool:
        return did.startswith("did:key:z")

    def resolve(self, did: str) -> DidDocument:
        multibase = did[len("did:key:"):]
        if not multibase.startswith("z"):
            raise DidResolutionError("did:key must use base58btc ('z') multibase")

        try:
            # the bounded codec: the base58 length and the varint width are capped by
            # openvc.multibase, so an oversized identifier costs nothing before this
            # refusal; MultibaseError's text carries the length, never the input
            raw = b58btc_decode(multibase[1:])
            code, offset = read_varint(raw)
        except MultibaseError as exc:
            raise DidResolutionError(f"malformed did:key: {exc}") from exc
        key_bytes = raw[offset:]

        if code == _MC_ED25519_PUB:
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(key_bytes)}
        elif code == _MC_P256_PUB:
            try:                                          # off-curve / malformed SEC1 point
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_bytes)
            except ValueError as exc:
                raise DidResolutionError(f"invalid did:key P-256 point: {exc}") from exc
            nums = pub.public_numbers()
            jwk = {
                "kty": "EC", "crv": "P-256",
                "x": _b64url(nums.x.to_bytes(32, "big")),
                "y": _b64url(nums.y.to_bytes(32, "big")),
            }
        elif code == _MC_P384_PUB:
            try:
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), key_bytes)
            except ValueError as exc:
                raise DidResolutionError(f"invalid did:key P-384 point: {exc}") from exc
            nums = pub.public_numbers()
            jwk = {
                "kty": "EC", "crv": "P-384",
                "x": _b64url(nums.x.to_bytes(48, "big")),
                "y": _b64url(nums.y.to_bytes(48, "big")),
            }
        else:
            raise DidResolutionError(f"unsupported did:key multicodec 0x{code:x}")

        # For did:key the verification method fragment IS the multibase value.
        vm_id = f"{did}#{multibase}"
        vm = VerificationMethod(
            id=vm_id, type="JsonWebKey2020", controller=did, public_key_jwk=jwk
        )
        raw_doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [
                {"id": vm_id, "type": "JsonWebKey2020", "controller": did,
                 "publicKeyJwk": jwk}
            ],
            "authentication": [vm_id],
            "assertionMethod": [vm_id],
        }
        return DidDocument(
            id=did, verification_methods=[vm], raw=raw_doc,
            relationships={"authentication": [vm_id], "assertionMethod": [vm_id]},
        )


__all__ = [
    "DidKeyResolver",
]
