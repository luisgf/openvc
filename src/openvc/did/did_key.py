"""
openvc.did.did_key — offline resolver for the did:key method (Ed25519, P-256).

did:key is self-contained: the public key is encoded in the identifier itself, so
resolution is pure decoding — no network. Format:

    did:key:z<base58btc( <multicodec-varint> || <raw-public-key> )>

Supported multicodecs:
    0xed   Ed25519 public key   -> OKP / Ed25519 JWK
    0x1200 P-256   public key   -> EC  / P-256  JWK (from the compressed point)
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric import ec

from .base import DidDocument, DidResolutionError, VerificationMethod

# base58btc (Bitcoin) alphabet
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

# multicodec codes (unsigned-varint encoded in the key bytes)
_MC_ED25519_PUB = 0xED
_MC_P256_PUB = 0x1200


def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        try:
            num = num * 58 + _B58_INDEX[ch]
        except KeyError:
            raise DidResolutionError(f"invalid base58 character {ch!r}") from None
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    n_leading = len(s) - len(s.lstrip("1"))          # each leading '1' == 0x00
    return b"\x00" * n_leading + body


def _read_varint(data: bytes) -> tuple[int, int]:
    result = shift = 0
    for i, byte in enumerate(data):
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i + 1
        shift += 7
    raise DidResolutionError("truncated multicodec varint")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class DidKeyResolver:
    def supports(self, did: str) -> bool:
        return did.startswith("did:key:z")

    def resolve(self, did: str) -> DidDocument:
        multibase = did[len("did:key:"):]
        if not multibase.startswith("z"):
            raise DidResolutionError("did:key must use base58btc ('z') multibase")

        raw = _b58decode(multibase[1:])
        code, offset = _read_varint(raw)
        key_bytes = raw[offset:]

        if code == _MC_ED25519_PUB:
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(key_bytes)}
        elif code == _MC_P256_PUB:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_bytes)
            nums = pub.public_numbers()
            jwk = {
                "kty": "EC", "crv": "P-256",
                "x": _b64url(nums.x.to_bytes(32, "big")),
                "y": _b64url(nums.y.to_bytes(32, "big")),
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
        return DidDocument(id=did, verification_methods=[vm], raw=raw_doc)
