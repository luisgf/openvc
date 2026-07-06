"""
openvc.keys — key backends implementing the SigningKey protocol.

Two software backends are provided:

  * Ed25519SigningKey  -> alg "EdDSA"   (default for general OB 3.0 issuance)
  * P256SigningKey     -> alg "ES256"   (P-256, required for EBSI/EUDI)

Both produce **JWS-compatible** signatures, which is the subtle part:

  * Ed25519 : cryptography already returns the raw 64-byte signature — no change.
  * ES256   : cryptography returns a DER-encoded ECDSA signature. JOSE requires the
              fixed-length raw form R||S (32 + 32 = 64 bytes). We convert on sign
              and back to DER on verify. Getting this wrong is the classic reason a
              locally-produced ES256 token fails to verify in another stack.

HSM / Vault backends: anything implementing SigningKey (alg, kid, sign returning
R||S for ES256) is a drop-in replacement — e.g. a PKCS#11 or Vault Transit backend
whose `sign` performs the operation without the private key ever entering the
process. These software classes are for dev, tests, and low-assurance issuance.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .errors import OpenvcError

P256_COORD_BYTES = 32  # a P-256 coordinate / scalar is 32 bytes


class KeyBackendError(OpenvcError): ...
class InvalidKey(KeyBackendError): ...


# --------------------------------------------------------------------------- #
# base64url + integer helpers
# --------------------------------------------------------------------------- #

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _int_to_fixed(n: int, length: int) -> bytes:
    """Big-endian fixed-length encoding (preserves leading zeros — the whole
    point of JOSE's fixed-width R and S)."""
    return n.to_bytes(length, "big")


# --------------------------------------------------------------------------- #
# Ed25519 (EdDSA)
# --------------------------------------------------------------------------- #

class Ed25519SigningKey:
    alg = "EdDSA"

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, kid: str) -> None:
        self._sk = private_key
        self._kid = kid

    @property
    def kid(self) -> str:
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        # cryptography returns the raw 64-byte signature; JOSE-ready as-is.
        return self._sk.sign(signing_input)

    def public_jwk(self) -> dict[str, Any]:
        raw = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_encode(raw)}

    def public_key_raw(self) -> bytes:
        """Raw 32-byte public key (used by the did:key encoder, multicodec 0xed01)."""
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    # -- constructors ------------------------------------------------------ #

    @classmethod
    def generate(cls, kid: str) -> "Ed25519SigningKey":
        return cls(ed25519.Ed25519PrivateKey.generate(), kid)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str) -> "Ed25519SigningKey":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" not in jwk:
            raise InvalidKey("not an Ed25519 private JWK")
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(_b64url_decode(jwk["d"]))
        return cls(sk, kid)

    @classmethod
    def from_pem(cls, pem: bytes, kid: str, password: bytes | None = None) -> "Ed25519SigningKey":
        sk = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(sk, ed25519.Ed25519PrivateKey):
            raise InvalidKey("PEM is not an Ed25519 private key")
        return cls(sk, kid)


# --------------------------------------------------------------------------- #
# P-256 (ES256)
# --------------------------------------------------------------------------- #

class P256SigningKey:
    alg = "ES256"

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, kid: str) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise InvalidKey("ES256 requires a P-256 (secp256r1) key")
        self._sk = private_key
        self._kid = kid

    @property
    def kid(self) -> str:
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        der = self._sk.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)                       # DER -> (int, int)
        return _int_to_fixed(r, P256_COORD_BYTES) + _int_to_fixed(s, P256_COORD_BYTES)

    def public_jwk(self) -> dict[str, Any]:
        nums = self._sk.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_encode(_int_to_fixed(nums.x, P256_COORD_BYTES)),
            "y": _b64url_encode(_int_to_fixed(nums.y, P256_COORD_BYTES)),
        }

    def public_key_raw(self, *, compressed: bool = True) -> bytes:
        """SEC1 point (compressed by default) — used by the did:key encoder
        (multicodec 0x1200 for P-256)."""
        fmt = (serialization.PublicFormat.CompressedPoint if compressed
               else serialization.PublicFormat.UncompressedPoint)
        return self._sk.public_key().public_bytes(serialization.Encoding.X962, fmt)

    # -- constructors ------------------------------------------------------ #

    @classmethod
    def generate(cls, kid: str) -> "P256SigningKey":
        return cls(ec.generate_private_key(ec.SECP256R1()), kid)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str) -> "P256SigningKey":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" not in jwk:
            raise InvalidKey("not a P-256 private JWK")
        d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
        return cls(ec.derive_private_key(d, ec.SECP256R1()), kid)

    @classmethod
    def from_pem(cls, pem: bytes, kid: str, password: bytes | None = None) -> "P256SigningKey":
        sk = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(sk, ec.EllipticCurvePrivateKey):
            raise InvalidKey("PEM is not an EC private key")
        return cls(sk, kid)


# --------------------------------------------------------------------------- #
# Dependency-light verification (for did:key self-contained verify + tests)
# --------------------------------------------------------------------------- #

def verify_signature(
    *, alg: str, public_jwk: dict[str, Any], signing_input: bytes, signature: bytes
) -> bool:
    """Verify a JOSE signature directly from a public JWK, without PyJWT.

    Handy for did:key (where the key is inside the DID) and for round-trip tests.
    The VC verification path uses the proof suite instead; this is complementary.
    """
    try:
        if alg == "EdDSA":
            raw = _b64url_decode(public_jwk["x"])
            ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(signature, signing_input)
            return True
        if alg == "ES256":
            if len(signature) != 2 * P256_COORD_BYTES:
                raise InvalidKey("ES256 signature must be 64-byte R||S")
            r = int.from_bytes(signature[:P256_COORD_BYTES], "big")
            s = int.from_bytes(signature[P256_COORD_BYTES:], "big")
            der = encode_dss_signature(r, s)                   # R||S -> DER for verify
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_b64url_decode(public_jwk["x"]), "big"),
                int.from_bytes(_b64url_decode(public_jwk["y"]), "big"),
                ec.SECP256R1(),
            ).public_key()
            pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        raise InvalidKey(f"unsupported alg {alg!r}")
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- #
# Convenience factory
# --------------------------------------------------------------------------- #

def signing_key_from_jwk(jwk: dict[str, Any], kid: str):
    """Dispatch to the right backend from a private JWK."""
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        return Ed25519SigningKey.from_jwk(jwk, kid)
    if kty == "EC" and crv == "P-256":
        return P256SigningKey.from_jwk(jwk, kid)
    raise InvalidKey(f"unsupported key type kty={kty!r} crv={crv!r}")
