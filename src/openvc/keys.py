"""
openvc.keys — key backends implementing the SigningKey protocol.

Two software backends are provided:

  * Ed25519SigningKey  -> alg "EdDSA"   (default for general OB 3.0 issuance;
                                         opt into the RFC 9864 fully-specified
                                         name "Ed25519" with alg="Ed25519")
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
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .proof.vc_jwt import SigningKey

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .errors import OpenvcError

P256_COORD_BYTES = 32  # a P-256 coordinate / scalar is 32 bytes
P384_COORD_BYTES = 48  # a P-384 coordinate / scalar is 48 bytes

# The polymorphic "EdDSA" and its RFC 9864 fully-specified equivalent "Ed25519"
# name the same Ed25519 signature; IANA deprecated "EdDSA" (RFC 9864), so an
# Ed25519 backend may emit either. Both verify identically.
ED25519_ALG_NAMES = frozenset({"EdDSA", "Ed25519"})


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
    """An in-process Ed25519 (``EdDSA``) signing key — the general OB 3.0 default.

    The JOSE algorithm name emitted in the header defaults to the (still-supported)
    polymorphic ``"EdDSA"``; pass ``alg="Ed25519"`` to emit the RFC 9864
    fully-specified name instead. Both name the same Ed25519 signature.
    """

    def __init__(
        self, private_key: ed25519.Ed25519PrivateKey, kid: str, *, alg: str = "EdDSA"
    ) -> None:
        if alg not in ED25519_ALG_NAMES:
            raise InvalidKey(f"Ed25519 alg must be one of {sorted(ED25519_ALG_NAMES)}, "
                             f"got {alg!r}")
        self._sk = private_key
        self._kid = kid
        self._alg = alg

    @property
    def alg(self) -> str:
        """The JOSE algorithm name in the header — ``"EdDSA"`` (default) or the RFC
        9864 fully-specified ``"Ed25519"``."""
        return self._alg

    @property
    def kid(self) -> str:
        """The verification-method id this key signs as."""
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        # cryptography returns the raw 64-byte signature; JOSE-ready as-is.
        """Sign *signing_input*; returns the raw 64-byte Ed25519 signature."""
        return self._sk.sign(signing_input)

    def public_jwk(self) -> dict[str, Any]:
        """The public key as an OKP JWK."""
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
    def generate(cls, kid: str, *, alg: str = "EdDSA") -> "Ed25519SigningKey":
        return cls(ed25519.Ed25519PrivateKey.generate(), kid, alg=alg)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str, *, alg: str = "EdDSA") -> "Ed25519SigningKey":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" not in jwk:
            raise InvalidKey("not an Ed25519 private JWK")
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(_b64url_decode(jwk["d"]))
        return cls(sk, kid, alg=alg)

    @classmethod
    def from_pem(
        cls, pem: bytes, kid: str, password: bytes | None = None, *, alg: str = "EdDSA"
    ) -> "Ed25519SigningKey":
        sk = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(sk, ed25519.Ed25519PrivateKey):
            raise InvalidKey("PEM is not an Ed25519 private key")
        return cls(sk, kid, alg=alg)


# --------------------------------------------------------------------------- #
# P-256 (ES256)
# --------------------------------------------------------------------------- #

class P256SigningKey:
    """An in-process P-256 (``ES256``) signing key — required for EBSI/EUDI."""
    alg = "ES256"

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, kid: str) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise InvalidKey("ES256 requires a P-256 (secp256r1) key")
        self._sk = private_key
        self._kid = kid

    @property
    def kid(self) -> str:
        """The verification-method id this key signs as."""
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        """Sign *signing_input*; returns the raw R‖S signature (JOSE ES256, not DER)."""
        der = self._sk.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)                       # DER -> (int, int)
        return _int_to_fixed(r, P256_COORD_BYTES) + _int_to_fixed(s, P256_COORD_BYTES)

    def public_jwk(self) -> dict[str, Any]:
        """The public key as an EC P-256 JWK."""
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
# P-384 (ES384) — the larger NIST curve for Data Integrity ecdsa-*-2019
# --------------------------------------------------------------------------- #

class P384SigningKey:
    """An in-process P-384 (``ES384``) signing key — the P-384 leg of the
    Data Integrity ECDSA cryptosuites (``ecdsa-jcs-2019`` / ``ecdsa-rdfc-2019``)."""
    alg = "ES384"

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, kid: str) -> None:
        if not isinstance(private_key.curve, ec.SECP384R1):
            raise InvalidKey("ES384 requires a P-384 (secp384r1) key")
        self._sk = private_key
        self._kid = kid

    @property
    def kid(self) -> str:
        """The verification-method id this key signs as."""
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        """Sign *signing_input* over SHA-384; returns the raw R‖S signature (JOSE
        ES384, 96 bytes — not DER)."""
        der = self._sk.sign(signing_input, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der)
        return _int_to_fixed(r, P384_COORD_BYTES) + _int_to_fixed(s, P384_COORD_BYTES)

    def public_jwk(self) -> dict[str, Any]:
        """The public key as an EC P-384 JWK."""
        nums = self._sk.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-384",
            "x": _b64url_encode(_int_to_fixed(nums.x, P384_COORD_BYTES)),
            "y": _b64url_encode(_int_to_fixed(nums.y, P384_COORD_BYTES)),
        }

    def public_key_raw(self, *, compressed: bool = True) -> bytes:
        """SEC1 point (compressed by default) — used by the did:key encoder
        (multicodec 0x1201 for P-384)."""
        fmt = (serialization.PublicFormat.CompressedPoint if compressed
               else serialization.PublicFormat.UncompressedPoint)
        return self._sk.public_key().public_bytes(serialization.Encoding.X962, fmt)

    # -- constructors ------------------------------------------------------ #

    @classmethod
    def generate(cls, kid: str) -> "P384SigningKey":
        return cls(ec.generate_private_key(ec.SECP384R1()), kid)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str) -> "P384SigningKey":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-384" or "d" not in jwk:
            raise InvalidKey("not a P-384 private JWK")
        d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
        try:                                              # d=0 / d>=n -> not a valid scalar
            return cls(ec.derive_private_key(d, ec.SECP384R1()), kid)
        except ValueError as exc:
            raise InvalidKey(f"invalid P-384 private scalar: {exc}") from exc

    @classmethod
    def from_pem(cls, pem: bytes, kid: str, password: bytes | None = None) -> "P384SigningKey":
        sk = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(sk, ec.EllipticCurvePrivateKey):
            raise InvalidKey("PEM is not an EC private key")
        return cls(sk, kid)


# --------------------------------------------------------------------------- #
# ECDH key agreement (JWE ECDH-ES — HAIP encrypted responses)
# --------------------------------------------------------------------------- #

@runtime_checkable
class KeyAgreementKey(Protocol):
    """The recipient's static private half for JWE ECDH-ES key agreement.

    The encryption counterpart of :class:`~openvc.proof.vc_jwt.SigningKey`: an
    HSM/Vault backend that runs the raw ECDH on-device (never exporting the private
    scalar) drops in by implementing ``crv``, ``kid`` and ``agree`` — which returns
    the raw ECDH shared secret ``Z``; the public JWE Concat KDF is applied by the
    caller (:mod:`openvc.jwe`), so no secret-derived material beyond ``Z`` crosses the
    boundary.
    """
    crv: str

    @property
    def kid(self) -> str: ...

    def agree(self, peer_public_jwk: dict[str, Any]) -> bytes: ...


class P256KeyAgreementKey:
    """An in-process P-256 ECDH key-agreement key (JWE ``ECDH-ES``, HAIP responses)."""
    crv = "P-256"

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, kid: str) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise InvalidKey("ECDH-ES over P-256 requires a P-256 (secp256r1) key")
        self._sk = private_key
        self._kid = kid

    @property
    def kid(self) -> str:
        """The id the recipient key is published under (JWE ``kid``)."""
        return self._kid

    def agree(self, peer_public_jwk: dict[str, Any]) -> bytes:
        """Return the raw ECDH shared secret ``Z`` (the 32-byte big-endian X
        coordinate of the shared point) with the peer's ephemeral public key (the JWE
        ``epk``). A non-P-256 peer key is rejected before any curve operation."""
        if peer_public_jwk.get("kty") != "EC" or peer_public_jwk.get("crv") != "P-256":
            raise InvalidKey("ECDH-ES peer (epk) must be an EC P-256 public JWK")
        try:
            x = int.from_bytes(_b64url_decode(peer_public_jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(peer_public_jwk["y"]), "big")
            peer = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        except (KeyError, ValueError, TypeError) as exc:               # malformed epk
            raise InvalidKey(f"invalid ECDH-ES peer public key: {exc}") from exc
        return self._sk.exchange(ec.ECDH(), peer)

    def public_jwk(self) -> dict[str, Any]:
        """The public key as an EC P-256 JWK marked ``use:"enc"`` — the verifier
        publishes this (in ``client_metadata.jwks``) for the wallet to encrypt to."""
        nums = self._sk.public_key().public_numbers()
        return {
            "kty": "EC", "crv": "P-256", "use": "enc",
            "x": _b64url_encode(_int_to_fixed(nums.x, P256_COORD_BYTES)),
            "y": _b64url_encode(_int_to_fixed(nums.y, P256_COORD_BYTES)),
        }

    # -- constructors ------------------------------------------------------ #

    @classmethod
    def generate(cls, kid: str) -> "P256KeyAgreementKey":
        return cls(ec.generate_private_key(ec.SECP256R1()), kid)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str) -> "P256KeyAgreementKey":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" not in jwk:
            raise InvalidKey("not a P-256 private JWK")
        d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
        return cls(ec.derive_private_key(d, ec.SECP256R1()), kid)

    @classmethod
    def from_pem(
        cls, pem: bytes, kid: str, password: bytes | None = None
    ) -> "P256KeyAgreementKey":
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
        if alg in ED25519_ALG_NAMES:                       # "EdDSA" or RFC 9864 "Ed25519"
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
        if alg == "ES384":
            if len(signature) != 2 * P384_COORD_BYTES:
                raise InvalidKey("ES384 signature must be 96-byte R||S")
            r = int.from_bytes(signature[:P384_COORD_BYTES], "big")
            s = int.from_bytes(signature[P384_COORD_BYTES:], "big")
            der = encode_dss_signature(r, s)                   # R||S -> DER for verify
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_b64url_decode(public_jwk["x"]), "big"),
                int.from_bytes(_b64url_decode(public_jwk["y"]), "big"),
                ec.SECP384R1(),
            ).public_key()
            pub.verify(der, signing_input, ec.ECDSA(hashes.SHA384()))
            return True
        raise InvalidKey(f"unsupported alg {alg!r}")
    except InvalidSignature:
        return False
    except (ValueError, KeyError, TypeError) as exc:
        # A malformed / mismatched public JWK (wrong-curve coords, an OKP key with no
        # "y", a bad-length Ed25519 x) must fail closed as a typed InvalidKey, not leak
        # a bare ValueError/KeyError to callers that catch only KeyBackendError.
        raise InvalidKey(f"malformed public key for {alg}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Convenience factory
# --------------------------------------------------------------------------- #

def signing_key_from_jwk(jwk: dict[str, Any], kid: str) -> "SigningKey":
    """Dispatch to the right backend from a private JWK."""
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        return Ed25519SigningKey.from_jwk(jwk, kid)
    if kty == "EC" and crv == "P-256":
        return P256SigningKey.from_jwk(jwk, kid)
    if kty == "EC" and crv == "P-384":
        return P384SigningKey.from_jwk(jwk, kid)
    raise InvalidKey(f"unsupported key type kty={kty!r} crv={crv!r}")


__all__ = [
    "Ed25519SigningKey",
    "InvalidKey",
    "KeyAgreementKey",
    "KeyBackendError",
    "P256KeyAgreementKey",
    "P256SigningKey",
    "P384SigningKey",
    "signing_key_from_jwk",
    "verify_signature",
]
