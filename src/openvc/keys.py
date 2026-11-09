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
import hashlib
import json
from collections.abc import Mapping
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

from . import _json
from .errors import OpenvcError

P256_COORD_BYTES = 32  # a P-256 coordinate / scalar is 32 bytes
P384_COORD_BYTES = 48  # a P-384 coordinate / scalar is 48 bytes

# The polymorphic "EdDSA" and its RFC 9864 fully-specified equivalent "Ed25519"
# name the same Ed25519 signature; IANA deprecated "EdDSA" (RFC 9864), so an
# Ed25519 backend may emit either. Both verify identically.
ED25519_ALG_NAMES = frozenset({"EdDSA", "Ed25519"})


class KeyBackendError(OpenvcError): ...
class InvalidKey(KeyBackendError): ...


class NonCanonicalKey(InvalidKey):
    """A public JWK that decodes to a valid key but is not spelled canonically.

    Raised only by :func:`canonical_public_jwk` with ``strict=True``: a binary member
    carries ``=`` padding, a non-alphabet character, the standard ``+``/``/`` alphabet or
    non-zero trailing bits. The message names the member, never its value. Distinct from
    a plain :class:`InvalidKey` (which it also is) so a caller can tell "send it
    canonically" apart from "this is not a key".
    """


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
# ML-DSA (RFC 9964) — EXPERIMENTAL post-quantum signing (kty "AKP"), opt-in only
# --------------------------------------------------------------------------- #

# The three ML-DSA parameter sets registered as JOSE `alg` values (RFC 9964). The
# parameter set lives in `alg`, not a `crv`: the AKP key type carries a seed-only
# private key (`priv`) and the raw public key (`pub`).
MLDSA_ALGS: frozenset[str] = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
_MLDSA_SEED_BYTES = 32


def _mldsa_module() -> Any:
    """Import the cryptography ML-DSA backend or raise a typed error. ML-DSA needs
    ``cryptography>=48`` (the ``[pq]`` extra) built against OpenSSL >= 3.5."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:                        # pragma: no cover - env dependent
        raise InvalidKey(
            "ML-DSA requires cryptography>=48: pip install 'openvc-core[pq]'") from exc
    return mldsa


def mldsa_available() -> bool:
    """``True`` if ML-DSA is usable here — the module imports **and** the OpenSSL build
    supports it (a wheel built against OpenSSL < 3.5 raises at first use even on
    cryptography 49). Gate experimental ML-DSA paths and skip tests where unavailable."""
    try:
        _mldsa_module().MLDSA44PrivateKey.generate()
        return True
    except Exception:
        return False


def _mldsa_classes(alg: str) -> tuple[Any, Any]:
    if alg not in MLDSA_ALGS:
        raise InvalidKey(f"{alg!r} is not an ML-DSA algorithm")
    mldsa = _mldsa_module()
    suffix = alg.rsplit("-", 1)[-1]                   # "44" | "65" | "87"
    return (getattr(mldsa, f"MLDSA{suffix}PrivateKey"),
            getattr(mldsa, f"MLDSA{suffix}PublicKey"))


class MLDSASigningKey:
    """**Experimental** post-quantum ML-DSA (RFC 9964) signing key — opt-in, **not** a
    production trust path (ADR-0004). Implements the :class:`SigningKey` protocol: ``alg``
    is the parameter set (``ML-DSA-44`` / ``ML-DSA-65`` / ``ML-DSA-87``), the private key
    is a 32-byte seed, and ``sign`` returns the raw ML-DSA signature — no R‖S transform,
    it is already the JOSE-wire form.

    An HSM/Vault backend uses external-mu (``sign_mu``) so the message never reaches the
    device in the clear; this in-process backend is for dev, tests and low-assurance
    issuance, exactly like the EC / Ed backends."""

    def __init__(self, private_key: Any, kid: str, alg: str) -> None:
        if alg not in MLDSA_ALGS:
            raise InvalidKey(f"ML-DSA alg must be one of {sorted(MLDSA_ALGS)}, got {alg!r}")
        self._sk = private_key
        self._kid = kid
        self._alg = alg

    @property
    def alg(self) -> str:
        return self._alg

    @property
    def kid(self) -> str:
        return self._kid

    def sign(self, signing_input: bytes) -> bytes:
        """Sign *signing_input*; returns the raw ML-DSA signature (JOSE-wire form)."""
        try:
            return self._sk.sign(signing_input)
        except Exception as exc:                       # OpenSSL < 3.5 -> typed, fail closed
            raise InvalidKey(f"ML-DSA signing failed ({self._alg}): {exc}") from exc

    def public_jwk(self) -> dict[str, Any]:
        """The public key as an RFC 9964 ``AKP`` JWK (``kty`` / ``alg`` / ``pub``)."""
        return {"kty": "AKP", "alg": self._alg,
                "pub": _b64url_encode(self._sk.public_key().public_bytes_raw())}

    def private_jwk(self) -> dict[str, Any]:
        """The private ``AKP`` JWK — adds the 32-byte seed ``priv``. Handle with care."""
        return dict(self.public_jwk(), priv=_b64url_encode(self._sk.private_bytes_raw()))

    @classmethod
    def generate(cls, kid: str, *, alg: str = "ML-DSA-65") -> "MLDSASigningKey":
        priv_cls, _ = _mldsa_classes(alg)
        try:
            return cls(priv_cls.generate(), kid, alg)
        except InvalidKey:
            raise
        except Exception as exc:                       # OpenSSL < 3.5 -> typed
            raise InvalidKey(f"ML-DSA unavailable ({alg}): {exc}") from exc

    @classmethod
    def from_seed(cls, seed: bytes, kid: str, *, alg: str = "ML-DSA-65") -> "MLDSASigningKey":
        priv_cls, _ = _mldsa_classes(alg)
        if len(seed) != _MLDSA_SEED_BYTES:
            raise InvalidKey(f"ML-DSA seed must be {_MLDSA_SEED_BYTES} bytes, got {len(seed)}")
        return cls(priv_cls.from_seed_bytes(seed), kid, alg)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str) -> "MLDSASigningKey":
        if jwk.get("kty") != "AKP" or "priv" not in jwk:
            raise InvalidKey("not an AKP (ML-DSA) private JWK")
        alg = jwk.get("alg")
        if not isinstance(alg, str) or alg not in MLDSA_ALGS:
            raise InvalidKey(f"unsupported AKP alg {alg!r}")
        return cls.from_seed(_b64url_decode(jwk["priv"]), kid, alg=alg)


# --------------------------------------------------------------------------- #
# RFC 7638 JWK Thumbprint
# --------------------------------------------------------------------------- #

_THUMBPRINT_HASHES = {
    "sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512,
}
_DEFAULT_THUMBPRINT_HASH = "sha-256"

# RFC 7638 §3.2 (+ RFC 8037 §2 for OKP): the members that are *required* for each key
# type, and only these, form the canonical JSON. Everything else — `kid`, `use`, `alg`,
# `x5c`, and in particular every private member (`d`, `p`, `q`, `dp`, `dq`, `qi`) — is
# excluded by construction, which is what makes a private key and its public half hash
# identically. Listing the sets explicitly (rather than filtering a deny-list) means a
# member we have never heard of can never leak into a digest.
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
    "oct": ("k", "kty"),
}


def jwk_thumbprint_bytes(
    jwk: Mapping[str, Any], *, hash_name: str = _DEFAULT_THUMBPRINT_HASH
) -> bytes:
    """The raw RFC 7638 JWK Thumbprint digest of *jwk*.

    The digest covers **only** the members RFC 7638 declares required for the key
    type, serialized with no whitespace and ordered lexicographically by code point.
    A private key and its public half therefore produce the *same* thumbprint.

    Fails closed: an unknown ``kty``, a missing required member, a non-string
    member value, or a member holding a lone UTF-16 surrogate (JSON ``"\\ud800"``, which
    has no UTF-8 form to digest) raises :class:`InvalidKey` rather than hashing a partial
    key.
    """
    try:
        hasher = _THUMBPRINT_HASHES[hash_name]
    except KeyError as exc:
        raise InvalidKey(f"unsupported thumbprint hash {hash_name!r}") from exc

    kty = jwk.get("kty")
    if not isinstance(kty, str):
        raise InvalidKey("JWK has no string 'kty'; cannot compute a thumbprint")
    try:
        members = _THUMBPRINT_MEMBERS[kty]
    except KeyError as exc:
        raise InvalidKey(f"unsupported JWK kty {kty!r} for a thumbprint") from exc

    canonical: dict[str, str] = {}
    for name in members:
        value = jwk.get(name)
        if not isinstance(value, str):
            # The canonical form is defined over string members. A missing or
            # non-string one means we would be digesting something other than the
            # key the caller believes they hold — reject instead of guessing.
            raise InvalidKey(
                f"JWK of kty {kty!r} needs a string {name!r} member for a thumbprint")
        # ensure_ascii=False below passes a lone UTF-16 surrogate (JSON "\ud800") through,
        # and it has no UTF-8 form to digest. Refuse it here, naming the member, not its text.
        _json.utf8(value, error=InvalidKey, what=f"JWK member {name!r}")
        canonical[name] = value

    # sort_keys gives RFC 7638 §3's lexicographic-by-code-point order; the separators
    # drop the whitespace it forbids; ensure_ascii=False keeps the UTF-8 serialization
    # the RFC specifies rather than \u-escaping it into a different digest.
    serialized = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hasher(serialized.encode("utf-8")).digest()


def jwk_thumbprint(
    jwk: Mapping[str, Any], *, hash_name: str = _DEFAULT_THUMBPRINT_HASH
) -> str:
    """The RFC 7638 JWK Thumbprint of *jwk*, base64url-encoded without padding.

    This is the form used as a `kid`, in a `cnf` claim, and as the DPoP `jkt`. For
    the raw digest — e.g. the ``mdoc_jwk_thumbprint`` an ISO 18013-7 SessionTranscript
    needs — use :func:`jwk_thumbprint_bytes`.

    Fails closed exactly as :func:`jwk_thumbprint_bytes` does: :class:`InvalidKey` for an
    unknown ``kty``, a missing or non-string required member, or a member holding a lone
    UTF-16 surrogate.
    """
    return _b64url_encode(jwk_thumbprint_bytes(jwk, hash_name=hash_name))


# --------------------------------------------------------------------------- #
# Canonical public JWK — the RFC 7638 members, fixed-width unpadded base64url
# --------------------------------------------------------------------------- #

# RFC 7518 §6.2.1.2 / §6.2.1.3 and RFC 8037 §2: the exact octet length of every binary
# member, per curve. A coordinate of any other length is not another spelling of the
# key — the RFC makes the full fixed width a MUST — so it is refused, never widened or
# trimmed into shape.
_CANONICAL_WIDTHS: dict[tuple[str, str], int] = {
    ("EC", "P-256"): P256_COORD_BYTES,
    ("EC", "P-384"): P384_COORD_BYTES,
    ("OKP", "Ed25519"): 32,
}
_EC_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}

# edwards25519's field prime, and the y-coordinate of each of its eight small-order points
# (the torsion subgroup): 1 is the identity, p-1 the point of order 2, 0 the two points of
# order 4 (x = ±sqrt(-1), told apart by the sign bit) and the last two the four points of
# order 8 (each with either sign bit). libsodium's `ge25519_has_small_order` blocklist, in
# little-endian hex 26e8958f…fc05 and c7176a70…037a; a test re-derives them from the curve
# constants. `Ed25519PublicKey.from_public_bytes` checks only the length, so without this
# the identity point alone has four 32-byte spellings — y = 1 and y = 1 + p, each with
# either sign bit — all "canonical" base64url, all distinct thumbprints, and a signature
# under it needs no private key at all (RFC 8032 §5.1.3 would refuse three of the four).
_ED25519_P = 2**255 - 19
_ED25519_SMALL_ORDER_Y: frozenset[int] = frozenset({
    0, 1, _ED25519_P - 1,
    2707385501144840649318225287225658788936804267575313519463743609750303402022,
    55188659117513257062467267217118295137698188065244968500265048394206261417927,
})


def _check_ed25519_point(enc: bytes) -> None:
    """Refuse a 32-byte Ed25519 encoding that is not a canonical, usable public key.

    RFC 8032 §5.1.3: decoding fails for y >= p (the top bit is the sign of x, the other 255
    bits are y) and for x = 0 with the sign bit set — the only points with x = 0 are the
    identity (y = 1) and the point of order 2 (y = p - 1), both in the small-order set
    below, so that rule is covered there. The eight small-order points are refused as
    libsodium does: a "key" of order 8 or less signs nothing anyone holds, and its
    alternate encodings are exactly the spellings a canonical form exists to remove.
    """
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        raise InvalidKey(
            "JWK member 'x' is not a canonical Ed25519 point encoding "
            "(y >= p, RFC 8032 §5.1.3)")
    if y in _ED25519_SMALL_ORDER_Y:
        raise InvalidKey(
            "JWK member 'x' is a small-order Ed25519 point, not a usable public key")


def _shown(value: Any) -> str:
    """A key-type label fit for an error message: the string itself when short, else only
    its type — the value is the peer's and may be arbitrarily long."""
    return repr(value) if isinstance(value, str) and len(value) <= 32 else type(value).__name__


def canonical_public_jwk(jwk: Mapping[str, Any], *, strict: bool = False) -> dict[str, Any]:
    """The minimal canonical form of an EC or OKP public JWK.

    Returns a fresh dict holding **only** the RFC 7638 thumbprint members of the key type
    (``kty``/``crv``/``x``/``y`` for EC, ``kty``/``crv``/``x`` for OKP), each binary member
    decoded through the key backend and re-encoded as fixed-width, unpadded base64url —
    the spelling the ``public_jwk()`` of every backend here emits. ``kid``, ``alg``,
    ``use``, ``key_ops``, ``x5u``/``jku``/``x5c`` and any member this function has never
    heard of are dropped by construction, which is what makes the result safe to copy into
    a ``cnf.jwk`` or to deduplicate wallet keys by.

    Why it exists: RFC 7638 digests the member *strings*, while the tolerant base64url
    decoder behind signature verification accepts an explicit ``=`` padding, a
    non-alphabet character, the standard ``+``/``/`` alphabet and non-zero trailing bits.
    One key therefore has many spellings that verify identically and thumbprint
    differently; thumbprinting *this* form instead gives one digest per key.

    *strict*: when ``True``, a binary member whose spelling is not already the canonical
    one — padding, a non-alphabet character, non-zero trailing bits — raises
    :class:`NonCanonicalKey` (an :class:`InvalidKey`) naming the member, never echoing its
    value. Use it on a JWK the peer chose, where the rule is "send it canonically or be
    refused"; leave it ``False`` to normalise material from a trusted source (a
    certificate, a key attestation).

    Supports the curves the backends decode: EC ``P-256`` / ``P-384`` and OKP
    ``Ed25519``. Fails closed with :class:`InvalidKey` for anything else (RSA, ``oct``,
    the AKP ML-DSA shape, an unknown ``crv``), a non-object input, a missing or non-string
    member, a member that is not base64url at all (a lone UTF-16 surrogate included —
    named by code point and index, as :func:`jwk_thumbprint_bytes` does), a member of the
    wrong width (RFC 7518 §6.2.1.2), an EC point that is not on the curve or has a
    coordinate >= p, and an Ed25519 encoding that is not a canonical point (y >= p, RFC
    8032 §5.1.3) or is one of the eight small-order points. Messages name a member, never
    echo its value.
    """
    if not isinstance(jwk, Mapping):
        raise InvalidKey(f"JWK must be a JSON object, got {type(jwk).__name__}")
    kty = jwk.get("kty")
    if not isinstance(kty, str):
        raise InvalidKey("JWK has no string 'kty'; cannot canonicalize it")
    if kty not in _THUMBPRINT_MEMBERS:
        raise InvalidKey(f"unsupported JWK kty {_shown(kty)} for a canonical public key")
    crv = jwk.get("crv")
    if not isinstance(crv, str) or (kty, crv) not in _CANONICAL_WIDTHS:
        raise InvalidKey(
            f"no canonical public form for kty={_shown(kty)} crv={_shown(crv)}: "
            "EC P-256 / P-384 and OKP Ed25519 only")
    width = _CANONICAL_WIDTHS[(kty, crv)]
    # Reuse the thumbprint's member sets rather than restating them: the binary members
    # are exactly the RFC 7638 members that are not the key-type labels.
    binary = [name for name in _THUMBPRINT_MEMBERS[kty] if name not in ("kty", "crv")]

    decoded: dict[str, bytes] = {}
    for name in binary:
        value = jwk.get(name)
        if not isinstance(value, str):
            raise InvalidKey(f"JWK of kty {kty!r} needs a string {name!r} member")
        # A lone surrogate (JSON "\ud800") has no UTF-8 form; name the code point and its
        # index, never the text, before the base64 decoder gets to complain about it.
        _json.utf8(value, error=InvalidKey, what=f"JWK member {name!r}")
        try:
            raw = _b64url_decode(value)
        except (ValueError, TypeError) as exc:            # binascii.Error is a ValueError
            raise InvalidKey(f"JWK member {name!r} is not base64url: {exc}") from exc
        if len(raw) != width:
            raise InvalidKey(
                f"JWK member {name!r} must decode to the {width}-byte fixed width of "
                f"{crv} (RFC 7518 §6.2.1.2), got {len(raw)} bytes")
        decoded[name] = raw

    # Are these bytes a key at all? For EC the backend decides — `from_encoded_point`
    # refuses an off-curve point and a coordinate >= p (which `EllipticCurvePublicNumbers`
    # would silently reduce). For Ed25519 `from_public_bytes` checks only the length, so
    # the RFC 8032 decoding rules and the small-order blocklist are applied here first.
    try:
        if kty == "EC":
            ec.EllipticCurvePublicKey.from_encoded_point(
                _EC_CURVES[crv](), b"\x04" + decoded["x"] + decoded["y"])
        else:
            _check_ed25519_point(decoded["x"])
            ed25519.Ed25519PublicKey.from_public_bytes(decoded["x"])
    except (ValueError, TypeError) as exc:
        raise InvalidKey(f"JWK is not a valid {crv} public key: {exc}") from exc

    canonical: dict[str, Any] = {"kty": kty, "crv": crv}
    for name in binary:
        canonical[name] = _b64url_encode(decoded[name])
    if strict:
        off = [name for name in binary if jwk[name] != canonical[name]]
        if off:
            raise NonCanonicalKey(
                f"JWK member(s) {off} are not canonical base64url (RFC 7515 §2: the "
                "URL-safe alphabet, no padding, zero trailing bits)")
    return canonical


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
        if alg in MLDSA_ALGS:                              # experimental PQ (RFC 9964)
            _, pub_cls = _mldsa_classes(alg)               # typed InvalidKey if cryptography<48
            pub_cls.from_public_bytes(_b64url_decode(public_jwk["pub"])).verify(
                signature, signing_input)                  # raises InvalidSignature on failure
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
    if kty == "AKP":                                   # experimental ML-DSA (RFC 9964)
        return MLDSASigningKey.from_jwk(jwk, kid)
    raise InvalidKey(f"unsupported key type kty={kty!r} crv={crv!r}")


__all__ = [
    "Ed25519SigningKey",
    "InvalidKey",
    "KeyAgreementKey",
    "KeyBackendError",
    "MLDSA_ALGS",
    "MLDSASigningKey",
    "NonCanonicalKey",
    "P256KeyAgreementKey",
    "P256SigningKey",
    "P384SigningKey",
    "canonical_public_jwk",
    "jwk_thumbprint",
    "jwk_thumbprint_bytes",
    "mldsa_available",
    "signing_key_from_jwk",
    "verify_signature",
]
