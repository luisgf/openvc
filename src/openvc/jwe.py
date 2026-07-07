"""
openvc.jwe — decrypt a JWE Compact token (JWE ``ECDH-ES`` direct key agreement).

**Decrypt only.** A verifier consuming a HAIP / OpenID4VP 1.0 encrypted Authorization
Response (``direct_post.jwt``) receives the ``vp_token`` wrapped in a JWE; this turns
that JWE back into its plaintext bytes. Generating (encrypting) a response is a wallet
concern and out of scope.

Exactly the HAIP-mandated shape is accepted, **allow-listed before any crypto** (the
same fail-closed stance the JWS path takes for signatures): key management
``ECDH-ES`` (direct — the CEK is derived, there is no wrapped key), content encryption
``A128GCM`` / ``A256GCM``, over an ephemeral **P-256** key. The ECDH runs through a
:class:`~openvc.keys.KeyAgreementKey` backend, so the recipient's private half can
live in an HSM/Vault. The public NIST SP 800-56A Concat KDF (RFC 7518 §4.6) and the
AES-GCM decrypt are done here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import OpenvcError
from .keys import KeyAgreementKey, KeyBackendError

__all__ = [
    "decrypt_compact",
    "JweError",
    "JweMalformed",
    "UnsupportedJweAlgorithm",
    "JweDecryptionFailed",
    "ALLOWED_ALG",
    "ALLOWED_ENC",
]

# The fail-closed allow-list (HAIP 1.0). Anything else is rejected before any crypto.
ALLOWED_ALG = frozenset({"ECDH-ES"})               # direct key agreement, empty encrypted_key
ALLOWED_ENC = {"A128GCM": 16, "A256GCM": 32}       # content encryption -> CEK length (bytes)


class JweError(OpenvcError):
    """Base class for JWE decryption failures."""


class JweMalformed(JweError):
    """The JWE token / header is structurally invalid."""


class UnsupportedJweAlgorithm(JweError):
    """A JWE ``alg`` / ``enc`` outside the fail-closed allow-list."""


class JweDecryptionFailed(JweError):
    """The AES-GCM tag did not verify (wrong key, or tampered ciphertext)."""


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _len_prefixed(data: bytes) -> bytes:
    """NIST SP 800-56A ``Datalen ‖ Data`` (a 32-bit big-endian length, then the bytes)."""
    return struct.pack(">I", len(data)) + data


def _concat_kdf(z: bytes, keydatalen_bits: int, alg_id: bytes, apu: bytes, apv: bytes) -> bytes:
    """The NIST SP 800-56A Concat KDF with SHA-256 (RFC 7518 §4.6.2).

    For direct ``ECDH-ES`` the ``AlgorithmID`` is the ``enc`` value, ``PartyUInfo`` /
    ``PartyVInfo`` are ``apu`` / ``apv`` (each length-prefixed), ``SuppPubInfo`` is the
    32-bit key length, and there is no ``SuppPrivInfo``.
    """
    other_info = (_len_prefixed(alg_id) + _len_prefixed(apu) + _len_prefixed(apv)
                  + struct.pack(">I", keydatalen_bits))
    keydatalen_bytes = keydatalen_bits // 8
    out = b""
    counter = 1
    while len(out) < keydatalen_bytes:                 # one SHA-256 round covers 128/256-bit
        out += hashlib.sha256(struct.pack(">I", counter) + z + other_info).digest()
        counter += 1
    return out[:keydatalen_bytes]


def decrypt_compact(token: str, *, key: KeyAgreementKey) -> bytes:
    """Decrypt a JWE Compact *token* to its plaintext bytes.

    Accepts only direct ``ECDH-ES`` + ``A128GCM`` / ``A256GCM`` over a P-256 ephemeral
    key (allow-listed before any crypto). *key* is the recipient's
    :class:`~openvc.keys.KeyAgreementKey`; the raw ECDH runs inside it, so a
    Vault/HSM private half never enters the process. Raises
    :class:`UnsupportedJweAlgorithm` for a disallowed ``alg``/``enc``,
    :class:`JweMalformed` for a bad shape/header/ephemeral key, and
    :class:`JweDecryptionFailed` if the authentication tag does not verify.
    """
    parts = token.split(".")
    if len(parts) != 5:
        raise JweMalformed("a JWE Compact token has 5 base64url parts")
    protected_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

    try:
        header = json.loads(_b64url_decode(protected_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise JweMalformed(f"invalid JWE protected header: {exc}") from exc
    if not isinstance(header, dict):
        raise JweMalformed("JWE protected header must be a JSON object")

    alg = header.get("alg")
    enc = header.get("enc")
    # isinstance guards keep an unhashable alg/enc (a JSON list/object) from raising a
    # bare TypeError out of the `in frozenset/dict` test — fail closed and typed.
    if not isinstance(alg, str) or alg not in ALLOWED_ALG:
        raise UnsupportedJweAlgorithm(f"JWE alg {alg!r} is not permitted (only ECDH-ES)")
    if not isinstance(enc, str) or enc not in ALLOWED_ENC:
        raise UnsupportedJweAlgorithm(
            f"JWE enc {enc!r} is not permitted (only A128GCM / A256GCM)")
    if header.get("zip") is not None:                  # no decompression -> no zip bombs
        raise UnsupportedJweAlgorithm("JWE compression ('zip') is not supported")
    if "crit" in header:                               # unknown critical extensions -> reject
        raise UnsupportedJweAlgorithm("JWE 'crit' extensions are not supported")
    if encrypted_key_b64:                              # direct ECDH-ES derives the CEK
        raise JweMalformed("direct ECDH-ES must carry an empty encrypted key")

    epk = header.get("epk")
    if not isinstance(epk, dict):
        raise JweMalformed("ECDH-ES requires an 'epk' ephemeral public key in the header")
    try:
        z = key.agree(epk)                             # raw ECDH shared secret (HSM boundary)
    except KeyBackendError as exc:
        raise JweMalformed(f"invalid ephemeral public key (epk): {exc}") from exc

    try:
        apu = _b64url_decode(header["apu"]) if "apu" in header else b""
        apv = _b64url_decode(header["apv"]) if "apv" in header else b""
        iv = _b64url_decode(iv_b64)
        ciphertext = _b64url_decode(ciphertext_b64)
        tag = _b64url_decode(tag_b64)
    except (ValueError, TypeError) as exc:
        raise JweMalformed(f"invalid JWE base64url segment: {exc}") from exc
    if len(iv) != 12:                                  # JWE AES-GCM mandates a 96-bit IV
        raise JweMalformed(f"JWE AES-GCM IV must be 96-bit, got {len(iv) * 8}-bit")
    if len(tag) != 16:                                 # ...and a 128-bit authentication tag
        raise JweMalformed(f"JWE AES-GCM tag must be 128-bit, got {len(tag) * 8}-bit")

    cek = _concat_kdf(z, ALLOWED_ENC[enc] * 8, enc.encode("ascii"), apu, apv)
    aad = protected_b64.encode("ascii")                # RFC 7516 §5.1: AAD = ASCII(protected)
    try:
        return AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise JweDecryptionFailed("JWE authentication tag verification failed") from exc
    except ValueError as exc:                          # e.g. wrong IV length
        raise JweDecryptionFailed(f"JWE decryption failed: {exc}") from exc
