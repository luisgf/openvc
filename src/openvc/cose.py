"""
openvc.cose — verify COSE_Sign1 / COSE_Mac0 (RFC 9052), the signature layer of
ISO 18013-5 ``mso_mdoc``.

A **verify-only**, hand-rolled, dependency-free reader for the two COSE structures an
mdoc verifier meets: ``COSE_Sign1`` (the issuer's ``IssuerAuth`` over the MSO, and the
holder's ``DeviceSignature``) and ``COSE_Mac0`` (the holder's ``DeviceMac``). It parses
the structure, rebuilds the ``Sig_structure`` / ``MAC_structure`` the signer covered
(RFC 9052 §4.4 / §6.3), and checks it — reusing :func:`openvc.keys.verify_signature`
(COSE ECDSA is the same raw ``R‖S`` as JOSE) and, for the MAC, a constant-time HMAC.

Like the JOSE path, the **algorithm is allow-listed before any crypto runs**: only
``ES256`` (COSE ``-7``), ``ES384`` (``-35``) and ``EdDSA`` (``-8``) for signatures, and
``HMAC 256/256`` (``5``) for the MAC. Everything else — RSA, ES512, the reserved
values — is rejected up front, mirroring the JOSE ``{ES256, ES384, EdDSA}`` allow-list.
There is **no signing surface here** (ADR-0005): openvc consumes and verifies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from . import cbor
from .errors import OpenvcError
from .keys import verify_signature

__all__ = [
    "CoseError",
    "CoseMalformed",
    "CoseUnsupportedAlgorithm",
    "CoseSign1",
    "CoseMac0",
    "COSE_ALG_TO_JOSE",
    "parse_sign1",
    "parse_mac0",
    "verify_sign1",
    "verify_mac0",
    "x5chain_ders",
    "cose_key_to_jwk",
]

# COSE header labels (RFC 9052 §3.1, RFC 9360 §2).
_HDR_ALG = 1
_HDR_CRIT = 2
_HDR_X5CHAIN = 33

# Protected-header labels this verifier actually processes; a `crit` (label 2) listing any
# label outside this set must fail closed (RFC 9052 §3.1).
_KNOWN_CRIT_LABELS = frozenset({_HDR_ALG, _HDR_X5CHAIN})

# COSE algorithm identifiers -> the JOSE name openvc.keys.verify_signature understands.
# Deliberately narrow (the mdoc/EUDI profile is ES256; ES384 and EdDSA are the other
# curves ISO 18013-5 §9.1.3.6 permits). ES512 and RSA are intentionally absent.
COSE_ALG_TO_JOSE = {-7: "ES256", -35: "ES384", -8: "EdDSA"}
_COSE_HMAC_256 = 5                       # HMAC w/ SHA-256 (COSE_Mac0 DeviceMac)

# COSE_Key (RFC 9052 §7) label/value constants.
_KEY_KTY = 1
_KEY_CRV = -1
_KEY_X = -2
_KEY_Y = -3
_KTY_OKP = 1
_KTY_EC2 = 2
_CRV_P256 = 1
_CRV_P384 = 2
_CRV_ED25519 = 6
_EC2_CRV_TO_JWK = {_CRV_P256: ("P-256", 32), _CRV_P384: ("P-384", 48)}


class CoseError(OpenvcError):
    """A COSE structure is malformed, uses an unsupported algorithm, or fails to verify."""


class CoseMalformed(CoseError):
    """The COSE_Sign1 / COSE_Mac0 shape or a header is not well-formed."""


class CoseUnsupportedAlgorithm(CoseError):
    """The COSE ``alg`` is not in the allow-list (rejected before any crypto)."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
# COSE_Sign1
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CoseSign1:
    """A parsed ``COSE_Sign1`` (RFC 9052 §4.2): ``[protected, unprotected, payload,
    signature]``. *protected* is the raw protected-header bstr (signed as-is);
    *payload* is the attached message bytes, or ``None`` when detached (nil)."""
    protected: bytes
    protected_header: dict[Any, Any]
    unprotected: dict[Any, Any]
    payload: bytes | None
    signature: bytes

    @property
    def alg(self) -> int:
        """The signature algorithm (COSE label 1) from the **protected** header. Raises
        :class:`CoseMalformed` if absent or not an integer (RFC 9052 §3.1: `alg` is
        integrity-critical, so it is never taken from the unsigned unprotected header)."""
        return _require_alg(self.protected_header)


@dataclass(frozen=True)
class CoseMac0:
    """A parsed ``COSE_Mac0`` (RFC 9052 §6.2): ``[protected, unprotected, payload,
    tag]``. Same shape as :class:`CoseSign1` with the MAC in *tag*."""
    protected: bytes
    protected_header: dict[Any, Any]
    unprotected: dict[Any, Any]
    payload: bytes | None
    tag: bytes

    @property
    def alg(self) -> int:
        return _require_alg(self.protected_header)


def _unwrap(obj: Any, tag: int, kind: str) -> list[Any]:
    """Accept the structure tagged (``#6.<tag>``) or bare, returning its 4-element
    array. mdoc carries these untagged inside the DeviceResponse; other producers tag."""
    if isinstance(obj, cbor.CborTag):
        if obj.tag != tag:
            raise CoseMalformed(f"{kind}: unexpected CBOR tag {obj.tag}")
        obj = obj.value
    if not isinstance(obj, list) or len(obj) != 4:
        raise CoseMalformed(f"{kind} must be a 4-element array")
    return obj


def _parse_protected(protected: Any, kind: str) -> tuple[bytes, dict[Any, Any]]:
    if not isinstance(protected, (bytes, bytearray)):
        raise CoseMalformed(f"{kind}: protected header must be a byte string")
    protected = bytes(protected)
    if protected == b"":                     # RFC 9052: empty bstr == no protected params
        return protected, {}
    try:
        header = cbor.decode(protected)
    except cbor.CborError as exc:
        raise CoseMalformed(f"{kind}: protected header is not valid CBOR: {exc}") from exc
    if not isinstance(header, dict):
        raise CoseMalformed(f"{kind}: protected header must be a CBOR map")
    _reject_unhandled_crit(header, kind)
    return protected, header


def _reject_unhandled_crit(header: dict[Any, Any], kind: str) -> None:
    """RFC 9052 §3.1: if the protected header carries ``crit`` (label 2), every label it
    lists is one the recipient MUST understand — so any label this verifier does not
    process fails closed rather than being silently ignored."""
    if _HDR_CRIT not in header:
        return
    crit = header[_HDR_CRIT]
    if not isinstance(crit, list) or not crit:
        raise CoseMalformed(f"{kind}: 'crit' (label 2) must be a non-empty array")
    unknown = [lbl for lbl in crit if lbl not in _KNOWN_CRIT_LABELS]
    if unknown:
        raise CoseMalformed(f"{kind}: unsupported critical header label(s) {unknown!r}")


def _require_alg(protected_header: dict[Any, Any]) -> int:
    # RFC 9052 §3.1: `alg` is integrity-critical and MUST be read from the PROTECTED header
    # only. The unprotected header is not covered by the signature, so honouring an `alg`
    # there would let an attacker choose the verification algorithm on an unsigned field.
    alg = protected_header.get(_HDR_ALG)
    if not isinstance(alg, int) or isinstance(alg, bool):
        raise CoseMalformed("COSE protected header has no integer 'alg' (label 1)")
    return alg


def parse_sign1(obj: Any) -> CoseSign1:
    """Parse a ``COSE_Sign1`` (tagged ``#6.18`` or bare). Does **not** verify."""
    protected_raw, unprotected, payload, signature = _unwrap(obj, cbor.TAG_COSE_SIGN1, "COSE_Sign1")
    protected, header = _parse_protected(protected_raw, "COSE_Sign1")
    if not isinstance(unprotected, dict):
        raise CoseMalformed("COSE_Sign1: unprotected header must be a map")
    if payload is not None and not isinstance(payload, (bytes, bytearray)):
        raise CoseMalformed("COSE_Sign1: payload must be a byte string or nil")
    if not isinstance(signature, (bytes, bytearray)):
        raise CoseMalformed("COSE_Sign1: signature must be a byte string")
    return CoseSign1(
        protected=protected, protected_header=header, unprotected=unprotected,
        payload=None if payload is None else bytes(payload), signature=bytes(signature))


def parse_mac0(obj: Any) -> CoseMac0:
    """Parse a ``COSE_Mac0`` (tagged ``#6.17`` or bare). Does **not** verify."""
    protected_raw, unprotected, payload, tag = _unwrap(obj, cbor.TAG_COSE_MAC0, "COSE_Mac0")
    protected, header = _parse_protected(protected_raw, "COSE_Mac0")
    if not isinstance(unprotected, dict):
        raise CoseMalformed("COSE_Mac0: unprotected header must be a map")
    if payload is not None and not isinstance(payload, (bytes, bytearray)):
        raise CoseMalformed("COSE_Mac0: payload must be a byte string or nil")
    if not isinstance(tag, (bytes, bytearray)):
        raise CoseMalformed("COSE_Mac0: tag must be a byte string")
    return CoseMac0(
        protected=protected, protected_header=header, unprotected=unprotected,
        payload=None if payload is None else bytes(payload), tag=bytes(tag))


def _tbs(context: str, protected: bytes, external_aad: bytes, payload: bytes) -> bytes:
    # Sig_structure / MAC_structure (RFC 9052 §4.4 / §6.3), deterministically encoded.
    return cbor.encode([context, protected, external_aad, payload])


def _effective_payload(
    attached: bytes | None, detached: bytes | None, kind: str
) -> bytes:
    if attached is not None:
        if detached is not None:
            raise CoseMalformed(
                f"{kind}: payload is attached but a detached payload was also supplied")
        return attached
    if detached is None:
        raise CoseMalformed(f"{kind}: payload is detached (nil) but none was supplied")
    return detached


def verify_sign1(
    sign1: CoseSign1,
    *,
    public_jwk: dict[str, Any],
    detached_payload: bytes | None = None,
    external_aad: bytes = b"",
) -> bool:
    """Verify a ``COSE_Sign1`` against *public_jwk*. Pass *detached_payload* when the
    payload field is nil (``DeviceSignature`` over ``DeviceAuthenticationBytes``); for an
    attached payload (``IssuerAuth`` over the MSO) leave it ``None``. The ``alg`` is
    allow-listed first (raises :class:`CoseUnsupportedAlgorithm`); returns ``True``/``False``."""
    jose_alg = COSE_ALG_TO_JOSE.get(sign1.alg)
    if jose_alg is None:
        raise CoseUnsupportedAlgorithm(
            f"COSE_Sign1 alg {sign1.alg} is not allow-listed (need one of "
            f"{sorted(COSE_ALG_TO_JOSE)} = ES256/ES384/EdDSA)")
    payload = _effective_payload(sign1.payload, detached_payload, "COSE_Sign1")
    tbs = _tbs("Signature1", sign1.protected, external_aad, payload)
    return verify_signature(
        alg=jose_alg, public_jwk=public_jwk, signing_input=tbs, signature=sign1.signature)


def verify_mac0(
    mac0: CoseMac0,
    *,
    mac_key: bytes,
    detached_payload: bytes | None = None,
    external_aad: bytes = b"",
) -> bool:
    """Verify a ``COSE_Mac0`` tag with *mac_key* (the derived ``EMacKey``) under
    HMAC-SHA-256, constant-time. Only ``HMAC 256/256`` (alg 5) is accepted."""
    if mac0.alg != _COSE_HMAC_256:
        raise CoseUnsupportedAlgorithm(
            f"COSE_Mac0 alg {mac0.alg} is not allow-listed (need 5 = HMAC 256/256)")
    payload = _effective_payload(mac0.payload, detached_payload, "COSE_Mac0")
    tbm = _tbs("MAC0", mac0.protected, external_aad, payload)
    expected = hmac.new(mac_key, tbm, hashlib.sha256).digest()
    return hmac.compare_digest(expected, mac0.tag)


# --------------------------------------------------------------------------- #
# x5chain (RFC 9360) and COSE_Key (RFC 9052 §7)
# --------------------------------------------------------------------------- #

def x5chain_ders(sign1: CoseSign1) -> list[bytes]:
    """The certificate chain (label 33) as DER bytes, leaf first. A single certificate
    may appear as one bstr; a chain is an array of bstr. Checks the unprotected header
    then the protected one. Raises :class:`CoseMalformed` if absent or malformed."""
    value = sign1.unprotected.get(_HDR_X5CHAIN, sign1.protected_header.get(_HDR_X5CHAIN))
    if value is None:
        raise CoseMalformed("COSE_Sign1 has no x5chain (label 33) to anchor the signer")
    if isinstance(value, (bytes, bytearray)):
        return [bytes(value)]
    if isinstance(value, list) and value and all(isinstance(c, (bytes, bytearray)) for c in value):
        return [bytes(c) for c in value]
    raise CoseMalformed("x5chain must be a certificate bstr or a non-empty array of bstr")


def cose_key_to_jwk(cose_key: Any) -> dict[str, Any]:
    """Convert a ``COSE_Key`` (RFC 9052 §7) map to a public JWK. Supports EC2 (P-256 /
    P-384) and OKP (Ed25519) — the curves :func:`openvc.keys.verify_signature` verifies.
    Raises :class:`CoseMalformed` on any other key type/curve or a malformed coordinate."""
    if not isinstance(cose_key, dict):
        raise CoseMalformed("COSE_Key must be a CBOR map")
    kty = cose_key.get(_KEY_KTY)
    if kty == _KTY_EC2:
        crv = cose_key.get(_KEY_CRV)
        info = (_EC2_CRV_TO_JWK.get(crv)
                if isinstance(crv, int) and not isinstance(crv, bool) else None)
        if info is None:
            raise CoseMalformed(f"COSE_Key EC2 curve {crv!r} is not P-256 or P-384")
        name, size = info
        x, y = cose_key.get(_KEY_X), cose_key.get(_KEY_Y)
        if not isinstance(x, (bytes, bytearray)) or not isinstance(y, (bytes, bytearray)):
            raise CoseMalformed("COSE_Key EC2 needs byte-string x (-2) and y (-3) coordinates")
        if len(x) != size or len(y) != size:
            raise CoseMalformed(f"COSE_Key EC2 {name} coordinates must be {size} bytes")
        return {"kty": "EC", "crv": name, "x": _b64url(bytes(x)), "y": _b64url(bytes(y))}
    if kty == _KTY_OKP:
        crv = cose_key.get(_KEY_CRV)
        if crv != _CRV_ED25519 or isinstance(crv, bool):
            raise CoseMalformed(f"COSE_Key OKP curve {crv!r} is not Ed25519")
        x = cose_key.get(_KEY_X)
        if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
            raise CoseMalformed("COSE_Key OKP Ed25519 needs a 32-byte x (-2)")
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(bytes(x))}
    raise CoseMalformed(f"COSE_Key kty {kty!r} is not EC2 (2) or OKP (1)")
