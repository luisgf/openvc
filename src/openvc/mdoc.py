"""
openvc.mdoc — verify a received ISO/IEC 18013-5 ``mso_mdoc`` (verify-only, server-side).

Given a ``DeviceResponse`` a wallet returned over OpenID4VP (ISO 18013-7 online), this
checks the two authentications ISO 18013-5 §9.1 defines and nothing more (ADR-0005):

* **Issuer data authentication** — the ``IssuerAuth`` ``COSE_Sign1`` over the
  ``MobileSecurityObject`` (MSO); the document-signer ``x5chain`` (COSE label 33)
  path-validated to a caller-provided **IACA** trust anchor; the MSO ``docType`` and
  ``validityInfo`` window; and, for every disclosed ``IssuerSignedItem``, the recomputed
  digest matched against ``MobileSecurityObject.valueDigests`` (the mdoc analogue of
  SD-JWT disclosure hashing).
* **Device authentication (holder binding)** — the ``DeviceSignature`` (``COSE_Sign1``)
  or ``DeviceMac`` (``COSE_Mac0``) over the ``DeviceAuthentication`` structure built from
  the OpenID4VP / ISO 18013-7 **SessionTranscript** (the caller supplies its bytes — see
  :mod:`openvc.openid4vp`). This is the session/replay binding, the security-critical crux.

**Out of scope**, unchanged from the ROADMAP: device engagement, NFC/BLE/QR proximity,
issuance / provisioning, and any COSE *signing* surface. This module consumes and verifies
one received document. It is dependency-free (hand-rolled CBOR + COSE, reusing
:mod:`openvc.keys` for the signature and :mod:`openvc.x5c` for the chain), fails closed on
every check, and ships **experimental** until interop-tested against the EUDI reference
wallet (ADR-0005 D7).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Sequence

from . import cbor, cose
from .errors import OpenvcError
from .x5c import X5cError, resolve_mdoc_signer_key

__all__ = [
    "MdocError",
    "MdocMalformed",
    "MdocTrustError",
    "MdocSignatureInvalid",
    "MdocDigestMismatch",
    "MdocValidityError",
    "MdocDocTypeMismatch",
    "MdocDeviceAuthError",
    "MdocValidity",
    "VerifiedMdoc",
    "verify_device_response",
    "verify_issuer_signed",
    "DEFAULT_LEEWAY_S",
]

DEFAULT_LEEWAY_S = 300

# ISO 18013-5 map keys (all text strings).
_DR_DOCUMENTS, _DR_STATUS = "documents", "status"
_DOC_DOCTYPE, _DOC_ISSUER_SIGNED, _DOC_DEVICE_SIGNED = "docType", "issuerSigned", "deviceSigned"
_IS_NAMESPACES, _IS_ISSUERAUTH = "nameSpaces", "issuerAuth"
_MSO_DIGEST_ALG, _MSO_VALUE_DIGESTS = "digestAlgorithm", "valueDigests"
_MSO_DEVICE_KEY_INFO, _MSO_DOCTYPE, _MSO_VALIDITY = "deviceKeyInfo", "docType", "validityInfo"
_DKI_DEVICE_KEY = "deviceKey"
_VI_SIGNED, _VI_VALID_FROM, _VI_VALID_UNTIL = "signed", "validFrom", "validUntil"
_ISI_DIGEST_ID, _ISI_ELEMENT_ID = "digestID", "elementIdentifier"
_ISI_ELEMENT_VALUE = "elementValue"
_DS_NAMESPACES, _DS_DEVICE_AUTH = "nameSpaces", "deviceAuth"
_DA_DEVICE_SIGNATURE, _DA_DEVICE_MAC = "deviceSignature", "deviceMac"

# MSO digest algorithms (ISO 18013-5 §9.1.2.5). Allow-listed — anything else fails closed.
_DIGEST_ALGS: dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512,
}


# --------------------------------------------------------------------------- #
# Errors (all fail closed; every check that fails raises one of these)
# --------------------------------------------------------------------------- #

class MdocError(OpenvcError):
    """Base: an mdoc ``DeviceResponse`` is malformed or fails to verify."""


class MdocMalformed(MdocError):
    """The DeviceResponse / MSO / COSE structure is not well-formed."""


class MdocTrustError(MdocError):
    """The document-signer chain did not path-validate to an IACA trust anchor."""


class MdocSignatureInvalid(MdocError):
    """The IssuerAuth (MSO) signature does not verify."""


class MdocDigestMismatch(MdocError):
    """A disclosed IssuerSignedItem's digest does not match the MSO ``valueDigests``."""


class MdocValidityError(MdocError):
    """The MSO ``validityInfo`` window does not include the evaluation instant."""


class MdocDocTypeMismatch(MdocError):
    """The MSO ``docType`` disagrees with the document (or the expected docType)."""


class MdocDeviceAuthError(MdocError):
    """Device authentication (holder binding) is missing or does not verify."""


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class MdocValidity:
    """The MSO ``validityInfo`` timestamps (ISO 18013-5 §9.1.2.4)."""
    signed: datetime | None
    valid_from: datetime | None
    valid_until: datetime | None


@dataclass(frozen=True)
class VerifiedMdoc:
    """One verified mdoc document.

    *namespaces* maps each disclosed namespace to ``{elementIdentifier: elementValue}`` —
    only the items whose digest matched the issuer's seal. *device_signed* is ``True`` when
    holder binding (DeviceAuth) was verified; it is ``False`` for a result from
    :func:`verify_issuer_signed`, which checks issuer data authentication only.
    """
    doc_type: str
    namespaces: dict[str, dict[str, Any]]
    device_signed: bool
    issuer_key: dict[str, Any]
    validity: MdocValidity

    def elements(self, namespace: str) -> dict[str, Any]:
        """The disclosed ``{elementIdentifier: elementValue}`` for *namespace* (empty if
        the document disclosed nothing under it)."""
        return dict(self.namespaces.get(namespace, {}))


@dataclass(frozen=True)
class _IssuerParts:
    doc_type: str
    namespaces: dict[str, dict[str, Any]]
    issuer_key: dict[str, Any]
    validity: MdocValidity
    mso: dict[Any, Any]


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #

def verify_device_response(
    device_response: bytes,
    *,
    trust_anchors: Sequence[Any],
    session_transcript: bytes,
    now: datetime | None = None,
    leeway_s: int = DEFAULT_LEEWAY_S,
    expected_doc_type: str | None = None,
    device_mac_key: bytes | None = None,
) -> list[VerifiedMdoc]:
    """Verify a received ``DeviceResponse`` (CBOR bytes) end to end — issuer data
    authentication **and** device authentication — and return one
    :class:`VerifiedMdoc` per document.

    *trust_anchors* are the IACA root ``x509.Certificate`` objects the document-signer
    chain must validate to (e.g. ``openvc.trustlist`` anchors). *session_transcript* is
    the CBOR-encoded ISO 18013-7 / OpenID4VP ``SessionTranscript`` the ``DeviceAuth``
    is bound to — build it with :func:`openvc.openid4vp` from the request's
    client_id / origin, nonce and the mdoc-generated nonce. *now* pins the instant for
    the ``validityInfo`` and chain-validity checks (defaults to now, UTC). Pass
    *expected_doc_type* to require every document to be that ``docType``.
    *device_mac_key* supplies the ISO 18013-5 ``EMacKey`` for a ``DeviceMac`` binding
    (proximity); the OpenID4VP online flow uses ``DeviceSignature`` and does not need it.

    Raises a typed :class:`MdocError` (fail closed) on any malformed structure or failed
    check; a single document failing rejects the whole response.
    """
    documents = _parse_response(device_response)
    results = []
    for document in documents:
        parts = _verify_issuer_signed(
            document, trust_anchors=trust_anchors, now=now, leeway_s=leeway_s,
            expected_doc_type=expected_doc_type)
        _verify_device_auth(document, parts, session_transcript, device_mac_key)
        results.append(VerifiedMdoc(
            doc_type=parts.doc_type, namespaces=parts.namespaces, device_signed=True,
            issuer_key=parts.issuer_key, validity=parts.validity))
    return results


def verify_issuer_signed(
    document: Any,
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None = None,
    leeway_s: int = DEFAULT_LEEWAY_S,
    expected_doc_type: str | None = None,
) -> VerifiedMdoc:
    """Verify **issuer data authentication only** for a single decoded mdoc *document*
    (the ``IssuerAuth`` seal over the MSO, the ``x5chain`` to an IACA anchor, the MSO
    validity window, and the ``valueDigests`` of every disclosed item) and return the
    disclosed claims.

    This does **not** check device authentication (holder binding) — the returned
    :class:`VerifiedMdoc` has ``device_signed=False``. Use it to verify the issuer seal of
    an mdoc at rest; for a presented mdoc use :func:`verify_device_response`, which also
    binds the holder to the session.
    """
    parts = _verify_issuer_signed(
        document, trust_anchors=trust_anchors, now=now, leeway_s=leeway_s,
        expected_doc_type=expected_doc_type)
    return VerifiedMdoc(
        doc_type=parts.doc_type, namespaces=parts.namespaces, device_signed=False,
        issuer_key=parts.issuer_key, validity=parts.validity)


# --------------------------------------------------------------------------- #
# DeviceResponse parsing
# --------------------------------------------------------------------------- #

def _parse_response(device_response: bytes) -> list[Any]:
    if not isinstance(device_response, (bytes, bytearray)):
        raise MdocMalformed("DeviceResponse must be CBOR bytes")
    try:
        parsed = cbor.decode(bytes(device_response))
    except cbor.CborError as exc:
        raise MdocMalformed(f"DeviceResponse is not valid CBOR: {exc}") from exc
    if not isinstance(parsed, dict):
        raise MdocMalformed("DeviceResponse must be a CBOR map")
    status = parsed.get(_DR_STATUS)
    if not isinstance(status, int) or isinstance(status, bool):
        raise MdocMalformed("DeviceResponse has no integer status")
    if status != 0:
        raise MdocMalformed(f"DeviceResponse status is {status} (not 0 = OK)")
    documents = parsed.get(_DR_DOCUMENTS)
    if not isinstance(documents, list) or not documents:
        raise MdocMalformed("DeviceResponse carries no documents")
    return documents


# --------------------------------------------------------------------------- #
# Issuer data authentication
# --------------------------------------------------------------------------- #

def _verify_issuer_signed(
    document: Any, *, trust_anchors: Sequence[Any], now: datetime | None,
    leeway_s: int, expected_doc_type: str | None,
) -> _IssuerParts:
    if not isinstance(document, dict):
        raise MdocMalformed("each document must be a CBOR map")
    doc_type = document.get(_DOC_DOCTYPE)
    if not isinstance(doc_type, str) or not doc_type:
        raise MdocMalformed("document has no docType")
    if expected_doc_type is not None and doc_type != expected_doc_type:
        raise MdocDocTypeMismatch(
            f"document docType {doc_type!r} is not the expected {expected_doc_type!r}")
    issuer_signed = document.get(_DOC_ISSUER_SIGNED)
    if not isinstance(issuer_signed, dict):
        raise MdocMalformed("document has no issuerSigned map")

    # IssuerAuth: DS key from x5chain -> IACA, then verify the COSE_Sign1 over the MSO.
    try:
        issuer_auth = cose.parse_sign1(issuer_signed.get(_IS_ISSUERAUTH))
        chain = cose.x5chain_ders(issuer_auth)
    except cose.CoseError as exc:
        raise MdocMalformed(f"issuerAuth: {exc}") from exc
    instant = _instant(now)
    try:
        issuer_key = resolve_mdoc_signer_key(chain, trust_anchors=trust_anchors, now=instant)
    except X5cError as exc:
        raise MdocTrustError(
            f"document-signer chain did not validate to an IACA anchor: {exc}") from exc
    if issuer_auth.payload is None:
        raise MdocMalformed("IssuerAuth has a detached payload (no MSO)")
    try:
        ok = cose.verify_sign1(issuer_auth, public_jwk=issuer_key)
    except cose.CoseError as exc:
        raise MdocSignatureInvalid(f"IssuerAuth signature could not be checked: {exc}") from exc
    if not ok:
        raise MdocSignatureInvalid("IssuerAuth (MSO) signature does not verify")

    mso = _decode_mso(issuer_auth.payload)
    mso_doc_type = mso.get(_MSO_DOCTYPE)
    if mso_doc_type != doc_type:
        raise MdocDocTypeMismatch(
            f"MSO docType {mso_doc_type!r} does not match the document docType {doc_type!r}")
    alg_name = mso.get(_MSO_DIGEST_ALG)
    hasher = _DIGEST_ALGS.get(alg_name) if isinstance(alg_name, str) else None
    if hasher is None:
        raise MdocMalformed(f"MSO digestAlgorithm {alg_name!r} is not SHA-256/384/512")
    validity = _check_validity(mso, instant, leeway_s)
    namespaces = _verify_value_digests(issuer_signed, mso, hasher)
    return _IssuerParts(doc_type, namespaces, issuer_key, validity, mso)


def _decode_mso(payload: bytes) -> dict[Any, Any]:
    try:
        tagged = cbor.decode(payload)
    except cbor.CborError as exc:
        raise MdocMalformed(f"MSO payload is not valid CBOR: {exc}") from exc
    if not isinstance(tagged, cbor.CborTag) or tagged.tag != cbor.TAG_ENCODED_CBOR:
        raise MdocMalformed("IssuerAuth payload is not a #6.24 embedded-CBOR MSO")
    if not isinstance(tagged.value, (bytes, bytearray)):
        raise MdocMalformed("MSO embedded-CBOR tag does not wrap a byte string")
    try:
        mso = cbor.decode(bytes(tagged.value))
    except cbor.CborError as exc:
        raise MdocMalformed(f"MSO is not valid CBOR: {exc}") from exc
    if not isinstance(mso, dict):
        raise MdocMalformed("MSO must be a CBOR map")
    return mso


def _verify_value_digests(
    issuer_signed: dict[Any, Any], mso: dict[Any, Any],
    hasher: Callable[[bytes], "hashlib._Hash"],
) -> dict[str, dict[str, Any]]:
    value_digests = mso.get(_MSO_VALUE_DIGESTS)
    if not isinstance(value_digests, dict):
        raise MdocMalformed("MSO has no valueDigests map")
    ns_items = issuer_signed.get(_IS_NAMESPACES)
    disclosed: dict[str, dict[str, Any]] = {}
    if ns_items is None:
        return disclosed                              # a response may disclose nothing
    if not isinstance(ns_items, dict):
        raise MdocMalformed("issuerSigned.nameSpaces must be a map")
    for namespace, items in ns_items.items():
        if not isinstance(namespace, str):
            raise MdocMalformed("issuerSigned namespace must be a text string")
        if not isinstance(items, list):
            raise MdocMalformed(f"namespace {namespace!r} must map to an array of items")
        ns_digests = value_digests.get(namespace)
        if not isinstance(ns_digests, dict):
            raise MdocDigestMismatch(
                f"MSO valueDigests has no digests for namespace {namespace!r}")
        claims: dict[str, Any] = {}
        for item in items:
            claims.update(_verify_item(namespace, item, ns_digests, hasher))
        disclosed[namespace] = claims
    return disclosed


def _verify_item(
    namespace: str, item: Any, ns_digests: dict[Any, Any],
    hasher: Callable[[bytes], "hashlib._Hash"],
) -> dict[str, Any]:
    # Each item is an IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem). The
    # digest is over the tagged item's EXACT received bytes (cbor keeps them on .raw), so
    # a non-canonically-encoded-but-signed item still matches — never a re-encoding.
    if (not isinstance(item, cbor.CborTag) or item.tag != cbor.TAG_ENCODED_CBOR
            or item.raw is None or not isinstance(item.value, (bytes, bytearray))):
        raise MdocMalformed("IssuerSignedItem must be a #6.24 embedded-CBOR byte string")
    digest = hasher(item.raw).digest()
    try:
        issuer_item = cbor.decode(bytes(item.value))
    except cbor.CborError as exc:
        raise MdocMalformed(f"IssuerSignedItem is not valid CBOR: {exc}") from exc
    if not isinstance(issuer_item, dict):
        raise MdocMalformed("IssuerSignedItem must be a CBOR map")
    digest_id = issuer_item.get(_ISI_DIGEST_ID)
    if not isinstance(digest_id, int) or isinstance(digest_id, bool):
        raise MdocMalformed("IssuerSignedItem has no integer digestID")
    expected = ns_digests.get(digest_id)
    if not isinstance(expected, (bytes, bytearray)):
        raise MdocDigestMismatch(
            f"MSO valueDigests[{namespace!r}] has no digest for digestID {digest_id}")
    if not hmac.compare_digest(digest, bytes(expected)):
        raise MdocDigestMismatch(
            f"IssuerSignedItem digestID {digest_id} in {namespace!r} does not match "
            f"its MSO valueDigest (tampered or wrong item)")
    element_id = issuer_item.get(_ISI_ELEMENT_ID)
    if not isinstance(element_id, str) or not element_id:
        raise MdocMalformed("IssuerSignedItem has no elementIdentifier")
    return {element_id: _plain(issuer_item.get(_ISI_ELEMENT_VALUE))}


def _plain(value: Any) -> Any:
    """Decoded CBOR -> a plain value for the caller: unwrap tags to their content (dates
    become their string), recurse into arrays/maps, leave bytes/scalars as-is."""
    if isinstance(value, cbor.CborTag):
        return _plain(value.value)
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------- #
# validityInfo
# --------------------------------------------------------------------------- #

def _check_validity(mso: dict[Any, Any], instant: datetime, leeway_s: int) -> MdocValidity:
    info = mso.get(_MSO_VALIDITY)
    if not isinstance(info, dict):
        raise MdocMalformed("MSO has no validityInfo map")
    signed = _parse_date(info.get(_VI_SIGNED))
    valid_from = _parse_date(info.get(_VI_VALID_FROM))
    valid_until = _parse_date(info.get(_VI_VALID_UNTIL))
    if valid_from is None or valid_until is None:
        raise MdocMalformed("MSO validityInfo needs both validFrom and validUntil")
    leeway = timedelta(seconds=leeway_s)
    if instant < valid_from - leeway:
        raise MdocValidityError(f"MSO is not yet valid (validFrom {valid_from.isoformat()})")
    if instant > valid_until + leeway:
        raise MdocValidityError(f"MSO has expired (validUntil {valid_until.isoformat()})")
    return MdocValidity(signed=signed, valid_from=valid_from, valid_until=valid_until)


def _parse_date(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, cbor.CborTag):
        if value.tag == cbor.TAG_DATE_TIME:
            return _parse_rfc3339(value.value)
        if value.tag == cbor.TAG_FULL_DATE:
            return _parse_full_date(value.value)
        raise MdocMalformed(f"validityInfo date has unexpected CBOR tag {value.tag}")
    if isinstance(value, str):                        # tolerate an untagged tstr date-time
        return _parse_rfc3339(value)
    raise MdocMalformed("validityInfo date must be a tdate / full-date string")


def _parse_rfc3339(text: Any) -> datetime:
    if not isinstance(text, str):
        raise MdocMalformed("date-time must be a text string")
    raw = text.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise MdocMalformed(f"invalid RFC 3339 date-time {text!r}: {exc}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _parse_full_date(text: Any) -> datetime:
    if not isinstance(text, str):
        raise MdocMalformed("full-date must be a text string")
    try:
        day = date.fromisoformat(text.strip())
    except ValueError as exc:
        raise MdocMalformed(f"invalid full-date {text!r}: {exc}") from exc
    return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Device authentication (holder binding)
# --------------------------------------------------------------------------- #

def _verify_device_auth(
    document: dict[Any, Any], parts: _IssuerParts,
    session_transcript: bytes, device_mac_key: bytes | None,
) -> None:
    device_signed = document.get(_DOC_DEVICE_SIGNED)
    if not isinstance(device_signed, dict):
        raise MdocDeviceAuthError("document has no deviceSigned (holder binding missing)")
    device_ns = device_signed.get(_DS_NAMESPACES)
    if (not isinstance(device_ns, cbor.CborTag) or device_ns.tag != cbor.TAG_ENCODED_CBOR
            or device_ns.raw is None):
        raise MdocMalformed("deviceSigned.nameSpaces must be a #6.24 embedded-CBOR value")
    device_auth = device_signed.get(_DS_DEVICE_AUTH)
    if not isinstance(device_auth, dict):
        raise MdocMalformed("deviceSigned has no deviceAuth map")
    if not isinstance(session_transcript, (bytes, bytearray)):
        raise MdocMalformed("session_transcript must be CBOR bytes")

    # DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication). The
    # SessionTranscript and DeviceNameSpacesBytes go in as their exact bytes (CborRaw),
    # so the ToBeSigned matches what the wallet signed byte for byte.
    device_authentication = cbor.encode([
        "DeviceAuthentication",
        cbor.CborRaw(bytes(session_transcript)),
        parts.doc_type,
        cbor.CborRaw(device_ns.raw),
    ])
    detached = cbor.encode(cbor.CborTag(cbor.TAG_ENCODED_CBOR, device_authentication))

    device_info = parts.mso.get(_MSO_DEVICE_KEY_INFO)
    if not isinstance(device_info, dict):
        raise MdocMalformed("MSO has no deviceKeyInfo")
    try:
        device_key = cose.cose_key_to_jwk(device_info.get(_DKI_DEVICE_KEY))
    except cose.CoseError as exc:
        raise MdocMalformed(f"MSO deviceKey: {exc}") from exc

    signature = device_auth.get(_DA_DEVICE_SIGNATURE)
    mac = device_auth.get(_DA_DEVICE_MAC)
    if signature is not None:
        try:
            sign1 = cose.parse_sign1(signature)
            ok = cose.verify_sign1(sign1, public_jwk=device_key, detached_payload=detached)
        except cose.CoseError as exc:
            raise MdocDeviceAuthError(f"DeviceSignature could not be checked: {exc}") from exc
        if not ok:
            raise MdocDeviceAuthError("DeviceSignature does not verify (holder binding failed)")
        return
    if mac is not None:
        if device_mac_key is None:
            raise MdocDeviceAuthError(
                "DeviceMac holder binding needs the ISO 18013-5 session EMacKey, which the "
                "OpenID4VP online flow does not establish; pass device_mac_key for a "
                "proximity SessionTranscript")
        try:
            mac0 = cose.parse_mac0(mac)
            ok = cose.verify_mac0(mac0, mac_key=device_mac_key, detached_payload=detached)
        except cose.CoseError as exc:
            raise MdocDeviceAuthError(f"DeviceMac could not be checked: {exc}") from exc
        if not ok:
            raise MdocDeviceAuthError("DeviceMac does not verify (holder binding failed)")
        return
    raise MdocMalformed("deviceAuth has neither deviceSignature nor deviceMac")


def _instant(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)
