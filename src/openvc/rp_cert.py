"""
openvc.rp_cert — parse and validate an EUDI Wallet-Relying-Party Access Certificate
(WRPAC).

Under CIR (EU) 2025/848 every wallet relying party carries an **access certificate**
(WRPAC, mandatory): an X.509 certificate profiled by ETSI TS 119 411-8 that
authenticates *who is asking* — the relying party's EU-wide entity identifier, its
service identifier and trade name — rooted in the Access Certificate Authority (ACA)
trust anchors a Member State notifies. This reads that certificate over the existing
``cryptography`` X.509 machinery and exposes its attributes as a typed object the
caller can gate on, with the same fail-closed posture as :mod:`openvc.x5c`.

Two entry points, mirroring the library's trusted/untrusted split:

* :func:`parse_rp_access_certificate` — read the attributes WITHOUT establishing
  trust (UNTRUSTED, like ``peek_*``); for inspection only.
* :func:`verify_rp_access_certificate` — validate the chain to caller-provided ACA
  anchors first, then parse; the result is safe to act on.

The **registration** certificate (WRPRC — the entitlements artifact) is a signed JWT or
CWT (ETSI TS 119 475), *not* an X.509 certificate, so it lives in its own module:
:mod:`openvc.rp_registration`, which also carries the cross-check binding a WRPRC back
to the WRPAC parsed here. This module is WRPAC-only. Scope: parse + validate. NOT
registrar workflows or certificate issuance.
"""
from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from .errors import OpenvcError


class RpCertError(OpenvcError):
    """A relying-party access certificate is malformed, does not validate to the
    provided anchors, or lacks a required attribute."""


@dataclass(frozen=True)
class RelyingPartyAccessCertificate:
    """The parsed attributes of a WRPAC — the answer to "who is asking?".

    ``entity_identifier`` is the EU-wide unique identifier (subject
    ``organizationIdentifier``, OID 2.5.4.97); ``trade_name`` is the human-readable
    name (subject ``commonName``). ``extended_key_usages``, ``certificate_policies``
    and ``registration_records`` (the Subject Information Access locations pointing at
    the RP's registration record) are the caller-gateable attribute set — this module
    does not hardcode which EKU/policy the EUDI profile mandates (that OID is still
    settling); it surfaces them for the caller to check. ``public_jwk`` is the leaf's
    EC public key as a JWK when it is P-256/P-384, else ``None``."""
    entity_identifier: str | None
    trade_name: str | None
    organization_name: str | None
    country: str | None
    subject: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    extended_key_usages: tuple[str, ...]
    certificate_policies: tuple[str, ...]
    registration_records: tuple[str, ...]
    public_jwk: dict[str, Any] | None
    certificate: Any                       # the underlying x509.Certificate


_EC_CURVE_JWK = {"secp256r1": ("P-256", 32), "secp384r1": ("P-384", 48)}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_cert(cert: Any) -> Any:
    """Load *cert* — an ``x509.Certificate``, DER/PEM ``bytes``, or a base64 (not
    base64url) DER ``str`` — into an ``x509.Certificate``, fail-closed."""
    from cryptography import x509

    if isinstance(cert, x509.Certificate):
        return cert
    try:
        if isinstance(cert, str):
            return x509.load_der_x509_certificate(base64.b64decode(cert))
        if isinstance(cert, (bytes, bytearray)):
            raw = bytes(cert)
            if raw.lstrip().startswith(b"-----BEGIN"):
                return x509.load_pem_x509_certificate(raw)
            return x509.load_der_x509_certificate(raw)
    except Exception as exc:
        raise RpCertError(f"not a valid X.509 certificate: {exc}") from exc
    raise RpCertError(
        "certificate must be an x509.Certificate, DER/PEM bytes, or a base64 string")


def _subject_value(cert: Any, oid: Any) -> str | None:
    """The single subject value for *oid*, or ``None`` if absent/empty.

    A WRPAC identity attribute is single-valued; a subject carrying the OID **more
    than once** is rejected fail-closed rather than silently reporting the DER-first
    one (which a downstream that reads the last value — or a human reading the full
    ``subject`` — would disagree with, a spoofing wedge). An empty/whitespace value is
    normalised to ``None`` so a caller's ``is None`` guard is not defeated by ``''``."""
    attrs = cert.subject.get_attributes_for_oid(oid)
    if not attrs:
        return None
    if len(attrs) > 1:
        raise RpCertError(
            f"subject carries {oid.dotted_string} {len(attrs)} times — a relying-party "
            f"identity attribute must be single-valued")
    value = attrs[0].value
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def _public_jwk(cert: Any) -> dict[str, Any] | None:
    from cryptography.hazmat.primitives.asymmetric import ec

    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return None
    mapped = _EC_CURVE_JWK.get(pub.curve.name)
    if mapped is None:                                  # an EC curve openvc does not use
        return None
    crv, size = mapped
    nums = pub.public_numbers()
    return {
        "kty": "EC", "crv": crv,
        "x": _b64url(nums.x.to_bytes(size, "big")),
        "y": _b64url(nums.y.to_bytes(size, "big")),
    }


def _extended_key_usages(cert: Any) -> tuple[str, ...]:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(oid.dotted_string for oid in eku)


def _certificate_policies(cert: Any) -> tuple[str, ...]:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        policies = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(p.policy_identifier.dotted_string for p in policies)


def _registration_records(cert: Any) -> tuple[str, ...]:
    """The Subject Information Access URIs — WRPAC points these at the RP's
    registration record (ETSI TS 119 411-8)."""
    from cryptography import x509
    from cryptography.x509 import UniformResourceIdentifier
    from cryptography.x509.oid import ExtensionOID

    try:
        sia = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(
        ad.access_location.value for ad in sia
        if isinstance(ad.access_location, UniformResourceIdentifier))


def parse_rp_access_certificate(cert: Any) -> RelyingPartyAccessCertificate:
    """Parse a WRPAC's attributes WITHOUT establishing trust.

    UNTRUSTED — it does not validate the chain or the signature. Use it only to
    inspect a certificate (e.g. to read its registration-record URL); call
    :func:`verify_rp_access_certificate` to root it in ACA anchors before making any
    trust decision on the identity it names.
    """
    from cryptography.x509.oid import NameOID

    c = _load_cert(cert)
    try:
        return RelyingPartyAccessCertificate(
            entity_identifier=_subject_value(c, NameOID.ORGANIZATION_IDENTIFIER),
            trade_name=_subject_value(c, NameOID.COMMON_NAME),
            organization_name=_subject_value(c, NameOID.ORGANIZATION_NAME),
            country=_subject_value(c, NameOID.COUNTRY_NAME),
            subject=c.subject.rfc4514_string(),
            serial_number=format(c.serial_number, "x"),
            not_before=c.not_valid_before_utc,
            not_after=c.not_valid_after_utc,
            extended_key_usages=_extended_key_usages(c),
            certificate_policies=_certificate_policies(c),
            registration_records=_registration_records(c),
            public_jwk=_public_jwk(c),
            certificate=c,
        )
    except RpCertError:
        raise
    except Exception as exc:                            # a malformed extension/name field
        raise RpCertError(f"could not parse relying-party certificate: {exc}") from exc


def verify_rp_access_certificate(
    cert: Any,
    *,
    trust_anchors: Sequence[Any],
    intermediates: Sequence[Any] = (),
    required_eku: str | None = None,
    now: datetime | None = None,
) -> RelyingPartyAccessCertificate:
    """Validate a WRPAC and return its parsed attributes.

    The chain (leaf *cert* + any *intermediates*) is path-validated to *trust_anchors*
    (the ACA roots — the trusted-list anchors that root them; each an
    ``x509.Certificate``, DER/PEM bytes, or a base64 string) by ``cryptography``'s
    verifier: signatures, the validity window, ``basicConstraints`` and path length are
    enforced; only the TLS-specific EKU requirement is relaxed (a WRPAC is an
    e-seal/signature certificate, not a TLS server cert). If *required_eku* (an EKU OID
    dotted string) is given, the leaf must carry it.

    **This proves the certificate chains to your anchors (and carries *required_eku* if
    given) — it does NOT, by itself, prove the certificate is a WRPAC.** If your
    *trust_anchors* certify end-entities beyond relying-party access certificates (e.g. a
    broad national/eIDAS root rather than a dedicated ACA), pass *required_eku* — or gate
    on the returned ``certificate_policies`` — to distinguish a WRPAC. With no such gate
    this accepts any end-entity under the anchor.

    Raises :class:`RpCertError` on a malformed certificate, a bad/empty anchor set, a
    path-validation failure, or a missing required EKU. Same fail-closed posture as
    :func:`openvc.x5c.resolve_x5c_key`.
    """
    from cryptography.x509.verification import (
        ExtensionPolicy,
        PolicyBuilder,
        Store,
        VerificationError,
    )

    # Fail closed — with a typed error — on a mistyped trust parameter (e.g. a single
    # Certificate where a sequence is expected, or a string `now`) rather than leaking a
    # bare TypeError/AttributeError past the OpenvcError family.
    if isinstance(trust_anchors, (str, bytes)) or not isinstance(trust_anchors, Iterable):
        raise RpCertError("trust_anchors must be a sequence of ACA roots, not a single value")
    if isinstance(intermediates, (str, bytes)) or not isinstance(intermediates, Iterable):
        raise RpCertError("intermediates must be a sequence of certificates")
    if now is not None and not isinstance(now, datetime):
        raise RpCertError("now must be a datetime or None")

    # Load anchors through the same coercion as cert/intermediates — symmetric, and a
    # bad anchor is a typed error, not a silent drop that would fail-open the anchor set.
    anchors = [_load_cert(a) for a in trust_anchors]
    if not anchors:
        raise RpCertError("no trust anchors given (a sequence of ACA roots)")

    leaf = _load_cert(cert)
    inter = [_load_cert(i) for i in intermediates]

    if now is None:
        instant = datetime.now(timezone.utc)
    elif now.tzinfo is None:                            # a naive now is taken as UTC, not
        instant = now.replace(tzinfo=timezone.utc)      # silently as the host's local time
    else:
        instant = now.astimezone(timezone.utc)

    # webpki CA policy keeps basicConstraints/path checks strict; permit_all on the
    # end-entity relaxes only the TLS EKU a WRPAC (an e-seal cert) would not carry.
    builder = (
        PolicyBuilder().store(Store(anchors)).time(instant)
        .extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all())
    )
    try:
        builder.build_client_verifier().verify(leaf, inter)
    except VerificationError as exc:
        raise RpCertError(f"WRPAC did not validate to a trust anchor: {exc}") from exc

    parsed = parse_rp_access_certificate(leaf)
    if required_eku is not None and required_eku not in parsed.extended_key_usages:
        raise RpCertError(
            f"WRPAC does not carry the required extendedKeyUsage {required_eku!r} "
            f"(has {list(parsed.extended_key_usages)})")
    return parsed


__all__ = [
    "RelyingPartyAccessCertificate",
    "RpCertError",
    "parse_rp_access_certificate",
    "verify_rp_access_certificate",
]
