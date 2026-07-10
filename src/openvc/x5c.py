"""
openvc.x5c — validate a JOSE ``x5c`` certificate chain and bind it to the issuer.

Some issuers (notably eIDAS / EUDI document signers) anchor trust in **X.509**
rather than a DID: the JOSE header carries ``x5c``, a chain of base64 (not
base64url) DER certificates, leaf first. This validates that chain to a
**caller-provided** set of trust anchors and returns the leaf's public key as a
JWK for the signature check.

Two things make this safe:

* **Path validation** (signatures, validity window, name chaining, and
  ``basicConstraints`` on CA certs) is done by ``cryptography``'s X.509 verifier —
  which *refuses* to skip ``basicConstraints``, so a non-CA cert cannot be smuggled
  in as an intermediate. Only the TLS-specific EKU requirement is relaxed (a VC
  issuer cert is not a TLS server/client cert). Requires ``cryptography >= 45``.
* **Issuer binding** — the token's ``iss`` must appear in the leaf certificate's
  Subject Alternative Name (a matching URI, or a DNS name equal to the ``iss``
  host). Without it, a holder of *any* certificate under a trusted anchor could
  forge a credential naming an arbitrary issuer.

Only an **EC P-256** leaf is usable (the JOSE allow-list is ``{ES256, ES384, EdDSA, Ed25519}``; an
RSA leaf is rejected by the algorithm allow-list anyway). openvc ships no root
store — the trust anchors are the caller's.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Sequence
from urllib.parse import urlparse

from .errors import OpenvcError


class X5cError(OpenvcError):
    """The x5c chain is malformed, does not validate, is not bound to the issuer,
    or has an unusable key."""


def _load_chain(x5c: Sequence[str]) -> list:
    from cryptography import x509
    if not isinstance(x5c, (list, tuple)) or not x5c:
        raise X5cError("x5c header is missing or empty")
    chain = []
    for entry in x5c:
        if not isinstance(entry, str):
            raise X5cError("x5c entries must be base64 strings")
        try:
            chain.append(x509.load_der_x509_certificate(base64.b64decode(entry)))
        except Exception as exc:
            raise X5cError(f"x5c entry is not a valid certificate: {exc}") from exc
    return chain


def _check_issuer_binding(leaf: Any, iss: str) -> None:
    from cryptography import x509
    from cryptography.x509 import DNSName, UniformResourceIdentifier
    from cryptography.x509.oid import ExtensionOID
    try:
        san = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        raise X5cError("x5c leaf certificate has no Subject Alternative Name to bind the issuer")
    if iss in san.get_values_for_type(UniformResourceIdentifier):
        return
    host = urlparse(iss).hostname
    if host and host in san.get_values_for_type(DNSName):
        return
    raise X5cError(f"issuer {iss!r} is not in the x5c leaf certificate's SAN (not bound)")


def _leaf_public_jwk(leaf: Any) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import ec
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise X5cError("x5c leaf key is not EC P-256 (only ES256 is supported)")
    nums = pub.public_numbers()
    return {
        "kty": "EC", "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _instant(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:                          # a naive now is taken as UTC, not
        return now.replace(tzinfo=timezone.utc)     # silently as the host's local time
    return now.astimezone(timezone.utc)


def validate_cert_chain(
    leaf: Any,
    intermediates: Sequence[Any],
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None = None,
) -> None:
    """Path-validate *leaf* + *intermediates* (``x509.Certificate`` objects, leaf first)
    to one of *trust_anchors* at *now* — the shared X.509 core behind both the JOSE
    ``x5c`` path and the mdoc IssuerAuth adapter (ADR-0005 D5). Checks chain signatures,
    validity windows, name chaining and ``basicConstraints`` (``cryptography`` refuses to
    skip the latter, so a non-CA cert cannot be smuggled in as an intermediate); only the
    TLS-specific EKU is relaxed (a VC/mdoc signer cert is not a TLS server cert). Raises
    :class:`X5cError` on any failure; returns ``None`` on success."""
    from cryptography import x509
    from cryptography.x509.verification import (
        ExtensionPolicy,
        PolicyBuilder,
        Store,
        VerificationError,
    )

    anchors = [a for a in trust_anchors if isinstance(a, x509.Certificate)]
    if not anchors:
        raise X5cError("no trust anchors given (a sequence of x509.Certificate roots)")

    # webpki CA policy keeps basicConstraints/path checks strict; permit_all on the
    # end-entity relaxes only the TLS EKU a VC / mdoc signer cert would not carry.
    builder = (
        PolicyBuilder().store(Store(anchors)).time(_instant(now))
        .extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all())
    )
    try:
        builder.build_client_verifier().verify(leaf, list(intermediates))
    except VerificationError as exc:
        raise X5cError(f"certificate chain did not validate to a trust anchor: {exc}") from exc


def resolve_x5c_key(
    x5c: Sequence[str],
    iss: str,
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate the *x5c* chain (leaf first) against *trust_anchors* (trusted root
    ``x509.Certificate`` objects), confirm the leaf is bound to *iss* via its SAN,
    and return the leaf's public key as an EC P-256 JWK.

    Raises :class:`X5cError` on a malformed chain, a path-validation failure, an
    unbound issuer, or a non-P-256 leaf key."""
    chain = _load_chain(x5c)
    validate_cert_chain(chain[0], chain[1:], trust_anchors=trust_anchors, now=now)
    _check_issuer_binding(chain[0], iss)
    return _leaf_public_jwk(chain[0])


def _load_der_chain(x5chain: Sequence[Any]) -> list:
    from cryptography import x509
    if not isinstance(x5chain, (list, tuple)) or not x5chain:
        raise X5cError("mdoc x5chain is missing or empty")
    chain = []
    for der in x5chain:
        if not isinstance(der, (bytes, bytearray)):
            raise X5cError("mdoc x5chain entries must be DER byte strings")
        try:
            chain.append(x509.load_der_x509_certificate(bytes(der)))
        except Exception as exc:
            raise X5cError(f"mdoc x5chain entry is not a valid certificate: {exc}") from exc
    return chain


def _leaf_ec_jwk(leaf: Any) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    pub = leaf.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if isinstance(pub.curve, ec.SECP256R1):
            name, size = "P-256", 32
        elif isinstance(pub.curve, ec.SECP384R1):
            name, size = "P-384", 48
        else:
            raise X5cError(f"mdoc signer key curve {pub.curve.name!r} is not P-256 or P-384")
        nums = pub.public_numbers()
        return {"kty": "EC", "crv": name,
                "x": _b64url(nums.x.to_bytes(size, "big")),
                "y": _b64url(nums.y.to_bytes(size, "big"))}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        from cryptography.hazmat.primitives import serialization
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
    raise X5cError("mdoc signer leaf key is not EC P-256/P-384 or Ed25519")


# ISO 18013-5 §B.1.1: the mdoc document-signer ExtendedKeyUsage. A cert that chains to a
# trusted IACA is only a valid document signer if it carries this EKU — otherwise ANY leaf
# under the IACA (a TLS server cert, another DS for a different purpose) could sign an MSO.
_MDOC_DS_EKU_OID = "1.0.18013.5.1.2"


def _require_mdoc_ds_eku(leaf: Any) -> None:
    from cryptography import x509
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        raise X5cError("mdoc document-signer certificate has no ExtendedKeyUsage "
                       "(needs the mdoc DS EKU 1.0.18013.5.1.2)")
    if x509.ObjectIdentifier(_MDOC_DS_EKU_OID) not in eku:
        raise X5cError("mdoc document-signer certificate lacks the DS ExtendedKeyUsage "
                       "1.0.18013.5.1.2 (ISO 18013-5 Annex B)")


def check_mdoc_signed_within_ds_validity(x5chain: Sequence[Any], signed: datetime) -> None:
    """ISO 18013-5 §9.3.1: the MSO ``signed`` time must fall within the document-signer
    certificate's own validity window. (The chain *path* is validated at verification time
    — the conservative policy — so a currently-expired DS is still rejected; this additionally
    catches a ``signed`` inconsistent with the cert that produced it.) Raises :class:`X5cError`."""
    leaf = _load_der_chain(x5chain)[0]
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    if not (nb <= signed <= na):
        raise X5cError(f"MSO signed {signed.isoformat()} is outside the document-signer "
                       f"certificate validity [{nb.isoformat()} .. {na.isoformat()}]")


def resolve_mdoc_signer_key(
    x5chain: Sequence[Any],
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate an mdoc ``IssuerAuth`` ``x5chain`` (COSE label 33: DER certificates,
    leaf first) to a caller-provided **IACA** anchor set and return the document-signer
    leaf's public key as a JWK (P-256 / P-384 / Ed25519).

    Unlike :func:`resolve_x5c_key` there is **no** ``iss``→SAN binding: mdoc trust is
    "the DS cert chains to a trusted IACA root" (ISO 18013-5 §9.1.2). The ``docType`` and
    ``validityInfo`` are bound against the MSO by the mdoc verifier, not the certificate.
    Raises :class:`X5cError` on a malformed chain, a path-validation failure, or an
    unusable leaf key."""
    chain = _load_der_chain(x5chain)
    validate_cert_chain(chain[0], chain[1:], trust_anchors=trust_anchors, now=now)
    _require_mdoc_ds_eku(chain[0])
    return _leaf_ec_jwk(chain[0])


__all__ = [
    "X5cError",
    "resolve_x5c_key",
    "validate_cert_chain",
    "resolve_mdoc_signer_key",
    "check_mdoc_signed_within_ds_validity",
]
