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
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from .errors import OpenvcError
from .proof._verify_common import safe_repr, utc_instant


class X5cError(OpenvcError):
    """The x5c chain is malformed, does not validate, is not bound to the issuer,
    or has an unusable key."""


def load_x5c_chain(x5c: Sequence[str]) -> list:
    """Load a JOSE ``x5c`` header value — base64 (not base64url) DER certificates, leaf
    first — into ``x509.Certificate`` objects. Raises :class:`X5cError` on a missing,
    empty, or malformed chain. Shared with the EUDI registration-certificate lane
    (:mod:`openvc.rp_registration`), which carries its signer chain the same way."""
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
    # A dNSName binds only a clean https issuer: with userinfo or a backslash, Python
    # and a browser read different hosts out of the same iss.
    from .jwt_vc_issuer import JwtVcIssuerError, _parse_https_issuer
    try:
        host = _parse_https_issuer(iss).hostname
    except JwtVcIssuerError:
        host = None
    if host and host in san.get_values_for_type(DNSName):
        return
    raise X5cError(f"issuer {iss!r} is not in the x5c leaf certificate's SAN (not bound)")


def _leaf_p256_jwk(leaf: Any) -> dict[str, Any]:
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
    _validate_to_anchor(leaf, intermediates, trust_anchors=trust_anchors, now=now)


def _validate_to_anchor(
    leaf: Any,
    intermediates: Sequence[Any],
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None,
) -> Any:
    """The body of :func:`validate_cert_chain`, returning the **matched trust anchor**
    (the last certificate of the verified chain — matched by key, not by name, so a
    same-named anchor with another key is never reported). The mdoc adapter needs the
    anchor for the ISO 18013-5 §9.3.3 subject checks; the JOSE path ignores it."""
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
        PolicyBuilder().store(Store(anchors)).time(utc_instant(now, error=X5cError))
        .extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all())
    )
    try:
        verified = builder.build_client_verifier().verify(leaf, list(intermediates))
    except VerificationError as exc:
        raise X5cError(f"certificate chain did not validate to a trust anchor: {exc}") from exc
    anchor = verified.chain[-1] if verified.chain else None
    if anchor is None or anchor not in anchors:          # defensive: never report a non-anchor
        raise X5cError("certificate chain did not end at one of the given trust anchors")
    return anchor


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
    chain = load_x5c_chain(x5c)
    validate_cert_chain(chain[0], chain[1:], trust_anchors=trust_anchors, now=now)
    _check_issuer_binding(chain[0], iss)
    return _leaf_p256_jwk(chain[0])


def load_der_chain(x5chain: Sequence[Any]) -> list:
    """Load a COSE ``x5chain`` (RFC 9360 label 33) — raw DER certificates, leaf first —
    into ``x509.Certificate`` objects. Raises :class:`X5cError` on a missing, empty, or
    malformed chain. Shared by the mdoc ``IssuerAuth`` and EUDI registration-certificate
    (CWT) lanes."""
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


def leaf_public_jwk(leaf: Any) -> dict[str, Any]:
    """A certificate's public key as a JWK, restricted to the curves
    :func:`openvc.keys.verify_signature` accepts (EC P-256 / P-384, Ed25519). Any other
    key type — notably RSA — raises :class:`X5cError` rather than producing a JWK no
    allow-listed algorithm could consume."""
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
    leaf = load_der_chain(x5chain)[0]
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    if not (nb <= signed <= na):
        raise X5cError(f"MSO signed {signed.isoformat()} is outside the document-signer "
                       f"certificate validity [{nb.isoformat()} .. {na.isoformat()}]")


# ISO 18013-5 Annex B subject attributes, as the short names the result reports them under.
_SUBJECT_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    ("C", "2.5.4.6"),       # countryName           (IACA and DS: mandatory, §9.3.3 equality)
    ("ST", "2.5.4.8"),      # stateOrProvinceName   (optional; §9.3.3 equality when both carry it)
    ("CN", "2.5.4.3"),      # commonName            (mandatory; informational here)
    ("O", "2.5.4.10"),      # organizationName      (optional; informational here)
)


@dataclass(frozen=True)
class MdocSigner:
    """A validated mdoc document signer: its *public_jwk*, the subject attributes of the
    DS certificate (*ds_subject*) and of the IACA anchor it validated to (*anchor_subject*).
    Each subject is a mapping of the ISO 18013-5 Annex B attributes present — ``C``, ``ST``,
    ``CN``, ``O`` — to their string value; an attribute the subject lacks is absent."""
    public_jwk: dict[str, Any]
    ds_subject: Mapping[str, str]
    anchor_subject: Mapping[str, str]


# The attributes §9.3.3 compares: each must appear exactly once to be comparable. CN / O are
# reported only — a repeated or odd one is omitted from the mapping, never a refusal.
_COMPARED = frozenset({"C", "ST"})


def _subject_attributes(cert: Any, role: str) -> dict[str, str]:
    """The Annex B subject attributes of *cert* as ``{"C": ..., "ST": ..., ...}``.

    ``cryptography`` decodes the Name lazily on the first ``.subject`` read — path
    validation compares issuer and subject as raw DER and never decodes them — so a
    path-valid certificate with an undecodable attribute raises there (``ValueError``,
    ``KeyError``, ``TypeError``): the read is guarded into a typed refusal. The same decode
    warns when a ``countryName`` is not two characters; the warning is silenced and the
    length is refused explicitly (§9.3.3 compares ISO 3166-1 alpha-2 codes). A ``C`` or
    ``ST`` that appears more than once is refused — the ISO profile uses each once and the
    equality is undefined otherwise; ``CN`` / ``O`` are informational: exposed when they
    appear exactly once, omitted otherwise."""
    from cryptography import x509
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            subject = cert.subject
    except (ValueError, TypeError, KeyError) as exc:
        raise X5cError(f"mdoc {role} certificate subject cannot be decoded") from exc
    out: dict[str, str] = {}
    for short, dotted in _SUBJECT_ATTRIBUTES:
        values = subject.get_attributes_for_oid(x509.ObjectIdentifier(dotted))
        if not values:
            continue
        if len(values) != 1:
            if short in _COMPARED:
                raise X5cError(f"mdoc {role} certificate subject carries {len(values)} {short} "
                               f"attributes; the ISO 18013-5 profile uses each once and the "
                               f"9.3.3 equality needs one")
            continue
        value = values[0].value
        if not isinstance(value, str):
            if short in _COMPARED:
                raise X5cError(f"mdoc {role} certificate subject {short} is not a string")
            continue
        out[short] = value
    country = out.get("C")
    if country is not None and len(country) != 2:
        raise X5cError(f"mdoc {role} certificate subject countryName {safe_repr(country)} is "
                       f"not a 2-character ISO 3166-1 alpha-2 code")
    return out


def _require_same_country_and_state(ds_subject: Mapping[str, str],
                                    anchor_subject: Mapping[str, str]) -> None:
    """ISO 18013-5 §9.3.3: the DS and its IACA share ``countryName`` (mandatory on both —
    absent on either side is a refusal) and ``stateOrProvinceName`` when both carry it
    (absent on one side: no constraint). Compared as strings, no normalisation."""
    ds_c, iaca_c = ds_subject.get("C"), anchor_subject.get("C")
    if ds_c is None or iaca_c is None:
        side = "document-signer" if ds_c is None else "IACA anchor"
        raise X5cError(f"mdoc {side} certificate subject has no countryName (C); ISO 18013-5 "
                       "Annex B requires it on the DS and the IACA")
    if ds_c != iaca_c:
        raise X5cError(f"mdoc document-signer countryName {safe_repr(ds_c)} is not its IACA "
                       f"anchor's {safe_repr(iaca_c)} (ISO 18013-5 9.3.3)")
    ds_st, iaca_st = ds_subject.get("ST"), anchor_subject.get("ST")
    if ds_st is not None and iaca_st is not None and ds_st != iaca_st:
        raise X5cError(f"mdoc document-signer stateOrProvinceName {safe_repr(ds_st)} is not its "
                       f"IACA anchor's {safe_repr(iaca_st)} (ISO 18013-5 9.3.3)")


def resolve_mdoc_signer(
    x5chain: Sequence[Any],
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None = None,
) -> MdocSigner:
    """Validate an mdoc ``IssuerAuth`` ``x5chain`` (COSE label 33: DER certificates,
    leaf first) to a caller-provided **IACA** anchor set and return the document signer:
    the leaf's public key as a JWK (P-256 / P-384 / Ed25519) with the DS and matched-anchor
    subject attributes (:class:`MdocSigner`).

    Unlike :func:`resolve_x5c_key` there is **no** ``iss``→SAN binding: mdoc trust is
    "the DS cert chains to a trusted IACA root" (ISO 18013-5 §9.1.2), the DS carries the
    document-signer EKU (Annex B), and — §9.3.3 — the DS subject ``countryName`` equals the
    matched IACA's (mandatory on both) and so does ``stateOrProvinceName`` when both carry
    it. The ``docType`` and ``validityInfo`` are bound against the MSO by the mdoc verifier,
    not the certificate. Raises :class:`X5cError` on a malformed chain, a path-validation
    failure, a missing DS EKU, a country / state mismatch, or an unusable leaf key."""
    chain = load_der_chain(x5chain)
    anchor = _validate_to_anchor(chain[0], chain[1:], trust_anchors=trust_anchors, now=now)
    _require_mdoc_ds_eku(chain[0])
    ds_subject = _subject_attributes(chain[0], "document-signer")
    anchor_subject = _subject_attributes(anchor, "IACA anchor")
    _require_same_country_and_state(ds_subject, anchor_subject)
    return MdocSigner(leaf_public_jwk(chain[0]), ds_subject, anchor_subject)


def resolve_mdoc_signer_key(
    x5chain: Sequence[Any],
    *,
    trust_anchors: Sequence[Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """:func:`resolve_mdoc_signer` reduced to the document-signer leaf's public JWK — the
    same validation (path, DS EKU, §9.3.3 country / state equality), the key alone. Raises
    :class:`X5cError` as that function does."""
    return resolve_mdoc_signer(x5chain, trust_anchors=trust_anchors, now=now).public_jwk


__all__ = [
    "X5cError",
    "resolve_x5c_key",
    "validate_cert_chain",
    "load_x5c_chain",
    "load_der_chain",
    "leaf_public_jwk",
    "MdocSigner",
    "resolve_mdoc_signer",
    "resolve_mdoc_signer_key",
    "check_mdoc_signed_within_ds_validity",
]
