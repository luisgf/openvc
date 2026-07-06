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

Only an **EC P-256** leaf is usable (the JOSE allow-list is ``{ES256, EdDSA}``; an
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

    chain = _load_chain(x5c)
    leaf, intermediates = chain[0], chain[1:]
    if now is None:
        instant = datetime.now(timezone.utc)
    elif now.tzinfo is None:                        # a naive now is taken as UTC, not
        instant = now.replace(tzinfo=timezone.utc)  # silently as the host's local time
    else:
        instant = now.astimezone(timezone.utc)

    # webpki CA policy keeps basicConstraints/path checks strict; permit_all on the
    # end-entity relaxes only the TLS EKU a VC issuer cert would not carry.
    builder = (
        PolicyBuilder().store(Store(anchors)).time(instant)
        .extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all())
    )
    try:
        builder.build_client_verifier().verify(leaf, intermediates)
    except VerificationError as exc:
        raise X5cError(f"x5c chain did not validate to a trust anchor: {exc}") from exc

    _check_issuer_binding(leaf, iss)
    return _leaf_public_jwk(leaf)


__all__ = [
    "X5cError",
    "resolve_x5c_key",
]
