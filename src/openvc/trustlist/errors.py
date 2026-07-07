"""openvc.trustlist.errors — the error family for EU Trusted List consumption."""
from __future__ import annotations

from ..errors import OpenvcError


class TrustListError(OpenvcError):
    """Base class for every Trusted List failure."""


class TrustListParseError(TrustListError):
    """The Trusted List XML is malformed, oversize, or carries a forbidden
    construct (a DTD/DOCTYPE — an XXE / entity-expansion vector)."""


class TrustListSignatureUnavailable(TrustListError):
    """A Trusted List had to be verified but no ``verify_signature`` callback was
    supplied (fail-closed — a list is never trusted unverified). Inject a
    ``verify_signature`` (a reference XAdES one will ship in the ``[trustlist]``
    extra)."""


class TrustListSignatureError(TrustListError):
    """The Trusted List's XML signature did not verify against the expected signer
    certificate(s) — the list is not authentic."""


__all__ = [
    "TrustListError",
    "TrustListParseError",
    "TrustListSignatureError",
    "TrustListSignatureUnavailable",
]
