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
    supplied (fail-closed — a list is never trusted unverified). Pass the reference
    :func:`openvc.trustlist.verify_xades_enveloped` (``pip install
    openvc-core[trustlist]``), or inject your own."""


class TrustListSignatureError(TrustListError):
    """The Trusted List's signature (XML XAdES, or a LoTE's compact JAdES) did
    not verify against the expected signer certificate(s) — the list is not
    authentic."""


class TrustListProfileError(TrustListError):
    """A verified, well-formed LoTE does not conform to the requested profile
    (ETSI TS 119 602 clause 4.7 — e.g. the Annex F/G EU WRPAC/WRPRC providers
    lists): wrong ``LoTEType``, a forbidden component present, a service type
    outside the profile's exclusive set, or an update window over the ceiling.
    Fail-closed: a non-conformant list contributes no anchors."""


class TrustListSignatureBackendUnavailable(TrustListSignatureUnavailable):
    """XAdES signature verification was requested (via the reference
    :func:`openvc.trustlist.verify_xades_enveloped`) but the ``[trustlist]`` extra
    (``signxml``) is not installed (``pip install openvc-core[trustlist]``). A
    subclass of :class:`TrustListSignatureUnavailable`: no verifier is available, so
    a list is still never trusted unverified."""


__all__ = [
    "TrustListError",
    "TrustListParseError",
    "TrustListProfileError",
    "TrustListSignatureBackendUnavailable",
    "TrustListSignatureError",
    "TrustListSignatureUnavailable",
]
