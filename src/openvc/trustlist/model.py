"""
openvc.trustlist.model — the typed value objects for an ETSI TS 119 612 Trusted
List and the anchors distilled from a LOTL→TL walk.

A parsed :class:`TrustList` is either the **LOTL** (List of Trusted Lists — carries
``pointers`` to each national TL) or a **national TL** (carries ``providers``). The
distillate a verifier actually consumes is a :class:`TrustAnchorSet`: the
:class:`TrustServiceAnchor`\\s that verified, plus a ``problems`` account of every
TL/service that did not (fail-closed — a list that cannot be fetched or verified
contributes zero anchors, never silence).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class TslPointer:
    """One ``OtherTSLPointer`` in the LOTL: where a national TL lives and the
    certificate(s) that TL's XML signature must verify against (the LOTL vouches
    for these — ADR-0003 D5)."""
    location: str                          # TSLLocation (the national TL URL)
    signer_certs: tuple[Any, ...]          # x509.Certificate objects (DigitalId X509Certificate)
    territory: str | None = None           # SchemeTerritory in the pointer's AdditionalInformation
    tsl_type: str | None = None            # pointed list's TSLType (EUgeneric / EUlistofthelists)
    mime_type: str | None = None


@dataclass(frozen=True)
class TrustServiceAnchor:
    """One trust-service X.509 certificate with the metadata that lets a verifier
    decide whether to trust it (service type, status, provider, territory)."""
    certificate: Any                       # an x509.Certificate
    service_type: str                      # ServiceTypeIdentifier URI
    service_status: str                    # ServiceStatus URI
    tsp_name: str | None = None            # the Trust Service Provider name
    service_name: str | None = None
    territory: str | None = None           # the TL's SchemeTerritory

    @property
    def sha256(self) -> str:
        """The hex SHA-256 of the certificate DER — HAIP ``x509_hash`` for this anchor."""
        from cryptography.hazmat.primitives.serialization import Encoding
        return hashlib.sha256(self.certificate.public_bytes(Encoding.DER)).hexdigest()


@dataclass(frozen=True)
class TrustServiceProvider:
    """A Trust Service Provider and its services (national TL entry)."""
    name: str | None
    services: tuple[TrustServiceAnchor, ...]


@dataclass(frozen=True)
class TrustList:
    """A parsed ETSI TS 119 612 Trusted List — the LOTL (``pointers``) or a national
    TL (``providers``)."""
    tsl_type: str | None
    scheme_operator: str | None
    territory: str | None
    sequence_number: int | None
    issue_datetime: str | None
    next_update: datetime | None
    pointers: tuple[TslPointer, ...] = ()          # LOTL: pointers to national TLs
    providers: tuple[TrustServiceProvider, ...] = ()  # national TL: the TSP list

    @property
    def is_lotl(self) -> bool:
        """Whether this is the List of Trusted Lists (by ``TSLType``)."""
        return self.tsl_type is not None and self.tsl_type.endswith("EUlistofthelists")


@dataclass(frozen=True)
class TrustListProblem:
    """Why a TL (or the LOTL) contributed no anchors — surfaced, never silent."""
    location: str                          # the TL URL (or "<lotl>")
    stage: str                             # "fetch" | "signature" | "parse" | "expired"
    detail: str


@dataclass(frozen=True)
class TrustAnchorSet:
    """The result of a LOTL→TL walk: the anchors that verified + the problems."""
    anchors: tuple[TrustServiceAnchor, ...]
    problems: tuple[TrustListProblem, ...] = field(default_factory=tuple)

    @property
    def certificates(self) -> list[Any]:
        """The bare ``x509.Certificate`` anchors — pass straight to
        ``verify_credential(..., x5c_trust_anchors=...)``. Deduplicated by DER."""
        seen: set[bytes] = set()
        out: list[Any] = []
        from cryptography.hazmat.primitives.serialization import Encoding
        for a in self.anchors:
            der = a.certificate.public_bytes(Encoding.DER)
            if der not in seen:
                seen.add(der)
                out.append(a.certificate)
        return out

    @property
    def x509_hashes(self) -> set[str]:
        """The HAIP ``x509_hash`` (hex SHA-256) of every anchor certificate."""
        return {a.sha256 for a in self.anchors}


__all__ = [
    "TrustAnchorSet",
    "TrustList",
    "TrustListProblem",
    "TrustServiceAnchor",
    "TrustServiceProvider",
    "TslPointer",
]
