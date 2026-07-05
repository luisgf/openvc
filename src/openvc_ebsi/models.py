"""
openvc_ebsi.models — the version-agnostic domain model.

This is the stable contract shared by the resolver and every version adapter.
It contains NO wire-format parsing and NO HTTP: an EBSI API version can never
reach these types. Both ``resolver`` and ``versioning`` import from here.
"""

from __future__ import annotations

from dataclasses import dataclass

# Trust-chain roles as reported by the TIR.
REVOKED_ROLE = "revoked"
TRUST_ROLES = frozenset({"RootTAO", "TAO", "TI"})


# NOTE: VerificationMethod and DidDocument moved to openvc.did.base — they are
# generic to every DID method, not EBSI-specific. Import them from there.


@dataclass(frozen=True)
class Accreditation:
    attribute_id: str
    issuer_type: str              # RootTAO | TAO | TI | revoked
    tao: str | None               # DID that accredited this issuer
    root_tao: str | None
    credential_types: tuple[str, ...] = ()   # what this accreditation authorises

    @property
    def is_revoked(self) -> bool:
        return self.issuer_type == REVOKED_ROLE


@dataclass(frozen=True)
class IssuerRecord:
    did: str
    has_attributes: bool
    accreditations: tuple[Accreditation, ...]
