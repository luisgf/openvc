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
    # The raw accreditation VC-JWT (the TIR revision `body`), kept so the trust
    # walker can VERIFY the accreditation's signature against the accreditor's
    # resolved key — the parsed fields above are untrusted until it does.
    credential_jwt: str | None = None

    @property
    def is_revoked(self) -> bool:
        return self.issuer_type == REVOKED_ROLE


@dataclass(frozen=True)
class IssuerRecord:
    did: str
    has_attributes: bool
    accreditations: tuple[Accreditation, ...]
