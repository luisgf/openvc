"""
openvc_ebsi.models — the version-agnostic domain model.

This is the stable contract shared by the resolver and every version adapter.
It contains NO wire-format parsing and NO HTTP: an EBSI API version can never
reach these types. Both ``resolver`` and ``versioning`` import from here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# Trust-chain roles as the registries spell them (#358). EBSI stores the issuer type on
# chain as a small integer and both APIs render it as a name: the legacy Trusted Issuers
# Registry API v5 (`/trusted-issuers-registry/v5/openapi.json`, info.version 5.0.0) documents
# `attribute.issuerType` as "RootTAO, TAO, TI, Revoked or Undefined"; the EBSI Core API v1
# (`/v1/openapi.json` on every node, `Accept: application/openapi+json`, info.version 1.0.0)
# enumerates `["undefined", "RootTAO", "TAO", "TI", "Revoked"]`, "`undefined` (lowercase) is
# returned for type 0". Both read 2026-10-30; the recorded fixtures carry `RootTAO` only.
#
# Policy (trust.py and verify.py): an accreditation is ELIGIBLE only if its role is exactly one
# of TRUST_ROLES, and above the leaf of a chain only one of DELEGATING_ROLES may accredit (a TI
# attests, it does not accredit). `Revoked`, `undefined`, an absent member (read as ""), another
# case or any other string are not eligible; nothing is compared case-insensitively.
TRUST_ROLES = frozenset({"RootTAO", "TAO", "TI"})
DELEGATING_ROLES = frozenset({"RootTAO", "TAO"})
REVOKED_ROLE = "Revoked"
# `is_revoked` also reads the lowercase `revoked`, the spelling openvc compared with before
# 1.38.0 (neither API emits it; a caller's own record builder may).
REVOKED_ROLES = frozenset({REVOKED_ROLE, "revoked"})

# The two accreditation kinds EBSI's trust model issues (#368), named in the token's `vc.type`:
# a RootTAO or TAO holds a `VerifiableAccreditationToAccredit` (it may accredit others); an
# issuer holds a `VerifiableAccreditationToAttest` (it may issue what its `accreditedFor`
# lists). Every recorded accreditation token (v5 pilot, Core v1 preprod and prod) is a
# `…ToAttest`, and EBSI's own schema for the accreditation record (the `credentialSchema` those
# tokens name, pilot TSR `zjVFNvbE…` and Core v1 `0xf57ce42c…`, read 2026-10-30) makes
# `credentialSubject.accreditedFor` REQUIRED, each entry with `schemaId` and `types`.
ACCREDITATION_TO_ATTEST = "VerifiableAccreditationToAttest"
ACCREDITATION_TO_ACCREDIT = "VerifiableAccreditationToAccredit"

# The generic base types (#367): `VerifiableCredential` (VCDM), `VerifiableAttestation` (EBSI's
# base type, which its schema requires on every credential) and `VerifiableAccreditation` (the
# base of the two accreditation kinds). Every recorded `type` list and every recorded
# `accreditedFor.types` list starts with the first two, so a match that intersected whole
# lists was never empty and said nothing about WHAT an issuer may issue. The type match is
# made on the SPECIFIC types only: every specific type of the credential must be listed.
GENERIC_TYPES = frozenset({"VerifiableCredential", "VerifiableAttestation",
                           "VerifiableAccreditation"})


def specific_types(types: Iterable[str]) -> frozenset[str]:
    """*types* without the generic base types (:data:`GENERIC_TYPES`), as a set (#367)."""
    return frozenset(types) - GENERIC_TYPES


# NOTE: VerificationMethod and DidDocument moved to openvc.did.base — they are
# generic to every DID method, not EBSI-specific. Import them from there.


@dataclass(frozen=True)
class Accreditation:
    attribute_id: str
    issuer_type: str              # RootTAO | TAO | TI | Revoked | undefined (as served)
    tao: str | None               # DID that accredited this issuer
    root_tao: str | None
    credential_types: tuple[str, ...] = ()   # what this accreditation authorises: its
    #                                          accreditedFor types; () authorises NOTHING (#368)
    # The raw accreditation VC-JWT (the TIR revision `body`), kept so the trust
    # walker can VERIFY the accreditation's signature against the accreditor's
    # resolved key — the parsed fields above are untrusted until it does.
    credential_jwt: str | None = None
    accreditation_types: tuple[str, ...] = ()   # the token's `vc.type`, as served (#368)

    @property
    def is_revoked(self) -> bool:
        """The registry revoked this accreditation (``Revoked``, or the pre-1.38 ``revoked``)."""
        return self.issuer_type in REVOKED_ROLES

    @property
    def has_trust_role(self) -> bool:
        """The role is exactly one of the three live ones (:data:`TRUST_ROLES`): what makes an
        accreditation eligible at all. False for ``Revoked``, ``undefined``, an absent member,
        another case or any other string."""
        return self.issuer_type in TRUST_ROLES

    @property
    def can_accredit(self) -> bool:
        """The role may accredit others (:data:`DELEGATING_ROLES`: ``RootTAO`` or ``TAO``), so
        the accreditation can stand above the leaf of a chain. A ``TI`` attests only."""
        return self.issuer_type in DELEGATING_ROLES

    @property
    def specific_credential_types(self) -> frozenset[str]:
        """The ``accreditedFor`` types without the generic base types: what this accreditation
        authorises, as the type match reads it (#367)."""
        return specific_types(self.credential_types)

    @property
    def is_to_attest(self) -> bool:
        """The token's ``vc.type`` names :data:`ACCREDITATION_TO_ATTEST`: the kind an issuer
        holds at the leaf of a chain (#368)."""
        return ACCREDITATION_TO_ATTEST in self.accreditation_types

    @property
    def is_to_accredit(self) -> bool:
        """The token's ``vc.type`` names :data:`ACCREDITATION_TO_ACCREDIT`: the kind an
        accreditor holds, the one read from its record above the leaf (#368)."""
        return ACCREDITATION_TO_ACCREDIT in self.accreditation_types


@dataclass(frozen=True)
class IssuerRecord:
    did: str
    has_attributes: bool
    accreditations: tuple[Accreditation, ...]
