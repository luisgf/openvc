"""
openvc.did.base — core DID resolution primitives.

Home of the generic types every DID method shares: VerificationMethod, DidDocument,
the DidResolver protocol, a shared W3C DID-document parser, and a registry that
dispatches a DID to the backend that supports it. No network, no method specifics.

(These types used to live in the EBSI plugin; they are generic to did:key,
did:web and did:ebsi alike, so they belong in the core.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..errors import OpenvcError

# The W3C verification relationships a proofPurpose can name. Captured so a
# verifier can bind a key to the purpose it is authorized for (a proof claiming
# `assertionMethod` must be signed by a key the document lists under it).
RELATIONSHIP_KEYS = (
    "assertionMethod", "authentication", "keyAgreement",
    "capabilityInvocation", "capabilityDelegation",
)


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerificationMethod:
    id: str                       # e.g. did:...#key-1
    type: str
    controller: str
    public_key_jwk: dict[str, Any]

    @property
    def kid(self) -> str:
        return self.id.split("#", 1)[-1]


@dataclass(frozen=True)
class DidDocument:
    id: str
    verification_methods: list[VerificationMethod]
    raw: dict[str, Any]
    # {relationship -> [verificationMethod id, ...]} for the relationships the
    # document actually declares. A relationship absent from this mapping was not
    # declared by the document (distinct from declared-but-empty).
    relationships: dict[str, list[str]] = field(default_factory=dict)

    def key_by_kid(self, kid: str | None) -> VerificationMethod | None:
        """Match on the full verificationMethod id or its fragment (a JWS `kid`
        may carry either). If kid is None, fall back to the sole key if unique."""
        if kid is None:
            return self.verification_methods[0] if len(self.verification_methods) == 1 else None
        fragment = kid.split("#", 1)[-1]
        return next(
            (vm for vm in self.verification_methods if vm.id == kid or vm.kid == fragment),
            None,
        )

    def key_for_purpose(
        self, kid: str | None, proof_purpose: str
    ) -> VerificationMethod | None:
        """Like :meth:`key_by_kid`, but authorized for *proof_purpose*.

        If the document declares that relationship, the method must be referenced
        by it (returns None otherwise — the key exists but is not usable for this
        purpose). If the document does not declare the relationship at all, the
        binding cannot be enforced and the matched key is returned as-is."""
        vm = self.key_by_kid(kid)
        if vm is None:
            return None
        refs = self.relationships.get(proof_purpose)
        if refs is None:                       # relationship not declared -> lenient
            return vm
        if any(ref == vm.id or ref.split("#", 1)[-1] == vm.kid for ref in refs):
            return vm
        return None


# --------------------------------------------------------------------------- #
# Errors + protocol
# --------------------------------------------------------------------------- #

class DidError(OpenvcError): ...
class UnsupportedDidMethod(DidError): ...
class DidResolutionError(DidError): ...


@runtime_checkable
class DidResolver(Protocol):
    def supports(self, did: str) -> bool: ...
    def resolve(self, did: str) -> DidDocument: ...


# --------------------------------------------------------------------------- #
# Shared W3C DID-document parser (used by did:web and the EBSI DID Registry)
# --------------------------------------------------------------------------- #

def _relationship_refs(doc: dict[str, Any], key: str) -> list[str]:
    """The verificationMethod ids a relationship references. Entries may be a bare
    id string or an embedded verification-method object (we take its `id`)."""
    refs: list[str] = []
    for item in doc.get(key, []):
        if isinstance(item, str):
            refs.append(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            refs.append(item["id"])
    return refs


def parse_did_document(raw: dict[str, Any]) -> DidDocument:
    """Parse a W3C DID document. Tolerates a `didDocument` wrapper or a bare doc
    (the EBSI DID Registry returns it bare, as application/did+ld+json)."""
    doc = raw.get("didDocument", raw)
    vms = [
        VerificationMethod(
            id=vm["id"],
            type=vm.get("type", ""),
            controller=vm.get("controller", doc.get("id", "")),
            public_key_jwk=vm["publicKeyJwk"],
        )
        for vm in doc.get("verificationMethod", [])
        if "publicKeyJwk" in vm
    ]
    relationships = {
        key: _relationship_refs(doc, key) for key in RELATIONSHIP_KEYS if key in doc
    }
    return DidDocument(
        id=doc.get("id", ""), verification_methods=vms, raw=doc,
        relationships=relationships,
    )


# --------------------------------------------------------------------------- #
# Registry — dispatch a DID to the first backend that supports it
# --------------------------------------------------------------------------- #

class DidResolverRegistry:
    def __init__(self, resolvers: list[DidResolver] | None = None) -> None:
        self._resolvers: list[DidResolver] = list(resolvers or [])

    def register(self, resolver: DidResolver) -> None:
        self._resolvers.append(resolver)

    def resolve(self, did: str) -> DidDocument:
        for r in self._resolvers:
            if r.supports(did):
                return r.resolve(did)
        raise UnsupportedDidMethod(f"no resolver for {did!r}")
