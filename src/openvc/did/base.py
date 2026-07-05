"""
openvc.did.base — core DID resolution primitives.

Home of the generic types every DID method shares: VerificationMethod, DidDocument,
the DidResolver protocol, a shared W3C DID-document parser, and a registry that
dispatches a DID to the backend that supports it. No network, no method specifics.

(These types used to live in the EBSI plugin; they are generic to did:key,
did:web and did:ebsi alike, so they belong in the core.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


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


# --------------------------------------------------------------------------- #
# Errors + protocol
# --------------------------------------------------------------------------- #

class DidError(Exception): ...
class UnsupportedDidMethod(DidError): ...
class DidResolutionError(DidError): ...


@runtime_checkable
class DidResolver(Protocol):
    def supports(self, did: str) -> bool: ...
    def resolve(self, did: str) -> DidDocument: ...


# --------------------------------------------------------------------------- #
# Shared W3C DID-document parser (used by did:web and the EBSI DID Registry)
# --------------------------------------------------------------------------- #

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
    return DidDocument(id=doc.get("id", ""), verification_methods=vms, raw=doc)


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
