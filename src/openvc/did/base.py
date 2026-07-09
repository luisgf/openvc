"""
openvc.did.base — core DID resolution primitives.

Home of the generic types every DID method shares: VerificationMethod, DidDocument,
the DidResolver protocol, a shared W3C DID-document parser, and a registry that
dispatches a DID to the backend that supports it. No network, no method specifics.

(These types used to live in the EBSI plugin; they are generic to did:key,
did:web and did:ebsi alike, so they belong in the core.)
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Awaitable, Protocol, runtime_checkable

from ..errors import OpenvcError
from ..multibase import MultibaseError, decode_multibase, read_varint

# multicodec varint heads for the public-key types openvc decodes from a Multikey
# (publicKeyMultibase) — Ed25519 and the two NIST curves, matching did:key.
_MC_ED25519 = 0xED
_MC_P256 = 0x1200
_MC_P384 = 0x1201

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
        """The verification-method id — the ``#fragment`` key identifier."""
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
    def supports(self, did: str) -> bool:
        """Whether this resolver handles *did* (its DID method)."""
    def resolve(self, did: str) -> DidDocument:
        """Resolve *did* to a :class:`DidDocument`, or raise :class:`DidResolutionError`."""


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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def multikey_to_jwk(multibase_key: str) -> dict[str, Any]:
    """Decode a ``publicKeyMultibase`` Multikey to a public JWK.

    Handles the key types openvc verifies with — Ed25519 (multicodec ``0xed``) and the
    NIST curves P-256 (``0x1200``) / P-384 (``0x1201``, SEC1 compressed points) — the same
    set as :mod:`openvc.did.did_key`. Raises :class:`~openvc.multibase.MultibaseError`
    (or ``ValueError`` for an off-curve point / unknown codec) so the caller can skip an
    undecodable method rather than crash."""
    raw = decode_multibase(multibase_key)
    code, off = read_varint(raw)
    key = raw[off:]
    if code == _MC_ED25519:
        if len(key) != 32:
            raise ValueError(f"Ed25519 Multikey must be 32 bytes, got {len(key)}")
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(key)}
    if code in (_MC_P256, _MC_P384):
        from cryptography.hazmat.primitives.asymmetric import ec

        curve, crv, size = (
            (ec.SECP256R1(), "P-256", 32) if code == _MC_P256 else (ec.SECP384R1(), "P-384", 48))
        pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, key)  # validates on-curve
        nums = pub.public_numbers()
        return {"kty": "EC", "crv": crv,
                "x": _b64url(nums.x.to_bytes(size, "big")),
                "y": _b64url(nums.y.to_bytes(size, "big"))}
    raise ValueError(f"unsupported Multikey multicodec 0x{code:x}")


def _vm_public_jwk(vm: dict[str, Any]) -> dict[str, Any] | None:
    """The verification method's public key as a JWK — from ``publicKeyJwk`` directly, or
    converted from a ``publicKeyMultibase`` Multikey. ``None`` if neither is present or the
    Multikey is an undecodable type (the method is then skipped, as before)."""
    jwk = vm.get("publicKeyJwk")
    if isinstance(jwk, dict):
        return jwk
    mb = vm.get("publicKeyMultibase")
    if isinstance(mb, str):
        try:
            return multikey_to_jwk(mb)
        except (MultibaseError, ValueError, TypeError):
            return None
    return None


def parse_did_document(raw: dict[str, Any]) -> DidDocument:
    """Parse a W3C DID document. Tolerates a `didDocument` wrapper or a bare doc
    (the EBSI DID Registry returns it bare, as application/did+ld+json). Verification
    methods may carry ``publicKeyJwk`` or a ``publicKeyMultibase`` Multikey (did:webvh and
    modern did:web documents use the latter)."""
    doc = raw.get("didDocument", raw)
    vms = [
        VerificationMethod(
            id=vm["id"],
            type=vm.get("type", ""),
            controller=vm.get("controller", doc.get("id", "")),
            public_key_jwk=jwk,
        )
        for vm in doc.get("verificationMethod", [])
        if isinstance(vm, dict) and "id" in vm and (jwk := _vm_public_jwk(vm)) is not None
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
    """A registry that dispatches ``resolve`` to the first resolver that supports the DID."""

    def __init__(self, resolvers: list[DidResolver] | None = None) -> None:
        self._resolvers: list[DidResolver] = list(resolvers or [])

    def register(self, resolver: DidResolver) -> None:
        """Add a resolver (consulted in registration order)."""
        self._resolvers.append(resolver)

    def resolve(self, did: str) -> DidDocument:
        """Resolve *did* via the first matching resolver, else raise ``UnsupportedDidMethod``."""
        for r in self._resolvers:
            if r.supports(did):
                return r.resolve(did)
        raise UnsupportedDidMethod(f"no resolver for {did!r}")


# --------------------------------------------------------------------------- #
# Async variants (additive — see docs/adr/ADR-0002-async-verification.md)
# --------------------------------------------------------------------------- #

@runtime_checkable
class AsyncDidResolver(Protocol):
    """The async counterpart of :class:`DidResolver`: ``supports`` stays a plain
    predicate (no I/O), ``resolve`` is awaitable so a backend can await a non-blocking
    fetch. A sync resolver is adapted to this shape by :func:`as_async_resolver`."""
    def supports(self, did: str) -> bool:
        """Whether this resolver handles *did* (its DID method)."""
    def resolve(self, did: str) -> Awaitable[DidDocument]:
        """Resolve *did* to a :class:`DidDocument`, or raise :class:`DidResolutionError`."""


class _SyncResolverAsAsync:
    """Adapts a sync :class:`DidResolver` to :class:`AsyncDidResolver`. Used for the
    offline methods (did:key / did:jwk) whose ``resolve`` is pure compute — the
    coroutine awaits nothing and returns immediately."""
    def __init__(self, resolver: DidResolver) -> None:
        self._resolver = resolver

    def supports(self, did: str) -> bool:
        return self._resolver.supports(did)

    async def resolve(self, did: str) -> DidDocument:
        return self._resolver.resolve(did)


def as_async_resolver(resolver: DidResolver) -> AsyncDidResolver:
    """Wrap a sync :class:`DidResolver` as an :class:`AsyncDidResolver` (its
    ``resolve`` awaits nothing). Lets an offline did:key / did:jwk resolver — or any
    sync resolver whose blocking is acceptable — drop into an async registry."""
    return _SyncResolverAsAsync(resolver)


class AsyncDidResolverRegistry:
    """The async counterpart of :class:`DidResolverRegistry`: dispatches an awaitable
    ``resolve`` to the first :class:`AsyncDidResolver` that supports the DID."""

    def __init__(self, resolvers: list[AsyncDidResolver] | None = None) -> None:
        self._resolvers: list[AsyncDidResolver] = list(resolvers or [])

    def register(self, resolver: AsyncDidResolver) -> None:
        """Add a resolver (consulted in registration order)."""
        self._resolvers.append(resolver)

    async def resolve(self, did: str) -> DidDocument:
        """Resolve *did* via the first matching resolver, else raise ``UnsupportedDidMethod``."""
        for r in self._resolvers:
            if r.supports(did):
                return await r.resolve(did)
        raise UnsupportedDidMethod(f"no resolver for {did!r}")


__all__ = [
    "AsyncDidResolver",
    "AsyncDidResolverRegistry",
    "DidDocument",
    "DidError",
    "DidResolutionError",
    "DidResolver",
    "DidResolverRegistry",
    "RELATIONSHIP_KEYS",
    "UnsupportedDidMethod",
    "VerificationMethod",
    "as_async_resolver",
    "parse_did_document",
]
