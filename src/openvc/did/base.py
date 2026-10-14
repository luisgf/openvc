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
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Protocol, runtime_checkable

from .. import _json
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

# A DID, not a DID URL: DID Core 1.0 §3.1 (`did:` method-name `:` method-specific-id,
# with no path, query or fragment). Only a document whose `id` is one resolves a
# `#fragment` reference (§3.2.2).
_DID_SYNTAX = re.compile(
    r"did:[a-z0-9]+:(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*"
    r"(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+")


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
        may carry either). If kid is None, fall back to the sole key if unique.
        This is the JOSE lanes' lookup; a Data Integrity proof's key is selected by
        the stricter, exact-id :meth:`key_for_purpose`."""
        if kid is None:
            return self.verification_methods[0] if len(self.verification_methods) == 1 else None
        if not isinstance(kid, str):
            return None
        fragment = kid.split("#", 1)[-1]
        return next(
            (vm for vm in self.verification_methods if vm.id == kid or vm.kid == fragment),
            None,
        )

    def _base(self) -> str | None:
        """The document ``id`` when it is a DID (DID Core 1.0 §3.1), the only base a
        ``#fragment`` resolves against (§3.2.2); else ``None``.

        A lookup calls this a fixed number of times, never once per method or
        reference: the ``id`` (as long as the DID the proof names) and the number of
        references are both the document host's to choose, so re-checking the ``id``
        per reference would cost their product."""
        doc_id = self.id
        return doc_id if isinstance(doc_id, str) and _DID_SYNTAX.fullmatch(doc_id) else None

    @staticmethod
    def _absolute(url: Any, base: str | None) -> str | None:
        """*url* — a method ``id`` or a relationship reference — as an absolute DID URL,
        or ``None`` when it does not resolve to one (DID Core 1.0 §3.2.2).

        A ``did:`` URL is returned unchanged. A ``#fragment`` is resolved against the
        document ``id`` (RFC 3986 §5), and only when that ``id`` is a DID (§3.1), which
        is what *base* is (:meth:`_base`): ``#key-1`` in ``did:example:123`` is
        ``did:example:123#key-1``. Anything else is ``None``: a bare ``key-1`` is a
        relative *path* reference, and a ``?query``, ``/path`` or ``https:`` URL can
        never resolve to ``<did>#fragment`` either, so treating them as unresolvable
        fails closed instead of resolving them in full."""
        if not isinstance(url, str):
            return None
        if url.startswith("did:"):
            return url
        if url.startswith("#") and base is not None:
            return base + url
        return None

    @staticmethod
    def _spellings(absolute: Any, base: str | None) -> tuple[str, ...]:
        """Every string that :meth:`_absolute` resolves to *absolute* against *base*:
        *absolute* itself, when it is a ``did:`` URL, and, when it is *base* followed by
        a ``#fragment``, that fragment. Nothing resolves to a value that is not a
        ``did:`` URL, so that is ``()``.

        A method id or reference is then matched by comparing it with these, not by
        resolving it: each comparison costs at most the candidate's own length, so a
        lookup stays linear in the document size. Resolving every ``#fragment`` would
        copy the document ``id`` once per reference."""
        if not isinstance(absolute, str) or not absolute.startswith("did:"):
            return ()
        if (base is not None and absolute.startswith(base)
                and absolute.startswith("#", len(base))):
            return (absolute, absolute[len(base):])
        return (absolute,)

    def _methods_with_id(self, vm_id: Any, base: str | None) -> list[VerificationMethod]:
        """The methods whose absolute ``id`` (against *base*, :meth:`_base`) is exactly
        *vm_id* (CID 1.0 §3.3 step 9): a plain, case-sensitive string comparison, with
        no fallback to the fragment."""
        spellings = self._spellings(vm_id, base)
        return [vm for vm in self.verification_methods
                if isinstance(vm.id, str) and vm.id in spellings]

    def key_for_purpose(
        self, kid: str | None, proof_purpose: str
    ) -> VerificationMethod | None:
        """The verification method *kid* names, if it is authorized for *proof_purpose*.

        This is the Data Integrity lookup, and it is stricter than :meth:`key_by_kid`
        (which the JOSE lanes keep, since a JWS ``kid`` is only a hint). Method ids and
        relationship references are compared as absolute DID URLs, resolved as DID
        Core 1.0 §3.2.2 says (see :meth:`_absolute`): ``#key-1`` in the document for
        ``did:example:123`` is ``did:example:123#key-1``, while a bare ``key-1``, a
        ``?query``, a ``/path`` or a non-DID URL resolves to nothing. The comparison is
        a plain, case-sensitive string equality, as in CID 1.0 §3.3 (Retrieve
        Verification Method):

        1. **select** (step 9): *kid* must equal the absolute ``id`` of exactly one
           method. Nothing falls back to the fragment, and a second method with the
           same absolute ``id`` is not resolved by document order: returns None.
        2. **grant** (step 11): when the document declares the relationship named by
           *proof_purpose*, one of its references (a string, or the ``id`` of an
           embedded method) must resolve to that same absolute ``id``. A reference to
           another DID, another version, a path or a non-DID URL grants nothing, even
           when its fragment matches; returns None (the key exists but is not usable
           for this purpose). A declared but empty relationship grants nothing.

        If the document does not declare the relationship at all, the binding cannot
        be enforced and the selected method is returned as-is. A *kid* of None falls
        back to the document's sole method, if it has exactly one, and that method
        must then pass step 2. A *proof_purpose* that is not a string (including
        None) names no relationship and returns None.

        The document ``id`` is checked a fixed number of times, and only the selected
        method's own relative ``id`` is resolved; no other method id or reference is:
        each is compared with the spellings of the one absolute ``id`` it would have to
        resolve to (:meth:`_spellings`), computed once per lookup. The cost is linear in
        the document size, however long its ``id`` and however many references it
        lists."""
        if not isinstance(proof_purpose, str):                 # unhashable -> no key
            return None
        base = self._base()                    # once per lookup, never per reference
        if kid is None:
            vm = self.key_by_kid(None)                         # the sole-key fallback
        else:
            matches = self._methods_with_id(kid, base)
            vm = matches[0] if len(matches) == 1 else None
        if vm is None:
            return None
        refs = self.relationships.get(proof_purpose)
        if refs is None:                       # relationship not declared -> lenient
            return vm
        # an unresolvable method id has no spellings, so nothing grants it
        spellings = self._spellings(self._absolute(vm.id, base), base)
        if any(isinstance(ref, str) and ref in spellings for ref in refs):
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

def _array(value: Any, what: str) -> list[Any]:
    """*value* as the JSON array a DID document member must be, else
    :class:`DidResolutionError`. The document is attacker-hosted JSON: ``null``, a
    scalar, a string or an object where an array belongs is a typed failure, never a bare
    ``TypeError``, and never read as "the member is absent" — an absent relationship
    leaves the key purpose unenforced, so the wrong-typed one must not."""
    if not isinstance(value, (list, tuple)):
        raise DidResolutionError(
            f"DID document {what} must be an array, not {type(value).__name__}")
    return list(value)


def _relationship_refs(doc: dict[str, Any], key: str) -> list[str]:
    """The verificationMethod ids a relationship references. Entries may be a bare
    id string or an embedded verification-method object (we take its `id`). An entry
    that is neither is dropped, which can only narrow what the relationship grants; a
    relationship that is not an array is :class:`DidResolutionError` (a bare string would
    otherwise be read one character at a time, each a one-letter key reference)."""
    refs: list[str] = []
    for item in _array(doc.get(key, []), key):
        if isinstance(item, str):
            refs.append(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            refs.append(item["id"])
    return refs


def _text(value: Any) -> str:
    """*value* if it is a string, else ``""`` — keeps the ``str`` fields of the model
    honest when a document gives ``id`` / ``type`` / ``controller`` some other JSON type.
    Nothing is selected on them (a method is chosen by its ``id``). A resolver that
    compares the document ``id`` with the DID it asked for (``did:web`` does) never
    matches an empty one; the parser itself compares nothing."""
    return value if isinstance(value, str) else ""


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
    modern did:web documents use the latter).

    The parser is **context-agnostic** — it reads the document *shape*
    (``verificationMethod`` / relationships), never ``@context`` — so **DID 1.1 / CID 1.0**
    documents (the ``https://www.w3.org/ns/did/v1.1`` context) resolve unchanged. The DID 1.1
    relationship-semantics diff is revisited when it reaches Proposed Recommendation.

    The document is attacker-hosted JSON, so its *shape* is checked, not assumed. A
    document or ``didDocument`` wrapper that is not an object, and a ``verificationMethod``
    or relationship (``assertionMethod`` …) that is present but not an array, raise
    :class:`DidResolutionError` — never read as an absent member, since an undeclared
    relationship leaves the key purpose unenforced. The check is per document, not per
    lane: a relationship that is not an array rejects the whole document, even for a
    lane that never reads relationships. A method whose ``id`` is not a string is dropped
    and a relationship entry that is neither an id string nor an object with a string
    ``id`` is dropped. A dropped method is never selected, by ``kid`` or by purpose, and
    a dropped entry grants nothing. The ``kid``-less fallback to the sole key counts the
    methods that remain, so a dropped method that carried a key no longer makes it
    ambiguous (as a method with an undecodable Multikey never did). An ``id`` / ``type`` /
    ``controller`` that is not a string reads as ``""``."""
    if not isinstance(raw, dict):            # an injected fetch can hand over any JSON value
        raise DidResolutionError(
            f"DID document must be a JSON object, not {type(raw).__name__}")
    if _json.nesting_exceeds(raw):           # an injected fetch hands it over already parsed
        raise DidResolutionError(
            f"DID document is nested deeper than {_json.MAX_DEPTH} levels")
    doc = raw["didDocument"] if "didDocument" in raw else raw    # present-but-null is not absent
    if not isinstance(doc, dict):
        raise DidResolutionError(
            f"didDocument must be an object, not {type(doc).__name__}")
    doc_id = _text(doc.get("id"))
    vms = [
        VerificationMethod(
            id=vm["id"],
            type=_text(vm.get("type")),
            controller=_text(vm["controller"]) if "controller" in vm else doc_id,
            public_key_jwk=jwk,
        )
        for vm in _array(doc.get("verificationMethod", []), "verificationMethod")
        # an entry without a string id names no key (VerificationMethod.kid splits it)
        if isinstance(vm, dict) and isinstance(vm.get("id"), str)
        and (jwk := _vm_public_jwk(vm)) is not None
    ]
    relationships = {
        key: _relationship_refs(doc, key) for key in RELATIONSHIP_KEYS if key in doc
    }
    return DidDocument(id=doc_id, verification_methods=vms, raw=doc, relationships=relationships)


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
