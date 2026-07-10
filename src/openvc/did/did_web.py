"""
openvc.did.did_web — resolver for the did:web method.

did:web maps a DID to an https URL and fetches the DID document from the issuer's
own domain:

    did:web:example.edu                 -> https://example.edu/.well-known/did.json
    did:web:example.edu:issuers:physics -> https://example.edu/issuers/physics/did.json
    did:web:example.edu%3A3000          -> https://example.edu:3000/.well-known/did.json

SSRF note
---------
did:web is *intentionally* cross-host — the whole point is to resolve a controller's
own domain — so a fixed host allow-list does NOT apply here (unlike the EBSI client).
Pass a general-purpose `fetch` for this resolver, ideally one that still enforces
https and blocks private/link-local address ranges. Do NOT reuse the EBSI client,
whose allow-list would reject every legitimate did:web host.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable
from urllib.parse import unquote

from .base import DidDocument, DidResolutionError, parse_did_document

Fetch = Callable[[str], dict[str, Any]]
# The async counterpart: an https URL -> an awaitable of its parsed JSON object.
AsyncFetch = Callable[[str], Awaitable[dict[str, Any]]]


def _did_web_url(did: str) -> str:
    """Map a ``did:web`` identifier to its https DID-document URL (pure)."""
    msi = did[len("did:web:"):]
    if not msi:
        raise DidResolutionError("empty did:web identifier")
    parts = msi.split(":")                          # ':' separates path segments
    host = unquote(parts[0])                        # %3A -> ':' for an explicit port
    segments = [unquote(p) for p in parts[1:]]
    if segments:
        return f"https://{host}/" + "/".join(segments) + "/did.json"
    return f"https://{host}/.well-known/did.json"


def _validated_document(raw: dict[str, Any], did: str) -> DidDocument:
    """Parse *raw* and apply the did:web id integrity check (shared sync/async)."""
    doc = parse_did_document(raw)
    if doc.id != did:                               # bind the document to the requested DID —
        raise DidResolutionError(                   # a missing/empty id fails too (did:webvh is
            f"document id {doc.id!r} != requested {did!r}")   # strict here; don't be laxer)
    return doc


class DidWebResolver:
    def __init__(self, fetch: Fetch) -> None:
        self._fetch = fetch

    def supports(self, did: str) -> bool:
        return did.startswith("did:web:")

    def resolve(self, did: str) -> DidDocument:
        return _validated_document(self._fetch(_did_web_url(did)), did)

    _did_to_url = staticmethod(_did_web_url)            # back-compat alias


class AsyncDidWebResolver:
    """The async counterpart of :class:`DidWebResolver`: same URL mapping and id
    integrity check, but awaits an injected async fetch (pass
    :func:`openvc.fetch.https_json_fetch_async` for the SSRF-guarded one)."""
    def __init__(self, fetch: AsyncFetch) -> None:
        self._fetch = fetch

    def supports(self, did: str) -> bool:
        return did.startswith("did:web:")

    async def resolve(self, did: str) -> DidDocument:
        return _validated_document(await self._fetch(_did_web_url(did)), did)


__all__ = [
    "AsyncDidWebResolver",
    "AsyncFetch",
    "DidWebResolver",
    "Fetch",
]
