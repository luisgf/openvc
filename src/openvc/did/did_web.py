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

from typing import Any, Callable
from urllib.parse import unquote

from .base import DidDocument, DidResolutionError, parse_did_document

Fetch = Callable[[str], dict[str, Any]]


class DidWebResolver:
    def __init__(self, fetch: Fetch) -> None:
        self._fetch = fetch

    def supports(self, did: str) -> bool:
        return did.startswith("did:web:")

    def resolve(self, did: str) -> DidDocument:
        raw = self._fetch(self._did_to_url(did))
        doc = parse_did_document(raw)
        if doc.id and doc.id != did:                    # basic integrity check
            raise DidResolutionError(f"document id {doc.id!r} != requested {did!r}")
        return doc

    @staticmethod
    def _did_to_url(did: str) -> str:
        msi = did[len("did:web:"):]
        if not msi:
            raise DidResolutionError("empty did:web identifier")
        parts = msi.split(":")                          # ':' separates path segments
        host = unquote(parts[0])                        # %3A -> ':' for an explicit port
        segments = [unquote(p) for p in parts[1:]]
        if segments:
            return f"https://{host}/" + "/".join(segments) + "/did.json"
        return f"https://{host}/.well-known/did.json"
