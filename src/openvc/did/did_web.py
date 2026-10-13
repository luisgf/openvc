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

import re
from typing import Any, Awaitable, Callable
from urllib.parse import unquote

from .base import DidDocument, DidResolutionError, parse_did_document

Fetch = Callable[[str], dict[str, Any]]
# The async counterpart: an https URL -> an awaitable of its parsed JSON object.
AsyncFetch = Callable[[str], Awaitable[dict[str, Any]]]

# One RFC 1123 host label: letters, digits and inner hyphens, at most 63 characters.
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PORT = re.compile(r"[0-9]{1,5}")


def _check_host(host: str, did: str) -> None:
    """Reject a decoded did:web host that is not a domain name with an optional port.

    The spec defines the host by RFC 1035/1123 domain-name syntax. Checking it here
    keeps a hostile host (a bad port, a bracket, a control character, ``@`` or ``/``)
    a typed error before any fetch runs, the caller's own fetch included. A Unicode
    host is checked in its IDNA (``xn--``) form, the form the resolver looks up.
    """
    name, colon, port = host.rpartition(":") if ":" in host else (host, "", "")
    if colon and not (_PORT.fullmatch(port) and 0 < int(port) <= 65535):
        raise DidResolutionError(f"did:web {did!r} has an invalid port {port!r}")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DidResolutionError(f"did:web {did!r} has an invalid host: {exc}") from exc
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        raise DidResolutionError(f"did:web {did!r} host {name!r} is not a domain name")


def _did_web_url(did: str) -> str:
    """Map a ``did:web`` identifier to its https DID-document URL (pure)."""
    msi = did[len("did:web:"):]
    if not msi:
        raise DidResolutionError("empty did:web identifier")
    parts = msi.split(":")                          # ':' separates path segments
    host = unquote(parts[0])                        # %3A -> ':' for an explicit port
    _check_host(host, did)
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
