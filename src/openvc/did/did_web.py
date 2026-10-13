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

from ..proof._verify_common import safe_repr
from .base import DidDocument, DidResolutionError, parse_did_document

Fetch = Callable[[str], dict[str, Any]]
# The async counterpart: an https URL -> an awaitable of its parsed JSON object.
AsyncFetch = Callable[[str], Awaitable[dict[str, Any]]]

# One RFC 1123 host label: letters, digits and inner hyphens, at most 63 characters.
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PORT = re.compile(r"[0-9]{1,5}")
# A last label a WHATWG parser reads as an IPv4 number: decimal, or 0x hex.
_NUMERIC_LABEL = re.compile(r"[0-9]+|0[xX][0-9A-Fa-f]*")


def _check_host(host: str, did: str) -> None:
    """Reject a decoded did:web host that is not a domain name with an optional port.

    The spec defines the host by RFC 1035/1123 domain-name syntax, which is ASCII,
    and forbids IP addresses. Checking it here keeps a hostile host (a bad port, an
    IP literal, a control character, ``@`` or ``/``) a typed error before any fetch
    runs, the caller's own fetch included.

    An internationalized host must be written as its A-label (``xn--…``). A Unicode
    host is refused rather than converted: Python's IDNA codec is IDNA2003, which
    maps ``faß.de`` to ``fass.de`` where IDNA2008 and browsers use ``xn--fa-hia.de``,
    a different registrable domain. Its punycode encoder is also quadratic, so the
    length is bounded first, before any per-character work. A dotted, decimal or hex
    IPv4 form (``127.0.0.1``, ``2130706433``, ``0x7f.1``) is refused the way WHATWG
    spots one: the last label is a number.
    """
    shown = safe_repr(did)              # bounded: the DID can be megabytes long
    name, colon, port = host.rpartition(":") if ":" in host else (host, "", "")
    if colon and not (_PORT.fullmatch(port) and 0 < int(port) <= 65535):
        raise DidResolutionError(f"did:web {shown} has an invalid port {safe_repr(port)}")
    if len(name) > 253:
        raise DidResolutionError(f"did:web {shown} host is longer than 253 characters")
    if not name.isascii():
        raise DidResolutionError(
            f"did:web {shown} host {name!r} is not ASCII; write an IDN as its xn-- A-label")
    labels = name.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise DidResolutionError(f"did:web {shown} host {name!r} is not a domain name")
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        raise DidResolutionError(
            f"did:web {shown} host {name!r} is an IP address, which did:web forbids")


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
