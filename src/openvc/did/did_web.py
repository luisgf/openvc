"""
openvc.did.did_web — resolver for the did:web method.

did:web maps a DID to an https URL and fetches the DID document from the issuer's
own domain:

    did:web:example.edu                 -> https://example.edu/.well-known/did.json
    did:web:example.edu:issuers:physics -> https://example.edu/issuers/physics/did.json
    did:web:example.edu%3A3000          -> https://example.edu:3000/.well-known/did.json

The mapping is the spec's and nothing more: ``:`` becomes ``/``, the port's ``%3A``
is the only percent-escape that is decoded, and every path segment goes on the wire
as written. A segment must match the method's own grammar (did:web §"Method Specific
Identifier", the DID Core 1.0 §3.1 ``idchar``: ``ALPHA / DIGIT / "." / "-" / "_" /
pct-encoded``), must not be empty or a dot segment in any spelling, and must not
percent-encode a delimiter, a control character, whitespace or a non-ASCII octet;
anything else is refused as a typed error before any fetch — see
:func:`_check_segment`.

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

from ..jwt_vc_issuer import _DOT_SEGMENTS  # the spellings a WHATWG parser resolves away
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
# The one escape did:web decodes: the ``:`` before an explicit port, in the host segment.
_PORT_ESCAPE = re.compile(r"%3[Aa]")
# A did:web path segment: one or more ``idchar`` of the method's ABNF (did:web §"Method
# Specific Identifier" = DID Core 1.0 §3.1), ``ALPHA / DIGIT / "." / "-" / "_" /
# pct-encoded`` with ``pct-encoded = "%" HEXDIG HEXDIG``. The two branches share no
# character, so the match is linear in the segment.
_SEGMENT = re.compile(r"(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+")
# A ``%`` that does not start a ``%XX`` escape (for the message), and the ``XX`` of each
# one that does.
_BARE_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ESCAPED_OCTET = re.compile(r"%([0-9A-Fa-f]{2})")
# The characters a path segment may not percent-encode either (none is an ``idchar``, so
# none can be written literally): a segment boundary, the query and fragment delimiters
# (``urlparse`` cuts the path at them, so ``did.json`` would never be requested), the
# backslash a WHATWG parser reads as ``/``, ``%`` itself (an escape of an escape decodes
# twice on some servers) and ``;``, which a servlet container strips as a path parameter
# before it normalizes the path (``..;`` is ``..`` to Tomcat).
_SEGMENT_DELIMITERS = frozenset("/?#\\%;")


def _check_host(host: str, did: str) -> None:
    """Reject a did:web host that is not a domain name with an optional port.

    The spec defines the host by RFC 1035/1123 domain-name syntax, which is ASCII,
    and forbids IP addresses. Checking it here keeps a hostile host (a bad port, an
    IP literal, a control character, ``@`` or ``/``) a typed error before any fetch
    runs, the caller's own fetch included. *host* arrives with only the port's
    ``%3A`` decoded, so any other ``%`` fails the label syntax below: did:web decodes
    nothing else of the host.

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


def _check_segment(segment: str, did: str) -> None:
    """Reject a did:web path segment the method's grammar does not allow.

    did:web decodes no escape in a path segment: ``did:web:host:a:b`` is
    ``https://host/a/b/did.json`` with ``a`` and ``b`` sent verbatim. A segment is
    accepted only when it matches the method's own ABNF (did:web §"Method Specific
    Identifier", which is the DID Core 1.0 §3.1 grammar) — one or more ``idchar``,
    ``idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded`` — so that the request it
    produces is ``<path>/did.json`` on that host and no parser reads it as another path
    or host. Refused, as a :class:`DidResolutionError` before any fetch runs (the
    caller's own fetch included), is a segment that is:

    * empty (``did:web:host::x``, a trailing ``:``), which would send ``//``;
    * a dot segment in any spelling (``.``, ``..``, ``%2E%2E``, …: the set an https
      issuer identifier is held to), which a WHATWG parser resolves away;
    * outside the grammar: that one rule refuses ``;`` (``..;`` is ``..`` to a servlet
      container, which strips path parameters before it normalizes), the delimiters
      ``/ ? # \\`` (``urlparse`` cuts the path at ``?`` and ``#``, so ``did.json`` is never
      requested; WHATWG reads ``\\`` as ``/``), every other reserved or unsafe character
      (``@ ~ ! $ & ' ( ) * + , = " < > { } [ ] | ^`` and the backtick), whitespace, a
      control character (``urlsplit`` drops ``\\t\\r\\n``, so two identifiers would name
      one URL), non-ASCII
      (the identifier policy of the host — ASCII only, an IDN as its ``xn--`` A-label —
      applies to the path too) and a ``%`` that is not a ``%XX`` escape;
    * a ``%XX`` escape of a delimiter, ``;``, ``%``, a control character, whitespace or a
      non-ASCII octet (``%2F``, ``%3F``, ``%23``, ``%5C``, ``%3B``, ``%25``,
      ``%00``–``%20``, ``%7F``, ``%80`` and up): kept verbatim here, but decoded by a
      server into the very character the grammar keeps out.

    An escape of any other printable ASCII character (``%40``, ``%41``, ``%3A``) is
    grammatical and is sent as written, never decoded. Each check is linear in the
    segment, and the message names the DID and the segment through ``safe_repr``, built
    only on refusal: both can be megabytes long.
    """
    def refuse(reason: str) -> DidResolutionError:
        return DidResolutionError(f"did:web {safe_repr(did)} {reason}")

    if not segment:
        raise refuse("has an empty path segment")
    if segment.lower() in _DOT_SEGMENTS:
        raise refuse(f"has a dot path segment {safe_repr(segment)}")
    if not _SEGMENT.fullmatch(segment):
        if not segment.isascii():
            raise refuse(f"path segment {safe_repr(segment)} is not ASCII")
        if _BARE_PERCENT.search(segment):
            raise refuse(
                f"path segment {safe_repr(segment)} has a % that is not a %XX escape")
        raise refuse(
            f"path segment {safe_repr(segment)} is outside the did:web idchar grammar "
            f"(ALPHA / DIGIT / . - _ / %XX)")
    for octet in {int(hexpair, 16) for hexpair in set(_ESCAPED_OCTET.findall(segment))}:
        if octet < 0x21 or octet > 0x7E or chr(octet) in _SEGMENT_DELIMITERS:
            raise refuse(
                f"path segment {safe_repr(segment)} percent-encodes %{octet:02X}, a "
                f"delimiter, control character or non-ASCII octet")


def _did_web_url(did: str) -> str:
    """Map a ``did:web`` identifier to its https DID-document URL (pure).

    The host segment has only the port's ``%3A`` decoded and is checked by
    :func:`_check_host`; each path segment is checked by :func:`_check_segment` and
    used as written. Both refuse before any fetch runs.
    """
    msi = did[len("did:web:"):]
    if not msi:
        raise DidResolutionError("empty did:web identifier")
    parts = msi.split(":")                          # ':' separates path segments
    host = _PORT_ESCAPE.sub(":", parts[0])          # %3A -> ':' for an explicit port
    _check_host(host, did)
    segments = parts[1:]
    for segment in segments:
        _check_segment(segment, did)
    if segments:
        return f"https://{host}/" + "/".join(segments) + "/did.json"
    return f"https://{host}/.well-known/did.json"


def _validated_document(raw: dict[str, Any], did: str) -> DidDocument:
    """Parse *raw* and apply the did:web id integrity check (shared sync/async)."""
    doc = parse_did_document(raw)
    if doc.id != did:                               # bind the document to the requested DID —
        # a missing/empty id fails too (did:webvh is strict here; don't be laxer). The fetched
        # id is wire data and the DID may be a caller's str subclass: both go through safe_repr.
        raise DidResolutionError(
            f"document id {safe_repr(doc.id)} != requested {safe_repr(did)}")
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
