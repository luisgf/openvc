"""
openvc_ebsi.versioning — anti-corruption layer for EBSI's versioned registries.

The problem
-----------
EBSI ships versioned APIs (DID Registry v5, TIR v5, TSR v3, ...) and the *shape*
of responses drifts between versions. Real example: the TIR issuer-attributes
response went from inline `{hash, body, issuerType, tao, rootTao}` in v4 to
`{id, href}` pointing to a separate revisions resource in v5 — a different number
of HTTP calls and a different JSON shape for the same domain concept.

The design
----------
Keep the DOMAIN MODEL (DidDocument, IssuerRecord, Accreditation) stable and
version-agnostic. Put every version-specific concern — URL layout, JSON shape,
and multi-step fetch flows — behind ONE adapter per version. The resolver and the
trust-chain logic depend only on the domain model, never on EBSI's wire format.

Consequence: supporting a new version = write one new adapter class and register
it. No change to the domain model, the resolver, or anything downstream.

Two lanes
---------
* The legacy pilot, one API per service: ``DidRegistryV5``, ``TirV4``, ``TirV5``
  (``"v5"`` and ``"v4"``). Fixtures: ``tests/fixtures/ebsi/*.json``.
* The EBSI Core API v1: ``DidRegistryCoreV1`` and ``TirCoreV1`` (``"core-v1"``), at
  ``/v1/...`` on the *answering node's own origin*. Fixtures:
  ``tests/fixtures/ebsi/core-v1/``.

Both TIR lanes share one attribute walk (``_TirAttributeWalk``), so the origin pin and the
caps are written once. The defaults of ``did_registry_adapter()`` and ``tir_adapter()`` stay
``"v5"``. A Core v1 caller selects the node (``base``, a bare origin, on its HTTP client's
allow-list), ``didr`` and ``tir`` together: nothing infers one from the others.

Principles baked in below
-------------------------
1. Anti-corruption boundary: raw EBSI JSON never escapes an adapter.
2. Encapsulate multi-step flows *inside* the adapter (via an injected `fetch`),
   so callers don't grow `if version == ...` ladders.
3. Pin, don't float: the client is constructed with an explicit version; upgrades
   are a deliberate choice, not silent.
4. Tolerant reads: ignore unknown/extra fields (additive changes don't break),
   be strict only about the fields you depend on.
5. Per-version golden fixtures (recorded real responses) prove each adapter maps
   to the same domain model — the drift alarm.
6. Method-level policy lives in the resolver, once, for every version: the DID is
   validated as a ``did:ebsi`` identifier before any registry URL is built (#266), the
   DID Registry document's ``id`` is bound to the requested DID (#257), and so is the
   TIR issuer response's own DID (#267), which an adapter only *locates* on the wire
   (``TirAdapter.response_did``). The adapters build URLs and map JSON; they expect a
   DID the resolver has already validated, and a new version inherits all three checks.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Iterator
from urllib.parse import parse_qsl, urlparse, urlsplit, urlunsplit

from openvc.did.base import DidDocument, DidResolutionError, parse_did_document
from openvc.observability import logger
from openvc.proof._verify_common import safe_repr
from .errors import MalformedRegistryResponse
from .models import Accreditation, IssuerRecord

# Injected capabilities (keep transport + crypto out of the adapters).
Fetch = Callable[[str], dict[str, Any]]          # GET a URL -> JSON
DecodeJwt = Callable[[str], dict[str, Any]]      # VC-JWT body -> claims (proof suite)

# EBSI's registry URLs run to a few hundred characters; this is far below httpx's own
# 64 KiB URL limit, so the origin pin never passes a URL the client then rejects.
_MAX_URL_LENGTH = 8192
# The port an absent one stands for. Only https: the HTTP client refuses anything else, so
# an http URL keeps an empty port and can never match an https listing anyway.
_DEFAULT_PORTS = {"https": 443}

# The ``did:ebsi`` identifier of a Legal Entity: ``z`` (multibase base58btc) followed by the
# base58btc encoding of 17 bytes, a version byte (``1``) and 16 random bytes. EBSI DevHub,
# "The did:ebsi DID method", "Method Syntax" / "Structure" (read 2026-10-14):
# https://hub.ebsi.eu/docs/onboarding/legal-entity/did-ebsi-method. A value in
# [2**128, 2**129) needs 22 base58 digits when it is below 58**22 and 23 above it, never
# 21 or 24, so the identifier is ``z`` plus 22 or 23 characters. The recorded pilot DID
# (``tests/fixtures/ebsi``, ``zZeKyEJfUTGwajhNyNX928z``) and the page's two examples are all
# ``z`` plus 22. Alphabet and length only: nothing is decoded, so the version byte is not
# checked. The page's optional ``did:ebsi:[network]:`` segment is "fully omitted for the
# EBSI blockchain", which is what the DID Registry and TIR APIs serve: a network-qualified
# DID is not accepted. An explicit ASCII class, never ``\w`` or ``\d``; matched with
# ``fullmatch``, never ``match`` + ``$`` (``$`` accepts a trailing newline).
_DID_EBSI = re.compile(r"did:ebsi:z[1-9A-HJ-NP-Za-km-z]{22,23}")


def _origin(url: str) -> str:
    """``scheme://host:port`` (lowercased) — used to keep pagination on the listing's
    own origin. A belt-and-suspenders check on top of the HTTP client's SSRF allow-list:
    a ``links.next`` cursor may only advance within the same web origin as the listing —
    the port is part of that origin, so a ``next`` that only changes the port is refused
    (the SSRF host allow-list matches host but not port).

    A URL with no origin to compare — an out-of-range or non-numeric port, a broken IPv6
    literal — raises a typed :class:`MalformedRegistryResponse`, never a bare
    ``ValueError`` (#243). So does one the HTTP client would read differently (#246):
    anything but visible ASCII (urlsplit drops a tab or newline and ignores other
    control characters that httpx rejects), or longer than ``_MAX_URL_LENGTH``. That
    check runs first: on CPython ≤ 3.12 ``urlparse`` NFKC-normalizes a non-ASCII netloc
    in quadratic time.

    An absent port is the scheme's default (RFC 3986 §6.2.3), so ``https://host`` and
    ``https://host:443`` are one origin, as they are to httpx (#253). Only an absent port
    is filled in: an explicit ``:0`` stays port 0, never the default. httpcore would
    connect ``:0`` to 443, so refusing it is stricter than the client, and fails closed."""
    if len(url) > _MAX_URL_LENGTH:
        raise MalformedRegistryResponse("registry URL is too long")
    if not (url.isascii() and url.isprintable()) or " " in url:
        raise MalformedRegistryResponse("registry URL is not visible ASCII")
    try:
        p = urlparse(url)                 # raises on a broken IPv6 literal
        port = p.port                     # raises on a bad port
    except ValueError as exc:
        raise MalformedRegistryResponse("registry URL does not parse") from exc
    scheme = p.scheme.lower()
    if port is None:                      # `is None`: port 0 is falsy, not absent
        port = _DEFAULT_PORTS.get(scheme)
    return f"{scheme}://{(p.hostname or '').lower()}:{'' if port is None else port}"


def _on_origin(url: str, origin: str) -> bool:
    """Whether ``url`` sits on ``origin``. A URL that does not parse has no origin, so it
    is off-origin: the walk skips it exactly as it skips a well-formed foreign URL."""
    try:
        return _origin(url) == origin
    except MalformedRegistryResponse:
        return False


def _require_object(value: Any, what: str) -> dict[str, Any]:
    """A fetched registry body must be a JSON object where the adapter reads one.
    A non-object (``null`` / list / string / number — a flaky or compromised registry)
    fails closed as a typed :class:`MalformedRegistryResponse`, never a bare
    ``AttributeError`` leaking past the ``EbsiError`` / ``OpenvcError`` family."""
    if not isinstance(value, dict):
        raise MalformedRegistryResponse(
            f"expected a JSON object for {what}, got {type(value).__name__}")
    return value


def _require_did_ebsi(did: object) -> str:
    """*did*, if it is a ``did:ebsi`` identifier; else :class:`DidResolutionError`.

    DID syntax belongs to the method, not to an API version, so it is checked once, by
    :class:`DidEbsiResolver`, before any registry URL is built. The URL builders in the
    adapters put the DID into the path verbatim, so anything else would steer the
    request: ``/`` and ``.``/``..`` segments (httpx collapses them), ``?`` (a query that
    swallows the ``/attributes`` suffix), ``#`` (dropped by httpx), ``%2f`` and
    ``%2e%2e`` (forwarded as written), and a length up to httpx's 64 KiB. A DID URL
    (``did:ebsi:zX#key-1``) is not a DID, so it fails too. No normalisation: the
    identifier is case-sensitive and nothing is percent-decoded. The message shows the
    value through :func:`~openvc.proof._verify_common.safe_repr`: the DID is a token's
    ``iss`` or a registry's ``accreditedBy``, so it is attacker-sized.

    The value returned is an exact ``str``. A ``str`` subclass can override ``__format__``,
    ``__str__`` or ``__eq__``, and the adapters build the URL with an f-string, which calls
    ``type(did).__format__``: the text that matched the pattern would not be the text put in
    the URL. ``str.__str__`` is the plain slot (``str(did)`` itself can be overridden) and
    copies the underlying characters into an exact ``str``, so what is checked, formatted into
    the URL and compared with the document's ``id`` is one value. A subclass is read as its
    characters, not refused."""
    if not isinstance(did, str):
        raise DidResolutionError(f"not a did:ebsi identifier: {safe_repr(did)}")
    exact = str.__str__(did)
    if not _DID_EBSI.fullmatch(exact):
        raise DidResolutionError(f"not a did:ebsi identifier: {safe_repr(exact)}")
    return exact


# The query parameter that selects a registry instance on a Core API v1 read.
_CONTRACT_ADDRESS_PARAM = "contractAddress"
# What a configured contract address may be: ASCII letters, digits, ``.``, ``_`` and ``-``,
# 1 to 128 of them. Wide on purpose: the OpenAPI contract that defines the format could not
# be read (gitlab.com answered 503), and every value the nodes publish on ``/<registry>/details``
# is ``0x`` and 40 hexadecimal digits, which fits. What matters here is the negative: none of
# ``/ ? # & = %`` or a space can reach the URL, so configuration cannot reshape the path or
# add a parameter. ``fullmatch``, never ``match`` + ``$`` (``$`` accepts a trailing newline).
_CONTRACT_ADDRESS = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _require_contract_address(value: object) -> str:
    """*value*, if it can be a ``contractAddress``; else :class:`ValueError`, as for an
    unknown adapter version. Configuration, not a registry response, so a bad value is a
    programming error and not a typed registry failure. An exact ``str`` is returned
    (``str.__str__``, as in :func:`_require_did_ebsi`): the text checked is the text put in
    the URL, whatever a ``str`` subclass overrides."""
    if not isinstance(value, str):
        raise ValueError(f"contract_address must be a str, not {type(value).__name__}")
    exact = str.__str__(value)
    if not _CONTRACT_ADDRESS.fullmatch(exact):
        raise ValueError(
            "contract_address must be 1 to 128 ASCII letters, digits, '.', '_' or '-': "
            f"{safe_repr(exact)}")
    return exact


def _on_contract_address(url: str, address: str) -> str:
    """*url*, a link the registry handed out, bound to the configured registry instance.

    The nodes do not echo ``contractAddress`` in ``self``, ``links``, ``attributes`` or
    ``href`` (recorded, ``tests/fixtures/ebsi/core-v1/contract-address/``), so a followed
    link names none and a node would read it against its *default* instance: a walk
    configured for another one would mix two. A link that names none therefore gets the
    configured address as its last query parameter; one that names the configured address
    is left as it is; one that names another, however spelled, is
    :class:`MalformedRegistryResponse`. The parameter name is compared case-insensitively
    and after percent-decoding, so a variant spelling cannot slip a different instance
    past the check. The query is otherwise kept exactly as the node wrote it. Called only
    on a URL that :func:`_origin` has already accepted, so it is visible ASCII, short and
    parseable."""
    parts = urlsplit(url)
    named = [(name, value) for name, value in parse_qsl(parts.query, keep_blank_values=True)
             if name.lower() == _CONTRACT_ADDRESS_PARAM.lower()]
    if not named:
        query = f"{parts.query}&" if parts.query else ""
        return urlunsplit(parts._replace(query=f"{query}{_CONTRACT_ADDRESS_PARAM}={address}"))
    for name, value in named:
        if name != _CONTRACT_ADDRESS_PARAM or value != address:
            raise MalformedRegistryResponse(
                f"registry link names contract address {safe_repr(value)}, "
                f"not the configured {safe_repr(address)}")
    return url


def _flatten_accredited_for(accredited_for: Any) -> tuple[str, ...]:
    """The credential types an accreditation authorises.

    EBSI v5 encodes ``accreditedFor`` as objects ``{schemaId, types: [...]}``;
    older shapes used a plain list of type strings. Accept both and flatten to a
    deduped tuple of type strings — the domain model only cares about the types.
    """
    if not isinstance(accredited_for, list):
        return ()
    types: list[str] = []
    for entry in accredited_for:
        if isinstance(entry, str):
            types.append(entry)
        elif isinstance(entry, dict):
            types.extend(t for t in entry.get("types", []) if isinstance(t, str))
    return tuple(dict.fromkeys(types))           # dedupe, preserve first-seen order


# --------------------------------------------------------------------------- #
# DID Registry adapters
# --------------------------------------------------------------------------- #

class DidRegistryAdapter(ABC):
    """One DID Registry API version: where a document lives and how its JSON maps to
    :class:`~openvc.did.base.DidDocument`. Wire-only: ``identifiers_url`` interpolates
    the DID as given and expects one that :class:`DidEbsiResolver` has already validated
    (#266); calling an adapter directly with an unvalidated string is the caller's
    risk."""
    version: str

    @abstractmethod
    def identifiers_url(self, base: str, did: str) -> str: ...

    @abstractmethod
    def parse_did_document(self, raw: dict[str, Any]) -> DidDocument: ...


class DidRegistryV5(DidRegistryAdapter):
    version = "v5"

    def identifiers_url(self, base: str, did: str) -> str:
        return f"{base}/did-registry/{self.version}/identifiers/{did}"

    def parse_did_document(self, raw: dict[str, Any]) -> DidDocument:
        return parse_did_document(raw)              # shared W3C parser (core)


class DidRegistryCoreV1(DidRegistryAdapter):
    """The EBSI Core API v1 DID Registry. The path is ``/v1/did-registry/identifiers/{did}``
    on the *answering node's own origin*, so ``base`` is a bare node origin and the ``/v1``
    belongs to this adapter. The registered name is ``"core-v1"``, the path segment is
    ``v1``: unlike its siblings this adapter never interpolates ``self.version``.

    ``contract_address`` selects a registry instance (``?contractAddress=``); omitted, the
    node's environment default is read. It comes from configuration only, never from a
    response, a link or a token; see :func:`_require_contract_address` for what it may be.
    Two adapters with different addresses build different URLs, so a client's URL-keyed
    cache never serves one's document to the other. The registry's own address is the one
    its ``/did-registry/details`` publishes (the Trusted Issuers Registry has another)."""
    version = "core-v1"

    def __init__(self, *, contract_address: str | None = None) -> None:
        self._contract_address = (
            None if contract_address is None else _require_contract_address(contract_address))

    def identifiers_url(self, base: str, did: str) -> str:
        url = f"{base}/v1/did-registry/identifiers/{did}"
        if self._contract_address is None:
            return url
        return f"{url}?{_CONTRACT_ADDRESS_PARAM}={self._contract_address}"

    def parse_did_document(self, raw: dict[str, Any]) -> DidDocument:
        return parse_did_document(raw)              # shared W3C parser (core)


# --------------------------------------------------------------------------- #
# Trusted Issuers Registry adapters — where the real drift lives
# --------------------------------------------------------------------------- #

class TirAdapter(ABC):
    """One Trusted Issuers Registry API version. Wire-only: ``issuer_url`` interpolates
    the DID as given and expects one that :class:`DidEbsiResolver` has already validated
    (#266), and ``parse_issuer`` is only handed a response the resolver has already bound
    to that DID (#267)."""
    version: str

    @abstractmethod
    def issuer_url(self, base: str, did: str) -> str: ...

    def response_did(self, raw: dict[str, Any]) -> Any:
        """The DID the registry says this issuer response is about, as found and
        UNCHECKED (any JSON value, or ``None`` when absent).

        This says *where the DID sits on the wire* and nothing else. The policy, that it
        must equal the DID that was requested, is :class:`DidEbsiResolver`'s: it compares
        before ``parse_issuer`` is called, so no ``attributes`` page and no revision
        ``href`` is fetched for a record that is not about the DID. Both shipped versions
        carry it at the top level; a version that moves it overrides this method. Concrete
        on purpose: a third-party adapter written before the hook existed still
        instantiates, and gets the top-level ``did`` (#267)."""
        return raw.get("did")

    @abstractmethod
    def parse_issuer(
        self, raw: dict[str, Any], *, base: str, did: str,
        fetch: Fetch, decode: DecodeJwt,
    ) -> IssuerRecord:
        """Map the issuer response to an IssuerRecord.

        `fetch`/`decode` are injected so an adapter can perform any extra calls its
        version requires (e.g. attribute -> revision -> body) without the caller
        knowing anything about it.

        `did` is the DID that was requested, already validated as a ``did:ebsi``
        identifier, and `raw` is a JSON object whose own DID (``response_did``) equals
        it: the resolver checked both before calling. The record is built from `did`
        because, after that check, it is also the DID the registry named.
        """


class TirV4(TirAdapter):
    """v4: attributes are inline, one call. issuerType/tao/rootTao sit on each."""
    version = "v4"

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/trusted-issuers-registry/{self.version}/issuers/{did}"

    def parse_issuer(self, raw: Any, *, base: str, did: str, fetch: Any,
                     decode: Any) -> IssuerRecord:
        accs = [
            Accreditation(
                attribute_id=a.get("hash", ""),
                issuer_type=a.get("issuerType", ""),
                tao=a.get("tao"),
                root_tao=a.get("rootTao"),
                credential_types=self._types_from_body(a.get("body"), decode),
                credential_jwt=a.get("body"),
            )
            for a in raw.get("attributes", [])
        ]
        return IssuerRecord(did=did, has_attributes=bool(accs), accreditations=tuple(accs))

    @staticmethod
    def _types_from_body(body: str | None, decode: DecodeJwt) -> tuple[str, ...]:
        if not body:
            return ()
        subject = decode(body).get("vc", {}).get("credentialSubject", {})
        return _flatten_accredited_for(subject.get("accreditedFor"))


class _TirAttributeWalk(TirAdapter):
    """The multi-hop attribute walk of the issuer response shape ``{did, hasAttributes,
    attributes}`` -> a paginated ``{items: [{id, href}]}`` listing -> one attribute per
    ``href``. A version's adapter inherits it and supplies only ``version`` and
    ``issuer_url``; the origin pin, the caps and the typed errors are written once, here.
    Private on purpose: callers select an adapter by version (``tir_adapter``), never by
    this class."""

    # A registry with many accreditations paginates `/attributes`; these bound the walk
    # so a registry that keeps handing out a `next` cursor — or one giant page — can
    # never spin forever nor fan one verify out into unbounded revision fetches.
    _MAX_ATTRIBUTE_PAGES = 50
    _MAX_ATTRIBUTE_ITEMS = 1000

    def _default_attributes_url(self, base: str, did: str) -> str:
        """The attributes listing of *did*, for an issuer response that names none."""
        return self.issuer_url(base, did) + "/attributes"

    def _follow(self, url: str) -> str:
        """The URL to fetch for a link the registry handed out (``attributes``, an item
        ``href``, ``links.next``). Called only on a URL already pinned to the listing's
        origin, so it is visible ASCII and parses. The identity here; a version whose links
        must stay on one configured registry instance overrides it."""
        return url

    def _iter_attribute_items(self, attributes_url: str, fetch: Fetch) -> Iterator[dict[str, Any]]:
        """Yield every attribute-listing item across EBSI's paginated `/attributes`.

        The v5 listing is JSON:API-style — ``items`` plus a ``links.next`` cursor and a
        ``total``. Production traps this closes: an issuer with more accreditations than
        one page (the old code read only the first page and silently dropped the rest — a
        fail-*closed* trust gap); EBSI returning ``links.next`` even on the last page,
        sometimes pointing at the *same* URL (following it blindly loops forever); and a
        page (or ``total``) big enough to fan one verify into unbounded revision fetches.
        Stop when we have collected ``total`` items, or ``next`` is absent / already
        visited / off the listing's origin, or a page yields no items; a hard page cap and
        a hard item cap backstop the rest. Every page is fetched through the injected
        SSRF-guarded ``fetch``, and ``next`` may only advance within the listing's own
        origin (host AND port) — a compromised registry can neither pivot pagination
        elsewhere nor make it spin."""
        origin = _origin(attributes_url)
        url: str | None = attributes_url
        seen: set[str] = set()
        collected = 0
        total: int | None = None
        while url is not None and url not in seen and len(seen) < self._MAX_ATTRIBUTE_PAGES:
            seen.add(url)
            page = _require_object(fetch(url), "TIR attributes page")
            items = page.get("items")
            if not isinstance(items, list) or not items:
                break
            for item in items:
                if not isinstance(item, dict):
                    continue
                yield item
                collected += 1
                if collected >= self._MAX_ATTRIBUTE_ITEMS:   # bound total revision fetches
                    logger.warning(
                        "TIR /attributes listing exceeded %d items; truncating the walk "
                        "(the issuer may appear to hold fewer accreditations)",
                        self._MAX_ATTRIBUTE_ITEMS)
                    return
            if total is None:
                t = page.get("total")
                # bool is an int subclass — `total: true` must NOT read as 1 and stop early.
                total = t if isinstance(t, int) and not isinstance(t, bool) and t >= 0 else None
            if total is not None and collected >= total:
                break
            links = page.get("links")
            nxt = links.get("next") if isinstance(links, dict) else None
            url = (self._follow(nxt)
                   if isinstance(nxt, str) and nxt and _on_origin(nxt, origin) else None)

    def parse_issuer(self, raw: Any, *, base: str, did: str, fetch: Any,
                     decode: Any) -> IssuerRecord:
        raw = _require_object(raw, "TIR issuer response")
        has_attrs = bool(raw.get("hasAttributes", False))
        accs: list[Accreditation] = []
        if has_attrs:
            # ADR-0001 D6: the v5 issuer response carries the attributes URL in its
            # body (HATEOAS); follow it rather than reconstructing the path.
            # The HTTP client allow-list is hostname-only; `links.next` is already
            # pinned to scheme://host:port. The same pin must apply to `attributes`
            # and each `href` or a compromised body can pivot to another port on
            # an allow-listed EBSI host (#172). An `attributes` URL that does not
            # parse raises from `_origin`; an `href` or `next` that does not parse is
            # off-origin, so it is skipped (#243).
            listing_origin = _origin(self.issuer_url(base, did))
            raw_attrs = raw.get("attributes")
            if not raw_attrs:
                attributes_url = self._default_attributes_url(base, did)
            elif isinstance(raw_attrs, str) and _origin(raw_attrs) == listing_origin:
                attributes_url = raw_attrs
            else:
                raise MalformedRegistryResponse(
                    "TIR attributes URL is off the listing origin")
            for item in self._iter_attribute_items(self._follow(attributes_url), fetch):
                href = item.get("href")
                if not isinstance(href, str) or not href:
                    continue
                if not _on_origin(href, listing_origin):
                    continue
                revision = _require_object(                      # v5 hop
                    fetch(self._follow(href)), "TIR attribute revision")
                # v5 nests the accreditation under `attribute`: the signed VC-JWT
                # is `attribute.body`, and issuerType/tao/rootTao sit on the
                # `attribute` object itself — NOT in the VC credentialSubject
                # (whose `accreditedFor` carries the authorised types).
                attribute = revision.get("attribute")
                if not isinstance(attribute, dict):
                    # not `{}`: an empty attribute reads as an accreditation with no type
                    # restriction, which single-level trust accepts for any credential
                    raise MalformedRegistryResponse(
                        "TIR attribute revision has no attribute object")
                body = attribute.get("body")
                if body is not None and not isinstance(body, str):
                    # the proof suite's `decode` takes a token; a number or an array would
                    # leave it as a bare AttributeError
                    raise MalformedRegistryResponse("TIR attribute body is not a string")
                claims = decode(body) if body else {}
                vc = claims.get("vc") if isinstance(claims, dict) else None
                subject = vc.get("credentialSubject") if isinstance(vc, dict) else None
                subject = subject if isinstance(subject, dict) else {}
                accs.append(Accreditation(
                    attribute_id=item.get("id", "") or attribute.get("hash", ""),
                    issuer_type=attribute.get("issuerType", ""),
                    tao=attribute.get("tao"),
                    root_tao=attribute.get("rootTao"),
                    credential_types=_flatten_accredited_for(subject.get("accreditedFor")),
                    credential_jwt=body,
                ))
        return IssuerRecord(did=did, has_attributes=has_attrs, accreditations=tuple(accs))


class TirV5(_TirAttributeWalk):
    """v5: issuer carries `hasAttributes`; attributes come as {id, href} and the
    body lives one fetch deeper, in a revision. Two+ calls, different shape."""
    version = "v5"

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/trusted-issuers-registry/{self.version}/issuers/{did}"


class TirCoreV1(_TirAttributeWalk):
    """The EBSI Core API v1 Issuers Registry: the v5 read shapes at
    ``/v1/issuers-registry/issuers/{did}`` on the answering node's own origin. The issuer
    response, the paginated ``attributes`` listing and each ``href`` keep the v5 shape (one
    new field on the attribute, ``parentAttributeId``, which nothing reads), so the walk, its
    origin pin and its caps are the shared ones; ``self``, ``links``, ``attributes`` and
    ``href`` name the host of the node that answered, which is why the pin is to the
    listing's own origin and never to a fixed host. ``Accreditation.attribute_id`` is the
    list item's ``id``, which is not the attribute's ``hash``.

    ``contract_address`` is this registry's own address (its ``/issuers-registry/details``),
    not the DID Registry's. Configured, it is on the issuer URL and on every link the walk
    follows, and a link that names another is refused, so a walk never mixes registry
    instances."""
    version = "core-v1"

    def __init__(self, *, contract_address: str | None = None) -> None:
        self._contract_address = (
            None if contract_address is None else _require_contract_address(contract_address))

    def _issuer_path(self, base: str, did: str) -> str:
        return f"{base}/v1/issuers-registry/issuers/{did}"

    def _with_query(self, url: str) -> str:
        # `url` is built here from a path with no query, so the query is appended last
        if self._contract_address is None:
            return url
        return f"{url}?{_CONTRACT_ADDRESS_PARAM}={self._contract_address}"

    def issuer_url(self, base: str, did: str) -> str:
        return self._with_query(self._issuer_path(base, did))

    def _default_attributes_url(self, base: str, did: str) -> str:
        # the suffix goes on the path, then the query: `issuer_url(...) + "/attributes"`
        # would put it after the query
        return self._with_query(self._issuer_path(base, did) + "/attributes")

    def _follow(self, url: str) -> str:
        if self._contract_address is None:
            return url
        return _on_contract_address(url, self._contract_address)


# --------------------------------------------------------------------------- #
# Version selection — the only place a version string maps to an adapter
# --------------------------------------------------------------------------- #

# "core-v1", not "v1": the Core API's name must not collide with the older per-service
# vocabulary ("trusted-contracts-registry/v1"). The defaults below stay "v5", the legacy lane.
DID_REGISTRY_ADAPTERS: dict[str, type[DidRegistryAdapter]] = {
    "v5": DidRegistryV5, "core-v1": DidRegistryCoreV1}
TIR_ADAPTERS: dict[str, type[TirAdapter]] = {"v4": TirV4, "v5": TirV5, "core-v1": TirCoreV1}


def did_registry_adapter(version: str = "v5") -> DidRegistryAdapter:
    try:
        return DID_REGISTRY_ADAPTERS[version]()
    except KeyError:
        raise ValueError(f"no DID Registry adapter for {version!r}") from None


def tir_adapter(version: str = "v5") -> TirAdapter:
    try:
        return TIR_ADAPTERS[version]()
    except KeyError:
        raise ValueError(f"no TIR adapter for {version!r}") from None


# --------------------------------------------------------------------------- #
# Resolver, now version-agnostic — it only talks to adapters + domain model
# --------------------------------------------------------------------------- #

class DidEbsiResolver:
    """Same behaviour as before, but all version specifics are delegated."""

    def __init__(
        self,
        http_get: Fetch,
        decode_jwt: DecodeJwt,
        *,
        base: str = "https://api-pilot.ebsi.eu",
        didr: DidRegistryAdapter | None = None,
        tir: TirAdapter | None = None,
    ) -> None:
        self._get = http_get
        self._decode = decode_jwt
        self._base = base
        self._didr = didr or did_registry_adapter()
        self._tir = tir or tir_adapter()

    def resolve(self, did: str) -> DidDocument:
        """The DID document of *did*, or :class:`~openvc.did.base.DidResolutionError`.

        *did* must be a ``did:ebsi`` identifier: ``z`` plus 22 or 23 base58btc characters
        (EBSI DevHub, "The did:ebsi DID method",
        https://hub.ebsi.eu/docs/onboarding/legal-entity/did-ebsi-method, which also
        defines an optional network segment that is not accepted here). Anything else, a
        DID URL (``did:ebsi:zX#key-1``), another DID method, a path, a query, ``..``, a
        percent escape or a 60 KB string, raises :class:`DidResolutionError` before any
        registry URL is built, so a token's unsigned ``iss`` cannot steer the request
        (#266). The check is exact: case-sensitive, no normalisation, no decoding.

        The adapter then parses the registry body, and this method holds the parsed
        document's ``id`` to the DID that was asked for, exactly. It is the same contract
        ``did:web`` and ``did:webvh`` enforce, and both checks are version-agnostic, so
        they live here and a new registry adapter inherits them. A missing, empty or
        non-string ``id`` never matches: the parser reads all three as ``""``, which is
        never a validated DID. The messages show both values through
        :func:`~openvc.proof._verify_common.safe_repr`: the requested DID is a token's
        ``iss``, so it is attacker-sized.

        Raises:
            DidResolutionError: *did* is not a ``did:ebsi`` identifier, or the document's
                ``id`` is not *did*. The registry's own failures (``HttpNotFound``,
                ``MalformedRegistryResponse``, ...) propagate as they are."""
        did = _require_did_ebsi(did)
        raw = self._get(self._didr.identifiers_url(self._base, did))
        doc = self._didr.parse_did_document(raw)           # no version logic here
        if doc.id != did:                                   # bind the document to the request
            raise DidResolutionError(
                f"document id {safe_repr(doc.id)} != requested {safe_repr(did)}")
        return doc

    def issuer_record(self, did: str) -> IssuerRecord:
        """The Trusted Issuers Registry record of *did*.

        *did* is validated as for :meth:`resolve`, before the URL is built, and a string
        that is not a ``did:ebsi`` identifier raises :class:`DidResolutionError` (#266).
        The response must then be a JSON object (:class:`MalformedRegistryResponse`
        otherwise, for every version), and the DID it names itself,
        ``TirAdapter.response_did``, must be exactly *did*: another DID, an absent, ``null``,
        non-string or empty one, all raise :class:`MalformedRegistryResponse`, shown through
        ``safe_repr``. That comparison runs before the adapter follows any link, so a
        record that is not about *did* costs one request, not the ``attributes`` page and a
        revision per accreditation. ``IssuerRecord.did`` is therefore the DID the registry
        named, not just the one that was asked for (#267). A mismatched body is malformed
        input, not an untrusted issuer, so it is not wrapped in a trust error. The
        ``attributes`` / ``href`` path is still pinned to the listing's origin only, not
        to the issuer.

        Raises:
            DidResolutionError: *did* is not a ``did:ebsi`` identifier.
            MalformedRegistryResponse: the response is not an object, or is not about *did*.
        """
        did = _require_did_ebsi(did)
        raw = _require_object(self._get(self._tir.issuer_url(self._base, did)),
                              "TIR issuer response")
        named = self._tir.response_did(raw)
        if not (isinstance(named, str) and named == did):    # bind the record to the request
            raise MalformedRegistryResponse(
                f"TIR issuer response names {safe_repr(named)}, requested {safe_repr(did)}")
        return self._tir.parse_issuer(
            raw, base=self._base, did=did, fetch=self._get, decode=self._decode,
        )

    # The trust-chain logic (openvc_ebsi.trust.verify_trust_chain) operates purely
    # on IssuerRecord / Accreditation, so no API version can reach it.


# --------------------------------------------------------------------------- #
# Adding a new version later, in full:
#
#   class TirV6(_TirAttributeWalk):          # the shared walk, if the shapes still fit;
#       version = "v6"                       # else subclass TirAdapter and write parse_issuer
#       def issuer_url(self, base, did): ...
#       # def response_did(self, raw): ...   # only if the response's own DID moves
#
#   TIR_ADAPTERS["v6"] = TirV6               # a name that collides with no other lane
#                                            # ("core-v1", not "v1")
#
# ...plus a golden fixture test, recorded from the real service. Nothing else in openvc changes.
# --------------------------------------------------------------------------- #
