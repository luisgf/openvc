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
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from openvc.did.base import DidDocument, parse_did_document
from openvc.observability import logger
from .errors import MalformedRegistryResponse
from .models import Accreditation, IssuerRecord

# Injected capabilities (keep transport + crypto out of the adapters).
Fetch = Callable[[str], dict[str, Any]]          # GET a URL -> JSON
DecodeJwt = Callable[[str], dict[str, Any]]      # VC-JWT body -> claims (proof suite)


def _origin(url: str) -> str:
    """``scheme://host:port`` (lowercased) — used to keep pagination on the listing's
    own origin. A belt-and-suspenders check on top of the HTTP client's SSRF allow-list:
    a ``links.next`` cursor may only advance within the same web origin as the listing —
    the port is part of that origin, so a ``next`` that only changes the port is refused
    (the SSRF host allow-list matches host but not port)."""
    p = urlparse(url)
    port = "" if p.port is None else p.port
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}:{port}"


def _require_object(value: Any, what: str) -> dict[str, Any]:
    """A fetched registry body must be a JSON object where the adapter reads one.
    A non-object (``null`` / list / string / number — a flaky or compromised registry)
    fails closed as a typed :class:`MalformedRegistryResponse`, never a bare
    ``AttributeError`` leaking past the ``EbsiError`` / ``OpenvcError`` family."""
    if not isinstance(value, dict):
        raise MalformedRegistryResponse(
            f"expected a JSON object for {what}, got {type(value).__name__}")
    return value


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


# --------------------------------------------------------------------------- #
# Trusted Issuers Registry adapters — where the real drift lives
# --------------------------------------------------------------------------- #

class TirAdapter(ABC):
    version: str

    @abstractmethod
    def issuer_url(self, base: str, did: str) -> str: ...

    @abstractmethod
    def parse_issuer(
        self, raw: dict[str, Any], *, base: str, did: str,
        fetch: Fetch, decode: DecodeJwt,
    ) -> IssuerRecord:
        """Map the issuer response to an IssuerRecord.

        `fetch`/`decode` are injected so an adapter can perform any extra calls its
        version requires (e.g. attribute -> revision -> body) without the caller
        knowing anything about it.
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


class TirV5(TirAdapter):
    """v5: issuer carries `hasAttributes`; attributes come as {id, href} and the
    body lives one fetch deeper, in a revision. Two+ calls, different shape."""
    version = "v5"

    # A registry with many accreditations paginates `/attributes`; these bound the walk
    # so a registry that keeps handing out a `next` cursor — or one giant page — can
    # never spin forever nor fan one verify out into unbounded revision fetches.
    _MAX_ATTRIBUTE_PAGES = 50
    _MAX_ATTRIBUTE_ITEMS = 1000

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/trusted-issuers-registry/{self.version}/issuers/{did}"

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
            url = nxt if isinstance(nxt, str) and nxt and _origin(nxt) == origin else None

    def parse_issuer(self, raw: Any, *, base: str, did: str, fetch: Any,
                     decode: Any) -> IssuerRecord:
        raw = _require_object(raw, "TIR issuer response")
        has_attrs = bool(raw.get("hasAttributes", False))
        accs: list[Accreditation] = []
        if has_attrs:
            # ADR-0001 D6: the v5 issuer response carries the attributes URL in its
            # body (HATEOAS); follow it rather than reconstructing the path.
            attributes_url = raw.get("attributes") or (self.issuer_url(base, did) + "/attributes")
            for item in self._iter_attribute_items(attributes_url, fetch):
                href = item.get("href")
                if not href:
                    continue
                revision = _require_object(fetch(href), "TIR attribute revision")  # v5 hop
                # v5 nests the accreditation under `attribute`: the signed VC-JWT
                # is `attribute.body`, and issuerType/tao/rootTao sit on the
                # `attribute` object itself — NOT in the VC credentialSubject
                # (whose `accreditedFor` carries the authorised types).
                attribute = revision.get("attribute")
                attribute = attribute if isinstance(attribute, dict) else {}
                body = attribute.get("body")
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


# --------------------------------------------------------------------------- #
# Version selection — the only place a version string maps to an adapter
# --------------------------------------------------------------------------- #

DID_REGISTRY_ADAPTERS: dict[str, type[DidRegistryAdapter]] = {"v5": DidRegistryV5}
TIR_ADAPTERS: dict[str, type[TirAdapter]] = {"v4": TirV4, "v5": TirV5}


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
        raw = self._get(self._didr.identifiers_url(self._base, did))
        return self._didr.parse_did_document(raw)          # no version logic here

    def issuer_record(self, did: str) -> IssuerRecord:
        raw = self._get(self._tir.issuer_url(self._base, did))
        return self._tir.parse_issuer(
            raw, base=self._base, did=did, fetch=self._get, decode=self._decode,
        )

    # The trust-chain logic (openvc_ebsi.trust.verify_trust_chain) operates purely
    # on IssuerRecord / Accreditation, so no API version can reach it.


# --------------------------------------------------------------------------- #
# Adding a new version later, in full:
#
#   class TirV6(TirAdapter):
#       version = "v6"
#       def issuer_url(self, base, did): ...
#       def parse_issuer(self, raw, *, base, did, fetch, decode): ...
#
#   TIR_ADAPTERS["v6"] = TirV6
#
# ...plus a golden fixture test. Nothing else in openvc changes.
# --------------------------------------------------------------------------- #
