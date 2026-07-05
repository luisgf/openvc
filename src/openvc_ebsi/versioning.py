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
from typing import Any, Callable

from openvc.did.base import DidDocument, parse_did_document
from .models import Accreditation, IssuerRecord

# Injected capabilities (keep transport + crypto out of the adapters).
Fetch = Callable[[str], dict[str, Any]]          # GET a URL -> JSON
DecodeJwt = Callable[[str], dict[str, Any]]      # VC-JWT body -> claims (proof suite)


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

    def parse_issuer(self, raw, *, base, did, fetch, decode) -> IssuerRecord:
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
        return tuple(subject.get("accreditedFor", []) or [])


class TirV5(TirAdapter):
    """v5: issuer carries `hasAttributes`; attributes come as {id, href} and the
    body lives one fetch deeper, in a revision. Two+ calls, different shape."""
    version = "v5"

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/trusted-issuers-registry/{self.version}/issuers/{did}"

    def parse_issuer(self, raw, *, base, did, fetch, decode) -> IssuerRecord:
        has_attrs = bool(raw.get("hasAttributes", False))
        accs: list[Accreditation] = []
        if has_attrs:
            # ADR-0001 D6: the v5 issuer response carries the attributes URL in its
            # body (HATEOAS); follow it rather than reconstructing the path.
            attributes_url = raw.get("attributes") or (self.issuer_url(base, did) + "/attributes")
            listing = fetch(attributes_url)
            for item in listing.get("items", []):
                href = item.get("href")
                if not href:
                    continue
                revision = fetch(href)                    # extra hop, v5-specific
                body = revision.get("body")
                claims = decode(body) if body else {}
                subject = claims.get("vc", {}).get("credentialSubject", {})
                accs.append(Accreditation(
                    attribute_id=item.get("id", ""),
                    issuer_type=subject.get("issuerType", ""),
                    tao=subject.get("accreditedBy"),
                    root_tao=subject.get("rootTao"),
                    credential_types=tuple(subject.get("accreditedFor", []) or []),
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
