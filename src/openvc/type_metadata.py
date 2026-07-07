"""
openvc.type_metadata — SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc-17 §4).

Verifier side: resolve the Type Metadata a credential's ``vct`` points to, pin it with
``vct#integrity`` (a W3C Subresource-Integrity hash), enforce ``metadata.vct`` equals
the credential's ``vct``, walk the ``extends`` chain (parent before child, each
integrity-pinned, cycle-/depth-bounded), compose the inherited claim metadata, and
validate the processed SD-JWT payload against it — the DCQL-style ``path`` engine plus
``mandatory``. Fetch is **opt-in** and every failure is **fail-closed** (§4.7: "*If
claim metadata processing or validation fails, the SD-JWT VC MUST be rejected*").

Two scope notes tied to the current draft:

* Embedded **JSON Schema was removed** from Type Metadata in draft-12 — there is no
  ``schema`` / ``schema_uri`` member and no schema dialect. Payload validation is done
  through the ``claims`` array, not a JSON Schema.
* The per-claim ``sd`` (selective-disclosure) constraint is an **issuance**-time rule; a
  verifier can only check it against per-claim disclosure provenance, which the SD-JWT
  layer does not currently expose, so it is **not enforced here** (path structure and
  ``mandatory`` presence are). This is a documented boundary, not a silent skip.

Reuses :func:`openvc.schema._verify_sri` (the reviewed, constant-time SRI check) and,
via the caller-supplied resolver, :func:`openvc.fetch.https_bytes_fetch` — so the fetch
inherits the SSRF / size / time guards. Type Metadata URLs are as untrusted as
``did:web``; never resolve them through the EBSI client.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .errors import OpenvcError
from .schema import SchemaResolutionError, _verify_sri

__all__ = [
    "validate_type_metadata",
    "TypeMetadataResult",
    "TypeMetadataError",
    "TypeMetadataResolutionError",
    "TypeMetadataMismatch",
    "TypeMetadataClaimsInvalid",
    "ResolveTypeMetadata",
]

# A resolver maps a Type Metadata URL (the credential's ``vct``, or an ``extends`` URI)
# to the raw document bytes. Opt-in; e.g. openvc.resolvers.default_type_metadata_resolver.
ResolveTypeMetadata = Callable[[str], bytes]

# Bound the extends chain so a hostile hierarchy cannot exhaust resolution (§6.3).
_MAX_EXTENDS_DEPTH = 10

# Bound path selection so a `null`-heavy path over a deeply-nested (issuer-signed)
# payload cannot blow up combinatorially. Generous for any real credential.
_MAX_SELECT_NODES = 10_000


class TypeMetadataError(OpenvcError):
    """Base class for SD-JWT VC Type Metadata failures."""


class TypeMetadataResolutionError(TypeMetadataError):
    """The Type Metadata could not be fetched, parsed, integrity-checked, or the
    ``extends`` chain cycles / is too deep."""


class TypeMetadataMismatch(TypeMetadataError):
    """A resolved document's ``vct`` differs from the credential's ``vct``."""


class TypeMetadataClaimsInvalid(TypeMetadataError):
    """The processed SD-JWT payload does not satisfy the composed claim metadata."""


@dataclass(frozen=True)
class TypeMetadataResult:
    """The outcome of Type Metadata processing for a verified SD-JWT VC."""
    vct: str
    documents: tuple[dict[str, Any], ...]     # the resolved chain, subtype first
    claims: tuple[dict[str, Any], ...]        # the composed claim-metadata objects


def validate_type_metadata(
    payload: dict[str, Any],
    *,
    vct: str,
    vct_integrity: str | None = None,
    resolve: ResolveTypeMetadata,
    max_extends_depth: int = _MAX_EXTENDS_DEPTH,
) -> TypeMetadataResult:
    """Resolve and enforce the Type Metadata for a verified SD-JWT VC's *payload*.

    *vct* / *vct_integrity* are the credential's ``vct`` and ``vct#integrity`` claims
    (from the processed payload). *resolve* fetches a Type Metadata document by URL
    (opt-in — pass e.g. :func:`openvc.resolvers.default_type_metadata_resolver`). Fails
    closed: an integrity mismatch, a document whose ``vct`` differs, an ``extends``
    cycle / over-depth, or a claim-metadata violation each raise a
    :class:`TypeMetadataError`.
    """
    documents, claims = _resolve_chain(vct, vct_integrity, resolve, max_extends_depth, [])
    _validate_claims(payload, claims)
    return TypeMetadataResult(vct=vct, documents=tuple(documents), claims=tuple(claims))


# --------------------------------------------------------------------------- #
# resolution + the extends chain
# --------------------------------------------------------------------------- #

def _resolve_chain(
    vct: str, integrity: str | None, resolve: ResolveTypeMetadata,
    max_depth: int, seen: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if len(seen) >= max_depth:
        raise TypeMetadataResolutionError(
            f"type metadata extends chain exceeds {max_depth} levels")
    if vct in seen:
        raise TypeMetadataResolutionError(f"type metadata extends cycle at {vct!r}")
    seen.append(vct)

    document = _fetch_document(vct, integrity, resolve)
    documents = [document]
    claims = _claim_list(document, vct)

    extends = document.get("extends")
    if extends is not None:
        if not isinstance(extends, str):
            raise TypeMetadataResolutionError(
                f"type metadata {vct!r} has a non-string extends")
        parent_docs, parent_claims = _resolve_chain(
            extends, document.get("extends#integrity"), resolve, max_depth, seen)
        documents = documents + parent_docs
        claims = _compose_claims(child=claims, parent=parent_claims)
    return documents, claims


def _fetch_document(
    vct: str, integrity: str | None, resolve: ResolveTypeMetadata,
) -> dict[str, Any]:
    try:
        raw = resolve(vct)
    except Exception as exc:                            # SSRF block, oversize, HTTP error — or a
        raise TypeMetadataResolutionError(              # custom resolver's own error; all typed
            f"could not retrieve type metadata for {vct!r}: {exc}") from exc
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeMetadataResolutionError(
            f"type metadata resolver for {vct!r} must return bytes")
    raw = bytes(raw)

    # Integrity is verified over the RAW retrieved bytes, before parsing (§5).
    if integrity is not None:
        if not isinstance(integrity, str):
            raise TypeMetadataResolutionError(f"{vct!r} #integrity must be a string")
        try:
            _verify_sri(raw, integrity, vct)
        except SchemaResolutionError as exc:
            raise TypeMetadataResolutionError(
                f"type metadata for {vct!r} fails its integrity hash: {exc}") from exc

    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise TypeMetadataResolutionError(
            f"type metadata for {vct!r} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TypeMetadataResolutionError(
            f"type metadata for {vct!r} must be a JSON object")
    # The identity check (§4.3): the document must describe the type it was fetched for.
    if document.get("vct") != vct:
        raise TypeMetadataMismatch(
            f"type metadata vct {document.get('vct')!r} != requested {vct!r}")
    return document


def _claim_list(document: dict[str, Any], vct: str) -> list[dict[str, Any]]:
    claims = document.get("claims")
    if claims is None:
        return []
    if not isinstance(claims, list) or not all(isinstance(c, dict) for c in claims):
        raise TypeMetadataResolutionError(
            f"type metadata {vct!r} claims must be an array of objects")
    # Validate the path SHAPE at ingestion (path is REQUIRED, §4.6) so a malformed —
    # e.g. unhashable, a nested list — path fails closed as a typed error before it is
    # used as a dict/set key in _compose_claims.
    for claim in claims:
        if not _is_valid_path(claim.get("path")):
            raise TypeMetadataResolutionError(
                f"type metadata {vct!r} has a malformed claim path {claim.get('path')!r}")
    return claims


def _is_valid_component(component: Any) -> bool:
    return (isinstance(component, str) or component is None
            or (isinstance(component, int) and not isinstance(component, bool)
                and component >= 0))


def _is_valid_path(path: Any) -> bool:
    return isinstance(path, list) and bool(path) and all(_is_valid_component(c) for c in path)


def _compose_claims(
    *, child: list[dict[str, Any]], parent: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    # Inherit the supertype's claim metadata; a child claim with the same path overrides
    # it wholesale (no deep merge) — §4.6.5. Child entries come first, then non-overridden
    # parent entries.
    overridden = {_path_key(c.get("path")) for c in child}
    return child + [p for p in parent if _path_key(p.get("path")) not in overridden]


def _path_key(path: Any) -> tuple:
    return tuple(path) if isinstance(path, list) else (path,)


# --------------------------------------------------------------------------- #
# claim-metadata validation (the DCQL-style path engine + mandatory)
# --------------------------------------------------------------------------- #

def _validate_claims(payload: dict[str, Any], claims: list[dict[str, Any]]) -> None:
    for claim in claims:
        path = claim.get("path")
        if not isinstance(path, list) or not path:
            raise TypeMetadataClaimsInvalid("a claim metadata object needs a non-empty path")
        selection = _select(payload, path)
        # `mandatory` (default false): the claim must be present in the payload being
        # validated. (A verifier that requires the mandatory claims disclosed passes the
        # disclosed set; the per-claim `sd` constraint needs disclosure provenance and is
        # a documented non-goal here.)
        if claim.get("mandatory") is True and not selection:
            raise TypeMetadataClaimsInvalid(
                f"mandatory claim at path {path} is not present in the credential")


def _select(payload: dict[str, Any], path: list[Any]) -> list[Any]:
    """Select the node(s) a Type Metadata / DCQL *path* addresses (§4.6.1.2): a string
    selects an object key, ``None`` selects every element of an array, a non-negative
    integer selects an array index. A component applied to the wrong node type is a
    structural error (reject); a missing key/index drops from the selection."""
    nodes: list[Any] = [payload]
    for component in path:
        selected: list[Any] = []
        for node in nodes:
            if isinstance(component, str):
                if not isinstance(node, dict):
                    raise TypeMetadataClaimsInvalid(
                        f"path component {component!r} applied to a non-object")
                if component in node:
                    selected.append(node[component])
            elif component is None:
                if not isinstance(node, list):
                    raise TypeMetadataClaimsInvalid("null path component applied to a non-array")
                selected.extend(node)
            elif isinstance(component, int) and not isinstance(component, bool) and component >= 0:
                if not isinstance(node, list):
                    raise TypeMetadataClaimsInvalid(
                        f"index path component {component} applied to a non-array")
                if component < len(node):
                    selected.append(node[component])
            else:
                raise TypeMetadataClaimsInvalid(f"invalid path component {component!r}")
        nodes = selected
        if len(nodes) > _MAX_SELECT_NODES:
            raise TypeMetadataClaimsInvalid(
                f"claim path selection exceeds {_MAX_SELECT_NODES} nodes")
    return nodes
