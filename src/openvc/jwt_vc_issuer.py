"""
openvc.jwt_vc_issuer — SD-JWT VC / OID4VC issuer-key discovery.

When a JOSE credential's ``iss`` is an **https URL** rather than a DID, the issuer
publishes its signing keys at a well-known endpoint (draft-ietf-oauth-sd-jwt-vc,
"JWT VC Issuer Metadata"). For ``iss = https://host/path`` the metadata lives at

    https://host/.well-known/jwt-vc-issuer/path

(the well-known segment is inserted between the host and the issuer path). The
document is JSON with a REQUIRED ``issuer`` — which **must equal** the ``iss``
(anti-substitution) — and either an inline ``jwks`` JWK Set or a ``jwks_uri`` to
fetch one. The issuer JWT's ``kid`` header selects the key.

Fetching is delegated to an injected ``fetch`` (pass :func:`openvc.fetch.https_json_fetch`
so the SSRF guards apply), keeping this module transport-agnostic. This is the
opt-in HTTPS-issuer counterpart to DID-based key resolution in the pipeline.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable
from urllib.parse import urlparse, urlunparse

from .errors import OpenvcError

# Fetch an https URL -> its parsed JSON object (e.g. openvc.fetch.https_json_fetch).
Fetch = Callable[[str], dict]
# The async counterpart: the same, returning an awaitable.
AsyncFetch = Callable[[str], Awaitable[dict]]

_WELL_KNOWN = "/.well-known/jwt-vc-issuer"


class JwtVcIssuerError(OpenvcError):
    """The issuer metadata could not be resolved, did not match, or has no key."""


def jwt_vc_issuer_metadata_url(iss: str) -> str:
    """The JWT VC Issuer Metadata URL for an https *iss* — the well-known segment
    inserted between the host and the issuer's path."""
    parsed = urlparse(iss)
    if parsed.scheme != "https":
        raise JwtVcIssuerError(f"issuer {iss!r} is not an https URL")
    if not parsed.netloc:
        raise JwtVcIssuerError(f"issuer {iss!r} has no host")
    path = parsed.path if parsed.path and parsed.path != "/" else ""
    return urlunparse(("https", parsed.netloc, _WELL_KNOWN + path, "", "", ""))


def _select_key(keys: list, kid: str | None) -> dict[str, Any]:
    candidates = [k for k in keys if isinstance(k, dict) and "d" not in k]  # public only
    if not candidates:
        raise JwtVcIssuerError("issuer JWKS has no usable public key")
    if kid is not None:
        for key in candidates:
            if key.get("kid") == kid:
                return key
        raise JwtVcIssuerError(f"no key with kid {kid!r} in the issuer JWKS")
    if len(candidates) == 1:
        return candidates[0]
    raise JwtVcIssuerError("issuer JWKS has multiple keys but the token has no kid")


def _inline_jwks_or_uri(metadata: Any, iss: str) -> tuple[Any, str | None]:
    """Validate the issuer metadata (``issuer`` must equal *iss* — anti-substitution)
    and return either its inline ``jwks`` (uri ``None``) or the ``jwks_uri`` to fetch
    (jwks ``None``). Pure — shared by the sync and async resolvers."""
    if not isinstance(metadata, dict):
        raise JwtVcIssuerError("issuer metadata is not a JSON object")
    if metadata.get("issuer") != iss:
        raise JwtVcIssuerError(
            f"metadata issuer {metadata.get('issuer')!r} != token iss {iss!r}")
    jwks = metadata.get("jwks")
    if jwks is not None:
        return jwks, None
    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise JwtVcIssuerError("issuer metadata has neither jwks nor jwks_uri")
    return None, jwks_uri


def _key_from_jwks(jwks: Any, kid: str | None) -> dict[str, Any]:
    """Select the public JWK for *kid* from a fetched JWKS (pure — shared)."""
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list) or not keys:
        raise JwtVcIssuerError("issuer JWKS has no `keys` array")
    return _select_key(keys, kid)


def resolve_jwt_vc_issuer_key(iss: str, kid: str | None, *, fetch: Fetch) -> dict[str, Any]:
    """Resolve the public JWK for an https *iss* + *kid* via its JWT VC Issuer
    Metadata. Verifies the metadata's ``issuer`` equals *iss* before trusting any
    key. *fetch* performs the (SSRF-guarded) https GETs."""
    metadata = fetch(jwt_vc_issuer_metadata_url(iss))
    jwks, jwks_uri = _inline_jwks_or_uri(metadata, iss)
    if jwks is None:
        jwks = fetch(jwks_uri)  # type: ignore[arg-type]  # jwks_uri is str when jwks is None
    return _key_from_jwks(jwks, kid)


async def resolve_jwt_vc_issuer_key_async(
    iss: str, kid: str | None, *, fetch: AsyncFetch
) -> dict[str, Any]:
    """Async :func:`resolve_jwt_vc_issuer_key` — awaits the (up to two) https GETs;
    identical metadata validation and key selection (the same pure code)."""
    metadata = await fetch(jwt_vc_issuer_metadata_url(iss))
    jwks, jwks_uri = _inline_jwks_or_uri(metadata, iss)
    if jwks is None:
        jwks = await fetch(jwks_uri)  # type: ignore[arg-type]  # str when jwks is None
    return _key_from_jwks(jwks, kid)


__all__ = [
    "AsyncFetch",
    "Fetch",
    "JwtVcIssuerError",
    "jwt_vc_issuer_metadata_url",
    "resolve_jwt_vc_issuer_key",
    "resolve_jwt_vc_issuer_key_async",
]
