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
from urllib.parse import ParseResult, urlparse, urlunparse

from . import _json
from .errors import OpenvcError
from .proof._verify_common import safe_repr

# Fetch an https URL -> its parsed JSON object (e.g. openvc.fetch.https_json_fetch).
Fetch = Callable[[str], dict]
# The async counterpart: the same, returning an awaitable.
AsyncFetch = Callable[[str], Awaitable[dict]]

_WELL_KNOWN = "/.well-known/jwt-vc-issuer"


class JwtVcIssuerError(OpenvcError):
    """The issuer metadata could not be resolved, did not match, or has no key."""


# Path segments a WHATWG parser resolves away and urlparse keeps as they are.
_DOT_SEGMENTS = frozenset({".", "..", "%2e", ".%2e", "%2e.", "%2e%2e"})

# Python's ``urlparse`` and a WHATWG parser (a browser, a JS front-end) read some
# https URLs as different hosts, ports or paths. The two checks below refuse those
# forms, and the https issuer lanes (``jwt_vc_issuer``, ``x5c``, ``openid4vci``)
# share them so they refuse the same ones:
#
# * a non-ASCII URL: the host is IDNA2003 to Python and UTS 46 to a browser
#   (``faß.de`` is ``fass.de`` to one and ``xn--fa-hia.de`` to the other), and
#   ``urlparse`` NFKC-normalizes it, which is quadratic on CPython <= 3.12;
# * a backslash, which WHATWG reads as ``/``;
# * ``;``, ``?`` and ``#``, even empty: an issuer identifier carries no params,
#   query or fragment, and the metadata URL would silently drop them;
# * a percent-encoded host, which WHATWG decodes;
# * port 0, which WHATWG keeps and the guarded fetch reads as 443;
# * a ``.`` or ``..`` segment, which WHATWG resolves away.


def _raw_url_disagreement(value: str) -> str | None:
    """Why the parsers could disagree on *value*, checked before ``urlparse`` runs."""
    if not value.isascii():
        return "is not ASCII; write an IDN host as its xn-- A-label"
    if "\\" in value:
        return "contains a backslash"
    if any(char in value for char in ";?#"):
        return "must not carry params, a query or a fragment"
    return None


def _parsed_url_disagreement(parsed: ParseResult) -> str | None:
    """Why the parsers could disagree on an already-parsed URL."""
    if "%" in parsed.netloc:
        return "has a percent-encoded host"
    if parsed.port == 0:
        return "has port 0"
    if any(segment.lower() in _DOT_SEGMENTS for segment in parsed.path.split("/")):
        return "has a . or .. path segment"
    return None


def _parse_https_issuer(iss: Any) -> ParseResult:
    """Parse an https issuer identifier, or raise :class:`JwtVcIssuerError`.

    Beyond the scheme, this refuses every form that lets two URL parsers name
    different hosts or paths. A control character or whitespace is refused before
    parsing, because ``urlparse`` drops ``\\t\\r\\n``. Userinfo is refused:
    ``https://trusted.example\\@attacker.example`` names ``attacker.example`` to
    Python and ``trusted.example`` to a browser. The rest is the shared list above,
    with its non-ASCII check run before ``urlparse``.
    """
    if not isinstance(iss, str):
        raise JwtVcIssuerError(f"issuer must be a string, not {type(iss).__name__}")
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in iss):
        raise JwtVcIssuerError(
            f"issuer {safe_repr(iss)} contains control characters or whitespace")
    reason = _raw_url_disagreement(iss)
    if reason is not None:
        raise JwtVcIssuerError(f"issuer {safe_repr(iss)} {reason}")
    try:
        parsed = urlparse(iss)
        _ = parsed.hostname, parsed.port    # lazy: force a bad port or bracket to raise here
    except ValueError as exc:
        raise JwtVcIssuerError(f"issuer {safe_repr(iss)} is not a valid URL: {exc}") from exc
    if parsed.scheme != "https":
        raise JwtVcIssuerError(f"issuer {safe_repr(iss)} is not an https URL")
    if not parsed.hostname or not parsed.hostname.strip("."):
        raise JwtVcIssuerError(f"issuer {safe_repr(iss)} has no host")
    if parsed.username is not None or parsed.password is not None:
        raise JwtVcIssuerError(f"issuer {safe_repr(iss)} must not carry userinfo")
    reason = _parsed_url_disagreement(parsed)
    if reason is not None:
        raise JwtVcIssuerError(f"issuer {safe_repr(iss)} {reason}")
    return parsed


def jwt_vc_issuer_metadata_url(iss: str) -> str:
    """The JWT VC Issuer Metadata URL for an https *iss* — the well-known segment
    inserted between the host and the issuer's path."""
    parsed = _parse_https_issuer(iss)
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
        raise JwtVcIssuerError(f"no key with kid {safe_repr(kid)} in the issuer JWKS")
    if len(candidates) == 1:
        return candidates[0]
    raise JwtVcIssuerError("issuer JWKS has multiple keys but the token has no kid")


def _inline_jwks_or_uri(metadata: Any, iss: str) -> tuple[Any, str | None]:
    """Validate the issuer metadata (``issuer`` must equal *iss* — anti-substitution)
    and return either its inline ``jwks`` (uri ``None``) or the ``jwks_uri`` to fetch
    (jwks ``None``). Pure — shared by the sync and async resolvers."""
    if not isinstance(metadata, dict):
        raise JwtVcIssuerError("issuer metadata is not a JSON object")
    if _json.nesting_exceeds(metadata):       # the injected fetch hands it over parsed
        raise JwtVcIssuerError(
            f"issuer metadata is nested deeper than {_json.MAX_DEPTH} levels")
    if metadata.get("issuer") != iss:
        raise JwtVcIssuerError(
            f"metadata issuer {safe_repr(metadata.get('issuer'))} != token iss {iss!r}")
    jwks = metadata.get("jwks")
    if jwks is not None:
        return jwks, None
    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise JwtVcIssuerError("issuer metadata has neither jwks nor jwks_uri")
    return None, jwks_uri


def _key_from_jwks(jwks: Any, kid: str | None) -> dict[str, Any]:
    """Select the public JWK for *kid* from a fetched JWKS (pure — shared)."""
    if _json.nesting_exceeds(jwks):
        raise JwtVcIssuerError(f"issuer JWKS is nested deeper than {_json.MAX_DEPTH} levels")
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
