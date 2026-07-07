"""
openvc.fetch — an SSRF-guarded, stdlib-only https JSON fetch for did:web.

did:web is intentionally cross-host (it resolves a controller's own domain), so
it cannot use a host allow-list like the EBSI client. This fetch instead blocks
the *dangerous* targets: it requires https, resolves the host and refuses any
private / loopback / link-local / reserved / multicast address (the cloud
metadata endpoint 169.254.169.254 is link-local, so it is covered), and refuses
HTTP redirects — a common SSRF pivot.

DNS-rebinding is closed, not just documented: the connection is **pinned to the
validated IP** (we resolve, validate every resolved address, then open the TCP
socket to that exact IP) while TLS SNI, certificate validation, and the Host
header still use the hostname. So an attacker who flips DNS between the check and
the connect cannot redirect us to an internal address — we never re-resolve.

Dependency-light on purpose: pure stdlib (http.client + ssl + socket +
ipaddress). Pass ``https_json_fetch`` wherever a ``Fetch`` is expected, or use
``default_did_web_resolver()``.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from .did.base import DidResolutionError
from .did.did_web import DidWebResolver

DEFAULT_TIMEOUT_S = 10.0
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB — DID documents are small; bound memory.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class UnsafeUrlError(DidResolutionError):
    """The URL or a resolved address is not allowed (scheme, host, or IP range)."""


def _ip_is_forbidden(ip_str: str) -> bool:
    """True for any non-globally-routable / SSRF-sensitive address."""
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _resolve_public_ips(host: str, port: int) -> list[str]:
    """Resolve *host* and return its addresses, raising if ANY is SSRF-sensitive
    (fail closed: one bad address rejects the host)."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"cannot resolve host {host!r}: {exc}") from exc
    ips = [str(info[4][0]) for info in infos]
    if not ips:
        raise UnsafeUrlError(f"host {host!r} did not resolve")
    for addr in ips:
        if _ip_is_forbidden(addr):
            raise UnsafeUrlError(
                f"host {host!r} resolves to blocked address {addr}")
    return ips


def _https_get(
    hostname: str, ip: str, port: int, target: str, *,
    timeout: float, max_bytes: int,
) -> tuple[int, bytes]:
    """GET *target* over https, TCP-pinned to *ip* but with TLS SNI, certificate
    validation and Host header for *hostname*. Returns (status, body). Reads at
    most ``max_bytes + 1`` so the caller can detect oversize."""
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=context)

    def _connect_to_validated_ip(address: Any, timeout: Any = None,
                                 source_address: Any = None) -> socket.socket:
        # Ignore the (hostname, port) address http.client would use; connect to
        # the IP we validated. wrap_socket still uses hostname for SNI + cert.
        return socket.create_connection((ip, port), timeout=timeout,
                                        source_address=source_address)

    setattr(conn, "_create_connection", _connect_to_validated_ip)
    try:
        conn.request("GET", target, headers={
            "Accept": "application/did+ld+json, application/json"})
        resp = conn.getresponse()
        return resp.status, resp.read(max_bytes + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise DidResolutionError(f"fetch failed for https://{hostname}{target}: {exc}") from exc
    finally:
        conn.close()


def _https_fetch_guarded(
    url: str, *, timeout_s: float, max_bytes: int,
) -> bytes:
    """Fetch *url* over https with the SSRF guards above and return the raw body.
    Shared by :func:`https_json_fetch` and :func:`https_text_fetch`."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UnsafeUrlError(f"only https is allowed, got scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise UnsafeUrlError("URL has no host")
    port = parsed.port or 443
    ip = _resolve_public_ips(parsed.hostname, port)[0]

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    status, raw = _https_get(parsed.hostname, ip, port, target,
                             timeout=timeout_s, max_bytes=max_bytes)
    if status in _REDIRECT_STATUSES:
        raise UnsafeUrlError(f"redirect ({status}) not followed (SSRF guard)")
    if status != 200:
        raise DidResolutionError(f"unexpected status {status} for {url!r}")
    if len(raw) > max_bytes:
        raise DidResolutionError(f"response exceeds {max_bytes} bytes")
    return raw


def https_json_fetch(
    url: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Fetch *url* as a JSON object with the SSRF guards above. Returns the parsed
    object.

    Raises :class:`UnsafeUrlError` for a disallowed scheme/host/address or a
    redirect (a subclass of :class:`~openvc.did.base.DidResolutionError`), and
    ``DidResolutionError`` for transport / oversize / non-JSON failures.
    """
    raw = _https_fetch_guarded(url, timeout_s=timeout_s, max_bytes=max_bytes)
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise DidResolutionError(f"response is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DidResolutionError("response must be a JSON object")
    return data


def https_text_fetch(
    url: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> str:
    """Fetch *url* as UTF-8 text with the same SSRF guards as :func:`https_json_fetch`.

    For resources that are not JSON objects — a compact-JWS status-list credential
    (VC-JWT) or an IETF ``statuslist+jwt`` token. Raises the same error family."""
    raw = _https_fetch_guarded(url, timeout_s=timeout_s, max_bytes=max_bytes)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DidResolutionError(f"response is not UTF-8 text: {exc}") from exc


def https_bytes_fetch(
    url: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> bytes:
    """Fetch *url* as raw bytes with the same SSRF guards as :func:`https_json_fetch`.

    For resources whose *exact bytes* matter — a ``credentialSchema`` whose
    ``digestSRI`` is verified over the response before parsing. Raises the same
    error family."""
    return _https_fetch_guarded(url, timeout_s=timeout_s, max_bytes=max_bytes)


def default_did_web_resolver() -> DidWebResolver:
    """A :class:`~openvc.did.did_web.DidWebResolver` wired to the SSRF-guarded
    fetch — the batteries-included way to resolve did:web offline of any HTTP
    client dependency."""
    return DidWebResolver(https_json_fetch)


__all__ = [
    "DEFAULT_TIMEOUT_S",
    "MAX_RESPONSE_BYTES",
    "UnsafeUrlError",
    "default_did_web_resolver",
    "https_bytes_fetch",
    "https_json_fetch",
    "https_text_fetch",
]
