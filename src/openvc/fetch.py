"""
openvc.fetch — an SSRF-guarded, stdlib-only https JSON fetch for did:web.

did:web is intentionally cross-host (it resolves a controller's own domain), so
it cannot use a host allow-list like the EBSI client. This fetch instead blocks
the *dangerous* targets: it requires https, resolves the host and refuses any
private / loopback / link-local / reserved / multicast address (the cloud
metadata endpoint 169.254.169.254 is link-local, so it is covered), and refuses
HTTP redirects — a common SSRF pivot.

Dependency-light on purpose: pure stdlib (urllib + socket + ipaddress), so the
core needs no HTTP client. Pass ``https_json_fetch`` wherever a ``Fetch`` is
expected, or use ``default_did_web_resolver()``.

Residual risk (documented, not yet closed): the host is validated at resolve
time and urllib then connects by name, leaving a TOCTOU window a DNS-rebinding
attacker could exploit. Pinning the connection to the validated IP closes it and
is tracked in docs/ROADMAP.md; for resolving well-known issuer domains this
check is already a substantial guard.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any
from urllib import request as urlrequest
from urllib.error import URLError
from urllib.parse import urlparse

from .did.base import DidResolutionError
from .did.did_web import DidWebResolver

DEFAULT_TIMEOUT_S = 10.0
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB — DID documents are small; bound memory.


class UnsafeUrlError(DidResolutionError):
    """The URL or a resolved address is not allowed (scheme, host, or IP range)."""


def _ip_is_forbidden(ip_str: str) -> bool:
    """True for any non-globally-routable / SSRF-sensitive address."""
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _assert_public_host(host: str, port: int) -> None:
    """Resolve *host* and reject if ANY resolved address is SSRF-sensitive."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"cannot resolve host {host!r}: {exc}") from exc
    if not infos:
        raise UnsafeUrlError(f"host {host!r} did not resolve")
    for info in infos:
        addr = str(info[4][0])
        if _ip_is_forbidden(addr):
            raise UnsafeUrlError(
                f"host {host!r} resolves to blocked address {addr}")


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise UnsafeUrlError("HTTP redirects are not followed (SSRF guard)")


def _build_opener() -> urlrequest.OpenerDirector:
    # Factored out so tests can substitute the transport without real network.
    return urlrequest.build_opener(_NoRedirect)


def https_json_fetch(
    url: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Fetch *url* as JSON with the SSRF guards above. Returns the parsed object.

    Raises :class:`UnsafeUrlError` for a disallowed scheme/host/address (a
    subclass of :class:`~openvc.did.base.DidResolutionError`), and
    ``DidResolutionError`` for transport / oversize / non-JSON failures.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UnsafeUrlError(f"only https is allowed, got scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise UnsafeUrlError("URL has no host")
    _assert_public_host(parsed.hostname, parsed.port or 443)

    req = urlrequest.Request(
        url, headers={"Accept": "application/did+ld+json, application/json"})
    try:
        with _build_opener().open(req, timeout=timeout_s) as resp:
            raw = resp.read(max_bytes + 1)
    except UnsafeUrlError:
        raise                                    # our own guard, keep the type
    except URLError as exc:
        raise DidResolutionError(f"fetch failed for {url!r}: {exc}") from exc

    if len(raw) > max_bytes:
        raise DidResolutionError(f"response exceeds {max_bytes} bytes")
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise DidResolutionError(f"response is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DidResolutionError("DID document must be a JSON object")
    return data


def default_did_web_resolver() -> DidWebResolver:
    """A :class:`~openvc.did.did_web.DidWebResolver` wired to the SSRF-guarded
    fetch — the batteries-included way to resolve did:web offline of any HTTP
    client dependency."""
    return DidWebResolver(https_json_fetch)
