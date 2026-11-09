"""
openvc.fetch — an SSRF-guarded, stdlib-only https JSON fetch for did:web.

did:web is intentionally cross-host (it resolves a controller's own domain), so
it cannot use a host allow-list like the EBSI client. This fetch instead blocks
the *dangerous* targets: it requires https, resolves the host and refuses any
address that is not globally routable (private / loopback / link-local /
reserved / multicast / unspecified, and RFC 6598 CGNAT ``100.64.0.0/10`` — the
cloud metadata endpoint 169.254.169.254 is link-local, so it is covered), and
refuses HTTP redirects — a common SSRF pivot.

DNS-rebinding is closed, not just documented: the connection is **pinned to the
validated IP** (we resolve, validate every resolved address, then open the TCP
socket to that exact IP) while TLS SNI, certificate validation, and the Host
header still use the hostname. So an attacker who flips DNS between the check and
the connect cannot redirect us to an internal address — we never re-resolve.

One wall-clock deadline, ``timeout_s``, bounds the **whole** dereference: DNS
resolution, the TCP connect, the TLS handshake, the status line and headers, and
the body. The per-operation socket timeout alone would not — ``http.client`` reads
the response head one socket operation at a time, so a server dripping one byte
per operation held a verifier thread for ``timeout_s`` × bytes (hours for a 1 KB
head), and ``getaddrinfo`` has no timeout at all. So the lookup runs on a helper
thread the caller waits on only until the deadline, and a watchdog timer shuts the
socket down at the deadline so a blocked read fails with a typed error. The one
residual is the lookup itself: a ``getaddrinfo`` that never returns is abandoned
on its daemon thread (the caller is released; the thread lives until the OS
resolver gives up). ``timeout_s`` must be an ``int`` or ``float`` number of seconds
greater than 0 and at most one day (``MAX_TIMEOUT_S``), the same ceiling as the EBSI
client's ``deadline_s``; anything else is refused with the typed error before any lookup.

Dependency-light on purpose: pure stdlib (http.client + ssl + socket +
ipaddress + threading). Pass ``https_json_fetch`` wherever a ``Fetch`` is
expected, or use ``default_did_web_resolver()``.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlparse

from . import _json
from .did.base import DidResolutionError
from .did.did_web import AsyncDidWebResolver, DidWebResolver
from .observability import logger, span

if TYPE_CHECKING:
    from .did.did_webvh import AsyncDidWebvhResolver, DidWebvhResolver

DEFAULT_TIMEOUT_S = 10.0
MAX_TIMEOUT_S = 86_400.0  # one day: the ceiling of a wall-clock budget, as the EBSI deadline_s
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB — DID documents are small; bound memory.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_WATCHDOG_THREAD_NAME = "openvc-fetch-watchdog"


class UnsafeUrlError(DidResolutionError):
    """The URL or a resolved address is not allowed (scheme, host, or IP range)."""


def ip_is_forbidden(ip_str: str) -> bool:
    """True for any non-globally-routable / SSRF-sensitive address.

    The flag union covers private / loopback / link-local / reserved /
    multicast / unspecified. ``not is_global`` additionally closes RFC 6598
    shared space (``100.64.0.0/10``, CGNAT), which ``is_private`` does not
    set — multicast stays in the union because some multicast addresses
    report ``is_global=True``, and so does the deprecated IPv6 site-local
    prefix ``fec0::/10`` (RFC 3879), which ``is_site_local`` catches.
    IPv4-mapped forms inherit the same classification (``::ffff:100.64.0.1``).

    Public so a caller that brings its own HTTP client applies the same rule instead of
    a copy of it (the ``_ip_is_forbidden`` name is kept as the same function). Raises
    ``ValueError`` for a string that is not an IP address; the caller decides what that
    means.
    """
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        or not ip.is_global
        # fec0::/10 reports is_global=True and no other flag; only IPv6 has the property.
        or (isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local)
    )


_ip_is_forbidden = ip_is_forbidden


def _resolve_public_ips(host: str, port: int) -> list[str]:
    """Resolve *host* and return its addresses, raising if ANY is SSRF-sensitive
    (fail closed: one bad address rejects the host)."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    # ValueError covers the UnicodeError the IDNA codec raises on a host it cannot
    # encode (an empty label, or one over 63 characters) before any DNS query.
    except (socket.gaierror, ValueError) as exc:
        raise UnsafeUrlError(f"cannot resolve host {host!r}: {exc}") from exc
    ips = [str(info[4][0]) for info in infos]
    if not ips:
        raise UnsafeUrlError(f"host {host!r} did not resolve")
    for addr in ips:
        if _ip_is_forbidden(addr):
            raise UnsafeUrlError(
                f"host {host!r} resolves to blocked address {addr}")
    return ips


def _resolve_within(hostname: str, port: int, deadline: float, timeout_s: float) -> str:
    """:func:`_resolve_public_ips` on a daemon thread, waited on until *deadline*.

    ``getaddrinfo`` has no timeout of its own, so the caller waits for the lookup only
    until the deadline and then fails closed with a typed error. The thread is then
    abandoned (it is a daemon, so it never blocks interpreter exit); it holds its
    resolver resources until the OS resolver gives up — the documented residual. The
    SSRF classification is the untouched :func:`_resolve_public_ips`, run as is, so a
    stubbed resolver (tests) still governs."""
    addresses: list[list[str]] = []
    failures: list[BaseException] = []

    def _run() -> None:
        try:
            addresses.append(_resolve_public_ips(hostname, port))
        except BaseException as exc:  # re-raised on the calling thread below
            failures.append(exc)

    worker = threading.Thread(target=_run, name="openvc-fetch-dns", daemon=True)
    try:
        worker.start()
    except RuntimeError as exc:  # thread exhaustion: fail closed, typed
        raise DidResolutionError(f"cannot start the DNS lookup for {hostname!r}: {exc}") from exc
    worker.join(max(deadline - time.monotonic(), 0.0))
    if failures:
        raise failures[0]
    if not addresses:
        raise DidResolutionError(
            f"DNS resolution of {hostname!r} exceeded the {timeout_s:g}s deadline")
    return addresses[0][0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An ``HTTPSConnection`` whose TCP socket goes to one validated *ip* while TLS SNI,
    certificate validation and the Host header use the hostname (what closes DNS
    rebinding: the name is never resolved again). Every socket it opens is handed to
    *watch* as soon as it exists — the TLS socket before the handshake, which is why
    the wrap and the handshake are two steps — so the deadline watchdog can shut it
    down at any point of the exchange. ``phase`` names the step in progress, for the
    error message."""

    def __init__(self, hostname: str, port: int, *, ip: str, timeout: float,
                 context: ssl.SSLContext, watch: Callable[[socket.socket], None]) -> None:
        # The base constructor raises InvalidURL on a control character in the host.
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._tls_context = context
        self._watch = watch
        self.phase = "TCP connect"

    def connect(self) -> None:
        # The event the stdlib connect() emits, so an audit hook still sees openvc's connects.
        sys.audit("http.client.connect", self, self.host, self.port)
        # The (hostname, port) address http.client would connect to is ignored.
        raw = socket.create_connection((self._pinned_ip, self.port), timeout=self.timeout)
        self._watch(raw)
        try:  # as http.client does; some OSs do not implement TCP_NODELAY
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.phase = "TLS handshake"
        # wrap_socket detaches *raw* (the TLS socket owns the descriptor from here), so
        # the TLS socket must be watched before the first handshake byte is read.
        self.sock = self._tls_context.wrap_socket(
            raw, server_hostname=self.host, do_handshake_on_connect=False)
        self._watch(self.sock)
        self.sock.do_handshake()
        self.phase = "request write"


def _https_get(
    hostname: str, ip: str, port: int, target: str, *,
    timeout: float, max_bytes: int,
) -> tuple[int, bytes]:
    """GET *target* over https, TCP-pinned to *ip* but with TLS SNI, certificate
    validation and Host header for *hostname*. Returns (status, body). Reads at
    most ``max_bytes + 1`` so the caller can detect oversize.

    *timeout* is one wall-clock budget, in seconds from this call, for the whole
    exchange — TCP connect, TLS handshake, request, status line, headers and body —
    and also the per-operation socket timeout. A watchdog timer shuts the socket
    down when the budget runs out, so a read blocked inside ``getresponse`` fails at
    once instead of being allowed the per-operation timeout again for every byte
    (``http.client`` reads the head one operation at a time, so a server dripping
    one byte per operation held the connection for ``timeout`` × bytes before
    1.39.0; CPython already bounds one ``do_handshake`` call as a whole). Once the
    watchdog has fired, every outcome is the typed deadline error — never a
    truncated body returned as complete."""
    deadline = time.monotonic() + timeout
    context = ssl.create_default_context()
    expired = threading.Event()
    sockets: list[socket.socket] = []

    def _shutdown(sock: socket.socket) -> None:
        # The base-class method, on purpose: SSLSocket.shutdown also drops the socket's
        # _sslobj, which the main thread reads between an "is not None" check and the
        # call in send() / read() — a bare AttributeError race. The descriptor-level
        # shutdown is all that is needed: the blocked read returns EOF or fails.
        try:
            socket.socket.shutdown(sock, socket.SHUT_RDWR)
        except OSError:  # already closed, or a raw socket detached by wrap_socket
            pass

    def _expire() -> None:
        # The flag goes first: a read that then returns EOF is seen as expired.
        expired.set()
        for sock in list(sockets):
            _shutdown(sock)

    def _watch(sock: socket.socket) -> None:
        sockets.append(sock)
        if expired.is_set():  # the watchdog fired before this socket existed
            _shutdown(sock)

    conn: _PinnedHTTPSConnection | None = None
    watchdog: threading.Timer | None = None
    try:
        # Built inside the try: the constructor raises InvalidURL on a control
        # character in the host.
        conn = _PinnedHTTPSConnection(hostname, port, ip=ip, timeout=timeout,
                                      context=context, watch=_watch)
        remaining_s = deadline - time.monotonic()
        if remaining_s <= 0:
            raise _deadline_error(hostname, target, conn.phase)
        timer = threading.Timer(remaining_s, _expire)
        timer.name = _WATCHDOG_THREAD_NAME
        timer.daemon = True
        try:
            timer.start()
        except RuntimeError as exc:  # thread exhaustion: fail closed, typed
            raise DidResolutionError(
                f"fetch failed for https://{hostname}{target}: cannot start the deadline "
                f"watchdog: {exc}") from exc
        watchdog = timer
        # request() opens the connection (connect + TLS handshake) on first use.
        conn.request("GET", target, headers={
            "Accept": "application/did+ld+json, application/json"})
        conn.phase = "response head"
        resp = conn.getresponse()
        if expired.is_set():
            raise _deadline_error(hostname, target, conn.phase)
        # Read against the same deadline, not only the per-socket timeout: a hostile
        # server dripping one byte before each recv could otherwise hold the connection (and,
        # on the async path, a to_thread worker) for timeout × number-of-recv. read1 does at
        # most one recv per call, so the deadline is actually enforced between reads.
        conn.phase = "response body"
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            if expired.is_set() or time.monotonic() > deadline:
                raise _deadline_error(hostname, target, conn.phase)
            chunk = resp.read1(min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        # An EOF caused by the watchdog's shutdown is not a complete body.
        if expired.is_set():
            raise _deadline_error(hostname, target, conn.phase)
        return resp.status, b"".join(chunks)
    # ValueError: a non-ASCII request target fails to encode (UnicodeEncodeError) as
    # the request line is written, and ssl rejects some server hostnames.
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # The watchdog's shutdown is what made the read fail — or the per-operation
        # socket timeout, armed later than the watchdog, ran out of the same budget.
        if expired.is_set() or (isinstance(exc, TimeoutError) and time.monotonic() >= deadline):
            raise _deadline_error(
                hostname, target, conn.phase if conn is not None else "TCP connect") from exc
        raise DidResolutionError(f"fetch failed for https://{hostname}{target}: {exc}") from exc
    finally:
        if watchdog is not None:
            # cancel() alone could leave the callback mid-run; join() orders it before the
            # conn.close() below. http.client closes the descriptor earlier on some paths (a
            # ConnectionError inside getresponse(), a body that ends under Connection: close):
            # there the socket object's own invalidation covers it — a closed socket has fd -1,
            # so the shutdown is EBADF, swallowed, never a descriptor the OS has reused.
            watchdog.cancel()
            watchdog.join()
        if conn is not None:
            conn.close()


def _deadline_error(hostname: str, target: str, phase: str) -> DidResolutionError:
    return DidResolutionError(
        f"fetch failed for https://{hostname}{target}: exceeded the wall-clock deadline "
        f"during the {phase}")


def _https_fetch_guarded(
    url: str, *, timeout_s: float, max_bytes: int,
) -> bytes:
    """Fetch *url* over https with the SSRF guards above and return the raw body.
    Shared by :func:`https_json_fetch` and :func:`https_text_fetch`.

    The deadline starts here, before anything is parsed or resolved: DNS, connect,
    TLS, headers and body all spend the one ``timeout_s`` budget."""
    # The budget's whole domain is checked up front, typed: a NaN would make every deadline
    # comparison false (the deadline would never fire), inf or a finite value past ~9.2e9 s
    # overflows the timers (a bare OverflowError), a non-number is a bare TypeError in the
    # arithmetic, and bool is not a number of seconds. int or float in (0, one day]; the
    # chained comparison alone excludes NaN and inf, and never converts a huge int to float.
    if (isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
            or not 0 < timeout_s <= MAX_TIMEOUT_S):
        raise DidResolutionError(
            "timeout_s must be an int or float number of seconds greater than 0 and at most "
            f"{MAX_TIMEOUT_S:g} (one day), got {timeout_s!r}")
    deadline = time.monotonic() + timeout_s
    # ASCII before anything parses it. urlparse NFKC-normalizes a non-ASCII netloc,
    # which is quadratic on CPython <= 3.12 for out-of-order combining marks, even
    # on a worker thread (normalize holds the GIL). getaddrinfo would IDNA-encode a
    # Unicode host with IDNA2003, mapping faß.de to fass.de where IDNA2008 and
    # browsers give xn--fa-hia.de, another domain. A non-ASCII path cannot be sent
    # either. An IDN must arrive as its xn-- A-label.
    if not url.isascii():
        raise UnsafeUrlError("URL is not ASCII; send an IDN host as its xn-- A-label")
    try:
        parsed = urlparse(url)
        # Force the lazy accessors: an out-of-range or non-numeric port, an unbalanced
        # IPv6 bracket, or a netloc that NFKC-normalizes into a delimiter raises
        # ValueError here, inside the typed taxonomy.
        hostname, port = parsed.hostname, parsed.port or 443
    except ValueError as exc:
        raise UnsafeUrlError(f"malformed URL: {exc}") from exc
    if parsed.scheme != "https":
        raise UnsafeUrlError(f"only https is allowed, got scheme {parsed.scheme!r}")
    if not hostname:
        raise UnsafeUrlError("URL has no host")
    if len(hostname) > 253:
        raise UnsafeUrlError("host is longer than 253 characters")
    # Refused before DNS: getaddrinfo would resolve a host truncated at a NUL.
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in hostname):
        raise UnsafeUrlError(f"host {hostname!r} contains control characters or whitespace")
    # Log host + path only — a query string could carry a caller secret, so it is never
    # logged (nor is any response body).
    logger.debug("fetch https://%s%s", hostname, parsed.path or "/")
    ip = _resolve_within(hostname, port, deadline, timeout_s)

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    # What the lookup left of the budget is the exchange's whole budget: _https_get
    # measures connect, TLS, head and body from the same start instant.
    remaining_s = deadline - time.monotonic()
    if remaining_s <= 0:
        raise DidResolutionError(
            f"DNS resolution of {hostname!r} exceeded the {timeout_s:g}s deadline")
    with span("openvc.fetch", host=hostname):
        status, raw = _https_get(hostname, ip, port, target,
                                 timeout=remaining_s, max_bytes=max_bytes)
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
        data = _json.loads(raw)
    except (ValueError, json.JSONDecodeError, RecursionError) as exc:
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


def default_did_webvh_resolver() -> "DidWebvhResolver":
    """A :class:`~openvc.did.did_webvh.DidWebvhResolver` wired to the SSRF-guarded
    **text** fetch (``did.jsonl`` is JSON Lines, not one JSON object) — the
    batteries-included did:webvh resolver."""
    from .did.did_webvh import DidWebvhResolver
    return DidWebvhResolver(https_text_fetch)


# --------------------------------------------------------------------------- #
# Async fetches (additive — see docs/adr/ADR-0002-async-verification.md)
#
# These run the EXACT same SSRF/DNS-rebinding guard under asyncio.to_thread: the
# guarantees (https-only, blocked address ranges, TCP pinned to the validated IP,
# no redirects) are identical because it is the same code — only the event loop is
# freed while the blocking GET runs on a worker thread. No new dependency: the
# guard stays stdlib and httpx remains an EBSI-only extra. A caller who wants a
# native httpx.AsyncClient fetch may inject their own; they then own the SSRF
# contract (`_ip_is_forbidden` / `_resolve_public_ips` are the primitives to reuse).
# --------------------------------------------------------------------------- #

async def https_json_fetch_async(
    url: str, *, timeout_s: float = DEFAULT_TIMEOUT_S, max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Async :func:`https_json_fetch` — same SSRF guards, run off the event loop."""
    return await asyncio.to_thread(https_json_fetch, url, timeout_s=timeout_s, max_bytes=max_bytes)


async def https_text_fetch_async(
    url: str, *, timeout_s: float = DEFAULT_TIMEOUT_S, max_bytes: int = MAX_RESPONSE_BYTES,
) -> str:
    """Async :func:`https_text_fetch` — same SSRF guards, run off the event loop."""
    return await asyncio.to_thread(https_text_fetch, url, timeout_s=timeout_s, max_bytes=max_bytes)


async def https_bytes_fetch_async(
    url: str, *, timeout_s: float = DEFAULT_TIMEOUT_S, max_bytes: int = MAX_RESPONSE_BYTES,
) -> bytes:
    """Async :func:`https_bytes_fetch` — same SSRF guards, run off the event loop."""
    return await asyncio.to_thread(https_bytes_fetch, url, timeout_s=timeout_s, max_bytes=max_bytes)


def default_async_did_web_resolver() -> AsyncDidWebResolver:
    """An :class:`~openvc.did.did_web.AsyncDidWebResolver` wired to the SSRF-guarded
    async fetch — the async counterpart of :func:`default_did_web_resolver`."""
    return AsyncDidWebResolver(https_json_fetch_async)


def default_async_did_webvh_resolver() -> "AsyncDidWebvhResolver":
    """The async counterpart of :func:`default_did_webvh_resolver` — an
    :class:`~openvc.did.did_webvh.AsyncDidWebvhResolver` on the SSRF-guarded async
    text fetch."""
    from .did.did_webvh import AsyncDidWebvhResolver
    return AsyncDidWebvhResolver(https_text_fetch_async)


__all__ = [
    "DEFAULT_TIMEOUT_S",
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT_S",
    "UnsafeUrlError",
    "default_async_did_web_resolver",
    "default_async_did_webvh_resolver",
    "default_did_web_resolver",
    "default_did_webvh_resolver",
    "https_bytes_fetch",
    "https_bytes_fetch_async",
    "https_json_fetch",
    "https_json_fetch_async",
    "https_text_fetch",
    "https_text_fetch_async",
    "ip_is_forbidden",
]
