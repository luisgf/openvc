"""
openvc_ebsi.http — the read-only HTTP client that satisfies the `Fetch` capability.

It is deliberately small but covers the production concerns a verifier needs:

  * timeouts        : never block forever (connect + read).
  * retries         : bounded, only on idempotent GET and transient failures
                      (network errors, 429, 5xx), with exponential backoff + jitter
                      and Retry-After support — no thundering herd.
  * caching         : TTL + bounded size. EBSI registry reads (DID docs, TIR
                      entries, schemas) change rarely and are hit on every verify.
  * SSRF guard      : the TIR v5 flow follows `href` values taken from registry
                      responses; those hrefs are only fetched if their host is on
                      an allow-list derived from the configured EBSI base. A
                      compromised/malicious registry response cannot pivot the
                      client to an internal address.
  * connection reuse: a single pooled httpx.Client; redirects disabled.
  * address guard   : OPT-IN (``address_guard=AddressGuard()``, off by default). The host
                      allow-list matches a NAME and trusts DNS for it. With the guard on,
                      every request resolves the name, refuses the host if ANY answer is not
                      a globally routable address (the rules ``openvc.fetch`` applies to
                      did:web), and connects to one validated address while the TLS server
                      name, the certificate check and ``Host`` stay the host name. It does
                      not stop an attacker who holds a valid certificate for a public
                      address, and it needs the local resolver, so it refuses to be built
                      behind an environment proxy. See :class:`AddressGuard`.

Pass ``client.get_json`` wherever a ``Fetch`` is expected (e.g. into the resolver).
"""

from __future__ import annotations

import ipaddress
import random
import socket
import time
import urllib.request
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from openvc import _json
from openvc import __version__
from openvc.cache import TtlCache
from openvc.fetch import ip_is_forbidden
from openvc.proof._verify_common import safe_repr

from .errors import EbsiError, MalformedRegistryResponse

# EBSI registry reads (DID docs, TIR entries, schemas) are small; bound the memory an
# attacker-influenced (or compromised) allow-listed host can force. The general fetch caps
# did:web at 1 MiB; TIR walks can be a little larger, so allow more headroom here.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Hosts per EBSI environment (used to seed the SSRF allow-list).
EBSI_HOSTS: dict[str, str] = {
    "pilot": "api-pilot.ebsi.eu",
    "conformance": "api-conformance.ebsi.eu",
    # EBSI's business/production environment (EUROPEUM-EDIC-governed, ebsi.eu family)
    # launches Q4 2026 on the unprefixed production host, following the established
    # api-<env>.ebsi.eu naming. Registered so `for_ebsi("production")`, `EBSI_BASE`, and
    # the SSRF allow-list are ready at cutover; any additional issuer host a deployment
    # needs (e.g. a status-list origin) is still permitted explicitly via `extra_hosts`.
    "production": "api.ebsi.eu",
}
EBSI_BASE: dict[str, str] = {env: f"https://{host}" for env, host in EBSI_HOSTS.items()}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class HttpError(EbsiError):
    def __init__(self, message: str, *, status: int | None = None, url: str | None = None):
        super().__init__(message)
        self.status = status
        self.url = url


class HttpNotFound(HttpError): ...          # 404 — maps to DidNotFound upstream
class HttpForbiddenHost(HttpError): ...     # SSRF guard tripped
class HttpTransientExhausted(HttpError): ...  # retries used up


class HttpForbiddenAddress(HttpForbiddenHost):
    """The address guard refused an allow-listed host: it resolves to (or is) an address
    that is not globally routable. A subclass of :class:`HttpForbiddenHost`, so a caller
    that already handles the name guard handles this too. Never retried, never cached."""


class HttpAddressResolutionFailed(HttpError):
    """The address guard's resolver returned no usable answer (a resolution error or an
    empty list). Handled like a connection failure: retried, then
    :class:`HttpTransientExhausted`."""


class HttpAddressGuardUnavailable(HttpError):
    """An :class:`AddressGuard` was requested but cannot be honest in this process: an
    environment proxy would resolve and connect on its own. Raised when the client is
    built, before any request."""


# The thread-safe, bounded TtlCache now lives in core (openvc.cache) so the whole
# library — DID/status/schema resolution — shares one caching primitive; EBSI consumes
# it downward and keeps its short-TTL default (ADR-0001 D2: EBSI sends no cache headers).


# --------------------------------------------------------------------------- #
# Retry policy
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 3
    backoff_base_s: float = 0.25
    backoff_max_s: float = 5.0
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})

    def backoff(self, attempt: int) -> float:
        # exponential with equal jitter: half fixed, half random.
        ceiling = min(self.backoff_base_s * (2 ** attempt), self.backoff_max_s)
        return ceiling / 2 + random.uniform(0, ceiling / 2)


# --------------------------------------------------------------------------- #
# Resolved-address guard (opt-in)
# --------------------------------------------------------------------------- #

Resolver = Callable[[str, int], Sequence[str]]


def _system_resolver(host: str, port: int) -> list[str]:
    """The default resolver: ``socket.getaddrinfo`` for TCP, the addresses as strings in the
    order the system returned them (IPv4 and IPv6)."""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _checked_address(host: str, answer: object) -> str:
    """*answer* as the canonical text of an address that is safe to connect to, or
    :class:`HttpForbiddenAddress`. Anything that is not exactly a globally routable IP
    address fails closed: a non-string, a string that does not parse (`ipaddress` rejects
    non-ASCII digits, whitespace and over-long text), and an IPv6 address carrying a scope
    id (a public address has none; one would only ever be pasted into the pinned URL)."""
    if isinstance(answer, str):
        text = str.__str__(answer)           # a subclass's own methods are never consulted
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            ip = None
        if ip is not None and getattr(ip, "scope_id", None) is None \
                and not ip_is_forbidden(text):
            return str(ip)
    raise HttpForbiddenAddress(
        f"host {safe_repr(host)} resolves to blocked address {safe_repr(answer)}")


@dataclass(frozen=True)
class AddressGuard:
    """Opt-in guard on *where* an allow-listed EBSI host name points.

    The client's host allow-list matches a name and trusts DNS for it. That was enough for
    three names run by one party; a client whose hosts are operator-run DNS names also needs
    to know the name has not been pointed at a private, loopback or link-local address
    (a rebinding resolver, a lapsed or shared zone, a compromised operator zone). Pass
    ``address_guard=AddressGuard()`` to :class:`EbsiHttpClient` (or :func:`for_ebsi`):
    on every request that misses the cache it resolves the host, **refuses the host if any
    address in the answer is not globally routable** (the rule ``openvc.fetch`` applies to
    did:web, :func:`openvc.fetch.ip_is_forbidden`, in either order and however many
    public addresses sit beside the bad one), and connects to one validated address while
    the TLS server name, the certificate check and ``Host`` stay the host name. The
    validated address is the one connected to, so there is no window between the check and
    the connect. An allow-listed host that is itself an IP literal is classified directly,
    with no DNS.

    **Several addresses.** The addresses are used in the order the resolver gave them, one
    per attempt, so a retry (bounded by :class:`RetryPolicy`) reaches the next address
    instead of the one that just failed: a host with four addresses of which two do not
    answer, or an AAAA record with no local IPv6 route, is slow, not down.

    **No keep-alive.** A pinned request is sent with ``Connection: close``. httpx pools by
    the address in the URL, not by the name the certificate was checked for, so a reused
    connection would answer for a second name that resolves to the same address with no
    certificate check for that name. A fresh connection per request is verified against the
    name it serves.

    **What it does not do.** It does not stop an attacker who also holds a valid
    certificate for a public address, a dishonest listed node, or anything about registry
    content; it is not certificate pinning, DNSSEC or DoH. It needs the local resolver, so
    a client with a guard refuses to be built behind an environment proxy
    (:class:`HttpAddressGuardUnavailable`). Addresses are classified by the standard
    library's :mod:`ipaddress` (see the threat model, R5): NAT64, 6to4, Teredo and the
    IPv4-compatible forms are refused as whole prefixes, whatever IPv4 they embed. The
    classifier is fixed, with no exemptions; an operator who must reach an internal mirror
    builds a second client without the guard.

    ``resolver`` is ``(host, port) -> addresses as strings`` and exists so a test or a
    caller with its own resolver can supply the answers; it cannot change what is allowed.
    """

    resolver: Resolver = _system_resolver

    def addresses(self, host: str, port: int) -> list[str]:
        """The validated addresses for *host*, in resolver order, without duplicates.

        Raises :class:`HttpForbiddenAddress` if any address is not globally routable (or is
        not an address at all), and :class:`HttpAddressResolutionFailed` if the resolver
        failed or answered with nothing. Nothing else escapes."""
        if _is_ip_literal(host):
            answers: list[object] = [host]
        else:
            try:
                answers = list(self.resolver(host, port))
            except (OSError, ValueError, TypeError) as exc:      # socket.gaierror is an OSError
                raise HttpAddressResolutionFailed(
                    f"cannot resolve {safe_repr(host)}: {type(exc).__name__}") from exc
            if not answers:
                raise HttpAddressResolutionFailed(f"{safe_repr(host)} did not resolve")
        return list(dict.fromkeys(_checked_address(host, answer) for answer in answers))


def _refuse_environment_proxy() -> None:
    """Refuse to build a guarded client where httpx would use an environment proxy. A proxy
    resolves the name and opens the connection itself, so the guard could not validate the
    address that is actually used; and the pinned request names an IP literal, which a proxy
    tunnel checks the certificate against (a mismatch, after the proxy has been told the
    address). ``NO_PROXY`` cannot make it work: httpx matches it against the host of the
    request URL, which is the pinned literal, so a request for a host that ``NO_PROXY``
    names is still sent to the proxy (measured). ``urllib.request.getproxies`` is what
    httpx reads: the ``*_PROXY`` variables, and on macOS and Windows the system settings."""
    proxies = urllib.request.getproxies()
    if proxies.get("https") or proxies.get("all"):
        raise HttpAddressGuardUnavailable(
            "address_guard cannot be used behind an environment proxy (HTTPS_PROXY / "
            "ALL_PROXY, or the system proxy settings on macOS and Windows; NO_PROXY does "
            "not help, because the pinned request names an address, not the host): the "
            "proxy resolves and connects on its own, so the guard could not validate the "
            "address that is used. Unset the proxy for this process, or build the client "
            "without address_guard")


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

def _parse_retry_after(value: str | None) -> float | None:
    """`Retry-After` as seconds, supporting both the delta-seconds and the HTTP-date forms
    (RFC 9110 §10.2.3). Returns None when absent or unparseable (caller keeps its backoff)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


class EbsiHttpClient:
    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        timeout_s: float = 10.0,
        cache: TtlCache | None = None,
        cache_ttl_s: float = 300.0,
        retry: RetryPolicy | None = None,
        verify_tls: bool = True,
        user_agent: str = f"openvc-core/{__version__}",
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        address_guard: AddressGuard | None = None,
    ) -> None:
        self._allowed = {h.lower() for h in allowed_hosts}
        self._timeout_s = timeout_s
        self._max_bytes = max_response_bytes
        # Opt-in (see AddressGuard). Refused before the pooled client is built, so a
        # refusal leaves nothing to close.
        if address_guard is not None:
            _refuse_environment_proxy()
        self._address_guard = address_guard
        # ADR-0001 D2: EBSI sends no Cache-Control/ETag, so freshness is OUR call.
        # With no revalidation path and DID docs that change on key rotation, keep
        # the TTL short (minutes) and configurable per deployment.
        self._cache = cache if cache is not None else TtlCache(ttl_s=cache_ttl_s)
        self._retry = retry or RetryPolicy()
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_s),
            verify=verify_tls,
            follow_redirects=False,           # avoid redirect-based SSRF
            # The DID Registry content-negotiates: it serves application/did+ld+json
            # and returns 406 to a bare "application/json". Accept both (plus a
            # low-priority wildcard) — every body is parsed as JSON regardless.
            headers={
                "User-Agent": user_agent,
                "Accept": "application/json, application/did+ld+json, */*;q=0.1",
            },
        )

    # -- the Fetch capability --------------------------------------------- #

    def get_json(self, url: str) -> dict[str, Any]:
        self._guard_host(url)

        cached = self._cache.get(url)
        if cached is not None:
            return cached

        last_exc: Exception | None = None
        tried: list[str] = []          # validated addresses already used by this call
        for attempt in range(self._retry.attempts):
            body: bytes | None = None
            try:
                # Stream so the body is read against a size cap AND a total wall-clock
                # deadline (not just the per-socket timeout) — a compromised/flaky allow-listed
                # host cannot exhaust memory with a huge body nor pin the client with a slow drip.
                with self._open_stream(url, tried) as resp:
                    status = resp.status_code
                    if status == 200:
                        body = self._read_capped(resp, url)
                    else:
                        resp.read()                  # drain the small error body, reuse the conn
            except httpx.InvalidURL as exc:          # not a TransportError: never retried
                # Backstop for any other urlparse/httpx disagreement (#246).
                raise HttpForbiddenHost("URL rejected by the HTTP client", url=url) from exc
            except httpx.DecodingError as exc:       # not a TransportError: never retried
                # A corrupt gzip/deflate body, on the capped read or the error drain (#248).
                raise MalformedRegistryResponse(
                    f"registry returned a body that does not decode: {url}") from exc
            except httpx.TransportError as exc:      # network error / timeout
                last_exc = exc
                self._sleep_before_retry(attempt)
                continue
            except HttpAddressResolutionFailed as exc:   # the address guard found nothing usable
                # (HttpForbiddenAddress is deliberately not caught: it is never retried)
                last_exc = exc
                self._sleep_before_retry(attempt)
                continue

            if status == 200:
                try:
                    data = _json.loads(body or b"")
                except (ValueError, RecursionError) as exc:   # non-JSON or hostile-depth body
                    raise MalformedRegistryResponse(
                        f"registry returned a 200 with a non-JSON body: {url}") from exc
                if not isinstance(data, dict):           # null / array / string / number
                    raise MalformedRegistryResponse(
                        f"registry returned a 200 that is not a JSON object: {url}")
                self._cache.set(url, data)           # only cache successes
                return data
            if status == 404:
                raise HttpNotFound("not found", status=404, url=url)
            if status in self._retry.retry_statuses:
                self._sleep_before_retry(attempt, resp)
                last_exc = HttpError("transient", status=status, url=url)
                continue
            raise HttpError(f"unexpected status {status}", status=status, url=url)

        raise HttpTransientExhausted(
            f"gave up after {self._retry.attempts} attempts: {last_exc}", url=url
        )

    def _read_capped(self, resp: httpx.Response, url: str) -> bytes:
        """Read the streamed body against the size cap and a total wall-clock deadline."""
        deadline = time.monotonic() + self._timeout_s
        body = bytearray()
        for chunk in resp.iter_bytes():
            if time.monotonic() > deadline:
                raise HttpError(f"read exceeded {self._timeout_s:g}s deadline", url=url)
            body += chunk
            if len(body) > self._max_bytes:
                raise HttpError(
                    f"response exceeds {self._max_bytes} bytes", status=200, url=url)
        return bytes(body)

    def _open_stream(self, url: str, tried: list[str]) -> AbstractContextManager[httpx.Response]:
        """Open the GET for one attempt. Without an address guard that is exactly
        ``client.stream("GET", url)``. With one, the host (already checked against the
        allow-list by `_guard_host`) is resolved and validated now, one validated address is
        picked (the first one this call has not used yet, so a retry rotates), and the
        request goes to that address with the host NAME kept for the TLS server name (and so
        the certificate check) and for ``Host``. The URL is rebuilt from its parts rather than
        edited: the connect target is the validated literal and nothing in the original
        authority (userinfo included) can change it."""
        guard = self._address_guard
        if guard is None:
            return self._client.stream("GET", url)
        try:
            parsed = urlparse(url)
            host, port = parsed.hostname, parsed.port
        except ValueError as exc:
            raise HttpForbiddenHost("URL rejected: does not parse", url=url) from exc
        authority_start = url.find("//") + 2
        if (host is None or authority_start < 2
                or url[authority_start:authority_start + len(parsed.netloc)] != parsed.netloc):
            raise HttpForbiddenHost("URL rejected: no readable authority", url=url)
        if port is None:
            port = 443
        try:
            addresses = guard.addresses(host, port)
        except HttpError as exc:
            exc.url = url
            raise
        fresh = [a for a in addresses if a not in tried]
        if not fresh:                           # every validated address has had its turn
            tried.clear()
            fresh = addresses
        address = fresh[0]
        tried.append(address)
        literal = f"[{address}]" if ":" in address else address
        name = f"[{host}]" if ":" in host else host            # an allow-listed IP literal
        return self._client.stream(
            "GET",
            f"https://{literal}:{port}{url[authority_start + len(parsed.netloc):]}",
            headers={"Host": name if port == 443 else f"{name}:{port}", "Connection": "close"},
            extensions={"sni_hostname": host},
        )

    # -- internals --------------------------------------------------------- #

    def _guard_host(self, url: str) -> None:
        # A URL is checked by `urlparse` here and fetched by httpx, which reads some URLs
        # differently: urlsplit drops a tab or newline and ignores other control
        # characters that httpx rejects. Refuse anything that is not visible ASCII
        # before `urlparse` reads it (on CPython <= 3.12 it NFKC-normalizes a non-ASCII
        # netloc in quadratic time), and a URL `urlparse` cannot read, port included —
        # typed, before any I/O (#246).
        if not (url.isascii() and url.isprintable()) or " " in url:
            raise HttpForbiddenHost("URL rejected: not visible ASCII", url=url)
        try:
            parsed = urlparse(url)
            parsed.port                       # raises on an out-of-range or non-numeric port
        except ValueError as exc:
            raise HttpForbiddenHost("URL rejected: does not parse", url=url) from exc
        if parsed.scheme != "https":
            raise HttpForbiddenHost(f"non-https URL rejected: {url}", url=url)
        if parsed.hostname is None or parsed.hostname.lower() not in self._allowed:
            raise HttpForbiddenHost(f"host not in allow-list: {parsed.hostname}", url=url)

    def _sleep_before_retry(self, attempt: int, resp: httpx.Response | None = None) -> None:
        if attempt >= self._retry.attempts - 1:
            return
        delay = self._retry.backoff(attempt)
        if resp is not None:
            secs = _parse_retry_after(resp.headers.get("Retry-After"))
            if secs is not None:
                delay = max(delay, secs)
        time.sleep(delay)

    # -- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "EbsiHttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #

def for_ebsi(
    environment: str = "pilot",
    *,
    extra_hosts: set[str] | None = None,
    **kwargs: Any,
) -> EbsiHttpClient:
    """Build a client whose SSRF allow-list is seeded from the EBSI environment.

    ``extra_hosts`` lets you permit additional issuer status-list hosts if you
    also follow StatusList proxies through this client.

    Every other keyword argument is passed to :class:`EbsiHttpClient`. In particular
    ``address_guard=AddressGuard()`` turns on the opt-in resolved-address guard: the host
    allow-list still matches names only, and the guard additionally refuses a host that
    resolves to an address that is not globally routable and connects to the validated
    address. It is **off** by default (a deployment with split-horizon DNS or a private
    mirror of a node would break), it is refused behind an environment proxy, and it does
    not stop an attacker who holds a certificate for a public address; see
    :class:`AddressGuard`.
    """
    if environment not in EBSI_HOSTS:
        raise ValueError(f"unknown EBSI environment: {environment!r}")
    hosts = {EBSI_HOSTS[environment]} | (extra_hosts or set())
    return EbsiHttpClient(allowed_hosts=hosts, **kwargs)
