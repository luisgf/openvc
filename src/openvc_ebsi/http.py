"""
openvc_ebsi.http — the read-only HTTP client that satisfies the `Fetch` capability.

It is deliberately small but covers the production concerns a verifier needs:

  * timeouts        : never block forever (connect + read).
  * retries         : bounded, only on idempotent GET and transient failures
                      (network errors, 429, 5xx), with exponential backoff + jitter
                      and Retry-After support — no thundering herd. No single sleep is
                      longer than ``RetryPolicy.retry_after_max_s`` (default: the backoff
                      ceiling), whatever a server asks for, and a ``Retry-After`` that is not
                      a short run of ASCII digits or an HTTP-date is ignored.
  * body reads      : ``get_json`` and ``get_bytes`` read a 200 body through ONE bounded
                      reader. The wire size and the DECODED size are both held to the cap
                      before a chunk is appended; a single ``gzip`` or ``deflate`` coding is
                      decoded with zlib asked for at most the room left, so a decompression
                      bomb is refused inside the stdlib and never allocated.
  * caching         : TTL + bounded size. EBSI registry reads (DID docs, TIR
                      entries, schemas) change rarely and are hit on every verify.
  * SSRF guard      : the TIR v5 flow follows `href` values taken from registry
                      responses; those hrefs are only fetched if their ORIGIN is on
                      the allow-list: https, a host derived from the configured EBSI
                      base, and port 443 (an absent port is 443); a URL with userinfo
                      is refused too (#318). A compromised/malicious registry
                      response cannot pivot the client to an internal address, nor to
                      another port of an allow-listed host.
  * connection reuse: a single pooled httpx.Client; redirects disabled.
                      No cookie jar: a `Set-Cookie` is dropped, nothing is sent back.
  * bytes path     : ``get_bytes`` returns a body verbatim (no JSON, no cache, no text
                      decoding), with a hard cap on the wire size and on the DECODED size.
                      ``get_tnl_files`` uses it to fetch the Trusted Nodes List from a
                      client that allow-lists ``tnl.ebsi.eu`` alone (ADR-0009 D4).
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
import re
import socket
import sys
import time
import urllib.request
import warnings
import zlib
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import Cookie, CookieJar, CookiePolicy
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request

import httpx

from openvc import _json
from openvc import __version__
from openvc.cache import TtlCache
from openvc.fetch import ip_is_forbidden
from openvc.proof._verify_common import safe_repr

from ._url import HTTPS_PORT, UrlDoesNotParse, UrlNotVisibleAscii, carries_userinfo, read_origin
from .environments import fixed_hosts
from .errors import EbsiError, MalformedRegistryResponse, UnknownEbsiEnvironment

# EBSI registry reads (DID docs, TIR entries, schemas) are small; bound the memory an
# attacker-influenced (or compromised) allow-listed host can force. The general fetch caps
# did:web at 1 MiB; TIR walks can be a little larger, so allow more headroom here.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# An error answer is read for its RFC 9457 Problem Details ``type`` and nothing else. Problem
# documents are a few hundred bytes (the recorded ones are 150 to 190); a node's firewall page
# was measured at 35 KB. Past this the read stops and the connection is dropped, so a
# compromised or flaky allow-listed host cannot make an error answer cost more than the
# success answer it replaces (the 200 branch has MAX_RESPONSE_BYTES and a deadline).
MAX_ERROR_BODY_BYTES = 16 * 1024
_PROBLEM_MEDIA_TYPE = "application/problem+json"
# ``type`` is an opaque URI reference: kept only as 1 to 256 characters of visible ASCII
# (0x21 to 0x7e), so what ``HttpError.problem_type`` holds is short, printable and safe to log.
_PROBLEM_TYPE = re.compile(r"[\x21-\x7e]{1,256}")

# Host per EBSI environment name (used to seed the SSRF allow-list): the fixed-host projection
# of the table in `environments.py`, which says what each name means.
EBSI_HOSTS: dict[str, str] = fixed_hosts()
EBSI_BASE: dict[str, str] = {env: f"https://{host}" for env, host in EBSI_HOSTS.items()}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class HttpError(EbsiError):
    """An HTTP failure. ``problem_type`` is the RFC 9457 Problem Details ``type`` of an error
    answer, or ``None``: an opaque string (``"about:blank"``, a ``urn:ebsi:problems:...``
    slug, anything the node wrote) that this module never interprets, kept only when the answer
    was ``application/problem+json``, parsed within :data:`MAX_ERROR_BODY_BYTES` and a
    visible-ASCII string of at most 256 characters. ``title`` and ``detail`` are not read."""

    def __init__(self, message: str, *, status: int | None = None, url: str | None = None,
                 problem_type: str | None = None):
        super().__init__(message)
        self.status = status
        self.url = url
        self.problem_type = problem_type


class HttpNotFound(HttpError): ...          # 404 — maps to DidNotFound upstream
class HttpForbiddenHost(HttpError): ...     # SSRF guard tripped
class HttpTransientExhausted(HttpError): ...  # retries used up
class HttpUnexpectedEncoding(HttpError): ...  # Content-Encoding the bytes path does not decode


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
# Result of the bytes path
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class BytesResponse:
    """What :meth:`EbsiHttpClient.get_bytes` returns. **The body is unauthenticated: a
    signature over it is the only thing that makes it trustworthy, and this class checks
    none.**

    ``body`` is ``None`` exactly when the server answered 304 Not Modified to the
    ``If-None-Match`` that was sent (it means "use the bytes you stored, and verify them
    again"). ``etag`` is the opaque validator: the one the server sent with a 200 (``None``
    when it sent none, or one that is not a plausible header value), or, on a 304, the one
    that was sent."""

    body: bytes | None
    etag: str | None

    @property
    def not_modified(self) -> bool:
        return self.body is None


# --------------------------------------------------------------------------- #
# Retry policy
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RetryPolicy:
    """How a read is retried.

    ``retry_after_max_s`` is the longest ONE sleep between attempts may be, whatever the
    server asks for with ``Retry-After``: every sleep is
    ``min(max(backoff, Retry-After), ceiling)``, and a caller's ``deadline_s`` can only shorten
    it further. An allow-listed host (a listed node, say) therefore cannot hold a walk for the
    time it asks. ``None``, the default, means ``backoff_max_s``: the ceiling is looked up
    when a sleep is taken, so a policy derived with ``dataclasses.replace(policy,
    backoff_max_s=X)`` follows ``X`` and the attribute keeps reading ``None``. By default a
    server therefore cannot make the client wait longer than its own backoff would. The bound
    applies to every sleep, the backoff included, so a ceiling below ``backoff_max_s`` lowers
    that ceiling too. An explicit value must be a number from 0 to one day; anything else is a
    ``ValueError`` when the policy is built (construction-time misuse, not wire input).
    ``backoff_max_s`` is not validated, as it never was, and a value that follows it is not
    either: whatever the policy, no sleep is longer than one day, and none is negative (a
    negative ``backoff_max_s`` is a ceiling that sleeps 0 s)."""

    attempts: int = 3
    backoff_base_s: float = 0.25
    backoff_max_s: float = 5.0
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})
    retry_after_max_s: float | None = None

    def __post_init__(self) -> None:
        cap = self.retry_after_max_s
        if cap is None:
            return                            # `backoff_max_s`, looked up when a sleep is taken
        if (not isinstance(cap, (int, float)) or isinstance(cap, bool)
                or not 0 <= cap <= _MAX_DEADLINE_S):
            # Compared, never converted: `0 <= nan` is False, and `10**400` compares without
            # becoming a float (`float(10**400)` raises OverflowError).
            raise ValueError(
                f"retry_after_max_s must be None or a number of seconds from 0 to "
                f"{_MAX_DEADLINE_S}, not {safe_repr(cap)}")

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
    per attempt, so a retry reaches the next address instead of the one that just failed.
    The bound is :class:`RetryPolicy`'s: the address at position *k* of the answer is
    reached only if the policy allows *k* attempts, so with the default policy (3) only
    the first three addresses are ever tried. A host with four addresses of which two do
    not answer is slow, not down; a host whose first three addresses do not answer (an AAAA
    record with three addresses, on a client with no IPv6 route) is down for this client
    even though the fourth would answer. A name-based connect tries every address of the
    answer within one attempt (``socket.create_connection``); this does not. A deployment
    that expects dead addresses sets ``RetryPolicy(attempts=...)`` to at least the number
    of addresses it needs to be able to reach. Any transport error (connect, TLS
    handshake, read or write timeout, protocol error), a 429 or a 5xx moves to the next
    address; a 404 or another 4xx does not.

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
        failed or answered with nothing. That holds for the default resolver; the
        exceptions of an injected ``resolver`` other than ``OSError``, ``ValueError`` and
        ``TypeError`` propagate unchanged (a caller's bug is not hidden behind the retry
        loop)."""
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

# The delta-seconds form of `Retry-After` is a short run of ASCII digits. Nine digits reach 31
# years, far past any wait a client honours (every sleep is cut to the policy's ceiling,
# `retry_after_max_s` or `backoff_max_s` when that is None, anyway), and keep `float()` of a
# hostile value finite. A longer run is not read as a number.
_RETRY_AFTER_MAX_DIGITS = 9
# An HTTP-date is 29 characters (IMF-fixdate) and at most 33 in the obsolete forms (RFC 850 with
# the longest day name). A longer value is not one, and is not handed to the stdlib's date parser.
_RETRY_AFTER_MAX_DATE_CHARS = 64


def _parse_retry_after(value: str | None) -> float | None:
    """`Retry-After` as seconds, supporting both the delta-seconds and the HTTP-date forms
    (RFC 9110 §10.2.3). Returns None when absent or unparseable (caller keeps its backoff).

    The value comes from an allow-listed but not trusted host, so this never raises and the
    result is either ``None`` or a finite number of seconds, never negative. Delta-seconds is
    a run of ASCII digits only (``str.isdigit`` alone also accepts a superscript, which
    ``float`` rejects with a bare ``ValueError``, and other scripts' decimal digits, which
    ``float`` reads as a number of seconds: ``"١٢٣"`` was 123 s), at most
    :data:`_RETRY_AFTER_MAX_DIGITS` long; ``-1``, ``nan``, ``1e400``, a sign or a blank are
    not it. Spaces and tabs around the value are optional whitespace and are dropped. Anything
    else is read as an HTTP-date, which may be far in the future: the caller bounds the sleep,
    not this function."""
    if not isinstance(value, str):
        return None
    text = value.strip(" \t")
    if not text or not text.isascii():
        return None
    if text.isdigit():                        # ASCII digits only: `isascii` held above
        return float(text) if len(text) <= _RETRY_AFTER_MAX_DIGITS else None
    if len(text) > _RETRY_AFTER_MAX_DATE_CHARS:
        return None
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _problem_type(content_type: str | None, body: bytes) -> str | None:
    """The ``type`` member of an RFC 9457 Problem Details body, or ``None``. Pure, and it
    never raises.

    Only ``application/problem+json`` counts (the media type is compared without parameters
    and without case): a node's firewall answers a 403 with a 35 KB ``text/html`` page, and a
    JSON-looking body under any other type is not Problem Details. The body goes through the
    bounded loader and must be a JSON object; ``type`` must be a string of 1 to 256 visible
    ASCII characters. The value is opaque, and an absent ``type`` is ``None`` (RFC 9457 reads
    it as ``about:blank``; this reports what the node wrote)."""
    if not content_type or content_type.split(";", 1)[0].strip().lower() != _PROBLEM_MEDIA_TYPE:
        return None
    try:
        data = _json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("type")
    if isinstance(value, str) and _PROBLEM_TYPE.fullmatch(value):
        return value
    return None


class _NoCookiePolicy(CookiePolicy):
    """Refuse every cookie, in both directions.

    The client is a stateless GET reader whose only state is the TTL cache (ADR-0001 D2):
    a `Set-Cookie` (the load-balancer affinity cookie of a node, say) must neither be kept
    nor sent back, or a retry stays pinned to the backend it is leaving and the jar becomes
    hidden state that lives as long as the client (#317, ADR-0009).

    ``set_ok`` is the load-bearing method. httpx copies the client's jar into a fresh
    default-policy one when it builds a request, so a cookie that was stored would be sent
    whatever ``return_ok`` says; the other three are defence in depth, not the guard.
    """

    netscape = True       # the jar reads these three attributes
    rfc2965 = False
    hide_cookie2 = False

    def set_ok(self, cookie: Cookie, request: Request) -> bool:
        return False

    def return_ok(self, cookie: Cookie, request: Request) -> bool:
        return False

    def domain_return_ok(self, domain: str, request: Request) -> bool:
        return False

    def path_return_ok(self, path: str, request: Request) -> bool:
        return False


class EbsiHttpClient:
    """A read-only, SSRF-guarded GET client for the EBSI registries.

    ``allowed_hosts`` is a set of host NAMES, matched case-insensitively. A URL is fetched
    only if it is ``https`` on one of those hosts at port 443 (an absent or empty port is
    443; ``:0443`` reads as 443 too) and carries no userinfo: any other port of an
    allow-listed host is :class:`HttpForbiddenHost`, before any request (#318). Port 443 is
    implied; an entry that spells a scheme or a port never matches. Redirects are off."""

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
                # Ask only for the codings the bounded reader decodes (httpx would add `br`
                # and `zstd` when their packages are installed, and a body in either is
                # refused). `get_bytes` overrides this per request with `identity`.
                "Accept-Encoding": "gzip, deflate",
            },
            # No cookie jar (#317): a bare CookieJar is the only form httpx keeps as given
            # (an httpx.Cookies, a dict or a list is rebuilt with the default policy).
            cookies=CookieJar(policy=_NoCookiePolicy()),
        )

    # -- the Fetch capability --------------------------------------------- #

    def get_json(self, url: str) -> dict[str, Any]:
        self._guard_host(url)

        cached = self._cache.get(url)
        if cached is not None:
            return cached

        # Stream so the body is read against a size cap AND a total wall-clock
        # deadline (not just the per-socket timeout) — a compromised/flaky allow-listed
        # host cannot exhaust memory with a huge body nor pin the client with a slow drip.
        _, body, _ = self._request(
            url, read_body=lambda resp: self._read_capped(resp, url), drain_error_body=True)
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

    def get_bytes(
        self,
        url: str,
        *,
        max_bytes: int | None = None,
        etag: str | None = None,
        deadline_s: float | None = None,
    ) -> BytesResponse:
        """GET *url* and return the body exactly as the server sent it.

        **Returns unauthenticated bytes; verify them before use.** Nothing here parses,
        decodes to text, strips or caches the body: a signature over it (the Trusted
        Nodes List's, for example) covers exactly these bytes.

        Same host guard (before any I/O), redirects off, retry on 429 / 5xx and
        transport errors, and per-body read deadline as :meth:`get_json`. The body is
        asked for with ``Accept-Encoding: identity``; a single ``gzip`` or ``deflate``
        coding is decoded anyway if the server applies one, under the same cap on the
        DECODED size, and any other coding is :class:`HttpUnexpectedEncoding`.
        ``max_bytes`` can only lower the client's ``max_response_bytes``.

        ``deadline_s`` (a positive number of seconds, at most one day) is a budget over the
        attempts, the sleeps between them (a ``Retry-After`` or backoff sleep is clamped to
        what remains) and the body read, which checks the clock after every chunk it
        receives. **It is not a ceiling on the wait for one response's headers**: the
        connect, the TLS handshake and each socket read are bounded only by ``timeout_s``
        each, so a server that sends its headers slowly enough to keep every read under
        ``timeout_s`` is not cut off (the stack's header-size limit is the only other
        bound). A response that arrives after the budget is spent is refused as soon as a
        body chunk is read. A caller that needs a hard wall-clock limit has to enforce it
        outside this call.

        ``etag`` (an opaque validator from an earlier response) is sent verbatim as
        ``If-None-Match``; a 304 is then ``BytesResponse(None, etag)``. A 304 that was not
        asked for, any other 3xx, a 204, a 206 and a 403 are :class:`HttpError`, and the
        body of a non-200 response is never read. A 404 is :class:`HttpNotFound`.
        """
        cap = self._max_bytes
        if max_bytes is not None:
            cap = min(_checked_cap(max_bytes), cap)         # can only lower the client's cap
        headers = {"Accept": "*/*", "Accept-Encoding": "identity"}
        sent: str | None = None
        if etag is not None:
            sent = _checked_etag(etag)
            headers["If-None-Match"] = sent
        until = None if deadline_s is None else time.monotonic() + _checked_deadline(deadline_s)

        status, body, reply = self._request(
            url, headers=headers, accept_not_modified=sent is not None, until=until,
            drain_error_body=False,
            read_body=lambda resp: self._read_verbatim(resp, url, cap, until))
        if status == 304:
            return BytesResponse(None, sent)
        return BytesResponse(body, _plausible_etag(reply.get("etag")))

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """The host allow-list this client was built with (lower-cased, read-only)."""
        return frozenset(self._allowed)

    def _request(
        self,
        url: str,
        *,
        read_body: Callable[[httpx.Response], bytes],
        drain_error_body: bool,
        headers: Mapping[str, str] | None = None,
        accept_not_modified: bool = False,
        until: float | None = None,
    ) -> tuple[int, bytes, httpx.Headers]:
        """The one request loop under :meth:`get_json` and :meth:`get_bytes`: host guard,
        stream, the ``InvalidURL`` / ``DecodingError`` / ``TransportError`` mapping (#246,
        #248) and retry on 429 / 5xx with ``Retry-After``, so the two paths cannot drift.

        Returns ``(200, body, headers)``, or ``(304, b"", headers)`` when
        *accept_not_modified*; every other outcome raises. *until* is a ``time.monotonic``
        instant that bounds the attempts and the sleeps between them."""
        self._guard_host(url)

        last_exc: Exception | None = None
        tried: list[str] = []          # validated addresses already used by this call
        for attempt in range(self._retry.attempts):
            if until is not None and until - time.monotonic() <= 0:
                raise HttpError("deadline exceeded", url=url)
            body: bytes = b""
            problem_type: str | None = None
            try:
                # Stream so the body is read against a size cap AND a total wall-clock
                # deadline (not just the per-socket timeout) — a compromised/flaky allow-listed
                # host cannot exhaust memory with a huge body nor pin the client with a slow drip.
                with self._open_stream(url, tried, headers) as resp:
                    status = resp.status_code
                    if status == 200:
                        body = read_body(resp)
                    elif drain_error_body:
                        # bounded; may drop the conn. Never read for get_bytes: the body of a
                        # non-200 answer is not read there at all.
                        problem_type = self._read_problem_type(resp)
            except httpx.InvalidURL as exc:          # not a TransportError: never retried
                # Backstop for any other urlparse/httpx disagreement (#246).
                raise HttpForbiddenHost("URL rejected by the HTTP client", url=url) from exc
            except httpx.DecodingError as exc:       # not a TransportError: never retried
                # A corrupt gzip/deflate body, on the capped read or the error drain (#248).
                raise MalformedRegistryResponse(
                    f"registry returned a body that does not decode: {url}") from exc
            except httpx.TransportError as exc:      # network error / timeout
                last_exc = exc
                self._sleep_before_retry(attempt, until=until)
                continue
            except HttpAddressResolutionFailed as exc:   # the address guard found nothing usable
                # (HttpForbiddenAddress is deliberately not caught: it is never retried)
                last_exc = exc
                self._sleep_before_retry(attempt, until=until)
                continue

            if status == 200:
                return status, body, resp.headers
            if status == 304 and accept_not_modified:
                return status, b"", resp.headers
            if status == 404:
                raise HttpNotFound("not found", status=404, url=url, problem_type=problem_type)
            if status in self._retry.retry_statuses:
                self._sleep_before_retry(attempt, resp, until=until)
                last_exc = HttpError(
                    "transient", status=status, url=url, problem_type=problem_type)
                continue
            raise HttpError(f"unexpected status {status}", status=status, url=url,
                            problem_type=problem_type)

        raise HttpTransientExhausted(
            f"gave up after {self._retry.attempts} attempts: {last_exc}", url=url,
            problem_type=last_exc.problem_type if isinstance(last_exc, HttpError) else None,
        )

    def _read_capped(self, resp: httpx.Response, url: str) -> bytes:
        """Read the streamed body of :meth:`get_json` against the client's size cap and a total
        wall-clock deadline: the reader :meth:`get_bytes` uses, at the client's cap and with no
        overall budget. The cap holds on the wire size and on the DECODED size, checked before
        a chunk is appended (``iter_bytes`` would hand over a whole inflated chunk first, so
        one small ``gzip`` chunk could allocate the expansion ratio times itself). Only
        ``identity``, one ``gzip`` or one ``deflate`` coding is read; any other
        ``Content-Encoding`` is :class:`HttpUnexpectedEncoding`."""
        return self._read_verbatim(resp, url, self._max_bytes, None)

    def _open_stream(
        self, url: str, tried: list[str], headers: Mapping[str, str] | None = None
    ) -> AbstractContextManager[httpx.Response]:
        """Open the GET for one attempt. Without an address guard that is exactly
        ``client.stream("GET", url, headers=headers)``. With one, the host (already checked
        against the allow-list by `_guard_host`) is resolved and validated now, one validated
        address is picked (the first one this call has not used yet, so a retry rotates), and the
        request goes to that address with the host NAME kept for the TLS server name (and so
        the certificate check) and for ``Host``. The URL is rebuilt from its parts rather than
        edited: the connect target is the validated literal and nothing in the original
        authority (userinfo included) can change it."""
        guard = self._address_guard
        if guard is None:
            return self._client.stream("GET", url, headers=headers)
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
            # the caller's headers first: the pinned request's own Host / Connection win
            headers={**(headers or {}),
                     "Host": name if port == 443 else f"{name}:{port}", "Connection": "close"},
            extensions={"sni_hostname": host},
        )

    def _read_verbatim(
        self, resp: httpx.Response, url: str, cap: int, until: float | None
    ) -> bytes:
        """Read a 200 body for :meth:`get_bytes` and :meth:`get_json`: the wire bytes, or the
        result of decoding ONE ``gzip`` / ``deflate`` coding, never more than *cap* bytes of
        either.

        A coded body is read with ``iter_raw``, which hands over the wire bytes undecoded, so
        httpx never inflates anything. A body with no coding has nothing to inflate and is
        read with ``iter_bytes`` (``_decoder_for`` returns ``None`` only for no coding or
        ``identity``, and httpx then applies no decoder), as is a body a test double has
        already read into memory, a coded one too (httpx decoded it when it was built). The
        wire total and the decoded total are both checked BEFORE a chunk is appended, and
        ``zlib`` is asked for at most ``room + 1`` bytes, so a decompression bomb is refused
        inside the stdlib, before the allocation, not after it."""
        decoder = _decoder_for(resp.headers.get("content-encoding"), url)
        if decoder is not None and resp.is_stream_consumed:
            # A response a test double built from `content=` is read into memory when it is
            # made, and httpx has already decoded it: `iter_raw` would raise `StreamConsumed`
            # and there is nothing left to inflate. No socket hands one over (a stream is
            # consumed only by reading it), so this is not reachable from the wire; the cap
            # still holds on what is read.
            decoder = None
        declared = _declared_length(resp.headers.get("content-length"))
        if declared is not None and declared > cap:
            raise HttpError(f"response exceeds {cap} bytes", status=200, url=url)

        deadline = time.monotonic() + self._timeout_s
        if until is not None:
            deadline = min(deadline, until)
        wire = 0
        body = bytearray()
        for chunk in (resp.iter_bytes() if decoder is None else resp.iter_raw()):
            if time.monotonic() > deadline:
                raise HttpError("read exceeded its deadline", url=url)
            wire += len(chunk)
            if wire > cap:
                raise HttpError(f"response exceeds {cap} bytes", status=200, url=url)
            if decoder is None:
                body += chunk
                continue
            if decoder.eof:
                raise MalformedRegistryResponse(
                    f"response has bytes after the end of its compressed stream: {safe_repr(url)}")
            room = cap - len(body)
            try:
                # max_length is positive (room + 1 >= 1; 0 would mean unlimited) and at most
                # sys.maxsize, the largest C ssize_t zlib takes (a client cap past it would
                # raise OverflowError otherwise). A call that returns at most `room` bytes
                # consumed its whole input (or hit the end of the stream), so nothing is
                # pending in `unconsumed_tail`; one that returns room + 1 is over the cap,
                # which is the refusal below.
                piece = decoder.decompress(chunk, min(room + 1, sys.maxsize))
            except zlib.error as exc:
                raise MalformedRegistryResponse(
                    f"response body does not decode: {safe_repr(url)}") from exc
            if len(piece) > room:
                raise HttpError(
                    f"response exceeds {cap} bytes once decoded", status=200, url=url)
            body += piece
            if decoder.unused_data:
                raise MalformedRegistryResponse(
                    f"response has bytes after the end of its compressed stream: {safe_repr(url)}")
        if decoder is not None and not decoder.eof:
            raise MalformedRegistryResponse(
                f"response body is a truncated compressed stream: {safe_repr(url)}")
        return bytes(body)

    def _read_problem_type(self, resp: httpx.Response) -> str | None:
        """Read an error answer's body, bounded, and return its Problem Details ``type``.

        Reads at most :data:`MAX_ERROR_BODY_BYTES` within the client's wall-clock deadline.
        Past either, the rest is not read and the response is closed, which drops the
        connection instead of draining it: the status error is raised as before, with no
        ``type``. A body that is small enough is read to the end, so the connection can be
        reused. Never raises for a body it cannot use; a body that does not decode
        (``httpx.DecodingError``) and a transport failure propagate to ``get_json`` exactly
        as they did when this was ``resp.read()`` (#248)."""
        deadline = time.monotonic() + self._timeout_s
        body = bytearray()
        for chunk in resp.iter_bytes():
            body += chunk
            if len(body) > MAX_ERROR_BODY_BYTES or time.monotonic() > deadline:
                resp.close()
                return None
        return _problem_type(resp.headers.get("content-type"), bytes(body))

    # -- internals --------------------------------------------------------- #

    def _guard_host(self, url: str) -> None:
        # The guard admits an ORIGIN: https, a listed host, port 443 (#318). A URL is
        # checked here by `urlparse` (through `read_origin`, the reader the TIR adapter's
        # origin pin uses too) and fetched by httpx, which reads some URLs differently:
        # urlsplit drops a tab or newline and ignores other control characters that httpx
        # rejects. Refuse anything that is not visible ASCII before `urlparse` reads it (on
        # CPython <= 3.12 it NFKC-normalizes a non-ASCII netloc in quadratic time), and a
        # URL `urlparse` cannot read, port included — typed, before any I/O (#246).
        try:
            scheme, host, port = read_origin(url)
        except UrlNotVisibleAscii:
            raise HttpForbiddenHost("URL rejected: not visible ASCII", url=url) from None
        except UrlDoesNotParse as exc:
            raise HttpForbiddenHost("URL rejected: does not parse", url=url) from exc.__cause__
        if scheme != "https":
            raise HttpForbiddenHost(f"non-https URL rejected: {url}", url=url)
        if not host or host not in self._allowed:
            raise HttpForbiddenHost(f"host not in allow-list: {host or None}", url=url)
        # `read_origin` fills in 443 for an absent https port and only for an absent one,
        # so `:0` stays 0 here and is refused with every other port.
        if port != HTTPS_PORT:
            raise HttpForbiddenHost(f"port {port} not allowed: https port 443 only", url=url)
        # Userinfo is outside an origin and the Trusted Nodes List publishes none (ADR-0009).
        # httpx would send it as a Basic `Authorization` header. This refusal names the rule
        # and carries no credentials, in the message or in `.url` (None here); an earlier
        # rule's message and `.url` still hold the URL as given.
        if carries_userinfo(url):
            raise HttpForbiddenHost("URL rejected: carries userinfo", url=None)

    def _sleep_before_retry(
        self, attempt: int, resp: httpx.Response | None = None, *, until: float | None = None
    ) -> None:
        if attempt >= self._retry.attempts - 1:
            return
        delay = self._retry.backoff(attempt)
        if resp is not None:
            secs = _parse_retry_after(resp.headers.get("Retry-After"))
            if secs is not None:
                delay = max(delay, secs)
        # A server decides what it asks for, never how long this client waits: no sleep is
        # longer than the policy's ceiling (`retry_after_max_s`, `backoff_max_s` when that is
        # None), and none is longer than one day, which `time.sleep` always takes (it raises
        # OverflowError from about 9.2e9 s). Nor is one negative, which `time.sleep` refuses
        # with a ValueError: `backoff_max_s` is not validated, so a negative one is a ceiling
        # of every sleep, and it sleeps 0 s.
        ceiling = self._retry.retry_after_max_s
        delay = min(delay, self._retry.backoff_max_s if ceiling is None else ceiling,
                    _MAX_DEADLINE_S)
        if until is not None:                 # never sleep past the caller's budget
            delay = min(delay, max(0.0, until - time.monotonic()))
        time.sleep(max(0.0, delay))

    # -- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "EbsiHttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# Helpers of the bytes path
# --------------------------------------------------------------------------- #

# A validator is opaque, so it is only checked as a header VALUE: visible ASCII, bounded, and
# not the `*` wildcard. `fullmatch`: `$` would accept a trailing newline.
_ETAG_VALUE = re.compile(r"[\x21-\x7e]{1,256}")


def _plausible_etag(value: str | None) -> str | None:
    """A received ``ETag`` as-is when it is a plausible header value, else ``None``. The
    signature authenticates the body; the validator only saves bandwidth, so a strange one
    is dropped rather than failing the fetch."""
    if value is None or value == "*" or _ETAG_VALUE.fullmatch(value) is None:
        return None
    return value


def _checked_etag(value: object) -> str:
    """A caller-supplied validator, or :class:`HttpError` before any I/O. Without this a
    non-ASCII value would escape from httpx's header encoding as a bare
    ``UnicodeEncodeError``, the class #246 closed."""
    if not isinstance(value, str):
        raise HttpError(f"etag must be a str, not {safe_repr(value)}")
    text = str.__str__(value)             # the characters checked are the characters sent
    if text == "*" or _ETAG_VALUE.fullmatch(text) is None:
        raise HttpError(f"etag is not a usable validator: {safe_repr(text)}")
    return text


def _checked_cap(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise HttpError(f"max_bytes must be a non-negative int, not {safe_repr(value)}")
    return int(value)


# The longest budget `deadline_s` takes: one day, like `MAX_LEEWAY_S`. With it a sleep clamped to
# the remaining budget is always one `time.sleep` accepts (it raises OverflowError past about
# 9.2e9 seconds, which a `Retry-After` of any length would otherwise reach through `min(...)`).
_MAX_DEADLINE_S = 24 * 3600


def _checked_deadline(value: object) -> float:
    # Compared, never converted first: `float(10**400)` and `math.isfinite(10**400)` raise
    # OverflowError. NaN fails `0 < value` and infinity fails `value <= _MAX_DEADLINE_S`.
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not 0 < value <= _MAX_DEADLINE_S):
        raise HttpError(
            f"deadline_s must be a number of seconds above 0 and at most {_MAX_DEADLINE_S}, "
            f"not {safe_repr(value)}")
    return float(value)


def _declared_length(value: str | None) -> int | None:
    """``Content-Length`` as an int, or ``None`` when absent or not a plain non-negative
    decimal (the streamed cap still applies then). A value too long to be a size is
    reported as larger than any cap."""
    if value is None:
        return None
    text = value.strip()
    if not (text.isascii() and text.isdigit()):
        return None
    return int(text) if len(text) <= 19 else 2**64


def _decoder_for(content_encoding: str | None, url: str) -> Any:
    """The ``zlib`` decompressor for the response's ``Content-Encoding``: ``None`` for none
    or ``identity``, one for a single ``gzip`` or ``deflate`` (the zlib wrapper; a raw
    deflate body is not guessed at and fails as malformed), and :class:`HttpUnexpectedEncoding`
    for anything else, a list such as ``gzip, gzip`` included."""
    coding = (content_encoding or "").strip().lower()
    if coding in ("", "identity"):
        return None
    if coding == "gzip":
        return zlib.decompressobj(31)
    if coding == "deflate":
        return zlib.decompressobj(15)
    raise HttpUnexpectedEncoding(
        f"unsupported Content-Encoding {safe_repr(content_encoding)}", status=200, url=url)


# --------------------------------------------------------------------------- #
# The Trusted Nodes List host (ADR-0009 D4)
# --------------------------------------------------------------------------- #

TNL_HOST = "tnl.ebsi.eu"
# The four documents the verifier of the Trusted Nodes List needs, in the order they are
# fetched. The key-list key (`keylist-key.asc`) is NOT here and is never fetched at run time:
# the publisher's rule is "never download the pinned key at runtime", and doing so would turn
# the pin into trust-on-first-use of DNS and TLS.
TNL_FILES = ("trusted-keys.json", "trusted-keys.json.sig", "tnl.json", "tnl.json.sig")
# Proposed caps, not facts about the publisher: the JSON files are 7068 and 1811 bytes today
# and the signature files a few hundred.
TNL_MAX_BYTES: Mapping[str, int] = MappingProxyType({
    "trusted-keys.json": 64 * 1024, "trusted-keys.json.sig": 4 * 1024,
    "tnl.json": 64 * 1024, "tnl.json.sig": 4 * 1024})


def for_tnl(**kwargs: Any) -> EbsiHttpClient:
    """A client for the Trusted Nodes List host and for nothing else.

    Its allow-list is ``{TNL_HOST}`` alone, never the node set a list names, so a poisoned
    list cannot widen where the list itself is fetched; ``allowed_hosts`` cannot be passed.
    It keeps no cookies, and its response cap defaults to 64 KiB.
    """
    if "allowed_hosts" in kwargs:
        raise TypeError("for_tnl() allow-lists tnl.ebsi.eu alone; allowed_hosts cannot be passed")
    kwargs.setdefault("max_response_bytes", 64 * 1024)
    return EbsiHttpClient(allowed_hosts={TNL_HOST}, **kwargs)


def get_tnl_files(
    client: EbsiHttpClient | None = None,
    *,
    etags: Mapping[str, str] | None = None,
    deadline_s: float = 30.0,
) -> dict[str, BytesResponse]:
    """Fetch the four Trusted Nodes List documents from ``https://tnl.ebsi.eu/``.

    **Returns unauthenticated bytes; verify them before use.** This function verifies
    nothing, polls nothing, persists nothing and never fetches the pinned key-list key.
    It makes one request per file, in the order of :data:`TNL_FILES`, sharing one
    ``deadline_s`` (see :meth:`EbsiHttpClient.get_bytes` for what that bounds: the attempts,
    the sleeps and the body reads, **not** the wait for one response's headers), and is
    all-or-nothing: if one request fails, the exception propagates
    (its message names the file) and no partial result is returned. A mixed set (a new
    ``tnl.json`` beside a 304 for its signature, or a publish that lands between two
    requests) is handed over as it is; the verifier fails closed on a signature mismatch.

    *client* must allow-list ``tnl.ebsi.eu`` and nothing else, or this raises
    :class:`HttpForbiddenHost` before any request; ``None`` builds (and closes) a
    :func:`for_tnl` client. Only that client is built to keep no cookie: one you build
    yourself keeps whatever its cookie jar accepts, until the client policy of #317.
    *etags* maps a file name to the validator of the copy the caller holds (HTTP cache
    state only; a key that is not a file name is an :class:`HttpError`): a 304 is then
    ``BytesResponse(None, <that etag>)``, which means "re-use the bytes you stored and
    verify them again with a fresh ``now``".
    """
    if client is None:
        with for_tnl() as own:
            return get_tnl_files(own, etags=etags, deadline_s=deadline_s)
    if getattr(client, "allowed_hosts", None) != frozenset({TNL_HOST}):
        raise HttpForbiddenHost(f"the client must allow-list {TNL_HOST} alone")
    supplied: dict[str, str] = {}
    if etags is not None:
        if not isinstance(etags, Mapping):
            raise HttpError(f"etags must be a mapping, not {safe_repr(etags)}")
        for name in etags:
            if name not in TNL_FILES:
                raise HttpError(f"etags names a file that is not fetched: {safe_repr(name)}")
            supplied[name] = _checked_etag(etags[name])
    end = time.monotonic() + _checked_deadline(deadline_s)

    out: dict[str, BytesResponse] = {}
    for name in TNL_FILES:
        try:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise HttpError("deadline exceeded", url=f"https://{TNL_HOST}/{name}")
            out[name] = client.get_bytes(
                f"https://{TNL_HOST}/{name}", max_bytes=TNL_MAX_BYTES[name],
                etag=supplied.get(name), deadline_s=remaining)
        except EbsiError as exc:
            exc.args = (f"{name}: {exc}", *exc.args[1:])      # name the file, keep the class
            raise
    return out


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #

_PILOT_DEPRECATION = (
    "for_ebsi('pilot') is deprecated: use 'legacy-pilot', which seeds the same allow-list "
    "(api-pilot.ebsi.eu, the legacy per-service lane). 'pilot' will change meaning at the next "
    "MAJOR release, to the EBSI Core API pilot, which is a different ledger "
    "(https://github.com/luisgf/openvc/issues/74)")


def for_ebsi(
    environment: str = "legacy-pilot",
    *,
    extra_hosts: set[str] | None = None,
    **kwargs: Any,
) -> EbsiHttpClient:
    """Build a client whose SSRF allow-list is seeded from the EBSI environment.

    * ``"legacy-pilot"`` (the default): ``api-pilot.ebsi.eu``, the legacy per-service lane
      (the v5 adapters), the only place the recorded fixtures and the weekly smoke are valid.
    * ``"pilot"``: the same host and lane as ``"legacy-pilot"``, **deprecated** since 1.37.0.
      It emits a :class:`DeprecationWarning` that names ``"legacy-pilot"``, and seeds exactly
      the same allow-list. EBSI now also calls its Core API pilot "pilot", a different ledger
      that this name does not reach; the name will change meaning at the next MAJOR release
      (2.0, #74), so use ``"legacy-pilot"``. The warning is raised here, so a name read from
      configuration (an environment variable, say) and passed on to this function warns the
      same way.
    * ``"conformance"``: ``api-conformance.ebsi.eu``. A measurement on 2026-10-16 completed
      no connection in 12 s (ADR-0009).
    * ``"production"``: ``api.ebsi.eu``. The certificate that host presented on 2026-10-16
      did not cover its name, so a client built from it is not known to complete a request
      (ADR-0009).

    ``extra_hosts`` lets you permit additional issuer status-list hosts if you
    also follow StatusList proxies through this client. Entries are host NAMES: only
    ``https`` on port 443 of a listed host is reachable (#318), so a status list on another
    port is refused as :class:`HttpForbiddenHost`, and an entry that spells a scheme or a
    port never matches.

    An environment that is not one of these names (another case, empty, not a string)
    raises :class:`~openvc_ebsi.errors.UnknownEbsiEnvironment`, which is also a ``ValueError``.

    Every other keyword argument is passed to :class:`EbsiHttpClient`. In particular
    ``address_guard=AddressGuard()`` turns on the opt-in resolved-address guard: the host
    allow-list still matches names only, and the guard additionally refuses a host that
    resolves to an address that is not globally routable and connects to the validated
    address. It is **off** by default (a deployment with split-horizon DNS or a private
    mirror of a node would break), it is refused behind an environment proxy, and it does
    not stop an attacker who holds a certificate for a public address; see
    :class:`AddressGuard`.
    """
    # `type(...)`, not `isinstance`: a value whose `__class__` claims `str` is not one, and
    # `str.__str__` would raise a bare TypeError on it.
    name = str.__str__(environment) if issubclass(type(environment), str) else None
    if name is None or name not in EBSI_HOSTS:
        raise UnknownEbsiEnvironment(
            f"unknown EBSI environment: {safe_repr(environment)} "
            f"(known: {', '.join(sorted(map(str, EBSI_HOSTS)))})")
    if name == "pilot":
        # `name` is the plain `str` read above, never the caller's object, so a `str` subclass
        # holding "pilot" is compared by its characters. Before the client is built, so a
        # warning turned into an error leaves no client open.
        warnings.warn(_PILOT_DEPRECATION, DeprecationWarning, stacklevel=2)
    hosts = {EBSI_HOSTS[name]} | (extra_hosts or set())
    return EbsiHttpClient(allowed_hosts=hosts, **kwargs)
