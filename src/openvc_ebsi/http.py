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
  * bytes path     : ``get_bytes`` returns a body verbatim (no JSON, no cache, no text
                      decoding), with a hard cap on the wire size and on the DECODED size.
                      ``get_tnl_files`` uses it to fetch the Trusted Nodes List from a
                      client that allow-lists ``tnl.ebsi.eu`` alone (ADR-0009 D4).

Pass ``client.get_json`` wherever a ``Fetch`` is expected (e.g. into the resolver).
"""

from __future__ import annotations

import math
import random
import re
import time
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import DefaultCookiePolicy
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

import httpx

from openvc import _json
from openvc import __version__
from openvc.cache import TtlCache
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
class HttpUnexpectedEncoding(HttpError): ...  # Content-Encoding the bytes path does not decode


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
    attempts: int = 3
    backoff_base_s: float = 0.25
    backoff_max_s: float = 5.0
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})

    def backoff(self, attempt: int) -> float:
        # exponential with equal jitter: half fixed, half random.
        ceiling = min(self.backoff_base_s * (2 ** attempt), self.backoff_max_s)
        return ceiling / 2 + random.uniform(0, ceiling / 2)


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
    ) -> None:
        self._allowed = {h.lower() for h in allowed_hosts}
        self._timeout_s = timeout_s
        self._max_bytes = max_response_bytes
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
        ``max_bytes`` can only lower the client's ``max_response_bytes``. ``deadline_s`` is
        an overall budget across attempts and sleeps (a ``Retry-After`` sleep is clamped to
        what remains).

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
        for attempt in range(self._retry.attempts):
            if until is not None and until - time.monotonic() <= 0:
                raise HttpError("deadline exceeded", url=url)
            body: bytes = b""
            try:
                with self._client.stream("GET", url, headers=headers) as resp:
                    status = resp.status_code
                    if status == 200:
                        body = read_body(resp)
                    elif drain_error_body:
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
                self._sleep_before_retry(attempt, until=until)
                continue

            if status == 200:
                return status, body, resp.headers
            if status == 304 and accept_not_modified:
                return status, b"", resp.headers
            if status == 404:
                raise HttpNotFound("not found", status=404, url=url)
            if status in self._retry.retry_statuses:
                self._sleep_before_retry(attempt, resp, until=until)
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

    def _read_verbatim(
        self, resp: httpx.Response, url: str, cap: int, until: float | None
    ) -> bytes:
        """Read a 200 body for :meth:`get_bytes`: the raw wire bytes, or the result of
        decoding ONE ``gzip`` / ``deflate`` coding, never more than *cap* bytes of either.

        ``iter_raw`` hands over the wire bytes undecoded, so httpx never inflates anything.
        The wire total and the decoded total are both checked BEFORE a chunk is appended,
        and ``zlib`` is asked for at most ``room + 1`` bytes, so a decompression bomb is
        refused inside the stdlib, before the allocation, not after it."""
        decoder = _decoder_for(resp.headers.get("content-encoding"), url)
        declared = _declared_length(resp.headers.get("content-length"))
        if declared is not None and declared > cap:
            raise HttpError(f"response exceeds {cap} bytes", status=200, url=url)

        deadline = time.monotonic() + self._timeout_s
        if until is not None:
            deadline = min(deadline, until)
        wire = 0
        body = bytearray()
        for chunk in resp.iter_raw():
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
                # max_length is positive (room + 1 >= 1; 0 would mean unlimited). A call that
                # returns at most `room` bytes consumed its whole input (or hit the end of
                # the stream), so nothing is pending in `unconsumed_tail`; one that returns
                # room + 1 is over the cap, which is the refusal below.
                piece = decoder.decompress(chunk, room + 1)
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
        if until is not None:                 # never sleep past the caller's budget
            delay = min(delay, max(0.0, until - time.monotonic()))
        time.sleep(delay)

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


def _checked_deadline(value: object) -> float:
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or value <= 0):
        raise HttpError(f"deadline_s must be a positive finite number, not {safe_repr(value)}")
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


class _NoCookiePolicy(DefaultCookiePolicy):
    """Stores no cookie, so nothing a server sets can ever be sent back: the TNL client keeps
    no state. (httpx builds each request's Cookie header from a copy of the jar, which is why
    the policy refuses at storing, the one place it governs.)"""

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False


def _refuse_cookies(client: EbsiHttpClient) -> None:
    client._client.cookies.jar.set_policy(_NoCookiePolicy())


def for_tnl(**kwargs: Any) -> EbsiHttpClient:
    """A client for the Trusted Nodes List host and for nothing else.

    Its allow-list is ``{TNL_HOST}`` alone, never the node set a list names, so a poisoned
    list cannot widen where the list itself is fetched; ``allowed_hosts`` cannot be passed.
    It keeps no cookies, and its response cap defaults to 64 KiB.
    """
    if "allowed_hosts" in kwargs:
        raise TypeError("for_tnl() allow-lists tnl.ebsi.eu alone; allowed_hosts cannot be passed")
    kwargs.setdefault("max_response_bytes", 64 * 1024)
    client = EbsiHttpClient(allowed_hosts={TNL_HOST}, **kwargs)
    _refuse_cookies(client)
    return client


def get_tnl_files(
    client: EbsiHttpClient | None = None,
    *,
    etags: Mapping[str, str] | None = None,
    deadline_s: float = 30.0,
) -> dict[str, BytesResponse]:
    """Fetch the four Trusted Nodes List documents from ``https://tnl.ebsi.eu/``.

    **Returns unauthenticated bytes; verify them before use.** This function verifies
    nothing, polls nothing, persists nothing and never fetches the pinned key-list key.
    It makes one request per file, in the order of :data:`TNL_FILES`, under one overall
    ``deadline_s``, and is all-or-nothing: if one request fails, the exception propagates
    (its message names the file) and no partial result is returned. A mixed set (a new
    ``tnl.json`` beside a 304 for its signature, or a publish that lands between two
    requests) is handed over as it is; the verifier fails closed on a signature mismatch.

    *client* must allow-list ``tnl.ebsi.eu`` and nothing else, or this raises
    :class:`HttpForbiddenHost` before any request; ``None`` builds (and closes) a
    :func:`for_tnl` client. *etags* maps a file name to the validator of the copy the
    caller holds (HTTP cache state only; a key that is not a file name is an
    :class:`HttpError`): a 304 is then ``BytesResponse(None, <that etag>)``, which means
    "re-use the bytes you stored and verify them again with a fresh ``now``".
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

def for_ebsi(
    environment: str = "pilot",
    *,
    extra_hosts: set[str] | None = None,
    **kwargs: Any,
) -> EbsiHttpClient:
    """Build a client whose SSRF allow-list is seeded from the EBSI environment.

    ``extra_hosts`` lets you permit additional issuer status-list hosts if you
    also follow StatusList proxies through this client.
    """
    if environment not in EBSI_HOSTS:
        raise ValueError(f"unknown EBSI environment: {environment!r}")
    hosts = {EBSI_HOSTS[environment]} | (extra_hosts or set())
    return EbsiHttpClient(allowed_hosts=hosts, **kwargs)
