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

Pass ``client.get_json`` wherever a ``Fetch`` is expected (e.g. into the resolver).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from openvc import __version__
from openvc.cache import TtlCache

from .errors import EbsiError

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
# Client
# --------------------------------------------------------------------------- #

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
    ) -> None:
        self._allowed = {h.lower() for h in allowed_hosts}
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
        for attempt in range(self._retry.attempts):
            try:
                resp = self._client.get(url)
            except httpx.TransportError as exc:      # network error / timeout
                last_exc = exc
                self._sleep_before_retry(attempt)
                continue

            if resp.status_code == 200:
                data = resp.json()
                self._cache.set(url, data)           # only cache successes
                return data
            if resp.status_code == 404:
                raise HttpNotFound("not found", status=404, url=url)
            if resp.status_code in self._retry.retry_statuses:
                self._sleep_before_retry(attempt, resp)
                last_exc = HttpError("transient", status=resp.status_code, url=url)
                continue
            raise HttpError(f"unexpected status {resp.status_code}",
                            status=resp.status_code, url=url)

        raise HttpTransientExhausted(
            f"gave up after {self._retry.attempts} attempts: {last_exc}", url=url
        )

    # -- internals --------------------------------------------------------- #

    def _guard_host(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise HttpForbiddenHost(f"non-https URL rejected: {url}", url=url)
        if parsed.hostname is None or parsed.hostname.lower() not in self._allowed:
            raise HttpForbiddenHost(f"host not in allow-list: {parsed.hostname}", url=url)

    def _sleep_before_retry(self, attempt: int, resp: httpx.Response | None = None) -> None:
        if attempt >= self._retry.attempts - 1:
            return
        delay = self._retry.backoff(attempt)
        if resp is not None:
            retry_after = resp.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = max(delay, float(retry_after))
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
    """
    if environment not in EBSI_HOSTS:
        raise ValueError(f"unknown EBSI environment: {environment!r}")
    hosts = {EBSI_HOSTS[environment]} | (extra_hosts or set())
    return EbsiHttpClient(allowed_hosts=hosts, **kwargs)
