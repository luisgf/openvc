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
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

# Hosts per EBSI environment (used to seed the SSRF allow-list).
EBSI_HOSTS: dict[str, str] = {
    "pilot": "api-pilot.ebsi.eu",
    "conformance": "api-conformance.ebsi.eu",
}
EBSI_BASE: dict[str, str] = {env: f"https://{host}" for env, host in EBSI_HOSTS.items()}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class HttpError(Exception):
    def __init__(self, message: str, *, status: int | None = None, url: str | None = None):
        super().__init__(message)
        self.status = status
        self.url = url


class HttpNotFound(HttpError): ...          # 404 — maps to DidNotFound upstream
class HttpForbiddenHost(HttpError): ...     # SSRF guard tripped
class HttpTransientExhausted(HttpError): ...  # retries used up


# --------------------------------------------------------------------------- #
# TTL cache (thread-safe, bounded)
# --------------------------------------------------------------------------- #

class TtlCache:
    def __init__(self, *, ttl_s: float = 300.0, max_entries: int = 1024) -> None:
        self._ttl = ttl_s
        self._max = max_entries
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        now = time.monotonic()
        with self._lock:
            hit = self._data.get(key)
            if hit is None:
                return None
            expires, value = hit
            if expires < now:
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._data) >= self._max and key not in self._data:
                # cheap eviction: drop the soonest-to-expire entry
                oldest = min(self._data, key=lambda k: self._data[k][0])
                self._data.pop(oldest, None)
            self._data[key] = (time.monotonic() + self._ttl, value)


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
        user_agent: str = "openvc/0.1 (+ebsi-verifier)",
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
