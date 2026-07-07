"""
openvc.cache — thread-safe, bounded TTL caching for the resolution paths.

Verification re-resolves the same things constantly: a batch of credentials from one
issuer resolves that DID once per credential, and a shared status list is re-fetched
(and re-verified) for every credential that points at it. This module is the **opt-in**
fix — a pure-stdlib :class:`TtlCache` plus two thin wrappers that memoize a
:class:`~openvc.did.base.DidResolver` and the ``Callable[[str], …]`` fetch/resolve
functions ``verify_credential`` accepts. No new dependency; core-hosted so
``openvc_ebsi`` (whose HTTP client already had this cache) consumes it downward.

**Opt-in, like the guarded resolvers in :mod:`openvc.resolvers`:** the pipeline default
resolves *uncached* — caching is a decision with a freshness cost, so the caller makes
it explicitly by wrapping their resolver / fetch.

**Freshness is a security property for status.** A cached status list cannot reflect a
revocation that happened after it was cached until the entry expires, so a revoked
credential can verify as *valid* for up to the TTL. That is why status caching defaults
to a **short** TTL (:data:`DEFAULT_STATUS_TTL_S`) — keep it short, and never cache a
status list for longer than your tolerance for stale revocation. DID documents change
only on key rotation, so they tolerate a longer TTL (:data:`DEFAULT_DID_TTL_S`). Tune
either by passing your own :class:`TtlCache`.

The TTL and size live on the :class:`TtlCache` (one knob, one place); the wrappers just
consume a cache. Caching is best-effort under contention: two threads that miss the same
cold key concurrently will each resolve it once (no single-flight) — correct, just not
deduplicated on that first race.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Callable, TypeVar

if TYPE_CHECKING:                    # annotation-only — keep did.base out of the runtime graph
    from .did.base import DidDocument, DidResolver

__all__ = [
    "DEFAULT_DID_TTL_S",
    "DEFAULT_STATUS_TTL_S",
    "CachingDidResolver",
    "TtlCache",
    "cached_resolve",
]

# DID documents change only on key rotation → a few minutes is safe. Status lists gate
# revocation → keep the window short (a cached list cannot see a fresh revocation until
# it expires). Both are defaults the caller can override by passing a TtlCache.
DEFAULT_DID_TTL_S = 300.0
DEFAULT_STATUS_TTL_S = 60.0

T = TypeVar("T")


class TtlCache:
    """A thread-safe, bounded, time-to-live cache keyed by string.

    ``get`` returns the stored value while it is fresh, else ``None`` (so a value of
    ``None`` cannot be distinguished from a miss — the resolution values cached here are
    never ``None``). When full, ``set`` evicts the oldest entry in O(1); since a single
    cache has one TTL, oldest-inserted is also soonest-to-expire. The clock is injectable
    for deterministic tests; it defaults to :func:`time.monotonic` so wall-clock changes
    (NTP steps) cannot make an entry look fresh forever.
    """

    def __init__(
        self,
        *,
        ttl_s: float = DEFAULT_DID_TTL_S,
        max_entries: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_s
        self._max = max_entries
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        now = self._clock()
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
            if key not in self._data and len(self._data) >= self._max:
                self._data.popitem(last=False)          # O(1) evict of the oldest entry
            self._data[key] = (self._clock() + self._ttl, value)
            self._data.move_to_end(key)                 # write order tracks expiry order

    def clear(self) -> None:
        """Drop every entry (e.g. to force a re-resolve after a known key rotation)."""
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        """The number of stored entries (some may be expired but not yet evicted)."""
        with self._lock:
            return len(self._data)


def cached_resolve(
    fn: Callable[[str], T],
    *,
    cache: TtlCache | None = None,
) -> Callable[[str], T]:
    """Wrap a ``Callable[[str], T]`` — a ``resolve_status_list`` /
    ``resolve_status_list_token`` / ``resolve_credential_schema`` / fetch — so repeated
    keys within the TTL are served from a bounded, thread-safe cache.

    Without a *cache* it builds one with the **short** :data:`DEFAULT_STATUS_TTL_S`,
    because the primary use is status lists, where the TTL is exactly the window a revoked
    credential can still verify as valid — keep it short. Schema / type-metadata resolvers
    are content-integrity-pinned and tolerate a longer TTL: pass a ``TtlCache(ttl_s=…)``.
    Only successful calls are cached; an exception propagates uncached so a transient fetch
    failure is retried, never pinned.
    """
    c = cache if cache is not None else TtlCache(ttl_s=DEFAULT_STATUS_TTL_S)

    def resolve(key: str) -> T:
        hit = c.get(key)
        if hit is not None:
            return hit
        value = fn(key)                                 # errors propagate uncached
        c.set(key, value)
        return value

    return resolve


class CachingDidResolver:
    """Wrap a :class:`~openvc.did.base.DidResolver` so repeated ``resolve(did)`` within
    the TTL are served from a bounded, thread-safe cache — the win is skipping the
    ``did:web`` network round-trip (and its verification) on a batch from one issuer.

    Memoization is the same :func:`cached_resolve` primitive applied to the resolver's
    ``resolve``: only **successful** resolutions are cached, so a ``DidResolutionError`` /
    ``UnsupportedDidMethod`` propagates and is retried, never pinned. ``supports`` delegates
    to the wrapped resolver (returning ``True`` when it exposes none, matching how a bare
    :class:`~openvc.did.base.DidResolverRegistry` is treated). Without a *cache* it builds
    one with the longer :data:`DEFAULT_DID_TTL_S`. Drop it into
    ``verify_credential(resolver=…)``.
    """

    def __init__(self, resolver: DidResolver, *, cache: TtlCache | None = None) -> None:
        self._inner = resolver
        if cache is None:
            cache = TtlCache(ttl_s=DEFAULT_DID_TTL_S)
        self._resolve: Callable[[str], DidDocument] = cached_resolve(
            resolver.resolve, cache=cache)

    def supports(self, did: str) -> bool:
        inner_supports = getattr(self._inner, "supports", None)
        return inner_supports(did) if inner_supports is not None else True

    def resolve(self, did: str) -> DidDocument:
        return self._resolve(did)
