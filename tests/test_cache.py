"""
tests/test_cache.py — the core TTL cache and its resolver wrappers (issue #23).

Covers the pure-stdlib :class:`TtlCache` (TTL expiry, bounded eviction, thread-safety —
all deterministic via an injected clock), the :class:`CachingDidResolver` and
:func:`cached_resolve` wrappers (success-only caching; a raised error is never memoized;
per-key isolation), and one end-to-end check that wrapping a resolver dedupes DID
resolution across repeated verifications through the real pipeline.
"""
from __future__ import annotations

import base64
import threading
from datetime import datetime, timezone

import pytest

from openvc.cache import (
    DEFAULT_DID_TTL_S,
    DEFAULT_STATUS_TTL_S,
    CachingDidResolver,
    TtlCache,
    cached_resolve,
)

UTC = timezone.utc


class FakeClock:
    """A manually-advanced monotonic clock so TTL tests never sleep."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


# --------------------------------------------------------------------------- #
# TtlCache
# --------------------------------------------------------------------------- #

def test_get_set_roundtrip():
    c = TtlCache()
    assert c.get("k") is None
    c.set("k", 42)
    assert c.get("k") == 42


def test_ttl_expiry():
    clock = FakeClock()
    c = TtlCache(ttl_s=10, clock=clock)
    c.set("k", "v")
    clock.advance(9)
    assert c.get("k") == "v"          # still fresh at t=9
    clock.advance(2)
    assert c.get("k") is None         # expired at t=11 > ttl 10


def test_expired_entry_is_evicted_on_get():
    clock = FakeClock()
    c = TtlCache(ttl_s=1, clock=clock)
    c.set("k", "v")
    clock.advance(2)
    assert c.get("k") is None
    assert len(c) == 0                # the stale tuple is popped, not left to leak


def test_bounded_eviction_drops_soonest_to_expire():
    clock = FakeClock()
    c = TtlCache(ttl_s=1000, max_entries=3, clock=clock)
    for i in range(6):
        clock.advance(1)              # distinct expiries so eviction is deterministic
        c.set(f"k{i}", i)
    assert len(c) == 3
    assert (c.get("k3"), c.get("k4"), c.get("k5")) == (3, 4, 5)   # newest kept
    assert c.get("k0") is None and c.get("k2") is None            # oldest evicted


def test_updating_existing_key_does_not_evict():
    c = TtlCache(ttl_s=1000, max_entries=2)
    c.set("a", 1)
    c.set("b", 2)
    c.set("a", 3)                     # in-place update, not a new slot
    assert len(c) == 2
    assert c.get("a") == 3 and c.get("b") == 2


def test_clear():
    c = TtlCache()
    c.set("k", 1)
    c.clear()
    assert c.get("k") is None and len(c) == 0


def test_falsy_value_is_served_not_treated_as_miss():
    """A value of {} / b'' / 0 is a real hit — only a true miss/expiry returns None."""
    c = TtlCache()
    c.set("empty", {})
    assert c.get("empty") == {}


def test_wall_clock_default_is_monotonic():
    """The default clock is time.monotonic, so an NTP step back cannot make an entry
    look fresh forever — just a smoke check that the default constructs and works."""
    import time
    c = TtlCache(ttl_s=1000)
    c.set("k", "v")
    assert c.get("k") == "v"
    assert c._clock is time.monotonic     # noqa: SLF001 - guards the freshness invariant


def test_thread_safe_under_concurrent_access():
    c = TtlCache(ttl_s=1000, max_entries=32)
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for i in range(500):
                c.set(f"k{i % 64}", n)
                c.get(f"k{i % 64}")
        except Exception as exc:               # pragma: no cover - only on a race bug
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(c) <= 32                        # eviction held the bound under contention


# --------------------------------------------------------------------------- #
# CachingDidResolver
# --------------------------------------------------------------------------- #

class _CountingResolver:
    """A minimal DidResolver stand-in that counts resolve() calls."""

    def __init__(self, result=None, supports_fn=None):
        self.calls = 0
        self._result = result if result is not None else object()
        self._supports_fn = supports_fn

    def supports(self, did: str) -> bool:
        return self._supports_fn(did) if self._supports_fn is not None else True

    def resolve(self, did: str):
        self.calls += 1
        return self._result


def test_caching_resolver_caches_success():
    clock = FakeClock()
    inner = _CountingResolver()
    r = CachingDidResolver(inner, cache=TtlCache(ttl_s=10, clock=clock))
    a = r.resolve("did:x")
    b = r.resolve("did:x")
    assert a is b and inner.calls == 1         # second served from cache
    clock.advance(11)
    r.resolve("did:x")
    assert inner.calls == 2                     # re-resolved after TTL


def test_caching_resolver_keys_by_did():
    inner = _CountingResolver()
    r = CachingDidResolver(inner)
    r.resolve("did:a")
    r.resolve("did:b")
    r.resolve("did:a")
    assert inner.calls == 2                     # did:a cached, did:b distinct


def test_caching_resolver_does_not_cache_errors():
    from openvc.did.base import DidResolutionError

    class _Flaky:
        def __init__(self):
            self.calls = 0

        def supports(self, did):
            return True

        def resolve(self, did):
            self.calls += 1
            raise DidResolutionError("boom")

    inner = _Flaky()
    r = CachingDidResolver(inner)
    for _ in range(3):
        with pytest.raises(DidResolutionError):
            r.resolve("did:x")
    assert inner.calls == 3                     # a transient failure is retried, not pinned


def test_caching_resolver_delegates_supports():
    r = CachingDidResolver(
        _CountingResolver(supports_fn=lambda d: d.startswith("did:key")))
    assert r.supports("did:key:z") is True
    assert r.supports("did:web:example.com") is False


def test_caching_resolver_supports_true_when_inner_has_none():
    class _NoSupports:            # like a bare DidResolverRegistry
        def resolve(self, did):
            return object()

    r = CachingDidResolver(_NoSupports())
    assert r.supports("did:whatever") is True


# --------------------------------------------------------------------------- #
# cached_resolve
# --------------------------------------------------------------------------- #

def test_cached_resolve_caches_by_key():
    clock = FakeClock()
    calls: list[str] = []

    def fetch(url: str) -> dict:
        calls.append(url)
        return {"u": url}

    c = cached_resolve(fetch, cache=TtlCache(ttl_s=10, clock=clock))
    assert c("u1") == {"u": "u1"}
    assert c("u1") == {"u": "u1"}
    assert calls == ["u1"]                      # second served from cache
    assert c("u2") == {"u": "u2"} and calls == ["u1", "u2"]
    clock.advance(11)
    c("u1")
    assert calls == ["u1", "u2", "u1"]          # re-fetched after TTL


def test_cached_resolve_does_not_cache_errors():
    calls: list[str] = []

    def flaky(url: str) -> dict:
        calls.append(url)
        raise ValueError("boom")

    c = cached_resolve(flaky)
    for _ in range(3):
        with pytest.raises(ValueError):
            c("u")
    assert calls == ["u", "u", "u"]             # never memoized


def test_status_default_ttl_is_shorter_than_did():
    """The status default must stay short — it is the window a revoked credential can
    still verify as valid — and shorter than the DID-doc default."""
    assert 0 < DEFAULT_STATUS_TTL_S < DEFAULT_DID_TTL_S


# --------------------------------------------------------------------------- #
# Integration — the wrapper dedupes DID resolution through the real pipeline
# --------------------------------------------------------------------------- #

def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key_ed25519(key) -> str:
    from openvc.multibase import encode_multibase
    raw = base64.urlsafe_b64decode(key.public_jwk()["x"] + "==")
    return "did:key:" + encode_multibase(_leb128(0xED) + raw)


class _CountingDelegate:
    """Wraps a real resolver and counts how often resolve() reaches it."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = 0

    def supports(self, did):
        return self.inner.supports(did)

    def resolve(self, did):
        self.calls += 1
        return self.inner.resolve(did)


def test_caching_resolver_dedupes_did_resolution_in_pipeline():
    """Two verifications of a did:key credential through one CachingDidResolver resolve
    the issuer DID exactly once — the batch-verification win, on the real pipeline."""
    from openvc import VerificationPolicy, verify_credential
    from openvc.did.did_key import DidKeyResolver
    from openvc.keys import Ed25519SigningKey
    from openvc.proof.di_jcs import EddsaJcsProofSuite

    key = Ed25519SigningKey.generate(kid="tmp")
    did = _did_key_ed25519(key)
    vm = f"{did}#{did[len('did:key:'):]}"
    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": did,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice"},
    }
    secured = EddsaJcsProofSuite().add_proof(
        credential, signing_key=key, verification_method=vm)

    counting = _CountingDelegate(DidKeyResolver())
    resolver = CachingDidResolver(counting)
    policy = VerificationPolicy(require_status=False, now=datetime(2021, 1, 1, tzinfo=UTC))

    r1 = verify_credential(secured, resolver=resolver, policy=policy)
    r2 = verify_credential(secured, resolver=resolver, policy=policy)
    assert r1.issuer == did and r2.issuer == did
    assert counting.calls == 1                  # second verify hit the cache
