"""
openvc.proof.contexts — bundled JSON-LD contexts and an offline document loader
for RDF canonicalization.

Canonicalizing a JSON-LD credential expands it against its ``@context``. Fetching
those over the network at verify time is both a performance and a security
problem (a moved/served-differently context silently changes the canonical form
and thus the signature check). So the loader serves a small bundled allow-list
and, by default, **refuses to hit the network** — unknown contexts must be
supplied explicitly via ``extra_contexts``.

pyld ≥3 ships its own ``FrozenDocumentLoader`` / ``BUNDLED_CONTEXTS``; openvc
deliberately keeps this loader instead (#124), so the exact context bytes that
feed canonicalization stay vendored here, independent of the installed pyld.

:func:`pyld_options` is the other half: every pyld call in openvc takes its options from
it, so the loader a call is handed is the only source of contexts that call sees (#225).
"""
from __future__ import annotations

import json
import functools
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, MutableMapping

from ...errors import OpenvcError

_DIR = Path(__file__).parent

# url -> bundled file. Kept deliberately small; callers inject the rest.
_BUNDLED_FILES: dict[str, Path] = {
    "https://www.w3.org/ns/credentials/v2": _DIR / "credentials-v2.json",
}

# What pyld's ``ContextResolver`` resolved for each *bundled* context URL, kept for the life
# of the process (``url -> {tag: [ResolvedContext]}``, the shape the resolver writes). It
# holds nothing else: see :class:`_BundledResolutions`.
_BUNDLED_RESOLVED: dict[str, Any] = {}


class DocumentLoaderError(OpenvcError):
    """A context was requested that is neither bundled nor injected."""


@lru_cache(maxsize=None)
def _parse_bundled(path_str: str) -> dict:
    return json.loads(Path(path_str).read_text())


def bundled_contexts() -> dict[str, dict]:
    """The bundled contexts as ``url -> parsed JSON``.

    The per-file parse is cached (the files ship read-only), so RDF canonicalization does
    not re-read and re-parse them on every proof. A **fresh top-level dict** is returned each
    call (so a caller's ``.update(extra_contexts)`` cannot pollute the cache), while the
    parsed context objects are shared — pyld treats a loaded context document as read-only."""
    return {url: _parse_bundled(str(path)) for url, path in _BUNDLED_FILES.items()}


def document_loader(
    extra_contexts: Mapping[str, dict] | None = None,
) -> Callable[[str, Any], dict]:
    """Return a pyld-compatible document loader over the bundled contexts plus
    any *extra_contexts* (``url -> context document``). Never fetches: an
    unlisted URL raises :class:`DocumentLoaderError`.

    Only the **bundled** files are tagged ``static``. pyld promotes a tagged document
    into a resolved-context cache keyed by context URL (the process-global one, or the
    ``shared_cache`` of the ``ContextResolver`` a call is given), so the tag is sound only
    for documents that are byte-identical in every loader in the process — which the
    bundled files are, shipping read-only. A caller-injected document is **never** tagged,
    including one that shadows a bundled URL: tagging it would publish the first caller's
    term definitions to every later caller of that URL, and canonicalization would silently
    use terms the signer never had. (:func:`pyld_options` hands each call a resolver that
    shares only the bundled entries, so a call cannot reach the process-global cache at
    all; the tag stays so that those are what it shares.)

    The returned callable also carries ``contexts``, a read-only ``url -> document`` view
    of everything it serves. Context validation indexes the term definitions of every
    one of them, not only those a document lists, since the document's ``@context`` is
    what a holder can rewrite."""
    bundled = bundled_contexts()
    cache = dict(bundled)
    if extra_contexts:
        cache.update(extra_contexts)
    # Identity, not URL membership: a caller may shadow a bundled URL with its own
    # document, and that document must not inherit the bundled URL's tag.
    static_urls = frozenset(url for url, doc in cache.items() if bundled.get(url) is doc)
    return _OfflineLoader(cache, static_urls)


class _OfflineLoader:
    """The loader :func:`document_loader` returns: a pyld document loader over a fixed
    ``url -> document`` map, which it exposes read-only as ``contexts``."""

    __slots__ = ("contexts", "_static_urls")

    def __init__(self, cache: dict[str, dict], static_urls: frozenset[str]) -> None:
        self.contexts: Mapping[str, dict] = MappingProxyType(cache)
        self._static_urls = static_urls

    def __call__(self, url: str, options: Any = None) -> dict:
        try:
            document = self.contexts[url]
        except KeyError:
            from .._verify_common import safe_repr  # lazily: this package loads first
            raise DocumentLoaderError(
                f"refusing to fetch JSON-LD context over the network: {safe_repr(url)} "
                f"(bundle it or pass it via extra_contexts)") from None
        loaded: dict[str, Any] = {
            "contextUrl": None,
            "documentUrl": url,
            "document": document,
        }
        if url in self._static_urls:
            loaded["static"] = True        # the jsonld.js shape; pyld itself reads ``tag``
            loaded["tag"] = "static"
        return loaded


class _BundledResolutions(MutableMapping):
    """The ``shared_cache`` of one call's pyld ``ContextResolver``: a window onto
    ``_BUNDLED_RESOLVED`` that opens only on the URLs the call's loader serves **from the
    bundle, object for object** (``_OfflineLoader``'s static URLs). Any other key reads as
    absent and a write to it is dropped: an injected URL, a bundled URL the caller shadowed
    with its own document, and an inline object ``@context``, which the resolver keys by its
    JSON and tags ``static`` itself (the entry that carried one caller's ``@import`` to the
    next one, #225), all live and die with the resolver.

    Sharing the bundled ones is sound because their resolution is a function of one
    read-only document that references no other URL (``tests/test_pyld_options.py`` fails if
    a bundled document ever does), and it is worth having: the resolution keeps the
    processed form of the context, which is most of the cost of expanding against it."""

    __slots__ = ("_urls",)

    def __init__(self, urls: frozenset[str]) -> None:
        self._urls = urls

    def __getitem__(self, key: str) -> Any:
        if key not in self._urls:
            raise KeyError(key)
        return _BUNDLED_RESOLVED[key]

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self._urls:
            _BUNDLED_RESOLVED[key] = value

    def __delitem__(self, key: str) -> None:
        if key not in self._urls:
            raise KeyError(key)
        del _BUNDLED_RESOLVED[key]

    def __iter__(self) -> Iterator[str]:
        return iter([key for key in list(_BUNDLED_RESOLVED) if key in self._urls])

    def __len__(self) -> int:
        return len(list(iter(self)))


def pyld_options(loader: Callable[[str, Any], dict], **options: Any) -> dict[str, Any]:
    """The options for **one** pyld call: *options* plus ``documentLoader`` and a
    ``contextResolver`` private to the call.

    pyld keeps a **process-global** resolved-context cache and, unless a call is handed its
    own ``ContextResolver``, reads and writes it. It caches an inline (object) ``@context``
    by its JSON, together with the processed result of any ``@import`` inside it, tagged
    ``static`` whatever the loader said. So an inline context that ``@import``s a URL was
    resolved once, through whichever caller's loader came first, and every later call in
    the process reused that: another caller's ``extra_contexts`` terms, or a context its own
    loader would have refused (#225, the follow-up to GHSA-vrxg-57v4-85mc;
    :func:`document_loader` closed the same hole for a URL document in 1.27.1). The resolver
    built here starts every call from nothing, except for the bundled contexts
    :class:`_BundledResolutions` lets it keep, so a call sees the contexts its *loader*
    serves and no others.

    Every pyld call in openvc takes its options from here (``tests/test_pyld_options.py``
    fails on one that does not; ``tests/test_pyld_context_isolation.py`` runs the cross-caller
    cases through the real pipeline), so a new call site cannot leave the resolver out. Build
    the options anew for each call: a resolver remembers what it resolved, and one call's
    must not be another's. The loader may be any callable; one that is not
    :func:`document_loader`'s shares nothing. pyld is imported here, not at module level,
    because the core loads without it.

    The resolver is an :func:`_identity_resolver_class` instance: pyld serializes an inline
    context again on every use to build its cache key, a cost proportional to the size of
    the context for every node that uses it (issue #446)."""
    shared: MutableMapping[str, Any] = (
        _BundledResolutions(loader._static_urls) if isinstance(loader, _OfflineLoader) else {})
    return {**options, "documentLoader": loader,
            "contextResolver": _identity_resolver_class()(shared, loader)}


@functools.lru_cache(maxsize=1)
def _identity_resolver_class() -> Any:
    """pyld's ``ContextResolver`` that resolves an inline context *object* once per call.

    ``ContextResolver.resolve`` (pyld 2.0.4 and 3.x alike) turns every object element of an
    ``@context`` into a cache key with ``canonicalize(dict(ctx))``, the whole context
    serialized, each time pyld applies it: once per node that uses a scoped context, hit or
    miss, before any term is defined. So a scoped context of J bytes used by N nodes costs
    J x N bytes of serialization whatever the processed-context cache does (100 KiB: 190 s),
    work that no count of term definitions sees. This subclass remembers, by object identity,
    what an inline context resolved to and answers the next use from that; everything else
    (a URL, ``None``, a non-object, an object it has not seen) goes to pyld's own ``resolve``
    one element at a time, so the result, the errors and the ``cycles`` set are pyld's.

    The memo is sound because (1) what an inline element resolves to depends on the object
    alone: ``ResolvedContext(ctx)``, found or created under a key that is a function of the
    object's content, never of ``active_ctx``, ``base`` or ``cycles``; (2) it holds a
    reference to every object it keys, so an ``id`` cannot be reused for another object while
    the resolver lives; (3) it lives in the resolver, which :func:`pyld_options` builds anew
    for every call, so nothing is shared between calls and a loader that hands out a private
    copy of a document on every load loses only the memo hits; and (4) the one place pyld
    mutates a context object it has already seen is ``_resolve_context_urls``, which
    rewrites relative ``@context`` URLs inside a freshly fetched remote document in place.
    That method is overridden to forget the memo first, so a hit on an object that was
    rewritten afterwards cannot happen. The caller's input is not touched: pyld expands a
    deep copy. A ``frozendict`` is immutable, so keying it by identity is as safe, and the
    top-level ``@context`` unwrap applies to the argument only, as in pyld, never to a list
    element."""
    from frozendict import frozendict
    from pyld.context_resolver import ContextResolver

    class _IdentityResolver(ContextResolver):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._seen: dict[int, tuple[Any, list[Any]]] = {}

        def resolve(self, active_ctx: Any, context: Any, base: Any, cycles: Any = None) -> Any:
            if cycles is None:
                cycles = set()                       # shared by every element, as in pyld
            if isinstance(context, (dict, frozendict)) and "@context" in context:
                context = context["@context"]       # the argument only, never an element
            if not isinstance(context, list):
                context = [context]
            resolved: list[Any] = []
            for element in context:
                if isinstance(element, (dict, frozendict)):
                    hit = self._seen.get(id(element))
                    if hit is None or hit[0] is not element:
                        hit = (element, super().resolve(active_ctx, [element], base, cycles))
                        self._seen[id(element)] = hit    # holds the object: its id is not reused
                    resolved.extend(hit[1])
                else:
                    resolved.extend(super().resolve(active_ctx, [element], base, cycles))
            return resolved

        def _resolve_context_urls(self, context: Any, base: Any) -> None:
            self._seen.clear()                       # pyld rewrites context objects in place
            super()._resolve_context_urls(context, base)

    return _IdentityResolver


__all__ = [
    "DocumentLoaderError",
    "bundled_contexts",
    "document_loader",
    "pyld_options",
]
