"""
openvc.proof.contexts — bundled JSON-LD contexts and an offline document loader
for RDF canonicalization.

Canonicalizing a JSON-LD credential expands it against its ``@context``. Fetching
those over the network at verify time is both a performance and a security
problem (a moved/served-differently context silently changes the canonical form
and thus the signature check). So the loader serves a small bundled allow-list
and, by default, **refuses to hit the network** — unknown contexts must be
supplied explicitly via ``extra_contexts``.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping

from ...errors import OpenvcError

_DIR = Path(__file__).parent

# url -> bundled file. Kept deliberately small; callers inject the rest.
_BUNDLED_FILES: dict[str, Path] = {
    "https://www.w3.org/ns/credentials/v2": _DIR / "credentials-v2.json",
}


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
    unlisted URL raises :class:`DocumentLoaderError`."""
    cache = bundled_contexts()
    if extra_contexts:
        cache.update(extra_contexts)

    def _loader(url: str, options: Any = None) -> dict:
        try:
            document = cache[url]
        except KeyError:
            raise DocumentLoaderError(
                f"refusing to fetch JSON-LD context over the network: {url!r} "
                f"(bundle it or pass it via extra_contexts)") from None
        return {"contextUrl": None, "documentUrl": url, "document": document}

    return _loader


__all__ = [
    "DocumentLoaderError",
    "bundled_contexts",
    "document_loader",
]
