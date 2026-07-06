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


def bundled_contexts() -> dict[str, dict]:
    """Load the bundled contexts as ``url -> parsed JSON`` (fresh copy)."""
    return {url: json.loads(path.read_text()) for url, path in _BUNDLED_FILES.items()}


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
