"""
tests/test_contexts.py — the offline JSON-LD document loader (#183).

The loader never fetches: an unlisted URL fails closed. Bundled contexts are tagged
``static`` so pyld resolves their term definitions once per process instead of on every
canonicalization.

That tag is **provenance-gated**, and the gate is a correctness property rather than a
micro-optimisation: pyld promotes a tagged document into a *process-global* cache keyed
by context URL (``pyld.jsonld._resolved_context_cache``, via ``ContextResolver``), so a
tagged caller-injected document would serve the first caller's term definitions to every
later caller of that URL — canonicalizing with terms the signer never had. The bundled
files may be tagged because they ship read-only, so every loader in the process serves
the same bytes for a given URL. The last test pins the isolation end to end.
"""
from __future__ import annotations

import pytest

from openvc.proof.contexts import DocumentLoaderError, bundled_contexts, document_loader

CREDS_V2 = "https://www.w3.org/ns/credentials/v2"


def test_bundled_context_is_tagged_static():
    loaded = document_loader()(CREDS_V2, {})
    assert loaded["contextUrl"] is None
    assert loaded["documentUrl"] == CREDS_V2
    assert isinstance(loaded["document"], dict)
    assert loaded["tag"] == "static"
    assert loaded["static"] is True
    assert CREDS_V2 in bundled_contexts()


def test_injected_context_is_not_tagged_static():
    url = "https://example.org/ctx/injected/v1"
    doc = {"@context": {"@vocab": "https://example.org/#"}}
    loader = document_loader({url: doc})
    loaded = loader(url, {})
    assert loaded["document"] is doc
    assert "tag" not in loaded and "static" not in loaded
    assert loader(CREDS_V2, {})["tag"] == "static"      # bundled ones still are


def test_injected_override_of_a_bundled_url_is_not_tagged():
    """The gate is provenance, not URL membership — a caller may shadow a bundled URL,
    and that document must not inherit the bundled URL's tag."""
    shadow = {"@context": {"@vocab": "https://shadow.example/#"}}
    loaded = document_loader({CREDS_V2: shadow})(CREDS_V2, {})
    assert loaded["document"] is shadow
    assert "tag" not in loaded and "static" not in loaded


def test_unknown_url_fails_closed():
    with pytest.raises(DocumentLoaderError, match="refusing to fetch"):
        document_loader()("https://evil.example/ctx", {})


def test_extra_contexts_cannot_pollute_the_bundled_cache():
    """``bundled_contexts()`` hands out a fresh top-level dict, so an injected override
    on one loader must not be visible to the next."""
    document_loader({CREDS_V2: {"@context": {"@vocab": "https://shadow.example/#"}}})
    assert document_loader()(CREDS_V2, {})["document"] is bundled_contexts()[CREDS_V2]


def test_injected_contexts_do_not_cross_contaminate_pylds_global_cache():
    """#183 regression: two consumers, one context URL, two different documents.

    pyld's resolved-context cache is process-global and keyed by URL, so while injected
    documents were tagged ``static`` the second consumer silently expanded with the
    first one's terms.
    """
    jsonld = pytest.importorskip("pyld.jsonld")
    url = "https://example.org/ctx/tenant/v1"
    payload = {"@context": url, "name": "Ada"}

    def expand_with(vocab):
        loader = document_loader({url: {"@context": {"name": f"{vocab}#name"}}})
        return jsonld.expand(payload, {"documentLoader": lambda u, o=None: loader(u, o)})

    (first,) = expand_with("https://first.example")
    (second,) = expand_with("https://second.example")
    assert list(first) == ["https://first.example#name"]
    assert list(second) == ["https://second.example#name"]
