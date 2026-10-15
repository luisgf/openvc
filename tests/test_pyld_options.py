"""
tests/test_pyld_options.py — every pyld call takes its options from ``pyld_options`` (#225).

``openvc.proof.contexts.pyld_options(loader, **options)`` is the one place that builds the
options of a pyld call: the document loader plus a ``ContextResolver`` private to the call, so
the call sees the contexts its loader serves and none that pyld's process-global cache holds
for another caller. The behaviour that buys is pinned end to end in
``test_pyld_context_isolation.py``. This file pins the invariants a future change could
break without any of those scenarios noticing:

1. No pyld call in the source can leave the resolver out: a scan of every ``jsonld.*`` call
   (and a runtime recorder across the suites, ``missing_types`` and the OpenID4VP type
   expansion) requires the options to come from the helper, and the scanner is itself tested
   on snippets so it cannot go blind.
2. The one thing a resolver may keep across calls is the resolution of a *bundled* context
   (the processed form of the VC v2 context is most of the cost of a verification): never an
   injected URL, a bundled URL the caller shadowed, an inline object context, or anything
   served by a loader that is not ``document_loader``'s.
3. What makes that sharing sound: the bundled documents reference no other URL.

Helpers are self-contained (tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pyld")              # the RDF suites canonicalize with pyld

from pyld import jsonld  # noqa: E402

from openvc import VerificationPolicy, verify_credential  # noqa: E402
from openvc.did.base import DidResolutionError, parse_did_document  # noqa: E402
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.openid4vp import _expanded_types  # noqa: E402
from openvc.proof import contexts as contexts_module  # noqa: E402
from openvc.proof.contexts import (  # noqa: E402
    DocumentLoaderError,
    bundled_contexts,
    document_loader,
    pyld_options,
)
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.verify import FORMAT_DI_EDDSA  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
DID = "did:example:issuer"
VM = f"{DID}#k"


def _expand_types(loader, document=None):
    document = document or {"@context": V2, "type": "VerifiableCredential"}
    return jsonld.expand(document, pyld_options(loader))[0]["@type"]


# --------------------------------------------------------------------------- #
# 1a. A scan of the source: no pyld call can leave the resolver out
# --------------------------------------------------------------------------- #

# Entry points of pyld that take ``documentLoader`` in their options.
_ENTRY_POINTS = frozenset({
    "expand", "compact", "flatten", "frame", "link", "normalize", "to_rdf", "load_document"})
# The repository's source (not wherever ``openvc`` happens to be installed), so the scan
# reads exactly the files under test, with or without an editable install.
_SRC = Path(__file__).resolve().parents[1] / "src"
_HELPER_FILE = Path("openvc/proof/contexts/__init__.py")


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


def _pyld_calls(source):
    """``(line, name, options come from pyld_options)`` for every call of a pyld entry point
    in *source*: ``jsonld.expand(...)``, ``_pyld().normalize(...)``, ``pyld.jsonld.frame(...)``,
    ``JsonLdProcessor().expand(...)``."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _ENTRY_POINTS):
            continue
        receiver = _dotted(node.func.value)
        if receiver.split(".")[-1] not in {
                "jsonld", "pyld", "_pyld()", "_require_pyld()", "JsonLdProcessor",
                "JsonLdProcessor()"}:
            continue
        arguments = list(node.args) + [keyword.value for keyword in node.keywords]
        helper = any(isinstance(arg, ast.Call) and _dotted(arg.func) == "pyld_options"
                     for arg in arguments)
        found.append((node.lineno, f"{receiver}.{node.func.attr}", helper))
    return found


def _source_files():
    return sorted(path for path in _SRC.rglob("*.py") if path.relative_to(_SRC) != _HELPER_FILE)


def test_every_pyld_call_takes_its_options_from_the_helper():
    sites = []
    for path in _source_files():
        for line, name, helper in _pyld_calls(path.read_text(encoding="utf-8")):
            sites.append((f"{path.relative_to(_SRC)}:{line}", name, helper))
    assert len(sites) >= 10, sites          # the scan sees the calls it is there to police
    bare = [f"{where} {name}" for where, name, helper in sites if not helper]
    assert not bare, (
        "build the options of these pyld calls with openvc.proof.contexts.pyld_options "
        f"(a bare documentLoader shares pyld's process-global context cache): {bare}")


def test_only_the_helper_builds_pyld_options_or_resolvers():
    """No other file spells the option keys or constructs a resolver, so a call cannot be
    handed a hand-made one (or the global cache) by a different route."""
    offenders = []
    for path in _source_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and node.value in {
                    "documentLoader", "contextResolver"}:
                offenders.append(f"{path.relative_to(_SRC)}:{node.lineno} {node.value!r}")
            if isinstance(node, ast.Name) and node.id == "ContextResolver":
                offenders.append(f"{path.relative_to(_SRC)}:{node.lineno} ContextResolver")
            if isinstance(node, ast.alias) and node.name == "ContextResolver":
                offenders.append(f"{path.relative_to(_SRC)}:{node.lineno} import")
    assert not offenders, offenders


@pytest.mark.parametrize("snippet, expected", [
    ('jsonld.expand(d, {"documentLoader": loader})', [False]),
    ("jsonld.expand(d, options)", [False]),
    ("jsonld.expand(d, pyld_options(loader))", [True]),
    ("jsonld.compact(d, ctx, options=pyld_options(loader, base=b))", [True]),
    ('_pyld().normalize(d, {"algorithm": "x", "documentLoader": loader})', [False]),
    ('_pyld().to_rdf(d, pyld_options(loader, format="f"))', [True]),
    ("pyld.jsonld.frame(d, f, opts)", [False]),
    ("JsonLdProcessor().expand(d, opts)", [False]),
    ("jsonld.expand(d, wrap(pyld_options(loader)))", [False]),     # not the options itself
    ("re_match.expand(template)", []),                              # not a pyld receiver
    ("JsonLdProcessor.to_nquads(dataset)", []),                     # no loader involved
    ("a = jsonld.expand(d, pyld_options(l))\nb = jsonld.compact(d, c, {})", [True, False]),
])
def test_the_scanner_tells_helper_options_from_bare_ones(snippet, expected):
    assert [helper for _, _, helper in sorted(_pyld_calls(snippet), key=lambda c: c[0])] \
        == expected


# --------------------------------------------------------------------------- #
# 1b. A recorder at run time: each call gets a fresh, private resolver
# --------------------------------------------------------------------------- #

def _registry(public_jwk):
    doc = parse_did_document({
        "id": DID,
        "verificationMethod": [
            {"id": VM, "type": "JsonWebKey2020", "controller": DID, "publicKeyJwk": public_jwk}],
        "assertionMethod": [VM],
    })

    class _Reg:
        def supports(self, did):
            return did == DID

        def resolve(self, did):
            if did != DID:
                raise DidResolutionError(f"unknown DID {did!r}")
            return doc

    return _Reg()


def _credential():
    return {
        "@context": [V2, {"@vocab": "https://vocab.example/"}],
        "id": "urn:uuid:7d1e5c38-0000-4000-8000-000000000226",
        "type": ["VerifiableCredential", "ExampleDegree"],
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
    }


def _drive_every_pyld_caller():
    """One pass through every code path that calls pyld."""
    ed = Ed25519SigningKey.generate(kid=VM)
    secured = DataIntegrityProofSuite().add_proof(
        _credential(), signing_key=ed, verification_method=VM)
    DataIntegrityProofSuite().verify(secured, public_key_jwk=ed.public_jwk())
    # expected_types: ``missing_types`` expands the credential once more
    verify_credential(secured, resolver=_registry(ed.public_jwk()),
                      policy=VerificationPolicy(
                          expected_types=["https://vocab.example/ExampleDegree"]))

    p256 = P256SigningKey.generate(kid=VM)
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=p256, verification_method=VM)
    EcdsaRdfcProofSuite().verify(secured, public_key_jwk=p256.public_jwk())

    sd = EcdsaSdProofSuite()
    base = sd.add_base_proof(_credential(), signing_key=p256, verification_method=VM,
                             mandatory_pointers=["/issuer", "/validFrom"])
    derived = sd.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    sd.verify(derived, public_key_jwk=p256.public_jwk())

    # OpenID4VP ``type_values`` expands the types of a verified credential
    result = SimpleNamespace(format=FORMAT_DI_EDDSA, credential=_credential())
    assert _expanded_types("q", 0, result, document_loader())


def test_every_pyld_call_gets_its_own_fresh_resolver_that_is_not_pylds_global_cache(
        monkeypatch):
    global_cache = getattr(jsonld, "_resolved_context_cache", object())
    seen = []

    def record(name, original):
        def recorder(*args, **kwargs):
            if not sys._getframe(1).f_globals.get("__name__", "").startswith("openvc"):
                return original(*args, **kwargs)     # pyld calling itself with our options
            options = kwargs["options"] if "options" in kwargs else args[-1]
            resolver = options.get("contextResolver")
            seen.append({
                "call": name,
                "resolver": resolver,                # kept alive: ids of freed objects repeat
                "has_resolver": resolver is not None,
                "private": resolver is not None and resolver.shared_cache is not global_cache,
                "fresh": resolver is not None and resolver.per_op_cache == {},
                "id": id(resolver),
                "loader": options.get("documentLoader"),
                "resolver_loader": getattr(resolver, "document_loader", None),
            })
            return original(*args, **kwargs)
        return recorder

    for name in ("expand", "compact", "normalize", "to_rdf"):
        monkeypatch.setattr(jsonld, name, record(name, getattr(jsonld, name)))

    _drive_every_pyld_caller()

    assert {entry["call"] for entry in seen} == {"expand", "compact", "normalize", "to_rdf"}
    assert len(seen) >= 10, seen            # the recorder sees the calls it is there to police
    assert all(entry["has_resolver"] for entry in seen), seen
    assert all(entry["private"] for entry in seen), seen
    assert all(entry["fresh"] for entry in seen), seen
    assert all(entry["resolver_loader"] is entry["loader"] for entry in seen), seen
    # one resolver per pyld call, never carried from one to the next
    assert len({entry["id"] for entry in seen}) == len(seen), seen


# --------------------------------------------------------------------------- #
# The helper
# --------------------------------------------------------------------------- #

def test_pyld_options_is_the_loader_a_private_resolver_and_the_callers_options():
    loader = document_loader()
    first = pyld_options(loader, base="https://rp.example/", format="application/n-quads")
    assert first["documentLoader"] is loader
    assert first["base"] == "https://rp.example/"
    assert first["format"] == "application/n-quads"
    assert first["contextResolver"].document_loader is loader
    second = pyld_options(loader)
    assert second["contextResolver"] is not first["contextResolver"]
    assert set(second) == {"documentLoader", "contextResolver"}


def test_pyld_options_keys_cannot_be_overridden_by_the_caller():
    loader = document_loader()
    options = pyld_options(loader, documentLoader=lambda url, opts=None: {}, contextResolver=None)
    assert options["documentLoader"] is loader
    assert options["contextResolver"] is not None
    assert options["contextResolver"].document_loader is loader


# --------------------------------------------------------------------------- #
# 2. What a resolver may keep across calls: bundled contexts only
# --------------------------------------------------------------------------- #

@pytest.fixture
def store(monkeypatch):
    """An empty store of shared bundled resolutions, restored afterwards."""
    fresh: dict = {}
    monkeypatch.setattr(contexts_module, "_BUNDLED_RESOLVED", fresh)
    return fresh


def test_the_bundled_context_resolution_is_shared_between_calls(store):
    assert store == {}
    _expand_types(document_loader())
    assert set(store) == {V2}
    first = store[V2]["static"]
    options = pyld_options(document_loader())
    # the next call starts from the shared resolution, not from nothing
    assert options["contextResolver"].shared_cache.get(V2) is store[V2]
    _expand_types(document_loader({"https://x.example/ctx": {"@context": {}}}))
    assert store[V2]["static"] is first


def test_injected_urls_and_inline_contexts_are_never_kept(store):
    imported = "https://tenant.example/keep/ctx"
    wrapper = "https://tenant.example/keep/wrapper"
    inline = {"@context": [V2, {"@import": imported}], "type": ["VerifiableCredential", "Dl"]}
    served = {wrapper: {"@context": [{"@import": imported}]},
              imported: {"@context": {"Dl": "https://dmv.example/DL"}}}
    _expand_types(document_loader({imported: served[imported]}), inline)
    _expand_types(document_loader(served), {"@context": [V2, wrapper], "type": "Dl"})
    _expand_types(document_loader(served), {"@context": [V2, {"@vocab": "https://v.example/"}],
                                            "type": "Thing"})
    assert set(store) <= {V2}, set(store)
    assert set(store) == {V2}


def test_a_bundled_url_the_caller_shadowed_does_not_use_or_fill_the_shared_one(store):
    shadow = {"@context": {"type": "@type",
                           "VerifiableCredential": "https://shadow.example/VC"}}
    shadowed = document_loader({V2: shadow})
    # cold store: the shadowing call leaves nothing behind
    assert _expand_types(shadowed) == ["https://shadow.example/VC"]
    assert store == {}
    # warm store: the shadowing call does not take the bundled resolution, and is not taken
    bundled = _expand_types(document_loader())
    assert bundled != ["https://shadow.example/VC"]
    kept = store[V2]
    assert _expand_types(shadowed) == ["https://shadow.example/VC"]
    assert store[V2] is kept
    assert _expand_types(document_loader()) == bundled


def test_a_loader_that_is_not_documentloader_shares_nothing(store):
    served = dict(bundled_contexts())

    def tags_everything_static(url, options=None):
        if url not in served:
            raise DocumentLoaderError(url)
        return {"contextUrl": None, "documentUrl": url, "document": served[url],
                "tag": "static", "static": True}

    options = pyld_options(tags_everything_static)
    assert options["contextResolver"].shared_cache == {}
    assert jsonld.expand({"@context": V2, "type": "VerifiableCredential"}, options)
    assert store == {}


def test_the_shared_window_opens_only_on_the_urls_the_loader_serves_from_the_bundle(store):
    window = contexts_module._BundledResolutions(frozenset({V2}))
    window[V2] = {"static": ["resolved"]}
    window["https://elsewhere.example/ctx"] = {"static": ["leaked"]}   # dropped
    window['{"@import":"x"}'] = {"static": ["leaked"]}                  # dropped
    assert store == {V2: {"static": ["resolved"]}}
    assert window.get(V2) == {"static": ["resolved"]}
    assert window.get("https://elsewhere.example/ctx") is None
    assert list(window) == [V2] and len(window) == 1
    # a key the window does not open on reads as absent even if the store holds it
    store["https://elsewhere.example/ctx"] = {"static": ["planted"]}
    assert window.get("https://elsewhere.example/ctx") is None
    assert list(window) == [V2]
    with pytest.raises(KeyError):
        del window["https://elsewhere.example/ctx"]
    del window[V2]
    assert V2 not in store and window.get(V2) is None


def test_the_call_leaves_pylds_global_cache_alone():
    global_cache = getattr(jsonld, "_resolved_context_cache", None)
    if global_cache is None:
        pytest.skip("this pyld has no process-global resolved-context cache")
    before = set(global_cache)
    imported = "https://tenant.example/global/ctx"
    document = {"@context": [V2, {"@import": imported}], "type": ["VerifiableCredential", "Dl"]}
    _expand_types(document_loader({imported: {"@context": {"Dl": "https://dmv.example/DL"}}}),
                  document)
    _expand_types(document_loader())
    assert set(global_cache) == before


def test_pyld_still_shares_inline_imports_across_calls_when_not_given_a_resolver():
    """The control: why every call needs ``pyld_options``. Handed only a loader, pyld
    resolves an inline ``@import`` once, in its process-global cache, for whoever asks next.
    If a pyld release stops doing that the hazard is gone upstream and this test, not the
    helper, is what to retire."""
    global_cache = getattr(jsonld, "_resolved_context_cache", None)
    if global_cache is None:
        pytest.skip("this pyld has no process-global resolved-context cache")
    imported = "https://tenant.example/control/ctx"
    document = {"@context": [V2, {"@import": imported}], "type": ["VerifiableCredential", "Dl"]}

    def bare(iri):
        loader = document_loader({imported: {"@context": {"Dl": iri}}})
        return jsonld.expand(document, {"documentLoader": loader})[0]["@type"]

    snapshot = dict(global_cache)
    try:
        first = bare("https://dmv.example/DL")
        second = bare("https://other.example/X")
        if second != first:
            pytest.skip("pyld no longer shares an inline @import between calls")
        assert second == ["https://www.w3.org/2018/credentials#VerifiableCredential",
                          "https://dmv.example/DL"]
    finally:
        global_cache.clear()
        global_cache.update(snapshot)


# --------------------------------------------------------------------------- #
# 3. What makes sharing the bundled resolutions sound
# --------------------------------------------------------------------------- #

def _references(node, path=""):
    """URLs a context document refers to: ``@import``, or a string / array ``@context``
    entry inside it (a ``null`` context, which resets the active one, is no reference)."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "@import":
                found.append((path, key, value))
            elif key == "@context" and not isinstance(value, dict) and value is not None:
                found.append((path, key, value))
            found.extend(_references(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_references(value, f"{path}[{index}]"))
    return found


@pytest.mark.parametrize("url", sorted(bundled_contexts()))
def test_a_bundled_context_references_no_other_url(url):
    """The shared resolution of a bundled URL is a function of that one document. A bundled
    document that pulled in another URL would let that URL's content, served by one caller's
    loader, ride into every later call through the shared entry: drop it from the shared set
    (or keep the sharing off) before bundling such a document."""
    assert _references(bundled_contexts()[url]) == []


def test_the_reference_scan_sees_references():
    assert _references({"@context": {"@import": "https://x.example/a"}})
    assert _references({"@context": ["https://x.example/a", {"t": "u"}]})
    assert _references({"a": {"@context": "https://x.example/a"}})
    assert _references({"a": {"@context": None}, "b": {"@context": {"t": "u"}}}) == []
