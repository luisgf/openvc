"""
tests/test_pyld_identity_resolver.py — pyld no longer serializes an inline context on every
use (issue #446).

``ContextResolver.resolve`` (pyld 2.0.4 and 3.x) builds the cache key of an inline context
with ``canonicalize(dict(ctx))``, the whole context serialized, each time pyld applies it, hit
or miss and before any term is defined. One scoped context of J bytes used by N nodes cost
J x N bytes of serialization (100 KiB of document: 190 s), work that a count of term
definitions never sees. ``openvc.proof.contexts.pyld_options`` now hands pyld a resolver that
resolves an inline context object once per call (``_identity_resolver_class``).

The work is asserted by measuring it independently of the budget's counter: the bytes that go
through ``pyld.context_resolver.canonicalize`` while a hostile document is verified are bounded
by the size of the document, not by N times it. A control with pyld's own resolver shows the
measurement is not vacuous. The rest pins the resolver's equivalence with pyld's, the soundness
of its identity key and the per-call lifetime of its memo. Self-contained helpers (tests/ is
not a package: no cross-import).
"""
from __future__ import annotations

import asyncio
import json
import threading

import pytest

pytest.importorskip("pyld")

from frozendict import frozendict  # noqa: E402
from pyld import context_resolver as pyld_context_resolver  # noqa: E402
from pyld import jsonld  # noqa: E402
from pyld.context_resolver import ContextResolver  # noqa: E402

from openvc import VerificationPolicy, verify_credential  # noqa: E402
from openvc.proof import _rdfc  # noqa: E402
from openvc.proof.contexts import (  # noqa: E402
    _identity_resolver_class,
    document_loader,
    pyld_options,
)
from openvc.proof.errors import SignatureInvalid  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
GARBAGE = "z" + "1" * 86
POLICY = VerificationPolicy(require_status=False)
# the reserved key "@x" of the body shape makes pyld warn that it ignores it
pytestmark = pytest.mark.filterwarnings("ignore::SyntaxWarning")


def _credential(subject, context=None):
    return {"@context": context or [V2], "type": ["VerifiableCredential"], "issuer": DID,
            "credentialSubject": subject,
            "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                      "verificationMethod": f"{DID}#{DID[8:]}", "created": "2026-01-01T00:00:00Z",
                      "proofPurpose": "assertionMethod", "proofValue": GARBAGE}}


def _cache_hit_shape(k: int, n: int) -> dict:
    """K-term property-scoped context defined once, used N times under one active context
    (every use is a processed-context cache hit: no term definition at all)."""
    big = {f"t{i}": f"x:{i}" for i in range(k)}
    return _credential({
        "@context": {"v": "@value", "p": {"@id": "x:p", "@context": big}},
        "id": "did:example:s", "p": [{"v": None} for _ in range(n)]})


def _body_shape(j: int, n: int) -> dict:
    """A type-scoped context with one reserved key and a body of J digits (no term to
    define), the type used N times (4 bytes a use)."""
    scoped = {"T": {"@id": "x:T", "@context": {"@x": [1] * j}}}
    return _credential({"@context": scoped, "id": "did:example:s", "type": ["T"] * n})


@pytest.fixture
def serialized(monkeypatch):
    """The bytes pyld's resolver serialized (a one-item list)."""
    total = [0]
    original = pyld_context_resolver.canonicalize

    def counted(value):
        out = original(value)
        total[0] += len(out)
        return out

    monkeypatch.setattr(pyld_context_resolver, "canonicalize", counted)
    return total


@pytest.mark.parametrize("name, document", [
    ("cache-hit K=800 N=1500", _cache_hit_shape(800, 1500)),
    ("body J=3000 N=1500", _body_shape(3000, 1500)),
], ids=lambda value: value if isinstance(value, str) else "")
def test_the_bytes_pyld_serializes_are_bounded_by_the_document_not_by_n_times_it(
        name, document, serialized):
    size = len(json.dumps(document))
    with pytest.raises(SignatureInvalid):
        verify_credential(document, policy=POLICY)          # pyld expanded it, then the proof
    assert serialized[0] > 0, "the resolver is reached"
    assert serialized[0] <= 12 * size, (serialized[0], size)


def test_the_control_with_pyld_own_resolver_serializes_n_times_the_document(serialized):
    """Without the identity resolver the same bytes are N times the document: the
    measurement above is not vacuous."""
    document = _body_shape(3000, 1500)
    loader = document_loader(None)
    options = pyld_options(loader)
    options["contextResolver"] = ContextResolver({}, loader)
    jsonld.expand(document, options)
    assert serialized[0] > 100 * len(json.dumps(document))


# --------------------------------------------------------------------------- #
# Equivalence with pyld's resolve
# --------------------------------------------------------------------------- #

def _pair():
    served = {"https://a.example/served": {"@context": {"x": "https://a.example/x"}}}
    loader = document_loader(served)
    return (ContextResolver({}, loader), _identity_resolver_class()({}, loader))


def _outcome(call):
    try:
        resolved = call()
    except jsonld.JsonLdError as exc:
        return ("error", exc.code, str(exc.details) if exc.details else "")
    return ("ok", [(r.document if not hasattr(r.document, "items") else dict(r.document))
                   for r in resolved])


ARGUMENTS = [
    V2,
    "https://a.example/served",
    "https://a.example/not-served",
    {"@vocab": "https://a.example/"},
    {"@context": {"@vocab": "https://a.example/"}},                # unwrapped: the argument
    {"@context": [V2, {"@vocab": "https://a.example/"}]},
    [V2, {"@vocab": "https://a.example/"}, "https://a.example/served"],
    [{"@context": {"@vocab": "https://a.example/"}}],               # an element is NOT unwrapped
    [{"@vocab": "https://a.example/"}, {"@vocab": "https://a.example/"}],
    [None],
    [False],
    None,
    [V2, None, {"a": "https://a.example/a"}],
    frozendict({"@vocab": "https://a.example/"}),
    [frozendict({"@vocab": "https://a.example/"}), {"@vocab": "https://a.example/"}],
    frozendict({"@context": frozendict({"@vocab": "https://a.example/"})}),
    5,
    [5],
    [[{"@vocab": "https://a.example/"}]],                           # an array inside an array
    [V2, 5],
    {},
    [{}, {}],
]


@pytest.mark.parametrize("argument", ARGUMENTS, ids=lambda value: repr(value)[:50])
def test_resolve_is_pyld_s_resolve_element_for_element(argument):
    ours, theirs = _pair()
    assert _outcome(lambda: ours.resolve({}, argument, "")) == _outcome(
        lambda: theirs.resolve({}, argument, ""))


def test_the_cycles_set_is_shared_by_every_element():
    ours, theirs = _pair()
    shared_ours, shared_theirs = set(), set()
    arg = ["https://a.example/served", V2, {"@vocab": "https://a.example/"}]
    ours.resolve({}, arg, "", shared_ours)
    theirs.resolve({}, arg, "", shared_theirs)
    assert shared_ours == shared_theirs and shared_ours


# --------------------------------------------------------------------------- #
# The identity key
# --------------------------------------------------------------------------- #

def test_an_inline_object_is_resolved_once_and_its_result_reused(serialized):
    resolver = _identity_resolver_class()({}, document_loader(None))
    context = {"@vocab": "https://a.example/", "t": "https://a.example/t"}
    first = resolver.resolve({}, [context], "")
    after_first = serialized[0]
    assert after_first > 0
    for _ in range(50):
        again = resolver.resolve({}, [context], "")
        assert again[0] is first[0]
    assert serialized[0] == after_first, "no serialization on a reuse"


def test_an_equal_but_distinct_object_is_still_resolved_by_pyld(serialized):
    resolver = _identity_resolver_class()({}, document_loader(None))
    one = {"@vocab": "https://a.example/"}
    two = {"@vocab": "https://a.example/"}
    resolver.resolve({}, [one], "")
    before = serialized[0]
    resolver.resolve({}, [two], "")
    assert serialized[0] > before


def test_a_recycled_id_cannot_return_another_objects_result():
    resolver = _identity_resolver_class()({}, document_loader(None))
    stale = {"@vocab": "https://stale.example/"}
    fresh = {"@vocab": "https://fresh.example/"}
    stale_result = resolver.resolve({}, [stale], "")
    resolver._seen[id(fresh)] = (stale, stale_result)       # what an id reuse would look like
    got = resolver.resolve({}, [fresh], "")
    assert dict(got[0].document) == fresh


def test_the_memo_keeps_a_reference_to_every_object_it_keys():
    resolver = _identity_resolver_class()({}, document_loader(None))
    resolver.resolve({}, [{"@vocab": "https://a.example/"}], "")     # no other reference
    (held, _), = resolver._seen.values()
    assert held == {"@vocab": "https://a.example/"}


def test_pyld_rewriting_context_objects_in_place_forgets_the_memo():
    resolver = _identity_resolver_class()({}, document_loader(None))
    resolver.resolve({}, [{"@vocab": "https://a.example/"}], "")
    assert resolver._seen
    resolver._resolve_context_urls({"@context": ["relative/ctx"]}, "https://a.example/base/")
    assert resolver._seen == {}


def test_the_memo_belongs_to_one_resolver_and_so_to_one_call():
    loader = document_loader(None)
    first = pyld_options(loader)["contextResolver"]
    second = pyld_options(loader)["contextResolver"]
    assert first is not second and first._seen is not second._seen
    context = {"@vocab": "https://a.example/"}
    first.resolve({}, [context], "")
    assert second._seen == {} and id(context) in first._seen
    assert first.per_op_cache is not second.per_op_cache


def test_the_options_still_carry_a_pyld_context_resolver_per_call():
    options = pyld_options(document_loader(None))
    assert isinstance(options["contextResolver"], ContextResolver)
    assert options["contextResolver"].document_loader is options["documentLoader"]


# --------------------------------------------------------------------------- #
# The per-verification budget is scoped to a block
# --------------------------------------------------------------------------- #

def test_a_budget_block_is_shared_joined_and_nested_fresh():
    with _rdfc.verification_budget() as outer:
        assert _rdfc.new_processor().work is outer
        with _rdfc.verification_budget(join=True) as joined:
            assert joined is outer
        with _rdfc.verification_budget() as inner:
            assert inner is not outer and _rdfc.new_processor().work is inner
        assert _rdfc.new_processor().work is outer
    assert _rdfc.new_processor().work is not outer          # none open: a private budget


def test_a_budget_block_is_closed_by_an_exception():
    with pytest.raises(RuntimeError):
        with _rdfc.verification_budget() as leaked:
            raise RuntimeError("boom")
    assert _rdfc.new_processor().work is not leaked


def test_budget_blocks_are_per_thread_and_per_task():
    seen: list[object] = []
    with _rdfc.verification_budget() as here:
        thread = threading.Thread(target=lambda: seen.append(_rdfc.new_processor().work))
        thread.start()
        thread.join()

        async def task():
            with _rdfc.verification_budget() as mine:
                await asyncio.sleep(0)
                return mine, _rdfc.new_processor().work

        async def main():
            return await asyncio.gather(task(), task())

        results = asyncio.run(main())
    assert seen[0] is not here
    for mine, used in results:
        assert mine is used and mine is not here
    assert results[0][0] is not results[1][0]
