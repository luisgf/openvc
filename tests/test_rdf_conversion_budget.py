"""
tests/test_rdf_conversion_budget.py — the JSON-LD to RDF conversion budget (issue #426).

pyld's node-map builder checks each new value of a (subject, property) against every value
already stored there, so N values under one property cost about N**2/2 ``compare_values``
calls (a 71 KB credential, 10 s), and the RDF Data Integrity suites run the conversion
before the signature is looked at. ``openvc.proof._rdfc`` replays that merge on the expanded
document, counts the comparisons pyld will make, and refuses over the ceiling before
``to_rdf`` runs.

Boundedness is asserted by counting the ``compare_values`` calls pyld was let make (zero for a
refusal), never by wall-clock. The load-bearing test is the soundness one: **the charge is
never below what pyld really does**, over a corpus of shapes and a seeded fuzz; an under-count
would be a bypass.
"""
from __future__ import annotations

import base64
import json
import random
from pathlib import Path

import pytest

pytest.importorskip("pyld")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from pyld import jsonld  # noqa: E402
from pyld.jsonld import JsonLdProcessor  # noqa: E402

from openvc import VerificationPolicy, verify_credential, verify_many  # noqa: E402
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof import _rdfc  # noqa: E402
from openvc.proof.contexts import document_loader, pyld_options  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityProofSuite, _canonize  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import ProofMalformed, SignatureInvalid  # noqa: E402

VC2 = "https://www.w3.org/ns/credentials/v2"
CTX = [VC2, {"@vocab": "https://v.example/"}]
V = "https://v.example/"
BUDGET_ERROR = "CanonicalizationBudgetExceeded"
FIXTURES = Path(__file__).parent / "fixtures"
_ISSUER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
# one property with N distinct values costs N*(N-1)/2: this N is above the ceiling
HOSTILE_N = 1500


@pytest.fixture
def pyld_calls(monkeypatch):
    """The ``compare_values`` calls pyld makes (a list with one counter)."""
    calls = [0]
    original = JsonLdProcessor.compare_values

    def counting(v1, v2):
        calls[0] += 1
        return original(v1, v2)

    monkeypatch.setattr(JsonLdProcessor, "compare_values", staticmethod(counting))
    return calls


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _ed_key():
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = _b64d(Ed25519SigningKey(priv, kid="t").public_jwk()["x"])
    did = "did:key:" + encode_multibase(_leb128(0xED) + raw)
    vm = f"{did}#{did[len('did:key:'):]}"
    return Ed25519SigningKey(priv, kid=vm), did, vm


def _p256_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = P256SigningKey(priv, kid="t").public_jwk()
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"),
        ec.SECP256R1()).public_key()
    comp = pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.CompressedPoint)
    did = "did:key:" + encode_multibase(_leb128(0x1200) + comp)
    vm = f"{did}#{did[len('did:key:'):]}"
    return P256SigningKey(priv, kid=vm), did, vm


# --------------------------------------------------------------------------- #
# The corpus: every shape of the issue's parenthesis, small enough to run in ms
# --------------------------------------------------------------------------- #

def _ld(*nodes, **top) -> dict:
    return {"@context": {"@vocab": V}, "@graph": list(nodes), **top} if nodes else \
        {"@context": {"@vocab": V}, **top}


def _vals(n, prefix="v"):
    return [f"{prefix}{i}" for i in range(n)]


def _padded(k: int, m: int, value="v") -> list:
    """K empty lists (added without a comparison, they still enlarge the stored values) then M
    repeats of *value*: pyld pays M * (K + 1) comparisons for the repeats in a slot where
    *value* is new, and M in a slot where it was already the first."""
    return [{"@list": []} for _ in range(k)] + [value] * m


def _slot_shapes() -> dict[str, dict]:
    """A value first stored in one slot, then repeated behind padding in another. A counter that
    folds two slots pyld keeps apart (or splits one it merges) charges M instead of M * (K + 1):
    these shapes are what the slot partition is tested with (#445 review: F1-F3)."""
    k, m, s = 6, 12, V + "s"
    shapes = {
        "slot: another graph": _ld(
            {"@id": s, "p": "v"}, {"@id": V + "g", "@graph": [{"@id": s, "p": _padded(k, m)}]}),
        "slot: another subject": _ld(
            {"@id": V + "s1", "p": "v"}, {"@id": V + "s2", "p": _padded(k, m)}),
        "slot: another property": _ld({"@id": s, "p": "v", "q": _padded(k, m)}),
        "slot: forward against reverse": _ld(
            {"@id": V + "x", "@reverse": {"q": {"@id": s}}},
            {"@id": s, "q": _padded(k, m, {"@id": V + "x"})}),
        "slot: blank-node property, forward against reverse": _ld(
            {"@id": V + "x", "@reverse": {"_:q": {"@id": s}}},
            {"@id": s, "_:q": _padded(k, m, {"@id": V + "x"})}),
        "slot: forward blank-node property against a reverse _:b0": _ld(
            {"@id": V + "x", "@reverse": {"_:b0": {"@id": s}}},
            {"@id": s, "_:x": _padded(k, m, {"@id": V + "x"})}),
        "slot: a blank-node type is labelled before a blank-node property": _ld(
            {"@id": V + "x", "@reverse": {"_:b1": {"@id": s}}},
            {"@id": s, "@type": ["_:t"], "_:x": _padded(k, m, {"@id": V + "x"})}),
        "slot: an anonymous node takes a label before a blank-node property": _ld(
            {"@id": V + "x", "@reverse": {"_:b1": {"@id": s}}},
            {"@id": s, "@included": [{"p": "v"}], "_:x": _padded(k, m, {"@id": V + "x"})}),
        "slot: a blank-node id takes a label before a blank-node property": _ld(
            {"@id": V + "x", "@reverse": {"_:b1": {"@id": s}}},
            {"@id": s, "@included": [{"@id": "_:n", "p": "v"}],
             "_:x": _padded(k, m, {"@id": V + "x"})}),
        "slot: two blank-node properties": _ld(
            {"@id": s, "_:q": _padded(k, 4), "_:r": _padded(k, 4)}),
        "slot: nested graphs": _ld({"@id": V + "g", "@graph": [
            {"@id": s, "p": "v"}, {"@id": V + "h", "@graph": [{"@id": s, "p": _padded(k, m)}]}]}),
        "slot: subjects that differ only by case": _ld(
            {"@id": V + "s", "p": "v"}, {"@id": V + "S", "p": _padded(k, m)}),
        "slot: blank-node labels that differ only by case": _ld(
            {"@id": "_:a", "p": "v"}, {"@id": "_:A", "p": _padded(k, m)}),
        "slot: graph named by a blank node": _ld(
            {"@id": s, "p": "v"}, {"@id": "_:g", "@graph": [{"@id": s, "p": _padded(k, m)}]}),
    }
    for keyword in ("@type", "@none", "@graph", "@id", "@value", "@set"):
        shapes[f"slot: graph named {keyword}"] = _ld(
            {"@id": s, "p": "v"}, {"@id": keyword, "@graph": [{"@id": s, "p": _padded(k, m)}]})
    shapes["slot: graph named @default"] = _ld(
        {"@id": s, "p": "v"}, {"@id": "@default", "@graph": [{"@id": s, "p": _padded(k, m)}]})
    return shapes


def _null_id_shapes() -> dict[str, dict]:
    """A keyword-like id (``"@a"``) expands to ``"@id": null``: pyld puts every such node on one
    key (and crashes later, after the merge, once a string-keyed node shares the graph)."""
    n, s = 14, V + "s"
    return {
        "null id: one type each": _ld(*[{"@id": "@a", "@type": V + f"T{i}"} for i in range(n)]),
        "null id: in @included": _ld({"@id": s, "@included": [
            {"@id": "@a", "@type": V + f"T{i}"} for i in range(n)]}),
        "null id: reverse items under N parents": _ld(
            *[{"@id": V + f"s{i}", "@reverse": {"q": {"@id": "@a"}}} for i in range(n)]),
        "null id: reverse items with types": _ld(
            *[{"@id": V + f"s{i}", "@reverse": {"q": {"@id": "@a", "@type": V + f"T{i}"}}}
              for i in range(n)]),
        "null id: graph names": _ld(
            *[{"@id": "@a", "@graph": [{"@id": s, "p": f"v{i}"}]} for i in range(n)]),
        "null id: references": _ld({"@id": s, "p": [{"@id": "@a"}] * n}),
        "null id: in a list": _ld({"@id": s, "p": {"@list": [
            {"@id": "@a", "@type": V + f"T{i}"} for i in range(n)]}}),
        "null id: with forward values": _ld(
            *[{"@id": "@a", "p": f"v{i}"} for i in range(n)]),
        "null id: id map with keyword-like keys": {
            "@context": {"@vocab": V, "idm": {"@container": "@id"}}, "@id": s,
            "idm": {f"@k{chr(97 + i)}": {"@type": V + f"T{i}"} for i in range(n)}},
    }


def _corpus() -> dict[str, dict]:
    n = 14
    s = "https://v.example/s"
    return {
        "one fat property": _ld({"@id": s, "p": _vals(n)}),
        "duplicates": _ld({"@id": s, "p": ["a", "b", "a", "c", "a", "b", "d"] * 3}),
        "identical values": _ld({"@id": s, "p": ["x"] * n}),
        "number, bool and string spellings": _ld(
            {"@id": s, "p": [1, True, 1.0, "1", "true", 1, False, 0, None, 1.5, 2**70]}),
        "typed and language literals": _ld({"@id": s, "p": [
            {"@value": "x", "@type": V + "T"}, {"@value": "x", "@type": V + "U"},
            {"@value": "x", "@language": "en"}, {"@value": "x", "@language": "de"},
            {"@value": "x"}, {"@value": "x", "@type": V + "T"}, {"@value": "x", "@language": "en"},
            {"@value": "{}", "@type": "@json"}, {"@value": {"a": 1}, "@type": "@json"},
            {"@value": {"a": 1}, "@type": "@json"}]}),
        "NaN values (never equal to themselves)": _ld(
            {"@id": s, "p": [float("nan")] * n}),
        "NaN, infinities and big numbers": _ld(
            {"@id": s, "p": [float("nan"), float("inf"), float("inf"), -float("inf"), 2**80,
                             2**80, 0.1, 0.1, -0.0, 0.0, float("nan")]}),
        "@json values that print alike": _ld({"@id": s, "p": [
            {"@value": {"1": "x"}, "@type": "@json"}, {"@value": {"1": "x"}, "@type": "@json"},
            {"@value": [1, 2], "@type": "@json"}, {"@value": [1, 2], "@type": "@json"},
            {"@value": [True], "@type": "@json"}, {"@value": [1], "@type": "@json"},
            {"@value": [1.0], "@type": "@json"}]}),
        "a graph named @default": _ld(
            *[{"@id": s, "p": f"v{i}"} for i in range(6)],
            {"@id": "@default", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(6, 12)]}),
        "same-@id node objects, one value each": _ld(
            *[{"@id": s, "p": f"v{i}"} for i in range(n)]),
        "same-@id node objects, with duplicates": _ld(
            *[{"@id": s, "p": f"v{i % 4}"} for i in range(n)]),
        "same-@id nodes across two properties": _ld(
            *[{"@id": s, "p": f"v{i}", "q": f"w{i % 3}"} for i in range(n)]),
        "repeated blank label across objects": _ld(
            *[{"@id": "_:a", "p": f"v{i}"} for i in range(n)]),
        "blank label referenced and described": _ld(
            *[{"@id": f"_:n{i}", "p": {"@id": "_:a"}, "q": f"v{i}"} for i in range(n)],
            {"@id": "_:a", "p": _vals(5)}),
        "anonymous nodes": _ld({"@id": s, "p": [{"q": i} for i in range(n)]}),
        "anonymous nodes holding fat properties": _ld(
            {"@id": s, "p": [{"q": _vals(5)} for _ in range(5)]}),
        "N distinct types": _ld({"@id": s, "@type": [V + f"T{i}" for i in range(n)]}),
        "types with duplicates": _ld({"@id": s, "@type": [V + "A", V + "B", V + "A"] * 4}),
        "types across same-@id objects": _ld(
            *[{"@id": s, "@type": V + f"T{i % 5}"} for i in range(n)]),
        "blank-node types": _ld({"@id": s, "@type": ["_:t1", "_:t2", "_:t1", V + "T"]}),
        "IRI objects": _ld({"@id": s, "p": [{"@id": V + f"o{i}"} for i in range(n)]}),
        "IRI objects with duplicates": _ld(
            {"@id": s, "p": [{"@id": V + f"o{i % 3}"} for i in range(n)]}),
        "IRI objects and literals mixed": _ld({"@id": s, "p": [
            {"@id": V + "o"}, "o", {"@id": V + "o"}, {"@value": "o"}, {"@id": V + "o2"}, "o"]}),
        "node object nested under its own parent id": _ld(
            {"@id": s, "p": [{"@id": s, "q": "x"}, {"@id": s, "q": "y"}, {"@id": s, "r": "z"}]}),
        "reverse: many items": _ld({"@id": s, "@reverse": {
            "q": [{"@id": V + f"i{i}"} for i in range(n)]}}),
        "reverse: same item ids and properties": _ld(
            *[{"@id": s, "@reverse": {"q": {"@id": V + "i"}, "r": {"@id": V + "i"}}}
              for _ in range(n)]),
        "reverse: one item under many parents": _ld(
            *[{"@id": V + f"s{i}", "@reverse": {"q": {"@id": V + "item"}}} for i in range(n)]),
        "reverse with described items": _ld({"@id": s, "@reverse": {
            "q": [{"@id": V + f"i{i}", "p": "x"} for i in range(5)]}},
            {"@id": V + "i1", "q": {"@id": s}}),
        "reverse and forward over the same pair": _ld(
            *[{"@id": V + f"i{i}", "q": {"@id": s}} for i in range(n)],
            {"@id": s, "@reverse": {"q": [{"@id": V + f"i{i}"} for i in range(n)]}}),
        "reverse with anonymous items": _ld({"@id": s, "@reverse": {"q": [{"p": 1}, {"p": 2}]}}),
        "reverse with blank labels": _ld({"@id": s, "@reverse": {"q": [
            {"@id": "_:x"}, {"@id": "_:x"}, {"@id": "_:y"}]}}),
        "included: same-@id objects": _ld({"@id": s, "@included": [
            {"@id": s, "p": f"v{i}"} for i in range(n)]}),
        "included inside a graph": _ld({"@id": V + "g", "@graph": [
            {"@id": s, "@included": [{"@id": s, "p": f"v{i}"} for i in range(n)]}]}),
        "named graph with same-@id nodes": _ld(
            {"@id": V + "g", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(n)]}),
        "the same graph name twice": _ld(
            {"@id": V + "g", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(5)]},
            {"@id": V + "g", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(5, 10)]}),
        "same node in default and named graph": _ld(
            *[{"@id": s, "p": f"v{i}"} for i in range(7)],
            {"@id": V + "g", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(7)]}),
        "nested named graphs": _ld({"@id": V + "g", "@graph": [
            {"@id": V + "h", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(n)]},
            {"@id": s, "p": _vals(6)}]}),
        "blank graph name": _ld(
            {"@id": "_:g", "@graph": [{"@id": s, "p": f"v{i}"} for i in range(n)]}),
        "graph container without a name": _ld(
            {"@graph": [{"@id": s, "p": f"v{i}"} for i in range(n)]}),
        "graph as an object": _ld({"@id": s, "p": {"@graph": [
            {"@id": V + "x", "q": f"v{i}"} for i in range(6)]}}),
        "graph container values": {"@context": {"@vocab": V, "p": {"@container": "@graph"}},
                                   "@id": s, "p": [{"q": f"v{i}"} for i in range(6)]},
        "one list": _ld({"@id": s, "p": {"@list": _vals(n)}}),
        "many lists under one property": _ld(
            *[{"@id": s, "p": {"@list": [f"v{i}"]}} for i in range(n)]),
        "lists and values together": _ld({"@id": s, "p": [
            {"@list": ["a"]}, "a", {"@list": ["a"]}, "b", {"@list": []}, "b", "c"]}),
        "a list of nodes with fat properties": _ld({"@id": s, "p": {"@list": [
            {"@id": V + "e", "q": _vals(6)}, {"@id": V + "e", "q": _vals(6, "w")}]}}),
        "a list in a list": _ld({"@id": s, "p": {"@list": [{"@list": ["a", "b"]}, "c"]}}),
        "list and set container": {"@context": {"@vocab": V, "p": {"@container": "@list"},
                                                "q": {"@container": "@set"}},
                                   "@id": s, "p": _vals(5), "q": _vals(8)},
        "an empty property": _ld({"@id": s, "p": [], "q": "x"}),
        "keywords and context terms": {"@context": {"@vocab": V, "@base": "https://b.example/",
                                                    "n": {"@id": V + "nest", "@nest": "@nest"}},
                                       "@id": "a", "@index": "i", "p": _vals(5)},
        "nested depth": _ld({"@id": s, "p": {"@id": V + "a", "p": {"@id": V + "b", "p": [
            {"@id": V + "c", "p": _vals(6)}, {"@id": V + "c", "p": _vals(6, "w")}]}}}),
        **_slot_shapes(),
        **_null_id_shapes(),
    }


@pytest.mark.parametrize("name", sorted(_corpus()))
def test_the_charge_is_never_below_what_pyld_really_does(name, pyld_calls):
    document = _corpus()[name]
    loader = document_loader(None)
    pyld_calls[0] = 0
    expanded = jsonld.expand(document, pyld_options(loader))
    during_expand = pyld_calls[0]
    pyld_calls[0] = 0
    try:
        jsonld.to_rdf(document, pyld_options(loader))
    except Exception:                  # noqa: BLE001 - pyld may fail after the merge was done
        pass
    real = pyld_calls[0] - during_expand            # the node-map merge alone
    assert _rdfc._conversion_cost(expanded, 10**9) >= real, name


def test_the_corpus_is_not_vacuous(pyld_calls):
    # shapes that are quadratic really do cost pyld calls, and the charge is exact for them
    loader = document_loader(None)
    for name in ("one fat property", "same-@id node objects, one value each", "N distinct types",
                 "IRI objects", "repeated blank label across objects",
                 "reverse: one item under many parents"):
        document = _corpus()[name]
        expanded = jsonld.expand(document, pyld_options(loader))
        pyld_calls[0] = 0
        jsonld.to_rdf(document, pyld_options(loader))
        assert pyld_calls[0] >= 14 * 13 // 2, name
        assert _rdfc._conversion_cost(expanded, 10**9) >= 14 * 13 // 2, name


_FUZZ_CONTEXT = {
    "@vocab": V,
    "lst": {"@container": "@list"}, "st": {"@container": "@set"},
    "idx": {"@container": "@index"}, "lang": {"@container": "@language"},
    "gr": {"@container": "@graph"}, "gid": {"@container": ["@graph", "@id"]},
    "idm": {"@container": "@id"}, "tym": {"@container": "@type"},
    "ref": {"@type": "@id"}, "voc": {"@type": "@vocab"}, "js": {"@type": "@json"},
    "rev": {"@reverse": V + "p"}, "revq": {"@reverse": V + "q", "@container": "@set"},
    "nst": "@nest", "inc": "@included",
    "sc": {"@id": V + "sc", "@context": {"p": V + "q", "q": V + "p"}},     # scoped contexts
    "T": {"@id": V + "T", "@context": {"r": {"@id": V + "p", "@type": "@id"}}},
    "en": {"@id": V + "p", "@language": "en"},
}
_FUZZ_ALPHABETS = {
    # (extra ids, extra forward properties, extra reverse properties)
    "plain": ([], [], []),
    "keywords": (["@a", "@foo", "@type", "@none", "@default", "@graph", "@id", "@merged"], [], []),
    "bnode-properties": ([], ["_:b0", "_:b1", "_:p"], ["_:b0", "_:b1", "_:p"]),
    "all": (["@a", "@type", "@none", "@default", "@merged"], ["_:b0", "_:p"], ["_:b0", "_:p"]),
}


class _Fuzz:
    """Seeded JSON-LD generator: blank labels that collide with pyld's own (``_:b0``), IRIs,
    relative ids, keyword and keyword-like ids, blank-node properties in forward and ``@reverse``
    position, named graphs (by IRI, blank node and keyword id), lists, reverse and nested
    properties, ``@included``, and the context features above."""

    def __init__(self, seed: int, alphabet: str) -> None:
        self.rng = random.Random(seed)
        ids, props, rprops = _FUZZ_ALPHABETS[alphabet]
        self.ids = ["_:a", "_:b", "_:b0", "_:b1", V + "x", V + "y", "rel", "urn:z"] + ids
        self.types = [V + "T", V + "U", "_:t", "_:b0", "T"]
        self.props = ["p", "q", "r", "sc", "en", "ref", "voc"] + props
        self.rprops = ["p", "q"] + rprops

    def scalar(self):
        return self.rng.choice(["a", "b", 1, True, 1.0, "1", False, float("nan"), "x"])

    def value(self, depth: int):
        r = self.rng
        kind = r.randrange(12 if depth > 0 else 6)
        if kind == 0:
            return self.scalar()
        if kind == 1:
            return {"@value": r.choice(["a", "b", 1]),
                    "@type": r.choice([V + "T", V + "U", "urn:t"])}
        if kind == 2:
            return {"@value": r.choice(["a", "b"]), "@language": r.choice(["en", "de"])}
        if kind == 3:
            return {"@id": r.choice(self.ids)}
        if kind == 4:
            return {"@list": [self.value(0) for _ in range(r.randrange(0, 4))]}
        if kind == 5:
            return {"@value": r.choice([{"a": 1}, [1], "s"]), "@type": "@json"}
        return self.node(depth - 1)

    def node(self, depth: int) -> dict:
        r = self.rng
        n: dict = {}
        if r.random() < 0.75:
            n["@id"] = r.choice(self.ids)
        if r.random() < 0.35:
            n["@type"] = [r.choice(self.types) for _ in range(r.randrange(1, 4))]
        for prop in r.sample(self.props, r.randrange(0, 4)):
            n[prop] = [self.value(depth) for _ in range(r.randrange(0, 6))]
        if r.random() < 0.12:
            n["lst"] = [self.value(0) for _ in range(r.randrange(0, 4))]
        if r.random() < 0.12:
            n["idx"] = {r.choice("ij"): [self.scalar() for _ in range(r.randrange(1, 3))]}
        if r.random() < 0.12:
            n["js"] = [r.choice([{"a": 1}, [1, 2], "s", True]) for _ in range(r.randrange(1, 4))]
        if depth > 0:
            if r.random() < 0.12:
                n["gr"] = [self.node(depth - 1) for _ in range(r.randrange(1, 3))]
            if r.random() < 0.12:
                n["gid"] = {r.choice(self.ids): [self.node(depth - 1)]}
            if r.random() < 0.12:
                n["idm"] = {r.choice(self.ids): self.node(depth - 1)}
            if r.random() < 0.10:
                n["tym"] = {r.choice(self.types): self.node(depth - 1)}
            if r.random() < 0.15:
                n["rev"] = [self.node(depth - 1) if r.random() < .5 else {"@id": r.choice(self.ids)}
                            for _ in range(r.randrange(1, 4))]
            if r.random() < 0.10:
                n["revq"] = [{"@id": r.choice(self.ids)} for _ in range(r.randrange(1, 4))]
            if r.random() < 0.15:
                n["nst"] = {r.choice(self.props): [self.value(depth - 1) for _ in range(3)]}
            if r.random() < 0.18:
                n["@graph"] = [self.node(depth - 1) for _ in range(r.randrange(0, 4))]
            if r.random() < 0.18:
                n["@included"] = [{**self.node(depth - 1), "p": [self.value(0)]}
                                  for _ in range(r.randrange(1, 3))]
            if r.random() < 0.10:
                n["inc"] = [{**self.node(depth - 1), "q": [self.value(0)]}
                            for _ in range(r.randrange(1, 3))]
            if r.random() < 0.2:
                n["@reverse"] = {r.choice(self.rprops): [
                    self.node(depth - 1) if r.random() < .4 else {"@id": r.choice(self.ids)}
                    for _ in range(r.randrange(1, 5))] for _ in range(r.randrange(1, 3))}
        return n

    def document(self) -> dict:
        body = {"@graph": [self.node(2) for _ in range(self.rng.randrange(1, 6))]}
        if self.rng.random() < 0.2:
            body = self.node(2)
        return {"@context": _FUZZ_CONTEXT, **body}


@pytest.mark.parametrize("alphabet", sorted(_FUZZ_ALPHABETS))
@pytest.mark.parametrize("seed", [426, 427])
def test_the_charge_is_never_below_pyld_over_a_seeded_fuzz(alphabet, seed, pyld_calls):
    # keyword-like ids, blank-node properties in both directions, graphs named by keywords and
    # blank nodes, scoped contexts: the classes a plain-alphabet fuzz never reached (#445 review)
    gen = _Fuzz(seed, alphabet)
    loader = document_loader(None)
    checked = nonzero = 0
    for _ in range(100):
        document = gen.document()
        try:
            pyld_calls[0] = 0
            expanded = jsonld.expand(document, pyld_options(loader))
            during_expand = pyld_calls[0]
            pyld_calls[0] = 0
            try:
                jsonld.to_rdf(document, pyld_options(loader))
            except Exception:              # noqa: BLE001 - pyld fails late: the merge was done
                pass
        except jsonld.JsonLdError:
            continue                       # not valid JSON-LD: pyld refuses it too
        real = pyld_calls[0] - during_expand
        charge = _rdfc._conversion_cost(expanded, 10**9)
        assert charge >= real, (alphabet, seed, charge, real, json.dumps(document))
        checked += 1
        nonzero += real > 0
    assert checked > 90 and nonzero > 50      # the generator reaches the merge path


def test_the_charge_of_one_fat_property_is_exact():
    loader = document_loader(None)
    for n in (2, 10, 57):
        expanded = jsonld.expand(_ld({"@id": V + "s", "p": _vals(n)}), pyld_options(loader))
        assert _rdfc._conversion_cost(expanded, 10**9) == n * (n - 1) // 2


@pytest.mark.parametrize("name", sorted(_slot_shapes()))
def test_slot_shapes_are_charged_exactly(name, pyld_calls):
    # the partition into (graph, subject, property) slots must be pyld's own: a slot folded
    # into another (or split) turns the duplicate shortcut into an under-count. Exact equality,
    # not >=, so that a mutant folding any of these slots fails by name (the review's m4,
    # "fold every named graph into its parent", charged 665 where pyld made 6 634).
    document = _slot_shapes()[name]
    loader = document_loader(None)
    expanded = jsonld.expand(document, pyld_options(loader))
    pyld_calls[0] = 0
    try:
        jsonld.to_rdf(document, pyld_options(loader))
    except Exception:                      # noqa: BLE001 - pyld may fail after the merge
        pass
    assert _rdfc._conversion_cost(expanded, 10**9) == pyld_calls[0], name
    assert pyld_calls[0] > 0, name         # the shape really reaches the merge


@pytest.mark.parametrize("name", sorted(_null_id_shapes()))
def test_null_id_shapes_are_charged_at_least_what_pyld_does_and_not_zero(name, pyld_calls):
    document = _null_id_shapes()[name]
    loader = document_loader(None)
    expanded = jsonld.expand(document, pyld_options(loader))
    assert '"@id": null' in json.dumps(expanded), name       # the shape is what it claims
    pyld_calls[0] = 0
    try:
        jsonld.to_rdf(document, pyld_options(loader))
    except Exception:                      # noqa: BLE001 - pyld fails after the merge
        pass
    charge = _rdfc._conversion_cost(expanded, 10**9)
    assert charge >= pyld_calls[0], name
    if name not in ("null id: id map with keyword-like keys", "null id: with forward values"):
        assert charge > 50, name       # (forward values of a null-id node are never stored)


def test_the_conversion_gets_the_document_as_written_not_its_expanded_form():
    # On pyld 3.x a second expansion is not the identity: it resolves a relative @id that
    # "@base": null kept relative, so the signed dataset changes (the forged-type document of
    # test_dcql_type_values.py, GHSA-vrxg-57v4-85mc). to_rdf therefore expands the document
    # itself, and the result is byte-identical to pyld's normalize.
    document = {"@context": [VC2, {"@base": None}], "id": "forged",
                "type": ["VerifiableCredential"],
                "credentialSubject": {"id": "did:example:s", "name": "x"}}
    loader = document_loader(None)
    expected = jsonld.normalize(
        document, pyld_options(loader, algorithm="URDNA2015", format="application/n-quads"))
    assert _rdfc.canonicalize_nquads(document, loader) == expected
    # (on pyld 3.x, to_rdf(jsonld.expand(document)) differs from to_rdf(document) for this
    # document; 2.0.4 does not show it, which is no reason to hand it the expanded form)


def test_a_document_with_a_keyword_like_id_still_converts():
    document = {"@context": {"@vocab": V}, "@id": "@a", "https://v.example/p": "v"}
    loader = document_loader(None)
    expected = jsonld.normalize(
        document, pyld_options(loader, algorithm="URDNA2015", format="application/n-quads"))
    assert _rdfc.canonicalize_nquads(document, loader) == expected


# --------------------------------------------------------------------------- #
# Negatives: the shapes of the issue, refused typed and before pyld compares anything
# --------------------------------------------------------------------------- #

def _wrap(subject, extra=None, cryptosuite="eddsa-rdfc-2022", issuer=_ISSUER) -> dict:
    return {"@context": CTX, "type": ["VerifiableCredential"], "issuer": issuer,
            "credentialSubject": subject, **(extra or {}),
            "proof": {"type": "DataIntegrityProof", "cryptosuite": cryptosuite,
                      "created": "2020-01-01T00:00:00Z",
                      "verificationMethod": f"{issuer}#{issuer[len('did:key:'):]}",
                      "proofPurpose": "assertionMethod", "proofValue": "z" + "1" * 86}}


def _shapes(n: int) -> dict[str, dict]:
    p = "p"                      # a term under @vocab: compacted form, as ecdsa requires
    return {
        "one property": _wrap({"id": "did:example:s", p: _vals(n)}),
        "same-id node objects": _wrap([{"id": "did:example:s", p: f"v{i}"} for i in range(n)]),
        "distinct types": _wrap({"id": "did:example:s"},
                                {"type": ["VerifiableCredential"] + [f"T{i}" for i in range(n)]}),
        "IRI objects": _wrap(
            {"id": "did:example:s", p: [{"id": f"did:example:o{i}"} for i in range(n)]}),
        "bundled term": _wrap({"id": "did:example:s"}, {"name": _vals(n)}),
        "blank labels": _wrap([{"id": "_:a", p: f"v{i}"} for i in range(n)]),
        "reverse": _wrap([{"id": f"did:example:s{i}", "@reverse": {"q": {"id": "did:example:item"}}}
                          for i in range(n)]),
        "included": {"@context": CTX, "type": ["VerifiableCredential"], "issuer": _ISSUER,
                     "credentialSubject": {"id": "did:example:s"},
                     "@included": [{"id": "did:example:s", p: f"v{i}"} for i in range(n)],
                     "proof": _wrap({})["proof"]},
    }


@pytest.mark.parametrize("shape", sorted(_shapes(3)))
@pytest.mark.parametrize("cryptosuite", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_hostile_shapes_are_refused_typed_before_pyld_compares_anything(
        shape, cryptosuite, pyld_calls):
    doc = _shapes(HOSTILE_N)[shape]
    if cryptosuite == "ecdsa-rdfc-2019":     # the suite checks the key's curve first
        did = _p256_key()[1]
        doc["issuer"] = did
        doc["proof"].update(cryptosuite=cryptosuite, verificationMethod=f"{did}#{did[8:]}")
    with pytest.raises(ProofMalformed) as ei:
        verify_credential(doc)
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    assert "conversion" in str(ei.value)               # names what was bounded
    assert "v1234" not in str(ei.value) and "v.example" not in str(ei.value)   # no document text
    assert pyld_calls[0] == 0              # refused by the count, pyld never ran the quadratic part


def test_nan_values_that_never_compare_equal_are_charged_in_full(pyld_calls):
    # pyld finds NaN unequal to itself, so N of them cost N**2/2 and a key by printed value
    # would charge N
    doc = _wrap({"id": "did:example:s", "p": [float("nan")] * HOSTILE_N})
    with pytest.raises(ProofMalformed) as ei:
        verify_credential(doc)
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    assert pyld_calls[0] == 0


def test_the_budget_is_what_stops_it_not_the_size_of_the_document(pyld_calls):
    # the same number of values under one property per subject, below the ceiling, is allowed
    # through to the signature check (and then rejected as the garbage it is)
    with pytest.raises(SignatureInvalid):
        verify_credential(_wrap({"id": "did:example:s", V + "p": _vals(HOSTILE_N // 3)}))
    assert pyld_calls[0] > 0


def test_verify_many_hostile_item_is_a_per_item_error_and_neighbours_verify():
    sk, did, vm = _ed_key()
    good = DataIntegrityProofSuite().add_proof(
        {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:s", "name": "Ada"}},
        signing_key=sk, verification_method=vm)
    hostile = _shapes(HOSTILE_N)["one property"]
    results = verify_many([good, hostile, good, _shapes(HOSTILE_N)["same-id node objects"]],
                          policy=VerificationPolicy())
    assert [r.error is None for r in results] == [True, False, True, False]
    assert type(results[1].error).__name__ == BUDGET_ERROR
    assert type(results[3].error).__name__ == BUDGET_ERROR


def test_ldp_vc_presentation_with_a_hostile_credential_is_refused_typed(pyld_calls):
    from openvc.openid4vp import verify_vp_token
    hostile = _shapes(HOSTILE_N)["one property"]
    vp = {"@context": [VC2], "type": ["VerifiablePresentation"], "holder": _ISSUER,
          "verifiableCredential": [hostile],
          "proof": {**_wrap({})["proof"], "proofPurpose": "authentication",
                    "challenge": "n1", "domain": "x509_san_dns:verifier.example"}}
    with pytest.raises(ProofMalformed) as ei:
        verify_vp_token({"c1": [vp]},
                        dcql_query={"credentials": [{"id": "c1", "format": "ldp_vc"}]},
                        nonce="n1", client_id="x509_san_dns:verifier.example")
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    assert pyld_calls[0] == 0


def test_ecdsa_sd_refuses_a_hostile_document_on_every_conversion_path(pyld_calls):
    sk = P256SigningKey.generate(kid="did:key:zDnaeykfoobar#zDnaeykfoobar")
    suite = EcdsaSdProofSuite()
    kid = "did:key:zDnaeykfoobar#zDnaeykfoobar"
    base_doc = {"@context": CTX, "type": ["VerifiableCredential"], "issuer": "did:example:issuer",
                "validFrom": "2026-01-01T00:00:00Z",
                "credentialSubject": {"id": "did:example:s", "name": "Ada"}}
    hostile_subject = {"id": "did:example:s", "p": _vals(HOSTILE_N)}
    # signing side
    with pytest.raises(ProofMalformed) as ei:
        suite.add_base_proof({**base_doc, "credentialSubject": hostile_subject}, signing_key=sk,
                             verification_method=kid, mandatory_pointers=["/issuer"])
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    # holder side, then the verifier on a derived credential whose revealed document was swapped
    base = suite.add_base_proof(base_doc, signing_key=sk, verification_method=kid,
                                mandatory_pointers=["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    derived["credentialSubject"] = {**derived["credentialSubject"], **hostile_subject}
    pyld_calls[0] = 0
    with pytest.raises(ProofMalformed) as ei:
        suite.verify(derived, public_key_jwk=sk.public_jwk())
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    assert pyld_calls[0] == 0


# --------------------------------------------------------------------------- #
# The documents of the #445 review (F1-F3): every one passed the first version of the count
# --------------------------------------------------------------------------- #

def _review_bodies() -> dict[str, dict]:
    """Bodies added to a credential whose only context is the VC v2 one."""
    return {
        "F1 null-id nodes, one type each (@included)": {"@included": [
            {"id": "@a", "type": f"urn:t:{i}"} for i in range(1600)]},
        "F1 null-id node as reverse item of N parents": {"@included": [
            {"id": f"urn:s:{i}", "@reverse": {"urn:q": {"id": "@a"}}} for i in range(1600)]},
        "F1 null-id graph names": {"@included": [
            {"id": "@a", "@graph": [{"id": "urn:s", "urn:p": f"v{i}"}]} for i in range(1600)]},
        "F1 null-id nodes in a list": {"credentialSubject": {"id": "did:example:s", "urn:p": {
            "@list": [{"id": "@a", "type": f"urn:t:{i}"} for i in range(1600)]}}},
        "F2 graph named by the keyword @type": {"@included": [
            {"id": "urn:s", "urn:p": "v"},
            {"id": "@type", "@graph": [{"id": "urn:s", "urn:p": _padded(400, 3000)}]}]},
        "F2 graph named by the keyword @none": {"@included": [
            {"id": "urn:s", "urn:p": "v"},
            {"id": "@none", "@graph": [{"id": "urn:s", "urn:p": _padded(400, 3000)}]}]},
        "F3 blank-node property, forward against reverse": {"@included": [
            {"id": "urn:x", "@reverse": {"_:q": {"id": "urn:s"}}},
            {"id": "urn:s", "_:q": [{"@list": []}] * 400 + [{"id": "urn:x"}] * 3000}]},
    }


def _vc2_credential(body: dict, cryptosuite: str) -> dict:
    issuer = _p256_key()[1] if cryptosuite == "ecdsa-rdfc-2019" else _ISSUER
    doc = {"@context": [VC2], "type": ["VerifiableCredential"], "issuer": issuer,
           "credentialSubject": {"id": "did:example:s"}, **body,
           "proof": {"type": "DataIntegrityProof", "cryptosuite": cryptosuite,
                     "created": "2020-01-01T00:00:00Z",
                     "verificationMethod": f"{issuer}#{issuer[len('did:key:'):]}",
                     "proofPurpose": "assertionMethod", "proofValue": "z" + "1" * 86}}
    return doc


@pytest.mark.parametrize("shape", sorted(_review_bodies()))
@pytest.mark.parametrize("cryptosuite", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_review_documents_are_refused_before_pyld_compares_anything(
        shape, cryptosuite, pyld_calls):
    doc = _vc2_credential(_review_bodies()[shape], cryptosuite)
    with pytest.raises(ProofMalformed) as ei:
        verify_credential(doc)
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    assert pyld_calls[0] == 0


@pytest.mark.parametrize("shape", sorted(_review_bodies()))
def test_review_documents_are_refused_on_ecdsa_sd_too(shape, pyld_calls):
    kid = "did:key:zDnaeykfoobar#zDnaeykfoobar"
    sk = P256SigningKey.generate(kid=kid)
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        {"@context": [VC2], "type": ["VerifiableCredential"], "issuer": "did:example:issuer",
         "validFrom": "2026-01-01T00:00:00Z",
         "credentialSubject": {"id": "did:example:s", "name": "Ada"}},
        signing_key=sk, verification_method=kid, mandatory_pointers=["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    derived.update(_review_bodies()[shape])
    pyld_calls[0] = 0
    with pytest.raises(ProofMalformed) as ei:
        suite.verify(derived, public_key_jwk=sk.public_jwk())
    assert type(ei.value).__name__ == BUDGET_ERROR, ei.value
    assert pyld_calls[0] == 0


def test_the_message_says_the_budget_is_summed_over_the_document_and_quotes_nothing():
    doc = _vc2_credential({"@included": [
        {"id": "urn:s", "urn:p": [f"marker-{i}" for i in range(1500)]}]}, "eddsa-rdfc-2022")
    with pytest.raises(ProofMalformed) as ei:
        verify_credential(doc)
    message = str(ei.value)
    assert "summed over the whole document" in message and "1000000" in message
    assert "marker" not in message and "urn:" not in message


def test_a_presentation_of_credentials_is_counted_per_document():
    # the budget is per converted document: three credentials of 1 000 distinct values each cost
    # 3 x 499 500 comparisons in one presentation and none of them is refused
    values = [f"v{i}" for i in range(1000)]
    one = _vc2_credential({"credentialSubject": {"id": "did:example:s", "urn:p": values}},
                          "eddsa-rdfc-2022")
    loader = document_loader(None)
    costs = [_rdfc._conversion_cost(jsonld.expand(d, pyld_options(loader)), 10**9)
             for d in (one, one, one)]
    assert costs == [1000 * 999 // 2] * 3 and sum(costs) > _rdfc.MAX_CONVERSION_COMPARISONS
    for d in (one, one, one):
        _rdfc.canonicalize_nquads({k: v for k, v in d.items() if k != "proof"}, loader)


# --------------------------------------------------------------------------- #
# Positives: what verified before still does
# --------------------------------------------------------------------------- #

def test_the_controls_still_reach_the_signature_check():
    p = V + "p"
    controls = {
        "identical values": _wrap({"id": "did:example:s", p: ["x"] * 8000}),
        "one value per property": _wrap({"id": "did:example:s",
                                         **{V + f"p{i}": "v" for i in range(8000)}}),
    }
    for name, doc in controls.items():
        with pytest.raises(SignatureInvalid):
            verify_credential(doc)


def test_a_signed_credential_with_a_few_hundred_values_under_one_property_verifies():
    sk, did, vm = _ed_key()
    skp, didp, vmp = _p256_key()
    for suite, key, issuer, method in ((DataIntegrityProofSuite(), sk, did, vm),
                                       (EcdsaRdfcProofSuite(), skp, didp, vmp)):
        signed = suite.add_proof(
            {"@context": CTX, "type": ["VerifiableCredential"], "issuer": issuer,
             "credentialSubject": {"id": "did:example:s", "p": _vals(300),
                                   "q": [{"id": f"did:example:o{i}"} for i in range(300)]}},
            signing_key=key, verification_method=method)
        assert verify_credential(signed)


def test_the_ceiling_has_four_times_headroom_over_every_rdf_fixture():
    # the W3C Data Integrity vectors and the ecdsa-sd interop documents: measured at 2 comparisons
    loader = document_loader({
        "https://www.w3.org/ns/credentials/examples/v2": json.loads(
            (FIXTURES / "vc_di_eddsa" / "credentials-examples-v2.json").read_text())})
    worst = measured = 0
    for path in sorted(FIXTURES.glob("vc_di_*/**/*.json")) + sorted(
            FIXTURES.glob("ecdsa_sd/**/*.json")):
        document = json.loads(path.read_text())
        if not isinstance(document, dict) or "@context" not in document:
            continue
        try:
            expanded = jsonld.expand(document, pyld_options(loader))
        except jsonld.JsonLdError:             # e.g. an example context the loader lacks
            continue
        worst = max(worst, _rdfc._conversion_cost(expanded, 10**9))
        measured += 1
    assert measured >= 6, measured             # not vacuous: the fixtures were really read
    assert worst * 4 <= _rdfc.MAX_CONVERSION_COMPARISONS
    # a credential with 300 values under one property is far from it, as are the #381 tests'
    # own 1 000-node documents (500 000 comparisons: 2x, not 4x, and they are synthetic)
    assert 300 * 299 // 2 * 4 <= _rdfc.MAX_CONVERSION_COMPARISONS


def test_the_ceiling_is_pinned():
    assert _rdfc.MAX_CONVERSION_COMPARISONS == 1_000_000
    assert issubclass(_rdfc.CanonicalizationBudgetExceeded, ProofMalformed)


def test_output_is_byte_identical_to_pyld_normalize_over_the_corpus():
    loader = document_loader(None)
    for name, document in _corpus().items():
        try:
            expected = jsonld.normalize(
                document, pyld_options(loader, algorithm="URDNA2015", format="application/n-quads"))
        except Exception:                      # noqa: BLE001 - pyld cannot canonicalize it
            continue
        assert _rdfc.canonicalize_nquads(document, loader) == expected, name


def test_the_w3c_goldens_are_byte_identical():
    examples = {"https://www.w3.org/ns/credentials/examples/v2": json.loads(
        (FIXTURES / "vc_di_eddsa" / "credentials-examples-v2.json").read_text())}
    vector = json.loads((FIXTURES / "vc_di_eddsa" / "signedDataInt.json").read_text())
    unsecured = {k: v for k, v in vector.items() if k != "proof"}
    loader = document_loader(examples)
    expected = jsonld.normalize(
        unsecured, pyld_options(loader, algorithm="URDNA2015", format="application/n-quads"))
    assert _canonize(unsecured, loader) == expected.encode("utf-8")


def test_a_document_pyld_cannot_expand_still_raises_pyld_s_own_error():
    document = {"@context": {"@vocab": V}, "@id": "x", "@reverse": {"q": "not a node"}}
    with pytest.raises(jsonld.JsonLdError):
        _rdfc.canonicalize_nquads(document, document_loader(None))
