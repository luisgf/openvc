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
    }


@pytest.mark.parametrize("name", sorted(_corpus()))
def test_the_charge_is_never_below_what_pyld_really_does(name, pyld_calls):
    document = _corpus()[name]
    loader = document_loader(None)
    pyld_calls[0] = 0
    expanded = jsonld.expand(document, pyld_options(loader))
    during_expand = pyld_calls[0]
    pyld_calls[0] = 0
    jsonld.to_rdf(document, pyld_options(loader))
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


def _fuzz_value(rng: random.Random, depth: int):
    ids = ["_:a", "_:b", V + "x", V + "y"]
    kind = rng.randrange(14 if depth > 0 else 6)
    if kind == 0:
        return rng.choice(["a", "b", 1, True, 1.0])
    if kind == 1:
        return {"@value": rng.choice(["a", "b"]), "@type": rng.choice([V + "T", V + "U"])}
    if kind == 2:
        return {"@value": rng.choice(["a", "b"]), "@language": rng.choice(["en", "de"])}
    if kind == 3:
        return {"@id": rng.choice(ids)}
    if kind == 4:
        return {"@list": [_fuzz_value(rng, 0) for _ in range(rng.randrange(0, 4))]}
    if kind == 5:
        return {"@id": rng.choice(ids)} if rng.random() < 0.5 else {"@value": "z"}
    return _fuzz_node(rng, depth - 1)


def _fuzz_node(rng: random.Random, depth: int) -> dict:
    node: dict = {}
    if rng.random() < 0.8:
        node["@id"] = rng.choice(["_:a", "_:b", "_:c", V + "x", V + "y"])
    if rng.random() < 0.3:
        node["@type"] = [rng.choice([V + "T", V + "U", "_:t"]) for _ in range(rng.randrange(1, 4))]
    for prop in rng.sample(["p", "q", "r"], rng.randrange(0, 4)):
        node[prop] = [_fuzz_value(rng, depth) for _ in range(rng.randrange(0, 6))]
    if depth > 0 and rng.random() < 0.2:
        node["@graph"] = [_fuzz_node(rng, depth - 1) for _ in range(rng.randrange(0, 4))]
    if depth > 0 and rng.random() < 0.2:
        node["@included"] = [_fuzz_node(rng, depth - 1) for _ in range(rng.randrange(1, 3))]
    if depth > 0 and rng.random() < 0.2:
        node["@reverse"] = {rng.choice(["p", "q"]): [
            {"@id": rng.choice(["_:a", "_:b", V + "x", V + "y"]), **(
                {"p": [_fuzz_value(rng, 0)]} if rng.random() < 0.3 else {})}
            for _ in range(rng.randrange(1, 5))]}
    return node


def test_the_charge_is_never_below_pyld_over_a_seeded_fuzz(pyld_calls):
    rng = random.Random(426)
    loader = document_loader(None)
    checked = nonzero = 0
    for _ in range(600):
        document = {"@context": {"@vocab": V},
                    "@graph": [_fuzz_node(rng, 3) for _ in range(rng.randrange(1, 6))]}
        try:
            pyld_calls[0] = 0
            expanded = jsonld.expand(document, pyld_options(loader))
            during_expand = pyld_calls[0]
            pyld_calls[0] = 0
            jsonld.to_rdf(document, pyld_options(loader))
        except jsonld.JsonLdError:
            continue                                # not valid JSON-LD: pyld refuses it too
        real = pyld_calls[0] - during_expand
        charge = _rdfc._conversion_cost(expanded, 10**9)
        assert charge >= real, (charge, real, json.dumps(document))
        checked += 1
        nonzero += real > 0
    assert checked > 200 and nonzero > 100         # the generator reaches the merge path


def test_the_charge_of_one_fat_property_is_exact():
    loader = document_loader(None)
    for n in (2, 10, 57):
        expanded = jsonld.expand(_ld({"@id": V + "s", "p": _vals(n)}), pyld_options(loader))
        assert _rdfc._conversion_cost(expanded, 10**9) == n * (n - 1) // 2


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
