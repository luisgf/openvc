"""
tests/test_ecdsa_sd_nquads_parse.py — ``ecdsa-sd-2023`` parses N-Quads in linear time
before the signature check (issue #447).

``ecdsa_sd._canonicalize`` used to hand the document's N-Quads to pyld's ``parse_nquads``,
which keeps each graph's triples unique by comparing every new triple with all those already
parsed (N distinct quads cost N**2/2 comparisons), and ``URDNA2015.main`` parsed the
canonical output a second time. A derived credential with N one-valued properties (or N
subjects with one property each) cost 10 s at 80 KB before the signature was looked at, and
neither RDF budget counts it. The parse is now one pyld ``parse_nquads`` per line plus a set
for the uniqueness, and ``main`` is asked for text.

The requirement that outranks the rest: the canonical lines and the blank-node label map are
byte-identical to what the old code returned, for every input, because they feed the signed
hash. The differential tests keep a copy of the old implementation (``_old_canonicalize``)
and compare it with the new one over a seeded corpus; the cost tests count pyld's triple
comparisons instead of timing anything. Helpers are self-contained (tests/ is not a package).
"""
from __future__ import annotations

import asyncio
import copy
import random

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

pytest.importorskip("pyld")

import pyld.jsonld as pyld_jsonld  # noqa: E402

from openvc import verify_credential, verify_credential_async  # noqa: E402
from openvc.keys import P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.openid4vp import verify_vp_token  # noqa: E402
from openvc.proof import ecdsa_sd  # noqa: E402
from openvc.proof._rdfc import new_canonicalizer  # noqa: E402
from openvc.proof.contexts import document_loader  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite, _canonicalize, _to_nquads  # noqa: E402
from openvc.proof.errors import SignatureInvalid  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
LOADER = document_loader(None)


# -- the implementation this change replaces, kept verbatim as the oracle ----------------- #

def _old_canonicalize(nquads_text):
    from pyld.jsonld import JsonLdProcessor
    issuer = new_canonicalizer()
    canonical = issuer.main(JsonLdProcessor.parse_nquads(nquads_text), {})
    text = JsonLdProcessor.to_nquads(canonical)
    lines = sorted(ln for ln in text.split("\n") if ln)
    return lines, dict(issuer.canonical_issuer.existing)


def _outcome(fn, text):
    try:
        return ("ok", fn(text))
    except Exception as exc:                                   # noqa: BLE001
        return ("raised", type(exc))


# -- counting pyld's triple comparisons ---------------------------------------------------- #

@pytest.fixture
def comparisons(monkeypatch):
    """A counter of pyld's per-triple uniqueness comparisons, on pyld 3.x (a module function
    in ``pyld.nquads``) and on 2.0.4 (a static method of ``JsonLdProcessor``)."""
    counter = {"n": 0}
    patched = False
    try:
        import pyld.nquads as nq
        original = nq._compare_rdf_triples

        def counted(a, b):
            counter["n"] += 1
            return original(a, b)
        monkeypatch.setattr(nq, "_compare_rdf_triples", counted)
        patched = True
    except (ImportError, AttributeError):
        pass
    if hasattr(pyld_jsonld.JsonLdProcessor, "_compare_rdf_triples"):
        original_static = pyld_jsonld.JsonLdProcessor._compare_rdf_triples

        def counted_static(a, b):
            counter["n"] += 1
            return original_static(a, b)
        monkeypatch.setattr(pyld_jsonld.JsonLdProcessor, "_compare_rdf_triples",
                            staticmethod(counted_static))
        patched = True
    assert patched, "no pyld comparison helper found to count"
    return counter


# -- parties ------------------------------------------------------------------------------- #

def _b36(i):
    digits = ""
    while True:
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[i % 36] + digits
        i //= 36
        if not i:
            return digits


@pytest.fixture(scope="module")
def derived():
    private = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(private, kid="_").public_key_raw(compressed=True)
    did = "did:key:" + encode_multibase(bytes([0x80, 0x24]) + raw)
    vm = f"{did}#{did[8:]}"
    suite = EcdsaSdProofSuite()
    credential = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
                  "validFrom": "2026-01-01T00:00:00Z",
                  "credentialSubject": {"id": "did:example:s", "name": "Ada"}}
    base = suite.add_base_proof(credential, signing_key=P256SigningKey(private, kid=vm),
                                verification_method=vm, mandatory_pointers=["/issuer"])
    return suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])


def _props(derived, n):
    doc = copy.deepcopy(derived)
    doc["credentialSubject"] = {**doc["credentialSubject"],
                                **{f"a:{_b36(i)}": 0 for i in range(n)}}
    return doc


def _subjects(derived, n):
    doc = copy.deepcopy(derived)
    doc["@included"] = [{"id": f"a:{_b36(i)}", "a:p": 0} for i in range(n)]
    return doc


SHAPES = [pytest.param(_props, id="n-one-valued-properties"),
          pytest.param(_subjects, id="n-subjects-one-property")]
N = 1500                     # N**2/2 = 1.1 million comparisons on the old code


def _verify_vp(doc):
    return verify_vp_token(
        {"q": [doc]},
        dcql_query={"credentials": [{"id": "q", "format": "ldp_vc",
                                     "require_cryptographic_holder_binding": False}]},
        nonce=NONCE, client_id=CLIENT_ID)


# -- 1. the cost: counted, not timed --------------------------------------------------------- #

def test_the_counter_sees_the_old_quadratic_scan(derived, comparisons):
    """Control: the same document through the old implementation hits the counter ~N**2/2
    times, so the bounds below are not vacuous."""
    doc = _props(derived, 300)
    unsecured = {k: v for k, v in doc.items() if k != "proof"}
    _old_canonicalize(_to_nquads(unsecured, LOADER))
    assert comparisons["n"] > 300 * 300 // 4


@pytest.mark.parametrize("make", SHAPES)
def test_verify_credential_is_not_quadratic(derived, comparisons, make):
    with pytest.raises(SignatureInvalid) as info:
        verify_credential(make(derived, N))
    assert type(info.value) is SignatureInvalid
    assert comparisons["n"] < N


@pytest.mark.parametrize("make", SHAPES)
def test_verify_credential_async_is_not_quadratic(derived, comparisons, make):
    async def run():
        return await verify_credential_async(make(derived, N))
    with pytest.raises(SignatureInvalid) as info:
        asyncio.run(run())
    assert type(info.value) is SignatureInvalid
    assert comparisons["n"] < N


@pytest.mark.parametrize("make", SHAPES)
def test_a_bare_ldp_vc_answer_is_not_quadratic(derived, comparisons, make):
    with pytest.raises(SignatureInvalid) as info:
        _verify_vp(make(derived, N))
    assert type(info.value) is SignatureInvalid
    assert comparisons["n"] < N


def test_the_control_derived_credential_still_verifies(derived):
    assert verify_credential(derived) is not None
    assert _verify_vp(derived).for_query("q")


# -- 2. byte identity with the old implementation -------------------------------------------- #

def _fuzz_document(rng):
    """A JSON-LD document in near-expanded form: every position that reaches N-Quads."""
    alphabet = ['a', 'Z', '0', ' ', '"', '\\', '\n', '\r', '\t', '\x01', '\x0b', '\x7f',
                'é', '\u2028', '\U0001F600', '<', '>', '#', '/', ':', '@', '{', '}', '.',
                '\\n', '\\"', '\\\\']

    def text():
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))

    def bnode():
        return f"_:b{rng.randint(0, 5)}"

    def node_id():
        return rng.choice([bnode(), bnode(), f"http://example.org/n{rng.randint(0, 4)}"])

    def value():
        kind = rng.randint(0, 9)
        if kind == 0:
            return {"@value": text()}
        if kind == 1:
            return {"@value": text(), "@language": rng.choice(["en", "en-US", "de-CH-1996", "x"])}
        if kind == 2:
            return {"@value": text(), "@type": rng.choice([
                "http://www.w3.org/2001/XMLSchema#date", "http://example.org/dt",
                "http://www.w3.org/2001/XMLSchema#string"])}
        if kind == 3:
            return {"@value": rng.randint(-5, 5)}
        if kind == 4:
            return {"@value": rng.choice([0.1, 1.5e300, -0.0, 12345678901234567890.0, 1e-7])}
        if kind == 5:
            return {"@value": rng.choice([True, False])}
        if kind == 6:
            return {"@value": rng.choice([{"a": [1, 2, {"b": text()}]}, [text(), 1], {}]),
                    "@type": "@json"}
        if kind == 7:
            return {"@id": node_id()}
        return {"@value": text()}

    def node(depth):
        n = {"@id": node_id()}
        if rng.random() < 0.3:
            n["@type"] = [f"http://example.org/T{rng.randint(0, 2)}"]
        for _ in range(rng.randint(0, 4)):
            vals = [value() for _ in range(rng.randint(1, 3))]
            if depth < 2 and rng.random() < 0.3:
                vals.append(node(depth + 1))
            n[f"http://example.org/p{rng.randint(0, 3)}"] = vals
        return n

    nodes = [node(0) for _ in range(rng.randint(1, 4))]
    if rng.random() < 0.5:
        nodes = nodes + copy.deepcopy(nodes[: rng.randint(1, len(nodes))])      # duplicate quads
    doc = []
    for n in nodes:
        r = rng.random()
        if r < 0.3:
            doc.append({"@id": node_id(), "@graph": [n]})                       # named graph
        elif r < 0.4:
            doc.append({"@id": node_id(), "@graph": []})                        # empty graph
        else:
            doc.append(n)
    return doc


def _corpus(seed, count):
    rng = random.Random(seed)
    return [_fuzz_document(rng) for _ in range(count)]


def test_fuzz_corpus_canonicalizes_byte_identically():
    produced = 0
    for doc in _corpus(447, 600):
        try:
            text = _to_nquads(doc, LOADER)
        except Exception:                                     # noqa: BLE001
            continue                                          # pyld refused the document itself
        produced += 1
        old, new = _outcome(_old_canonicalize, text), _outcome(_canonicalize, text)
        assert new == old, text
        # the same text de-skolemized and with a skolem IRI in play, as the issuer side feeds it
        skolem = text.replace("_:b1", "<urn:bnid:b1>")
        deskolem = ecdsa_sd._deskolemize_nquads(skolem)
        assert _outcome(_canonicalize, deskolem) == _outcome(_old_canonicalize, deskolem)
    assert produced > 450                                     # the corpus is mostly valid


def test_fuzz_corpus_covers_the_shapes_it_claims():
    seen = {"lang": 0, "typed": 0, "graph": 0, "bnode_graph": 0, "dup": 0, "escape": 0,
            "nonbmp": 0, "json": 0}
    for doc in _corpus(447, 600):
        try:
            text = _to_nquads(doc, LOADER)
        except Exception:                                     # noqa: BLE001
            continue
        lines = [ln for ln in text.split("\n") if ln]
        seen["lang"] += any('"@' in ln for ln in lines)
        seen["typed"] += any('"^^<' in ln for ln in lines)
        seen["graph"] += any(ln.endswith("> .") and ln.count("<") >= 4 for ln in lines)
        seen["bnode_graph"] += any(" _:" in ln[ln.rfind('"') + 1:] for ln in lines if '"' in ln)
        seen["dup"] += len(lines) != len(set(lines))
        seen["escape"] += any("\\\\" in ln or '\\"' in ln or "\\n" in ln for ln in lines)
        seen["nonbmp"] += any(ord(c) > 0xFFFF for c in text)
        seen["json"] += "rdf-syntax-ns#JSON" in text
    assert all(v > 0 for v in seen.values()), seen


@pytest.mark.parametrize("literal", [
    "\\n", "\\", "\\\\", "\\\"", '"', "\n", "\r\n", "\t", "a\\tb", "\\u00e9",
    "\x00\x1f", "\U0001F600",
    "\u2028", "\u0085", "\x0b", "\x1c",
])
def test_literals_survive_pyld_escaping_quirks_identically(literal):
    """pyld's unescape is not the inverse of its escape (backslash + n comes back as
    backslash + line feed); the old code applied it twice and so does the new one."""
    doc = [{"@id": "http://example.org/s", "http://example.org/p": [{"@value": literal}]}]
    text = _to_nquads(doc, LOADER)
    assert _outcome(_canonicalize, text) == _outcome(_old_canonicalize, text)
    # and the literal reaches the output (or the same refusal) in both
    kind, _ = _outcome(_canonicalize, text)
    assert kind in ("ok", "raised")


def test_the_unescape_quirk_is_real_so_the_test_above_means_something():
    doc = [{"@id": "http://example.org/s", "http://example.org/p": [{"@value": "\\n"}]}]
    lines, _ = _canonicalize(_to_nquads(doc, LOADER))
    assert lines == _old_canonicalize(_to_nquads(doc, LOADER))[0]


def test_duplicate_quads_are_dropped_as_before():
    text = ('<http://e/s> <http://e/p> "x" .\n' * 3
            + '<http://e/s> <http://e/p> "x"@en .\n<http://e/s> <http://e/p> "x"@en .\n'
            + '<http://e/s> <http://e/p> "x" <http://e/g> .\n'
            + '<http://e/s> <http://e/p> "x" <http://e/g> .\n'
            + '<http://e/s> <http://e/p> "x" _:g .\n<http://e/s> <http://e/p> "x" _:g .\n')
    lines, id_map = _canonicalize(text)
    assert (lines, id_map) == _old_canonicalize(text)
    assert len(lines) == 4


def test_label_map_and_lines_identical_for_blank_node_shapes():
    text = ("_:a <http://e/p> _:b .\n_:b <http://e/p> _:a _:g .\n_:g <http://e/q> \"v\" _:g .\n"
            "<http://e/s> <http://e/p> _:a <http://e/g> .\n_:a <http://e/p> _:b .\n")
    new, old = _canonicalize(text), _old_canonicalize(text)
    assert new == old and new[1]


# -- 3. malformed input stays typed, with pyld's own error ------------------------------------ #

@pytest.mark.parametrize("text", [
    "garbage\n",
    '<http://e/s> <http://e/p> "x"\n',                       # no terminating dot
    '<http://e/s> <http://e/p> "unterminated .\n',
    '<http://e/s> <http://e/p> "ok" .\n<nocolon> <http://e/p> "x" .\n',
    '<http://e/s> <http://e/p> "a\u2028b" .\n',
    '"lit" <http://e/p> "x" .\n',
    '<http://e/s> <http://e/p> "x" "g" .\n',
])
def test_malformed_text_raises_the_same_class_as_before(text):
    old, new = _outcome(_old_canonicalize, text), _outcome(_canonicalize, text)
    assert new == old
    if new[0] == "raised":
        assert issubclass(new[1], pyld_jsonld.JsonLdError)


def test_the_error_names_the_line_of_the_whole_text():
    good = '<http://e/s> <http://e/p> "x%d" .\n'
    text = "".join(good % i for i in range(7)) + "garbage\n"
    with pytest.raises(pyld_jsonld.JsonLdError) as new:
        _canonicalize(text)
    with pytest.raises(pyld_jsonld.JsonLdError) as old:
        _old_canonicalize(text)
    assert str(new.value) == str(old.value)


def test_blank_and_whitespace_lines_are_skipped_as_before():
    text = '\n  \n<http://e/s> <http://e/p> "x" .\n\t\n\n'
    assert _canonicalize(text) == _old_canonicalize(text)
    assert _canonicalize("") == _old_canonicalize("") == ([], {})
