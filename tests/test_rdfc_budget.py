"""
tests/test_rdfc_budget.py — the RDF canonicalization work budget (issue #381, audit M4).

The three RDF suites canonicalize before any signature check. RDFC-1.0's Hash N-Degree
Quads tries every permutation of tied blank nodes, so a symmetric blank-node graph costs
factorial time: a clique of 8 (2.5 KB) took ~20 s through ``verify_credential``, 9 took
~4 minutes, and a clique whose nodes carry thousands of literals multiplies every call.
``openvc.proof._rdfc`` is pyld's URDNA2015 with a work ceiling (quad visits, calls and
distinct permutations, counted before they run) plus a blank-node and a call backstop; over
budget is a typed ``ProofMalformed`` before any signature check, and everything that already
canonicalized still does, byte for byte.

Most refusals run with the work ceiling lowered (``tight``) so they cost nothing and prove
the plumbing; ``test_default_budget_*`` runs the real ceiling once. Boundedness is asserted
by counting the Hash N-Degree Quads calls pyld was let make, never by wall-clock (a loaded
CI runner turned a 0.3 s refusal into 4-8 s).

The poison graphs are built under an inline ``@vocab`` (what ``_check_context`` allows) and
verified through the public pipeline with the bundled contexts only.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("pyld")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from pyld import jsonld  # noqa: E402

from openvc import VerificationPolicy, verify_credential, verify_many  # noqa: E402
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof.contexts import document_loader, pyld_options  # noqa: E402
from openvc.proof.data_integrity import (  # noqa: E402
    DataIntegrityProofSuite,
    _canonize,
)
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite, _canonicalize  # noqa: E402
from openvc.proof.errors import ProofMalformed, SignatureInvalid  # noqa: E402

VC2 = "https://www.w3.org/ns/credentials/v2"
CTX = [VC2, {"@vocab": "https://v.example/"}]
FX = Path(__file__).parent / "fixtures" / "vc_di_eddsa"
BUDGET_ERROR = "CanonicalizationBudgetExceeded"

_ISSUER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


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
# The poison graphs (every key is a predicate under @vocab; ids are blank nodes)
# --------------------------------------------------------------------------- #

def _wrap(subject, issuer: str = _ISSUER) -> dict:
    return {"@context": CTX, "type": ["VerifiableCredential"], "issuer": issuer,
            "credentialSubject": subject,
            "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                      "created": "2020-01-01T00:00:00Z",
                      "verificationMethod": f"{issuer}#{issuer[len('did:key:'):]}",
                      "proofPurpose": "assertionMethod", "proofValue": "z" + "1" * 86}}


def _clique_subject(n: int) -> list:
    return [{"id": f"_:b{i}", "link": [{"id": f"_:b{j}"} for j in range(n) if j != i]}
            for i in range(n)]


def _bipartite_subject(m: int) -> list:
    return [{"id": f"_:l{i}", "link": [{"id": f"_:m{j}"} for j in range(m)]}
            for i in range(m)]


def _ring_subject(n: int) -> list:
    # linear: every node has its own literal, so no two first-degree hashes tie
    return [{"id": f"_:r{i}", "name": f"node-{i}", "next": {"id": f"_:r{(i + 1) % n}"}}
            for i in range(n)]


@pytest.fixture
def tight(monkeypatch):
    """The work ceiling lowered to 150 000 units (about 20 ms of work): refusals are instant."""
    from openvc.proof import _rdfc
    monkeypatch.setattr(_rdfc, "MAX_CANONICALIZATION_WORK", 150_000)


@pytest.fixture
def run(monkeypatch):
    """``run(fn) -> (exception or None, Hash N-Degree Quads calls that did real work)``."""
    from pyld.jsonld import URDNA2015
    calls = [0]
    original = URDNA2015.hash_n_degree_quads

    def counting(self, id_, issuer):
        calls[0] += 1
        return original(self, id_, issuer)

    monkeypatch.setattr(URDNA2015, "hash_n_degree_quads", counting)

    def runner(fn):
        calls[0] = 0
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - the caller asserts the class
            return exc, calls[0]
        return None, calls[0]

    return runner


def _plain_subject(n: int) -> list:
    return [{"id": f"_:n{i}", "name": f"v{i}"} for i in range(n)]


def _fat_clique_subject(n: int, literals: int) -> list:
    return [{"id": f"_:b{i}", "link": [{"id": f"_:b{j}"} for j in range(n) if j != i],
             **{f"p{k}": f"v{k}" for k in range(literals)}} for i in range(n)]


def _tree_subject(n: int) -> list:
    return [{"id": f"_:t{i}", "name": f"n{i}", "child": {"id": f"_:t{(i - 1) // 2}"}}
            for i in range(1, n)]


def _doc(subject) -> dict:
    return {"@context": CTX, "type": ["VerifiableCredential"], "issuer": _ISSUER,
            "credentialSubject": subject}


# --------------------------------------------------------------------------- #
# 1. Negatives: poison graphs are refused, typed and bounded
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("subject", [_clique_subject(8), _bipartite_subject(5),
                                     _fat_clique_subject(7, 2000)],
                         ids=["clique-8", "K5,5", "fat-clique-7"])
def test_poison_graph_refused_typed_and_bounded_through_verify_credential(subject, run, tight):
    from openvc.proof import _rdfc
    exc, calls = run(lambda: verify_credential(_wrap(subject)))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert isinstance(exc, ProofMalformed)
    assert "work" in str(exc)                 # names the ceiling
    assert "_:b0" not in str(exc) and "v.example" not in str(exc)   # never echoes the document
    # 150 000 units over the per-call charge: nowhere near the 10 000+ calls a clique costs
    assert calls <= _rdfc.MAX_CANONICALIZATION_WORK // 200


def _shared_target_cycle(n: int, predicates: int) -> list:
    # A tied cycle whose nodes each point at ONE canonical blank node under many predicates:
    # every one of those related groups is a singleton, and pyld deep-copies the identifier
    # issuer for each of them (review of #424, round 2).
    shared = {f"p{k}": {"id": "_:y"} for k in range(predicates)}
    return ([dict({"id": f"_:c{i}", "link": {"id": f"_:c{(i + 1) % n}"}}, **shared)
             for i in range(n)] + [{"id": "_:y", "tag": "u"}])


@pytest.mark.parametrize("subject", [_shared_target_cycle(100, 200), _shared_target_cycle(50, 500),
                                     _shared_target_cycle(20, 2000)],
                         ids=["cycle100xQ200", "cycle50xQ500", "cycle20xQ2000"])
def test_singleton_groups_are_charged_for_their_issuer_copies(subject, run, monkeypatch):
    # Without charging the copies of singleton groups these cost 13-31 s while the other
    # charges (quads, calls) stood at about 4 M units, and the document was accepted. At 6 M
    # only the copy charge can refuse it, so removing that charge fails this test.
    from openvc.proof import _rdfc
    monkeypatch.setattr(_rdfc, "MAX_CANONICALIZATION_WORK", 6_000_000)
    exc, calls = run(lambda: verify_credential(_wrap(subject)))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert calls < 3_000


def test_singleton_copies_decide_a_document_the_other_charges_would_accept(run, monkeypatch):
    # The uncharged total of this document is 4.0 M units (quads, calls), under a 6 M ceiling,
    # so it is the copies pyld makes of the issuer for its singleton groups that refuse it.
    from openvc.proof import _rdfc
    monkeypatch.setattr(_rdfc, "MAX_CANONICALIZATION_WORK", 6_000_000)
    exc, calls = run(lambda: verify_credential(_wrap(_shared_target_cycle(100, 200))))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert calls < 3_000      # the uncharged accounting let it run 10 000 calls (31 s)


def test_the_issuer_copy_charge_is_per_copy_and_per_entry(monkeypatch):
    import copy

    from openvc.proof import _rdfc
    from pyld.jsonld import IdentifierIssuer

    canon = _rdfc.new_canonicalizer()
    canon.blank_node_info = {"_:x": {"quads": []}}
    issuer = IdentifierIssuer("_:b")
    for name in ("_:x", "_:y", "_:z"):
        issuer.get_id(name)
    canon.hash_n_degree_quads("_:x", issuer)         # installs the charging issuer
    before = canon._work
    twin = copy.deepcopy(issuer)
    assert canon._work - before == _rdfc._COPY_FIXED_COST + _rdfc._COPY_ENTRY_COST * 3
    assert twin.existing == issuer.existing and twin.existing is not issuer.existing
    monkeypatch.setattr(_rdfc, "MAX_CANONICALIZATION_WORK", canon._work + 1)
    with pytest.raises(_rdfc.CanonicalizationBudgetExceeded):
        copy.deepcopy(twin)


def test_default_budget_refuses_k55_and_a_fat_clique_after_bounded_work(run):
    # The real ceiling, once (about 1-2 s each). The fat clique costs 10 000 calls of 7 000
    # quads each without a work counter (12 s measured); here the work, not the call count,
    # stops it.
    from openvc.proof import _rdfc
    for subject in (_bipartite_subject(5), _fat_clique_subject(7, 3000)):
        exc, calls = run(lambda: verify_credential(_wrap(subject)))
        assert type(exc).__name__ == BUDGET_ERROR, exc
        assert calls < _rdfc.MAX_CANONICALIZATION_WORK // 200


def test_clique_8_is_refused_in_the_first_call_when_its_permutations_exceed_the_budget(
        run, monkeypatch):
    from openvc.proof import _rdfc
    # 7! = 5040 distinct permutations of a tied group, each charged for what it costs
    monkeypatch.setattr(_rdfc, "MAX_CANONICALIZATION_WORK", 200_000)
    exc, calls = run(lambda: verify_credential(_wrap(_clique_subject(8))))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert calls == 1


def test_poison_item_is_a_per_item_error_in_verify_many_and_siblings_verify(tight):
    sk, did, vm = _ed_key()
    good = DataIntegrityProofSuite().add_proof(
        {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:s", "name": "Ada"}},
        signing_key=sk, verification_method=vm)
    results = verify_many([good, _wrap(_clique_subject(8)), good, _wrap(_bipartite_subject(5))],
                          policy=VerificationPolicy())
    assert [r.error is None for r in results] == [True, False, True, False]
    assert type(results[1].error).__name__ == BUDGET_ERROR
    assert type(results[3].error).__name__ == BUDGET_ERROR


def test_ecdsa_rdfc_suite_refuses_the_poison_after_the_key_matched(tight):
    sk, did, vm = _p256_key()
    suite = EcdsaRdfcProofSuite()
    signed = suite.add_proof(
        {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:s", "name": "Ada"}},
        signing_key=sk, verification_method=vm)
    signed["credentialSubject"] = _clique_subject(8)
    with pytest.raises(ProofMalformed) as ei:
        verify_credential(signed)
    assert type(ei.value).__name__ == BUDGET_ERROR
    # and the signing side refuses the same document
    unsecured = {k: v for k, v in signed.items() if k != "proof"}
    with pytest.raises(ProofMalformed):
        suite.add_proof(unsecured, signing_key=sk, verification_method=vm)


def test_ecdsa_sd_refuses_the_poison_on_both_canonicalization_paths(tight):
    clique_nquads = "".join(
        f"_:b{i} <https://v.example/link> _:b{j} .\n"
        for i in range(8) for j in range(8) if i != j)
    with pytest.raises(ProofMalformed) as ei:
        _canonicalize(clique_nquads)
    assert type(ei.value).__name__ == BUDGET_ERROR

    sk = P256SigningKey.generate(kid="did:key:zDnaeykfoobar#zDnaeykfoobar")
    credential = {"@context": CTX, "type": ["VerifiableCredential"],
                  "issuer": "did:example:issuer", "validFrom": "2026-01-01T00:00:00Z",
                  "credentialSubject": _clique_subject(8)}
    with pytest.raises(ProofMalformed) as ei:
        EcdsaSdProofSuite().add_base_proof(
            credential, signing_key=sk, verification_method="did:key:zDnaeykfoobar#zDnaeykfoobar",
            mandatory_pointers=["/issuer"])
    assert type(ei.value).__name__ == BUDGET_ERROR


def test_the_tied_cases_below_the_ceiling_still_reach_the_signature_check():
    # clique 5, K3,3 tie, run Hash N-Degree Quads and are within budget: the failure is the
    # (fake) signature, not the budget
    for subject in (_clique_subject(5), _bipartite_subject(3)):
        with pytest.raises(SignatureInvalid):
            verify_credential(_wrap(subject))


# --------------------------------------------------------------------------- #
# 2. The ceilings, pinned and each exercised
# --------------------------------------------------------------------------- #

def test_budget_constants_are_importable_and_pinned():
    from openvc.proof import _rdfc
    assert _rdfc.MAX_CANONICALIZATION_WORK == 20_000_000
    assert _rdfc.MAX_BLANK_NODES == 1024
    assert _rdfc.MAX_HNDQ_CALLS == 1_000_000
    assert issubclass(_rdfc.CanonicalizationBudgetExceeded, ProofMalformed)


def test_hndq_call_backstop_alone_stops_the_recursion(monkeypatch, run):
    from openvc.proof import _rdfc
    monkeypatch.setattr(_rdfc, "MAX_CANONICALIZATION_WORK", 10 ** 12)    # the work guard is off
    monkeypatch.setattr(_rdfc, "MAX_HNDQ_CALLS", 300)
    exc, calls = run(lambda: verify_credential(_wrap(_clique_subject(7))))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert "Hash N-Degree Quads calls" in str(exc)
    assert calls == 300


def test_a_tied_group_too_large_to_count_is_refused_without_computing_it(run):
    # 40 interchangeable neighbours of a hub that is itself tied with a twin hub: more than
    # 10 distinct tied members, refused in the first call whatever the work ceiling
    spokes = [{"id": f"_:s{i}"} for i in range(40)]
    subject = [{"id": "_:h0", "link": spokes}, {"id": "_:h1", "link": spokes}]
    exc, calls = run(lambda: verify_credential(_wrap(subject)))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert calls == 1


def test_permutations_are_counted_as_a_multiset_the_way_pyld_iterates_them():
    from openvc.proof._rdfc import _distinct_permutations
    cap = 10 ** 9
    assert _distinct_permutations(["g"] * 9, cap) == 1              # pyld yields one
    assert _distinct_permutations(["a", "a", "b", "b"], cap) == 6   # 4!/(2!2!), not 2 (a set)
    assert _distinct_permutations(["a", "b", "c", "c", "c", "c"], cap) == 30
    assert _distinct_permutations(list("abcdefg"), cap) == 5040
    assert _distinct_permutations([str(i) for i in range(11)], cap) > cap   # 11 distinct
    assert _distinct_permutations(["a"] * 500 + ["b"] * 500, cap) > cap     # never computed


def test_blank_node_ceiling_refuses_before_any_hashing(monkeypatch):
    from openvc.proof import _rdfc
    from pyld.jsonld import URDNA2015

    def bomb(self, id_):
        raise AssertionError("hashing started before the blank-node count was checked")

    monkeypatch.setattr(URDNA2015, "hash_first_degree_quads", bomb)
    doc = _doc(_plain_subject(_rdfc.MAX_BLANK_NODES))        # + the credential node
    with pytest.raises(_rdfc.CanonicalizationBudgetExceeded, match="blank nodes"):
        _rdfc.canonicalize_nquads(doc, document_loader(None))


def test_blank_node_ceiling_is_exact():
    from openvc.proof import _rdfc
    loader = document_loader(None)
    at = _doc(_plain_subject(_rdfc.MAX_BLANK_NODES - 1))     # + the credential node
    assert _rdfc.canonicalize_nquads(at, loader)
    with pytest.raises(_rdfc.CanonicalizationBudgetExceeded):
        _rdfc.canonicalize_nquads(_doc(_plain_subject(_rdfc.MAX_BLANK_NODES)), loader)


# --------------------------------------------------------------------------- #
# 3. Positives: nothing that canonicalized before stops canonicalizing
# --------------------------------------------------------------------------- #

def test_two_holder_bound_credentials_sharing_an_anonymous_sub_object_still_verify():
    # The standard multi-credential presentation: every VC of a VP lives in a blank-node-named
    # graph, and pyld lists that graph name once per quad. A group counted as k! (instead of
    # pyld's distinct permutations, one here) refused this from 6 fields up (review of #424).
    from openvc.openid4vp import verify_vp_token
    for suite_cls, key in ((DataIntegrityProofSuite, _ed_key), (EcdsaRdfcProofSuite, _p256_key)):
        isk, idid, ivm = key()
        hsk, hdid, hvm = key()
        address = {f"field{i}": f"value{i}" for i in range(8)}
        vcs = [suite_cls().add_proof(
            {"@context": CTX, "type": ["VerifiableCredential"], "issuer": idid,
             "validFrom": f"2026-01-0{k + 1}T00:00:00Z",
             "credentialSubject": {"id": hdid, "address": address}},
            signing_key=isk, verification_method=ivm) for k in range(3)]
        vp = suite_cls().add_proof(
            {"@context": [VC2], "type": ["VerifiablePresentation"], "holder": hdid,
             "verifiableCredential": vcs},
            signing_key=hsk, verification_method=hvm, proof_purpose="authentication",
            challenge="n1", domain="x509_san_dns:verifier.example")
        result = verify_vp_token(
            {"c1": [vp]}, dcql_query={"credentials": [{"id": "c1", "format": "ldp_vc"}]},
            nonce="n1", client_id="x509_san_dns:verifier.example")
        assert result


def test_tie_free_documents_of_any_reasonable_size_verify_without_hndq_work(run):
    sk, did, vm = _ed_key()
    for subject in (_ring_subject(256), _tree_subject(300), _ring_subject(1000)):
        signed = DataIntegrityProofSuite().add_proof(
            {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
             "credentialSubject": subject},
            signing_key=sk, verification_method=vm)
        exc, calls = run(lambda: verify_credential(signed))
        assert exc is None, exc
        assert calls == 0


def test_the_tied_shapes_that_must_keep_passing_pass_at_the_real_budget():
    # clique 6, K4,4, three disjoint K6 and a tied cycle of 100 reach the signature check
    three_k6 = [{"id": f"_:{g}{i}", "link": [{"id": f"_:{g}{j}"} for j in range(6) if j != i]}
                for g in "abc" for i in range(6)]
    cycle = [{"id": f"_:c{i}", "link": {"id": f"_:c{(i + 1) % 100}"}} for i in range(100)]
    for subject in (_clique_subject(6), _bipartite_subject(4), three_k6, cycle):
        with pytest.raises(SignatureInvalid):
            verify_credential(_wrap(subject))


def test_an_rdf_list_of_150_identical_items_still_canonicalizes(run):
    # a chain of tied blank nodes: O(n^2) cheap calls (21 904 of them), 0.7 s on main
    doc = _doc({"id": "did:example:s", "items": {"@list": ["x"] * 150}})
    out = []
    exc, calls = run(lambda: out.append(_canonize(doc, document_loader(None))))
    assert exc is None, exc
    assert calls > 10_000 and out


def test_output_is_byte_identical_to_pyld_normalize():
    loader = document_loader(None)
    for subject in (_clique_subject(4), _ring_subject(12), _plain_subject(5),
                    _bipartite_subject(3), _tree_subject(40)):
        doc = _doc(subject)
        expected = jsonld.normalize(
            doc, pyld_options(loader, algorithm="URDNA2015", format="application/n-quads"))
        assert _canonize(doc, loader) == expected.encode("utf-8")


def test_w3c_eddsa_golden_still_reproduces_byte_for_byte():
    examples = {"https://www.w3.org/ns/credentials/examples/v2":
                json.loads((FX / "credentials-examples-v2.json").read_text())}
    vector = json.loads((FX / "signedDataInt.json").read_text())
    proof = vector["proof"]
    unsecured = {k: v for k, v in vector.items() if k != "proof"}
    loader = document_loader(examples)
    expected = jsonld.normalize(
        unsecured, pyld_options(loader, algorithm="URDNA2015", format="application/n-quads"))
    assert _canonize(unsecured, loader) == expected.encode("utf-8")
    result = DataIntegrityProofSuite().verify(vector, extra_contexts=examples)
    assert result.proof["proofValue"] == proof["proofValue"]
