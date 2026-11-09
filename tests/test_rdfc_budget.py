"""
tests/test_rdfc_budget.py — the RDF canonicalization work budget (issue #381, audit M4).

The three RDF suites canonicalize before any signature check. RDFC-1.0's Hash N-Degree
Quads tries every permutation of tied blank nodes, so a symmetric blank-node graph costs
factorial time: a clique of 8 (2.5 KB) took ~20 s through ``verify_credential``, 9 took
~4 minutes. ``openvc.proof._rdfc`` is pyld's URDNA2015 with a blank-node, a HNDQ-call
and a permutation ceiling; over budget is a typed ``ProofMalformed`` before any signature
check, and everything that already canonicalized still does, byte for byte.

The poison graphs are built under an inline ``@vocab`` (what ``_check_context`` allows) and
verified through the public pipeline with the bundled contexts only.
"""
from __future__ import annotations

import base64
import json
import time
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
FAST = 3.0          # seconds, CI-runner slack: main takes 20 s on clique 8, minutes on 9
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


def _timed(fn):
    t = time.perf_counter()
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - the caller asserts the class
        return exc, time.perf_counter() - t
    return None, time.perf_counter() - t


# --------------------------------------------------------------------------- #
# 1. Negatives: poison graphs are refused, typed and fast
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("subject", [_clique_subject(8), _bipartite_subject(5)],
                         ids=["clique-8", "K5,5"])
def test_poison_graph_refused_typed_and_fast_through_verify_credential(subject):
    exc, dt = _timed(lambda: verify_credential(_wrap(subject)))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert isinstance(exc, ProofMalformed)
    assert dt < FAST, f"refusal took {dt:.2f}s"
    # names the ceiling, never echoes the document
    assert "budget" in str(exc)
    assert "_:b0" not in str(exc) and "v.example" not in str(exc)


def test_clique_8_refused_without_running_the_permutations():
    # the pre-count refuses the 7! = 5040 group before one permutation runs
    _, dt = _timed(lambda: verify_credential(_wrap(_clique_subject(8))))
    assert dt < 1.0


def test_poison_item_is_a_per_item_error_in_verify_many_and_siblings_verify():
    sk, did, vm = _ed_key()
    good = DataIntegrityProofSuite().add_proof(
        {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:s", "name": "Ada"}},
        signing_key=sk, verification_method=vm)
    t = time.perf_counter()
    results = verify_many([good, _wrap(_clique_subject(8)), good, _wrap(_bipartite_subject(5))],
                          policy=VerificationPolicy())
    assert time.perf_counter() - t < 2 * FAST
    assert [r.error is None for r in results] == [True, False, True, False]
    assert type(results[1].error).__name__ == BUDGET_ERROR
    assert type(results[3].error).__name__ == BUDGET_ERROR


def test_ecdsa_rdfc_suite_refuses_the_poison_after_the_key_matched():
    sk, did, vm = _p256_key()
    suite = EcdsaRdfcProofSuite()
    signed = suite.add_proof(
        {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:s", "name": "Ada"}},
        signing_key=sk, verification_method=vm)
    signed["credentialSubject"] = _clique_subject(8)
    exc, dt = _timed(lambda: verify_credential(signed))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert dt < FAST
    # and the signing side refuses the same document
    unsecured = {k: v for k, v in signed.items() if k != "proof"}
    with pytest.raises(ProofMalformed):
        suite.add_proof(unsecured, signing_key=sk, verification_method=vm)


def test_ecdsa_sd_refuses_the_poison_on_both_canonicalization_paths():
    clique_nquads = "".join(
        f"_:b{i} <https://v.example/link> _:b{j} .\n"
        for i in range(8) for j in range(8) if i != j)
    exc, dt = _timed(lambda: _canonicalize(clique_nquads))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert dt < FAST

    sk = P256SigningKey.generate(kid="did:key:zDnaeykfoobar#zDnaeykfoobar")
    credential = {"@context": CTX, "type": ["VerifiableCredential"],
                  "issuer": "did:example:issuer", "validFrom": "2026-01-01T00:00:00Z",
                  "credentialSubject": _clique_subject(8)}
    exc, dt = _timed(lambda: EcdsaSdProofSuite().add_base_proof(
        credential, signing_key=sk, verification_method="did:key:zDnaeykfoobar#zDnaeykfoobar",
        mandatory_pointers=["/issuer"]))
    assert isinstance(exc, ProofMalformed), exc
    assert type(exc).__name__ == BUDGET_ERROR
    assert dt < FAST


def test_budgets_below_the_ceiling_still_reach_the_signature_check():
    # clique 5 / K3,3 tie, run Hash N-Degree Quads, and are within budget: the failure is
    # the (fake) signature, not the budget
    for subject in (_clique_subject(5), _bipartite_subject(3)):
        with pytest.raises(SignatureInvalid):
            verify_credential(_wrap(subject))


# --------------------------------------------------------------------------- #
# 2. The three ceilings, each pinned alone
# --------------------------------------------------------------------------- #

def test_budget_constants_are_importable_and_pinned():
    from openvc.proof import _rdfc
    assert _rdfc.MAX_BLANK_NODES == 256
    assert _rdfc.MAX_HNDQ_CALLS == 10_000
    assert _rdfc.MAX_PERMUTATIONS == 10_000
    assert issubclass(_rdfc.CanonicalizationBudgetExceeded, ProofMalformed)


def test_hndq_call_ceiling_alone_stops_the_recursion(monkeypatch):
    from openvc.proof import _rdfc
    monkeypatch.setattr(_rdfc, "MAX_PERMUTATIONS", 10 ** 12)     # the permutation guard is off
    exc, dt = _timed(lambda: verify_credential(_wrap(_clique_subject(7))))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert "Hash N-Degree Quads calls" in str(exc)
    assert dt < 2 * FAST


def test_permutation_ceiling_alone_stops_a_tied_group(monkeypatch):
    from openvc.proof import _rdfc
    monkeypatch.setattr(_rdfc, "MAX_HNDQ_CALLS", 10 ** 12)       # the call guard is off
    exc, dt = _timed(lambda: verify_credential(_wrap(_clique_subject(8))))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert "permutations" in str(exc)
    assert dt < FAST


def test_a_tied_group_too_large_to_factor_is_refused_without_computing_the_factorial():
    # 40 interchangeable neighbours of one hub that is itself tied with a twin hub
    spokes = [{"id": f"_:s{i}"} for i in range(40)]
    subject = [{"id": "_:h0", "link": spokes}, {"id": "_:h1", "link": spokes}]
    exc, dt = _timed(lambda: verify_credential(_wrap(subject)))
    assert type(exc).__name__ == BUDGET_ERROR, exc
    assert dt < FAST


def _plain_subject(n: int) -> list:
    return [{"id": f"_:n{i}", "name": f"v{i}"} for i in range(n)]


def test_blank_node_ceiling_refuses_before_any_hashing(monkeypatch):
    from openvc.proof import _rdfc
    from pyld.jsonld import URDNA2015

    def bomb(self, id_):
        raise AssertionError("hashing started before the blank-node count was checked")

    monkeypatch.setattr(URDNA2015, "hash_first_degree_quads", bomb)
    # the credential node itself is one more blank node
    doc = {"@context": CTX, "type": ["VerifiableCredential"], "issuer": _ISSUER,
           "credentialSubject": _plain_subject(_rdfc.MAX_BLANK_NODES)}
    with pytest.raises(_rdfc.CanonicalizationBudgetExceeded, match="blank nodes"):
        _rdfc.canonicalize_nquads(doc, document_loader(None))


def test_blank_node_ceiling_is_exact():
    from openvc.proof import _rdfc
    loader = document_loader(None)
    at = {"@context": CTX, "type": ["VerifiableCredential"], "issuer": _ISSUER,
          "credentialSubject": _plain_subject(_rdfc.MAX_BLANK_NODES - 1)}   # +1: the credential
    assert _rdfc.canonicalize_nquads(at, loader)
    over = dict(at, credentialSubject=_plain_subject(_rdfc.MAX_BLANK_NODES))
    with pytest.raises(_rdfc.CanonicalizationBudgetExceeded):
        _rdfc.canonicalize_nquads(over, loader)


# --------------------------------------------------------------------------- #
# 3. Positives: nothing that canonicalized before stops canonicalizing
# --------------------------------------------------------------------------- #

def test_linear_ring_of_256_blank_nodes_still_verifies_within_the_budget():
    sk, did, vm = _ed_key()
    subject = _ring_subject(255)             # + the credential node = 256 blank nodes
    signed = DataIntegrityProofSuite().add_proof(
        {"@context": CTX, "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": subject},
        signing_key=sk, verification_method=vm)
    t = time.perf_counter()
    result = verify_credential(signed)
    assert time.perf_counter() - t < 2 * FAST
    assert result.issuer == did


def test_output_is_byte_identical_to_pyld_normalize():
    loader = document_loader(None)
    docs = [_wrap(_clique_subject(4))["credentialSubject"],
            _ring_subject(12), _plain_subject(5), _bipartite_subject(3)]
    for subject in docs:
        doc = {"@context": CTX, "type": ["VerifiableCredential"], "issuer": _ISSUER,
               "credentialSubject": subject}
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
