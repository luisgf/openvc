"""
tests/test_di_context_before_expansion.py — the JSON-LD context budget and the early
``@context`` refusal on the RDF Data Integrity suites (issue #446).

pyld re-processes a term's scoped context every time the term is used, so one definition of
K terms used by N nodes costs about K x N term definitions, and ``eddsa-rdfc-2022``,
``ecdsa-rdfc-2019`` and ``ecdsa-sd-2023`` expand before they check a signature. Two controls,
both in front of the signature:

1. ``check_context_before_expansion`` runs the document ``@context`` rule of the later
   validation (``_check_context``, same refusal) before any pyld work: the plain spelling of
   an inline term definition is refused without pyld being entered.
2. Everything else — a scoped context reached by a nested ``@context`` under a key named like
   an ``@json`` term, an embedded credential of a presentation, a ``type`` that adds
   ``VerifiablePresentation``, a context repeated, a ``type_values`` expansion — is bounded by
   a work budget: ``openvc.proof._rdfc.new_processor`` counts the term definitions one call
   creates and refuses over ``MAX_CONTEXT_WORK`` with ``CanonicalizationBudgetExceeded``.

Boundedness is asserted by counting the term definitions pyld really performed (wrapping the
base class's ``_create_term_definition``), never by wall-clock; the load-bearing test is the
soundness one: **the charge is never below what pyld really does**, over a seeded fuzz of
contexts, and the budgeted processor's output is pyld's own, byte for byte. Self-contained
helpers (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import ast
import asyncio
import copy
import random
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pyld")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from pyld import jsonld  # noqa: E402
from pyld.jsonld import JsonLdProcessor  # noqa: E402

from openvc import (  # noqa: E402
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.openid4vp import verify_vp_token  # noqa: E402
from openvc.proof import _rdfc, data_integrity, di_ecdsa_rdfc, ecdsa_sd  # noqa: E402
from openvc.proof._context_validation import (  # noqa: E402
    check_context_before_expansion,
    validate_document,
)
from openvc.proof._rdfc import CanonicalizationBudgetExceeded  # noqa: E402
from openvc.proof.contexts import document_loader, pyld_options  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.di_jcs import EddsaJcsProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import (  # noqa: E402
    ClaimsInvalid,
    ProofError,
    ProofMalformed,
    SignatureInvalid,
)

V2 = "https://www.w3.org/ns/credentials/v2"
ONLY_VOCAB = "an inline @context object may only carry @vocab"
SUITES = ["eddsa-rdfc-2022", "ecdsa-rdfc-2019", "ecdsa-sd-2023"]
POLICY = VerificationPolicy(require_status=False)
LIMIT = 3_000                       # the lowered ceiling the refusals run under
ABS = {"@vocab": "https://a.example/"}


# --------------------------------------------------------------------------- #
# Counters
# --------------------------------------------------------------------------- #

@pytest.fixture
def expansions(monkeypatch):
    """Entries into pyld's expansion / conversion (class methods; the module functions
    delegate to them)."""
    calls: list[str] = []
    for name in ("expand", "to_rdf", "compact"):
        original = getattr(JsonLdProcessor, name)

        def counted(*args, _name=name, _original=original, **kwargs):
            calls.append(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(JsonLdProcessor, name, counted)
    return calls


@pytest.fixture
def real_terms(monkeypatch):
    """A one-item list holding how many term definitions pyld really made (counted on the
    base class, under the budgeted subclass's own counting)."""
    count = [0]
    original = JsonLdProcessor._create_term_definition

    def counted(self, *args, **kwargs):
        count[0] += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(JsonLdProcessor, "_create_term_definition", counted)
    return count


@pytest.fixture
def low(monkeypatch):
    monkeypatch.setattr(_rdfc, "MAX_CONTEXT_WORK", LIMIT)
    return LIMIT


# --------------------------------------------------------------------------- #
# Keys and documents
# --------------------------------------------------------------------------- #

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
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    did = "did:key:" + encode_multibase(_leb128(0xED) + pub)
    vm = f"{did}#{did[len('did:key:'):]}"
    return Ed25519SigningKey(priv, kid=vm), did, vm


def _p256_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    did = "did:key:" + encode_multibase(_leb128(0x1200) + pub)
    vm = f"{did}#{did[len('did:key:'):]}"
    return P256SigningKey(priv, kid=vm), did, vm


ED_KEY, ED_DID, ED_VM = _ed_key()
P256_KEY, P256_DID, P256_VM = _p256_key()
GARBAGE = "z" + "1" * 86          # a proofValue that decodes; no key is involved


def _scoped(k: int, shape: str = "type") -> dict:
    inner = {f"k{i}": f"https://a.example/k{i}" for i in range(k)}
    if shape == "type":
        return {"T": {"@id": "https://a.example/T", "@context": inner}}
    return {"p": {"@id": "https://a.example/p", "@context": inner}}


def _rdf_credential(suite_id: str, context, subject=None, **extra) -> dict:
    """An RDF-suite credential with a garbage proof (issuer a resolvable did:key)."""
    did, vm = (ED_DID, ED_VM) if suite_id == "eddsa-rdfc-2022" else (P256_DID, P256_VM)
    doc = {"@context": context, "type": ["VerifiableCredential"], "issuer": did,
           "credentialSubject": subject or {"id": "did:example:s"},
           "proof": {"type": "DataIntegrityProof", "cryptosuite": suite_id,
                     "created": "2026-01-01T00:00:00Z", "verificationMethod": vm,
                     "proofPurpose": "assertionMethod", "proofValue": GARBAGE}}
    doc.update(extra)
    return doc


def _signed(suite_id: str, doc: dict, monkeypatch=None, **kwargs) -> dict:
    """*doc* signed by its issuer's key; *monkeypatch* switches the signing-side validation
    off for the call, to hold a document the verifier would refuse."""
    doc = {k: v for k, v in doc.items() if k != "proof"}
    if suite_id == "eddsa-rdfc-2022":
        suite, key, vm, module = DataIntegrityProofSuite(), ED_KEY, ED_VM, data_integrity
    else:
        suite, key, vm, module = EcdsaRdfcProofSuite(), P256_KEY, P256_VM, di_ecdsa_rdfc
    if monkeypatch is None:
        return suite.add_proof(doc, signing_key=key, verification_method=vm, **kwargs)
    with monkeypatch.context() as patched:      # undone before anything is verified
        patched.setattr(module, "validate_document", lambda *args, **kw: None)
        return suite.add_proof(doc, signing_key=key, verification_method=vm, **kwargs)


def _sd_derived(context=None, monkeypatch=None) -> dict:
    doc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
           "validFrom": "2020-01-01T00:00:00Z",
           "credentialSubject": {"id": "did:example:alice", "name": "Alice"}}
    if context is not None:
        doc["@context"] = context
    suite = EcdsaSdProofSuite()

    def derive() -> dict:
        base = suite.add_base_proof(doc, signing_key=P256_KEY, verification_method=P256_VM,
                                    mandatory_pointers=["/issuer", "/validFrom"])
        return suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])

    if monkeypatch is None:
        return derive()
    with monkeypatch.context() as patched:      # undone before anything is verified
        patched.setattr(ecdsa_sd, "validate_document", lambda *args, **kwargs: None)
        return derive()


_DERIVED = _sd_derived()


def _document(suite_id: str, context=None, subject=None, **extra) -> dict:
    """The document under test: an ``ecdsa-sd`` derived credential whose body was swapped
    after derivation (its proof still decodes), else an RDF-suite credential with a garbage
    proof."""
    if suite_id == "ecdsa-sd-2023":
        derived = copy.deepcopy(_DERIVED)
        if context is not None:
            derived["@context"] = context
        if subject is not None:
            derived["credentialSubject"] = subject
        derived.update(extra)
        return derived
    return _rdf_credential(suite_id, context if context is not None else [V2], subject, **extra)


# --------------------------------------------------------------------------- #
# The entry points
# --------------------------------------------------------------------------- #

def _verify_sync(doc, extra=None):
    return verify_credential(copy.deepcopy(doc), policy=POLICY, extra_contexts=extra)


def _verify_async(doc, extra=None):
    return asyncio.run(verify_credential_async(
        copy.deepcopy(doc), policy=POLICY, extra_contexts=extra))


def _verify_suite(doc, extra=None):
    cryptosuite = doc["proof"]["cryptosuite"]
    suite = {"eddsa-rdfc-2022": DataIntegrityProofSuite,
             "ecdsa-rdfc-2019": EcdsaRdfcProofSuite,
             "ecdsa-sd-2023": EcdsaSdProofSuite}[cryptosuite]()
    return suite.verify(copy.deepcopy(doc), extra_contexts=extra)


def _one(results):
    (item,) = results
    if item.error is not None:
        raise item.error
    return item.result


def _verify_many(doc, extra=None):
    return _one(verify_many([copy.deepcopy(doc)], policy=POLICY, extra_contexts=extra))


def _verify_many_async(doc, extra=None):
    return _one(asyncio.run(verify_many_async(
        [copy.deepcopy(doc)], policy=POLICY, extra_contexts=extra)))


ENTRIES = {"verify_credential": _verify_sync, "verify_credential_async": _verify_async,
           "verify_many": _verify_many, "verify_many_async": _verify_many_async,
           "suite.verify": _verify_suite}


# --------------------------------------------------------------------------- #
# 1. The plain spelling is refused before pyld is entered
# --------------------------------------------------------------------------- #

def _early_rows():
    return {
        "type-scoped": ([V2, _scoped(40)], None),
        "property-scoped": ([V2, _scoped(40, "property")], None),
        "inline-import": ([V2, {"@import": "https://a.example/ctx"}], None),
        "inline-vocab-plus-terms": ([V2, {"@vocab": "https://a.example/", "T": "a:T"}], None),
        "context-not-a-list": ({"@vocab": "https://a.example/"}, None),
        "context-an-int": (5, None),
        "context-null-entry": ([V2, None], None),
    }


@pytest.mark.parametrize("entry", sorted(ENTRIES))
@pytest.mark.parametrize("row", sorted(_early_rows()))
@pytest.mark.parametrize("suite_id", SUITES)
def test_the_plain_inline_term_definition_is_refused_before_pyld_is_entered(
        suite_id, row, entry, expansions):
    context, subject = _early_rows()[row]
    with pytest.raises(ProofError) as caught:
        ENTRIES[entry](_document(suite_id, context, subject))
    assert type(caught.value) is ProofMalformed, caught.value
    assert expansions == [], "pyld was entered before the refusal"


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_a_valid_signature_with_an_inline_term_definition_keeps_class_and_message(
        suite_id, monkeypatch, expansions):
    signed = _signed(suite_id, _rdf_credential(suite_id, [V2, _scoped(5)]), monkeypatch)
    del expansions[:]                                   # signing expanded; verifying must not
    with pytest.raises(ProofMalformed, match=ONLY_VOCAB) as caught:
        verify_credential(signed, policy=POLICY)
    assert type(caught.value) is ProofMalformed
    assert expansions == []


def test_a_valid_ecdsa_sd_signature_with_an_inline_term_definition_keeps_class_and_message(
        monkeypatch, expansions):
    derived = _sd_derived(context=[V2, _scoped(2)], monkeypatch=monkeypatch)
    del expansions[:]
    with pytest.raises(ProofMalformed, match=ONLY_VOCAB) as caught:
        verify_credential(derived, policy=POLICY)
    assert type(caught.value) is ProofMalformed
    assert expansions == []


def test_the_early_context_rule_is_the_one_the_full_validation_applies_first():
    loader = document_loader(None)
    for context in (None, 5, [], [V2, {"T": "a:T"}], [V2, {"@vocab": "rel"}], ["x"],
                    [V2, {"@import": V2}]):
        doc = {"@context": context, "type": ["VerifiableCredential"]}
        with pytest.raises(ProofMalformed) as early:
            check_context_before_expansion(doc)
        with pytest.raises(ProofMalformed) as late:
            validate_document(doc, {"@context": context}, loader)
        assert str(early.value) == str(late.value)
    for context in ([V2], [V2, ABS], V2, [V2, "https://a.example/served"]):   # accepted
        check_context_before_expansion({"@context": context})


# --------------------------------------------------------------------------- #
# 2. Everything else is bounded by the context budget
# --------------------------------------------------------------------------- #

def _node(k: int, n: int, shape: str = "type") -> dict:
    """A node that brings its own scoped context of *k* terms and uses it *n* times."""
    if shape == "typelist":                    # one node typed T n times (4 bytes a use)
        return {"@context": _scoped(k), "type": ["T"] * n}
    return {"@context": _scoped(k), "https://a.example/p": [{"@type": "T", "id": "a:s"}] * n}


EXTRA_JSON = {"https://a.example/ctx/json": {"@context": {
    "blob": {"@id": "https://a.example/blob", "@type": "@json"}}}}


def _budget_rows():
    k = n = 70                                      # k x n = 4 900 > LIMIT, per expansion
    vocab = [V2, ABS]
    return {
        # (a) the exemption the structural walk left: a key named like a served @json term
        "jwk-under-vocab": (vocab, {"id": "did:example:s", "jwk": _node(k, n)}, None, {}),
        "jsonSchema-under-vocab": (vocab, {"id": "did:example:s", "jsonSchema": _node(k, n)},
                                   None, {}),
        "extra-json-name-under-vocab": (
            vocab,                            # the served @json context is not listed
            {"id": "did:example:s", "blob": _node(k, n)}, None, EXTRA_JSON),
        "tuned-type-repeated": (vocab, {"id": "did:example:s", "jwk": _node(k, 2 * n, "typelist")},
                                None, {}),
        "nested-at-subject": (
            [V2], {"id": "did:example:s", **_node(k, n)}, None, {}),
        "nested-in-proof-member": (
            vocab, {"id": "did:example:s"},
            {"https://a.example/x": _node(k, n)}, {}),
        # (c) any credential may add VerifiablePresentation to its type
        "type-adds-presentation": (
            [V2, ABS], {"id": "did:example:s"},
            None, {"type": ["VerifiableCredential", "VerifiablePresentation"],
                   "verifiableCredential": [{"@context": [V2, _scoped(k)],
                                             "type": ["T"] * n}]}),
        # a context array repeating a served URL: ~100 term definitions per entry
        "served-url-repeated": ([V2] * 80, {"id": "did:example:s"}, None, {}),
    }


BUDGET_ROWS = sorted(_budget_rows())


def _budget_document(suite_id, row):
    context, subject, proof_member, extra = _budget_rows()[row]
    document = _document(suite_id, context, subject)
    document.update({key: value for key, value in extra.items()})
    if proof_member:
        document["proof"] = dict(document["proof"], **proof_member)
    return document


def _extra_for(row):
    return _budget_rows()[row][3] if row == "extra-json-name-under-vocab" else None


@pytest.mark.parametrize("entry", sorted(ENTRIES))
@pytest.mark.parametrize("row", BUDGET_ROWS)
@pytest.mark.parametrize("suite_id", SUITES)
def test_a_scoped_context_that_costs_too_much_is_refused_by_the_budget(
        suite_id, row, entry, low, real_terms):
    document = _budget_document(suite_id, row)
    with pytest.raises(ProofError) as caught:
        ENTRIES[entry](document, _extra_for(row))
    assert type(caught.value) is CanonicalizationBudgetExceeded, caught.value
    assert str(LIMIT) in str(caught.value), caught.value
    assert "a.example" not in str(caught.value), "the message quotes no document text"
    # pyld did real work, and was stopped where the ceiling is
    assert LIMIT - 200 <= real_terms[0] <= LIMIT + 800, real_terms[0]


@pytest.mark.parametrize("entry", ["verify_credential", "suite.verify", "verify_many_async"])
@pytest.mark.parametrize("row", BUDGET_ROWS)
@pytest.mark.parametrize("suite_id", SUITES)
def test_the_same_shapes_with_little_work_are_not_refused(suite_id, row, entry, real_terms):
    """Controls: the shapes of the rows above at a size the ceiling lets through reach
    pyld and fail only on the signature."""
    context, subject, proof_member, extra = _budget_rows()[row]
    if row == "served-url-repeated":
        context = [V2] * 3
    small = _scoped_shrunk(context, subject, proof_member, extra)
    document = _document(suite_id, small[0], small[1], **small[3])
    if small[2]:
        document["proof"] = dict(document["proof"], **small[2])
    with pytest.raises(ProofError) as caught:
        ENTRIES[entry](document, _extra_for(row))
    assert type(caught.value) is SignatureInvalid, caught.value
    assert real_terms[0] > 0


def _scoped_shrunk(context, subject, proof_member, extra):
    """The row with every scoped context cut to 3 terms and every use list to 3."""
    def shrink(value):
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                if key.startswith("k") and key[1:].isdigit():
                    if int(key[1:]) >= 3:
                        continue
                out[key] = shrink(item)
            return out
        if isinstance(value, list) and len(value) > 3 and not (
                value and isinstance(value[0], str) and value[0] == V2):
            return [shrink(item) for item in value[:3]]
        if isinstance(value, list):
            return [shrink(item) for item in value]
        return value
    return (shrink(context), shrink(subject), shrink(proof_member) if proof_member else None,
            shrink(extra))


# --- the calls after the signature, and the holder's derivation ------------------------ #

def _hostile_body(k=70, n=70):
    return {"@context": [V2, ABS], "type": ["VerifiableCredential"], "issuer": ED_DID,
            "credentialSubject": {"id": "did:example:s", "jwk": _node(k, n)}}


def test_context_validation_after_the_signature_is_budgeted_too(low, real_terms):
    document = _hostile_body()
    config = {"type": "DataIntegrityProof", "@context": document["@context"]}
    with pytest.raises(ProofError) as caught:
        validate_document(document, config, document_loader(None))
    assert type(caught.value) is CanonicalizationBudgetExceeded, caught.value
    assert LIMIT - 200 <= real_terms[0] <= LIMIT + 800


def test_missing_types_is_budgeted_too(low, real_terms):
    from openvc.proof._context_validation import missing_types

    with pytest.raises(ProofError) as caught:
        missing_types(_hostile_body(), ["VerifiableCredential"], document_loader(None))
    assert type(caught.value) is CanonicalizationBudgetExceeded, caught.value
    assert LIMIT - 200 <= real_terms[0] <= LIMIT + 800


def test_deriving_from_a_third_partys_base_credential_is_budgeted(
        low, real_terms, monkeypatch):
    """``derive_proof`` canonicalizes a credential another party issued; its expansion and
    compaction (``_transform``) run under the same budget."""
    suite = EcdsaSdProofSuite()
    document = _hostile_body(k=2, n=2)
    with monkeypatch.context() as patched:                   # sign it, tiny, unvalidated
        patched.setattr(ecdsa_sd, "validate_document", lambda *args, **kwargs: None)
        base = suite.add_base_proof(
            {**document, "issuer": P256_DID, "validFrom": "2020-01-01T00:00:00Z"},
            signing_key=P256_KEY, verification_method=P256_VM,
            mandatory_pointers=["/issuer"])
    base["credentialSubject"]["jwk"] = _node(70, 70)          # swapped for the hostile body
    real_terms[0] = 0
    with pytest.raises(ProofError) as caught:
        suite.derive_proof(base, selective_pointers=["/credentialSubject/id"])
    assert type(caught.value) is CanonicalizationBudgetExceeded, caught.value
    assert LIMIT - 200 <= real_terms[0] <= LIMIT + 800


# --- the copy of a big active context is charged too ------------------------------ #

def test_cloning_a_big_active_context_for_many_scoped_types_is_charged(
        monkeypatch, real_terms):
    """A served context of 5 000 terms is cheap to define once, but pyld copies the active
    context for every node whose type brings a scoped context of its own (the bundled
    ``JsonSchema``): the copies, one unit per 512 entries, stop it where the definitions
    alone (a handful per node) would not."""
    monkeypatch.setattr(_rdfc, "MAX_CONTEXT_WORK", 20_000)
    big = {"https://a.example/ctx/big": {"@context": {
        f"b{i}": f"https://a.example/b{i}" for i in range(5000)}}}
    n = 1200
    doc = _rdf_credential(
        "eddsa-rdfc-2022", [V2, "https://a.example/ctx/big"], {"id": "did:example:s"},
        credentialSchema=[{"id": f"https://e.example/s{i}", "type": "JsonSchema"}
                          for i in range(n)])
    with pytest.raises(ProofError) as caught:
        verify_credential(doc, policy=POLICY, extra_contexts=big)
    assert type(caught.value) is CanonicalizationBudgetExceeded, caught.value
    assert real_terms[0] < 20_000, "the definitions alone are under the ceiling"


# --- the issue's own shape, at the real ceiling ----------------------------------- #

def test_the_issues_document_at_its_size_is_refused_at_the_default_ceiling(real_terms):
    k = n = 1000                                   # the issue's 43 KB row, refused in 0.4 s
    doc = _rdf_credential("eddsa-rdfc-2022", [V2, ABS],
                          {"id": "did:example:s", "jwk": _node(k, n)})
    with pytest.raises(CanonicalizationBudgetExceeded):
        verify_credential(doc, policy=POLICY)
    assert _rdfc.MAX_CONTEXT_WORK - 200 <= real_terms[0] <= _rdfc.MAX_CONTEXT_WORK + 800


# --- ldp_vc in verify_vp_token (the shape OpenID4VP mandates) ----------------------- #

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"
DCQL = {"credentials": [{"id": "c1", "format": "ldp_vc"}]}


def _vp(suite_id, embedded):
    did, vm = (ED_DID, ED_VM) if suite_id == "eddsa-rdfc-2022" else (P256_DID, P256_VM)
    return {"@context": [V2], "type": ["VerifiablePresentation"], "holder": did,
            "verifiableCredential": embedded,
            "proof": {"type": "DataIntegrityProof", "cryptosuite": suite_id,
                      "created": "2026-01-01T00:00:00Z", "verificationMethod": vm,
                      "proofPurpose": "authentication", "challenge": NONCE,
                      "domain": CLIENT_ID, "proofValue": GARBAGE}}


def _answer(vp):
    return verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_an_ldp_vc_presentation_embedding_a_scoped_context_is_refused_by_the_budget(
        suite_id, low, real_terms):
    k = n = 70
    embedded = [{"@context": [V2, _scoped(k)], "type": ["VerifiableCredential"],
                 "issuer": ED_DID, "credentialSubject": {
                     "id": "did:example:s",
                     "https://a.example/p": [{"@type": "T", "id": "a:s"}] * n}}]
    with pytest.raises(ProofError) as caught:
        _answer(_vp(suite_id, embedded))
    assert type(caught.value) is CanonicalizationBudgetExceeded, caught.value
    assert LIMIT - 200 <= real_terms[0] <= LIMIT + 800


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_an_ldp_vc_control_reaches_pyld_and_fails_on_the_signature(suite_id, real_terms):
    with pytest.raises(ProofError) as caught:
        _answer(_vp(suite_id, [{"@context": [V2], "type": ["VerifiableCredential"],
                                "issuer": ED_DID, "credentialSubject": {"id": "did:example:s"}}]))
    assert type(caught.value) is SignatureInvalid, caught.value
    assert real_terms[0] > 0


# --- the type_values route (a self-signed JCS credential, no RDF suite involved) ------ #

def test_type_values_expansion_of_a_self_signed_credential_is_bounded(low, real_terms):
    key, did, vm = _ed_key()
    jcs = EddsaJcsProofSuite()
    k = n = 70
    vc = jcs.add_proof(
        {"@context": [V2, ABS, _scoped(k)], "type": ["VerifiableCredential"] + ["T"] * n,
         "issuer": did, "credentialSubject": {"id": did}},
        signing_key=key, verification_method=vm, proof_purpose="assertionMethod")
    vp = jcs.add_proof(
        {"@context": [V2], "type": ["VerifiablePresentation"], "holder": did,
         "verifiableCredential": [vc]},
        signing_key=key, verification_method=vm, proof_purpose="authentication",
        challenge=NONCE, domain=CLIENT_ID)
    query = {"credentials": [{"id": "c1", "format": "ldp_vc", "meta": {
        "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]]}}]}
    with pytest.raises(ClaimsInvalid, match="CanonicalizationBudgetExceeded") as caught:
        verify_vp_token({"c1": [vp]}, dcql_query=query, nonce=NONCE, client_id=CLIENT_ID)
    assert type(caught.value) is ClaimsInvalid
    assert LIMIT - 200 <= real_terms[0] <= LIMIT + 800


# --------------------------------------------------------------------------- #
# 3. What is accepted today still verifies (no wrong-reject)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
@pytest.mark.parametrize("context", [[V2], [V2, ABS]], ids=["bundled", "inline-vocab"])
def test_accepted_contexts_still_verify(suite_id, context):
    secured = _signed(suite_id, _rdf_credential(suite_id, context))
    assert verify_credential(secured, policy=POLICY).issuer


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_an_extra_contexts_url_with_a_scoped_context_still_verifies(suite_id):
    url = "https://a.example/ctx/nick"
    extra = {url: {"@context": {"nick": "https://a.example/vocab#nick",
                                "T": {"@id": "https://a.example/T", "@context": {
                                    "k": "https://a.example/k"}}}}}
    doc = _rdf_credential(suite_id, [V2, url], {"id": "did:example:s", "nick": "Al", "type": "T"})
    secured = _signed(suite_id, doc, extra_contexts=extra)
    assert verify_credential(secured, policy=POLICY, extra_contexts=extra).issuer


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
@pytest.mark.parametrize("member", [
    {"cnf": {"jwk": {"@context": {"T": "a:T"}, "kty": "OKP"}}},
    {"cnf": {"jwk": {"kty": "OKP", "x": [{"@context": "x"}]}}},
    {"credentialSchema": {"id": "https://e.example/s", "type": "JsonSchema",
                          "jsonSchema": {"@context": {"a": "b"}}}},
], ids=["cnf-jwk", "cnf-jwk-array", "json-schema"])
def test_an_at_context_key_inside_a_json_literal_still_verifies(suite_id, member):
    secured = _signed(suite_id, _rdf_credential(suite_id, [V2], **member))
    assert verify_credential(secured, policy=POLICY).issuer


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_a_json_literal_spelled_through_a_value_alias_still_verifies(suite_id):
    """The review's wrong-reject family 1: a served context aliases ``@value``."""
    url = "https://a.example/ctx/val"
    j_term = {"@id": "https://a.example/j", "@type": "@json"}
    extra = {url: {"@context": {"val": "@value", "j": j_term}}}
    doc = _rdf_credential(suite_id, [V2, url],
                          {"id": "did:example:s", "j": {"@context": {"a": "b"}}})
    secured = _signed(suite_id, doc, extra_contexts=extra)
    assert verify_credential(secured, policy=POLICY, extra_contexts=extra).issuer


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_a_language_map_key_spelled_at_context_still_verifies(suite_id):
    """The review's wrong-reject family 2: a language map with a key spelled ``@context``."""
    url = "https://a.example/ctx/lang"
    extra = {url: {"@context": {"label": {"@id": "https://a.example/label",
                                          "@container": "@language"}}}}
    doc = _rdf_credential(suite_id, [V2, url],
                          {"id": "did:example:s", "label": {"@context": "x", "en": "y"}})
    try:
        secured = _signed(suite_id, doc, extra_contexts=extra)
    except ProofError:
        pytest.skip("this pyld spells the language map differently")
    assert verify_credential(secured, policy=POLICY, extra_contexts=extra).issuer


def test_a_presentation_embedding_a_credential_with_a_term_still_verifies_its_shape():
    embedded = {"@context": [V2, {"T": {"@id": "https://a.example/T"}}],
                "type": ["VerifiableCredential"], "issuer": ED_DID,
                "credentialSubject": {"id": "did:example:s"}}
    presentation = {"@context": V2, "type": ["VerifiablePresentation"],
                    "verifiableCredential": [embedded]}
    check_context_before_expansion(presentation)           # the presentation's own context


# --------------------------------------------------------------------------- #
# 4. The budgeted processor is pyld's own, and its charge is never below the real work
# --------------------------------------------------------------------------- #

def _random_context(rng: random.Random, depth: int = 0) -> dict:
    ctx: dict[str, Any] = {}
    for i in range(rng.randint(1, 6)):
        term = f"t{depth}_{i}"
        kind = rng.choice(["iri", "id", "typed", "scoped", "scoped", "nopropagate", "protected"])
        iri = f"https://f.example/{term}"
        if kind == "iri":
            ctx[term] = iri
        elif kind == "id":
            ctx[term] = {"@id": iri, "@type": "@id"}
        elif kind == "typed":
            ctx[term] = {"@id": iri, "@type": "http://www.w3.org/2001/XMLSchema#integer"}
        elif kind == "protected":
            ctx[term] = {"@id": iri, "@protected": True}
        else:
            inner = _random_context(rng, depth + 1) if depth < 2 else {"x": iri + "/x"}
            if kind == "nopropagate":
                inner["@propagate"] = False
            ctx[term] = {"@id": iri, "@context": inner}
    if rng.random() < 0.3:
        ctx["@vocab"] = "https://v.example/"
    if rng.random() < 0.2:
        ctx["@protected"] = True
    return ctx


def _random_document(rng: random.Random, ctx: dict, depth: int = 0) -> dict:
    node: dict[str, Any] = {"@id": f"https://n.example/{rng.randint(0, 99)}"}
    terms = [t for t in ctx if not t.startswith("@")]
    if terms and rng.random() < 0.6:
        node["@type"] = rng.sample(terms, min(len(terms), rng.randint(1, 2)))
    for term in rng.sample(terms, min(len(terms), 3)):
        if depth < 3 and rng.random() < 0.6:
            node[term] = [_random_document(rng, ctx, depth + 1)
                          for _ in range(rng.randint(1, 4))]
        else:
            node[term] = rng.choice(["v", 5, {"@id": "https://n.example/ref"}])
    if depth > 0 and rng.random() < 0.25:                    # a node's own context
        node["@context"] = _random_context(rng, 5)
    return node


def _outcome(call):
    try:
        return ("ok", call())
    except jsonld.JsonLdError as exc:
        return ("error", exc.code if hasattr(exc, "code") else type(exc).__name__)


def test_the_budgeted_processor_is_pyld_byte_for_byte_and_its_charge_is_never_below(
        real_terms):
    loader = document_loader(None)
    rng = random.Random(446)
    compared = 0
    for _ in range(300):
        ctx = _random_context(rng)
        document = _random_document(rng, ctx)
        document["@context"] = [V2, ctx] if rng.random() < 0.5 else ctx
        reference = _outcome(lambda: JsonLdProcessor().expand(
            copy.deepcopy(document), pyld_options(loader)))
        real_terms[0] = 0
        processor = _rdfc.new_processor()
        ours = _outcome(lambda: processor.expand(copy.deepcopy(document), pyld_options(loader)))
        assert ours == reference
        assert processor.terms >= real_terms[0], "the charge is below the work done"
        assert processor.terms == real_terms[0]
        if ours[0] != "ok":
            continue
        compared += 1
        assert _outcome(lambda: _rdfc.budgeted_compact(
            ours[1], document["@context"], loader)) == _outcome(
            lambda: JsonLdProcessor().compact(
                copy.deepcopy(ours[1]), document["@context"], pyld_options(loader)))
        assert _outcome(lambda: _rdfc.to_rdf(copy.deepcopy(document), loader,
                                             format="application/n-quads")) == _outcome(
            lambda: JsonLdProcessor().to_rdf(
                copy.deepcopy(document),
                pyld_options(loader, format="application/n-quads")))
    assert compared > 100              # the fuzz is not vacuous: most documents expand


def test_each_processor_has_its_own_counters_and_a_trip_is_sticky(monkeypatch):
    first, second = _rdfc.new_processor(), _rdfc.new_processor()
    loader = document_loader(None)
    document = {"@context": [V2, ABS, _scoped(10)], "@id": "a:s", "@type": ["T"]}
    first.expand(document, pyld_options(loader))
    assert first.terms > 0 and second.terms == 0
    monkeypatch.setattr(_rdfc, "MAX_CONTEXT_WORK", 5)
    tight = _rdfc.new_processor()
    with pytest.raises(CanonicalizationBudgetExceeded, match="limit 5"):
        _rdfc.budgeted_expand(document, loader, tight)   # pyld re-wraps what a scope raises
    assert tight.tripped is not None


def test_a_second_budget_error_is_the_same_class_from_every_helper(monkeypatch):
    monkeypatch.setattr(_rdfc, "MAX_CONTEXT_WORK", 5)
    loader = document_loader(None)
    document = {"@context": [V2, _scoped(10)], "@id": "a:s", "@type": ["T"]}
    for call in (lambda: _rdfc.budgeted_expand(document, loader),
                 lambda: _rdfc.to_rdf(document, loader),
                 lambda: _rdfc.canonicalize_nquads(document, loader),
                 lambda: _rdfc.budgeted_compact({"@id": "a:s"}, document["@context"], loader)):
        with pytest.raises(CanonicalizationBudgetExceeded):
            call()


# --------------------------------------------------------------------------- #
# 5. No call site can forget the budget
# --------------------------------------------------------------------------- #

_SRC = Path(__file__).resolve().parents[1] / "src"
_UNBUDGETED = {"expand", "compact", "to_rdf", "flatten", "frame", "normalize", "from_rdf",
               "process_context", "load_document"}


def test_no_source_file_calls_an_unbudgeted_pyld_entry_point():
    """Every expansion, compaction and conversion goes through ``openvc.proof._rdfc``'s
    budgeted processor: nothing else in the source calls ``jsonld.<entry>`` or constructs a
    bare ``JsonLdProcessor`` (``_rdfc`` itself builds the budgeted subclass)."""
    offenders = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _UNBUDGETED):
                receiver = node.func.value
                name = receiver.id if isinstance(receiver, ast.Name) else (
                    receiver.attr if isinstance(receiver, ast.Attribute) else
                    receiver.func.id if isinstance(receiver, ast.Call)
                    and isinstance(receiver.func, ast.Name) else "")
                if name in {"jsonld", "pyld", "_pyld", "JsonLdProcessor"}:
                    offenders.append(
                        f"{path.relative_to(_SRC)}:{node.lineno} {name}.{node.func.attr}")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "JsonLdProcessor"):
                offenders.append(f"{path.relative_to(_SRC)}:{node.lineno} JsonLdProcessor()")
    assert not offenders, offenders
