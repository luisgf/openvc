"""
tests/test_di_context_before_expansion.py — inline term definitions are refused before
JSON-LD expansion on the three RDF Data Integrity suites (issue #446).

pyld re-processes a term's scoped context every time the term is used, so one inline
definition of K terms used by N nodes costs about N x K, and ``eddsa-rdfc-2022``,
``ecdsa-rdfc-2019`` and ``ecdsa-sd-2023`` expand before they check a signature. The shape
is one ``_check_context`` refuses after the signature anyway; ``check_before_expansion``
(``openvc.proof._context_validation``) now runs the structural rule first, plus the same
rule for a nested ``@context`` (which the compaction round trip refuses after the
signature, except inside an ``@json`` literal and inside the credentials a presentation
embeds). Refusal is asserted by pyld's expansion never being entered, counted on both the
module-level functions and ``JsonLdProcessor``'s methods, never by wall-clock. Every
hostile row is paired with a control that DOES expand (the counter is above zero), so a
count of zero cannot come from a document that never got that far. Self-contained helpers
(tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import asyncio
import copy
from typing import Any

import pytest

pytest.importorskip("pyld")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from pyld import jsonld  # noqa: E402

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
from openvc.proof import data_integrity, di_ecdsa_rdfc, ecdsa_sd  # noqa: E402
from openvc.proof._context_validation import (  # noqa: E402
    check_before_expansion,
    validate_document,
)
from openvc.proof.contexts import document_loader  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import ProofError, ProofMalformed, SignatureInvalid  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
ONLY_VOCAB = "an inline @context object may only carry @vocab"
NESTED = "a nested @context"
SUITES = ["eddsa-rdfc-2022", "ecdsa-rdfc-2019", "ecdsa-sd-2023"]
POLICY = VerificationPolicy(require_status=False)


# --------------------------------------------------------------------------- #
# The pyld counter
# --------------------------------------------------------------------------- #

@pytest.fixture
def expansions(monkeypatch):
    """Counts every entry into pyld's expansion / RDF conversion (module functions and
    ``JsonLdProcessor`` methods, which the module functions delegate to)."""
    calls: list[str] = []

    def wrap(owner, name):
        original = getattr(owner, name)

        def counted(*args, **kwargs):
            calls.append(name)
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, name, counted)

    for name in ("expand", "to_rdf", "compact", "normalize"):
        wrap(jsonld, name)
    for name in ("expand", "to_rdf"):
        wrap(jsonld.JsonLdProcessor, name)
    return calls


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


def _scoped_context(k: int, shape: str = "type") -> list:
    inner = {f"k{i}": f"https://a.example/k{i}" for i in range(k)}
    if shape == "type":
        term = {"T": {"@id": "https://a.example/T", "@context": inner}}
    else:                                           # a property-scoped context
        term = {"p": {"@id": "https://a.example/p", "@context": inner}}
    return [V2, term]


def _body(n: int, shape: str = "type") -> dict:
    if shape == "type":
        return {"id": "did:example:s", "@included": [{"type": "T", "id": "a:s"}] * n}
    return {"id": "did:example:s", "p": [{"id": "a:s"}] * n}


def _rdfc(suite_id: str, context, subject=None, **extra) -> dict:
    """An RDF-suite credential with a garbage proof (issuer a resolvable did:key)."""
    did, vm = (ED_DID, ED_VM) if suite_id == "eddsa-rdfc-2022" else (P256_DID, P256_VM)
    doc = {"@context": context, "type": ["VerifiableCredential"], "issuer": did,
           "credentialSubject": subject or {"id": "did:example:s"},
           "proof": {"type": "DataIntegrityProof", "cryptosuite": suite_id,
                     "created": "2026-01-01T00:00:00Z", "verificationMethod": vm,
                     "proofPurpose": "assertionMethod", "proofValue": GARBAGE}}
    doc.update(extra)
    return doc


def _signed(suite_id: str, doc: dict, monkeypatch=None) -> dict:
    """*doc* signed by its issuer's key; *monkeypatch* switches the signing-side
    validation off, to hold a document the verifier would refuse."""
    doc = {k: v for k, v in doc.items() if k != "proof"}
    if suite_id == "eddsa-rdfc-2022":
        suite, key, vm, module = DataIntegrityProofSuite(), ED_KEY, ED_VM, data_integrity
    else:
        suite, key, vm, module = EcdsaRdfcProofSuite(), P256_KEY, P256_VM, di_ecdsa_rdfc
    if monkeypatch is None:
        return suite.add_proof(doc, signing_key=key, verification_method=vm)
    with monkeypatch.context() as patched:      # undone before anything is verified
        patched.setattr(module, "validate_document", lambda *args, **kwargs: None)
        return suite.add_proof(doc, signing_key=key, verification_method=vm)


def _sd_derived(context=None, subject_extra=None, monkeypatch=None) -> dict:
    doc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
           "validFrom": "2020-01-01T00:00:00Z",
           "credentialSubject": {"id": "did:example:alice", "name": "Alice"}}
    if context is not None:
        doc["@context"] = context
    if subject_extra:
        doc["credentialSubject"].update(subject_extra)
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


def _document(suite_id: str, context=None, subject=None) -> dict:
    """The document under test for *suite_id*: an ``ecdsa-sd`` derived credential swapped
    to *context* / *subject* members, else an RDF-suite credential with a garbage proof."""
    if suite_id == "ecdsa-sd-2023":
        derived = copy.deepcopy(_DERIVED)
        if context is not None:
            derived["@context"] = context
        if subject is not None:
            derived["credentialSubject"] = subject
        return derived
    return _rdfc(suite_id, context if context is not None else [V2], subject)


# --------------------------------------------------------------------------- #
# The hostile rows (the issue's table) and their controls
# --------------------------------------------------------------------------- #

def _hostile_rows():
    return {
        "type-scoped": (_scoped_context(40), _body(40)),
        "property-scoped": (_scoped_context(40, "property"), _body(40, "property")),
        "inline-import": ([V2, {"@import": "https://a.example/ctx"}], None),
        "inline-vocab-plus-terms": ([V2, {"@vocab": "https://a.example/", "T": "a:T"}], None),
        "context-not-a-list": ({"@vocab": "https://a.example/"}, None),
        "context-an-int": (5, None),
        "context-null-entry": ([V2, None], None),
    }


ROWS = sorted(_hostile_rows())


def _row(suite_id: str, row: str) -> dict:
    context, subject = _hostile_rows()[row]
    return _document(suite_id, context, subject)


def _control(suite_id: str) -> dict:
    """The row's document minus the hostile context: it expands, then fails the signature."""
    return _document(suite_id, [V2, {"@vocab": "https://a.example/"}], _body(40, "property"))


def _verify_sync(suite_id: str, doc: dict) -> Any:
    return verify_credential(copy.deepcopy(doc), policy=POLICY)


def _verify_async(suite_id: str, doc: dict) -> Any:
    return asyncio.run(verify_credential_async(copy.deepcopy(doc), policy=POLICY))


def _verify_suite(suite_id: str, doc: dict) -> Any:
    suite = {"eddsa-rdfc-2022": DataIntegrityProofSuite,
             "ecdsa-rdfc-2019": EcdsaRdfcProofSuite,
             "ecdsa-sd-2023": EcdsaSdProofSuite}[suite_id]()
    return suite.verify(copy.deepcopy(doc))


def _verify_many(suite_id: str, doc: dict) -> Any:
    (item,) = verify_many([copy.deepcopy(doc)], policy=POLICY)
    if item.error is not None:
        raise item.error
    return item.result


def _verify_many_async(suite_id: str, doc: dict) -> Any:
    (item,) = asyncio.run(verify_many_async([copy.deepcopy(doc)], policy=POLICY))
    if item.error is not None:
        raise item.error
    return item.result


ENTRIES = {"verify_credential": _verify_sync, "verify_credential_async": _verify_async,
           "verify_many": _verify_many, "verify_many_async": _verify_many_async,
           "suite.verify": _verify_suite}


@pytest.mark.parametrize("entry", sorted(ENTRIES))
@pytest.mark.parametrize("row", ROWS)
@pytest.mark.parametrize("suite_id", SUITES)
def test_inline_term_definitions_are_refused_before_pyld_expands(
        suite_id, row, entry, expansions):
    with pytest.raises(ProofError) as caught:
        ENTRIES[entry](suite_id, _row(suite_id, row))
    assert type(caught.value) is ProofMalformed, caught.value
    assert expansions == [], "pyld was entered before the refusal"


@pytest.mark.parametrize("entry", sorted(ENTRIES))
@pytest.mark.parametrize("suite_id", SUITES)
def test_control_without_the_hostile_context_does_expand(suite_id, entry, expansions):
    with pytest.raises(ProofError) as caught:
        ENTRIES[entry](suite_id, _control(suite_id))
    assert type(caught.value) is SignatureInvalid, caught.value
    assert expansions, "the control must reach pyld, or a count of zero proves nothing"


# --- the nested @context variants ------------------------------------------- #

def _nested_rows():
    scoped = {"T": {"@id": "https://a.example/T",
                    "@context": {f"k{i}": f"https://a.example/k{i}" for i in range(40)}}}
    node = {"@context": scoped, "id": "did:example:s",
            "https://a.example/p": [{"@type": "T", "id": "a:s"}] * 40}
    return {"nested-in-subject": (None, node, None),
            "nested-url-in-subject": (None, {"@context": V2, "id": "did:example:s"}, None),
            "nested-in-array": (None, [{"id": "did:example:s"}, node], None),
            "nested-in-proof": ([V2, {"@vocab": "https://a.example/"}],
                                {"id": "did:example:s"},
                                {"https://a.example/x": {"@context": scoped}})}


@pytest.mark.parametrize("entry", ["verify_credential", "suite.verify"])
@pytest.mark.parametrize("row", sorted(_nested_rows()))
@pytest.mark.parametrize("suite_id", SUITES)
def test_a_nested_context_is_refused_before_pyld_expands(suite_id, row, entry, expansions):
    context, subject, proof_member = _nested_rows()[row]
    doc = _document(suite_id, context, subject)
    if proof_member:
        doc["proof"].update(proof_member)
    with pytest.raises(ProofError) as caught:
        ENTRIES[entry](suite_id, doc)
    assert type(caught.value) is ProofMalformed, caught.value
    assert NESTED in str(caught.value)
    assert expansions == []


# --- ldp_vc in verify_vp_token ----------------------------------------------- #

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"
DCQL = {"credentials": [{"id": "c1", "format": "ldp_vc"}]}


def _vp(context, suite_id="eddsa-rdfc-2022") -> dict:
    did, vm = (ED_DID, ED_VM) if suite_id == "eddsa-rdfc-2022" else (P256_DID, P256_VM)
    return {"@context": context, "type": ["VerifiablePresentation"], "holder": did,
            "proof": {"type": "DataIntegrityProof", "cryptosuite": suite_id,
                      "created": "2026-01-01T00:00:00Z", "verificationMethod": vm,
                      "proofPurpose": "authentication", "challenge": NONCE,
                      "domain": CLIENT_ID, "proofValue": GARBAGE}}


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_ldp_vc_answer_with_an_inline_term_definition_is_refused_first(suite_id, expansions):
    with pytest.raises(ProofError) as caught:
        verify_vp_token({"c1": [_vp(_scoped_context(40), suite_id)]}, dcql_query=DCQL,
                        nonce=NONCE, client_id=CLIENT_ID)
    assert type(caught.value) is ProofMalformed, caught.value
    assert expansions == []


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_ldp_vc_control_reaches_pyld(suite_id, expansions):
    with pytest.raises(ProofError) as caught:
        verify_vp_token({"c1": [_vp([V2])]}, dcql_query=DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)
    assert type(caught.value) is SignatureInvalid, caught.value
    assert expansions


# --- a VALID signature does not change the refusal ---------------------------- #

@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_a_valid_signature_with_an_inline_term_definition_keeps_class_and_message(
        suite_id, monkeypatch, expansions):
    signed = _signed(suite_id, _rdfc(suite_id, _scoped_context(5), _body(5)), monkeypatch)
    del expansions[:]
    with pytest.raises(ProofMalformed, match=ONLY_VOCAB) as caught:
        verify_credential(signed, policy=POLICY)
    assert type(caught.value) is ProofMalformed
    assert expansions == []


def test_a_valid_ecdsa_sd_signature_with_an_inline_term_definition_keeps_class_and_message(
        monkeypatch, expansions):
    derived = _sd_derived(
        context=[V2, {"T": {"@id": "https://a.example/T", "@context": {"k": "a:k"}}}],
        monkeypatch=monkeypatch)
    del expansions[:]
    with pytest.raises(ProofMalformed, match=ONLY_VOCAB) as caught:
        verify_credential(derived, policy=POLICY)
    assert type(caught.value) is ProofMalformed
    assert expansions == []


# --- what is accepted today still verifies ----------------------------------- #

@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
@pytest.mark.parametrize("name, context", [
    ("bundled", [V2]),
    ("inline-vocab", [V2, {"@vocab": "https://a.example/"}]),
], ids=lambda value: value if isinstance(value, str) else "")
def test_accepted_contexts_still_verify(suite_id, name, context):
    secured = _signed(suite_id, _rdfc(suite_id, context))
    assert verify_credential(secured, policy=POLICY).issuer


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_an_extra_contexts_url_still_verifies(suite_id):
    url = "https://a.example/ctx/nick"
    extra = {url: {"@context": {"nick": "https://a.example/vocab#nick",
                                "T": {"@id": "https://a.example/T", "@context": {
                                    "k": "https://a.example/k"}}}}}
    doc = _rdfc(suite_id, [V2, url], {"id": "did:example:s", "nick": "Al"})
    del doc["proof"]
    suite = DataIntegrityProofSuite() if suite_id == "eddsa-rdfc-2022" \
        else EcdsaRdfcProofSuite()
    key, vm = (ED_KEY, ED_VM) if suite_id == "eddsa-rdfc-2022" else (P256_KEY, P256_VM)
    secured = suite.add_proof(doc, signing_key=key, verification_method=vm,
                              extra_contexts=extra)
    assert verify_credential(secured, policy=POLICY, extra_contexts=extra).issuer


@pytest.mark.parametrize("suite_id", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
@pytest.mark.parametrize("member", [
    {"cnf": {"jwk": {"@context": {"T": "a:T"}, "kty": "OKP"}}},     # @json (cnf scope)
    {"cnf": {"jwk": {"kty": "OKP", "x": [{"@context": "x"}]}}},     # inside an array
    {"credentialSchema": {"id": "https://e.example/s", "type": "JsonSchema",
                          "jsonSchema": {"@context": {"a": "b"}}}},  # @json (type scope)
], ids=["cnf-jwk", "cnf-jwk-array", "json-schema"])
def test_an_at_context_key_inside_a_json_literal_still_verifies(suite_id, member):
    secured = _signed(suite_id, _rdfc(suite_id, [V2], **member))
    assert verify_credential(secured, policy=POLICY).issuer


def test_a_json_term_of_an_extra_context_is_exempt_too():
    url = "https://a.example/ctx/json"
    extra = {url: {"@context": {"blob": {"@id": "https://a.example/blob",
                                         "@type": "@json"}}}}
    doc = _rdfc("eddsa-rdfc-2022", [V2, url],
                {"id": "did:example:s", "blob": {"@context": {"a": "b"}}})
    del doc["proof"]
    secured = DataIntegrityProofSuite().add_proof(
        doc, signing_key=ED_KEY, verification_method=ED_VM, extra_contexts=extra)
    assert verify_credential(secured, policy=POLICY, extra_contexts=extra).issuer


def test_credentials_embedded_in_a_presentation_are_not_checked_as_the_presentation():
    embedded = {"@context": [V2, {"T": {"@id": "https://a.example/T"}}],
                "type": ["VerifiableCredential"], "issuer": ED_DID,
                "credentialSubject": {"id": "did:example:s"}}
    presentation = {"@context": V2, "type": ["VerifiablePresentation"],
                    "verifiableCredential": [embedded]}
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022"}
    check_before_expansion(presentation, proof, None)             # not refused
    # the same shape as a credential body is
    with pytest.raises(ProofMalformed, match=NESTED):
        check_before_expansion(
            {"@context": V2, "type": ["VerifiableCredential"],
             "evidence": [embedded]}, proof, None)


# --------------------------------------------------------------------------- #
# The differential: the early check refuses a subset of what the full validation does
# --------------------------------------------------------------------------- #

def _refused(call) -> bool:
    try:
        call()
    except ProofError:
        return True
    return False


_ABS = {"@vocab": "https://a.example/"}
_ENTRIES = [V2, V1, "https://unserved.example/ctx", _ABS, {"@vocab": "rel"},
            {"@vocab": "_:"}, {"T": "https://a.example/T"}, {"@import": V2},
            {"@version": 1.1}, {}, None, 5, [V2], "", _ABS | {"T": "a:T"}]


def _context_corpus():
    yield from _ENTRIES
    yield []
    for first in _ENTRIES:
        yield [first]
        for second in _ENTRIES:
            yield [first, second]
    for second in _ENTRIES:
        for third in _ENTRIES:
            yield [V2, second, third]


def _members():
    json_members = [
        {"cnf": {"jwk": {"@context": "x"}}},
        {"cnf": {"jwk": [{"@context": "x"}]}},
        {"_sd": {"@context": "x"}},
        {"credentialSchema": {"id": "https://e.example/s", "type": "JsonSchema",
                              "jsonSchema": {"@context": {}}}},
    ]
    refused = [
        {"credentialSubject": {"id": "did:example:s", "@context": {"T": "a:T"}}},
        {"credentialSubject": [{"id": "did:example:s"}, {"@context": V2}]},
        {"evidence": {"@context": None}},
        {"https://a.example/x": {"@context": [V2]}},
        {"jwk": {"@context": "x"}},                       # a json name, not a json position
        {"cnf": {"@context": "x"}},
    ]
    return json_members + refused


def test_the_early_check_refuses_a_subset_of_the_full_validation():
    loader = document_loader(None)
    checked = refused_early = 0
    for context in _context_corpus():
        doc = {"@context": context, "type": ["VerifiableCredential"], "issuer": ED_DID,
               "credentialSubject": {"id": "did:example:s"}}
        proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                 "created": "2026-01-01T00:00:00Z", "verificationMethod": ED_VM,
                 "proofPurpose": "assertionMethod"}
        early = _refused(lambda: check_before_expansion(doc, proof, None))
        late = _refused(lambda: validate_document(doc, dict(proof, **{"@context": context}),
                                                  loader))
        assert late or not early, f"the early check refused what validates: {context!r}"
        checked += 1
        refused_early += early
    for member in _members():
        for context in ([V2], [V2, _ABS]):
            doc = {"@context": context, "type": ["VerifiableCredential"],
                   "issuer": ED_DID, "credentialSubject": {"id": "did:example:s"}}
            doc.update(member)
            proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                     "created": "2026-01-01T00:00:00Z", "verificationMethod": ED_VM,
                     "proofPurpose": "assertionMethod"}
            early = _refused(lambda: check_before_expansion(doc, proof, None))
            late = _refused(lambda: validate_document(
                doc, dict(proof, **{"@context": context}), loader))
            assert late or not early, f"the early check refused what validates: {member!r}"
            checked += 1
            refused_early += early
    assert checked > 300 and refused_early > 200          # the corpus is not vacuous


def test_the_early_context_rule_is_the_one_the_full_validation_applies_first():
    # for the document's @context the two are the same function: same class, same message
    loader = document_loader(None)
    for context in (None, 5, [], [V2, {"T": "a:T"}], [V2, {"@vocab": "rel"}], ["x"]):
        doc = {"@context": context, "type": ["VerifiableCredential"]}
        with pytest.raises(ProofMalformed) as early:
            check_before_expansion(doc, {}, None)
        with pytest.raises(ProofMalformed) as late:
            validate_document(doc, {"@context": context}, loader)
        assert str(early.value) == str(late.value)


def test_the_json_name_exemption_is_the_known_residual():
    """A nested context under a key spelled like a served @json term, at a position where
    it is no literal (here under an inline @vocab), is let through by the early check by
    design (over-exempting is what keeps it a subset) and refused after the signature."""
    doc = {"@context": [V2, _ABS], "type": ["VerifiableCredential"], "issuer": ED_DID,
           "credentialSubject": {"id": "did:example:s",
                                 "jwk": {"@context": {"T": "a:T"}}}}
    check_before_expansion(doc, {}, None)
    with pytest.raises(ProofMalformed):
        validate_document(doc, {"@context": doc["@context"]}, document_loader(None))
