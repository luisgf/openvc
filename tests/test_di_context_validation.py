"""
tests/test_di_context_validation.py — the RDF Data Integrity suites validate the
document's JSON-LD form once the proof verifies (VC Data Integrity §2.4.1 / §4.6).

``eddsa-rdfc-2022``, ``ecdsa-rdfc-2019`` and ``ecdsa-sd-2023`` sign the RDF dataset a
document expands to, while every policy check after the signature (validity window,
``credentialStatus``, ``credentialSchema``, issuer/subject, holder binding) reads the
JSON. Through v1.30.1 nothing tied the two together, so JSON that expands to the signed
dataset could still show the policy something else: a signed member re-keyed to its IRI,
an inline ``@context`` that aliases a term or re-maps ``credentialSubject``, a term no
context defines (dropped from the dataset, so never signed), or ``@included`` / a nested
re-description moving signed statements out of the object the policy reads.

Every attack here keeps the signature valid — that is the point — and must now fail with
a typed :class:`ProofMalformed` on the sync and the async pipeline alike; each has a
control showing the policy rejects the plain spelling. Helpers are self-contained
(tests/ is not a package — no cross-import); ``asyncio.run`` drives the coroutines.
"""
from __future__ import annotations

import asyncio
import copy

import pytest

pytest.importorskip("pyld")              # the RDF suites canonicalize with pyld

from openvc import VerificationPolicy, verify_credential, verify_credential_async  # noqa: E402
from openvc.did.base import (  # noqa: E402
    DidResolutionError,
    as_async_resolver,
    parse_did_document,
)
from openvc.errors import OpenvcError  # noqa: E402
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.openid4vp import verify_vp_token  # noqa: E402
from openvc.proof import data_integrity as di  # noqa: E402
from openvc.proof.contexts import bundled_contexts, document_loader  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import (  # noqa: E402
    CredentialExpired,
    CredentialNotYetValid,
    ProofError,
    ProofMalformed,
    SignatureInvalid,
)
from openvc.verify import StatusUnavailable, verify_many  # noqa: E402
from openvc.schema import SchemaUnavailable  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
CRED = "https://www.w3.org/2018/credentials#"
SEC = "https://w3id.org/security#"
XSD_DT = "http://www.w3.org/2001/XMLSchema#dateTime"
EXAMPLES_VOCAB = {"@vocab": "https://www.w3.org/ns/credentials/examples#"}

DID = "did:example:issuer"
VM = f"{DID}#k"
VC_ID = "urn:uuid:7d1e5c38-0000-4000-8000-000000000001"
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"

STATUS = {
    "id": "https://status.example/lists/1#5",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "5",
    "statusListCredential": "https://status.example/lists/1",
}
SCHEMA = {"id": "https://schema.example/degree.json", "type": "JsonSchema"}

_SUITES = {
    "eddsa-rdfc-2022": (DataIntegrityProofSuite, Ed25519SigningKey),
    "ecdsa-rdfc-2019": (EcdsaRdfcProofSuite, P256SigningKey),
}
SUITE_IDS = sorted(_SUITES)


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


def _vc(**extra):
    doc = {
        "@context": [V2],
        "id": VC_ID,
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
    }
    doc.update(extra)
    return doc


def _sign(suite_id, doc):
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(doc, signing_key=key, verification_method=VM)
    return secured, _registry(key.public_jwk())


def _outcomes(secured, registry, policy=None):
    """The (sync, async) outcome of verifying *secured*: the exception type raised, or
    ``None`` when it verified."""
    out = []
    try:
        verify_credential(copy.deepcopy(secured), resolver=registry, policy=policy)
        out.append(None)
    except OpenvcError as exc:
        out.append(type(exc))
    try:
        asyncio.run(verify_credential_async(
            copy.deepcopy(secured), resolver=as_async_resolver(registry), policy=policy))
        out.append(None)
    except OpenvcError as exc:
        out.append(type(exc))
    return out


def _rekey(doc, term, iri, *, typed=False):
    """Move the signed member *term* to the absolute-IRI key *iri* — same RDF statement,
    so the signature still holds — keeping a dateTime's datatype when *typed*."""
    out = copy.deepcopy(doc)
    value = out.pop(term)
    out[iri] = {"@value": value, "@type": XSD_DT} if typed else value
    return out


# --------------------------------------------------------------------------- #
# 1. A signed member re-keyed to its IRI no longer hides from the policy
# --------------------------------------------------------------------------- #

_REKEYS = [
    # (case, extra members to sign, mutation, policy, what the plain spelling raises)
    ("validUntil", {"validUntil": PAST},
     lambda d: _rekey(d, "validUntil", CRED + "validUntil", typed=True),
     None, CredentialExpired),
    ("validFrom", {"validFrom": FUTURE},
     lambda d: _rekey(d, "validFrom", CRED + "validFrom", typed=True),
     None, CredentialNotYetValid),
    ("credentialStatus", {"credentialStatus": STATUS},
     lambda d: _rekey(d, "credentialStatus", CRED + "credentialStatus"),
     None, StatusUnavailable),
    ("credentialSchema", {"credentialSchema": SCHEMA},
     lambda d: _rekey(d, "credentialSchema", CRED + "credentialSchema"),
     VerificationPolicy(require_schema=True), SchemaUnavailable),
]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("case, extra, mutate, policy, plain_error", _REKEYS,
                         ids=[r[0] for r in _REKEYS])
def test_rekeyed_member_is_rejected(suite_id, case, extra, mutate, policy, plain_error):
    secured, registry = _sign(suite_id, _vc(**extra))
    assert _outcomes(secured, registry, policy) == [plain_error, plain_error]   # control

    attacked = mutate({k: v for k, v in secured.items() if k != "proof"})
    attacked["proof"] = secured["proof"]
    assert _outcomes(attacked, registry, policy) == [ProofMalformed, ProofMalformed]


def _sign_eddsa_with(doc, **proof_fields):
    """An eddsa-rdfc-2022 proof carrying members add_proof does not emit (``expires``)."""
    key = Ed25519SigningKey.generate(kid=VM)
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
             "created": "2020-01-01T00:00:00Z", "verificationMethod": VM,
             "proofPurpose": "assertionMethod", **proof_fields}
    config = dict(proof, **{"@context": doc["@context"]})
    signature = key.sign(di._hash_data(doc, config, document_loader()))
    return dict(doc, proof=dict(proof, proofValue=encode_multibase(signature))), \
        _registry(key.public_jwk())


def test_rekeyed_proof_expires_is_rejected():
    secured, registry = _sign_eddsa_with(_vc(), expires=PAST)
    assert _outcomes(secured, registry) == [CredentialExpired, CredentialExpired]

    attacked = copy.deepcopy(secured)
    attacked["proof"] = _rekey(attacked["proof"], "expires", SEC + "expiration", typed=True)
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


# --------------------------------------------------------------------------- #
# 2. The @context: VC base first, then trusted URLs or @vocab-only objects
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_inline_alias_cannot_hide_a_member(suite_id):
    # `vu` is shorter than `validUntil`, so compaction itself would pick it: the
    # compacted-form check alone cannot see this one — the context rule does.
    secured, registry = _sign(suite_id, _vc(validUntil=PAST))
    attacked = copy.deepcopy(secured)
    attacked["@context"] = [V2, {"vu": {"@id": CRED + "validUntil", "@type": XSD_DT}}]
    attacked["vu"] = attacked.pop("validUntil")
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


def _context_without_credential_subject():
    """The bundled v2 context with ``credentialSubject`` nulled and re-aliased: the
    JSON ``credentialSubject`` is dropped from the dataset; ``cs`` carries the real one."""
    inline = copy.deepcopy(bundled_contexts()[V2]["@context"])
    scoped = inline["VerifiableCredential"]["@context"]
    scoped["cs"] = scoped["credentialSubject"]
    scoped["credentialSubject"] = None
    return inline


def _swap_subject(credential, impostor):
    out = copy.deepcopy(credential)
    out["@context"] = [_context_without_credential_subject()]
    out["cs"] = out.pop("credentialSubject")
    out["credentialSubject"] = {"id": impostor}
    return out


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_context_swap_cannot_spoof_the_subject(suite_id):
    secured, registry = _sign(suite_id, _vc())
    attacked = _swap_subject(secured, "did:example:mallory")
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


# "same": the dataset is unchanged, so only the context rule can refuse it;
# "other": the dataset changes or cannot be built — any typed ProofError, never a pass.
@pytest.mark.parametrize("context, kind", [
    ([EXAMPLES_VOCAB, V2], "same"),                                  # base not first
    ([V2, {"@vocab": "https://vocab.example/", "x": "https://vocab.example/y"}], "same"),
    ([V2, {"@vocab": None}], "other"),
    ([V2, 7], "other"),
    ([], "other"),
    ({"@vocab": "https://vocab.example/"}, "other"),
], ids=["base-not-first", "term-definition", "null-vocab", "number", "empty", "object"])
def test_context_shape_is_enforced(context, kind):
    secured, registry = _sign("eddsa-rdfc-2022", _vc(**{"@context": [V2, EXAMPLES_VOCAB]}))
    attacked = dict(secured, **{"@context": context})
    outcomes = _outcomes(attacked, registry)
    if kind == "same":
        assert outcomes == [ProofMalformed, ProofMalformed]
    else:
        assert all(o is not None and issubclass(o, ProofError) for o in outcomes), outcomes


# --------------------------------------------------------------------------- #
# 3. Spellings the signature cannot see
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_undefined_term_cannot_inject_an_unsigned_claim(suite_id):
    # v2 has no @vocab: an undefined term is dropped from the signed dataset, so before
    # this check any value placed under it verified.
    secured, registry = _sign(suite_id, _vc())
    attacked = copy.deepcopy(secured)
    attacked["credentialSubject"]["age_over_18"] = True
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]

    tampered = copy.deepcopy(secured)                  # control: a *defined* term is signed
    tampered["credentialSubject"]["name"] = "Mallory"
    assert _outcomes(tampered, registry) == [SignatureInvalid, SignatureInvalid]


@pytest.mark.parametrize("mutate, why", [
    (lambda d: dict(d, validUntil={"@value": d["validUntil"], "@type": XSD_DT}),
     "value object under the term"),
    (lambda d: {**{k: v for k, v in d.items() if k != "type"}, "@type": d["type"]},
     "@type keyword instead of the type alias"),
    (lambda d: dict(d, credentialSubject=dict(
        d["credentialSubject"], **{"@context": {"@vocab": "https://vocab.example/"}})),
     "nested @context"),
])
def test_non_compact_spelling_is_rejected(mutate, why):
    secured, registry = _sign("eddsa-rdfc-2022", _vc(validUntil=FUTURE))
    attacked = mutate({k: v for k, v in secured.items() if k != "proof"})
    attacked["proof"] = secured["proof"]
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed], why


# --------------------------------------------------------------------------- #
# 4. Statements moved out of the object the policy reads
# --------------------------------------------------------------------------- #

def _strip(doc, *members):
    return {k: v for k, v in doc.items() if k not in members}


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_included_redescription_cannot_hide_status_or_expiry(suite_id):
    secured, registry = _sign(suite_id, _vc(validUntil=PAST, credentialStatus=STATUS))
    attacked = _strip(secured, "validUntil", "credentialStatus")
    attacked["@included"] = [{"id": VC_ID, "type": ["VerifiableCredential"],
                              "validUntil": PAST, "credentialStatus": STATUS}]
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_nested_self_redescription_cannot_hide_expiry(suite_id):
    # The credential links to itself (a signed relatedResource self-reference); the
    # holder re-embeds the credential node there and moves validUntil into it.
    secured, registry = _sign(suite_id, _vc(validUntil=PAST, relatedResource=VC_ID))
    attacked = _strip(secured, "validUntil")
    attacked["relatedResource"] = {"id": VC_ID, "type": ["VerifiableCredential"],
                                   "validUntil": PAST}
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


def test_top_level_graph_is_rejected():
    secured, registry = _sign("eddsa-rdfc-2022", _vc(credentialStatus=STATUS))
    node = _strip(secured, "@context", "proof", "credentialStatus")
    node["credentialStatus"] = STATUS["id"]
    status_node = {k: v for k, v in STATUS.items()}
    attacked = {"@context": secured["@context"], "@graph": [node, status_node],
                "proof": secured["proof"]}
    for outcome in _outcomes(attacked, registry):
        assert outcome in (ProofMalformed, SignatureInvalid)


# --------------------------------------------------------------------------- #
# 5. What stays accepted: the canonical spellings JSON-LD treats as equal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("doc", [
    _vc(),
    _vc(**{"@context": V2}),                                       # a bare URL
    _vc(**{"@context": [V2, EXAMPLES_VOCAB]},                      # @vocab-only object
        credentialSubject={"id": "did:example:alice", "degree": "BSc"}),
    _vc(issuer={"id": DID}),                                       # node ref as object
    _vc(issuer={"id": DID, "name": "Example University"}),
    _vc(credentialSubject={"id": "did:example:alice"}),            # compacts to a string
    _vc(type="VerifiableCredential"),
    _vc(name={"@value": "Alumni", "@language": "en"}),             # canonical value object
    _vc(validUntil=FUTURE, credentialStatus=[STATUS]),
], ids=["v2-list", "v2-string", "vocab", "issuer-ref", "issuer-object", "subject-ref",
        "type-string", "language", "status-array"])
def test_canonical_spellings_still_verify(suite_id, doc):
    secured, registry = _sign(suite_id, doc)
    policy = VerificationPolicy(require_status=False)
    assert _outcomes(secured, registry, policy) == [None, None]


# --------------------------------------------------------------------------- #
# 6. Issuance refuses JSON its own signature would not cover
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("doc", [
    _vc(credentialSubject={"id": "did:example:alice", "score": 42}),     # undefined term
    _vc(**{"@context": [V2, {"score": "https://vocab.example/score"}]}),
    _vc(**{CRED + "validUntil": {"@value": FUTURE, "@type": XSD_DT}}),
    _vc(**{"@context": EXAMPLES_VOCAB}),                                 # not an array/URL
    _vc(**{"@context": [V2, EXAMPLES_VOCAB]},                            # not JSON
        credentialSubject={"id": "did:example:alice", "score": float("nan")}),
], ids=["undefined-term", "inline-term-definition", "iri-key", "context-object", "nan"])
def test_add_proof_refuses_non_canonical_documents(suite_id, doc):
    suite_cls, key_cls = _SUITES[suite_id]
    with pytest.raises(ProofMalformed):
        suite_cls().add_proof(doc, signing_key=key_cls.generate(kid=VM),
                              verification_method=VM)


def test_rejection_names_the_offending_member():
    doc = _vc(credentialSubject=[{"id": "did:example:alice", "name": "Alice"},
                                 {"id": "did:example:bob", "name": "Bob", "score": 42}])
    with pytest.raises(ProofMalformed, match="/credentialSubject/1/score"):
        DataIntegrityProofSuite().add_proof(
            doc, signing_key=Ed25519SigningKey.generate(kid=VM), verification_method=VM)


def test_add_base_proof_refuses_an_undefined_term():
    with pytest.raises(ProofMalformed):
        EcdsaSdProofSuite().add_base_proof(
            _vc(credentialSubject={"id": "did:example:alice", "score": 42}),
            signing_key=P256SigningKey.generate(kid=VM), verification_method=VM,
            mandatory_pointers=["/issuer"])


# --------------------------------------------------------------------------- #
# 7. ecdsa-sd-2023 derived credentials
# --------------------------------------------------------------------------- #

def test_ecdsa_sd_rekeyed_mandatory_validity_is_rejected():
    key = P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        _vc(validUntil=PAST), signing_key=key, verification_method=VM,
        mandatory_pointers=["/issuer", "/validFrom", "/validUntil"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    with pytest.raises(CredentialExpired):                                    # control
        suite.verify(derived, public_key_jwk=key.public_jwk())

    attacked = _rekey(_strip(derived, "proof"), "validUntil", CRED + "validUntil", typed=True)
    attacked["proof"] = derived["proof"]
    with pytest.raises(ProofMalformed):
        suite.verify(attacked, public_key_jwk=key.public_jwk())


# --------------------------------------------------------------------------- #
# 8. The ldp_vc presentation cascade and verify_many
# --------------------------------------------------------------------------- #

def _did_key(key, multicodec):
    mb = encode_multibase(multicodec + key.public_key_raw())
    return f"did:key:{mb}", f"did:key:{mb}#{mb}"


@pytest.mark.parametrize("attack", ["subject-swap", "expiry-rekey"])
def test_ldp_vp_holder_binding_cannot_be_spoofed(attack):
    ed = bytes([0xED, 0x01])
    issuer_key = Ed25519SigningKey.generate(kid="_")
    issuer_did, issuer_vm = _did_key(issuer_key, ed)
    issuer_key = Ed25519SigningKey(issuer_key._sk, kid=issuer_vm)
    mallory_key = Ed25519SigningKey.generate(kid="_")
    mallory_did, mallory_vm = _did_key(mallory_key, ed)
    mallory_key = Ed25519SigningKey(mallory_key._sk, kid=mallory_vm)

    if attack == "subject-swap":      # Alice's credential, presented as Mallory's
        vc = DataIntegrityProofSuite().add_proof(
            _vc(issuer=issuer_did), signing_key=issuer_key, verification_method=issuer_vm)
        vc = _swap_subject(vc, mallory_did)
    else:                             # Mallory's own credential, expired
        vc = DataIntegrityProofSuite().add_proof(
            _vc(issuer=issuer_did, validUntil=PAST,
                credentialSubject={"id": mallory_did}),
            signing_key=issuer_key, verification_method=issuer_vm)
        vc = dict(_rekey(_strip(vc, "proof"), "validUntil", CRED + "validUntil",
                         typed=True), proof=vc["proof"])

    vp = DataIntegrityProofSuite().add_proof(
        {"@context": [V2], "type": ["VerifiablePresentation"], "holder": mallory_did,
         "verifiableCredential": [vc]},
        signing_key=mallory_key, verification_method=mallory_vm,
        proof_purpose="authentication", challenge="n-1", domain="x509_san_dns:rp.example")
    with pytest.raises(ProofMalformed):
        verify_vp_token({"c1": [vp]}, dcql_query={"credentials": [
            {"id": "c1", "format": "ldp_vc"}]},
            nonce="n-1", client_id="x509_san_dns:rp.example")


def test_verify_many_reports_the_rejection_per_item():
    key = Ed25519SigningKey.generate(kid=VM)
    suite = DataIntegrityProofSuite()
    expired = suite.add_proof(_vc(validUntil=PAST), signing_key=key, verification_method=VM)
    attacked = dict(_rekey(_strip(expired, "proof"), "validUntil", CRED + "validUntil",
                           typed=True), proof=expired["proof"])
    fine = suite.add_proof(_vc(), signing_key=key, verification_method=VM)
    results = verify_many([attacked, fine], resolver=_registry(key.public_jwk()))
    assert isinstance(results[0].error, ProofMalformed)
    assert results[1].error is None                  # one hostile item never aborts the rest


# --------------------------------------------------------------------------- #
# 9. Forging the whole top level over a node the dataset drops (relative @id)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("placement", ["included", "nested"])
def test_forged_top_level_over_a_dropped_relative_id_is_rejected(suite_id, placement):
    # With {"@base": null} a relative top-level @id makes every top-level statement
    # vanish from the dataset; the issuer's node, restated elsewhere, keeps the quads
    # identical while the JSON top level says what the holder wants.
    secured, registry = _sign(suite_id, {k: v for k, v in _vc(validUntil=PAST).items()
                                         if k != "id"})
    original = _strip(secured, "@context", "proof")
    forged = {"@context": [V2, {"@base": None}], "id": "forged",
              "type": ["VerifiableCredential"], "issuer": DID,
              "credentialSubject": {"id": "did:example:mallory"},
              "proof": secured["proof"]}
    if placement == "included":
        forged["@included"] = [original]
    else:
        forged["relatedResource"] = original
    for outcome in _outcomes(forged, registry):
        assert outcome in (ProofMalformed, SignatureInvalid), outcome


@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("node_id", ["urn:forged x", "urn:forged\tx", "did:example:a\nb"])
def test_forged_top_level_over_an_id_the_dataset_drops_is_rejected(suite_id, node_id):
    # No inline context needed: RDF conversion drops every statement whose subject is
    # not a well-formed absolute IRI (pyld's own test: no whitespace), so the forged
    # top level vanishes and the restated original keeps the quads identical.
    secured, registry = _sign(suite_id, {k: v for k, v in _vc(validUntil=PAST).items()
                                         if k != "id"})
    forged = {"@context": [V2], "id": node_id, "type": ["VerifiableCredential"],
              "issuer": DID, "credentialSubject": {"id": "did:example:mallory"},
              "relatedResource": _strip(secured, "@context", "proof"),
              "proof": secured["proof"]}
    assert _outcomes(forged, registry) == [ProofMalformed, ProofMalformed]


# --------------------------------------------------------------------------- #
# 10. Spellings JSON-LD keeps in the JSON but not in the dataset
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("vocab", ["_:", "_:x/"])
def test_blank_node_vocab_cannot_inject_an_unsigned_claim(suite_id, vocab):
    # A blank-node @vocab turns every undefined term into a blank-node predicate, which
    # RDF conversion drops — yet compaction reproduces the term, so only the context and
    # safe-mode rules see it.
    secured, registry = _sign(suite_id, _vc())
    attacked = copy.deepcopy(secured)
    attacked["@context"] = [V2, {"@vocab": vocab}]
    attacked["credentialSubject"]["age_over_18"] = True
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("annotation", [{"@direction": "rtl"}, {"@index": "anything"}])
def test_unsigned_value_annotations_are_rejected(annotation):
    secured, registry = _sign("eddsa-rdfc-2022", _vc())
    attacked = copy.deepcopy(secured)
    attacked["credentialSubject"]["name"] = {"@value": "Alice", **annotation}
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("mutate", [
    lambda d: dict(d, type=d["type"] + ["Degree Credential"]),          # dropped type
    lambda d: dict(d, credentialSubject=dict(d["credentialSubject"],
                                             **{"_:note": "unsigned"})),  # blank property
], ids=["type-with-whitespace", "blank-node-property"])
def test_statements_the_dataset_drops_are_rejected(mutate):
    secured, registry = _sign("eddsa-rdfc-2022", _vc(**{"@context": [V2, EXAMPLES_VOCAB]}))
    attacked = mutate({k: v for k, v in secured.items() if k != "proof"})
    attacked["proof"] = secured["proof"]
    assert _outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]
