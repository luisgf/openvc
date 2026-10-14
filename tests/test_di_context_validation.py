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

Sections 11 to 20 pin the follow-ups that survived v1.30.2 (GHSA-h9rq-wxcw-4rjc): an
array nested in an array, which expansion flattens (``credentialStatus: [S1, [S2]]``
hid S2's revocation bit); a defined member spelled by its IRI because its value does
not fit the term (an issuer-signed untyped ``validUntil`` never expired); a status entry
moved under another property that names it — a nested node's ``credentialStatus``
included — leaving ``{"id": X}`` or an unrelated type behind; an injected context
aliasing a core IRI; the refusals the fail-closed superset implies; and a served context
dropped from the document's ``@context`` in favour of an inline ``@vocab``, which took
its IRIs out of a term index built from that ``@context``; and a VC 1.1 (or
StatusList2021) credential re-compacted onto the bundled VC 2.0 base alone, which spelled
``expirationDate`` / ``issuanceDate`` (or the status entry) by IRIs no served context
defines a term for; and a signed type re-spelled through an inline ``@vocab`` that ends
inside its IRI, which met an ``expected_types`` pin on a name the issuer never wrote.
Section 19 is the status move on ``ecdsa-sd-2023`` through two JSON nodes the signature
saw as one (a non-injective label map, a deskolemized ``urn:bnid:`` IRI); section 20 the
exact copy of a status entry that must still verify (an OB 3.0 endorsement).

Every attack here keeps the signature valid — that is the point — and must now fail with
a typed :class:`ProofMalformed` (``TypeMismatch`` for a section 18 pin no served context
names; ``ProofValueMalformed`` or ``SignatureInvalid`` for a section 19 merge the
signature itself now refuses) on the sync and the async pipeline alike; each has a
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
from openvc.proof.contexts import (  # noqa: E402
    DocumentLoaderError,
    bundled_contexts,
    document_loader,
)
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite, ProofValueMalformed  # noqa: E402
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


# --------------------------------------------------------------------------- #
# 11. An array nested in an array (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# JSON-LD expansion flattens an array nested directly in an array (outside @list), so
# `credentialStatus: [S1, [S2]]` signs exactly the dataset of `[S1, S2]` — a holder can
# re-wrap the issuer's genuine credential without re-signing — while the status checker
# reads only the top-level objects and never saw S2. `[[S]]` hid every entry.

STATUS_2 = {
    "id": "https://status.example/lists/2#7",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "7",
    "statusListCredential": "https://status.example/lists/2",
}

_NESTED_STATUS = {
    "[S1,[S2]]": lambda s1, s2: [s1, [s2]],
    "[[S1,S2]]": lambda s1, s2: [[s1, s2]],
    "[[S1],[S2]]": lambda s1, s2: [[s1], [s2]],
}


def _status_lists():
    """List 1 has no bit set; list 2 has STATUS_2's bit (7) set — STATUS_2 is revoked."""
    from openvc.status.bitstring import new_bitstring, set_status_bit
    from openvc.status.issue import build_status_list_credential

    clear, revoked = new_bitstring(131072), new_bitstring(131072)
    set_status_bit(revoked, int(STATUS_2["statusListIndex"]), 1)
    return {
        STATUS["statusListCredential"]: build_status_list_credential(
            id=STATUS["statusListCredential"], issuer=DID, bitstring=clear),
        STATUS_2["statusListCredential"]: build_status_list_credential(
            id=STATUS_2["statusListCredential"], issuer=DID, bitstring=revoked),
    }


def _status_outcomes(secured, registry, *, require_status=True, extra_contexts=None):
    """Like :func:`_outcomes`, with a status-list resolver on both pipelines."""
    lists = _status_lists()
    policy = VerificationPolicy(require_status=require_status)
    seen = []

    def resolve(url):
        seen.append(url)
        return lists[url]

    async def resolve_async(url):
        seen.append(url)
        return lists[url]

    out = []
    try:
        verify_credential(copy.deepcopy(secured), resolver=registry, policy=policy,
                          resolve_status_list=resolve, extra_contexts=extra_contexts)
        out.append(None)
    except OpenvcError as exc:
        out.append(type(exc))
    try:
        asyncio.run(verify_credential_async(
            copy.deepcopy(secured), resolver=as_async_resolver(registry), policy=policy,
            resolve_status_list=resolve_async, extra_contexts=extra_contexts))
        out.append(None)
    except OpenvcError as exc:
        out.append(type(exc))
    return out


def _with_status(secured, status):
    out = copy.deepcopy(secured)
    out["credentialStatus"] = status
    return out


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("shape", sorted(_NESTED_STATUS))
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_nested_status_array_cannot_hide_a_revoked_entry(suite_id, shape, require_status):
    from openvc.status import CredentialRevoked

    secured, registry = _sign(suite_id, _vc(credentialStatus=[STATUS, STATUS_2]))
    assert _status_outcomes(secured, registry, require_status=require_status) == [
        CredentialRevoked, CredentialRevoked]                                  # control

    attacked = _with_status(secured, _NESTED_STATUS[shape](STATUS, STATUS_2))
    assert _status_outcomes(attacked, registry, require_status=require_status) == [
        ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_wrapped_single_status_is_never_accepted_unchecked(suite_id, require_status):
    # [[S]] left no entry at all: StatusUnavailable by luck under require_status, and
    # silently unchecked without it — never a verdict on the shape itself.
    from openvc.status import CredentialRevoked

    secured, registry = _sign(suite_id, _vc(credentialStatus=STATUS_2))
    assert _status_outcomes(secured, registry, require_status=require_status) == [
        CredentialRevoked, CredentialRevoked]                                  # control

    attacked = _with_status(secured, [[STATUS_2]])
    assert _status_outcomes(attacked, registry, require_status=require_status) == [
        ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("shape", sorted(_NESTED_STATUS) + ["[[S]]"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_suite_verify_refuses_a_nested_status_array(suite_id, shape):
    suite_cls, _ = _SUITES[suite_id]
    if shape == "[[S]]":
        secured, registry = _sign(suite_id, _vc(credentialStatus=STATUS_2))
        nested = [[STATUS_2]]
    else:
        secured, registry = _sign(suite_id, _vc(credentialStatus=[STATUS, STATUS_2]))
        nested = _NESTED_STATUS[shape](STATUS, STATUS_2)
    suite_cls().verify(copy.deepcopy(secured), resolver=registry)              # control
    with pytest.raises(ProofMalformed, match="not in compacted form .*/credentialStatus"):
        suite_cls().verify(_with_status(secured, nested), resolver=registry)


def _ecdsa_sd_derived(doc, mandatory, *, key=None):
    key = key or P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(doc, signing_key=key, verification_method=VM,
                                mandatory_pointers=mandatory)
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    return derived, key


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("shape", sorted(_NESTED_STATUS) + ["[[S]]"])
def test_ecdsa_sd_nested_status_array_is_rejected(shape, require_status):
    from openvc.status import CredentialRevoked

    statuses = STATUS_2 if shape == "[[S]]" else [STATUS, STATUS_2]
    derived, key = _ecdsa_sd_derived(
        _vc(credentialStatus=statuses), ["/issuer", "/validFrom", "/credentialStatus"])
    registry = _registry(key.public_jwk())
    assert _status_outcomes(derived, registry, require_status=require_status) == [
        CredentialRevoked, CredentialRevoked]                                  # control

    if shape == "[[S]]":
        nested = [[derived["credentialStatus"]]]
    else:
        nested = _NESTED_STATUS[shape](*derived["credentialStatus"])
    attacked = _with_status(derived, nested)
    assert _status_outcomes(attacked, registry, require_status=require_status) == [
        ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="/credentialStatus"):
        EcdsaSdProofSuite().verify(attacked, public_key_jwk=key.public_jwk())


def test_json_signed_nested_status_is_not_skipped():
    # The JCS suites sign the JSON itself, so only an issuer can produce this shape —
    # but the status checker must still refuse it rather than skip what it cannot read.
    from openvc.proof.di_jcs import EddsaJcsProofSuite

    key = Ed25519SigningKey.generate(kid=VM)
    secured = EddsaJcsProofSuite().add_proof(
        _vc(credentialStatus=[STATUS, [STATUS_2]]), signing_key=key, verification_method=VM)
    from openvc.status import StatusListError
    assert _status_outcomes(secured, _registry(key.public_jwk())) == [
        StatusListError, StatusListError]


def _unsigned(doc):
    """(unsecured, proof_config) as the suites hand them to validate_document."""
    config = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
              "created": "2020-01-01T00:00:00Z", "verificationMethod": VM,
              "proofPurpose": "assertionMethod", "@context": doc["@context"]}
    return doc, config


def _validate(doc, *, config=None, extra_contexts=None):
    from openvc.proof._context_validation import validate_document

    unsecured, default_config = _unsigned(doc)
    validate_document(unsecured, config or default_config, document_loader(extra_contexts))


SUBJECT_B = {"id": "did:example:bob", "name": "Bob"}
SCHEMA_2 = {"id": "https://schema.example/other.json", "type": "JsonSchema"}


@pytest.mark.parametrize("doc, where", [
    (_vc(credentialSubject=[[{"id": "did:example:alice", "name": "Alice"}]]),
     "/credentialSubject"),
    (_vc(credentialSubject=[{"id": "did:example:alice", "name": "Alice"}, [SUBJECT_B]]),
     "/credentialSubject"),
    # pyld itself refuses an array inside a @type array (already typed, before this fix)
    (_vc(type=[["VerifiableCredential"]]), "cannot validate"),
    (_vc(**{"@context": [V2, EXAMPLES_VOCAB]},
         type=["VerifiableCredential", ["ExampleDegreeCredential"]]), "cannot validate"),
    (_vc(**{"@context": [V2, EXAMPLES_VOCAB]}, credentialSubject={
        "id": "did:example:alice",
        "degree": [[{"type": "BachelorDegree", "name": "BSc"}]]}),
     "/credentialSubject"),
    (_vc(**{"@context": [V2, EXAMPLES_VOCAB]}, credentialSubject={
        "id": "did:example:alice",
        "alumniOf": [{"name": "Uni A"}, [{"name": "Uni B"}]]}),
     "/credentialSubject"),
    (_vc(**{"@context": [V2, EXAMPLES_VOCAB]}, credentialSubject={
        "id": "did:example:alice",
        "degree": {"type": "BachelorDegree", "name": [["BSc"]]}}),
     "/credentialSubject"),
    (_vc(validUntil=[[FUTURE]]), "/validUntil"),
    (_vc(credentialSchema=[SCHEMA, [SCHEMA_2]]), "/credentialSchema"),
    (_vc(credentialStatus=[[STATUS]]), "/credentialStatus"),
    (_vc(issuer=[[DID]]), "/issuer"),
], ids=["subject-wrapped", "subject-second", "type-wrapped", "type-second",
        "nested-object-wrapped", "nested-object-second", "nested-literal",
        "validUntil", "schema", "status", "issuer"])
def test_validate_document_refuses_an_array_inside_an_array(doc, where):
    match = where if where == "cannot validate" else f"not in compacted form .*{where}"
    with pytest.raises(ProofMalformed, match=match):
        _validate(doc)


@pytest.mark.parametrize("member, value", [
    ("domain", [["rp.example"]]),
    ("challenge", ["n-1", ["n-2"]]),
])
def test_validate_document_refuses_an_array_inside_an_array_in_the_proof(member, value):
    doc, config = _unsigned(_vc())
    config[member] = value
    with pytest.raises(ProofMalformed, match=f"proof is not in compacted form .*/{member}"):
        _validate(doc, config=config)


@pytest.mark.parametrize("doc", [
    _vc(credentialSubject=[{"id": "did:example:alice", "name": "Alice"}]),
    _vc(credentialSubject=[{"id": "did:example:alice", "name": "Alice"}, SUBJECT_B]),
    _vc(type=["VerifiableCredential"]),
    _vc(validUntil=[FUTURE]),
    _vc(credentialStatus=[STATUS, STATUS_2]),
    _vc(issuer=[DID]),
], ids=["subject-one", "subject-two", "type-one", "validUntil-one", "status-two",
        "issuer-one"])
def test_validate_document_still_folds_a_one_element_property_array(doc):
    _validate(doc)


_LIST_CONTEXT_URL = "https://context.example/steps/v1"
_LIST_CONTEXT = {"@context": {
    "@protected": True,
    "steps": {"@id": "https://vocab.example/steps", "@container": "@list"},
}}


@pytest.mark.parametrize("steps", [
    [["a", "b"]], ["a", ["b", "c"]], [["a"], ["b"]], [[["a"]]], ["a"], ["a", "b"],
], ids=["list-of-one-list", "mixed", "two-lists", "deep", "one", "flat"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_list_of_lists_still_verifies(suite_id, steps):
    # A term with "@container": "@list" signs an array inside an array as a nested
    # list, and compaction emits it back nested: both sides carry it, so it is not the
    # flattened spelling the rule refuses.
    extra = {_LIST_CONTEXT_URL: _LIST_CONTEXT}
    doc = _vc(**{"@context": [V2, _LIST_CONTEXT_URL]},
              credentialSubject={"id": "did:example:alice", "steps": steps})
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(doc, signing_key=key, verification_method=VM,
                                    extra_contexts=extra)
    verify_credential(copy.deepcopy(secured), resolver=_registry(key.public_jwk()),
                      extra_contexts=extra)


# --------------------------------------------------------------------------- #
# 12. A defined IRI spelled other than by its term (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# A term that coerces a datatype (validFrom / validUntil: xsd:dateTime; the proof's
# `expires`) or takes a node (credentialStatus: @id) cannot carry a value that does not
# match. Compaction then keeps that statement under the predicate's absolute IRI, a
# compact IRI or an @vocab suffix — and that spelling IS the compacted form, so the
# round trip matches while the policy reads only the term. An issuer signing such a
# document (openvc's own signers ran the same check, so they emitted it) produced a
# credential that verified as never expiring / never revoked.

_PREFIX_CONTEXT_URL = "https://context.example/cred-prefix/v1"
_PREFIX_CONTEXT = {"@context": {"cred": CRED}}


def _sign_raw(suite_id, doc, *, extra_contexts=None, **proof_fields):
    """Sign *doc* the way any RDF-suite issuer does — the hash over the canonical
    dataset — without openvc's add_proof guard: another implementation, or openvc
    before this fix."""
    from openvc.proof import di_ecdsa_rdfc as rdfc

    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    proof = {"type": "DataIntegrityProof", "cryptosuite": suite_id,
             "created": "2020-01-01T00:00:00Z", "verificationMethod": VM,
             "proofPurpose": "assertionMethod", **proof_fields}
    config = dict(proof, **{"@context": doc["@context"]})
    loader = document_loader(extra_contexts)
    if suite_id == "eddsa-rdfc-2022":
        data = di._hash_data(doc, config, loader)
    else:
        data = rdfc._hash_data(doc, config, loader, "sha256")
    return (dict(doc, proof=dict(proof, proofValue=encode_multibase(key.sign(data)))),
            _registry(key.public_jwk()))


_MISSPELLED = [
    # (case, signed document, extra contexts, what the term spelling raises)
    ("validUntil-iri", _vc(**{CRED + "validUntil": PAST}), None, CredentialExpired),
    ("validFrom-iri", {**{k: v for k, v in _vc().items() if k != "validFrom"},
                       CRED + "validFrom": FUTURE}, None, CredentialNotYetValid),
    ("validUntil-iri-with-vocab", _vc(**{"@context": [V2, {"@vocab": CRED}],
                                         CRED + "validUntil": PAST}),
     None, CredentialExpired),
    ("validUntil-vocab-suffix", _vc(**{"@context": [V2, {"@vocab": CRED + "valid"}],
                                       "Until": PAST}), None, CredentialExpired),
    ("validFrom-vocab-suffix", {**{k: v for k, v in _vc().items() if k != "validFrom"},
                                "@context": [V2, {"@vocab": CRED + "valid"}],
                                "From": FUTURE}, None, CredentialNotYetValid),
    ("validUntil-compact-iri", _vc(**{"@context": [V2, _PREFIX_CONTEXT_URL],
                                      "cred:validUntil": PAST}),
     {_PREFIX_CONTEXT_URL: _PREFIX_CONTEXT}, CredentialExpired),
    ("validUntil-language-tagged", _vc(**{CRED + "validUntil": {
        "@value": PAST, "@language": "en"}}), None, CredentialExpired),
    ("credentialStatus-literal", _vc(**{CRED + "credentialStatus": STATUS_2["id"]}),
     None, None),
]


def _term_spelled(doc):
    """*doc* with the misspelled member written as its term — what the policy reads."""
    out = {k: v for k, v in doc.items()
           if k not in (CRED + "validUntil", CRED + "validFrom", CRED + "credentialStatus",
                        "Until", "From", "cred:validUntil")}
    out["@context"] = [V2]
    for key, term in ((CRED + "validUntil", "validUntil"), ("Until", "validUntil"),
                      ("cred:validUntil", "validUntil"), (CRED + "validFrom", "validFrom"),
                      ("From", "validFrom")):
        if key in doc:
            value = doc[key]
            out[term] = value["@value"] if isinstance(value, dict) else value
    if CRED + "credentialStatus" in doc:
        out["credentialStatus"] = STATUS_2
    return out


@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("case, doc, extra, plain_error", _MISSPELLED,
                         ids=[c[0] for c in _MISSPELLED])
def test_defined_member_spelled_by_its_iri_is_rejected(suite_id, case, doc, extra,
                                                       plain_error):
    from openvc.status import CredentialRevoked

    plain_error = plain_error or CredentialRevoked
    control, registry = _sign(suite_id, _term_spelled(doc))
    assert _status_outcomes(control, registry) == [plain_error, plain_error]   # control

    secured, registry = _sign_raw(suite_id, doc, extra_contexts=extra)
    assert _status_outcomes(secured, registry, extra_contexts=extra) == [
        ProofMalformed, ProofMalformed]
    suite_cls, _ = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match="spells a property"):
        suite_cls().verify(secured, resolver=registry, extra_contexts=extra)


@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("key, context", [
    (SEC + "expiration", [V2]),
    ("tion", [V2, {"@vocab": SEC + "expira"}]),
], ids=["iri", "vocab-suffix"])
def test_proof_expires_spelled_by_its_iri_is_rejected(suite_id, key, context):
    control, registry = _sign_raw(suite_id, _vc(), expires=PAST)
    assert _outcomes(control, registry) == [CredentialExpired, CredentialExpired]

    secured, registry = _sign_raw(suite_id, _vc(**{"@context": context}), **{key: PAST})
    assert _outcomes(secured, registry) == [ProofMalformed, ProofMalformed]
    suite_cls, _ = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match="the proof spells a property"):
        suite_cls().verify(secured, resolver=registry)


@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("case, doc, extra, plain_error", _MISSPELLED,
                         ids=[c[0] for c in _MISSPELLED])
def test_add_proof_refuses_a_defined_member_spelled_by_its_iri(suite_id, case, doc, extra,
                                                               plain_error):
    suite_cls, key_cls = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match="spells a property"):
        suite_cls().add_proof(doc, signing_key=key_cls.generate(kid=VM),
                              verification_method=VM, extra_contexts=extra)


@pytest.mark.parametrize("case, doc, extra, plain_error", _MISSPELLED,
                         ids=[c[0] for c in _MISSPELLED])
def test_add_base_proof_refuses_a_defined_member_spelled_by_its_iri(case, doc, extra,
                                                                    plain_error):
    with pytest.raises(ProofMalformed, match="spells a property"):
        EcdsaSdProofSuite().add_base_proof(
            doc, signing_key=P256SigningKey.generate(kid=VM), verification_method=VM,
            mandatory_pointers=["/issuer"], extra_contexts=extra)


def test_ecdsa_sd_defined_member_spelled_by_its_iri_is_rejected(monkeypatch):
    # Signed by an issuer whose signer does not run the check (simulated by disabling
    # it while signing only): the mandatory, untyped validUntil hides from the policy.
    from openvc.proof import ecdsa_sd

    doc = _vc(**{CRED + "validUntil": PAST})
    with monkeypatch.context() as patched:
        patched.setattr(ecdsa_sd, "validate_document", lambda *args, **kwargs: None)
        derived, key = _ecdsa_sd_derived(doc, ["/issuer", "/validFrom",
                                               "/" + CRED.replace("/", "~1") + "validUntil"])
    assert CRED + "validUntil" in derived
    registry = _registry(key.public_jwk())
    assert _outcomes(derived, registry) == [ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="spells a property"):
        EcdsaSdProofSuite().verify(derived, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("doc", [
    _vc(**{"https://example.org/ext#note": "x", "urn:example:tag": "y"}),   # no term
    _vc(**{"@context": [V2, EXAMPLES_VOCAB]},
        credentialSubject={"id": "did:example:alice", "degree": "BSc"}),
    _vc(_sd=[{CRED + "validUntil": PAST, "nested": [["data"]]}]),           # @json data
    _vc(cnf={"jwk": {"kty": "OKP", CRED + "validUntil": PAST}}),             # @json data
    _vc(validUntil=FUTURE, credentialStatus=STATUS),
], ids=["extension-iris", "vocab-term", "json-literal", "scoped-json-literal",
        "terms"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_terms_and_undefined_iris_still_verify(suite_id, doc):
    secured, registry = _sign(suite_id, doc)
    assert _outcomes(secured, registry, VerificationPolicy(require_status=False)) == [
        None, None]


def test_term_spellings_come_from_the_trusted_contexts():
    from openvc.proof import _context_validation as cv

    spellings = cv._term_index([V2], document_loader()).spellings
    assert spellings[CRED + "validUntil"] == {"validUntil"}       # VerifiableCredential scope
    assert spellings[CRED + "validFrom"] == {"validFrom"}
    assert spellings[CRED + "credentialStatus"] == {"credentialStatus"}
    assert spellings[SEC + "expiration"] == {"expires"}          # DataIntegrityProof scope
    assert CRED not in spellings
    # Every context the loader serves is indexed, whether or not the document lists it:
    # the document's @context is the holder's to edit (section 16).
    loader = document_loader({_PREFIX_CONTEXT_URL: _PREFIX_CONTEXT})
    for context in ([V2], [V2, _PREFIX_CONTEXT_URL]):
        index = cv._term_index(context, loader)
        assert index.spellings[CRED + "validUntil"] == {"validUntil"}
        assert "cred" in index.spellings[CRED]
        # the VC base context is also indexed alone: what an injected alias is checked
        # against
        assert index.base[CRED + "validUntil"] == {"validUntil"}
        assert CRED not in index.base


# --------------------------------------------------------------------------- #
# 13. A status entry moved out from under credentialStatus (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# RDF lets a node referenced from two properties be described under either. When the
# issuer's graph also names a status entry from another property, the holder can move
# the entry's description there, without re-signing, and leave `{"id": X}` (which
# JSON-LD signs exactly as the bare X) or only an unrelated type under
# credentialStatus: the status parser skipped it, and S2's revocation bit was never read.

_OTHER_STATUS_TYPE = "ExampleStatusType"        # an unrelated type, under EXAMPLES_VOCAB


def _relocated(secured, left_behind):
    """*secured* with STATUS_2 described under relatedResource and *left_behind* in its
    place under credentialStatus — the same signed dataset."""
    moved = copy.deepcopy(secured)
    entries = moved["credentialStatus"]
    full = next(e for e in entries if isinstance(e, dict) and e.get("id") == STATUS_2["id"])
    moved["relatedResource"] = full
    moved["credentialStatus"] = [left_behind if e is full else e for e in entries]
    return moved


@pytest.mark.parametrize("left_behind", [
    {"id": STATUS_2["id"]}, STATUS_2["id"]], ids=["id-only", "bare"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_status_entry_moved_to_another_property_is_rejected(suite_id, left_behind):
    from openvc.status import CredentialRevoked

    secured, registry = _sign(suite_id, _vc(credentialStatus=[STATUS, STATUS_2],
                                            relatedResource=STATUS_2["id"]))
    assert _status_outcomes(secured, registry) == [CredentialRevoked] * 2       # control

    moved = _relocated(secured, left_behind)
    for require_status in (True, False):
        assert _status_outcomes(moved, registry, require_status=require_status) == [
            ProofMalformed, ProofMalformed]
    suite_cls, _ = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match="described outside credentialStatus"):
        suite_cls().verify(moved, resolver=registry)


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_status_parser_still_refuses_the_moved_entry_without_the_structural_rule(
        suite_id, monkeypatch):
    # Belt and braces: with the structural rule switched off, the status parser alone
    # still fails closed on what the move leaves behind (a typeless object or a string).
    from openvc.proof import _context_validation as cv
    from openvc.status import StatusListError

    secured, registry = _sign(suite_id, _vc(credentialStatus=[STATUS, STATUS_2],
                                            relatedResource=STATUS_2["id"]))
    monkeypatch.setattr(cv, "_check_status_in_place", lambda *args, **kwargs: None)
    for left_behind in ({"id": STATUS_2["id"]}, STATUS_2["id"]):
        moved = _relocated(secured, left_behind)
        for require_status in (True, False):
            assert _status_outcomes(moved, registry, require_status=require_status) == [
                StatusListError, StatusListError]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_multi_typed_status_entry_cannot_leave_only_its_unrelated_type(suite_id):
    # The variant the status parser alone cannot see: S2 is also of an unrelated type,
    # which stays under credentialStatus while the rest moves — a typed entry it skips.
    from openvc.status import CredentialRevoked

    entry = dict(STATUS_2, type=["BitstringStatusListEntry", _OTHER_STATUS_TYPE])
    secured, registry = _sign(suite_id, _vc(**{"@context": [V2, EXAMPLES_VOCAB]},
                                            credentialStatus=[STATUS, entry],
                                            relatedResource=STATUS_2["id"]))
    assert _status_outcomes(secured, registry) == [CredentialRevoked] * 2       # control

    moved = _relocated(secured, {"id": STATUS_2["id"], "type": _OTHER_STATUS_TYPE})
    moved["relatedResource"]["type"] = "BitstringStatusListEntry"
    assert _status_outcomes(moved, registry) == [ProofMalformed, ProofMalformed]


def test_ecdsa_sd_status_entry_moved_to_another_property_is_rejected():
    from openvc.status import CredentialRevoked

    derived, key = _ecdsa_sd_derived(
        _vc(credentialStatus=[STATUS, STATUS_2], relatedResource=STATUS_2["id"]),
        ["/issuer", "/validFrom", "/credentialStatus", "/relatedResource"])
    registry = _registry(key.public_jwk())
    assert _status_outcomes(derived, registry) == [CredentialRevoked] * 2       # control

    moved = _relocated(derived, {"id": STATUS_2["id"]})
    assert _status_outcomes(moved, registry) == [ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="described outside credentialStatus"):
        EcdsaSdProofSuite().verify(moved, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("signed, respelled", [
    ([STATUS, STATUS_2["id"]], [STATUS, {"id": STATUS_2["id"]}]),
    (STATUS_2["id"], {"id": STATUS_2["id"]}),
    ([STATUS_2["id"]], [{"id": STATUS_2["id"]}]),
], ids=["in-array", "alone", "alone-in-array"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_id_only_status_reference_fails_closed_like_the_string(suite_id, signed, respelled):
    # An issuer-signed bare reference fails closed; the holder's {"id": X} spelling of
    # it (the same dataset) must too, under either require_status setting.
    from openvc.status import StatusListError

    secured, registry = _sign(suite_id, _vc(credentialStatus=signed))
    attacked = _with_status(secured, respelled)
    for require_status in (True, False):
        assert _status_outcomes(secured, registry, require_status=require_status) == [
            StatusListError, StatusListError]                                  # control
        assert _status_outcomes(attacked, registry, require_status=require_status) == [
            StatusListError, StatusListError]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_list_object_status_is_never_accepted_unchecked(suite_id):
    # Only an issuer can sign an RDF list here, but the parser cannot read one: it is a
    # typeless object to it, so it fails closed even under require_status=False.
    from openvc.status import StatusListError

    secured, registry = _sign(suite_id, _vc(credentialStatus={"@list": [STATUS_2]}))
    for require_status in (True, False):
        assert _status_outcomes(secured, registry, require_status=require_status) == [
            StatusListError, StatusListError]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_status_entry_also_referenced_elsewhere_still_verifies(suite_id):
    # Referencing the entry from another property is fine while it is described where
    # the status check reads it.
    secured, registry = _sign(suite_id, _vc(credentialStatus=STATUS,
                                            relatedResource=STATUS["id"]))
    assert _status_outcomes(secured, registry) == [None, None]


# Only the top-level credentialStatus is read by the status check, so a nested node's
# credentialStatus is "elsewhere" too. Three ways the issuer's graph can name S2 from one:
# the subject typed VerifiableCredential (the VC type-scoped term applies), a nested node
# typed so, and an injected context defining `credentialStatus` at the top level.
_NESTED_STATUS_CONTEXT_URL = "https://context.example/status-ref/v1"
_NESTED_STATUS_CONTEXT = {_NESTED_STATUS_CONTEXT_URL: {"@context": {
    "credentialStatus": {"@id": CRED + "credentialStatus", "@type": "@id"}}}}
_NESTED_STATUS_HOLDERS = {
    # case -> (extra contexts, credentialSubject naming S2, path to the naming node)
    "subject-typed-vc": (None, {"id": "did:example:alice", "name": "Alice",
                                "type": "VerifiableCredential",
                                "credentialStatus": STATUS_2["id"]}, ()),
    "nested-typed-vc": (None, {"id": "did:example:alice", "name": "Alice",
                               "achievement": {"id": "urn:uuid:inner",
                                               "type": "VerifiableCredential",
                                               "credentialStatus": STATUS_2["id"]}},
                        ("achievement",)),
    "injected-term": (_NESTED_STATUS_CONTEXT, {"id": "did:example:alice", "name": "Alice",
                                               "credentialStatus": STATUS_2["id"]}, ()),
}


def _moved_under_nested_status(secured, path):
    """*secured* with S2's description moved under the nested credentialStatus at
    *path* (from credentialSubject) and only its unrelated type left at the top — the
    same signed dataset."""
    moved = copy.deepcopy(secured)
    full = moved["credentialStatus"][1]
    moved["credentialStatus"][1] = {"id": full["id"], "type": _OTHER_STATUS_TYPE}
    holder = moved["credentialSubject"]
    for step in path:
        holder = holder[step]
    holder["credentialStatus"] = dict(full, type="BitstringStatusListEntry")
    return moved


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("case", sorted(_NESTED_STATUS_HOLDERS))
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_status_entry_moved_under_a_nested_credential_status_is_rejected(
        suite_id, case, require_status):
    # A credentialStatus at any depth used to count as "in place", so the move above was
    # never seen as "described elsewhere": the top-level entry kept only its unrelated
    # type, the status check skipped it, and S2's revocation bit was never read.
    from openvc.status import CredentialRevoked

    extra, subject, path = _NESTED_STATUS_HOLDERS[case]
    context = [V2, *([_NESTED_STATUS_CONTEXT_URL] if extra else []), EXAMPLES_VOCAB]
    entry = dict(STATUS_2, type=["BitstringStatusListEntry", _OTHER_STATUS_TYPE])
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(
        _vc(**{"@context": context}, credentialStatus=[STATUS, entry],
            credentialSubject=copy.deepcopy(subject)),
        signing_key=key, verification_method=VM, extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(secured, registry, require_status=require_status,
                            extra_contexts=extra) == [CredentialRevoked] * 2   # control

    moved = _moved_under_nested_status(secured, path)
    assert _status_outcomes(moved, registry, require_status=require_status,
                            extra_contexts=extra) == [ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="described outside credentialStatus"):
        suite_cls().verify(moved, resolver=registry, extra_contexts=extra)


def test_ecdsa_sd_status_entry_moved_under_a_nested_credential_status_is_rejected():
    from openvc.status import CredentialRevoked

    _, subject, path = _NESTED_STATUS_HOLDERS["subject-typed-vc"]
    entry = dict(STATUS_2, type=["BitstringStatusListEntry", _OTHER_STATUS_TYPE])
    derived, key = _ecdsa_sd_derived(
        _vc(**{"@context": [V2, EXAMPLES_VOCAB]}, credentialStatus=[STATUS, entry],
            credentialSubject=copy.deepcopy(subject)),
        ["/issuer", "/validFrom", "/credentialStatus", "/credentialSubject"])
    assert derived["credentialSubject"]["credentialStatus"] == STATUS_2["id"]
    registry = _registry(key.public_jwk())
    assert _status_outcomes(derived, registry) == [CredentialRevoked] * 2       # control

    moved = _moved_under_nested_status(derived, path)
    for require_status in (True, False):
        assert _status_outcomes(moved, registry, require_status=require_status) == [
            ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="described outside credentialStatus"):
        EcdsaSdProofSuite().verify(moved, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_nested_status_entry_of_its_own_still_verifies(suite_id):
    # A nested node's own, distinct status entry is no move: it is never read, and the
    # top-level one still is.
    own = dict(STATUS_2, id="https://status.example/lists/2#8", statusListIndex="8")
    secured, registry = _sign(suite_id, _vc(
        credentialStatus=STATUS,
        credentialSubject={"id": "did:example:alice", "name": "Alice",
                           "type": "VerifiableCredential", "credentialStatus": own}))
    assert _status_outcomes(secured, registry) == [None, None]


# --------------------------------------------------------------------------- #
# 14. An injected alias for a VC base context IRI (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# A caller-injected context (extra_contexts) that gives a core IRI another term — any
# length when it does not coerce like the core term, or a shorter one compaction then
# prefers — captures that member in compacted form while the policy reads only the core
# term. The rule: a key for an IRI the VC base context defines must be a base term.

_ALIAS_URL = "https://context.example/alias/v1"


def _alias(**terms):
    return {_ALIAS_URL: {"@context": terms}}


def _outcomes_with(secured, registry, extra):
    return _status_outcomes(secured, registry, extra_contexts=extra, require_status=False)


_ALIASES = [
    # (case, extra context, signed document, what the core spelling raises)
    ("until", _alias(until=CRED + "validUntil"),
     _vc(**{"@context": [V2, _ALIAS_URL]}, until=PAST), CredentialExpired),
    ("long-uncoerced", _alias(credentialValidUntilInstant=CRED + "validUntil"),
     _vc(**{"@context": [V2, _ALIAS_URL]}, credentialValidUntilInstant=PAST),
     CredentialExpired),
    ("from", _alias(**{"from": CRED + "validFrom"}),
     {**{k: v for k, v in _vc().items() if k != "validFrom"},
      "@context": [V2, _ALIAS_URL], "from": FUTURE}, CredentialNotYetValid),
    ("statusRef", _alias(statusRef={"@id": CRED + "credentialStatus", "@type": "@id"}),
     _vc(**{"@context": [V2, _ALIAS_URL]}, statusRef=[STATUS, STATUS_2]), None),
]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
@pytest.mark.parametrize("case, extra, doc, plain_error", _ALIASES,
                         ids=[c[0] for c in _ALIASES])
def test_injected_alias_for_a_core_iri_is_rejected(suite_id, case, extra, doc, plain_error):
    from openvc.status import CredentialRevoked

    plain_error = plain_error or CredentialRevoked
    alias = next(k for k in doc if k not in _vc() and k != "@context")
    control = {k: v for k, v in doc.items() if k != alias}
    control["@context"] = [V2]
    control[{"until": "validUntil", "long-uncoerced": "validUntil", "from": "validFrom",
             "statusRef": "credentialStatus"}[case]] = doc[alias]
    signed, registry = _sign(suite_id, control)
    assert _status_outcomes(signed, registry) == [plain_error, plain_error]     # control

    secured, registry = _sign_raw(suite_id, doc, extra_contexts=extra)
    assert _status_outcomes(secured, registry, extra_contexts=extra) == [
        ProofMalformed, ProofMalformed]
    assert _outcomes_with(secured, registry, extra) == [ProofMalformed, ProofMalformed]
    suite_cls, key_cls = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match=f"spells a property .*/{alias}"):
        suite_cls().verify(secured, resolver=registry, extra_contexts=extra)
    with pytest.raises(ProofMalformed, match="spells a property"):
        suite_cls().add_proof(doc, signing_key=key_cls.generate(kid=VM),
                              verification_method=VM, extra_contexts=extra)


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_injected_alias_for_the_proof_expiry_is_rejected(suite_id):
    extra = _alias(exp2=SEC + "expiration")
    secured, registry = _sign_raw(suite_id, _vc(**{"@context": [V2, _ALIAS_URL]}),
                                  extra_contexts=extra, exp2=PAST)
    assert _outcomes_with(secured, registry, extra) == [ProofMalformed, ProofMalformed]
    suite_cls, _ = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match="the proof spells a property .*/exp2"):
        suite_cls().verify(secured, resolver=registry, extra_contexts=extra)


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_injected_context_restating_a_core_term_still_verifies(suite_id):
    # A context that defines the core term itself for the core IRI is no alias.
    extra = _alias(validUntil={"@id": CRED + "validUntil", "@type": XSD_DT})
    doc = _vc(**{"@context": [V2, _ALIAS_URL]}, validUntil=FUTURE)
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(doc, signing_key=key, verification_method=VM,
                                    extra_contexts=extra)
    assert _outcomes_with(secured, _registry(key.public_jwk()), extra) == [None, None]


# --------------------------------------------------------------------------- #
# 15. Intended refusals of the fail-closed superset (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# The term rule does not track where a scoped term is in effect, and pyld compacts an
# @json array of arrays lossily, so a few documents no attack needs are refused too.
# Pinned so a change to either is a deliberate one.

_DC_URL = "https://context.example/dcterms/v1"
_DC = {_DC_URL: {"@context": {"dcterms": "http://purl.org/dc/terms/"}}}
_SUBJECT = {"id": "did:example:alice"}


@pytest.mark.parametrize("doc, extra", [
    # `created` is a base term only inside the DataIntegrityProof scope: at a subject no
    # term for it is active, and the compact IRI is what compaction emits — refused.
    (_vc(**{"@context": [V2, _DC_URL]}, credentialSubject=dict(
        _SUBJECT, **{"dcterms:created": {"@value": PAST, "type": XSD_DT}})), _DC),
    (_vc(credentialSubject=dict(_SUBJECT, **{SEC + "nonce": "abc"})), None),
    # an alias for it does not help: the IRI is the base context's
    (_vc(**{"@context": [V2, _ALIAS_URL]}, credentialSubject=dict(
        _SUBJECT, dateMade={"@value": PAST, "type": XSD_DT})),
     _alias(dateMade="http://purl.org/dc/terms/created")),
], ids=["subject-compact-iri", "subject-iri", "subject-alias"])
def test_base_iri_outside_its_terms_scope_is_refused(doc, extra):
    with pytest.raises(ProofMalformed, match="spells a property .*/credentialSubject/"):
        _validate(doc, extra_contexts=extra)


def test_iri_only_an_injected_context_defines_can_be_given_its_own_term():
    # The documented way out for an IRI the base context does not define: a term of
    # your own for it in extra_contexts.
    scoped = {"Note": {"@id": "https://vocab.example/Note",
                       "@context": {"pinned": "https://vocab.example/pinned"}}}
    doc = _vc(**{"@context": [V2, _ALIAS_URL]},
              credentialSubject=dict(_SUBJECT, **{"https://vocab.example/pinned": "x"}))
    with pytest.raises(ProofMalformed, match="spells a property"):
        _validate(doc, extra_contexts=_alias(**scoped))   # its term is out of scope here
    _validate(_vc(**{"@context": [V2, _ALIAS_URL]},
                  credentialSubject=dict(_SUBJECT, pinnedAt="x")),
              extra_contexts=_alias(pinnedAt="https://vocab.example/pinned", **scoped))


@pytest.mark.parametrize("sd", [[["x"]], [["a"], ["b"]], ["a", ["b"]]],
                         ids=["wrapped", "two-wrapped", "second-wrapped"])
def test_json_array_of_arrays_is_refused(sd):
    # pyld compacts an @json array holding arrays lossily ([["x"]] -> "x"), so it is not
    # the compacted form; an array nested deeper inside @json content is untouched.
    with pytest.raises(ProofMalformed, match="not in compacted form .*/_sd"):
        _validate(_vc(_sd=sd))
    _validate(_vc(_sd=[{"nested": sd}]))


# --------------------------------------------------------------------------- #
# 16. A trusted context swapped for an inline @vocab (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# The term index of section 12 was built from the document's OWN @context, which the
# holder edits freely as long as the dataset is unchanged. Dropping an injected context
# (or moving a v2 credential onto a VC 1.1 base the verifier also serves) and adding an
# inline @vocab that spells the same IRIs kept the signature and the compacted form, and
# took those IRIs out of the index: the status entry's type no longer read
# "StatusList2021Entry" / "BitstringStatusListEntry", so the status parser skipped it.
# The index now covers every context the verifier's loader serves, listed or not.

_SL = "https://w3id.org/vc/status-list#"
_SL_URL = "https://w3id.org/vc/status-list/2021/v1"
_SL_CONTEXT = {"@context": {
    "@protected": True,
    "StatusList2021Entry": {"@id": _SL + "StatusList2021Entry", "@context": {
        "@protected": True, "id": "@id", "type": "@type",
        "statusPurpose": _SL + "statusPurpose", "statusListIndex": _SL + "statusListIndex",
        "statusListCredential": {"@id": _SL + "statusListCredential", "@type": "@id"}}},
}}
_SL_STATUS_2 = {"id": STATUS_2["id"], "type": "StatusList2021Entry",
                "statusPurpose": "revocation", "statusListIndex": "7",
                "statusListCredential": STATUS_2["statusListCredential"]}   # bit 7 set


def _vocab_respelled(secured, context, vocab, prefix, entry_type):
    """*secured* with *context* in place of its @context plus an inline *vocab*, and the
    status entry of *entry_type* re-keyed to the vocab-relative spellings — the same
    signed dataset."""
    out = copy.deepcopy(secured)
    out["@context"] = [*context, {"@vocab": vocab}]
    entries = out["credentialStatus"]
    one = isinstance(entries, dict)
    respelled = []
    for entry in [entries] if one else entries:
        if entry.get("type") == entry_type:
            entry = {"id": entry["id"], "type": prefix + entry_type,
                     prefix + "statusPurpose": entry["statusPurpose"],
                     prefix + "statusListIndex": entry["statusListIndex"],
                     prefix + "statusListCredential": {"id": entry["statusListCredential"]}}
        respelled.append(entry)
    out["credentialStatus"] = respelled[0] if one else respelled
    return out


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("status", [[STATUS, _SL_STATUS_2], _SL_STATUS_2],
                         ids=["mixed", "single"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_injected_status_context_swapped_for_vocab_is_rejected(suite_id, status,
                                                               require_status):
    # Before the fix: mixed -> [None, None] under BOTH policies (S1 clear is checked, S2
    # skipped as an unrelated type); single -> [None, None] when optional and
    # StatusUnavailable only by the "no recognised entry" branch when required.
    from openvc.status import CredentialRevoked

    extra = {_SL_URL: _SL_CONTEXT}
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(
        _vc(**{"@context": [V2, _SL_URL]}, credentialStatus=copy.deepcopy(status)),
        signing_key=key, verification_method=VM, extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(secured, registry, require_status=require_status,
                            extra_contexts=extra) == [CredentialRevoked] * 2    # control

    attacked = _vocab_respelled(secured, [V2], "https://w3id.org/vc/", "status-list#",
                                "StatusList2021Entry")
    assert _status_outcomes(attacked, registry, require_status=require_status,
                            extra_contexts=extra) == [ProofMalformed, ProofMalformed]


_V1 = "https://www.w3.org/2018/credentials/v1"
_DI_V2 = "https://w3id.org/security/data-integrity/v2"
_DI_V2_DOC = {"@context": {
    "id": "@id", "type": "@type", "@protected": True,
    "proof": {"@id": SEC + "proof", "@type": "@id", "@container": "@graph"},
    "DataIntegrityProof": {"@id": SEC + "DataIntegrityProof", "@context": {
        "@protected": True, "id": "@id", "type": "@type",
        "challenge": SEC + "challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": XSD_DT},
        "domain": SEC + "domain",
        "expires": {"@id": SEC + "expiration", "@type": XSD_DT},
        "nonce": SEC + "nonce",
        "previousProof": {"@id": SEC + "previousProof", "@type": "@id"},
        "proofPurpose": {"@id": SEC + "proofPurpose", "@type": "@vocab", "@context": {
            "@protected": True, "id": "@id", "type": "@type",
            "assertionMethod": {"@id": SEC + "assertionMethod", "@type": "@id",
                                "@container": "@set"},
            "authentication": {"@id": SEC + "authenticationMethod",
                               "@type": "@id", "@container": "@set"}}},
        "cryptosuite": {"@id": SEC + "cryptosuite", "@type": SEC + "cryptosuiteString"},
        "proofValue": {"@id": SEC + "proofValue", "@type": SEC + "multibase"},
        "verificationMethod": {"@id": SEC + "verificationMethod", "@type": "@id"}}}}}


def _v1_extra():
    """What a verifier that also accepts VC 1.1 serves: the VC 1.1 base context and the
    Data Integrity v2 context (openvc bundles neither)."""
    import json
    from pathlib import Path

    import pyld

    bundled = Path(pyld.__file__).parent / "documentloader" / "frozen" / "bundled"
    if not (bundled / "credentials-v1.jsonld").exists():
        pytest.skip("this pyld does not bundle the VC 1.1 context")
    return {_V1: json.loads((bundled / "credentials-v1.jsonld").read_text()),
            _DI_V2: _DI_V2_DOC}


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_base_context_swapped_to_v1_cannot_hide_a_bitstring_entry(suite_id, require_status):
    # A verifier that also accepts VC 1.1 serves v1 + data-integrity/v2. A holder moves a
    # v2 credential onto v1 (same dataset), where BitstringStatusListEntry is no term.
    from openvc.status import CredentialRevoked

    extra = _v1_extra()
    doc = _vc(credentialStatus=STATUS_2)
    doc["credentialSubject"] = {"id": "did:example:alice"}      # v1 has no schema.org name
    secured, registry = _sign(suite_id, doc)
    assert _status_outcomes(secured, registry, require_status=require_status,
                            extra_contexts=extra) == [CredentialRevoked] * 2    # control

    attacked = _vocab_respelled(secured, [_V1, _DI_V2], "https://www.w3.org/ns/credentials/",
                                "status#", "BitstringStatusListEntry")
    # Before the fix: [None, None] when optional; StatusUnavailable when required, only by
    # the "declared but no recognised entry" branch — never a verdict on the shape
    assert _status_outcomes(attacked, registry, require_status=require_status,
                            extra_contexts=extra) == [ProofMalformed, ProofMalformed]


def test_ecdsa_sd_injected_status_context_swapped_for_vocab_is_rejected():
    from openvc.status import CredentialRevoked

    extra = {_SL_URL: _SL_CONTEXT}
    key = P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        _vc(**{"@context": [V2, _SL_URL]}, credentialStatus=[STATUS, _SL_STATUS_2]),
        signing_key=key, verification_method=VM,
        mandatory_pointers=["/issuer", "/validFrom", "/credentialStatus"],
        extra_contexts=extra)
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"],
                                 extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(derived, registry, extra_contexts=extra) == [
        CredentialRevoked] * 2                                                 # control
    attacked = _vocab_respelled(derived, [V2], "https://w3id.org/vc/", "status-list#",
                                "StatusList2021Entry")
    assert _status_outcomes(attacked, registry, extra_contexts=extra) == [
        ProofMalformed, ProofMalformed]


_ALUMNI_URL = "https://context.example/alumni/v1"
_ALUMNI = {_ALUMNI_URL: {"@context": {
    "AlumniCredential": "https://ex.example/vocab#AlumniCredential"}}}


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_type_spelled_other_than_by_its_term_is_rejected(suite_id):
    # The same swap on a type alone: every key stays a VC base term, so only the rule on
    # `type` values sees that "vocab#AlumniCredential" spells a term-defined IRI.
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(
        _vc(**{"@context": [V2, _ALUMNI_URL]}, type=["VerifiableCredential",
                                                     "AlumniCredential"]),
        signing_key=key, verification_method=VM, extra_contexts=_ALUMNI)
    registry = _registry(key.public_jwk())
    assert _outcomes_with(secured, registry, _ALUMNI) == [None, None]          # control

    attacked = copy.deepcopy(secured)
    attacked["@context"] = [V2, {"@vocab": "https://ex.example/"}]
    attacked["type"] = ["VerifiableCredential", "vocab#AlumniCredential"]
    assert _outcomes_with(attacked, registry, _ALUMNI) == [ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="spells a property .*/type/1"):
        suite_cls().verify(attacked, resolver=registry, extra_contexts=_ALUMNI)


def test_status_type_spelled_by_vocab_is_rejected_by_validate_document():
    doc = _vc(**{"@context": [V2, {"@vocab": "https://w3id.org/vc/"}]},
              credentialStatus={"id": STATUS_2["id"], "type": "status-list#StatusList2021Entry"})
    with pytest.raises(ProofMalformed, match="spells a property .*/credentialStatus/type"):
        _validate(doc, extra_contexts={_SL_URL: _SL_CONTEXT})
    # No served context defines that IRI, but the status check reads it as the type
    # StatusList2021Entry, so it is refused whatever the loader serves (section 17).
    with pytest.raises(ProofMalformed, match="spells a property .*/credentialStatus/type"):
        _validate(doc)


def test_validation_needs_a_loader_that_lists_what_it_serves():
    # A bare callable cannot say which contexts it serves, so the term index could only
    # come from the document's own @context — the hole above. Fail closed instead.
    from openvc.proof._context_validation import validate_document

    served = document_loader()
    doc, config = _unsigned(_vc())
    with pytest.raises(ProofMalformed, match="document_loader"):
        validate_document(doc, config, lambda url, options=None: served(url, options))


_VOCAB_TERMS_URL = "https://context.example/vocab-terms/v1"


_VOCAB_TERMS = {_VOCAB_TERMS_URL: {"@context": {
    "@vocab": "https://ext.example/#", "bar": {"@container": "@set"}}}}   # `bar`: no @id


def test_term_index_does_not_grow_with_inline_vocabs():
    # Only the inline @vocab in effect where a context URL is listed, and the last one,
    # can name an IRI; an attacker piling up inline @vocab objects grew the index (and
    # every key's lookups) with each of them.
    from openvc.proof import _context_validation as cv

    loader = document_loader(_VOCAB_TERMS)

    def index(count):
        vocabs = [{"@vocab": f"https://v{i}.example/#"} for i in range(count)]
        return cv._term_index([V2, _VOCAB_TERMS_URL, *vocabs], loader)

    small, large = index(2), index(300)
    assert large.vocabs == {"https://ext.example/#", "https://v299.example/#"}
    assert len(small.vocabs) == len(large.vocabs) == 2
    assert len(small.iris["bar"]) == len(large.iris["bar"]) == 2
    assert len(small.spellings) == len(large.spellings)


def test_term_without_id_is_indexed_under_the_vocab_it_was_defined_with():
    # A context with no @vocab of its own gives `bar` the inline @vocab in effect where
    # the document lists it (a.example), not only the last one (b.example).
    from openvc.proof import _context_validation as cv

    a, b = {"@vocab": "https://a.example/#"}, {"@vocab": "https://b.example/#"}
    extra = {_VOCAB_TERMS_URL: {"@context": {"bar": {"@type": "@id"}}}}
    index = cv._term_index([V2, a, _VOCAB_TERMS_URL, b], document_loader(extra))
    assert index.iris["bar"] == {"https://a.example/#bar", "https://b.example/#bar"}
    # a literal does not fit the @id-coerced term, so compaction keeps the full IRI
    with pytest.raises(ProofMalformed, match="spells a property .*/credentialSubject/"):
        _validate(_vc(**{"@context": [V2, a, _VOCAB_TERMS_URL]},
                      credentialSubject={"id": "did:example:alice",
                                         "https://a.example/#bar": "x"}),
                  extra_contexts=extra)


def test_many_inline_vocabs_still_validate():
    vocabs = [{"@vocab": f"https://v{i}.example/#"} for i in range(200)]
    doc = _vc(**{"@context": [V2, _VOCAB_TERMS_URL, *vocabs]},
              credentialSubject={"id": "did:example:alice", "bar": ["x"], "note": "y"})
    _validate(doc, extra_contexts=_VOCAB_TERMS)


# --------------------------------------------------------------------------- #
# 17. An IRI the policy reads, defined only by a context the verifier does not serve
#     (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# The term rule of sections 12 and 16 refused an IRI spelling only for an IRI some
# *served* context defines a term for. expirationDate / issuanceDate are VC 1.1 terms
# with no VC 2.0 term, and StatusList2021Entry and its members have a term only in the
# StatusList2021 context, so a default verifier serves none of them. A holder who
# re-compacts the issuer's genuine credential onto the bundled VC 2.0 base alone keeps
# the dataset and the signature, compaction spells those members by IRI, and the policy
# — which reads only the term — saw no expiry, no not-before and no status entry. The
# IRIs the policy reads are now refused under any spelling but the key it reads them
# under, whatever the loader serves, and an alias a served context gives one is refused
# too.


def _vc11(**members):
    doc = {"@context": [_V1, _DI_V2], "id": VC_ID, "type": ["VerifiableCredential"],
           "issuer": DID, "issuanceDate": "2020-01-01T00:00:00Z",
           "credentialSubject": {"id": "did:example:alice"}}
    doc.update(members)
    return doc


def _rebased_onto_v2(secured, *, prefixed):
    """*secured* (VC 1.1) re-compacted under [v2] (plus a `cred:` prefix context when
    *prefixed*) — the same signed dataset, the v1-only members spelled by (compact) IRI."""
    out = {k: v for k, v in secured.items()
           if k not in ("@context", "issuanceDate", "expirationDate")}
    out["@context"] = [V2, _PREFIX_CONTEXT_URL] if prefixed else [V2]
    for name in ("issuanceDate", "expirationDate"):
        if name in secured:
            spelled = ("cred:" if prefixed else CRED) + name
            out[spelled] = {"type": XSD_DT, "@value": secured[name]}
    return out


@pytest.mark.parametrize("prefixed", [False, True], ids=["iri", "compact-iri"])
@pytest.mark.parametrize("member, value, plain_error", [
    ("expirationDate", PAST, CredentialExpired),
    ("issuanceDate", FUTURE, CredentialNotYetValid),
], ids=["expirationDate", "issuanceDate"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_vc11_credential_rebased_onto_v2_cannot_hide_its_validity(
        suite_id, member, value, plain_error, prefixed):
    extra = _v1_extra()
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(_vc11(**{member: value}), signing_key=key,
                                    verification_method=VM, extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(secured, registry, extra_contexts=extra) == [
        plain_error, plain_error]                                              # control

    attacked = _rebased_onto_v2(secured, prefixed=prefixed)
    served = {_PREFIX_CONTEXT_URL: _PREFIX_CONTEXT} if prefixed else None
    # Before the fix: [None, None] — verified as never expiring / already valid
    assert _status_outcomes(attacked, registry, extra_contexts=served) == [
        ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="spells a property"):
        suite_cls().verify(attacked, resolver=registry, extra_contexts=served)


def test_ecdsa_sd_vc11_credential_rebased_onto_v2_cannot_hide_its_expiry():
    extra = _v1_extra()
    key = P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        _vc11(expirationDate=PAST, credentialSubject={
            "id": "did:example:alice", "https://vocab.example/#name": "Alice"}),
        signing_key=key, verification_method=VM, extra_contexts=extra,
        mandatory_pointers=["/issuer", "/issuanceDate", "/expirationDate"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/id"],
                                 extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(derived, registry, extra_contexts=extra) == [
        CredentialExpired, CredentialExpired]                                  # control
    attacked = _rebased_onto_v2(derived, prefixed=False)
    assert _status_outcomes(attacked, registry) == [ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="spells a property"):
        suite.verify(attacked, public_key_jwk=key.public_jwk())


def _sl2021_by_iri(secured):
    """*secured* with the StatusList2021 context dropped: the entry's type and members
    come out of compaction under [v2] by their full IRIs — the same signed dataset."""
    attacked = copy.deepcopy(secured)
    attacked["@context"] = [V2]
    entry = attacked["credentialStatus"]
    attacked["credentialStatus"] = {
        "id": entry["id"], "type": _SL + "StatusList2021Entry",
        _SL + "statusPurpose": entry["statusPurpose"],
        _SL + "statusListIndex": entry["statusListIndex"],
        _SL + "statusListCredential": {"id": entry["statusListCredential"]}}
    return attacked


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_status_entry_of_an_unserved_status_context_is_not_skipped(suite_id,
                                                                   require_status):
    # Same root cause on the status check: with the StatusList2021 context not served,
    # the entry's type and members come out by IRI, and with require_status=False the
    # "unrecognised type" branch skipped the revoked entry.
    from openvc.status import CredentialRevoked

    extra = {_SL_URL: _SL_CONTEXT}
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(
        _vc(**{"@context": [V2, _SL_URL]}, credentialStatus=dict(_SL_STATUS_2)),
        signing_key=key, verification_method=VM, extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(secured, registry, require_status=require_status,
                            extra_contexts=extra) == [CredentialRevoked] * 2   # control

    # Before the fix: [None, None] when optional; StatusUnavailable when required, only
    # by the "declared but no recognised entry" branch
    assert _status_outcomes(_sl2021_by_iri(secured), registry,
                            require_status=require_status) == [ProofMalformed] * 2


def test_ecdsa_sd_status_entry_of_an_unserved_status_context_is_not_skipped():
    from openvc.status import CredentialRevoked

    extra = {_SL_URL: _SL_CONTEXT}
    key = P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        _vc(**{"@context": [V2, _SL_URL]}, credentialStatus=dict(_SL_STATUS_2)),
        signing_key=key, verification_method=VM, extra_contexts=extra,
        mandatory_pointers=["/issuer", "/validFrom", "/credentialStatus"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"],
                                 extra_contexts=extra)
    registry = _registry(key.public_jwk())
    assert _status_outcomes(derived, registry, require_status=False,
                            extra_contexts=extra) == [CredentialRevoked] * 2   # control
    assert _status_outcomes(_sl2021_by_iri(derived), registry, require_status=False) == [
        ProofMalformed, ProofMalformed]


_VALIDITY_ALIAS_URL = "https://context.example/validity-alias/v1"
_VALIDITY_ALIAS = {"@context": {
    "since": {"@id": CRED + "issuanceDate", "@type": XSD_DT},
    "expiry": {"@id": CRED + "expirationDate", "@type": XSD_DT}}}


@pytest.mark.parametrize("serves_v1", [False, True], ids=["v2-only", "v1-too"])
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_vc11_credential_rebased_onto_an_injected_alias_cannot_hide_its_expiry(
        suite_id, serves_v1):
    # Indexing the VC 1.1 terms like those of any served context is not enough: a served
    # context that gives cred:expirationDate a term of its own makes that term an
    # accepted spelling, compaction chooses it, and the policy reads only
    # `expirationDate`. The VC 2.0 base context has no term for these IRIs, so the
    # base-context rule of section 14 never applied to them.
    extra = _v1_extra()
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    secured = suite_cls().add_proof(_vc11(expirationDate=PAST), signing_key=key,
                                    verification_method=VM, extra_contexts=extra)
    registry = _registry(key.public_jwk())

    attacked = {k: v for k, v in secured.items()
                if k not in ("@context", "issuanceDate", "expirationDate")}
    attacked["@context"] = [V2, _VALIDITY_ALIAS_URL]
    attacked["since"] = secured["issuanceDate"]
    attacked["expiry"] = secured["expirationDate"]
    served = {**(extra if serves_v1 else {}), _VALIDITY_ALIAS_URL: _VALIDITY_ALIAS}
    assert _status_outcomes(attacked, registry, extra_contexts=served) == [
        ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_vc11_and_status_list_2021_credentials_still_verify(suite_id):
    # What a verifier that serves those contexts accepts is unchanged: the terms
    # themselves, an unexpired VC 1.1 credential and a clear StatusList2021Entry.
    from openvc.status import CredentialRevoked

    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    registry = _registry(key.public_jwk())
    extra = _v1_extra()
    secured = suite_cls().add_proof(_vc11(expirationDate=FUTURE), signing_key=key,
                                    verification_method=VM, extra_contexts=extra)
    assert _status_outcomes(secured, registry, extra_contexts=extra) == [None, None]

    extra = {_SL_URL: _SL_CONTEXT}
    for index, expected in (("3", None), ("7", CredentialRevoked)):   # bit 7 is set
        secured = suite_cls().add_proof(
            _vc(**{"@context": [V2, _SL_URL]},
                credentialStatus=dict(_SL_STATUS_2, statusListIndex=index)),
            signing_key=key, verification_method=VM, extra_contexts=extra)
        assert _status_outcomes(secured, registry, extra_contexts=extra) == [expected] * 2


def test_vc11_context_is_still_not_served_by_default():
    # The fix indexes the IRIs the policy reads; it does not start serving VC 1.1.
    with pytest.raises(DocumentLoaderError):
        document_loader()("https://www.w3.org/2018/credentials/v1")


_POLICY_IRIS = [
    (CRED + "issuanceDate", "issuanceDate"),
    (CRED + "expirationDate", "expirationDate"),
    (CRED + "validFrom", "validFrom"),
    (CRED + "validUntil", "validUntil"),
    (CRED + "credentialStatus", "credentialStatus"),
    (CRED + "credentialSchema", "credentialSchema"),
    (SEC + "expiration", "expires"),
    ("https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
     "BitstringStatusListEntry"),
    ("https://www.w3.org/ns/credentials/status#statusPurpose", "statusPurpose"),
    (_SL + "StatusList2021Entry", "StatusList2021Entry"),
    (_SL + "statusPurpose", "statusPurpose"),
    (_SL + "statusListIndex", "statusListIndex"),
    (_SL + "statusListCredential", "statusListCredential"),
]


@pytest.mark.parametrize("iri, term", _POLICY_IRIS, ids=[t[0] for t in _POLICY_IRIS])
def test_policy_iris_are_refused_under_any_other_spelling(iri, term):
    from openvc.proof import _context_validation as cv

    # whatever the loader serves: the default, and one that aliases the IRI
    alias = {"https://context.example/policy-alias/v1": {"@context": {"alias": iri}}}
    for loader in (document_loader(), document_loader(alias)):
        index = cv._term_index([V2], loader)
        assert cv._is_misspelled(iri, index)                         # its full IRI
        assert not cv._is_misspelled(term, index)                    # the key read
        assert term in index.spellings[iri]       # what an @vocab suffix is looked up in
    assert cv._is_misspelled("alias", index)
    namespace, _, local = iri.rpartition("#")
    vocab = cv._term_index([V2, {"@vocab": namespace + "#" + local[:2]}], document_loader())
    assert cv._is_misspelled(local[2:], vocab)                       # an @vocab suffix


def test_policy_iris_index_no_other_vc11_term():
    # Not the VC 1.1 context: its `cred` / `sec` prefixes and other terms stay out.
    from openvc.proof import _context_validation as cv

    index = cv._term_index([V2], document_loader())
    assert CRED not in index.spellings
    assert "issuanceDate" not in index.iris and "cred" not in index.iris


# --------------------------------------------------------------------------- #
# 18. A signed type re-spelled through an inline @vocab boundary (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# The issuer types its credential through its published context, which the verifier
# does not serve: "AlumniDegreeCredential" -> vendor#AlumniDegreeCredential. The holder
# swaps that context for {"@vocab": ".../vocab#Alumni"} and writes the type as
# "DegreeCredential": the same dataset, the same signature, the same compacted round
# trip. The term rule only asks which DEFINED IRIs a spelling may stand for, and
# expected_types compared JSON strings, so a pin on "DegreeCredential" passed (a) on a
# default verifier, which cannot even load the original, and (b) on one serving a
# context that defines "DegreeCredential" as another IRI. Now a served type term must
# stand for one of its own IRIs (b), and expected_types is matched by IRI, resolved
# through the served contexts only (a).

_VENDOR_URL = "https://vendor.example/ctx/v1"
_VENDOR_VOCAB = "https://vendor.example/vocab#"
_VENDOR = {_VENDOR_URL: {"@context": {
    "@protected": True,
    "AlumniDegreeCredential": _VENDOR_VOCAB + "AlumniDegreeCredential"}}}
_SERVED_URL = "https://served.example/ctx/v1"
_SERVED_TYPE = "https://served.example/vocab#DegreeCredential"
_SERVED = {_SERVED_URL: {"@context": {"@protected": True, "DegreeCredential": _SERVED_TYPE}}}
_EXAMPLES_URL = "https://www.w3.org/ns/credentials/examples/v2"
_EXAMPLES = {_EXAMPLES_URL: {"@context": EXAMPLES_VOCAB}}
_EXAMPLE_TYPE = EXAMPLES_VOCAB["@vocab"] + "ExampleDegreeCredential"
RDF_SUITE_IDS = [*SUITE_IDS, "ecdsa-sd-2023"]


def _issued(suite_id, doc, extra):
    """*doc* secured by *suite_id* with *extra* served to the issuer — derived, for
    ecdsa-sd-2023 — and a registry resolving its key."""
    if suite_id == "ecdsa-sd-2023":
        key = P256SigningKey.generate(kid=VM)
        suite = EcdsaSdProofSuite()
        base = suite.add_base_proof(doc, signing_key=key, verification_method=VM,
                                    mandatory_pointers=["/issuer", "/validFrom"],
                                    extra_contexts=extra)
        secured = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"],
                                     extra_contexts=extra)
    else:
        suite_cls, key_cls = _SUITES[suite_id]
        key = key_cls.generate(kid=VM)
        secured = suite_cls().add_proof(doc, signing_key=key, verification_method=VM,
                                        extra_contexts=extra)
    return secured, _registry(key.public_jwk())


def _typed_outcomes(secured, registry, expected=None, extra=None):
    """The (sync, async) outcome of verifying *secured* under ``expected_types`` =
    *expected* with *extra* served: the exception type raised, or None."""
    policy = VerificationPolicy(expected_types=expected)
    out = []
    try:
        verify_credential(copy.deepcopy(secured), resolver=registry, policy=policy,
                          extra_contexts=extra)
        out.append(None)
    except OpenvcError as exc:
        out.append(type(exc))
    try:
        asyncio.run(verify_credential_async(
            copy.deepcopy(secured), resolver=as_async_resolver(registry), policy=policy,
            extra_contexts=extra))
        out.append(None)
    except OpenvcError as exc:
        out.append(type(exc))
    return out


def _alumni(suite_id):
    return _issued(suite_id, _vc(**{"@context": [V2, _VENDOR_URL]},
                                 type=["VerifiableCredential", "AlumniDegreeCredential"]),
                   _VENDOR)


def _unloadable(suite_id):
    # an unserved context: the RDFC suites surface the loader's refusal, ecdsa-sd-2023
    # wraps it while canonicalizing the derived credential
    return ProofMalformed if suite_id == "ecdsa-sd-2023" else DocumentLoaderError


def _suffix_respelled(secured):
    """*secured* with its vendor type spelled as a suffix through an inline @vocab that
    ends inside the signed IRI — the same signed dataset."""
    out = copy.deepcopy(secured)
    out["@context"] = [V2, {"@vocab": _VENDOR_VOCAB + "Alumni"}]
    out["type"] = ["VerifiableCredential", "DegreeCredential"]
    return out


@pytest.mark.parametrize("suite_id", RDF_SUITE_IDS)
def test_signed_type_respelled_as_a_served_term_is_rejected(suite_id):
    from openvc.verify import TypeMismatch

    secured, registry = _alumni(suite_id)
    both = {**_VENDOR, **_SERVED}
    # controls: the issuer's own spelling is an AlumniDegreeCredential, not a
    # DegreeCredential, and a verifier serving only the served context cannot load it
    assert _typed_outcomes(secured, registry, ["AlumniDegreeCredential"], both) == [
        None, None]
    assert _typed_outcomes(secured, registry, ["DegreeCredential"], both) == [
        TypeMismatch, TypeMismatch]
    assert _typed_outcomes(secured, registry, ["DegreeCredential"], _SERVED) == [
        _unloadable(suite_id)] * 2

    attacked = _suffix_respelled(secured)
    # Before the fix: [None, None] under the pin, though "DegreeCredential" stood for
    # vendor#AlumniDegreeCredential here and for served#DegreeCredential to the verifier.
    for expected in (["DegreeCredential"], None):
        assert _typed_outcomes(attacked, registry, expected, _SERVED) == [
            ProofMalformed, ProofMalformed]
    suite = EcdsaSdProofSuite() if suite_id == "ecdsa-sd-2023" else _SUITES[suite_id][0]()
    with pytest.raises(ProofMalformed, match="type 'DegreeCredential' is a term"):
        suite.verify(copy.deepcopy(attacked), resolver=registry, extra_contexts=_SERVED)


@pytest.mark.parametrize("suite_id", RDF_SUITE_IDS)
def test_signed_type_respelled_as_a_suffix_does_not_meet_expected_types(suite_id):
    from openvc.verify import TypeMismatch

    secured, registry = _alumni(suite_id)
    assert _typed_outcomes(secured, registry, ["DegreeCredential"]) == [
        _unloadable(suite_id)] * 2                                         # control
    attacked = _suffix_respelled(secured)
    # Before the fix: [None, None] — a default verifier accepted the re-spelled credential
    # under a pin it never met. It is still the issuer's dataset, so it verifies without
    # the pin; only reading its JSON `type` for a name no served context defines would be
    # fooled, which is what expected_types no longer does.
    assert _typed_outcomes(attacked, registry, ["DegreeCredential"]) == [
        TypeMismatch, TypeMismatch]
    assert _typed_outcomes(attacked, registry, None) == [None, None]
    assert _typed_outcomes(attacked, registry,
                           [_VENDOR_VOCAB + "AlumniDegreeCredential"]) == [None, None]
    # Serving the vendor context makes the suffix a misspelling of its term (section 16)
    assert _typed_outcomes(attacked, registry, ["DegreeCredential"], _VENDOR) == [
        ProofMalformed, ProofMalformed]


@pytest.mark.parametrize("suite_id", RDF_SUITE_IDS)
def test_expected_types_match_by_iri_through_served_contexts(suite_id):
    # Behaviour change: a type an inline @vocab spells matches a bare name only when the
    # verifier serves a context giving it that name (here the one-line examples context,
    # which the credential does not even list), or by its full IRI.
    from openvc.verify import TypeMismatch

    secured, registry = _issued(
        suite_id, _vc(**{"@context": [V2, EXAMPLES_VOCAB]},
                      type=["VerifiableCredential", "ExampleDegreeCredential"]), None)
    assert _typed_outcomes(secured, registry, ["ExampleDegreeCredential"]) == [
        TypeMismatch, TypeMismatch]
    assert _typed_outcomes(secured, registry, ["ExampleDegreeCredential"], _EXAMPLES) == [
        None, None]
    assert _typed_outcomes(secured, registry, "ExampleDegreeCredential", _EXAMPLES) == [
        None, None]                                     # a bare string is one type
    assert _typed_outcomes(secured, registry, [_EXAMPLE_TYPE]) == [None, None]
    assert _typed_outcomes(secured, registry, ["VerifiableCredential"]) == [None, None]
    assert _typed_outcomes(secured, registry, ["VerifiableCredential", "Other"],
                           _EXAMPLES) == [TypeMismatch, TypeMismatch]


def test_typed_mismatch_names_the_remedy():
    from openvc.verify import TypeMismatch

    secured, registry = _issued(
        "eddsa-rdfc-2022", _vc(**{"@context": [V2, EXAMPLES_VOCAB]},
                               type=["VerifiableCredential", "ExampleDegreeCredential"]),
        None)
    with pytest.raises(TypeMismatch, match="pin the full type IRI"):
        verify_credential(secured, resolver=registry,
                          policy=VerificationPolicy(expected_types=["ExampleDegreeCredential"]))


def test_jcs_lane_still_compares_type_strings():
    # A JCS proof signs the JSON itself, so its `type` strings are what the issuer
    # wrote and stay compared as strings (unchanged).
    from openvc.proof.di_jcs import EddsaJcsProofSuite

    key = Ed25519SigningKey.generate(kid=VM)
    secured = EddsaJcsProofSuite().add_proof(
        _vc(**{"@context": [V2, EXAMPLES_VOCAB]},
            type=["VerifiableCredential", "ExampleDegreeCredential"]),
        signing_key=key, verification_method=VM)
    assert _typed_outcomes(secured, _registry(key.public_jwk()),
                           ["ExampleDegreeCredential"]) == [None, None]


def test_missing_types_resolves_names_through_the_served_contexts_only():
    from openvc.proof._context_validation import missing_types

    prefix = {"https://served.example/prefix/v1": {"@context": {
        "sv": "https://served.example/vocab#"}}}
    doc = _vc(**{"@context": [V2, _SERVED_URL]},
              type=["VerifiableCredential", "DegreeCredential"])
    loader = document_loader({**_SERVED, **prefix})
    names = ["DegreeCredential", _SERVED_TYPE, "sv:DegreeCredential",
             "VerifiableCredential", CRED + "VerifiableCredential", "@type", "", 5, "Other",
             "https://served.example/vocab#Other"]
    assert missing_types(doc, names, loader) == [
        "@type", "", 5, "Other", "https://served.example/vocab#Other"]

    # the document's own inline @vocab never resolves a name; a served one does
    own = _vc(**{"@context": [V2, {"@vocab": "https://own.example/#"}]},
              type=["VerifiableCredential", "Own"])
    assert missing_types(own, ["Own"], document_loader()) == ["Own"]
    served_vocab = {"https://own.example/ctx": {"@context": {"@vocab": "https://own.example/#"}}}
    assert missing_types(own, ["Own"], document_loader(served_vocab)) == []

    # a presentation is typed by its own node; its embedded credentials are not read
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],
          "verifiableCredential": [{"@context": [V2, "https://unserved.example/v1"]}]}
    assert missing_types(vp, ["VerifiablePresentation"], document_loader()) == []


def test_served_type_term_must_stand_for_its_own_iri():
    hijack = _vc(**{"@context": [V2, {"@vocab": _VENDOR_VOCAB + "Alumni"}]},
                 type=["VerifiableCredential", "DegreeCredential"])
    with pytest.raises(ProofMalformed, match="type 'DegreeCredential' is a term"):
        _validate(hijack, extra_contexts=_SERVED)
    _validate(hijack)                     # no served context names it: the policy's job
    # the term spelling its own IRI, under either of two served definitions, still passes
    other = {"https://other.example/ctx/v1": {"@context": {
        "DegreeCredential": "https://other.example/vocab#DegreeCredential"}}}
    for url in (_SERVED_URL, "https://other.example/ctx/v1"):
        _validate(_vc(**{"@context": [V2, url]},
                      type=["VerifiableCredential", "DegreeCredential"]),
                  extra_contexts={**_SERVED, **other})
    # an inline @vocab that lands on the served IRI itself is the term's own meaning
    _validate(_vc(**{"@context": [V2, {"@vocab": "https://served.example/vocab#"}]},
                  type=["VerifiableCredential", "DegreeCredential"]),
              extra_contexts=_SERVED)


def test_add_proof_refuses_a_served_type_term_standing_for_another_iri():
    suite_cls, key_cls = _SUITES["eddsa-rdfc-2022"]
    with pytest.raises(ProofMalformed, match="type 'DegreeCredential' is a term"):
        suite_cls().add_proof(
            _vc(**{"@context": [V2, {"@vocab": _VENDOR_VOCAB + "Alumni"}]},
                type=["VerifiableCredential", "DegreeCredential"]),
            signing_key=key_cls.generate(kid=VM), verification_method=VM,
            extra_contexts=_SERVED)


# --------------------------------------------------------------------------- #
# 19. ecdsa-sd-2023: a derived proof cannot merge blank nodes the JSON keeps apart
#     (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# The section-13 move on a derived ecdsa-sd-2023 credential whose status entry is a
# blank node (VCDM 2.0 makes an entry's `id` optional, so an issuer that names it from a
# second property labels it `_:s`). The verifier took blank-node identity for the
# signature from the holder's label map, which it never required to be injective, and
# from `urn:bnid:` IRIs it deskolemized into blank nodes; context validation takes it
# from the JSON. Two JSON blank nodes mapped to the issuer's one label, or
# `urn:bnid:bN` (an IRI to JSON-LD) turned into pyld's own `_:bN`, were one node to the
# signature and two to _check_status_in_place: the holder described the entry under
# relatedResource and left only its unrelated type under credentialStatus, and with
# require_status=False the revoked bit was never read.

def _sd_full_reveal(base, reveal, label_for):
    """*reveal* (the holder's JSON) with a holder-crafted derived proof disclosing every
    statement of *base*. *label_for(c14n_label, hmac_labels)* gives the issuer HMAC label
    (no ``_:``) for each canonical blank-node label of *reveal*, given the issuer's HMAC
    labels. The canonical labels are computed as the verifier did before this fix
    (deskolemizing ``urn:bnid:`` IRIs), so the proof is one that verifier accepted."""
    import re

    from openvc.proof import ecdsa_sd as m

    loader = document_loader()
    parts = m.decode_base_proof(base["proof"]["proofValue"])
    transform = m._transform({k: v for k, v in base.items() if k != "proof"},
                             parts["hmac_key"], loader)
    mandatory = m._selection_lines(
        m.select_json_ld(parts["mandatory_pointers"], transform.skolemized_compact) or {},
        transform.skolem_to_hmac, loader)
    signature_of = dict(zip([ln for ln in transform.relabeled if ln not in mandatory],
                            parts["signatures"]))
    hmac_labels = sorted({x[2:] for ln in transform.relabeled
                          for x in re.findall(r"_:u[A-Za-z0-9_-]+", ln)})
    unsecured = {k: v for k, v in reveal.items() if k != "proof"}
    lines, id_map = m._canonicalize(m._deskolemize_nquads(m._to_nquads(unsecured, loader)))
    label_map = {c[2:]: label_for(c[2:], hmac_labels) for c in sorted(set(id_map.values()))}
    relabeled = m._relabel(lines, {"_:" + k: "_:" + v for k, v in label_map.items()})
    mandatory_idx = [i for i, ln in enumerate(relabeled) if ln in mandatory]
    signatures = [signature_of[ln] for i, ln in enumerate(relabeled) if i not in mandatory_idx]
    out = copy.deepcopy(reveal)
    out["proof"] = {k: v for k, v in base["proof"].items() if k != "proofValue"}
    out["proof"]["proofValue"] = m.encode_derived_proof(
        base_signature=parts["base_signature"], public_key=parts["public_key"],
        signatures=signatures, label_map=label_map, mandatory_indexes=mandatory_idx)
    return out


def _sd_blank_status_base():
    """An issuer-signed ecdsa-sd-2023 base proof whose (revoked) STATUS_2 entry is a
    blank node, also of an unrelated type, named from relatedResource too: the
    section-13 shape with an id-less entry. Everything is mandatory."""
    entry = {k: v for k, v in STATUS_2.items() if k != "id"}
    entry.update(id="_:s", type=["BitstringStatusListEntry", _OTHER_STATUS_TYPE])
    key = P256SigningKey.generate(kid=VM)
    base = EcdsaSdProofSuite().add_base_proof(
        _vc(**{"@context": [V2, EXAMPLES_VOCAB]}, credentialStatus=entry,
            relatedResource={"id": "_:s"}),
        signing_key=key, verification_method=VM,
        mandatory_pointers=["/issuer", "/validFrom", "/credentialStatus",
                            "/relatedResource"])
    return base, entry, _registry(key.public_jwk())


def _sd_moved(base, entry, status_id):
    """The base's JSON with the entry described under relatedResource and only its
    unrelated type left under credentialStatus, as node *status_id* (None: id-less)."""
    moved = {k: v for k, v in base.items() if k != "proof"}
    moved["credentialStatus"] = {"type": _OTHER_STATUS_TYPE}
    if status_id is not None:
        moved["credentialStatus"]["id"] = status_id
    moved["relatedResource"] = dict(entry, type="BitstringStatusListEntry")
    return moved


def _skolem_iri_moved(base, entry):
    """:func:`_sd_moved` with the left-behind type on `urn:bnid:bN`, N being the label
    pyld gives the relatedResource node, so the pre-fix verifier merged the two and the
    label map stays injective."""
    from openvc.proof import ecdsa_sd as m

    for n in range(8):
        moved = _sd_moved(base, entry, f"urn:bnid:b{n}")
        _, id_map = m._canonicalize(m._deskolemize_nquads(m._to_nquads(
            moved, document_loader())))
        if len(set(id_map.values())) == 1:
            return moved
    raise AssertionError("no urn:bnid:bN collides with pyld's label")     # pragma: no cover


def _only(c14n, hmac_labels):
    assert len(hmac_labels) == 1             # the entry is the only blank node signed
    return hmac_labels[0]


# variant -> (the holder's JSON, what verifying it now raises)
_SD_MERGES = {
    # two JSON blank nodes, both mapped to the issuer's one entry
    "non-injective-label-map": (lambda b, e: _sd_moved(b, e, "_:a"), ProofValueMalformed),
    "non-injective-label-map-idless": (lambda b, e: _sd_moved(b, e, None),
                                       ProofValueMalformed),
    # an IRI to JSON-LD, the issuer's blank node to the deskolemizing verifier
    "skolem-iri": (_skolem_iri_moved, SignatureInvalid),
    # control: one JSON label in both places is one node to both, and context validation
    # refuses the move as in section 13
    "same-blank-label": (lambda b, e: _sd_moved(b, e, "_:s"), ProofMalformed),
}


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "optional"])
@pytest.mark.parametrize("variant", sorted(_SD_MERGES))
def test_ecdsa_sd_cannot_merge_blank_nodes_to_move_a_status_entry(variant, require_status):
    from openvc.status import CredentialRevoked

    base, entry, registry = _sd_blank_status_base()
    honest = _sd_full_reveal(base, {k: v for k, v in base.items() if k != "proof"}, _only)
    assert _status_outcomes(honest, registry, require_status=require_status) == [
        CredentialRevoked, CredentialRevoked]                                  # control

    build, raised = _SD_MERGES[variant]
    attacked = _sd_full_reveal(base, build(base, entry), _only)
    assert _status_outcomes(attacked, registry, require_status=require_status) == [
        raised, raised]
    with pytest.raises(raised):
        EcdsaSdProofSuite().verify(attacked, resolver=registry)


def test_ecdsa_sd_genuine_derived_blank_node_status_still_verifies():
    # openvc's own derive_proof labels the disclosed blank nodes `_:bN` and writes an
    # injective label map: an id-less status entry, disclosed or withheld, still works.
    from openvc.status import CredentialRevoked

    entry = {k: v for k, v in STATUS_2.items() if k != "id"}
    derived, key = _ecdsa_sd_derived(
        _vc(credentialStatus=entry), ["/issuer", "/validFrom", "/credentialStatus"])
    assert derived["credentialStatus"]["id"].startswith("_:")
    registry = _registry(key.public_jwk())
    for require_status in (True, False):
        assert _status_outcomes(derived, registry, require_status=require_status) == [
            CredentialRevoked, CredentialRevoked]


def test_ecdsa_sd_derive_never_relies_on_a_deskolemizing_verifier():
    # derive_proof computes the label map as verify canonicalizes the reveal. When a
    # blank node the issuer named from a second property reaches the reveal as a
    # `urn:bnid:` IRI (a compacted reference), the pre-fix derive deskolemized it and so
    # produced a proof only the pre-fix verifier accepted. Now it either fails closed at
    # derive or yields a proof that verifies; never one the verifier refuses.
    from openvc.proof.ecdsa_sd import EcdsaSdError

    key = P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    entry = dict(STATUS_2, id="_:b0")
    for related in ("_:b0", {"id": "_:b0"}):
        base = suite.add_base_proof(
            _vc(credentialStatus=entry, relatedResource=related),
            signing_key=key, verification_method=VM,
            mandatory_pointers=["/issuer", "/validFrom"])
        try:
            derived = suite.derive_proof(
                base, selective_pointers=["/credentialStatus", "/relatedResource"])
        except EcdsaSdError:
            continue
        suite.verify(derived, public_key_jwk=key.public_jwk())


# --------------------------------------------------------------------------- #
# 20. An exact copy of a status entry elsewhere still verifies (GHSA-h9rq-wxcw-4rjc)
# --------------------------------------------------------------------------- #
# A credential embedded in another (an OB 3.0 EndorsementCredential, say) may repeat the
# outer credentialStatus verbatim. RDF merges the two descriptions into the same
# statements, so the copy carries nothing the entry lacks: removing it leaves the same
# dataset and the same top-level entry. Section 13's rule refused any description
# elsewhere, so such a credential failed on every RDF suite. Now a description elsewhere
# is refused only when it is not an exact copy (equal expanded node objects) of a
# top-level entry with that id; moving any member out of the entry makes them differ.

def _with_endorsement_copy(status):
    inner = {"id": "urn:uuid:inner", "type": ["VerifiableCredential"],
             "issuer": "did:example:accreditor", "validFrom": "2020-01-01T00:00:00Z",
             "credentialSubject": {"id": DID}, "credentialStatus": dict(status)}
    return _vc(**{"@context": [V2, EXAMPLES_VOCAB]}, credentialStatus=dict(status),
               credentialSubject={"id": "did:example:alice", "name": "Alice",
                                  "endorsement": inner})


def _with_related_copy(status):
    return _vc(credentialStatus=dict(status), relatedResource=dict(status))


_STATUS_COPIES = {
    # placement -> (the credential, the copy of its status entry in it)
    "endorsement": (_with_endorsement_copy,
                    lambda doc: doc["credentialSubject"]["endorsement"]["credentialStatus"]),
    "related-resource": (_with_related_copy, lambda doc: doc["relatedResource"]),
}


@pytest.mark.parametrize("signer", ["openvc", "third-party"])
@pytest.mark.parametrize("placement", sorted(_STATUS_COPIES))
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_exact_status_copy_elsewhere_verifies(suite_id, placement, signer):
    from openvc.status import CredentialRevoked

    build, _ = _STATUS_COPIES[placement]
    sign = _sign if signer == "openvc" else _sign_raw
    clear, clear_registry = sign(suite_id, build(STATUS))
    revoked, revoked_registry = sign(suite_id, build(STATUS_2))
    assert _status_outcomes(clear, clear_registry) == [None, None]
    assert _status_outcomes(revoked, revoked_registry) == [CredentialRevoked] * 2
    for require_status in (True, False):
        assert _status_outcomes(revoked, revoked_registry,
                                require_status=require_status) == [CredentialRevoked] * 2


@pytest.mark.parametrize("placement", sorted(_STATUS_COPIES))
@pytest.mark.parametrize("suite_id", SUITE_IDS)
def test_a_copy_that_is_no_longer_exact_is_still_refused(suite_id, placement):
    # The holder moves a member out of the top-level entry (the copy keeps it, so the
    # dataset and the signature are unchanged), or out of the copy, or drops the
    # unrelated type from one side: either way the two descriptions now differ.
    build, copy_of = _STATUS_COPIES[placement]
    entry = dict(STATUS_2, type=["BitstringStatusListEntry", _OTHER_STATUS_TYPE])
    doc = build(entry)
    doc["@context"] = [V2, EXAMPLES_VOCAB]
    secured, registry = _sign(suite_id, doc)
    attacks = []
    for member in ("statusPurpose", "statusListIndex", "statusListCredential"):
        moved = copy.deepcopy(secured)
        del moved["credentialStatus"][member]
        attacks.append(moved)
    left_behind = copy.deepcopy(secured)                     # the section-13 shape
    left_behind["credentialStatus"] = {"id": STATUS_2["id"], "type": _OTHER_STATUS_TYPE}
    copy_of(left_behind)["type"] = "BitstringStatusListEntry"
    attacks.append(left_behind)
    for attacked in attacks:
        for require_status in (True, False):
            assert _status_outcomes(attacked, registry, require_status=require_status) == [
                ProofMalformed, ProofMalformed]
    suite_cls, _ = _SUITES[suite_id]
    with pytest.raises(ProofMalformed, match="described outside credentialStatus"):
        suite_cls().verify(attacks[0], resolver=registry)


def test_ecdsa_sd_exact_status_copy_in_an_embedded_credential_verifies():
    # An OB 3.0 library that verifies eddsa-rdfc-2022 itself, tolerating this copy, and
    # delegates ecdsa-sd-2023 to this suite verified one badge there and refused it here.
    from openvc.status import CredentialRevoked

    derived, key = _ecdsa_sd_derived(
        _with_endorsement_copy(STATUS_2),
        ["/issuer", "/validFrom", "/credentialStatus", "/credentialSubject"])
    registry = _registry(key.public_jwk())
    for require_status in (True, False):
        assert _status_outcomes(derived, registry, require_status=require_status) == [
            CredentialRevoked, CredentialRevoked]

    moved = copy.deepcopy(derived)
    del moved["credentialStatus"]["statusPurpose"]
    for require_status in (True, False):
        assert _status_outcomes(moved, registry, require_status=require_status) == [
            ProofMalformed, ProofMalformed]
    with pytest.raises(ProofMalformed, match="described outside credentialStatus"):
        EcdsaSdProofSuite().verify(moved, public_key_jwk=key.public_jwk())
