"""
tests/test_pyld_context_isolation.py — one call's JSON-LD contexts never reach another's
(#225, the hardening follow-up to GHSA-vrxg-57v4-85mc).

pyld keeps a process-global resolved-context cache. It caches an inline (object) ``@context``
by its JSON, with the processed result of any ``@import`` inside it, and tags that entry
``static`` whatever the document loader said. openvc's loader is per call
(``document_loader(extra_contexts)``), but until 1.35.0 the pyld calls shared that cache, so
an inline context that ``@import``s a URL was resolved once, with whichever caller's
``extra_contexts`` came first, and every later call in the process took the same result:
another caller's terms, or a context its own loader would have refused.

These tests drive the real pipeline, in one process, in the order that exposes the cache:
tenant A's contexts, then tenant B's for the *same* URLs, then none. Each call must see only
the loader it was handed. They name no 1.35.0 API, so they run unchanged on an older tree,
where they fail. The structural half (every pyld call takes its options from
``pyld_options``, the bundled-only cache) is ``test_pyld_options.py``.

Two shapes reach the cache. An inline ``{"@import": U}`` *in the credential* is what the
issue reports; the 1.30.2 inline-context rule refuses it after canonicalization, so it never
verifies. A *served* context (``extra_contexts``, which the rule trusts) that holds the inline
``@import`` is not refused, and there the leak reached the verdict without a hostile
document: the second tenant could not issue its own credential, and a credential signed under
the first tenant's definition of a property verified under the second tenant's contexts.

Every test uses URLs of its own, so no test depends on what an earlier one cached. Helpers
are self-contained (tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import pytest

pytest.importorskip("pyld")              # the RDF suites canonicalize with pyld

from openvc import VerificationPolicy, verify_credential  # noqa: E402
from openvc.did.base import DidResolutionError, parse_did_document  # noqa: E402
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof import data_integrity as di  # noqa: E402
from openvc.proof.contexts import DocumentLoaderError, document_loader  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import ProofMalformed, SignatureInvalid  # noqa: E402
from openvc.verify import TypeMismatch  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
DID = "did:example:issuer"
VM = f"{DID}#k"

# The two tenants define the same term differently.
DMV = "https://dmv.example/DL"
OTHER = "https://other.example/X"


def _tenant(iri):
    return {"@context": {"DriversLicense": iri}}


def _urls(case):
    """The wrapper and the imported URL of one test (unique, so tests do not share keys)."""
    return (f"https://tenant.example/{case}/wrapper", f"https://tenant.example/{case}/ctx")


def _served(wrapper, imported, iri):
    """What one tenant serves: *wrapper* holds an inline context that ``@import``s
    *imported*, which defines ``DriversLicense`` as *iri*."""
    return {wrapper: {"@context": [{"@import": imported}]}, imported: _tenant(iri)}


def _credential(*context_tail):
    return {
        "@context": [V2, *context_tail],
        "id": "urn:uuid:7d1e5c38-0000-4000-8000-000000000225",
        "type": ["VerifiableCredential", "DriversLicense"],
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
    }


def _raises_exactly(exc_type, fn, match=None):
    """*fn* must raise ``exc_type`` itself (not a subclass or a sibling)."""
    with pytest.raises(Exception, match=match) as caught:
        fn()
    assert type(caught.value) is exc_type, repr(caught.value)


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


# --------------------------------------------------------------------------- #
# 1. The issue's repro: an inline @import in the credential itself
# --------------------------------------------------------------------------- #

def test_inline_import_canonical_form_follows_the_loader_of_the_call():
    """The canonical N-Quads of one document follow each call's own loader."""
    _, imported = _urls("canonize")
    doc = _credential({"@import": imported})

    nquads_a = di._canonize(doc, document_loader({imported: _tenant(DMV)}))
    nquads_b = di._canonize(doc, document_loader({imported: _tenant(OTHER)}))
    assert f"<{DMV}>".encode() in nquads_a and f"<{OTHER}>".encode() not in nquads_a
    assert f"<{OTHER}>".encode() in nquads_b and f"<{DMV}>".encode() not in nquads_b

    # no extra_contexts: the loader refuses the URL; nothing a call cached stands in for it
    _raises_exactly(DocumentLoaderError, lambda: di._canonize(doc, document_loader()),
                    match="refusing to fetch")
    nquads_a_again = di._canonize(doc, document_loader({imported: _tenant(DMV)}))
    assert nquads_a_again == nquads_a


def test_an_earlier_inline_import_does_not_make_a_later_call_fail():
    """pyld keys an inline context by its JSON, and so does the entry of the context a URL
    serves (its inner object). When the two hold the same terms they were one resolved
    context, and what ``@import`` stored on it was handed back as an active context, so the
    second of two such calls died in canonicalization (``DataIntegrityError``, from
    ``KeyError: 'mappings'`` or a ``NormalizeError`` inside pyld). Whatever ran before, each
    form must canonicalize, to the same dataset."""
    _, imported = _urls("order")
    iri = "https://dmv.example/order-DL"
    served = {imported: _tenant(iri)}
    forms = {
        "import": _credential({"@import": imported}),
        "inline": _credential({"DriversLicense": iri}),
        "url": _credential(imported),
        "import_then_url": _credential({"@import": imported}, imported),
    }
    expected = None
    for name in ["import", "inline", "url", "import_then_url", "inline", "import", "url"]:
        nquads = di._canonize(forms[name], document_loader(served))
        assert f"<{iri}>".encode() in nquads, name
        expected = expected or nquads
        assert nquads == expected, name


def test_inline_import_credential_fails_for_the_right_reason_in_each_call():
    """A credential signed with the inline context, validation bypassed (what an attacker
    would hold). Tenant A: the signature is valid and the 1.30.2 rule refuses the inline
    context. Tenant B defines the term differently, so its dataset is another one and the
    signature must fail. No ``extra_contexts``: the import cannot load. On a tree that
    shares pyld's cache B and the third call both reach the rule instead."""
    _, imported = _urls("pipeline")
    key = Ed25519SigningKey.generate(kid=VM)
    jwk = key.public_jwk()
    doc = _credential({"@import": imported})
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
             "created": "2020-01-01T00:00:00Z", "verificationMethod": VM,
             "proofPurpose": "assertionMethod"}
    config = dict(proof, **{"@context": doc["@context"]})
    signature = key.sign(di._hash_data(doc, config, document_loader({imported: _tenant(DMV)})))
    signed = dict(doc, proof=dict(proof, proofValue=encode_multibase(signature)))
    suite = DataIntegrityProofSuite()

    def verify(extra):
        return lambda: suite.verify(signed, public_key_jwk=jwk, extra_contexts=extra)

    _raises_exactly(ProofMalformed, verify({imported: _tenant(DMV)}), match="may only carry @vocab")
    _raises_exactly(SignatureInvalid, verify({imported: _tenant(OTHER)}))
    _raises_exactly(DocumentLoaderError, verify(None), match="refusing to fetch")
    _raises_exactly(ProofMalformed, verify({imported: _tenant(DMV)}), match="may only carry @vocab")


# --------------------------------------------------------------------------- #
# 2. A served context that holds the inline @import (trusted, so not refused)
# --------------------------------------------------------------------------- #

_SUITES = {
    "eddsa-rdfc-2022": (DataIntegrityProofSuite, Ed25519SigningKey),
    "ecdsa-rdfc-2019": (EcdsaRdfcProofSuite, P256SigningKey),
}


@pytest.mark.parametrize("suite_id", sorted(_SUITES))
def test_served_inline_import_is_resolved_per_call(suite_id):
    wrapper, imported = _urls(f"served-{suite_id}")
    suite_cls, key_cls = _SUITES[suite_id]
    key = key_cls.generate(kid=VM)
    jwk = key.public_jwk()
    suite = suite_cls()
    tenant_a = _served(wrapper, imported, DMV)
    tenant_b = _served(wrapper, imported, OTHER)
    doc = _credential(wrapper)

    def sign(extra):
        return suite.add_proof(doc, signing_key=key, verification_method=VM, extra_contexts=extra)

    def verify(secured, extra):
        return lambda: suite.verify(secured, public_key_jwk=jwk, extra_contexts=extra)

    secured_a = sign(tenant_a)
    verify(secured_a, tenant_a)()
    # tenant B signs and verifies its own credential, under its own definition of the term
    secured_b = sign(tenant_b)
    verify(secured_b, tenant_b)()
    # each credential verifies under its own contexts only: the term is another IRI in the other
    _raises_exactly(SignatureInvalid, verify(secured_a, tenant_b))
    _raises_exactly(SignatureInvalid, verify(secured_b, tenant_a))
    # the wrapper without the imported URL: the loader refuses it, nothing cached supplies it
    _raises_exactly(DocumentLoaderError, verify(secured_a, {wrapper: tenant_a[wrapper]}),
                    match="refusing to fetch")
    verify(secured_a, tenant_a)()


def test_served_inline_import_is_resolved_per_call_on_ecdsa_sd():
    """``ecdsa-sd-2023`` has its own pyld calls (expand, compact, to_rdf, normalize)."""
    wrapper, imported = _urls("served-sd")
    key = P256SigningKey.generate(kid=VM)
    jwk = key.public_jwk()
    suite = EcdsaSdProofSuite()
    tenant_a = _served(wrapper, imported, DMV)
    tenant_b = _served(wrapper, imported, OTHER)
    doc = _credential(wrapper)

    def derived(extra):
        base = suite.add_base_proof(
            doc, signing_key=key, verification_method=VM,
            mandatory_pointers=["/issuer", "/validFrom", "/type"], extra_contexts=extra)
        return suite.derive_proof(
            base, selective_pointers=["/credentialSubject/name"], extra_contexts=extra)

    def verify(secured, extra):
        return lambda: suite.verify(secured, public_key_jwk=jwk, extra_contexts=extra)

    derived_a = derived(tenant_a)
    verify(derived_a, tenant_a)()
    derived_b = derived(tenant_b)
    verify(derived_b, tenant_b)()
    _raises_exactly(SignatureInvalid, verify(derived_a, tenant_b))
    _raises_exactly(SignatureInvalid, verify(derived_b, tenant_a))
    _raises_exactly(ProofMalformed, verify(derived_a, {wrapper: tenant_a[wrapper]}),
                    match="could not canonicalize")
    verify(derived_a, tenant_a)()


def test_expected_types_pin_is_resolved_per_call():
    """``expected_types`` expands the credential once more (``missing_types``) and matches
    the result against the contexts the verifier serves."""
    wrapper, imported = _urls("served-pin")
    key = Ed25519SigningKey.generate(kid=VM)
    registry = _registry(key.public_jwk())
    suite = DataIntegrityProofSuite()
    tenant_a = _served(wrapper, imported, DMV)
    tenant_b = _served(wrapper, imported, OTHER)
    doc = _credential(wrapper)
    pin = VerificationPolicy(expected_types=["DriversLicense"])

    def check(secured, extra):
        return lambda: verify_credential(
            secured, resolver=registry, policy=pin, extra_contexts=extra)

    secured_a = suite.add_proof(
        doc, signing_key=key, verification_method=VM, extra_contexts=tenant_a)
    secured_b = suite.add_proof(
        doc, signing_key=key, verification_method=VM, extra_contexts=tenant_b)
    check(secured_a, tenant_a)()
    check(secured_b, tenant_b)()
    # a pin on a type the verifier's contexts do not give this IRI is still a mismatch
    other_pin = VerificationPolicy(expected_types=["https://third.example/Other"])
    _raises_exactly(TypeMismatch, lambda: verify_credential(
        secured_b, resolver=registry, policy=other_pin, extra_contexts=tenant_b))


def test_a_credential_signed_under_another_callers_term_is_not_accepted():
    """The wrong-accept this leak allowed, with two callers that serve the same URLs with
    different definitions of a property. Caller A's credential verifies under A's contexts
    (which warms the process); caller B's contexts define the property as another IRI, so
    under B's configuration the signed dataset is different and the signature must not hold.
    Before 1.35.0 B accepted it: canonicalization ran with A's definition."""
    wrapper, imported = _urls("cross")
    key = Ed25519SigningKey.generate(kid=VM)
    jwk = key.public_jwk()
    suite = DataIntegrityProofSuite()

    def served(iri):
        return {wrapper: {"@context": [{"@import": imported}]},
                imported: {"@context": {"licenseNumber": iri}}}

    doc = _credential(wrapper)
    doc["type"] = ["VerifiableCredential"]
    doc["credentialSubject"]["licenseNumber"] = "X-1"
    secured = suite.add_proof(
        doc, signing_key=key, verification_method=VM, extra_contexts=served(f"{DMV}#number"))
    assert suite.verify(secured, public_key_jwk=jwk, extra_contexts=served(f"{DMV}#number"))
    _raises_exactly(SignatureInvalid, lambda: suite.verify(
        secured, public_key_jwk=jwk, extra_contexts=served(f"{OTHER}#number")))
    assert suite.verify(secured, public_key_jwk=jwk, extra_contexts=served(f"{DMV}#number"))
