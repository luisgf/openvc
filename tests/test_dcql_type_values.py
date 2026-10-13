"""
tests/test_dcql_type_values.py — DCQL ``meta.type_values`` on the W3C lanes (#205).

OpenID4VP 1.0 §B.1.1: ``type_values`` is a non-empty array of alternatives, each a
non-empty array of **fully expanded** type IRIs (the credential's ``type`` after applying
its ``@context``; a term no context defines stays a relative IRI). A credential matches
when its expanded types contain every IRI of at least one alternative. Before #205
``verify_vp_token`` never read it for ``jwt_vc_json`` / ``ldp_vc``: any verified
credential — one the holder minted from their own ``did:key`` included — answered.

The V1 / examples contexts below are **stand-ins** carrying only the term definitions the
§B.1.1 examples rely on (openvc bundles only the VCDM 2.0 context); the query and the
three credential shapes are the spec's own examples.
"""
from __future__ import annotations

import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import OpenID4VPError, VpTokenMalformed, verify_vp_token
from openvc.proof.contexts import DocumentLoaderError
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

try:
    import pyld  # noqa: F401
    _HAS_PYLD = True
except ImportError:                                    # pragma: no cover
    _HAS_PYLD = False

needs_pyld = pytest.mark.skipif(not _HAS_PYLD, reason="type_values expansion needs pyld")

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
EX = "https://www.w3.org/2018/credentials/examples/v1"
VC_IRI = "https://www.w3.org/2018/credentials#VerifiableCredential"
DEGREE_IRI = "https://example.org/examples#UniversityDegreeCredential"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
LANES = ["jwt_vc_json", "ldp_vc"]

V1_STANDIN = {"@context": {
    "@version": 1.1, "@protected": True, "id": "@id", "type": "@type",
    "VerifiableCredential": {"@id": VC_IRI}}}
EX_STANDIN = {"@context": {
    "@version": 1.1,
    "UniversityDegreeCredential": DEGREE_IRI,
    "AlumniCredential": "https://example.org/examples#AlumniCredential",
    "BachelorDegree": "https://example.org/examples#BachelorDegree"}}
STANDINS = {V1: V1_STANDIN, EX: EX_STANDIN}

# OpenID4VP 1.0 §B.1.1, verbatim.
SPEC_TYPE_VALUES = [
    [VC_IRI, "https://example.org/examples#AlumniCredential",
     "https://example.org/examples#BachelorDegree"],
    [VC_IRI, DEGREE_IRI],
    ["IdentityCredential"],
]


def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_ed25519():
    key = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())
    return Ed25519SigningKey(key._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _present(lane, bodies):
    """A VP for *lane* embedding one self-issued credential per (context, type) body,
    all issued by and to the presenter (a holder minting their own credential)."""
    if lane == "jwt_vc_json":
        key, did = _did_key_p256()
        vcs = [VcJwtProofSuite().sign(
            {"@context": ctx, "type": typ, "issuer": did, "credentialSubject": {"id": did}},
            signing_key=key) for ctx, typ in bodies]
        return VpJwtProofSuite().sign(vcs, holder_key=key, audience=CLIENT_ID, nonce=NONCE)
    key, did = _did_key_ed25519()
    suite = EddsaJcsProofSuite()
    vcs = [suite.add_proof(
        {"@context": ctx, "type": typ, "issuer": did, "credentialSubject": {"id": did}},
        signing_key=key, verification_method=key.kid, proof_purpose="assertionMethod")
        for ctx, typ in bodies]
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": did,
          "verifiableCredential": vcs}
    return suite.add_proof(vp, signing_key=key, verification_method=key.kid,
                           proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)


def _verify(lane, vp, type_values=None, *, meta=None, query_extra=None, **kw):
    query = {"id": "q", "format": lane, **(query_extra or {})}
    if meta is not None:
        query["meta"] = meta
    elif type_values is not None:
        query["meta"] = {"type_values": type_values}
    return verify_vp_token({"q": [vp]}, dcql_query={"credentials": [query]},
                           nonce=NONCE, client_id=CLIENT_ID, **kw).for_query("q")[0]


DEGREE_V2 = ([V2], ["VerifiableCredential", "UniversityDegreeCredential"])
PLAIN_V2 = ([V2], ["VerifiableCredential"])


# --------------------------------------------------------------------------- #
# matching
# --------------------------------------------------------------------------- #

@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_matching_credential_verifies(lane):
    # Under VCDM 2.0, VerifiableCredential is defined; the degree type is not (no @vocab),
    # so it stays the relative IRI it was written as.
    p = _verify(lane, _present(lane, [DEGREE_V2]), [[VC_IRI, "UniversityDegreeCredential"]])
    assert len(p.credentials) == 1


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_unrelated_self_minted_credential_no_longer_answers(lane):
    # The #205 gap: a holder's own did:key credential of the wrong type, even with
    # require_holder_binding=True (subject == holder), used to answer the query.
    vp = _present(lane, [PLAIN_V2])
    with pytest.raises(ClaimsInvalid, match="none of the requested type_values"):
        _verify(lane, vp, [[VC_IRI, "UniversityDegreeCredential"]],
                require_holder_binding=True)


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_short_name_of_a_defined_term_does_not_match(lane):
    # The spec compares expanded IRIs: VerifiableCredential is defined by the context,
    # so the bare short name in a query never matches a VCDM credential.
    with pytest.raises(ClaimsInvalid):
        _verify(lane, _present(lane, [DEGREE_V2]),
                [["VerifiableCredential", "UniversityDegreeCredential"]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("types", [
    ["VerifiableCredential", "UniversityDegreeCredential"],
    ["VerifiableCredential", "BachelorDegree", "AlumniCredential"],
], ids=["degree", "alumni-any-order"])
def test_spec_b11_examples_match(lane, types):
    vp = _present(lane, [([V1, EX], types)])
    _verify(lane, vp, SPEC_TYPE_VALUES, extra_contexts=STANDINS)


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_spec_b11_undefined_term_stays_relative(lane):
    vp = _present(lane, [([V1], ["VerifiableCredential", "IdentityCredential"])])
    _verify(lane, vp, SPEC_TYPE_VALUES, extra_contexts=STANDINS)


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_partial_alternative_does_not_match(lane):
    # AlumniCredential without BachelorDegree satisfies no inner array in full.
    vp = _present(lane, [([V1, EX], ["VerifiableCredential", "AlumniCredential"])])
    with pytest.raises(ClaimsInvalid):
        _verify(lane, vp, SPEC_TYPE_VALUES, extra_contexts=STANDINS)


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_inline_context_decides_the_iri(lane):
    ctx = [V2, {"UniversityDegreeCredential": DEGREE_IRI}]
    vp = _present(lane, [(ctx, ["VerifiableCredential", "UniversityDegreeCredential"])])
    _verify(lane, vp, [[VC_IRI, DEGREE_IRI]])
    with pytest.raises(ClaimsInvalid):           # now an IRI, no longer the relative term
        _verify(lane, vp, [[VC_IRI, "UniversityDegreeCredential"]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("bodies", [[DEGREE_V2, PLAIN_V2], [PLAIN_V2, DEGREE_V2]],
                         ids=["good-then-unrelated", "unrelated-then-good"])
def test_every_embedded_credential_must_match(lane, bodies):
    with pytest.raises(ClaimsInvalid, match="embedded credential #"):
        _verify(lane, _present(lane, bodies), [[VC_IRI, "UniversityDegreeCredential"]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_every_embedded_credential_matching_verifies(lane):
    p = _verify(lane, _present(lane, [DEGREE_V2, DEGREE_V2]),
                [[VC_IRI, "UniversityDegreeCredential"]])
    assert len(p.credentials) == 2


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("meta", [None, {}, {"vct_values": ["x"]}],
                         ids=["no-meta", "empty", "other-key"])
def test_absent_type_values_is_no_constraint(lane, meta):
    query = {"id": "q", "format": lane, **({} if meta is None else {"meta": meta})}
    verify_vp_token({"q": [_present(lane, [PLAIN_V2])]}, dcql_query={"credentials": [query]},
                    nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# fail closed
# --------------------------------------------------------------------------- #

@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_protected_term_redefinition_fails_closed(lane):
    ctx = [V2, {"VerifiableCredential": "https://evil.example/#VC"}]
    vp = _present(lane, [(ctx, ["VerifiableCredential"])])
    with pytest.raises(ClaimsInvalid, match="cannot expand"):
        _verify(lane, vp, [["https://evil.example/#VC"]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_unbundled_context_is_a_typed_loader_error(lane):
    url = "https://example.org/unbundled/v1"
    vp = _present(lane, [([V2, url], ["VerifiableCredential", "Thing"])])
    with pytest.raises(DocumentLoaderError):
        _verify(lane, vp, [["https://example.org/x#Thing"]])
    _verify(lane, vp, [["https://example.org/x#Thing"]],
            extra_contexts={url: {"@context": {"Thing": "https://example.org/x#Thing"}}})


@needs_pyld
def test_non_string_type_item_fails_closed():
    vp = _present("jwt_vc_json", [([V2], ["VerifiableCredential", 5])])
    with pytest.raises(ClaimsInvalid, match="cannot expand"):
        _verify("jwt_vc_json", vp, [[VC_IRI]])


@needs_pyld
def test_recursion_in_expansion_is_typed(monkeypatch):
    from pyld import jsonld

    def boom(*_a, **_k):
        raise RecursionError("too deep")
    monkeypatch.setattr(jsonld, "expand", boom)
    with pytest.raises(ClaimsInvalid, match="RecursionError"):
        _verify("jwt_vc_json", _present("jwt_vc_json", [DEGREE_V2]), [[VC_IRI]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_nested_sd_jwt_never_matches(lane):
    key, did = _did_key_p256()
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": did, "sub": did, "@context": [V2], "type": ["VerifiableCredential"]},
        signing_key=key, vct="https://credentials.example.com/x", disclosable=[])
    if lane == "jwt_vc_json":
        vp = VpJwtProofSuite().sign([sd_jwt], holder_key=key, audience=CLIENT_ID,
                                    nonce=NONCE)
    else:
        hk, hdid = _did_key_ed25519()
        vp = EddsaJcsProofSuite().add_proof(
            {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
             "verifiableCredential": [sd_jwt]},
            signing_key=hk, verification_method=hk.kid, proof_purpose="authentication",
            challenge=NONCE, domain=CLIENT_ID)
    # Opted out of holder binding (#196), so the KB-less SD-JWT gets as far as the type
    # check: even with an issuer-signed @context + type, it never matches.
    with pytest.raises(ClaimsInvalid, match="none of the requested type_values"):
        _verify(lane, vp, [[VC_IRI]],
                query_extra={"require_cryptographic_holder_binding": False})


MALFORMED = [
    pytest.param({"type_values": None}, id="null"),
    pytest.param({"type_values": "VerifiableCredential"}, id="string"),
    pytest.param({"type_values": []}, id="empty"),
    pytest.param({"type_values": [[]]}, id="empty-alternative"),
    pytest.param({"type_values": [VC_IRI]}, id="flat-list"),     # chars must not widen
    pytest.param({"type_values": [[""]]}, id="empty-string"),
    pytest.param({"type_values": [[5]]}, id="number"),
    pytest.param({"type_values": [[VC_IRI, None]]}, id="null-item"),
    pytest.param({"type_values": [(VC_IRI,)]}, id="tuple"),
    pytest.param({"type_values": {"a": [VC_IRI]}}, id="object"),
    pytest.param([], id="meta-array"),
    pytest.param("x", id="meta-string"),
]


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("meta", MALFORMED)
def test_malformed_constraint_fails_safe_before_verifying(lane, meta):
    # A presentation that could not verify: the malformed query is reported first.
    junk = "not-a-jwt" if lane == "jwt_vc_json" else {"type": ["VerifiablePresentation"]}
    with pytest.raises(VpTokenMalformed, match="meta"):
        _verify(lane, junk, meta=meta)


def test_missing_pyld_is_a_typed_error_before_verifying(monkeypatch):
    monkeypatch.setitem(sys.modules, "pyld", None)
    with pytest.raises(OpenID4VPError, match="data-integrity") as info:
        _verify("jwt_vc_json", "not-a-jwt", [[VC_IRI]])
    assert type(info.value) is OpenID4VPError


# --------------------------------------------------------------------------- #
# regressions from the adversarial review of #216
# --------------------------------------------------------------------------- #

@needs_pyld
@pytest.mark.parametrize("cryptosuite", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
def test_rdf_canonicalized_credential_is_refused_not_matched(cryptosuite):
    # type_values is matched only on VC-JWT and JCS credentials: even an honest
    # RDF-canonicalized credential of the requested type is refused rather than matched.
    if cryptosuite == "eddsa-rdfc-2022":
        from openvc.proof.data_integrity import DataIntegrityProofSuite as Suite
        ikey, idid = _did_key_ed25519()
    else:
        from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite as Suite
        ikey, idid = _did_key_p256()
    hkey, hdid = _did_key_ed25519()
    vc = Suite().add_proof(
        {"@context": [V2], "type": ["VerifiableCredential", "UniversityDegreeCredential"],
         "issuer": idid, "credentialSubject": {"id": hdid}},
        signing_key=ikey, verification_method=ikey.kid, proof_purpose="assertionMethod")
    vp = EddsaJcsProofSuite().add_proof(
        {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
         "verifiableCredential": [vc]},
        signing_key=hkey, verification_method=hkey.kid, proof_purpose="authentication",
        challenge=NONCE, domain=CLIENT_ID)
    _verify("ldp_vc", vp)                        # no type_values: still verifies
    with pytest.raises(ClaimsInvalid, match="matched only on VC-JWT and JCS"):
        _verify("ldp_vc", vp, [[VC_IRI, "UniversityDegreeCredential"]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_inline_import_is_not_cached_across_calls(lane):
    # Each expansion has its own context resolver: one call's extra_contexts never decide
    # another call's match, and an unknown @import is refused every time.
    url = "https://tenant.example/ctx"
    dmv, other = "https://dmv.example/DriversLicense", "https://other.example/X"
    vp = _present(lane, [([V2, {"@import": url}], ["VerifiableCredential", "DriversLicense"])])
    _verify(lane, vp, [[VC_IRI, dmv]],
            extra_contexts={url: {"@context": {"DriversLicense": dmv}}})
    with pytest.raises(ClaimsInvalid):
        _verify(lane, vp, [[VC_IRI, dmv]],
                extra_contexts={url: {"@context": {"DriversLicense": other}}})
    with pytest.raises(DocumentLoaderError):
        _verify(lane, vp, [[VC_IRI, dmv]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_context_base_is_honoured(lane):
    # JSON-LD resolves an undefined type against a context's absolute @base; pyld skips
    # that when the document base is None, which would have kept it relative.
    ctx = [V2, {"@base": "https://x.example/"}]
    vp = _present(lane, [(ctx, ["VerifiableCredential", "Foo"])])
    _verify(lane, vp, [[VC_IRI, "https://x.example/Foo"]])
    with pytest.raises(ClaimsInvalid):
        _verify(lane, vp, [[VC_IRI, "Foo"]])


@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_null_base_keeps_undefined_types_relative(lane):
    vp = _present(lane, [([V2, {"@base": None}], ["VerifiableCredential", "Foo"])])
    _verify(lane, vp, [[VC_IRI, "Foo"]])


@needs_pyld
def test_dot_segment_type_does_not_match_its_resolved_form():
    vp = _present("jwt_vc_json", [([V2], ["VerifiableCredential", "./Dot", "../Up"])])
    for wanted in ("Dot", "https://openvc.invalid/Up"):
        with pytest.raises(ClaimsInvalid):
            _verify("jwt_vc_json", vp, [[VC_IRI, wanted]])


@needs_pyld
def test_type_not_mapped_to_at_type_never_matches():
    # Without a context aliasing `type` to @type, the written types are not types at all.
    vp = _present("jwt_vc_json", [([{"type": "https://x.example/p"}], ["VerifiableCredential"])])
    with pytest.raises(ClaimsInvalid, match="none of the requested type_values"):
        _verify("jwt_vc_json", vp, [["VerifiableCredential"]])
