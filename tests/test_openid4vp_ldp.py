"""
tests/test_openid4vp_ldp.py — OpenID4VP 1.0 ``ldp_vc`` presentations: a W3C Verifiable
Presentation secured with a Data Integrity ``authentication`` proof (issue #61).

Covers all four whole-document cryptosuites (RDF + JCS, Ed25519 + P-256), the holder
binding (challenge = nonce, domain = the prefixed client_id), the embedded-credential
cascade, and the fail-closed rejections: wrong nonce/client_id, a bare string or bare
credential smuggled under an ``ldp_vc`` query, a missing/tampered embedded credential,
a non-``authentication`` proof, and an unsupported cryptosuite.
"""
from __future__ import annotations

import copy

import pytest

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import (
    UnsupportedPresentationFormat,
    VpTokenMalformed,
    verify_vp_token,
)
from openvc.proof.errors import ProofError, SignatureInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite

try:
    import pyld  # noqa: F401
    _HAS_PYLD = True
except ImportError:                                    # pragma: no cover
    _HAS_PYLD = False

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"
DCQL = {"credentials": [{"id": "c1", "format": "ldp_vc"}]}


def _did_key(key, mc_prefix: bytes):
    mb = encode_multibase(mc_prefix + key.public_key_raw())
    return f"did:key:{mb}", f"did:key:{mb}#{mb}"


def _suite(cryptosuite: str):
    if cryptosuite == "eddsa-rdfc-2022":
        from openvc.proof.data_integrity import DataIntegrityProofSuite
        return DataIntegrityProofSuite(), Ed25519SigningKey, bytes([0xED, 0x01])
    if cryptosuite == "eddsa-jcs-2022":
        from openvc.proof.di_jcs import EddsaJcsProofSuite
        return EddsaJcsProofSuite(), Ed25519SigningKey, bytes([0xED, 0x01])
    if cryptosuite == "ecdsa-rdfc-2019":
        from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
        return EcdsaRdfcProofSuite(), P256SigningKey, bytes([0x80, 0x24])
    from openvc.proof.di_jcs import EcdsaJcsProofSuite   # ecdsa-jcs-2019
    return EcdsaJcsProofSuite(), P256SigningKey, bytes([0x80, 0x24])


def _issue_and_present(cryptosuite: str, *, nonce=NONCE, client_id=CLIENT_ID,
                       purpose="authentication"):
    suite, key_factory, mc = _suite(cryptosuite)
    ik = key_factory.generate(kid="_")
    idid, ikid = _did_key(ik, mc)
    ik = key_factory(ik._sk, kid=ikid)
    hk = key_factory.generate(kid="_")
    hdid, hkid = _did_key(hk, mc)
    hk = key_factory(hk._sk, kid=hkid)

    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": idid,
          "credentialSubject": {"id": hdid, "alumniOf": "Example University"}}
    secured_vc = suite.add_proof(vc, signing_key=ik, verification_method=ikid,
                                 proof_purpose="assertionMethod")
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
          "verifiableCredential": [secured_vc]}
    secured_vp = suite.add_proof(vp, signing_key=hk, verification_method=hkid,
                                 proof_purpose=purpose, challenge=nonce, domain=client_id)
    return secured_vp


_ALL = [
    pytest.param("eddsa-rdfc-2022",
                 marks=pytest.mark.skipif(not _HAS_PYLD, reason="needs pyld")),
    "eddsa-jcs-2022",
    pytest.param("ecdsa-rdfc-2019",
                 marks=pytest.mark.skipif(not _HAS_PYLD, reason="needs pyld")),
    "ecdsa-jcs-2019",
]


@pytest.mark.parametrize("cryptosuite", _ALL)
def test_ldp_vp_roundtrip(cryptosuite):
    vp = _issue_and_present(cryptosuite)
    result = verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce=NONCE,
                             client_id=CLIENT_ID)
    (p,) = result.presentations
    assert p.format == "ldp_vc"
    assert p.holder and p.holder.startswith("did:key:")
    assert len(p.credentials) == 1
    assert p.credentials[0].subject == p.holder    # alumnus == presenter here


def test_ldp_vp_holder_is_the_authenticated_signer():
    # No self-asserted `holder` field -> the reported holder is the DID that signed.
    suite, key_factory, mc = _suite("eddsa-jcs-2022")
    ik = key_factory.generate(kid="_")
    idid, ikid = _did_key(ik, mc)
    ik = key_factory(ik._sk, kid=ikid)
    hk = key_factory.generate(kid="_")
    hdid, hkid = _did_key(hk, mc)
    hk = key_factory(hk._sk, kid=hkid)
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": idid,
          "credentialSubject": {"id": hdid}}
    svc = suite.add_proof(vc, signing_key=ik, verification_method=ikid,
                          proof_purpose="assertionMethod")
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],   # no `holder` field
          "verifiableCredential": [svc]}
    svp = suite.add_proof(vp, signing_key=hk, verification_method=hkid,
                          proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    (p,) = verify_vp_token({"c1": [svp]}, dcql_query=DCQL, nonce=NONCE,
                           client_id=CLIENT_ID).presentations
    assert p.holder == hdid                          # the signer, derived from the proof


def test_ldp_vp_rejects_self_asserted_holder_spoof():
    # Alice signs a VP but labels holder = Bob (a victim). The self-asserted holder must
    # not be trusted over the authenticating key. (The #61 adversarial-review finding.)
    suite, key_factory, mc = _suite("eddsa-jcs-2022")
    ik = key_factory.generate(kid="_")
    idid, ikid = _did_key(ik, mc)
    ik = key_factory(ik._sk, kid=ikid)
    bob = key_factory.generate(kid="_")
    bob_did, _bob_kid = _did_key(bob, mc)
    alice = key_factory.generate(kid="_")
    alice_did, alice_kid = _did_key(alice, mc)
    alice = key_factory(alice._sk, kid=alice_kid)

    vc_for_bob = suite.add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": idid,
         "credentialSubject": {"id": bob_did}},
        signing_key=ik, verification_method=ikid, proof_purpose="assertionMethod")
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": bob_did,
          "verifiableCredential": [vc_for_bob]}
    spoofed = suite.add_proof(vp, signing_key=alice, verification_method=alice_kid,
                              proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    with pytest.raises(ProofError):                  # ClaimsInvalid <: ProofError
        verify_vp_token({"c1": [spoofed]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_require_holder_binding_enforces_subject():
    # A holder legitimately presents a credential issued to SOMEONE ELSE. Allowed by
    # default; rejected when the caller demands subject == holder.
    suite, key_factory, mc = _suite("eddsa-jcs-2022")
    ik = key_factory.generate(kid="_")
    idid, ikid = _did_key(ik, mc)
    ik = key_factory(ik._sk, kid=ikid)
    hk = key_factory.generate(kid="_")
    hdid, hkid = _did_key(hk, mc)
    hk = key_factory(hk._sk, kid=hkid)
    other_subject = "did:example:carol"

    svc = suite.add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": idid,
         "credentialSubject": {"id": other_subject}},
        signing_key=ik, verification_method=ikid, proof_purpose="assertionMethod")
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
          "verifiableCredential": [svc]}
    svp = suite.add_proof(vp, signing_key=hk, verification_method=hkid,
                          proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)

    # default: a holder may present another party's credential
    (p,) = verify_vp_token({"c1": [svp]}, dcql_query=DCQL, nonce=NONCE,
                           client_id=CLIENT_ID).presentations
    assert p.holder == hdid and p.credentials[0].subject == other_subject
    # require_holder_binding: subject must be the authenticated holder
    with pytest.raises(ProofError):
        verify_vp_token({"c1": [svp]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID,
                        require_holder_binding=True)


def test_ldp_vp_wrong_nonce_rejected():
    vp = _issue_and_present("eddsa-jcs-2022")
    with pytest.raises(ProofError):                 # PresentationBindingError <: ProofError
        verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce="attacker", client_id=CLIENT_ID)


def test_ldp_vp_wrong_client_id_rejected():
    vp = _issue_and_present("eddsa-jcs-2022")
    with pytest.raises(ProofError):
        verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce=NONCE,
                        client_id="x509_san_dns:evil.example")


def test_ldp_vp_authentication_purpose_required():
    # A proof signed for assertionMethod (not authentication) must not stand in as a
    # holder presentation proof.
    vp = _issue_and_present("eddsa-jcs-2022", purpose="assertionMethod")
    with pytest.raises(ProofError):
        verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vc_rejects_bare_string():
    # The dc+sd-jwt "must be an SD-JWT" pin, for LDP: a string cannot carry a VP proof.
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"c1": ["not-a-vp"]}, dcql_query=DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)


def test_ldp_vc_rejects_bare_credential_without_presentation():
    # A bare VC (no VerifiablePresentation wrapper) carries no holder binding.
    bare = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": "did:key:z6Mk",
            "credentialSubject": {"id": "did:key:z6Mk"}}
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"c1": [bare]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_requires_embedded_credential():
    # A signed VP that embeds no verifiableCredential does not satisfy a Credential
    # Query — fail closed rather than pass a vacuous presentation.
    suite, key_factory, mc = _suite("eddsa-jcs-2022")
    hk = key_factory.generate(kid="_")
    hdid, hkid = _did_key(hk, mc)
    hk = key_factory(hk._sk, kid=hkid)
    empty_vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid}
    signed = suite.add_proof(empty_vp, signing_key=hk, verification_method=hkid,
                             proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"c1": [signed]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_cascade_rejects_bad_embedded_issuer_proof():
    # The holder validly signs the VP, but the embedded credential's OWN issuer proof
    # is broken. The VP proof passes (the holder wrapped these bytes); the cascade must
    # still reject the credential — proving the embedded-VC verification is not skipped.
    suite, key_factory, mc = _suite("eddsa-jcs-2022")
    ik = key_factory.generate(kid="_")
    idid, ikid = _did_key(ik, mc)
    ik = key_factory(ik._sk, kid=ikid)
    hk = key_factory.generate(kid="_")
    hdid, hkid = _did_key(hk, mc)
    hk = key_factory(hk._sk, kid=hkid)

    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": idid,
          "credentialSubject": {"id": hdid, "alumniOf": "Example University"}}
    secured_vc = suite.add_proof(vc, signing_key=ik, verification_method=ikid,
                                 proof_purpose="assertionMethod")
    # corrupt the issuer signature (still valid multibase, wrong bytes)
    pv = secured_vc["proof"]["proofValue"]
    secured_vc["proof"]["proofValue"] = pv[:-4] + ("1111" if pv[-4:] != "1111" else "2222")

    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
          "verifiableCredential": [secured_vc]}
    signed_vp = suite.add_proof(vp, signing_key=hk, verification_method=hkid,
                                proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    with pytest.raises(SignatureInvalid):
        verify_vp_token({"c1": [signed_vp]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_unsupported_cryptosuite():
    vp = _issue_and_present("eddsa-jcs-2022")
    vp = copy.deepcopy(vp)
    vp["proof"]["cryptosuite"] = "ecdsa-sd-2023"    # a real suite, but not a holder proof
    with pytest.raises(UnsupportedPresentationFormat):
        verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_multiple_proofs_rejected():
    vp = _issue_and_present("eddsa-jcs-2022")
    vp = copy.deepcopy(vp)
    vp["proof"] = [vp["proof"], vp["proof"]]
    with pytest.raises(UnsupportedPresentationFormat):
        verify_vp_token({"c1": [vp]}, dcql_query=DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_embeds_a_vc_jwt_string():
    # A VP whose verifiableCredential is a VC-JWT string still cascade-verifies.
    suite, key_factory, mc = _suite("eddsa-jcs-2022")
    issuer = Ed25519SigningKey.generate(kid="_")
    idid, ikid = _did_key(issuer, bytes([0xED, 0x01]))
    issuer = Ed25519SigningKey(issuer._sk, kid=ikid)
    vc_jwt = VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": idid,
         "credentialSubject": {"id": "did:example:alice"}}, signing_key=issuer)

    hk = Ed25519SigningKey.generate(kid="_")
    hdid, hkid = _did_key(hk, bytes([0xED, 0x01]))
    hk = Ed25519SigningKey(hk._sk, kid=hkid)
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
          "verifiableCredential": [vc_jwt]}
    signed = suite.add_proof(vp, signing_key=hk, verification_method=hkid,
                             proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    result = verify_vp_token({"c1": [signed]}, dcql_query=DCQL, nonce=NONCE,
                             client_id=CLIENT_ID)
    (p,) = result.presentations
    assert p.credentials[0].format == "vc-jwt" and p.credentials[0].issuer == idid
