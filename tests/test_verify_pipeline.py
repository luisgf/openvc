"""
tests/test_verify_pipeline.py — the generic verification pipeline
(`openvc.verify.verify_credential`, Etapa 7).

Exercises the one-call verifier across every format (VC-JWT, SD-JWT VC, Data
Integrity eddsa-rdfc-2022 + ecdsa-sd-2023, and enveloped), the format detector,
the fail-closed status policy, and the pipeline error surface. A tiny in-test DID
registry resolves the issuer key (so no network / real did:key encoding is needed).
"""
from __future__ import annotations

import pytest

from openvc import VerificationPolicy, verify_credential
from openvc.did.base import DidResolutionError, parse_did_document
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import (
    CredentialRevoked,
    CredentialSuspended,
    build_status_list_credential,
    build_status_list_entry,
    new_bitstring,
    set_status_bit,
)
from openvc.verify import (
    FORMAT_DI_ECDSA_SD,
    FORMAT_DI_EDDSA,
    FORMAT_ENVELOPED,
    FORMAT_SD_JWT_VC,
    FORMAT_VC_JWT,
    IssuerBindingError,
    KeyResolutionFailed,
    StatusUnavailable,
    TypeMismatch,
    UnknownCredentialFormat,
    detect_format,
)

VC2 = "https://www.w3.org/ns/credentials/v2"
ISS = "did:web:issuer.example"
VM = f"{ISS}#key-1"
LIST_URL = "https://issuer.example/status/1"


class _Registry:
    """A minimal DID registry: resolve(did) -> DidDocument, supports(did) -> bool."""

    def __init__(self):
        self._docs: dict[str, object] = {}

    def add(self, did, vm_id, jwk,
            relationships=("assertionMethod", "authentication"), declared_empty=()):
        raw = {
            "id": did,
            "verificationMethod": [
                {"id": vm_id, "type": "JsonWebKey2020", "controller": did,
                 "publicKeyJwk": jwk}
            ],
        }
        for rel in relationships:
            raw[rel] = [vm_id]
        for rel in declared_empty:          # declared but empty -> nothing authorized
            raw[rel] = []
        self._docs[did] = parse_did_document(raw)
        return self

    def supports(self, did):
        return did in self._docs

    def resolve(self, did):
        try:
            return self._docs[did]
        except KeyError:
            raise DidResolutionError(f"unknown DID {did!r}") from None


def _cred(**extra):
    c = {
        "@context": [VC2],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": ISS,
        "credentialSubject": {"id": "did:example:subject"},
    }
    c.update(extra)
    return c


# --------------------------------------------------------------------------- #
# Format detection
# --------------------------------------------------------------------------- #

def test_detect_format():
    assert detect_format("a.b.c") == FORMAT_VC_JWT
    assert detect_format("a.b.c~d~") == FORMAT_SD_JWT_VC
    assert detect_format({"proof": {"cryptosuite": "eddsa-rdfc-2022"}}) == FORMAT_DI_EDDSA
    assert detect_format({"proof": {"cryptosuite": "ecdsa-sd-2023"}}) == FORMAT_DI_ECDSA_SD
    assert detect_format(
        {"type": "EnvelopedVerifiableCredential", "id": "data:x,y"}) == FORMAT_ENVELOPED


def test_detect_format_rejects_unknown():
    with pytest.raises(UnknownCredentialFormat):
        detect_format("not-a-token")
    with pytest.raises(UnknownCredentialFormat):
        detect_format({"foo": "bar"})                       # no proof, not enveloped
    with pytest.raises(UnknownCredentialFormat):
        detect_format({"proof": {"cryptosuite": "made-up-2099"}})
    with pytest.raises(UnknownCredentialFormat):
        detect_format(12345)


# --------------------------------------------------------------------------- #
# VC-JWT
# --------------------------------------------------------------------------- #

def test_vc_jwt_end_to_end():
    sk = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(_cred(), signing_key=sk)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    result = verify_credential(token, resolver=reg)
    assert result.format == FORMAT_VC_JWT
    assert result.issuer == ISS
    assert result.subject == "did:example:subject"
    assert result.claims["iss"] == ISS


def test_expected_types_enforced():
    sk = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(_cred(), signing_key=sk)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    with pytest.raises(TypeMismatch):
        verify_credential(token, resolver=reg,
                          policy=VerificationPolicy(expected_types=["OpenBadgeCredential"]))
    ok = verify_credential(token, resolver=reg,
                           policy=VerificationPolicy(expected_types=["VerifiableCredential"]))
    assert ok.issuer == ISS


def test_key_resolution_failure():
    sk = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(_cred(), signing_key=sk)
    with pytest.raises(KeyResolutionFailed):
        verify_credential(token, resolver=_Registry())      # empty registry


# --------------------------------------------------------------------------- #
# Status policy (fail-closed by default)
# --------------------------------------------------------------------------- #

def _status_vc(revoked_index=None):
    bits = new_bitstring(64)
    if revoked_index is not None:
        set_status_bit(bits, revoked_index, 1)
    return build_status_list_credential(id=LIST_URL, issuer=ISS, bitstring=bits)


def test_status_fail_closed_by_default():
    sk = P256SigningKey.generate(kid=VM)
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=5)
    token = VcJwtProofSuite().sign(_cred(credentialStatus=entry), signing_key=sk)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    # declared status + no resolver -> fail closed
    with pytest.raises(StatusUnavailable):
        verify_credential(token, resolver=reg)
    # explicit opt-out skips the check
    skipped = verify_credential(token, resolver=reg,
                                policy=VerificationPolicy(require_status=False))
    assert skipped.status is None


def test_status_revoked_and_clear():
    sk = P256SigningKey.generate(kid=VM)
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=5)
    token = VcJwtProofSuite().sign(_cred(credentialStatus=entry), signing_key=sk)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    with pytest.raises(CredentialRevoked):
        verify_credential(token, resolver=reg,
                          resolve_status_list=lambda u: _status_vc(revoked_index=5))
    ok = verify_credential(token, resolver=reg,
                           resolve_status_list=lambda u: _status_vc(revoked_index=None))
    assert ok.status is not None and ok.status.revoked is False


# --------------------------------------------------------------------------- #
# SD-JWT VC
# --------------------------------------------------------------------------- #

def test_sd_jwt_end_to_end():
    issuer = Ed25519SigningKey.generate(kid=VM)
    holder = Ed25519SigningKey.generate(kid="did:key:zHolder#0")
    suite = SdJwtVcProofSuite()
    sd = suite.issue(
        {"iss": ISS, "given_name": "Ada", "age": 36}, signing_key=issuer,
        disclosable=["given_name", "age"], holder_jwk=holder.public_jwk(),
        vct="https://credentials.example/id")
    pres = suite.create_presentation(
        sd, holder_key=holder, audience="https://verifier.example", nonce="n-1")
    reg = _Registry().add(ISS, VM, issuer.public_jwk())
    result = verify_credential(
        pres, resolver=reg,
        policy=VerificationPolicy(audience="https://verifier.example", nonce="n-1",
                                  require_key_binding=True,
                                  expected_vct="https://credentials.example/id"))
    assert result.format == FORMAT_SD_JWT_VC
    assert result.issuer == ISS
    assert result.key_bound is True
    assert result.credential["given_name"] == "Ada"


# --------------------------------------------------------------------------- #
# Enveloped (VCDM 2.0)
# --------------------------------------------------------------------------- #

def test_enveloped_vc_jwt_unwrapped_and_verified():
    sk = P256SigningKey.generate(kid=VM)
    token = VcJwtProofSuite().sign(_cred(), signing_key=sk)
    enveloped = {
        "@context": [VC2],
        "type": "EnvelopedVerifiableCredential",
        "id": f"data:application/vc+jwt,{token}",
    }
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    result = verify_credential(enveloped, resolver=reg)
    assert result.format == FORMAT_VC_JWT              # unwrapped, then verified
    assert result.issuer == ISS


# --------------------------------------------------------------------------- #
# Data Integrity (needs pyld)
# --------------------------------------------------------------------------- #

def test_data_integrity_eddsa_end_to_end():
    pytest.importorskip("pyld")
    from openvc.proof.data_integrity import DataIntegrityProofSuite

    sk = Ed25519SigningKey.generate(kid=VM)
    signed = DataIntegrityProofSuite().add_proof(
        _cred(), signing_key=sk, verification_method=VM)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    result = verify_credential(signed, resolver=reg)
    assert result.format == FORMAT_DI_EDDSA
    assert result.issuer == ISS


def test_data_integrity_ecdsa_sd_end_to_end():
    pytest.importorskip("pyld")
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite

    sk = P256SigningKey.generate(kid=VM)
    suite = EcdsaSdProofSuite()
    cred = {
        "@context": [VC2, {"@vocab": "https://vocab.example/"}],
        "type": ["VerifiableCredential"], "issuer": ISS,
        "credentialSubject": {"id": "did:example:subject", "name": "Ada"},
    }
    base = suite.add_base_proof(
        cred, signing_key=sk, verification_method=VM, mandatory_pointers=["/issuer"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    result = verify_credential(derived, resolver=reg)
    assert result.format == FORMAT_DI_ECDSA_SD
    assert result.issuer == ISS
    assert result.credential["credentialSubject"]["name"] == "Ada"


def test_data_integrity_wrong_purpose_rejected():
    pytest.importorskip("pyld")
    from openvc.proof._verify_common import ProofPurposeMismatch
    from openvc.proof.data_integrity import DataIntegrityProofSuite

    sk = Ed25519SigningKey.generate(kid=VM)
    # key registered for authentication only; assertionMethod is declared but empty,
    # so the default-purpose (assertionMethod) proof must be rejected
    signed = DataIntegrityProofSuite().add_proof(
        _cred(), signing_key=sk, verification_method=VM)
    reg = _Registry().add(ISS, VM, sk.public_jwk(),
                          relationships=("authentication",), declared_empty=("assertionMethod",))
    with pytest.raises(ProofPurposeMismatch):
        verify_credential(signed, resolver=reg)


def test_data_integrity_issuer_not_bound_to_key_rejected():
    # a credential names issuer=ISS (the victim) but is signed by the attacker's own
    # key under the attacker's DID; the signature verifies, yet the pipeline rejects
    # it because the verificationMethod is not controlled by the named issuer
    pytest.importorskip("pyld")
    from openvc.proof.data_integrity import DataIntegrityProofSuite

    attacker_did = "did:web:attacker.example"
    attacker_vm = f"{attacker_did}#k"
    sk = Ed25519SigningKey.generate(kid=attacker_vm)
    signed = DataIntegrityProofSuite().add_proof(
        _cred(), signing_key=sk, verification_method=attacker_vm)   # issuer is ISS
    reg = _Registry().add(attacker_did, attacker_vm, sk.public_jwk())
    with pytest.raises(IssuerBindingError):
        verify_credential(signed, resolver=reg)


# --------------------------------------------------------------------------- #
# Status: both codecs on every format, suspension, unrecognised types
# --------------------------------------------------------------------------- #

def _sd_jwt_with_claims(extra_claims, disclosable=()):
    issuer = Ed25519SigningKey.generate(kid=VM)
    holder = Ed25519SigningKey.generate(kid="did:key:zHolder#0")
    suite = SdJwtVcProofSuite()
    sd = suite.issue({"iss": ISS, **extra_claims}, signing_key=issuer,
                     disclosable=disclosable, holder_jwk=holder.public_jwk(),
                     vct="https://credentials.example/id")
    pres = suite.create_presentation(
        sd, holder_key=holder, audience="https://verifier.example", nonce="n-1")
    reg = _Registry().add(ISS, VM, issuer.public_jwk())
    policy = VerificationPolicy(audience="https://verifier.example", nonce="n-1",
                                require_key_binding=True,
                                expected_vct="https://credentials.example/id")
    return pres, reg, policy


def test_sd_jwt_with_w3c_credential_status_is_checked():
    # an SD-JWT carrying a W3C credentialStatus must NOT skip revocation (the codec
    # is not the token `status` claim, but the pipeline checks both)
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=5)
    pres, reg, policy = _sd_jwt_with_claims({"credentialStatus": entry})
    with pytest.raises(StatusUnavailable):                        # fail-closed
        verify_credential(pres, resolver=reg, policy=policy)
    with pytest.raises(CredentialRevoked):
        verify_credential(pres, resolver=reg, policy=policy,
                          resolve_status_list=lambda u: _status_vc(revoked_index=5))


def test_sd_jwt_with_ietf_status_is_checked():
    ref = {"status_list": {"idx": 3, "uri": LIST_URL}}
    pres, reg, policy = _sd_jwt_with_claims({"status": ref})
    with pytest.raises(StatusUnavailable):                        # no token resolver
        verify_credential(pres, resolver=reg, policy=policy)


def test_malformed_ietf_status_fails_closed():
    # a `status` claim that is present but not a recognised reference must fail
    # closed under require_status, symmetric with the W3C unrecognised-type case
    pres, reg, policy = _sd_jwt_with_claims({"status": {"foo": "bar"}})
    with pytest.raises(StatusUnavailable):
        verify_credential(pres, resolver=reg, policy=policy)


def test_suspended_credential_rejected():
    sk = P256SigningKey.generate(kid=VM)
    entry = build_status_list_entry(
        status_list_credential=LIST_URL, index=5, status_purpose="suspension")
    token = VcJwtProofSuite().sign(_cred(credentialStatus=entry), signing_key=sk)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    bits = new_bitstring(64)
    set_status_bit(bits, 5, 1)
    status_vc = build_status_list_credential(
        id=LIST_URL, issuer=ISS, bitstring=bits, status_purpose="suspension")
    with pytest.raises(CredentialSuspended):
        verify_credential(token, resolver=reg, resolve_status_list=lambda u: status_vc)


def test_unrecognized_status_type_fails_closed():
    sk = P256SigningKey.generate(kid=VM)
    weird = {"type": "SomeUnknownStatusMethod2099", "id": "urn:x"}
    token = VcJwtProofSuite().sign(_cred(credentialStatus=weird), signing_key=sk)
    reg = _Registry().add(ISS, VM, sk.public_jwk())
    with pytest.raises(StatusUnavailable):                        # can't check -> fail closed
        verify_credential(token, resolver=reg)
    skipped = verify_credential(token, resolver=reg,
                                policy=VerificationPolicy(require_status=False))
    assert skipped.status is None


def test_enveloped_malformed_payload_rejected():
    enveloped = {
        "type": "EnvelopedVerifiableCredential",
        "id": "data:application/vc+ld+json,not-json{{",         # payload is not JSON
    }
    with pytest.raises(UnknownCredentialFormat):
        verify_credential(enveloped, resolver=_Registry())
