"""
tests/test_di_ecdsa_rdfc.py — the ecdsa-rdfc-2019 Data Integrity cryptosuite (issue #48).

The ECDSA analogue of ``eddsa-rdfc-2022``: whole-document ECDSA over RDF N-Quads,
**P-256/SHA-256** or **P-384/SHA-384**, selected by the key's curve. Needs pyld (the
``[data-integrity]`` extra); skips without it.

Two things are pinned to the authoritative **W3C vc-di-ecdsa** ``TestVectors/
ecdsa-rdfc-2019-p256`` and ``…-p384`` golden vectors (vendored under
``fixtures/vc_di_ecdsa``), per the repo's "golden fixtures are the drift alarm"
invariant. ECDSA signing is randomised, so — unlike the byte-for-byte eddsa-rdfc-2022
pin — interop is shown the way the ecdsa-sd suite shows it:

  1. the intermediate ``hashData`` (both SHA-256/384 halves and the config-first
     combined hash) reproduces the published hex — proving the RDF canonicalization
     and digest choice are byte-exact; and
  2. the published ``proofValue`` *verifies* end to end, resolving its ``did:key``
     (P-256 multicodec 0x1200 / P-384 0x1201) with no key passed in.

The rest are round-trip, tamper, multi-curve, pipeline-dispatch and fail-closed
negatives on self-contained credentials (bundled VC 2.0 context, no network).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("pyld")

from openvc import VerificationPolicy, verify_credential  # noqa: E402
from openvc.keys import (  # noqa: E402
    Ed25519SigningKey,
    P256SigningKey,
    P384SigningKey,
)
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof.contexts import DocumentLoaderError, document_loader  # noqa: E402
from openvc.proof.data_integrity import _canonize  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import (  # noqa: E402
    ECDSA_RDFC_CRYPTOSUITE,
    EcdsaRdfcProofSuite,
    _hash_data,
)
from openvc.proof.errors import (  # noqa: E402
    CredentialExpired,
    CredentialNotYetValid,
    ProofMalformed,
    ProofPurposeMismatch,
    SignatureInvalid,
    UnsupportedCryptosuite,
)
from openvc.verify import FORMAT_DI_ECDSA_RDFC, detect_format  # noqa: E402

UTC = timezone.utc
VC2 = "https://www.w3.org/ns/credentials/v2"
FX = Path(__file__).parent / "fixtures" / "vc_di_ecdsa"
EDDSA_FX = Path(__file__).parent / "fixtures" / "vc_di_eddsa"

# curve tag -> (hashData digest name, signing-key class, JOSE alg)
_CURVES = [("P256", "sha256", P256SigningKey, "ES256"),
           ("P384", "sha384", P384SigningKey, "ES384")]
_CURVE_IDS = ["P-256", "P-384"]


@pytest.fixture(scope="module")
def examples_ctx():
    """The credentials/examples/v2 term set the W3C vectors reference, injected so RDF
    canonicalization stays offline (the loader refuses to fetch anything else)."""
    return {"https://www.w3.org/ns/credentials/examples/v2":
            json.loads((EDDSA_FX / "credentials-examples-v2.json").read_text())}


def _load_vector(curve: str):
    d = FX / f"rdfc-2019-{curve.lower()}"
    return {
        "signed": json.loads((d / f"signedECDSA{curve}.json").read_text()),
        "proof_config": json.loads((d / f"proofConfigECDSA{curve}.json").read_text()),
        "doc_hash": (d / f"docHashECDSA{curve}.txt").read_text().strip(),
        "proof_hash": (d / f"proofHashECDSA{curve}.txt").read_text().strip(),
        "combined": (d / f"combinedHashECDSA{curve}.txt").read_text().strip(),
    }


# --------------------------------------------------------------------------- #
# 1. Official W3C vc-di-ecdsa vectors — conformance (P-256 and P-384)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_w3c_vector_hashes(curve, hash_name, KeyCls, alg, examples_ctx):
    """Both hashData halves reproduce the published hex, and the combined hash is
    proofConfigHash ‖ documentHash (config first), digested with the curve's SHA."""
    v = _load_vector(curve)
    loader = document_loader(examples_ctx)
    digest = getattr(hashlib, hash_name)
    unsecured = {k: val for k, val in v["signed"].items() if k != "proof"}
    assert digest(_canonize(unsecured, loader)).hexdigest() == v["doc_hash"]
    assert digest(_canonize(v["proof_config"], loader)).hexdigest() == v["proof_hash"]
    assert _hash_data(unsecured, v["proof_config"], loader, hash_name).hex() == v["combined"]
    assert v["combined"] == v["proof_hash"] + v["doc_hash"]      # config-first order


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_w3c_vector_verifies_via_did_key(curve, hash_name, KeyCls, alg, examples_ctx):
    """The published ECDSA proofValue verifies end to end, resolving its did:key with
    no key passed in — a real cross-implementation pin of the whole verify path."""
    v = _load_vector(curve)
    result = EcdsaRdfcProofSuite().verify(
        v["signed"], extra_contexts=examples_ctx, now=datetime(2023, 6, 1, tzinfo=UTC))
    assert result.issuer == "https://vc.example/issuers/5678"
    assert result.subject == "did:example:abcdefgh"
    assert result.proof["cryptosuite"] == ECDSA_RDFC_CRYPTOSUITE


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_w3c_vector_tamper_evident(curve, hash_name, KeyCls, alg, examples_ctx):
    v = _load_vector(curve)
    tampered = copy.deepcopy(v["signed"])
    tampered["credentialSubject"]["alumniOf"] = "Forged University"
    with pytest.raises(SignatureInvalid):
        EcdsaRdfcProofSuite().verify(
            tampered, extra_contexts=examples_ctx, now=datetime(2023, 6, 1, tzinfo=UTC))


def test_w3c_p256_did_key_is_p256_multicodec(examples_ctx):
    """The P-256 vector's verificationMethod is a zDna… did:key (multicodec 0x1200);
    the P-384 one a z82L… (0x1201) — the two legs really resolve to distinct curves."""
    from openvc.did.did_key import DidKeyResolver
    for curve, exp_crv in [("P256", "P-256"), ("P384", "P-384")]:
        vm = _load_vector(curve)["signed"]["proof"]["verificationMethod"]
        doc = DidKeyResolver().resolve(vm.split("#", 1)[0])
        assert doc.verification_methods[0].public_key_jwk["crv"] == exp_crv


# --------------------------------------------------------------------------- #
# 2. Round-trip / tamper on a self-contained credential (bundled VC2 context only)
# --------------------------------------------------------------------------- #

# Only VC-defined terms: RDF canonicalization (URDNA2015) drops JSON members that the
# @context does not define, so — unlike the byte-signing JCS suite — a custom property
# would silently fall outside the signed graph. Every field here is a defined term, so
# tampering any of them changes the canonical N-Quads and breaks the proof.
def _credential(issuer="did:example:issuer"):
    return {
        "@context": [VC2],
        "id": "urn:uuid:1111",
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice"},
    }


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_sign_then_verify_roundtrip(curve, hash_name, KeyCls, alg):
    key = KeyCls.generate(kid="did:example:issuer#k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    assert secured["proof"]["cryptosuite"] == ECDSA_RDFC_CRYPTOSUITE
    assert secured["proof"]["type"] == "DataIntegrityProof"
    assert secured["proof"]["proofValue"].startswith("z")
    result = EcdsaRdfcProofSuite().verify(secured, public_key_jwk=key.public_jwk())
    assert result.issuer == "did:example:issuer"
    assert result.subject == "did:example:alice"


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
@pytest.mark.parametrize("mutate", [
    lambda c: {**c, "credentialSubject": {"id": "did:example:mallory"}},
    lambda c: {**c, "issuer": "did:example:attacker"},
    lambda c: {**c, "validFrom": "1999-01-01T00:00:00Z"},
], ids=["subject", "issuer", "validFrom"])
def test_tamper_is_rejected(curve, hash_name, KeyCls, alg, mutate):
    key = KeyCls.generate(kid="did:example:issuer#k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    tampered = mutate(secured)
    tampered["proof"] = secured["proof"]                          # keep the signature
    with pytest.raises(SignatureInvalid):
        EcdsaRdfcProofSuite().verify(tampered, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_input_not_mutated(curve, hash_name, KeyCls, alg):
    key = KeyCls.generate(kid="k")
    cred = _credential()
    before = copy.deepcopy(cred)
    EcdsaRdfcProofSuite().add_proof(
        cred, signing_key=key, verification_method="did:example:issuer#k")
    assert cred == before


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_presentation_challenge_domain_roundtrip(curve, hash_name, KeyCls, alg):
    key = KeyCls.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k",
        proof_purpose="authentication", challenge="n-0S6_WzA2Mj", domain="https://verifier.example")
    result = EcdsaRdfcProofSuite().verify(
        secured, public_key_jwk=key.public_jwk(), expected_proof_purpose="authentication",
        expected_challenge="n-0S6_WzA2Mj", expected_domain="https://verifier.example")
    assert result.proof["challenge"] == "n-0S6_WzA2Mj"


# --------------------------------------------------------------------------- #
# 3. Fail-closed negatives — every path raises a typed ProofError
# --------------------------------------------------------------------------- #

def test_non_ecdsa_key_rejected_on_add_proof():
    with pytest.raises(UnsupportedCryptosuite):
        EcdsaRdfcProofSuite().add_proof(
            _credential(), signing_key=Ed25519SigningKey.generate(kid="k"),
            verification_method="did:example:issuer#k")


def test_add_proof_requires_context():
    cred = _credential()
    del cred["@context"]
    with pytest.raises(ProofMalformed):
        EcdsaRdfcProofSuite().add_proof(
            cred, signing_key=P256SigningKey.generate(kid="k"),
            verification_method="did:example:issuer#k")


def test_add_proof_refuses_double_proof():
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    with pytest.raises(ProofMalformed):
        EcdsaRdfcProofSuite().add_proof(
            secured, signing_key=key, verification_method="did:example:issuer#k")


def test_unbundled_context_fails_closed():
    cred = _credential()
    cred["@context"] = [VC2, "https://evil.example/ctx"]         # not bundled/injected
    with pytest.raises(DocumentLoaderError):
        EcdsaRdfcProofSuite().add_proof(
            cred, signing_key=P256SigningKey.generate(kid="k"),
            verification_method="did:example:issuer#k")


def test_unknown_cryptosuite_rejected():
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    secured["proof"]["cryptosuite"] = "ecdsa-sd-2023"
    with pytest.raises(UnsupportedCryptosuite):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("proof_value", [None, 123, "z!!!not-base58!!!", "not-multibase"],
                         ids=["missing", "non-string", "bad-b58", "no-multibase-prefix"])
def test_verify_rejects_bad_proof_value(proof_value):
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    if proof_value is None:
        del secured["proof"]["proofValue"]
    else:
        secured["proof"]["proofValue"] = proof_value
    with pytest.raises(ProofMalformed):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=key.public_jwk())


def test_cross_type_key_fails_closed():
    """An Ed25519 (OKP) key handed to this ecdsa suite must fail closed as
    ProofMalformed — _match_alg rejects it before verify_signature would read a
    missing JWK member ('y' on an OKP key) and raise KeyError."""
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    ed_jwk = Ed25519SigningKey.generate(kid="k").public_jwk()
    with pytest.raises(ProofMalformed):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=ed_jwk)


def test_wrong_curve_key_fails_signature():
    """Verifying a P-256 proof with a P-384 key: _match_alg picks ES384 from the key's
    curve, then the 64-byte R‖S is the wrong length for ES384 → SignatureInvalid."""
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    p384_jwk = P384SigningKey.generate(kid="k").public_jwk()
    with pytest.raises(SignatureInvalid):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=p384_jwk)


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_wrong_length_proof_value_fails_closed(curve, hash_name, KeyCls, alg):
    """A wrong-length R‖S is a bad signature (SignatureInvalid), not an InvalidKey
    leaking past the ProofError contract."""
    key = KeyCls.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    secured["proof"]["proofValue"] = encode_multibase(os.urandom(65))
    with pytest.raises(SignatureInvalid):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=key.public_jwk())


# --------------------------------------------------------------------------- #
# 4. Temporal / purpose policy is wired through the shared _verify_common layer
# --------------------------------------------------------------------------- #

def test_expired_credential_does_not_verify():
    cred = _credential()
    cred["validUntil"] = "2025-01-01T00:00:00Z"                  # past (today is 2026)
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(cred, signing_key=key, verification_method="k")
    with pytest.raises(CredentialExpired):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=key.public_jwk())


def test_not_yet_valid_credential_does_not_verify():
    cred = _credential()
    cred["validFrom"] = "2099-01-01T00:00:00Z"                  # future
    key = P384SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(cred, signing_key=key, verification_method="k")
    with pytest.raises(CredentialNotYetValid):
        EcdsaRdfcProofSuite().verify(secured, public_key_jwk=key.public_jwk())


def test_proof_purpose_mismatch_rejected():
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="k", proof_purpose="assertionMethod")
    with pytest.raises(ProofPurposeMismatch):
        EcdsaRdfcProofSuite().verify(
            secured, public_key_jwk=key.public_jwk(), expected_proof_purpose="authentication")


# --------------------------------------------------------------------------- #
# 5. Full verify pipeline — detect_format + verify_credential resolving did:key
# --------------------------------------------------------------------------- #

def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key(key) -> str:
    """A resolvable did:key for a P-256 (multicodec 0x1200) / P-384 (0x1201) key,
    built from its compressed SEC1 point."""
    codec = 0x1200 if key.alg == "ES256" else 0x1201
    return "did:key:" + encode_multibase(_leb128(codec) + key.public_key_raw(compressed=True))


@pytest.mark.parametrize("curve, hash_name, KeyCls, alg", _CURVES, ids=_CURVE_IDS)
def test_pipeline_detects_and_verifies(curve, hash_name, KeyCls, alg):
    key = KeyCls.generate(kid="tmp")
    did = _did_key(key)
    vm = f"{did}#{did[len('did:key:'):]}"
    secured = EcdsaRdfcProofSuite().add_proof(
        _credential(issuer=did), signing_key=key, verification_method=vm)
    assert detect_format(secured) == FORMAT_DI_ECDSA_RDFC
    result = verify_credential(secured, policy=VerificationPolicy(
        require_status=False, now=datetime(2021, 1, 1, tzinfo=UTC)))
    assert result.format == FORMAT_DI_ECDSA_RDFC
    assert result.issuer == did


def test_did_key_builder_matches_vector_prefix():
    """Sanity-check the test's own did:key encoder against the published vectors: a
    freshly built P-256 did:key starts zDna…, a P-384 one z82L… (as the W3C vectors do)."""
    assert _did_key(P256SigningKey.generate(kid="k")).startswith("did:key:zDn")
    assert _did_key(P384SigningKey.generate(kid="k")).startswith("did:key:z82")
