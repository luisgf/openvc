"""
tests/test_di_jcs.py — the JCS Data Integrity cryptosuites (issue #17).

Three things are pinned here to *authoritative* vectors, per the repo's
"golden fixtures are the drift alarm" invariant:

  1. the **RFC 8785 JCS** canonicalizer (:mod:`openvc.proof._jcs`) — the
     cyberphone / WebPKI reference in→out suite, byte-for-byte (vendored under
     ``fixtures/jcs/rfc8785``), plus the **RFC 8785 Appendix B** number table
     (IEEE-754 hex → serialization — the edge cases hand-rolled JCS gets wrong);
  2. the **eddsa-jcs-2022** worked example from the W3C *Data Integrity EdDSA
     Cryptosuites v1.0* Recommendation (15 May 2025) — the two JCS canonical
     strings, both SHA-256 hashes, the combined ``hashData``, and an end-to-end
     *verify* of the published Ed25519 ``proofValue`` resolved via ``did:key``; and
  3. the eddsa-jcs-2022 / ecdsa-jcs-2019 **suites** end to end — round-trip, tamper
     detection, the verify-pipeline dispatch, and the fail-closed negatives.

The whole point of these suites is a whole-document Data Integrity path with **no
``pyld``**, so the module asserts pyld is never imported.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from openvc import VerificationPolicy, verify_credential
from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey
from openvc.multibase import encode_multibase
from openvc.proof._jcs import JcsError, canonicalize
from openvc.proof.di_jcs import (
    ECDSA_JCS_CRYPTOSUITE,
    EDDSA_JCS_CRYPTOSUITE,
    EcdsaJcsProofSuite,
    EddsaJcsProofSuite,
    _hash_data,
)
from openvc.proof.errors import (
    ProofMalformed,
    SignatureInvalid,
    UnsupportedCryptosuite,
)
from openvc.verify import (
    FORMAT_DI_ECDSA_JCS,
    FORMAT_DI_EDDSA_JCS,
    detect_format,
)

UTC = timezone.utc
RFC8785 = Path(__file__).parent / "fixtures" / "jcs" / "rfc8785"


# --------------------------------------------------------------------------- #
# 1. RFC 8785 canonicalizer — the WebPKI/cyberphone reference suite (byte-exact)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "name", ["values", "weird", "structures", "arrays", "unicode", "french"])
def test_rfc8785_reference_vectors(name):
    """Each reference input canonicalizes to its published output, byte for byte.

    ``weird`` is the make-or-break case: object members sort by **UTF-16 code
    unit**, so U+1F602 (😂, a surrogate pair leading with 0xD83D) sorts *between*
    U+20AC and U+FB33 — a code-point sort would misplace it last. ``values`` pins
    the number reserialization; ``unicode`` pins that JCS does **not** NFC-normalize.
    """
    value = json.loads((RFC8785 / "in" / f"{name}.json").read_bytes())
    expected = (RFC8785 / "out" / f"{name}.json").read_bytes()
    assert canonicalize(value) == expected


# RFC 8785 Appendix B "Number Serialization" (IEEE-754 hex → JSON), plus the
# min-normal / max-subnormal / 0.1 rows from the reference oracle.
_NUMBER_VECTORS = """
0000000000000000 0
8000000000000000 0
0000000000000001 5e-324
8000000000000001 -5e-324
7fefffffffffffff 1.7976931348623157e+308
ffefffffffffffff -1.7976931348623157e+308
4340000000000000 9007199254740992
c340000000000000 -9007199254740992
4430000000000000 295147905179352830000
44b52d02c7e14af5 9.999999999999997e+22
44b52d02c7e14af6 1e+23
44b52d02c7e14af7 1.0000000000000001e+23
444b1ae4d6e2ef4e 999999999999999700000
444b1ae4d6e2ef4f 999999999999999900000
444b1ae4d6e2ef50 1e+21
3eb0c6f7a0b5ed8c 9.999999999999997e-7
3eb0c6f7a0b5ed8d 0.000001
41b3de4355555553 333333333.3333332
41b3de4355555555 333333333.3333333
becbf647612f3696 -0.0000033333333333333333
43143ff3c1cb0959 1424953923781206.2
3ff0000000000000 1
4024000000000000 10
3fe0000000000000 0.5
3fb999999999999a 0.1
0010000000000000 2.2250738585072014e-308
000fffffffffffff 2.225073858507201e-308
"""


@pytest.mark.parametrize("row", [ln.split() for ln in _NUMBER_VECTORS.split("\n") if ln.strip()])
def test_rfc8785_number_serialization(row):
    hx, expected = row
    d = struct.unpack(">d", bytes.fromhex(hx))[0]
    assert canonicalize(d) == expected.encode()


@pytest.mark.parametrize("hx", ["7ff0000000000000", "fff0000000000000", "7fffffffffffffff"],
                         ids=["+inf", "-inf", "nan"])
def test_rfc8785_rejects_non_finite_numbers(hx):
    d = struct.unpack(">d", bytes.fromhex(hx))[0]
    with pytest.raises(JcsError):
        canonicalize(d)


def test_canonicalizer_edge_cases():
    assert canonicalize(True) == b"true"
    assert canonicalize([None, False]) == b"[null,false]"
    assert canonicalize({}) == b"{}"
    assert canonicalize({"a": True}) == b'{"a":true}'        # bool *value* is fine
    assert canonicalize("\x00\t\x7f") == b'"\\u0000\\t\x7f"'  # C0->escape; U+007F raw
    with pytest.raises(JcsError):
        canonicalize({1: "int key"})                         # non-string object key
    with pytest.raises(JcsError):
        canonicalize({"s"})                                  # a set is not JSON


# --------------------------------------------------------------------------- #
# 2. eddsa-jcs-2022 — the W3C vc-di-eddsa Recommendation worked example
# --------------------------------------------------------------------------- #

_W3C_VM = ("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
           "#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
_W3C_CTX = ["https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"]
_W3C_UNSECURED = {
    "@context": _W3C_CTX,
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh",
                          "alumniOf": "The School of Examples"},
}
_W3C_PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": _W3C_VM,
    "proofPurpose": "assertionMethod",
    "@context": _W3C_CTX,
}
_W3C_DOC_HASH = "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
_W3C_CFG_HASH = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db"
_W3C_PROOF_VALUE = ("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3"
                    "GAVFuUfjoJdcnTMuVor51aX")


def test_w3c_eddsa_jcs_hashes():
    """Both SHA-256 halves reproduce the Recommendation's published hex, and the
    combined ``hashData`` is proofConfigHash ‖ documentHash (config first)."""
    assert hashlib.sha256(canonicalize(_W3C_UNSECURED)).hexdigest() == _W3C_DOC_HASH
    assert hashlib.sha256(canonicalize(_W3C_PROOF_OPTIONS)).hexdigest() == _W3C_CFG_HASH
    assert _hash_data(
        _W3C_UNSECURED, _W3C_PROOF_OPTIONS, "sha256").hex() == _W3C_CFG_HASH + _W3C_DOC_HASH


def test_w3c_eddsa_jcs_verifies_published_signature():
    """Verify the Recommendation's published Ed25519 ``proofValue`` end to end,
    resolving the ``did:key`` (no key passed in) — a real cross-implementation pin."""
    proof = {k: v for k, v in _W3C_PROOF_OPTIONS.items() if k != "@context"}
    proof["proofValue"] = _W3C_PROOF_VALUE
    secured = dict(_W3C_UNSECURED, proof=proof)
    result = EddsaJcsProofSuite().verify(secured, now=datetime(2023, 6, 1, tzinfo=UTC))
    assert result.issuer == "https://vc.example/issuers/5678"
    assert result.subject == "did:example:abcdefgh"


def test_w3c_eddsa_jcs_published_signature_is_tamper_evident():
    proof = {k: v for k, v in _W3C_PROOF_OPTIONS.items() if k != "@context"}
    proof["proofValue"] = _W3C_PROOF_VALUE
    tampered = dict(_W3C_UNSECURED, proof=proof)
    tampered["credentialSubject"] = dict(tampered["credentialSubject"], alumniOf="Forged U")
    with pytest.raises(SignatureInvalid):
        EddsaJcsProofSuite().verify(tampered, now=datetime(2023, 6, 1, tzinfo=UTC))


# --------------------------------------------------------------------------- #
# 2b. ecdsa-jcs-2019 P-384 — the W3C vc-di-ecdsa Recommendation §A.6 example
# (P-384 uses SHA-384; the published signature is high-S — the verifier accepts it)
# --------------------------------------------------------------------------- #

_P384_VM = ("did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"
            "#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ")
_P384_UNSECURED = {
    "@context": _W3C_CTX,
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh",
                          "alumniOf": "The School of Examples"},
}
_P384_PROOF_OPTIONS = {
    "type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2019",
    "created": "2023-02-24T23:36:38Z", "verificationMethod": _P384_VM,
    "proofPurpose": "assertionMethod", "@context": _W3C_CTX,
}
_P384_DOC_HASH = ("3e0be671cc1881035d463158c80921973dab3534d4f8dfacf4ff2725a4115eb7"
                  "18e49d66de0e90e7365cd6062abf2259")
_P384_CFG_HASH = ("83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8c7917f7a"
                  "d4792890b257c598baa17f4fbe6d183c")
_P384_PROOF_VALUE = ("zq3EuTeLiGurmB2JR5oL8oWEsT7u2tba4HT1oZbiMYWc5qzsoW2kLYcBcF4HM5vCpJyTkce"
                     "ULKrVXuJQkXeN5seL4uXrFNFRMm53GWy1Yrto8rTWxZi9DkNeWP7yUPs7ELAm")


def test_did_key_resolves_p384():
    from openvc.did.did_key import DidKeyResolver
    doc = DidKeyResolver().resolve(_P384_VM.split("#", 1)[0])
    jwk = doc.verification_methods[0].public_key_jwk
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-384"
    import base64
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    assert len(x) == 48                                  # 48-byte P-384 coordinate
    assert x.hex().startswith("ec3a4e415b4e19a4")        # the vector's X


def test_w3c_ecdsa_jcs_p384_hashes():
    """Both halves hash with SHA-384 (48 bytes each) and reproduce the §A.6 hex."""
    import hashlib
    assert hashlib.sha384(canonicalize(_P384_UNSECURED)).hexdigest() == _P384_DOC_HASH
    assert hashlib.sha384(canonicalize(_P384_PROOF_OPTIONS)).hexdigest() == _P384_CFG_HASH
    assert _hash_data(_P384_UNSECURED, _P384_PROOF_OPTIONS, "sha384").hex() == (
        _P384_CFG_HASH + _P384_DOC_HASH)


def test_w3c_ecdsa_jcs_p384_verifies_via_did_key():
    """The published high-S P-384 signature verifies end to end, resolving the
    did:key (which needs the P-384 multicodec 0x1201)."""
    proof = {k: v for k, v in _P384_PROOF_OPTIONS.items() if k != "@context"}
    proof["proofValue"] = _P384_PROOF_VALUE
    secured = dict(_P384_UNSECURED, proof=proof)
    result = EcdsaJcsProofSuite().verify(secured, now=datetime(2023, 6, 1, tzinfo=UTC))
    assert result.issuer == "https://vc.example/issuers/5678"


def test_w3c_ecdsa_jcs_p384_tamper_evident():
    proof = {k: v for k, v in _P384_PROOF_OPTIONS.items() if k != "@context"}
    proof["proofValue"] = _P384_PROOF_VALUE
    tampered = dict(_P384_UNSECURED, proof=proof)
    tampered["credentialSubject"] = dict(tampered["credentialSubject"], alumniOf="Forged U")
    with pytest.raises(SignatureInvalid):
        EcdsaJcsProofSuite().verify(tampered, now=datetime(2023, 6, 1, tzinfo=UTC))


# --------------------------------------------------------------------------- #
# 3. the suites end to end — round-trip, tamper, negatives, pipeline
# --------------------------------------------------------------------------- #

def _credential(issuer="did:example:issuer"):
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "score": 42, "active": True},
    }


_SUITES = [
    (EDDSA_JCS_CRYPTOSUITE, Ed25519SigningKey, EddsaJcsProofSuite),
    (ECDSA_JCS_CRYPTOSUITE, P256SigningKey, EcdsaJcsProofSuite),
    (ECDSA_JCS_CRYPTOSUITE, P384SigningKey, EcdsaJcsProofSuite),   # P-384 / SHA-384 leg
]
_SUITE_IDS = [f"{c}-{kc.__name__}" for c, kc, _ in _SUITES]


@pytest.mark.parametrize("cryptosuite, KeyCls, Suite", _SUITES, ids=_SUITE_IDS)
def test_roundtrip(cryptosuite, KeyCls, Suite):
    key = KeyCls.generate(kid="did:example:issuer#k")
    secured = Suite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    assert secured["proof"]["cryptosuite"] == cryptosuite
    assert secured["proof"]["type"] == "DataIntegrityProof"
    result = Suite().verify(secured, public_key_jwk=key.public_jwk())
    assert result.issuer == "did:example:issuer"
    assert result.subject == "did:example:alice"


@pytest.mark.parametrize("cryptosuite, KeyCls, Suite", _SUITES, ids=_SUITE_IDS)
@pytest.mark.parametrize("mutate", [
    lambda c: {**c, "credentialSubject": {**c["credentialSubject"], "score": 43}},
    lambda c: {**c, "@context": c["@context"] + ["https://evil.example/ctx"]},
    lambda c: {**c, "issuer": "did:example:attacker"},
], ids=["subject", "context", "issuer"])
def test_tamper_is_rejected(cryptosuite, KeyCls, Suite, mutate):
    key = KeyCls.generate(kid="did:example:issuer#k")
    secured = Suite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    tampered = mutate(secured)
    tampered["proof"] = secured["proof"]                      # keep the original signature
    with pytest.raises(SignatureInvalid):
        Suite().verify(tampered, public_key_jwk=key.public_jwk())


def test_eddsa_jcs_rejects_p256_key():
    with pytest.raises(UnsupportedCryptosuite):
        EddsaJcsProofSuite().add_proof(
            _credential(), signing_key=P256SigningKey.generate(kid="k"),
            verification_method="did:example:issuer#k")


def test_ecdsa_jcs_rejects_ed25519_key():
    with pytest.raises(UnsupportedCryptosuite):
        EcdsaJcsProofSuite().add_proof(
            _credential(), signing_key=Ed25519SigningKey.generate(kid="k"),
            verification_method="did:example:issuer#k")


def test_add_proof_requires_context():
    cred = _credential()
    del cred["@context"]
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().add_proof(
            cred, signing_key=Ed25519SigningKey.generate(kid="k"),
            verification_method="did:example:issuer#k")


def test_add_proof_refuses_double_proof():
    key = Ed25519SigningKey.generate(kid="k")
    secured = EddsaJcsProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().add_proof(
            secured, signing_key=key, verification_method="did:example:issuer#k")


def test_verify_rejects_wrong_cryptosuite():
    """An eddsa-jcs suite must reject an ecdsa-jcs proof (and vice versa)."""
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaJcsProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    with pytest.raises(UnsupportedCryptosuite):
        EddsaJcsProofSuite().verify(secured, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("proof_value", [None, 123, "z!!!not-base58!!!", "not-multibase"],
                         ids=["missing", "non-string", "bad-b58", "no-multibase-prefix"])
def test_verify_rejects_bad_proof_value(proof_value):
    key = Ed25519SigningKey.generate(kid="k")
    secured = EddsaJcsProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    if proof_value is None:
        del secured["proof"]["proofValue"]
    else:
        secured["proof"]["proofValue"] = proof_value
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().verify(secured, public_key_jwk=key.public_jwk())


# --------------------------------------------------------------------------- #
# fail-closed on hostile input — every path raises a typed ProofError, never a
# bare RecursionError / ValueError / KeyError (found by the adversarial review)
# --------------------------------------------------------------------------- #

def _deeply_nested(depth=3000):
    cred = _credential()
    node = cred["credentialSubject"]
    for _ in range(depth):
        node["n"] = {}
        node = node["n"]
    return cred


def test_canonicalize_depth_guard():
    node = value = {}
    for _ in range(3000):
        node["n"] = {}
        node = node["n"]
    with pytest.raises(JcsError):                            # not RecursionError
        canonicalize(value)


def test_deep_nesting_fails_closed_on_add_proof():
    key = Ed25519SigningKey.generate(kid="k")
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().add_proof(
            _deeply_nested(), signing_key=key, verification_method="did:example:issuer#k")


def test_deep_nesting_fails_closed_on_verify():
    key = Ed25519SigningKey.generate(kid="k")
    secured = EddsaJcsProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    secured["credentialSubject"] = _deeply_nested()["credentialSubject"]   # keep the proof
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().verify(secured, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")],
                         ids=["nan", "inf", "-inf"])
def test_non_finite_number_fails_closed(bad):
    """json.loads accepts NaN/Infinity by default, so a wire credential can carry
    one; it must fail closed as ProofMalformed, not a bare JcsError."""
    key = Ed25519SigningKey.generate(kid="k")
    secured = EddsaJcsProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    secured["credentialSubject"] = {"id": "did:example:alice", "amount": bad}
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().verify(secured, public_key_jwk=key.public_jwk())


def test_cross_curve_key_fails_closed():
    """An Ed25519 key resolved under an ecdsa-jcs-2019 proof (and vice versa) must
    fail closed as ProofMalformed — verify_signature would otherwise read a missing
    JWK member ('y' on an OKP key) and raise KeyError."""
    ed = Ed25519SigningKey.generate(kid="k")
    secured = EddsaJcsProofSuite().add_proof(
        _credential(), signing_key=ed, verification_method="did:example:issuer#k")
    secured["proof"]["cryptosuite"] = "ecdsa-jcs-2019"       # OKP key, ecdsa suite
    with pytest.raises(ProofMalformed):
        EcdsaJcsProofSuite().verify(secured, public_key_jwk=ed.public_jwk())

    p256 = P256SigningKey.generate(kid="k")
    secured2 = EcdsaJcsProofSuite().add_proof(
        _credential(), signing_key=p256, verification_method="did:example:issuer#k")
    secured2["proof"]["cryptosuite"] = "eddsa-jcs-2022"      # EC key, eddsa suite
    with pytest.raises(ProofMalformed):
        EddsaJcsProofSuite().verify(secured2, public_key_jwk=p256.public_jwk())


def test_wrong_length_ecdsa_proof_value_fails_closed():
    """A non-64-byte ES256 R‖S is a bad signature (SignatureInvalid), not an
    InvalidKey leaking past the ProofError contract."""
    import os
    key = P256SigningKey.generate(kid="k")
    secured = EcdsaJcsProofSuite().add_proof(
        _credential(), signing_key=key, verification_method="did:example:issuer#k")
    secured["proof"]["proofValue"] = encode_multibase(os.urandom(65))
    with pytest.raises(SignatureInvalid):
        EcdsaJcsProofSuite().verify(secured, public_key_jwk=key.public_jwk())


# -- did:key builder so the full pipeline can resolve the verificationMethod -- #

def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key(key) -> str:
    """Encode a generated key's public JWK as a resolvable did:key identifier."""
    jwk = key.public_jwk()
    if jwk["kty"] == "OKP":                                   # Ed25519, multicodec 0xED
        import base64
        raw = base64.urlsafe_b64decode(jwk["x"] + "==")
        body = _leb128(0xED) + raw
    else:                                                     # P-256, multicodec 0x1200
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        import base64
        pub = _ec.EllipticCurvePublicNumbers(
            int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big"),
            int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big"),
            _ec.SECP256R1()).public_key()
        point = pub.public_bytes(_ser.Encoding.X962, _ser.PublicFormat.CompressedPoint)
        body = _leb128(0x1200) + point
    return "did:key:" + encode_multibase(body)


@pytest.mark.parametrize("cryptosuite, KeyCls, Suite, fmt", [
    (EDDSA_JCS_CRYPTOSUITE, Ed25519SigningKey, EddsaJcsProofSuite, FORMAT_DI_EDDSA_JCS),
    (ECDSA_JCS_CRYPTOSUITE, P256SigningKey, EcdsaJcsProofSuite, FORMAT_DI_ECDSA_JCS),
], ids=["eddsa-jcs-2022", "ecdsa-jcs-2019"])
def test_pipeline_detects_and_verifies(cryptosuite, KeyCls, Suite, fmt):
    key = KeyCls.generate(kid="tmp")             # kid is unused; add_proof takes the VM param
    did = _did_key(key)
    vm = f"{did}#{did[len('did:key:'):]}"
    secured = Suite().add_proof(
        _credential(issuer=did), signing_key=key, verification_method=vm)
    assert detect_format(secured) == fmt
    result = verify_credential(secured, policy=VerificationPolicy(
        require_status=False, now=datetime(2021, 1, 1, tzinfo=UTC)))
    assert result.format == fmt
    assert result.issuer == did


def test_no_pyld_dependency():
    """A full JCS sign+verify must not import pyld — that is its whole reason to
    exist. Run in a fresh interpreter so the check is independent of test ordering
    (other suites in this process legitimately import pyld for the RDF path)."""
    import subprocess
    code = (
        "import sys\n"
        "from openvc.keys import Ed25519SigningKey\n"
        "from openvc.proof.di_jcs import EddsaJcsProofSuite\n"
        "k = Ed25519SigningKey.generate(kid='k')\n"
        "c = {'@context': ['https://www.w3.org/ns/credentials/v2'],\n"
        "     'type': ['VerifiableCredential'], 'issuer': 'did:example:i',\n"
        "     'credentialSubject': {'id': 'did:example:a'}}\n"
        "s = EddsaJcsProofSuite().add_proof(\n"
        "    c, signing_key=k, verification_method='did:example:i#k')\n"
        "EddsaJcsProofSuite().verify(s, public_key_jwk=k.public_jwk())\n"
        "assert 'pyld' not in sys.modules, sorted(m for m in sys.modules if 'pyld' in m)\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("value,expected", [
    (2**53 - 1, b"9007199254740991"),      # within the safe range: exact
    (2**53,     b"9007199254740992"),      # boundary: exact as a double
    (2**53 + 1, b"9007199254740992"),      # beyond: rounds to the nearest double
    (10**21,    b"1e+21"),                  # large integer -> ECMAScript exponent form
    (-(10**21), b"-1e+21"),
])
def test_large_integers_serialize_as_doubles_rfc8785(value, expected):
    # RFC 8785 §3.2.2.3: JSON numbers are IEEE-754 doubles; an integer beyond ±2^53 is not
    # exact and must serialise through the double path, matching every conformant impl
    # (#102/M7). str(value) would diverge and silently break cross-implementation interop.
    assert canonicalize(value) == expected
