"""
tests/test_ecdsa_sd_typed_verify.py — an ``ecdsa-sd-2023`` derived proof whose ephemeral
key is not a point on P-256, or whose signatures / issuer key do not fit ES256, is refused
inside the ``ProofError`` family (#382, #394).

The holder writes every byte of a derived proof value, and the base signature cannot be
relied on to refuse them: a holder mints a did:key, names it in ``proof.verificationMethod``
and signs ``proofHash ‖ bogusPublicKey ‖ mandatoryHash`` with it (the issuer binding runs
only after the suite returns). Before this change ``verify`` decoded the ephemeral key only
after the base signature verified, and ``p256_multikey_to_jwk`` checked the multicodec
prefix and the 35-byte length but let ``cryptography`` raise a bare ``ValueError`` for an x
off the curve or a point tag other than ``02``/``03``; one such item aborted a whole
``verify_many`` / ``verify_many_async`` batch (threat model I14, I15). Both
``verify_signature`` calls ran bare too, so a wrong-length base or statement signature, or
a ``verificationMethod`` resolving to an Ed25519 / P-384 key, surfaced as
``openvc.keys.InvalidKey`` — an ``OpenvcError``, but not the ``ProofError`` the module
promises — where the whole-document ECDSA suites run ``match_alg`` first (``ProofMalformed``)
and map every ``OpenvcError`` to ``SignatureInvalid``.

Now the ephemeral key is decoded right after the proof value, before canonicalization, key
resolution and any signature, and an off-curve point is ``ProofValueMalformed``; the issuer
key must match ES256 (``ProofMalformed``) and both signature checks map ``InvalidKey`` to
``SignatureInvalid``, as the siblings do. No wrong-accept anywhere: every case failed closed,
untyped.

Which tests discriminate (fail on the previous code) and which only pin behaviour that
already held is stated on each. Every negative asserts the EXACT class. Self-contained
(tests/ is not a package): the did:key builders and the re-signing helper are local.
"""
from __future__ import annotations

import asyncio
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

pytest.importorskip("pyld")              # ecdsa-sd-2023 canonicalizes with pyld

from openvc import verify_credential, verify_many, verify_many_async  # noqa: E402
from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof import ecdsa_sd as m  # noqa: E402
from openvc.proof.contexts import document_loader  # noqa: E402
from openvc.proof.ecdsa_sd import (  # noqa: E402
    EcdsaSdProofSuite,
    ProofValueMalformed,
    decode_derived_proof,
    encode_derived_proof,
    p256_multikey_to_jwk,
    p256_public_multikey,
)
from openvc.proof.errors import ProofError, ProofMalformed, SignatureInvalid  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
P256_PREFIX = bytes((0x80, 0x24))                       # multicodec p256-pub
P384_PREFIX = bytes((0x81, 0x24))                       # multicodec p384-pub
OFF_CURVE_MESSAGE = "ephemeral public key is not a point on P-256"
LENGTH_MESSAGE = "not a 35-byte P-256 multikey"


# --------------------------------------------------------------------------- #
# helpers: did:key issuers, a genuine derived proof, and its hostile rewrites
# --------------------------------------------------------------------------- #

def _did_key_ed25519():
    sk = ed25519.Ed25519PrivateKey.generate()
    mb = encode_multibase(bytes([0xED, 0x01]) + Ed25519SigningKey(sk, "_").public_key_raw())
    return Ed25519SigningKey(sk, f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_p256():
    sk = ec.generate_private_key(ec.SECP256R1())
    mb = encode_multibase(P256_PREFIX + P256SigningKey(sk, "_").public_key_raw())
    return P256SigningKey(sk, f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_p384():
    sk = ec.generate_private_key(ec.SECP384R1())
    mb = encode_multibase(P384_PREFIX + P384SigningKey(sk, "_").public_key_raw())
    return P384SigningKey(sk, f"did:key:{mb}#{mb}"), f"did:key:{mb}"


P256, P256_DID = _did_key_p256()                        # the genuine issuer
ED, ED_DID = _did_key_ed25519()                         # another curve's did:key
P384, P384_DID = _did_key_p384()
SD = EcdsaSdProofSuite()


def _credential(issuer: str = P256_DID) -> dict:
    # the inline @vocab defines the custom subject terms (V2 only aliases a few, e.g. name)
    return {"@context": [V2, {"@vocab": "https://vocab.example/"}],
            "type": ["VerifiableCredential"], "issuer": issuer,
            "validFrom": "2024-01-01T00:00:00Z", "validUntil": "2099-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:alice", "name": "Alice",
                                  "degree": "PhD"}}


def _derived() -> dict:
    base = SD.add_base_proof(_credential(), signing_key=P256, verification_method=P256.kid,
                             mandatory_pointers=["/issuer", "/validUntil"])
    return SD.derive_proof(base, selective_pointers=["/credentialSubject/name"])


def _verify_data(derived: dict) -> tuple[dict, bytes, bytes]:
    """The parsed proof value plus ``proofHash`` and ``mandatoryHash`` as the verifier
    computes them from the disclosed document (what the base signature covers, with the
    ephemeral key between them)."""
    parsed = decode_derived_proof(derived["proof"]["proofValue"])
    loader = document_loader(None)
    unsecured = {k: v for k, v in derived.items() if k != "proof"}
    c14n, _ = m._canonicalize(m._to_nquads(unsecured, loader))
    relabeled = m._relabel(
        c14n, {"_:" + k: "_:" + v for k, v in parsed["label_map"].items()})
    mandatory = set(parsed["mandatory_indexes"])
    mandatory_lines = [ln for i, ln in enumerate(relabeled) if i in mandatory]
    proof_hash = m._proof_config_hash(derived["proof"], derived["@context"], loader)
    return parsed, proof_hash, m._sha256_lines(mandatory_lines)


def _rewritten(derived: dict, *, public_key: bytes | None = None,
               base_signature: bytes | None = None, signatures: list[bytes] | None = None,
               resign: bool = False) -> dict:
    """*derived* with parts of its proof value replaced. With *resign* the base signature
    is recomputed by the issuer's key over the rewritten ephemeral key — what a holder who
    names their own did:key in ``verificationMethod`` can always do."""
    parsed, proof_hash, mandatory_hash = _verify_data(derived)
    key = parsed["public_key"] if public_key is None else public_key
    sig = parsed["base_signature"] if base_signature is None else base_signature
    if resign:
        sig = P256.sign(proof_hash + key + mandatory_hash)
    doc = copy.deepcopy(derived)
    doc["proof"]["proofValue"] = encode_derived_proof(
        base_signature=sig, public_key=key,
        signatures=parsed["signatures"] if signatures is None else signatures,
        label_map=parsed["label_map"], mandatory_indexes=parsed["mandatory_indexes"])
    return doc


def _assert_isolated(results, error_class) -> None:
    """The hostile item carries the typed error and the good one, after it, still verified."""
    assert len(results) == 2
    assert type(results[0].error) is error_class and results[0].result is None
    assert results[1].ok and results[1].error is None and results[1].result is not None


# --------------------------------------------------------------------------- #
# the hostile ephemeral keys
# --------------------------------------------------------------------------- #

_P = 2**256 - 2**224 + 2**192 + 2**96 - 1               # the P-256 field prime
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _x_off_curve() -> int:
    """The smallest x in the field for which x³ − 3x + b is a quadratic non-residue mod p
    (Euler's criterion): a compressed point with that x decodes to nothing on P-256."""
    for x in range(1, 1000):
        rhs = (pow(x, 3, _P) - 3 * x + _B) % _P
        if pow(rhs, (_P - 1) // 2, _P) == _P - 1:
            return x
    raise AssertionError("no quadratic non-residue below 1000")      # pragma: no cover


_X_OFF = _x_off_curve().to_bytes(32, "big")

# 35 bytes with the right prefix: on the previous code each reached from_encoded_point and
# escaped as a bare ValueError ("Invalid EC key." / "Unsupported elliptic curve point type")
OFF_CURVE_KEYS = {
    "x-above-p": P256_PREFIX + b"\x02" + b"\xff" * 32,
    "x-off-curve-tag-02": P256_PREFIX + b"\x02" + _X_OFF,
    "x-off-curve-tag-03": P256_PREFIX + b"\x03" + _X_OFF,
    "tag-05": P256_PREFIX + b"\x05" + b"\x11" * 32,
    "tag-00": P256_PREFIX + b"\x00" + b"\x11" * 32,
    "tag-04-in-33-bytes": P256_PREFIX + b"\x04" + b"\x11" * 32,
}
# a key of the wrong length or codec: already ProofValueMalformed, but only once the base
# signature had verified — now refused before it
WRONG_LENGTH_KEYS = {
    "34-bytes": P256_PREFIX + b"\x02" + b"\x11" * 31,
    "36-bytes": P256_PREFIX + b"\x02" + b"\x11" * 33,
    "p384-codec": P384_PREFIX + P256.public_key_raw(),
}


def _param(keys: dict[str, bytes]):
    return pytest.mark.parametrize("key", list(keys.values()), ids=list(keys))


# --------------------------------------------------------------------------- #
# 0. controls
# --------------------------------------------------------------------------- #

def test_control_the_genuine_derived_proof_verifies():
    derived = _derived()
    result = verify_credential(derived)
    assert result.issuer == P256_DID
    assert result.credential["credentialSubject"]["name"] == "Alice"
    assert "degree" not in result.credential["credentialSubject"]          # withheld
    # the re-signing helper reproduces what the issuer signed: a rewrite that changes
    # nothing but re-signs still verifies, so a refusal below is about the rewritten part
    assert verify_credential(_rewritten(derived, resign=True)).issuer == P256_DID


def test_control_the_genuine_ephemeral_key_round_trips():
    jwk = P256SigningKey.generate(kid="k").public_jwk()
    assert p256_multikey_to_jwk(p256_public_multikey(jwk)) == jwk
    assert _x_off_curve() == int.from_bytes(_X_OFF, "big") >= 1
    with pytest.raises(ValueError):                 # the vector really is off the curve
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x02" + _X_OFF)


# --------------------------------------------------------------------------- #
# 1. an ephemeral key off the curve is ProofValueMalformed (#382) — discriminating
# --------------------------------------------------------------------------- #

@_param(OFF_CURVE_KEYS)
def test_p256_multikey_to_jwk_refuses_an_off_curve_point_typed(key):
    with pytest.raises(ProofValueMalformed) as exc:
        p256_multikey_to_jwk(key)
    assert type(exc.value) is ProofValueMalformed
    assert str(exc.value) == OFF_CURVE_MESSAGE                # fixed text, no key bytes
    assert isinstance(exc.value.__cause__, ValueError)        # the refusal it wraps


@_param(OFF_CURVE_KEYS)
def test_an_off_curve_ephemeral_key_is_proof_value_malformed(key):
    # the base signature is re-signed over the bogus key: the holder-as-issuer path
    hostile = _rewritten(_derived(), public_key=key, resign=True)
    with pytest.raises(ProofValueMalformed) as exc:
        verify_credential(hostile)
    assert type(exc.value) is ProofValueMalformed
    assert str(exc.value) == OFF_CURVE_MESSAGE
    assert key.hex() not in str(exc.value)
    with pytest.raises(ProofValueMalformed) as sexc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(sexc.value) is ProofValueMalformed


@_param(OFF_CURVE_KEYS)
def test_verify_many_isolates_an_off_curve_ephemeral_key(key):
    hostile = _rewritten(_derived(), public_key=key, resign=True)
    _assert_isolated(verify_many([hostile, _derived()]), ProofValueMalformed)
    _assert_isolated(asyncio.run(verify_many_async([hostile, _derived()])),
                     ProofValueMalformed)


@_param(WRONG_LENGTH_KEYS)
def test_a_wrong_length_ephemeral_key_stays_proof_value_malformed(key):
    # pin: the length / codec check predates this change (it ran after the base signature)
    hostile = _rewritten(_derived(), public_key=key, resign=True)
    with pytest.raises(ProofValueMalformed) as exc:
        verify_credential(hostile)
    assert type(exc.value) is ProofValueMalformed
    assert str(exc.value) == LENGTH_MESSAGE
    _assert_isolated(verify_many([hostile, _derived()]), ProofValueMalformed)


# --------------------------------------------------------------------------- #
# 2. the ephemeral key is decoded before any signature, before key resolution and before
#    canonicalization — discriminating (the previous code reached a later check first)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("key", [OFF_CURVE_KEYS["x-off-curve-tag-02"],
                                 WRONG_LENGTH_KEYS["34-bytes"]],
                         ids=["off-curve", "34-bytes"])
def test_the_ephemeral_key_is_refused_before_the_base_signature_runs(key):
    # the GENUINE base signature is kept, so it no longer covers the rewritten key: the
    # previous order reported that as SignatureInvalid; the key bytes are refused first now
    hostile = _rewritten(_derived(), public_key=key)
    with pytest.raises(ProofValueMalformed) as exc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(exc.value) is ProofValueMalformed


def test_the_ephemeral_key_is_refused_before_the_issuer_key_is_resolved():
    # an unresolvable verificationMethod used to be the first refusal (KeyResolutionError)
    hostile = _rewritten(_derived(), public_key=OFF_CURVE_KEYS["x-off-curve-tag-02"])
    hostile["proof"]["verificationMethod"] = "did:example:nobody#k"
    hostile["issuer"] = "did:example:nobody"
    with pytest.raises(ProofValueMalformed) as exc:
        SD.verify(hostile)
    assert type(exc.value) is ProofValueMalformed
    with pytest.raises(ProofValueMalformed) as pexc:
        verify_credential(hostile)
    assert type(pexc.value) is ProofValueMalformed


def test_the_ephemeral_key_is_refused_before_the_document_is_canonicalized():
    # a context pyld cannot load used to be the first refusal (ProofMalformed)
    hostile = _rewritten(_derived(), public_key=OFF_CURVE_KEYS["x-off-curve-tag-02"])
    hostile["@context"] = [V2, "https://example.org/unknown-context"]
    with pytest.raises(ProofValueMalformed) as exc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(exc.value) is ProofValueMalformed


# --------------------------------------------------------------------------- #
# 3. InvalidKey never leaves the suite (#394) — discriminating
# --------------------------------------------------------------------------- #

BAD_LENGTHS = [0, 10, 63, 65, 96]            # 96 is an ES384 R‖S, never an ES256 one


@pytest.mark.parametrize("length", BAD_LENGTHS)
def test_a_wrong_length_base_signature_is_signature_invalid(length):
    hostile = _rewritten(_derived(), base_signature=b"\x00" * length)
    with pytest.raises(SignatureInvalid) as exc:
        verify_credential(hostile)
    assert type(exc.value) is SignatureInvalid
    assert str(exc.value).startswith("base signature does not verify")
    with pytest.raises(SignatureInvalid) as sexc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(sexc.value) is SignatureInvalid
    _assert_isolated(verify_many([hostile, _derived()]), SignatureInvalid)


@pytest.mark.parametrize("length", BAD_LENGTHS)
def test_a_wrong_length_statement_signature_is_signature_invalid(length):
    derived = _derived()
    count = len(decode_derived_proof(derived["proof"]["proofValue"])["signatures"])
    assert count >= 1                                                       # control
    hostile = _rewritten(derived, signatures=[b"\x00" * length] * count)
    with pytest.raises(SignatureInvalid, match="disclosed statement") as exc:
        verify_credential(hostile)
    assert type(exc.value) is SignatureInvalid
    with pytest.raises(SignatureInvalid, match="disclosed statement") as sexc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(sexc.value) is SignatureInvalid
    _assert_isolated(verify_many([hostile, _derived()]), SignatureInvalid)


@pytest.mark.parametrize("other,other_did,crv", [(ED, ED_DID, "Ed25519"),
                                                 (P384, P384_DID, "P-384")],
                         ids=["Ed25519", "P-384"])
def test_a_verification_method_of_another_curve_is_proof_malformed(other, other_did, crv):
    # the did:key resolves fine; it is the key's (kty, crv) that ecdsa-sd-2023 cannot use
    hostile = copy.deepcopy(_derived())
    hostile["proof"]["verificationMethod"] = other.kid
    hostile["issuer"] = other_did
    with pytest.raises(ProofMalformed) as exc:
        verify_credential(hostile)
    assert type(exc.value) is ProofMalformed
    assert "ecdsa-sd-2023 does not accept" in str(exc.value) and crv in str(exc.value)
    with pytest.raises(ProofMalformed) as sexc:
        SD.verify(hostile)
    assert type(sexc.value) is ProofMalformed
    _assert_isolated(verify_many([hostile, _derived()]), ProofMalformed)
    _assert_isolated(asyncio.run(verify_many_async([hostile, _derived()])), ProofMalformed)


@pytest.mark.parametrize("jwk", [ED.public_jwk(), P384.public_jwk(),
                                 {"kty": "OKP", "crv": "P-256", "x": "AAAA"},
                                 {"kty": "EC", "x": "AAAA", "y": "AAAA"}],
                         ids=["OKP", "P-384", "OKP-under-P-256", "no-crv"])
def test_a_pinned_key_of_another_type_is_proof_malformed(jwk):
    with pytest.raises(ProofMalformed) as exc:
        SD.verify(_derived(), public_key_jwk=jwk)
    assert type(exc.value) is ProofMalformed
    assert "ecdsa-sd-2023 does not accept" in str(exc.value)


@pytest.mark.parametrize("jwk", [
    {"kty": "EC", "crv": "P-256", "x": P256.public_jwk()["x"]},                 # no y
    {"kty": "EC", "crv": "P-256", "x": "!!", "y": "!!"},                        # not b64url
    {"kty": "EC", "crv": "P-256", "x": 0, "y": 0},                              # not str
    dict(P384.public_jwk(), crv="P-256"),                           # P-384 coords, P-256 crv
], ids=["no-y", "not-b64url", "not-str", "p384-coords"])
def test_a_pinned_p256_key_that_cannot_load_is_signature_invalid(jwk):
    # the (kty, crv) fits ES256, so the key reaches verify_signature, whose InvalidKey is
    # mapped as the sibling suites map it
    with pytest.raises(SignatureInvalid) as exc:
        SD.verify(_derived(), public_key_jwk=jwk)
    assert type(exc.value) is SignatureInvalid
    assert str(exc.value).startswith("base signature does not verify: ")


# --------------------------------------------------------------------------- #
# 4. pins: what the change must not move
# --------------------------------------------------------------------------- #

def test_pin_a_wrong_p256_issuer_key_is_still_signature_invalid_with_the_same_message():
    with pytest.raises(SignatureInvalid) as exc:
        SD.verify(_derived(), public_key_jwk=P256SigningKey.generate(kid="k").public_jwk())
    assert type(exc.value) is SignatureInvalid
    assert str(exc.value) == "base signature does not verify"


def test_pin_an_edited_disclosed_statement_is_still_signature_invalid():
    hostile = _derived()
    hostile["credentialSubject"]["name"] = "Mallory"
    with pytest.raises(SignatureInvalid, match="disclosed statement") as exc:
        verify_credential(hostile)
    assert type(exc.value) is SignatureInvalid


def test_pin_every_refusal_above_is_a_proof_error():
    derived = _derived()
    cases = [
        lambda: SD.verify(_rewritten(derived, public_key=OFF_CURVE_KEYS["tag-05"],
                                     resign=True), public_key_jwk=P256.public_jwk()),
        lambda: SD.verify(_rewritten(derived, base_signature=b"\x00" * 10),
                          public_key_jwk=P256.public_jwk()),
        lambda: SD.verify(derived, public_key_jwk=ED.public_jwk()),
        lambda: SD.verify(derived, public_key_jwk={"kty": "EC", "crv": "P-256", "x": "!!",
                                                   "y": "!!"}),
    ]
    for case in cases:
        with pytest.raises(ProofError):
            case()
