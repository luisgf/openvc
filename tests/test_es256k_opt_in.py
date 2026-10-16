"""
tests/test_es256k_opt_in.py — ES256K (RFC 8812) as an explicit VC-JWT opt-in (#323).

``VcJwtProofSuite(allow_es256k=True)`` verifies ``alg: ES256K`` (ECDSA over secp256k1
with SHA-256); the default allow-list ``{ES256, ES384, EdDSA, Ed25519}`` never changes.
EBSI Core API v1 signs its RootTAO accreditations with it (ADR-0009, open question 3).
Verification only: openvc never signs ES256K. The default suite, every other lane and the
recorded RootTAO golden are in ``test_es256k_default_refused.py`` and
``test_es256k_ebsi_chain.py``; this file is the opted-in suite itself.

Order: near-miss algorithm names; key and curve confusion (the pin is openvc's own, and
runs before PyJWT loads anything); hostile JWKs; the signature shapes and the claim
handling, each as a parity table against ES256 (ES256K is ES256 on another curve and
must share its handling); the gates that run after the allow-list; signing stays closed;
the independence of the two opt-ins; the positives (low-s and high-s); fuzzing.

Every token is built by hand with ``cryptography`` (never through a ``SigningKey``: openvc
has no secp256k1 one). Negatives first, each asserting the EXACT class so a test cannot pass
on an earlier failure. ``tests/`` is not a package: the helpers are copied, not imported.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from openvc.did.base import DidDocument, VerificationMethod
from openvc.errors import OpenvcError
from openvc.proof import vc_jwt
from openvc.proof.errors import (
    ClaimsInvalid,
    MalformedToken,
    ProofError,
    SignatureInvalid,
    UnsupportedAlgorithm,
)
from openvc.proof.vc_jwt import VcJwtProofSuite

# --------------------------------------------------------------------------- #
# Helpers (copied: tests/ is not a package)
# --------------------------------------------------------------------------- #

N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141     # secp256k1 order
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551   # P-256 order
FIELD_P = 2**256 - 2**32 - 977                                                # secp256k1 field
ISSUER = "did:example:issuer"
KID = "did:example:issuer#key-1"
NOW = int(time.time())


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Signer:
    """A hand-rolled EC signer: raw R||S, never DER, no SigningKey involved."""

    def __init__(self, alg: str, key: ec.EllipticCurvePrivateKey, crv: str, order: int,
                 hash_alg: hashes.HashAlgorithm, width: int) -> None:
        self.alg, self.key, self.crv, self.n, self.hash, self.width = (
            alg, key, crv, order, hash_alg, width)
        nums = key.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": crv,
                    "x": b64(nums.x.to_bytes(width, "big")),
                    "y": b64(nums.y.to_bytes(width, "big"))}

    def rs(self, signing_input: bytes) -> tuple[int, int]:
        return decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(self.hash)))

    def sign(self, signing_input: bytes) -> bytes:
        r, s = self.rs(signing_input)
        return r.to_bytes(self.width, "big") + s.to_bytes(self.width, "big")


def k1(d: int | None = None) -> Signer:
    key = (ec.generate_private_key(ec.SECP256K1()) if d is None
           else ec.derive_private_key(d, ec.SECP256K1()))
    return Signer("ES256K", key, "secp256k1", N_K1, hashes.SHA256(), 32)


def p256() -> Signer:
    return Signer("ES256", ec.generate_private_key(ec.SECP256R1()), "P-256", N_P256,
                  hashes.SHA256(), 32)


def p384() -> Signer:
    return Signer("ES384", ec.generate_private_key(ec.SECP384R1()), "P-384", 0,
                  hashes.SHA384(), 48)


K1 = k1()
OTHER_K1 = k1()
P256 = p256()
P384 = p384()


def credential(**over: Any) -> dict[str, Any]:
    vc = {"@context": ["https://www.w3.org/2018/credentials/v1"],
          "type": ["VerifiableCredential", "ExampleCredential"], "issuer": ISSUER,
          "credentialSubject": {"id": "did:example:subject", "name": "Ada"}}
    vc.update(over)
    return vc


def claims(**over: Any) -> dict[str, Any]:
    body = {"iss": ISSUER, "sub": "did:example:subject", "nbf": NOW - 5, "iat": NOW - 5,
            "exp": NOW + 3600, "jti": "urn:uuid:1", "vc": credential(id="urn:uuid:1")}
    body.update(over)
    return body


def token(signer: Signer, *, header: dict[str, Any] | None = None,
          payload: dict[str, Any] | None = None, payload_json: str | None = None,
          sig: Callable[[bytes, Signer], str] | None = None) -> str:
    """A compact JWS signed by *signer*. *sig* replaces the signature segment, given the
    signing input and the signer (so a mutation can use the real r and s)."""
    head: dict[str, Any] = {"alg": signer.alg, "typ": "JWT", "kid": KID}
    head.update(header or {})
    body = payload_json if payload_json is not None else json.dumps(payload or claims())
    h = b64(json.dumps(head).encode())
    p = b64(body.encode())
    signing_input = f"{h}.{p}".encode("ascii")
    segment = sig(signing_input, signer) if sig is not None else b64(signer.sign(signing_input))
    return f"{h}.{p}.{segment}"


def verify(signer: Signer, tok: str, jwk: Any = ..., *,
           suite: VcJwtProofSuite | None = None, **kwargs: Any) -> Any:
    """Verify *tok* with an opted-in suite against *jwk* (the signer's own by default;
    ``...`` is the sentinel, because ``None`` is a hostile value some tests pass)."""
    return (suite or VcJwtProofSuite(allow_es256k=True)).verify(
        tok, public_key_jwk=signer.jwk if jwk is ... else jwk, **kwargs)


def outcome(call: Callable[[], Any]) -> str:
    """The class name a call ends in, or ``verified``: for the parity tables."""
    try:
        call()
    except OpenvcError as exc:
        return type(exc).__name__
    return "verified"


@pytest.fixture()
def no_pyjwt():
    """PyJWT must not be reached: the refusals below are openvc's, before any crypto."""
    mp = pytest.MonkeyPatch()

    def reached(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("PyJWT decode was reached")

    mp.setattr(vc_jwt._JWT, "decode", reached)
    yield
    mp.undo()


def _key_with_zero_byte(member: str) -> Signer:
    """A real secp256k1 key whose x (or y) coordinate starts with a zero octet, found by
    search (about one key in 256): the shape a JWK writer that strips leading zeros breaks."""
    d = 1
    while True:
        signer = k1(d)
        raw = base64.urlsafe_b64decode(signer.jwk[member] + "=")
        if raw[0] == 0:
            return signer
        d += 1
        assert d < 20_000, f"no secp256k1 key with a leading-zero {member} found"


ZERO_X = _key_with_zero_byte("x")
ZERO_Y = _key_with_zero_byte("y")


def _non_canonical(value: str) -> str:
    """The same 32 octets spelled with different unused trailing bits (43 characters carry
    258 bits for 256): a lenient decoder reads it as the same coordinate."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(value[-1])
    twin = alphabet[last ^ 1]               # flips the lowest of the two unused bits
    return value[:-1] + twin


# --------------------------------------------------------------------------- #
# Near-misses and non-strings are refused even when opted in
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", ["es256k", "ES256K ", " ES256K", "ES256-K", "ES256K\x00",
                                 "ES256k", "ES-256K", "ES256Kx", "ES", "", "SECP256K1"])
def test_near_misses_of_the_name_are_refused_when_opted_in(alg, no_pyjwt):
    tok = token(K1, header={"alg": alg})
    with pytest.raises(UnsupportedAlgorithm, match="not permitted") as exc:
        verify(K1, tok)
    assert type(exc.value) is UnsupportedAlgorithm


@pytest.mark.parametrize("alg", [["ES256K"], {"alg": "ES256K"}, 7, None, True, 1.5],
                         ids=["array", "object", "int", "null", "bool", "float"])
def test_a_non_string_alg_is_unsupported_not_a_bare_type_error(alg, no_pyjwt):
    tok = token(K1, header={"alg": alg})
    with pytest.raises(UnsupportedAlgorithm) as exc:
        verify(K1, tok)
    assert type(exc.value) is UnsupportedAlgorithm


def test_the_opt_in_admits_only_the_one_name(no_pyjwt):
    # opting in adds ES256K and nothing else: not the weak algs, not ES512/ES256K-adjacent
    for alg in ("none", "HS256", "RS256", "PS256", "ES512", "ES521", "ML-DSA-65"):
        with pytest.raises(UnsupportedAlgorithm) as exc:
            verify(K1, token(K1, header={"alg": alg}))
        assert type(exc.value) is UnsupportedAlgorithm, alg


# --------------------------------------------------------------------------- #
# Curve and key-type confusion: the pin is openvc's, before PyJWT loads the key
# --------------------------------------------------------------------------- #

OKP = ed25519.Ed25519PrivateKey.generate().public_key()
OKP_JWK = {"kty": "OKP", "crv": "Ed25519", "x": b64(OKP.public_bytes_raw())}
FOREIGN_JWKS = {
    "P-256": P256.jwk,
    "P-384": P384.jwk,
    "Ed25519 OKP": OKP_JWK,
    "AKP (ML-DSA shaped)": {"kty": "AKP", "alg": "ML-DSA-65", "pub": b64(b"\x01" * 1952)},
    "RSA-shaped": {"kty": "RSA", "n": b64(b"\x01" * 256), "e": "AQAB"},
    "oct-shaped": {"kty": "oct", "k": b64(b"\x01" * 32)},
}


@pytest.mark.parametrize("name", sorted(FOREIGN_JWKS))
def test_an_es256k_header_with_a_foreign_key_is_a_proof_error(name, no_pyjwt):
    tok = token(K1)
    with pytest.raises(ProofError) as exc:
        verify(K1, tok, FOREIGN_JWKS[name])
    # the exact class: PyJWT's own InvalidKeyError would have become ClaimsInvalid
    assert type(exc.value) is ProofError, name
    assert "ES256K requires" in str(exc.value)


def test_a_mislabelled_key_is_refused_on_its_label_not_only_on_the_point(no_pyjwt):
    # genuine secp256k1 coordinates, wrong labels: the point alone would verify, the label
    # check is what refuses it (RFC 8812: check the key type and the curve)
    for member, value in (("crv", "P-256"), ("crv", "SECP256K1"), ("crv", "secp256k1 "),
                          ("crv", "K-256"), ("crv", "secp256r1"), ("crv", None),
                          ("kty", "OKP"), ("kty", "ec"), ("kty", "EC "), ("kty", None)):
        jwk = {**K1.jwk, member: value}
        with pytest.raises(ProofError, match="ES256K requires an EC secp256k1 key") as exc:
            verify(K1, token(K1), jwk)
        assert type(exc.value) is ProofError, (member, value)
    for member in ("kty", "crv"):
        jwk = {k: v for k, v in K1.jwk.items() if k != member}
        with pytest.raises(ProofError) as exc:
            verify(K1, token(K1), jwk)
        assert type(exc.value) is ProofError, member


def _foreign_token(alg: str) -> tuple[str, dict[str, Any]]:
    """A genuinely signed token of *alg*, and the public JWK that would verify it."""
    if alg == "ES256":
        return token(P256), P256.jwk
    if alg == "ES384":
        return token(P384), P384.jwk
    key = ed25519.Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(key.public_key().public_bytes_raw())}
    head = b64(json.dumps({"alg": alg, "typ": "JWT", "kid": KID}).encode())
    body = b64(json.dumps(claims()).encode())
    sig = b64(key.sign(f"{head}.{body}".encode()))
    return f"{head}.{body}.{sig}", jwk


@pytest.mark.parametrize("alg", ["ES256", "ES384", "EdDSA", "Ed25519"])
def test_a_classic_alg_with_a_secp256k1_key_is_a_proof_error(alg, no_pyjwt):
    # the existing pin, with the opt-in on AND off: a secp256k1 key never verifies a
    # token whose header names another algorithm
    tok, genuine = _foreign_token(alg)
    for suite in (VcJwtProofSuite(), VcJwtProofSuite(allow_es256k=True)):
        with pytest.raises(ProofError) as exc:
            verify(K1, tok, K1.jwk, suite=suite)
        assert type(exc.value) is ProofError, alg
    assert genuine != K1.jwk                    # the token's own key is another key


@pytest.mark.parametrize("alg", ["ES256", "ES384", "EdDSA", "Ed25519"])
def test_the_classic_algs_still_verify_with_their_own_key_under_the_opt_in(alg):
    tok, genuine = _foreign_token(alg)
    result = verify(K1, tok, genuine)
    assert result.issuer == ISSUER


def test_in_a_did_document_with_both_keys_the_wrong_kid_fails_the_same_way(no_pyjwt):
    # the shape of the recorded preprod DID document: a secp256k1 and a P-256 method
    doc = DidDocument(
        id=ISSUER, raw={}, verification_methods=[
            VerificationMethod(f"{ISSUER}#k1", "JsonWebKey2020", ISSUER, K1.jwk),
            VerificationMethod(f"{ISSUER}#p256", "JsonWebKey2020", ISSUER, P256.jwk)])
    # an ES256K token whose kid names the P-256 method
    wrong = token(K1, header={"kid": f"{ISSUER}#p256"})
    vm = doc.key_by_kid(f"{ISSUER}#p256")
    assert vm is not None and vm.public_key_jwk["crv"] == "P-256"
    with pytest.raises(ProofError) as exc:
        verify(K1, wrong, vm.public_key_jwk)
    assert type(exc.value) is ProofError
    # and the reverse: an ES256 token whose kid names the secp256k1 method
    wrong_p256 = token(P256, header={"kid": f"{ISSUER}#k1"})
    vm = doc.key_by_kid(f"{ISSUER}#k1")
    assert vm is not None and vm.public_key_jwk["crv"] == "secp256k1"
    with pytest.raises(ProofError) as exc2:
        verify(P256, wrong_p256, vm.public_key_jwk)
    assert type(exc2.value) is ProofError


# --------------------------------------------------------------------------- #
# Hostile JWKs: every failure a typed ProofError, before PyJWT
# --------------------------------------------------------------------------- #

def _jwk(**over: Any) -> dict[str, Any]:
    jwk = dict(K1.jwk)
    for name, value in over.items():
        if value is ...:
            del jwk[name]
        else:
            jwk[name] = value
    return jwk


def _x_plus_field_prime_with_a_valid_point() -> tuple[int, int]:
    """(x, y) of a genuine secp256k1 point with a SMALL x, so that x + p still fits in 32
    octets: the same point spelled modulo p, which a lenient reader would accept."""
    for x in range(1, 4000):
        rhs = (pow(x, 3, FIELD_P) + 7) % FIELD_P
        y = pow(rhs, (FIELD_P + 1) // 4, FIELD_P)       # p = 3 (mod 4)
        if y * y % FIELD_P == rhs:
            return x, y
    raise AssertionError("no small-x point found")


_SMALL_X, _SMALL_Y = _x_plus_field_prime_with_a_valid_point()
_ZERO_X_RAW = base64.urlsafe_b64decode(ZERO_X.jwk["x"] + "=")
_ZERO_Y_RAW = base64.urlsafe_b64decode(ZERO_Y.jwk["y"] + "=")

NOT_A_POINT = "could not load ES256K key from JWK"

HOSTILE_JWKS: dict[str, tuple[dict[str, Any], str]] = {
    # (jwk, a fragment of the message: pins WHICH openvc check refused it)
    "missing y": (_jwk(y=...), "'y' must be"),
    "missing x": (_jwk(x=...), "'x' must be"),
    "x is an int": (_jwk(x=7), "'x' must be"),
    "x is null": (_jwk(x=None), "'x' must be"),
    "x is a list": (_jwk(x=[K1.jwk["x"]]), "'x' must be"),
    "x is an object": (_jwk(x={"v": K1.jwk["x"]}), "'x' must be"),
    "x is bytes-like": (_jwk(x=K1.jwk["x"].encode()), "'x' must be"),
    "y is a bool": (_jwk(y=True), "'y' must be"),
    "x is empty": (_jwk(x=""), "'x' must be"),
    "x has padding": (_jwk(x=K1.jwk["x"] + "="), "'x' must be"),
    "x uses the + alphabet": (_jwk(x="+" + K1.jwk["x"][1:]), "'x' must be"),
    "x uses the / alphabet": (_jwk(x="/" + K1.jwk["x"][1:]), "'x' must be"),
    "x has a space": (_jwk(x=" " + K1.jwk["x"][1:]), "'x' must be"),
    "x has a newline": (_jwk(x=K1.jwk["x"] + "\n"), "'x' must be"),
    "x has a NUL": (_jwk(x=K1.jwk["x"][:-1] + "\x00"), "'x' must be"),
    "x has a non-ASCII digit": (_jwk(x="٠" + K1.jwk["x"][1:]), "'x' must be"),
    "x has a lone surrogate": (_jwk(x="\ud800" + K1.jwk["x"][1:]), "'x' must be"),
    "x is 31 octets (42 chars)": (_jwk(x=K1.jwk["x"][:-1]), "'x' must be"),
    "x is 33 octets (44 chars)": (_jwk(x=K1.jwk["x"] + "A"), "'x' must be"),
    "y is 31 octets": (_jwk(y=K1.jwk["y"][:-1]), "'y' must be"),
    "y is 33 octets": (_jwk(y=K1.jwk["y"] + "A"), "'y' must be"),
    "x is 64 octets": (_jwk(x=K1.jwk["x"] * 2), "'x' must be"),
    # a REAL key whose zero octet was stripped / padded: valid points, wrong width
    "real key, x written with its leading zero stripped (31 octets)":
        (dict(ZERO_X.jwk, x=b64(_ZERO_X_RAW[1:])), "'x' must be"),
    "real key, x padded to 33 octets":
        (dict(K1.jwk, x=b64(b"\x00" + base64.urlsafe_b64decode(K1.jwk["x"] + "="))),
         "'x' must be"),
    "real key, y written with its leading zero stripped (31 octets)":
        (dict(ZERO_Y.jwk, y=b64(_ZERO_Y_RAW[1:])), "'y' must be"),
    "real key, y padded to 33 octets":
        (dict(K1.jwk, y=b64(b"\x00" + base64.urlsafe_b64decode(K1.jwk["y"] + "="))),
         "'y' must be"),
    # the same 32 octets in a non-canonical spelling
    "x with non-zero unused trailing bits": (_jwk(x=_non_canonical(K1.jwk["x"])),
                                             "not canonical"),
    "y with non-zero unused trailing bits": (_jwk(y=_non_canonical(K1.jwk["y"])),
                                             "not canonical"),
    # width right, point wrong
    "point off the curve (y changed)": (_jwk(y=b64(bytes(31) + b"\x01")), NOT_A_POINT),
    "point (0, 0)": (_jwk(x=b64(bytes(32)), y=b64(bytes(32))), NOT_A_POINT),
    "x equals the field prime": (_jwk(x=b64(FIELD_P.to_bytes(32, "big"))), "field element"),
    "x above the field prime": (_jwk(x=b64(b"\xff" * 32)), "field element"),
    "y above the field prime": (_jwk(y=b64(b"\xff" * 32)), "field element"),
    "a genuine point written modulo p (x + p)":
        (_jwk(x=b64((_SMALL_X + FIELD_P).to_bytes(32, "big")), y=b64(_SMALL_Y.to_bytes(32, "big"))),
         "field element"),
    "the generator with swapped coordinates": (_jwk(x=K1.jwk["y"], y=K1.jwk["x"]),
                                               NOT_A_POINT),
}


@pytest.mark.parametrize("name", sorted(HOSTILE_JWKS))
def test_a_hostile_jwk_is_a_typed_proof_error_before_pyjwt(name, no_pyjwt):
    jwk, fragment = HOSTILE_JWKS[name]
    with pytest.raises(ProofError) as exc:
        verify(K1, token(K1), jwk)
    assert type(exc.value) is ProofError, name
    assert fragment in str(exc.value), (name, str(exc.value))


def test_the_small_x_point_is_a_real_point_so_the_modulo_p_case_is_not_vacuous():
    ec.EllipticCurvePublicNumbers(_SMALL_X, _SMALL_Y, ec.SECP256K1()).public_key()
    assert _SMALL_X + FIELD_P < 2**256


@pytest.mark.parametrize("shape", [None, [], [K1.jwk], "jwk", 7, b"x", True],
                         ids=["null", "list", "list-of-jwk", "str", "int", "bytes", "bool"])
def test_a_jwk_that_is_not_an_object_is_a_proof_error(shape, no_pyjwt):
    with pytest.raises(ProofError, match="JWK object") as exc:
        verify(K1, token(K1), shape)
    assert type(exc.value) is ProofError


def test_the_controls_for_the_hostile_table_do_verify():
    # every hostile JWK above differs from a valid one by the named defect only
    assert verify(K1, token(K1), K1.jwk).issuer == ISSUER
    assert verify(ZERO_X, token(ZERO_X), ZERO_X.jwk).issuer == ISSUER     # a real zero octet
    assert verify(ZERO_Y, token(ZERO_Y), ZERO_Y.jwk).issuer == ISSUER
    for signer in (ZERO_X, ZERO_Y):
        raw = base64.urlsafe_b64decode(signer.jwk["x"] + "=")
        assert len(raw) == 32                                              # kept at full width


def test_a_private_member_in_the_jwk_is_ignored_never_loaded():
    # only the public coordinates are read: a `d` that disagrees changes nothing
    jwk = dict(K1.jwk, d=b64(b"\x01" * 32))
    assert verify(K1, token(K1), jwk).issuer == ISSUER
    with pytest.raises(SignatureInvalid):
        verify(K1, token(K1), dict(OTHER_K1.jwk, d=K1.key.private_numbers().private_value
                                   .to_bytes(32, "big").hex()))


def test_pyjwt_registers_es256k_as_sha256_on_secp256k1():
    # The dependency this opt-in rests on, pinned where it can drift. pyproject floors
    # pyjwt>=2.13, and the suite's private PyJWT instance was measured to carry ES256K on 2.13.0,
    # the floor itself;
    # the curve check below is openvc's own, so a PyJWT that dropped `expected_curve` would
    # not open a hole, but a PyJWT that dropped the algorithm would end the lane.
    algorithm = vc_jwt._JWT._jws._algorithms["ES256K"]
    assert type(algorithm).__name__ == "ECAlgorithm"
    assert algorithm.hash_alg is hashes.SHA256
    assert algorithm.expected_curve is ec.SECP256K1


# --------------------------------------------------------------------------- #
# Wrong key, tampering
# --------------------------------------------------------------------------- #

def test_the_wrong_secp256k1_key_is_a_signature_failure():
    with pytest.raises(SignatureInvalid) as exc:
        verify(K1, token(K1), OTHER_K1.jwk)
    assert type(exc.value) is SignatureInvalid


def test_a_tampered_payload_is_a_signature_failure():
    good = token(K1)
    h, p, s = good.split(".")
    body = json.loads(base64.urlsafe_b64decode(p + "=="))
    body["vc"]["credentialSubject"]["name"] = "Mallory"
    forged = f"{h}.{b64(json.dumps(body).encode())}.{s}"
    with pytest.raises(SignatureInvalid) as exc:
        verify(K1, forged)
    assert type(exc.value) is SignatureInvalid


def test_a_tampered_header_is_a_signature_failure():
    h, p, s = token(K1).split(".")
    head = json.loads(base64.urlsafe_b64decode(h + "=="))
    head["kid"] = "did:example:issuer#key-2"
    with pytest.raises(SignatureInvalid) as exc:
        verify(K1, f"{b64(json.dumps(head).encode())}.{p}.{s}")
    assert type(exc.value) is SignatureInvalid


@pytest.mark.parametrize("index", [0, 1, 31, 32, 33, 63])
def test_one_flipped_signature_byte_is_a_signature_failure(index):
    def flipped(signing_input: bytes, signer: Signer) -> str:
        raw = bytearray(signer.sign(signing_input))
        raw[index] ^= 0x01
        return b64(bytes(raw))

    with pytest.raises(SignatureInvalid) as exc:
        verify(K1, token(K1, sig=flipped))
    assert type(exc.value) is SignatureInvalid


def test_an_es256_signature_over_the_same_input_is_not_an_es256k_signature():
    # a P-256 signature relabelled ES256K, checked against the secp256k1 key
    h, p, _ = token(K1).split(".")
    p256_sig = P256.sign(f"{h}.{p}".encode())
    with pytest.raises(SignatureInvalid) as exc:
        verify(K1, f"{h}.{p}.{b64(p256_sig)}")
    assert type(exc.value) is SignatureInvalid


# --------------------------------------------------------------------------- #
# Signature shapes: ES256K gives exactly what ES256 gives (parity table)
# --------------------------------------------------------------------------- #

def _raw(signing_input: bytes, signer: Signer) -> tuple[bytes, bytes]:
    r, s = signer.rs(signing_input)
    return r.to_bytes(32, "big"), s.to_bytes(32, "big")


SIGNATURES: dict[str, tuple[Callable[[bytes, Signer], str], str]] = {
    # name: (builder of the signature SEGMENT, the class both algs end in)
    "empty": (lambda si, g: "", "SignatureInvalid"),
    "1 octet": (lambda si, g: b64(g.sign(si)[:1]), "SignatureInvalid"),
    "63 octets": (lambda si, g: b64(g.sign(si)[:63]), "SignatureInvalid"),
    "65 octets": (lambda si, g: b64(g.sign(si) + b"\x00"), "SignatureInvalid"),
    "96 octets (an ES384-sized R||S)": (lambda si, g: b64(g.sign(si) + bytes(32)),
                                        "SignatureInvalid"),
    "DER-encoded": (lambda si, g: b64(encode_dss_signature(*g.rs(si))), "SignatureInvalid"),
    "r = 0": (lambda si, g: b64(bytes(32) + _raw(si, g)[1]), "SignatureInvalid"),
    "s = 0": (lambda si, g: b64(_raw(si, g)[0] + bytes(32)), "SignatureInvalid"),
    "r = n": (lambda si, g: b64(g.n.to_bytes(32, "big") + _raw(si, g)[1]), "SignatureInvalid"),
    "s = n": (lambda si, g: b64(_raw(si, g)[0] + g.n.to_bytes(32, "big")), "SignatureInvalid"),
    "r = s = 2^256 - 1": (lambda si, g: b64(b"\xff" * 64), "SignatureInvalid"),
    "bad characters": (lambda si, g: b64(g.sign(si))[:-2] + "!!", "SignatureInvalid"),
    "an inner space": (lambda si, g: b64(g.sign(si))[:10] + " " + b64(g.sign(si))[10:],
                       "ClaimsInvalid"),
    "non-ASCII": (lambda si, g: b64(g.sign(si)) + "é", "MalformedToken"),
    "a fourth segment": (lambda si, g: b64(g.sign(si)) + ".x", "MalformedToken"),
}


@pytest.mark.parametrize("name", sorted(SIGNATURES))
def test_signature_shape_parity_between_es256_and_es256k(name):
    build, expected = SIGNATURES[name]
    got = {signer.alg: outcome(lambda s=signer: verify(s, token(s, sig=build)))
           for signer in (P256, K1)}
    assert got == {"ES256": expected, "ES256K": expected}, (name, got)


def test_a_trailing_equals_on_the_signature_segment_is_what_es256_does_too():
    # PyJWT tolerates `=` padding on the signature segment, for ES256 as for ES256K. Not
    # widened by this change; pinned so a PyJWT that starts refusing it is noticed on both.
    def padded(signing_input: bytes, signer: Signer) -> str:
        return b64(signer.sign(signing_input)) + "="

    assert outcome(lambda: verify(P256, token(P256, sig=padded))) == "verified"
    assert outcome(lambda: verify(K1, token(K1, sig=padded))) == "verified"


def test_a_signature_is_exactly_64_octets_of_r_then_s():
    h, p, _ = token(K1).split(".")
    signing_input = f"{h}.{p}".encode()
    r, s = K1.rs(signing_input)
    good = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert len(good) == 64
    assert verify(K1, f"{h}.{p}.{b64(good)}").issuer == ISSUER
    for bad in (good[:63], good + b"\x00", encode_dss_signature(r, s),
                s.to_bytes(32, "big") + r.to_bytes(32, "big")):
        with pytest.raises(SignatureInvalid):
            verify(K1, f"{h}.{p}.{b64(bad)}")


# --------------------------------------------------------------------------- #
# The gates after the allow-list still run (and before the signature)
# --------------------------------------------------------------------------- #

GATES: dict[str, dict[str, Any]] = {
    "unknown crit": {"header": {"crit": ["x-unknown"], "x-unknown": 1}},
    "crit naming a standard parameter": {"header": {"crit": ["exp"]}},
    "typ dc+sd-jwt": {"header": {"typ": "dc+sd-jwt"}},
    "typ vc+sd-jwt": {"header": {"typ": "vc+sd-jwt"}},
    "typ application/vc+sd-jwt": {"header": {"typ": "application/vc+sd-jwt"}},
    "typ kb+jwt": {"header": {"typ": "kb+jwt"}},
    "payload carries _sd": {"payload": claims(vc=credential(_sd=["x"]))},
    "payload carries _sd_alg": {"payload": claims(_sd_alg="sha-256")},
    "payload carries a '...' digest": {"payload": claims(vc=credential(items=[{"...": "x"}]))},
}


@pytest.mark.parametrize("name", sorted(GATES))
def test_the_gates_after_the_allow_list_are_malformed_token_for_both_algs(name, no_pyjwt):
    spec = GATES[name]
    for signer in (P256, K1):
        tok = token(signer, header=spec.get("header"), payload=spec.get("payload"))
        with pytest.raises(MalformedToken) as exc:
            verify(signer, tok)
        assert type(exc.value) is MalformedToken, (name, signer.alg)


# --------------------------------------------------------------------------- #
# Claim handling: ES256K shares ES256's, case for case
# --------------------------------------------------------------------------- #

def _w(**over: Any) -> dict[str, Any]:
    return claims(**over)


def _without(name: str) -> dict[str, Any]:
    body = claims()
    del body[name]
    return body


CLAIM_CASES: dict[str, dict[str, Any]] = {
    # name: {payload|payload_json, kwargs, expected}
    "expired": {"payload": _w(exp=NOW - 3600), "expected": "ClaimsInvalid"},
    "expired just past leeway": {"payload": _w(exp=NOW - 61), "expected": "ClaimsInvalid"},
    "not yet valid": {"payload": _w(nbf=NOW + 3600), "expected": "ClaimsInvalid"},
    "iat in the future": {"payload": _w(iat=NOW + 3600), "expected": "ClaimsInvalid"},
    "aud mismatch": {"payload": _w(aud="https://other.example"),
                     "kwargs": {"audience": "https://rp.example"}, "expected": "ClaimsInvalid"},
    "aud missing, one expected": {"kwargs": {"audience": "https://rp.example"},
                                  "expected": "ClaimsInvalid"},
    "aud present, none expected": {"payload": _w(aud="https://rp.example"),
                                   "expected": "ClaimsInvalid"},
    "aud empty list, none expected": {"payload": _w(aud=[]), "expected": "ClaimsInvalid"},
    "aud matches": {"payload": _w(aud="https://rp.example"),
                    "kwargs": {"audience": "https://rp.example"}, "expected": "verified"},
    "exp null": {"payload_json": json.dumps(claims()).replace(f'"exp": {NOW + 3600}',
                                                              '"exp": null'),
                 "expected": "ClaimsInvalid"},
    "exp NaN": {"payload_json": json.dumps(claims()).replace(f'"exp": {NOW + 3600}',
                                                             '"exp": NaN'),
                "expected": "ClaimsInvalid"},
    "exp a string": {"payload": _w(exp="soon"), "expected": "ClaimsInvalid"},
    "nbf null": {"payload": _w(nbf=None), "expected": "ClaimsInvalid"},
    # the expiry waiver must not switch the shape gate off: a signed `NaN` would otherwise
    # never expire (PyJWT's verify_exp=False skips the claim entirely)
    "exp NaN, expiry waived": {
        "payload_json": json.dumps(claims()).replace(f'"exp": {NOW + 3600}', '"exp": NaN'),
        "kwargs": {"check_temporal": False}, "expected": "ClaimsInvalid"},
    "exp null, expiry waived": {
        "payload_json": json.dumps(claims()).replace(f'"exp": {NOW + 3600}', '"exp": null'),
        "kwargs": {"check_temporal": False}, "expected": "ClaimsInvalid"},
    "exp a string, expiry waived": {"payload": _w(exp="abc"),
                                    "kwargs": {"check_temporal": False},
                                    "expected": "ClaimsInvalid"},
    # PyJWT int()-casts these, so without openvc's NumericDate shape gate each would verify:
    # a numeric string, and a bool (True is 1, an expiry long past, which the waiver then drops)
    "exp a numeric string": {"payload": _w(exp=str(NOW + 3600)), "expected": "ClaimsInvalid"},
    "nbf a numeric string": {"payload": _w(nbf=str(NOW - 5)), "expected": "ClaimsInvalid"},
    "iat a numeric string": {"payload": _w(iat=str(NOW - 5)), "expected": "ClaimsInvalid"},
    "exp true, expiry waived": {"payload": _w(exp=True),
                                "kwargs": {"check_temporal": False},
                                "expected": "ClaimsInvalid"},
    "exp expired, expiry waived": {"payload": _w(exp=NOW - 3600),
                                   "kwargs": {"check_temporal": False}, "expected": "verified"},
    "sub not a string": {"payload": _w(sub=7), "expected": "ClaimsInvalid"},
    "jti not a string": {"payload": _w(jti=["urn:uuid:1"]), "expected": "ClaimsInvalid"},
    "sub differs from credentialSubject.id": {"payload": _w(sub="did:example:someone-else"),
                                              "expected": "ClaimsInvalid"},
    "jti differs from vc.id": {"payload": _w(jti="urn:uuid:2"), "expected": "ClaimsInvalid"},
    "iss differs from vc.issuer": {"payload": _w(iss="did:example:other"),
                                   "expected": "ClaimsInvalid"},
    "vc.issuer is another object id": {"payload": _w(vc=credential(issuer={"id": "did:x:y"})),
                                       "expected": "ClaimsInvalid"},
    "iss missing": {"payload": _without("iss"), "expected": "ClaimsInvalid"},
    "vc missing": {"payload": _without("vc"), "expected": "ClaimsInvalid"},
    "vc not an object": {"payload": _w(vc="x"), "expected": "ClaimsInvalid"},
    "expected type absent": {"kwargs": {"expected_types": ["NotThere"]},
                             "expected": "ClaimsInvalid"},
    "expected type present": {"kwargs": {"expected_types": ["ExampleCredential"]},
                              "expected": "verified"},
    "a plain valid token": {"expected": "verified"},
}


@pytest.mark.parametrize("name", sorted(CLAIM_CASES))
def test_claim_handling_parity_between_es256_and_es256k(name):
    spec = CLAIM_CASES[name]
    got = {}
    for signer in (P256, K1):
        tok = token(signer, payload=spec.get("payload"), payload_json=spec.get("payload_json"))
        got[signer.alg] = outcome(lambda s=signer, t=tok: verify(s, t, **spec.get("kwargs", {})))
    assert got == {"ES256": spec["expected"], "ES256K": spec["expected"]}, (name, got)


def test_an_expired_token_verifies_with_the_waiver_and_says_so_for_both_algs():
    for signer in (P256, K1):
        tok = token(signer, payload=_w(exp=NOW - 3600))
        result = verify(signer, tok, check_temporal=False)
        assert result.expired is True, signer.alg
        assert result.issuer == ISSUER
    # the waiver waives expiry only: the signature is still checked
    with pytest.raises(SignatureInvalid):
        verify(K1, token(K1, payload=_w(exp=NOW - 3600)), OTHER_K1.jwk, check_temporal=False)


def test_leeway_is_the_suite_leeway_for_both_algs():
    for signer in (P256, K1):
        tok = token(signer, payload=_w(exp=NOW - 30))
        assert verify(signer, tok).issuer == ISSUER                         # inside 60 s
        strict = VcJwtProofSuite(allow_es256k=True, leeway_s=0)
        with pytest.raises(ClaimsInvalid):
            verify(signer, tok, suite=strict)


# --------------------------------------------------------------------------- #
# Signing stays closed: the opt-in is for verification
# --------------------------------------------------------------------------- #

class StubKey:
    """A third-party SigningKey that claims *alg*. ``sign`` must never be called."""

    def __init__(self, alg: str) -> None:
        self._alg = alg
        self.calls = 0

    @property
    def alg(self) -> str:
        return self._alg

    @property
    def kid(self) -> str:
        return KID

    def sign(self, signing_input: bytes) -> bytes:
        self.calls += 1
        return b"\x00" * 64


SIGNING_SUITES = {
    "default": lambda: VcJwtProofSuite(),
    "es256k": lambda: VcJwtProofSuite(allow_es256k=True),
    "pq": lambda: VcJwtProofSuite(allow_pq=True),
    "pq+es256k": lambda: VcJwtProofSuite(allow_pq=True, allow_es256k=True),
}


@pytest.mark.parametrize("name", sorted(SIGNING_SUITES))
def test_no_suite_signs_with_an_es256k_key(name):
    suite = SIGNING_SUITES[name]()
    key = StubKey("ES256K")
    with pytest.raises(UnsupportedAlgorithm, match="not permitted") as exc:
        suite.sign(credential(), signing_key=key)
    assert type(exc.value) is UnsupportedAlgorithm
    assert key.calls == 0                       # refused BEFORE the backend was asked


def test_the_opt_in_does_not_narrow_what_the_suite_signs():
    from openvc.keys import P256SigningKey
    key = P256SigningKey.generate(kid=KID)
    signed = VcJwtProofSuite(allow_es256k=True).sign(credential(), signing_key=key)
    assert verify(K1, signed, key.public_jwk(), suite=VcJwtProofSuite()).issuer == ISSUER
    # and a suite that allows both opt-ins still signs ML-DSA names (a stub: no PQ build needed)
    pq = StubKey("ML-DSA-65")
    VcJwtProofSuite(allow_pq=True, allow_es256k=True).sign(credential(), signing_key=pq)
    assert pq.calls == 1
    # while allow_es256k alone does not offer them
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite(allow_es256k=True).sign(credential(), signing_key=StubKey("ML-DSA-65"))


# --------------------------------------------------------------------------- #
# The two opt-ins are independent
# --------------------------------------------------------------------------- #

def test_allow_pq_does_not_imply_es256k_and_the_reverse(no_pyjwt):
    with pytest.raises(UnsupportedAlgorithm):
        verify(K1, token(K1), suite=VcJwtProofSuite(allow_pq=True))
    mldsa = token(K1, header={"alg": "ML-DSA-65"})
    with pytest.raises(UnsupportedAlgorithm):
        verify(K1, mldsa, suite=VcJwtProofSuite(allow_es256k=True))


def test_the_constants_are_disjoint_and_the_default_list_is_unchanged():
    assert vc_jwt.ALLOWED_ALGS == frozenset({"ES256", "ES384", "EdDSA", "Ed25519"})
    assert vc_jwt.ALLOWED_ALGS_ES256K == frozenset({"ES256K"})
    assert vc_jwt.ALLOWED_ALGS_ES256K.isdisjoint(vc_jwt.ALLOWED_ALGS)
    assert vc_jwt.ALLOWED_ALGS_ES256K.isdisjoint(vc_jwt.ALLOWED_ALGS_PQ)
    assert "ALLOWED_ALGS_ES256K" in vc_jwt.__all__


def test_the_verify_set_is_the_three_terms_and_the_sign_set_drops_es256k():
    default = VcJwtProofSuite()
    assert default._algs == vc_jwt.ALLOWED_ALGS
    assert default._sign_algs == vc_jwt.ALLOWED_ALGS
    assert VcJwtProofSuite(allow_es256k=True)._algs == \
        vc_jwt.ALLOWED_ALGS | {"ES256K"}
    assert VcJwtProofSuite(allow_pq=True)._algs == \
        vc_jwt.ALLOWED_ALGS | vc_jwt.ALLOWED_ALGS_PQ
    both = VcJwtProofSuite(allow_pq=True, allow_es256k=True)
    assert both._algs == vc_jwt.ALLOWED_ALGS | vc_jwt.ALLOWED_ALGS_PQ | {"ES256K"}
    assert both._sign_algs == vc_jwt.ALLOWED_ALGS | vc_jwt.ALLOWED_ALGS_PQ
    for suite in (default, VcJwtProofSuite(allow_es256k=True), both):
        assert "ES256K" not in suite._sign_algs


def test_the_flag_is_keyword_only():
    with pytest.raises(TypeError):
        VcJwtProofSuite(60, False, True)           # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Positives: the synthetic round trip, low-s and high-s
# --------------------------------------------------------------------------- #

def test_a_hand_built_es256k_token_verifies_and_reconciles():
    result = verify(K1, token(K1))
    assert result.issuer == ISSUER
    assert result.subject == "did:example:subject"
    assert result.credential["type"] == ["VerifiableCredential", "ExampleCredential"]
    assert result.expired is False


def _with_s(signing_input: bytes, signer: Signer, *, high: bool) -> str:
    """The signature over *signing_input* with s forced into the upper or lower half."""
    r, s = signer.rs(signing_input)
    if (s > signer.n // 2) != high:
        s = signer.n - s                    # (r, n - s) is the other valid twin
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def test_both_the_low_s_and_the_high_s_form_of_a_signature_verify():
    # DECISION (#323, Decision 2): accept both. RFC 8812 says nothing about s being in the
    # lower half of the range; the existing ES256 path accepts the high-s twin too
    # (asserted here for ES256); a signer that does not normalise s emits high-s about half
    # the time, so a refusal would fail legitimate chains. This documents the NON-UNIQUENESS
    # of a valid signature, not a bug: openvc keeps no state and keys nothing on signature
    # bytes. If this ever changes, change it on purpose and re-read Decision 2.
    for signer in (K1, P256):
        low = token(signer, sig=lambda si, g: _with_s(si, g, high=False))
        high = token(signer, sig=lambda si, g: _with_s(si, g, high=True))
        assert low != high, "the twin must be a different byte string"
        s_of = lambda tok: int.from_bytes(                     # noqa: E731
            base64.urlsafe_b64decode(tok.split(".")[2] + "==")[32:], "big")
        assert s_of(low) <= signer.n // 2 < s_of(high)
        assert verify(signer, low).issuer == ISSUER, signer.alg
        assert verify(signer, high).issuer == ISSUER, signer.alg


def test_the_published_generator_point_reads_as_a_key():
    # d = 1 makes the public key the secp256k1 generator G (G). The
    # signature is computed here (cryptography randomises k), so this pins the JWK reading
    # of a published point, not a published signature.
    g = k1(1)
    assert g.jwk["x"] == b64(bytes.fromhex(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
    assert g.jwk["y"] == b64(bytes.fromhex(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))
    assert verify(g, token(g)).issuer == ISSUER


# --------------------------------------------------------------------------- #
# Fuzzing: never anything but an OpenvcError; a mutated token is never accepted
# --------------------------------------------------------------------------- #


def _suite() -> VcJwtProofSuite:
    return VcJwtProofSuite(allow_es256k=True)


VALID = token(K1)
_H, _P, _S = VALID.split(".")
_FUZZ = settings(max_examples=300, deadline=None,
                 suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def _verify_expecting_openvc_error(tok: str, jwk: Any) -> None:
    try:
        _suite().verify(tok, public_key_jwk=jwk)
    except OpenvcError:
        return
    except Exception as exc:                # pragma: no cover - the failure being hunted
        raise AssertionError(f"{type(exc).__name__} escaped OpenvcError: {exc}") from exc


@_FUZZ
@given(st.binary(max_size=200))
def test_arbitrary_signature_octets_never_escape_the_taxonomy(raw):
    _verify_expecting_openvc_error(f"{_H}.{_P}.{b64(raw)}", K1.jwk)


@_FUZZ
@given(st.text(max_size=120))
def test_an_arbitrary_signature_segment_never_escapes_the_taxonomy(segment):
    _verify_expecting_openvc_error(f"{_H}.{_P}.{segment}", K1.jwk)


_json_scalar = (st.none() | st.booleans() | st.integers(min_value=-2**300, max_value=2**300)
                | st.floats(allow_nan=True, allow_infinity=True) | st.text(max_size=60))
_json_value = st.recursive(
    _json_scalar,
    lambda kids: st.lists(kids, max_size=4) | st.dictionaries(st.text(max_size=8), kids,
                                                              max_size=4),
    max_leaves=10)
_member_value = st.one_of(
    _json_value, st.sampled_from([K1.jwk["x"], K1.jwk["y"]]),
    st.binary(min_size=0, max_size=70).map(b64),
    st.integers(min_value=0, max_value=2**260).map(lambda n: b64(n.to_bytes(33, "big"))))


@_FUZZ
@given(st.fixed_dictionaries({}, optional={"kty": _member_value, "crv": _member_value,
                                           "x": _member_value, "y": _member_value,
                                           "d": _member_value, "alg": _member_value,
                                           "kid": _member_value}))
def test_arbitrary_jwk_members_never_escape_the_taxonomy(jwk):
    base = dict(K1.jwk)
    base.update(jwk)
    _verify_expecting_openvc_error(VALID, base)


@_FUZZ
@given(st.one_of(_json_value, st.just(K1.jwk)))
def test_an_arbitrary_jwk_value_never_escapes_the_taxonomy(jwk):
    _verify_expecting_openvc_error(VALID, jwk)


@_FUZZ
@given(st.integers(0, 63), st.integers(1, 255))
def test_any_single_octet_change_to_the_signature_is_rejected(index, delta):
    raw = bytearray(base64.urlsafe_b64decode(_S + "=="))
    raw[index] ^= delta
    with pytest.raises(SignatureInvalid):
        _suite().verify(f"{_H}.{_P}.{b64(bytes(raw))}", public_key_jwk=K1.jwk)


@_FUZZ
@given(st.integers(0, 10_000), st.integers(1, 255))
def test_any_single_octet_change_to_the_payload_is_rejected(index, delta):
    raw = bytearray(base64.urlsafe_b64decode(_P + "=="))
    raw[index % len(raw)] ^= delta
    with pytest.raises(OpenvcError):
        _suite().verify(f"{_H}.{b64(bytes(raw))}.{_S}", public_key_jwk=K1.jwk)


@_FUZZ
@given(st.integers(0, 10_000), st.integers(1, 255))
def test_any_single_octet_change_to_the_header_is_rejected(index, delta):
    raw = bytearray(base64.urlsafe_b64decode(_H + "=="))
    raw[index % len(raw)] ^= delta
    with pytest.raises(OpenvcError):
        _suite().verify(f"{b64(bytes(raw))}.{_P}.{_S}", public_key_jwk=K1.jwk)
