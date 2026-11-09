"""
tests/test_did_key_bounded.py — did:key decoding is bounded by ``openvc.multibase``
(issue #386, internal security review of 2026-11-07, § M9).

``DidKeyResolver`` used to keep private copies of the base58 and varint decoders without
the caps ``openvc.multibase`` has (base58 input ≤ 4 096 characters, varint ≤ 9 bytes).
base58 decoding is O(n²) big-integer work and nothing bounds the length of a VC-JWT ``iss``
or a Data Integrity ``verificationMethod``, so a 200 000-character ``did:key`` cost about
5 s of CPU before any signature check — through ``verify_credential`` and through the Data
Integrity lanes' offline did:key fallback alike. The resolver now decodes through the
bounded codec and maps ``MultibaseError`` to the ``DidResolutionError`` callers already see
for a malformed did:key.

Negatives first; the typed class is asserted exactly. The timing bounds are CI-safe: the
refusals cost microseconds on the branch and seconds on the code before it.
"""
from __future__ import annotations

import asyncio
import base64
import json
import random
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import VerificationPolicy, verify_credential, verify_credential_async
from openvc.did.base import DidError, DidResolutionError
from openvc.did.did_key import DidKeyResolver
from openvc.errors import KeyResolutionFailed
from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey
from openvc.multibase import MultibaseError, encode_multibase
from openvc.proof._verify_common import resolve_verification_key
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import KeyResolutionError

V2 = "https://www.w3.org/ns/credentials/v2"
POLICY = VerificationPolicy(require_status=False)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# openvc.multibase's caps, restated here so a change there is a visible change here.
MAX_B58_LEN = 4096
MAX_VARINT_BYTES = 9

# did:key spec test vectors (one per supported multicodec).
ED25519_VECTOR = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
P256_VECTOR = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
P384_VECTOR = "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"


# --------------------------------------------------------------------------- #
# helpers (tests/ is not a package: copied, never imported)
# --------------------------------------------------------------------------- #

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        b, code = code & 0x7F, code >> 7
        out.append(b | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key_of(prefix: bytes, raw: bytes) -> str:
    return "did:key:" + encode_multibase(prefix + raw)


def _ed25519_did_key_body() -> str:
    """The multibase body (after ``did:key:``) of a valid Ed25519 did:key."""
    key = Ed25519SigningKey.generate(kid="_")
    return encode_multibase(_leb128(0xED) + key.public_key_raw())


def _long_did_key(n: int, *, seed: int | None = None) -> str:
    """A did:key whose base58 body has *n* characters: random base58 (seeded) or a run of
    ``z`` — never ``1``, whose leading-zero semantics keep the big integer at zero and
    would make the quadratic cost (the thing under test) vanish."""
    if seed is None:
        return "did:key:z" + "z" * n
    rng = random.Random(seed)
    return "did:key:z" + "".join(rng.choice(B58) for _ in range(n))


def _unsigned_vc_jwt(iss: str) -> str:
    """A VC-JWT with a junk signature: the pipeline must refuse it at key resolution."""
    header = _b64u(json.dumps({"alg": "EdDSA"}).encode())
    payload = _b64u(json.dumps({"iss": iss, "vc": {}}).encode())
    return f"{header}.{payload}.AA"


# --------------------------------------------------------------------------- #
# 1. the base58 cap: an oversized did:key is refused typed, cheaply
# --------------------------------------------------------------------------- #

def test_a_5000_char_did_key_is_refused_as_too_long_with_the_typed_class():
    did = _long_did_key(5_000)
    start = time.perf_counter()
    with pytest.raises(DidResolutionError, match="too long") as exc:
        DidKeyResolver().resolve(did)
    elapsed = time.perf_counter() - start
    assert type(exc.value) is DidResolutionError                 # the class callers see
    assert isinstance(exc.value, DidError)
    assert type(exc.value.__cause__) is MultibaseError           # the bounded codec refused
    assert elapsed < 0.5, elapsed


@pytest.mark.parametrize("seed", [None, 1], ids=["z-run", "random-base58"])
def test_a_200000_char_did_key_is_refused_in_under_a_second(seed):
    # ~5 s of big-integer work on the unbounded decoder; microseconds on the bounded one
    did = _long_did_key(200_000, seed=seed)
    start = time.perf_counter()
    with pytest.raises(DidResolutionError, match="too long") as exc:
        DidKeyResolver().resolve(did)
    elapsed = time.perf_counter() - start
    assert type(exc.value) is DidResolutionError
    assert elapsed < 1.0, elapsed


def test_the_refusal_never_echoes_the_identifier():
    did = _long_did_key(50_000)
    with pytest.raises(DidResolutionError) as exc:
        DidKeyResolver().resolve(did)
    message = str(exc.value)
    assert "50000" in message                                     # the length is said ...
    assert len(message) < 200 and "zzzz" not in message           # ... the input is not


def test_the_cap_is_exactly_multibases():
    # a body padded with leading '1's (NUL bytes) decodes cheaply: at the cap it passes
    # the length check and is refused later for its (zero) multicodec; one more is too long
    body = _ed25519_did_key_body()[1:]                            # drop the 'z'
    at_cap = "did:key:z" + "1" * (MAX_B58_LEN - len(body)) + body
    assert len(at_cap) - len("did:key:z") == MAX_B58_LEN
    with pytest.raises(DidResolutionError, match="unsupported did:key multicodec 0x0") as exc:
        DidKeyResolver().resolve(at_cap)
    assert exc.value.__cause__ is None                            # not the codec's refusal
    with pytest.raises(DidResolutionError, match="too long"):
        DidKeyResolver().resolve(at_cap[:len("did:key:z")] + "1" + at_cap[len("did:key:z"):])


# --------------------------------------------------------------------------- #
# 2. the varint cap: a continuation run longer than 9 bytes is refused typed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n_continuation", [MAX_VARINT_BYTES, 10, 200],
                         ids=["ten-bytes", "eleven-bytes", "long-run"])
def test_a_varint_longer_than_nine_bytes_is_refused_typed(n_continuation):
    did = _did_key_of(b"\x80" * n_continuation + b"\x01", b"")
    with pytest.raises(DidResolutionError, match="varint too long") as exc:
        DidKeyResolver().resolve(did)
    assert type(exc.value) is DidResolutionError
    assert type(exc.value.__cause__) is MultibaseError


def test_a_nine_byte_varint_passes_the_cap_and_is_an_unsupported_codec():
    did = _did_key_of(b"\x80" * (MAX_VARINT_BYTES - 1) + b"\x01", b"")   # code = 1 << 56
    with pytest.raises(DidResolutionError, match="unsupported did:key multicodec") as exc:
        DidKeyResolver().resolve(did)
    assert exc.value.__cause__ is None


def test_a_truncated_varint_is_still_refused_typed():
    did = _did_key_of(b"\x80" * 3, b"")
    with pytest.raises(DidResolutionError, match="truncated multicodec varint") as exc:
        DidKeyResolver().resolve(did)
    assert type(exc.value) is DidResolutionError
    assert type(exc.value.__cause__) is MultibaseError


# --------------------------------------------------------------------------- #
# 3. the other malformed shapes keep their class and their wording
# --------------------------------------------------------------------------- #

def test_an_invalid_base58_character_keeps_its_message_and_class():
    with pytest.raises(DidResolutionError, match="invalid base58 character") as exc:
        DidKeyResolver().resolve("did:key:zNOTAKEY")             # 'O' is not base58
    assert type(exc.value) is DidResolutionError
    assert type(exc.value.__cause__) is MultibaseError


def test_a_non_z_multibase_prefix_is_refused_before_decoding():
    with pytest.raises(DidResolutionError, match="must use base58btc") as exc:
        DidKeyResolver().resolve("did:key:f" + "0" * 10_000)
    assert exc.value.__cause__ is None


# --------------------------------------------------------------------------- #
# 4. every supported did:key shape still resolves (spec vectors + fresh keys)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did, kty, crv", [
    (ED25519_VECTOR, "OKP", "Ed25519"),
    (P256_VECTOR, "EC", "P-256"),
    (P384_VECTOR, "EC", "P-384"),
], ids=["ed25519", "p256", "p384"])
def test_the_did_key_spec_vectors_resolve_unchanged(did, kty, crv):
    doc = DidKeyResolver().resolve(did)
    body = did[len("did:key:"):]
    (vm,) = doc.verification_methods
    assert doc.id == did
    assert vm.id == f"{did}#{body}" and vm.controller == did
    assert vm.public_key_jwk["kty"] == kty and vm.public_key_jwk["crv"] == crv
    assert doc.relationships == {"authentication": [vm.id], "assertionMethod": [vm.id]}


def test_a_fresh_ed25519_key_round_trips():
    key = Ed25519SigningKey.generate(kid="_")
    did = _did_key_of(_leb128(0xED), key.public_key_raw())
    (vm,) = DidKeyResolver().resolve(did).verification_methods
    assert vm.public_key_jwk == {"kty": "OKP", "crv": "Ed25519", "x": key.public_jwk()["x"]}


def test_a_fresh_p256_key_round_trips():
    key = P256SigningKey.generate(kid="_")
    did = _did_key_of(_leb128(0x1200), key.public_key_raw(compressed=True))
    (vm,) = DidKeyResolver().resolve(did).verification_methods
    jwk = key.public_jwk()
    assert (vm.public_key_jwk["crv"], vm.public_key_jwk["x"], vm.public_key_jwk["y"]) == \
        ("P-256", jwk["x"], jwk["y"])


def test_a_fresh_p384_key_round_trips():
    key = P384SigningKey.generate(kid="_")
    did = _did_key_of(_leb128(0x1201), key.public_key_raw(compressed=True))
    (vm,) = DidKeyResolver().resolve(did).verification_methods
    jwk = key.public_jwk()
    assert (vm.public_key_jwk["crv"], vm.public_key_jwk["x"], vm.public_key_jwk["y"]) == \
        ("P-384", jwk["x"], jwk["y"])


# --------------------------------------------------------------------------- #
# 5. the Data Integrity lanes' offline did:key fallback
# --------------------------------------------------------------------------- #

def _did_key_signer() -> tuple[Ed25519SigningKey, str, str]:
    """(a key whose ``kid`` is its own did:key URL, the did:key, that URL)."""
    private = ed25519.Ed25519PrivateKey.generate()
    mb = encode_multibase(_leb128(0xED) + Ed25519SigningKey(private, kid="_").public_key_raw())
    did, vm = f"did:key:{mb}", f"did:key:{mb}#{mb}"
    return Ed25519SigningKey(private, kid=vm), did, vm


def test_the_offline_fallback_still_resolves_a_valid_did_key():
    key, did, vm = _did_key_signer()
    jwk = resolve_verification_key(vm, proof_purpose="assertionMethod", resolver=None)
    assert jwk["x"] == key.public_jwk()["x"]
    credential = EddsaJcsProofSuite().add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:alice"}},
        signing_key=key, verification_method=vm)
    assert EddsaJcsProofSuite().verify(credential, resolver=None).proof
    assert verify_credential(credential, policy=POLICY).issuer == did


def test_the_offline_fallback_refuses_an_oversized_did_key_in_under_a_second():
    did = _long_did_key(200_000)
    start = time.perf_counter()
    with pytest.raises(KeyResolutionError) as exc:
        resolve_verification_key(f"{did}#k", proof_purpose="assertionMethod", resolver=None)
    elapsed = time.perf_counter() - start
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is DidResolutionError
    assert "too long" in str(exc.value)
    assert elapsed < 1.0, elapsed


# --------------------------------------------------------------------------- #
# 6. the JOSE pipeline: a 200 000-character ``iss`` is refused before any signature
# --------------------------------------------------------------------------- #

def test_verify_credential_refuses_an_oversized_did_key_issuer_in_under_a_second():
    token = _unsigned_vc_jwt(_long_did_key(200_000))
    start = time.perf_counter()
    with pytest.raises(KeyResolutionFailed) as exc:
        verify_credential(token, policy=POLICY)
    elapsed = time.perf_counter() - start
    assert "too long" in str(exc.value)
    assert len(str(exc.value)) < 400                              # safe_repr cuts the DID
    assert elapsed < 1.0, elapsed


def test_verify_credential_async_refuses_an_oversized_did_key_issuer_in_under_a_second():
    token = _unsigned_vc_jwt(_long_did_key(200_000))
    start = time.perf_counter()
    with pytest.raises(KeyResolutionFailed) as exc:
        asyncio.run(verify_credential_async(token, policy=POLICY))
    elapsed = time.perf_counter() - start
    assert "too long" in str(exc.value)
    assert elapsed < 1.0, elapsed
