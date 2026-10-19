"""
tests/test_vcjwt_input_hygiene.py — two input-hygiene gaps in the JOSE suites (#341).

1. ``allow_pq`` was read by truthiness. ``VcJwtProofSuite(allow_pq="false")``, ``allow_pq=1``
   and ``allow_pq="x"`` all constructed and switched the EXPERIMENTAL ML-DSA algorithms on,
   so a deployment that read the flag from an environment variable or a configuration file
   as a string enabled a post-quantum verify path it meant to disable. It is now exactly
   ``True`` or ``False`` (a ``ProofError`` otherwise), as ``allow_es256k`` has been since #323.
   ``SdJwtVcProofSuite(allow_pq=...)`` is the same switch on the other JOSE suite and gets the
   same rule (a ``SdJwtError``, which is a ``ProofError``).
2. ``VcJwtProofSuite._jwk_to_key(jwk, alg)`` read ``jwk.get(...)`` before looking at what it was
   given, so a resolver or a caller that handed over ``None``, a list, a string or a number
   raised a bare ``AttributeError``: not an ``OpenvcError``, so it escaped ``verify_many`` and
   ``verify_many_async`` and aborted a whole batch. It is now a ``ProofError`` whose message
   names the type and never echoes the value.

Negatives first, each asserting the EXACT class so a test cannot pass on an earlier failure;
the controls (the two bools, a normal JWK, an empty or wrong-type object that keeps its old
message) come after. ``tests/`` is not a package: the helpers are copied, not imported.
"""
from __future__ import annotations

import asyncio
import base64
import json
from collections import OrderedDict, UserDict
from types import MappingProxyType
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from openvc import verify_many, verify_many_async
from openvc.did.base import DidDocument, DidResolutionError, VerificationMethod
from openvc.errors import OpenvcError
from openvc.keys import (
    Ed25519SigningKey,
    MLDSASigningKey,
    P256SigningKey,
    P384SigningKey,
    mldsa_available,
)
from openvc.proof.errors import ProofError, SignatureInvalid, UnsupportedAlgorithm
from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
from openvc.proof.vc_jwt import (
    ALLOWED_ALGS,
    ALLOWED_ALGS_PQ,
    VcJwtProofSuite,
)

# --------------------------------------------------------------------------- #
# Helpers (copied: tests/ is not a package)
# --------------------------------------------------------------------------- #

ISSUER = "did:example:issuer"
CRED = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": ISSUER,
    "credentialSubject": {"id": "did:example:subject"},
}
# The four classic algorithms and the signing key that makes each of them.
CLASSIC = {
    "ES256": lambda: P256SigningKey.generate(kid=f"{ISSUER}#k"),
    "ES384": lambda: P384SigningKey.generate(kid=f"{ISSUER}#k"),
    "EdDSA": lambda: Ed25519SigningKey.generate(kid=f"{ISSUER}#k"),
    "Ed25519": lambda: Ed25519SigningKey.generate(kid=f"{ISSUER}#k", alg="Ed25519"),
}
ALGS = [*CLASSIC, "ES256K"]


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# Truthy AND falsy non-bools: the test pins "not a bool", not "truthy". "false" and "0" are
# what a configuration file or an environment variable hands over, and `if flag:` reads both
# as True. 1, 1.0, 0 and 0.0 equal True/False, so a `flag in (True, False)` check lets them in.
NOT_A_BOOL = ["false", "False", "0", "true", "yes", "x", "", 1, 0, 2, -1, 1.0, 0.0, None, [],
              [True], {}, {"a": 1}, (), (True,), b"true", object()]
NOT_A_BOOL_IDS = ["object" if type(v) is object else repr(v)[:24] for v in NOT_A_BOOL]

# Shapes of "not a JWK object": what a buggy resolver or a caller can hand over.
NOT_AN_OBJECT = [None, [], [{"kty": "EC"}], "jwk", "", 7, 0, 1.5, b"x", True, False, ()]
NOT_AN_OBJECT_IDS = ["null", "list", "list-of-jwk", "str", "empty-str", "int", "zero", "float",
                     "bytes", "true", "false", "tuple"]


# --------------------------------------------------------------------------- #
# 1. allow_pq is exactly True or False: VcJwtProofSuite
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", NOT_A_BOOL, ids=NOT_A_BOOL_IDS)
def test_vc_jwt_pq_flag_that_is_not_a_bool_is_refused_at_construction(value):
    with pytest.raises(ProofError, match="allow_pq must be True or False") as exc:
        VcJwtProofSuite(allow_pq=value)
    assert type(exc.value) is ProofError
    assert type(value).__name__ in str(exc.value)        # names the type, never echoes the value


def test_vc_jwt_the_strings_a_configuration_file_hands_over_do_not_switch_ml_dsa_on():
    # the reproduction from the issue: each of these used to construct and enable ML-DSA
    for value in ("false", "0", "x", 1):
        with pytest.raises(ProofError):
            VcJwtProofSuite(allow_pq=value)              # type: ignore[arg-type]


def test_vc_jwt_the_refusal_of_a_non_bool_pq_flag_does_not_echo_it():
    secret = "a-very-long-value-" * 40
    with pytest.raises(ProofError) as exc:
        VcJwtProofSuite(allow_pq=secret)                 # type: ignore[arg-type]
    assert secret not in str(exc.value)
    assert len(str(exc.value)) < 100


def test_vc_jwt_a_bool_subclass_cannot_exist_so_the_pq_check_cannot_be_steered():
    # bool cannot be subclassed, and type() (not isinstance()) reads the real type of an
    # object that claims a __class__: neither can be passed off as True
    with pytest.raises(TypeError):
        type("B", (bool,), {})

    class Liar:
        __class__ = bool                     # type: ignore[assignment]

    assert isinstance(Liar(), bool)                       # isinstance() is fooled ...
    with pytest.raises(ProofError, match="allow_pq must be True or False"):
        VcJwtProofSuite(allow_pq=Liar())                  # type: ignore[arg-type]


def test_vc_jwt_the_two_flags_are_checked_in_signature_order():
    # both wrong: the first parameter's refusal is the one reported, every time
    with pytest.raises(ProofError, match="allow_pq must be True or False"):
        VcJwtProofSuite(allow_pq="false", allow_es256k="false")        # type: ignore[arg-type]
    # one wrong, one right: the wrong one is named, whichever it is
    with pytest.raises(ProofError, match="allow_pq must be True or False"):
        VcJwtProofSuite(allow_pq="false", allow_es256k=True)           # type: ignore[arg-type]
    with pytest.raises(ProofError, match="allow_es256k must be True or False"):
        VcJwtProofSuite(allow_pq=True, allow_es256k="false")           # type: ignore[arg-type]


def test_vc_jwt_a_refused_flag_builds_no_suite_to_misuse():
    # the refusal is the constructor's, so no half-configured suite exists, a valid
    # leeway_s alongside the bad flag included
    with pytest.raises(ProofError):
        VcJwtProofSuite(leeway_s=60, allow_pq=1)         # type: ignore[arg-type]


def test_vc_jwt_the_pq_flag_is_still_keyword_only():
    with pytest.raises(TypeError):
        VcJwtProofSuite(60, True)                        # type: ignore[misc]


def test_vc_jwt_the_two_bools_still_build_the_two_suites():
    assert VcJwtProofSuite(allow_pq=False)._algs == ALLOWED_ALGS
    assert VcJwtProofSuite()._algs == ALLOWED_ALGS
    assert VcJwtProofSuite(allow_pq=True)._algs == ALLOWED_ALGS | ALLOWED_ALGS_PQ
    # independent of the other opt-in, as before
    both = VcJwtProofSuite(allow_pq=True, allow_es256k=True)
    assert both._algs == ALLOWED_ALGS | ALLOWED_ALGS_PQ | {"ES256K"}
    assert VcJwtProofSuite(allow_pq=False, allow_es256k=True)._algs == ALLOWED_ALGS | {"ES256K"}


# --------------------------------------------------------------------------- #
# 1b. the same rule on the other JOSE suite
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", NOT_A_BOOL, ids=NOT_A_BOOL_IDS)
def test_sd_jwt_pq_flag_that_is_not_a_bool_is_refused_at_construction(value):
    with pytest.raises(SdJwtError, match="allow_pq must be True or False") as exc:
        SdJwtVcProofSuite(allow_pq=value)
    assert type(exc.value) is SdJwtError                  # a ProofError, like the other refusals
    assert isinstance(exc.value, ProofError)
    assert type(value).__name__ in str(exc.value)


def test_sd_jwt_the_refusal_of_a_non_bool_pq_flag_does_not_echo_it():
    secret = "a-very-long-value-" * 40
    with pytest.raises(SdJwtError) as exc:
        SdJwtVcProofSuite(allow_pq=secret)               # type: ignore[arg-type]
    assert secret not in str(exc.value)
    assert len(str(exc.value)) < 100


def test_sd_jwt_a_class_that_claims_to_be_bool_is_refused_too():
    class Liar:
        __class__ = bool                     # type: ignore[assignment]

    assert isinstance(Liar(), bool)
    with pytest.raises(SdJwtError, match="allow_pq must be True or False"):
        SdJwtVcProofSuite(allow_pq=Liar())               # type: ignore[arg-type]


def test_sd_jwt_the_two_bools_still_build_the_two_suites():
    assert SdJwtVcProofSuite()._algs == ALLOWED_ALGS
    assert SdJwtVcProofSuite(allow_pq=False)._algs == ALLOWED_ALGS
    assert SdJwtVcProofSuite(allow_pq=True)._algs == ALLOWED_ALGS | ALLOWED_ALGS_PQ


def test_sd_jwt_the_earlier_constructor_checks_keep_their_place():
    # leeway_s and hash_name are read before the flag, as before: each keeps its own message
    with pytest.raises(SdJwtError, match="unsupported hash"):
        SdJwtVcProofSuite(hash_name="md5", allow_pq="false")           # type: ignore[arg-type]
    with pytest.raises(SdJwtError, match="allow_pq must be True or False"):
        SdJwtVcProofSuite(leeway_s=60, hash_name="sha-256", allow_pq=1)   # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 2. a non-object JWK is a ProofError, on every algorithm
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize("shape", NOT_AN_OBJECT, ids=NOT_AN_OBJECT_IDS)
def test_a_non_object_jwk_is_a_proof_error_not_an_attribute_error(shape, alg):
    with pytest.raises(ProofError, match="requires a JWK object") as exc:
        VcJwtProofSuite._jwk_to_key(shape, alg)           # type: ignore[arg-type]
    assert type(exc.value) is ProofError
    assert alg in str(exc.value) and type(shape).__name__ in str(exc.value)


def test_the_refusal_of_a_non_object_jwk_does_not_echo_it():
    secret = "a-very-long-jwk-" * 40
    for alg in ALGS:
        with pytest.raises(ProofError) as exc:
            VcJwtProofSuite._jwk_to_key(secret, alg)      # type: ignore[arg-type]
        assert secret not in str(exc.value)
        assert len(str(exc.value)) < 100, alg


@pytest.mark.parametrize("alg", list(CLASSIC))
@pytest.mark.parametrize("shape", NOT_AN_OBJECT, ids=NOT_AN_OBJECT_IDS)
def test_verify_with_a_non_object_jwk_is_a_proof_error(shape, alg):
    # end to end, with a token a real key signed: the class is the ProofError of the key
    # layer, never the SignatureInvalid / ClaimsInvalid of a later stage, never an
    # AttributeError out of the suite
    key = CLASSIC[alg]()
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    with pytest.raises(ProofError, match="requires a JWK object") as exc:
        VcJwtProofSuite().verify(token, public_key_jwk=shape)         # type: ignore[arg-type]
    assert type(exc.value) is ProofError


def test_the_allow_list_still_runs_before_the_key_is_looked_at():
    # a header whose alg is not permitted is UnsupportedAlgorithm even when the key is None:
    # the new check sits after the allow-list, not before it
    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"iss": ISSUER, "vc": CRED}).encode())
    no_key: Any = None
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().verify(f"{header}.{payload}.", public_key_jwk=no_key)
    header = b64(json.dumps({"alg": "ES256K", "typ": "JWT"}).encode())
    with pytest.raises(UnsupportedAlgorithm):             # ES256K is not on by default
        VcJwtProofSuite().verify(f"{header}.{payload}.AAAA", public_key_jwk=no_key)


# -- a Mapping that is not a dict is not a JWK object either ----------------- #
# The check is `isinstance(jwk, dict)` (PR default 5): a `dict` subclass is an object, a
# read-only or custom Mapping is not, and nor is anything that merely has a `get` method. A
# check written `hasattr(jwk, "get")` or `isinstance(jwk, Mapping)` would let these through to
# the key-type pin or to json.dumps, which answer with a different message (or, for a valid
# key in a wrapper, a different reason) and no longer say what is wrong. Every such object
# was already a ProofError before this change; this pins which one, and that it is the first.

class _OnlyGet:
    """Not a mapping at all: it has a ``get`` method and nothing else."""

    def get(self, key: str, default: Any = None) -> Any:
        return default


MAPPING_LIKES = {
    "mappingproxy": lambda jwk: MappingProxyType(dict(jwk)),
    "UserDict": lambda jwk: UserDict(jwk),
    "_OnlyGet": lambda jwk: _OnlyGet(),
}


@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize("kind", MAPPING_LIKES)
def test_a_mapping_that_is_not_a_dict_is_not_a_jwk_object(kind, alg):
    # the content is a VALID key for the algorithm (ES256K: a P-256 one, the check is first)
    valid = (CLASSIC[alg]() if alg in CLASSIC else CLASSIC["ES256"]()).public_jwk()
    shape = MAPPING_LIKES[kind](valid)
    with pytest.raises(ProofError, match="requires a JWK object") as exc:
        VcJwtProofSuite._jwk_to_key(shape, alg)           # type: ignore[arg-type]
    assert type(exc.value) is ProofError
    assert alg in str(exc.value) and type(shape).__name__ in str(exc.value)


@pytest.mark.parametrize("alg", list(CLASSIC))
@pytest.mark.parametrize("kind", ["mappingproxy", "UserDict"])
def test_verify_with_the_right_key_in_a_mapping_wrapper_is_a_proof_error(kind, alg):
    # the token verifies against the bare key (the control), and is refused for the wrapper
    # with the object message: not signature-invalid, not a key-load failure
    key = CLASSIC[alg]()
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    assert VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk()).issuer == ISSUER
    wrapped: Any = MAPPING_LIKES[kind](key.public_jwk())
    with pytest.raises(ProofError, match="requires a JWK object") as exc:
        VcJwtProofSuite().verify(token, public_key_jwk=wrapped)
    assert type(exc.value) is ProofError


# -- the controls: what the new check must not touch ------------------------ #

@pytest.mark.parametrize("alg", list(CLASSIC))
def test_a_normal_jwk_still_verifies(alg):
    key = CLASSIC[alg]()
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    result = VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert result.issuer == ISSUER


@pytest.mark.parametrize("alg", list(CLASSIC))
def test_a_dict_subclass_is_still_a_jwk_object(alg):
    # a resolver may hand over an ordered or custom mapping type: it is a dict
    key = CLASSIC[alg]()
    token = VcJwtProofSuite().sign(CRED, signing_key=key)
    jwk: Any = OrderedDict(key.public_jwk())
    assert VcJwtProofSuite().verify(token, public_key_jwk=jwk).issuer == ISSUER


@pytest.mark.parametrize("alg", list(CLASSIC))
def test_a_jwk_loads_to_a_key_object(alg):
    assert VcJwtProofSuite._jwk_to_key(CLASSIC[alg]().public_jwk(), alg) is not None


def test_an_empty_object_keeps_the_message_it_always_had():
    # `{}` is an object: the key-type pin names what the algorithm needs, as before. A check
    # written `if not jwk` would report it as a non-object and lose the more useful message.
    for alg, fragment in (("ES256", "requires an EC P-256 key"),
                          ("ES384", "requires an EC P-384 key"),
                          ("EdDSA", "requires an OKP Ed25519 key"),
                          ("Ed25519", "requires an OKP Ed25519 key"),
                          ("ES256K", "requires an EC secp256k1 key")):
        with pytest.raises(ProofError, match=fragment) as exc:
            VcJwtProofSuite._jwk_to_key({}, alg)
        assert type(exc.value) is ProofError
        assert "JWK object" not in str(exc.value)


def test_a_wrong_type_key_object_keeps_its_curve_pin():
    p256 = P256SigningKey.generate(kid="k").public_jwk()
    ed = Ed25519SigningKey.generate(kid="k").public_jwk()
    with pytest.raises(ProofError, match="requires an EC P-384 key"):
        VcJwtProofSuite._jwk_to_key(p256, "ES384")
    with pytest.raises(ProofError, match="requires an OKP Ed25519 key"):
        VcJwtProofSuite._jwk_to_key(p256, "EdDSA")
    with pytest.raises(ProofError, match="requires an EC P-256 key"):
        VcJwtProofSuite._jwk_to_key(ed, "ES256")


# -- the ML-DSA lane never reached _jwk_to_key and was already typed -------- #

@pytest.mark.skipif(not mldsa_available(),
                    reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")
@pytest.mark.parametrize("alg", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
@pytest.mark.parametrize("shape", NOT_AN_OBJECT, ids=NOT_AN_OBJECT_IDS)
def test_ml_dsa_with_a_non_object_jwk_is_a_proof_error(shape, alg):
    # A CONTROL: this lane goes through keys.verify_signature, which turns the TypeError into
    # InvalidKey and the suite into a SignatureInvalid. It was never an AttributeError, and
    # this pins it so a later refactor cannot lose that.
    key = MLDSASigningKey.generate(kid=f"{ISSUER}#k", alg=alg)
    suite = VcJwtProofSuite(allow_pq=True)
    token = suite.sign(CRED, signing_key=key)
    with pytest.raises(SignatureInvalid) as exc:
        suite.verify(token, public_key_jwk=shape)         # type: ignore[arg-type]
    assert isinstance(exc.value, ProofError)
    assert suite.verify(token, public_key_jwk=key.public_jwk()).issuer == ISSUER   # the control


# -- the batch APIs: one bad key is one item's error, never the batch's ----- #

class _Resolver:
    """Resolves ``did:example:good`` to its key and ``did:example:broken`` to a document whose
    verification method carries *broken_jwk*, the shape of a buggy third-party resolver."""

    def __init__(self, good_jwk: dict[str, Any], broken_jwk: Any) -> None:
        self._docs = {
            "did:example:good": self._doc("did:example:good", good_jwk),
            "did:example:broken": self._doc("did:example:broken", broken_jwk),
        }

    @staticmethod
    def _doc(did: str, jwk: Any) -> DidDocument:
        vm = VerificationMethod(f"{did}#k", "JsonWebKey2020", did, jwk)
        return DidDocument(did, [vm], {}, {"assertionMethod": [vm.id]})

    def supports(self, did: str) -> bool:
        return did in self._docs

    def resolve(self, did: str) -> DidDocument:
        if did not in self._docs:
            raise DidResolutionError(f"unknown DID {did!r}")
        return self._docs[did]


class _AsyncResolver:
    def __init__(self, inner: _Resolver) -> None:
        self._inner = inner

    def supports(self, did: str) -> bool:
        return self._inner.supports(did)

    async def resolve(self, did: str) -> DidDocument:
        return self._inner.resolve(did)


def _batch(broken_jwk: Any) -> tuple[list[str], _Resolver]:
    good = P256SigningKey.generate(kid="did:example:good#k")
    broken = P256SigningKey.generate(kid="did:example:broken#k")
    suite = VcJwtProofSuite()

    def cred(did: str) -> dict[str, Any]:
        return {**CRED, "issuer": did}

    tokens = [suite.sign(cred("did:example:good"), signing_key=good),
              suite.sign(cred("did:example:broken"), signing_key=broken),
              suite.sign(cred("did:example:good"), signing_key=good)]
    return tokens, _Resolver(good.public_jwk(), broken_jwk)


@pytest.mark.parametrize("shape", NOT_AN_OBJECT, ids=NOT_AN_OBJECT_IDS)
def test_verify_many_isolates_a_non_object_key(shape):
    tokens, resolver = _batch(shape)
    results = verify_many(tokens, resolver=resolver)
    assert [r.ok for r in results] == [True, False, True]
    error = results[1].error
    assert type(error) is ProofError and "requires a JWK object" in str(error)


@pytest.mark.parametrize("shape", [None, [], "jwk", 7], ids=["null", "list", "str", "int"])
def test_verify_many_async_isolates_a_non_object_key(shape):
    tokens, resolver = _batch(shape)
    results = asyncio.run(verify_many_async(tokens, resolver=_AsyncResolver(resolver)))
    assert [r.ok for r in results] == [True, False, True]
    error = results[1].error
    assert type(error) is ProofError and "requires a JWK object" in str(error)


# -- fuzzing: a key or a ProofError, nothing else, whatever the JSON value -- #

_json_scalar = (st.none() | st.booleans() | st.integers(min_value=-2**300, max_value=2**300)
                | st.floats(allow_nan=True, allow_infinity=True) | st.text(max_size=60))
_json_value = st.recursive(
    _json_scalar,
    lambda kids: st.lists(kids, max_size=4) | st.dictionaries(st.text(max_size=8), kids,
                                                              max_size=4),
    max_leaves=10)
_FUZZ = settings(max_examples=300, deadline=None,
                 suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


@_FUZZ
@given(_json_value, st.sampled_from(ALGS))
def test_any_json_value_as_a_jwk_is_a_key_or_a_proof_error(value, alg):
    try:
        VcJwtProofSuite._jwk_to_key(value, alg)
    except ProofError:
        return
    except OpenvcError as exc:                              # pragma: no cover - hunted
        raise AssertionError(f"{type(exc).__name__}, not a plain ProofError: {exc}") from exc
    except Exception as exc:                                # pragma: no cover - the failure
        raise AssertionError(f"{type(exc).__name__} escaped OpenvcError: {exc}") from exc
