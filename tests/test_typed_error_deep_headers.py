"""
tests/test_typed_error_deep_headers.py — a deeply nested array where a string is
expected stays typed, and the message names it by type (#208).

``test_typed_error_unhashable_header.py`` pins a JSON array or object in the ``alg`` /
``typ`` / ``_sd_alg`` / ``cryptosuite`` slots, and sends a ~100k-level array through the
header lanes. Since #213 that deep array is refused where it enters, at the JSON parse,
as ``MalformedToken``. It never reaches the lane's own allow-list check, so the
``safe_repr`` in that lane's message is not exercised, and on every interpreter but
CPython 3.14 the shape does not even parse.

Here the array is **90 levels deep**: under the loader cap
(``openvc._json.MAX_DEPTH``, 100; the header object itself is level 1), so it parses on
every interpreter in the matrix and **reaches the lane's own check**. Two things tell
that apart from a parse refusal:

* the exact typed class of the lane (a refusal at the parse is ``MalformedToken``);
* the message, which names the value as ``list``. A ``!r`` in its place would quote all
  90 levels, and on CPython 3.14 a 70k-level array would overflow the stack in
  ``repr()``. ``repr()`` of this one is fine, so the message is the only observable.

Every issuer is a resolvable ``did:key``, so no test can pass on an earlier key-resolution
failure. Tokens carry a junk signature unless the lane sits behind the signature check
(``_sd_alg`` and the KB-JWT ``alg`` are issuer-signed, by a key any ``did:key`` provides).
"""
from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import verify_credential, verify_many, verify_many_async
from openvc._json import MAX_DEPTH, loads
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vci import verify_credential_request_proofs
from openvc.openid4vp import UnsupportedPresentationFormat, verify_vp_token
from openvc.proof._jws import sign_compact, verify_compact
from openvc.proof.errors import ClaimsInvalid, MalformedToken, UnsupportedAlgorithm
from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.status import verify_status_list_token
from openvc.verify import VerificationPolicy

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
CREDENTIAL_ISSUER = "https://issuer.example.org"
VCT = "https://credentials.example.com/identity_credential"
JWT_VC_DCQL = {"credentials": [{"id": "q", "format": "jwt_vc_json"}]}
LDP_VC_DCQL = {"credentials": [{"id": "q", "format": "ldp_vc"}]}
SD_JWT_DCQL = {"credentials": [{"id": "q", "format": "dc+sd-jwt"}]}

DEPTH = 90
assert DEPTH < MAX_DEPTH - 1        # the dict holding the array is level 1: room to spare


def _deep(depth: int = DEPTH) -> list:
    """An array nested *depth* levels, built in a loop (never through ``json``)."""
    value: list = []
    for _ in range(depth - 1):
        value = [value]
    return value


def _assert_names_the_type(exc: BaseException, cls: type, message: str) -> None:
    """The exact class, the lane's own message with ``list`` in the value's place, and
    no quoted brackets: the value reached the lane and was not ``repr``-ed."""
    assert type(exc) is cls, f"{type(exc).__name__}: {exc}"
    assert message in str(exc), str(exc)
    assert "[[" not in str(exc), str(exc)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _seg(obj) -> str:
    return _b64url(json.dumps(obj).encode())


def _unsigned(header, payload) -> str:
    """A compact JWS with a junk signature: every check here precedes the crypto."""
    return f"{_seg(header)}.{_seg(payload)}.AAAA"


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did): resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _did_key_p256()


@pytest.fixture(scope="module")
def holder():
    return _did_key_p256()


def _vc_claims(issuer_did):
    now = int(time.time())
    return {"iss": issuer_did, "sub": "did:example:s", "nbf": now, "iat": now,
            "vc": {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer_did,
                   "credentialSubject": {"id": "did:example:s"}}}


def _vc_jwt(issuer):
    issuer_key, issuer_did = issuer
    return sign_compact({"alg": issuer_key.alg, "typ": "JWT", "kid": issuer_key.kid},
                        _vc_claims(issuer_did), signing_key=issuer_key)


def _vc_jwt_with_alg(issuer, alg):
    issuer_key, issuer_did = issuer
    return _unsigned({"alg": alg, "typ": "JWT", "kid": issuer_key.kid}, _vc_claims(issuer_did))


def _vp_claims(holder_did):
    now = int(time.time())
    return {"iss": holder_did, "aud": CLIENT_ID, "nonce": NONCE, "nbf": now, "iat": now,
            "vp": {"@context": [V2], "type": ["VerifiablePresentation"],
                   "holder": holder_did, "verifiableCredential": []}}


def _sd_jwt_with_header(issuer, **header):
    """An unsigned SD-JWT issuer JWT whose header fields are overridden by *header*."""
    issuer_key, issuer_did = issuer
    base = {"alg": issuer_key.alg, "typ": "dc+sd-jwt", "kid": issuer_key.kid}
    payload = {"iss": issuer_did, "vct": VCT, "iat": int(time.time())}
    return _unsigned({**base, **header}, payload) + "~"


def _sd_jwt_signed(issuer, **claims):
    """A properly signed SD-JWT issuer JWT carrying *claims* verbatim, no disclosures."""
    issuer_key, issuer_did = issuer
    payload = {"iss": issuer_did, "vct": VCT, "iat": int(time.time()), **claims}
    return sign_compact({"alg": issuer_key.alg, "typ": "dc+sd-jwt", "kid": issuer_key.kid},
                        payload, signing_key=issuer_key) + "~"


def _sd_jwt_with_kb_alg(issuer, holder, alg):
    """A holder-bound SD-JWT, correctly issuer-signed, whose KB-JWT ``alg`` is *alg*."""
    issued = _sd_jwt_signed(issuer, cnf={"jwk": holder[0].public_jwk()})
    kb = _unsigned({"alg": alg, "typ": "kb+jwt"},
                   {"iat": int(time.time()), "aud": CLIENT_ID, "nonce": NONCE,
                    "sd_hash": "x"})
    return issued + kb


def _good_sd_jwt_presentation(issuer, holder):
    issuer_key, issuer_did = issuer
    suite = SdJwtVcProofSuite()
    issued = suite.issue({"iss": issuer_did, "given_name": "Ada"}, signing_key=issuer_key,
                         vct=VCT, disclosable=["given_name"],
                         holder_jwk=holder[0].public_jwk())
    return suite.create_presentation(issued, holder_key=holder[0],
                                     audience=CLIENT_ID, nonce=NONCE)


# --------------------------------------------------------------------------- #
# controls: the shape is reachable and the fixtures are sound
# --------------------------------------------------------------------------- #

def test_the_deep_array_is_under_the_loader_cap_and_one_past_it_is_not():
    # the tests below only mean something if the value survives the parse
    assert loads(json.dumps({"alg": _deep()})) == {"alg": _deep()}
    with pytest.raises(ValueError, match="nested deeper than"):
        loads(json.dumps({"alg": _deep(MAX_DEPTH)}))


def test_past_the_cap_the_lane_is_never_reached(issuer):
    # the contrast: one level too deep is refused at the parse, as MalformedToken
    with pytest.raises(MalformedToken) as caught:
        VcJwtProofSuite().verify(_vc_jwt_with_alg(issuer, _deep(MAX_DEPTH)),
                                 public_key_jwk={})
    assert type(caught.value) is MalformedToken
    assert "algorithm" not in str(caught.value)       # the allow-list never ran


def test_well_formed_tokens_still_verify(issuer, holder):
    assert verify_credential(_vc_jwt(issuer)).issuer == issuer[1]
    result = SdJwtVcProofSuite().verify(
        _good_sd_jwt_presentation(issuer, holder), public_key_jwk=issuer[0].public_jwk(),
        audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    assert result.key_bound


# --------------------------------------------------------------------------- #
# VC-JWT
# --------------------------------------------------------------------------- #

def test_vc_jwt_deep_alg_is_named_by_type(issuer):
    with pytest.raises(UnsupportedAlgorithm) as caught:
        VcJwtProofSuite().verify(_vc_jwt_with_alg(issuer, _deep()), public_key_jwk={})
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


def test_vc_jwt_pipeline_deep_alg_is_named_by_type(issuer):
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_credential(_vc_jwt_with_alg(issuer, _deep()))
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


# --------------------------------------------------------------------------- #
# SD-JWT VC: issuer alg and typ, _sd_alg, KB-JWT alg
# --------------------------------------------------------------------------- #

def test_sd_jwt_deep_issuer_alg_is_named_by_type(issuer):
    token = _sd_jwt_with_header(issuer, alg=_deep())
    for call in (lambda: SdJwtVcProofSuite().verify(token, public_key_jwk={}),
                 lambda: verify_credential(token)):
        with pytest.raises(UnsupportedAlgorithm) as caught:
            call()
        _assert_names_the_type(caught.value, UnsupportedAlgorithm,
                               "algorithm list is not permitted")


def test_sd_jwt_deep_issuer_typ_is_named_by_type(issuer):
    token = _sd_jwt_with_header(issuer, typ=_deep())
    for call in (lambda: SdJwtVcProofSuite().verify(token, public_key_jwk={}),
                 lambda: verify_credential(token)):
        with pytest.raises(SdJwtError) as caught:
            call()
        _assert_names_the_type(caught.value, SdJwtError, "unexpected issuer JWT typ list")


def test_sd_jwt_deep_sd_alg_is_named_by_type(issuer):
    # issuer-signed, so past the signature check; any did:key can make it
    token = _sd_jwt_signed(issuer, _sd_alg=_deep())
    for call in (lambda: SdJwtVcProofSuite().verify(
                     token, public_key_jwk=issuer[0].public_jwk()),
                 lambda: verify_credential(token)):
        with pytest.raises(SdJwtError) as caught:
            call()
        _assert_names_the_type(caught.value, SdJwtError, "unsupported _sd_alg list")


def test_sd_jwt_deep_kb_jwt_alg_is_named_by_type(issuer, holder):
    token = _sd_jwt_with_kb_alg(issuer, holder, _deep())
    with pytest.raises(UnsupportedAlgorithm) as caught:
        SdJwtVcProofSuite().verify(
            token, public_key_jwk=issuer[0].public_jwk(), audience=CLIENT_ID,
            nonce=NONCE, require_key_binding=True)
    _assert_names_the_type(caught.value, UnsupportedAlgorithm,
                           "KB-JWT algorithm list is not permitted")


def test_dc_sd_jwt_presentation_deep_kb_jwt_alg_is_named_by_type(issuer, holder):
    token = _sd_jwt_with_kb_alg(issuer, holder, _deep())
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_vp_token({"q": [token]}, dcql_query=SD_JWT_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)
    _assert_names_the_type(caught.value, UnsupportedAlgorithm,
                           "KB-JWT algorithm list is not permitted")


# --------------------------------------------------------------------------- #
# proof._jws.verify_compact: direct, VP-JWT (suite and OpenID4VP) and the status-list token
# --------------------------------------------------------------------------- #

def test_verify_compact_deep_alg_is_named_by_type(issuer):
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_compact(_vc_jwt_with_alg(issuer, _deep()), public_key_jwk={})
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


def test_vp_jwt_suite_deep_alg_is_named_by_type(holder):
    holder_key, holder_did = holder
    token = _unsigned({"alg": _deep(), "typ": "JWT", "kid": holder_key.kid},
                      _vp_claims(holder_did))
    with pytest.raises(UnsupportedAlgorithm) as caught:
        VpJwtProofSuite().verify(token, audience=CLIENT_ID, nonce=NONCE)
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


def test_jwt_vc_json_vp_token_deep_alg_is_named_by_type(holder):
    holder_key, holder_did = holder
    token = _unsigned({"alg": _deep(), "typ": "JWT", "kid": holder_key.kid},
                      _vp_claims(holder_did))
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_vp_token({"q": [token]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


def test_jwt_vc_json_nested_vc_deep_alg_is_named_by_type(issuer, holder):
    # the VP is correctly holder-signed; the embedded VC-JWT carries the hostile alg
    holder_key, holder_did = holder
    claims = _vp_claims(holder_did)
    claims["vp"]["verifiableCredential"] = [_vc_jwt_with_alg(issuer, _deep())]
    vp = sign_compact({"alg": holder_key.alg, "typ": "JWT", "kid": holder_key.kid},
                      claims, signing_key=holder_key)
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_vp_token({"q": [vp]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


def test_status_list_token_deep_alg_is_named_by_type():
    token = _unsigned({"alg": _deep(), "typ": "statuslist+jwt"},
                      {"sub": "https://status.example/1", "iat": int(time.time())})
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_status_list_token(token, public_key_jwk={})
    _assert_names_the_type(caught.value, UnsupportedAlgorithm, "algorithm list is not permitted")


# --------------------------------------------------------------------------- #
# OpenID4VCI key proof: typ and alg
# --------------------------------------------------------------------------- #

def _key_proof_request(holder, **header):
    proof = _unsigned({"alg": "ES256", "typ": "openid4vci-proof+jwt",
                       "jwk": holder[0].public_jwk(), **header},
                      {"aud": CREDENTIAL_ISSUER, "iat": int(time.time()), "nonce": "c"})
    return {"credential_configuration_id": "x", "proofs": {"jwt": [proof]}}


def test_openid4vci_deep_proof_typ_is_named_by_type(holder):
    with pytest.raises(ClaimsInvalid) as caught:
        verify_credential_request_proofs(
            _key_proof_request(holder, typ=_deep()), credential_issuer=CREDENTIAL_ISSUER,
            require_nonce=False)
    _assert_names_the_type(caught.value, ClaimsInvalid,
                           "key proof typ must be openid4vci-proof+jwt, got list")


def test_openid4vci_deep_proof_alg_is_named_by_type(holder):
    with pytest.raises(UnsupportedAlgorithm) as caught:
        verify_credential_request_proofs(
            _key_proof_request(holder, alg=_deep()), credential_issuer=CREDENTIAL_ISSUER,
            require_nonce=False)
    _assert_names_the_type(caught.value, UnsupportedAlgorithm,
                           "key proof alg list is not allow-listed")


# --------------------------------------------------------------------------- #
# OpenID4VP ldp_vc: the holder proof's cryptosuite
# --------------------------------------------------------------------------- #

def test_ldp_vc_deep_cryptosuite_is_named_by_type():
    # the vp_token is held to the same cap, with the cryptosuite five levels in
    # ({"q": [ {proof: {cryptosuite: <array>}} ]}), so the array has 4 fewer levels to give
    holder_did = _did_key_p256()[1]
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": holder_did,
          "verifiableCredential": [{}],
          "proof": {"type": "DataIntegrityProof", "cryptosuite": _deep(MAX_DEPTH - 4),
                    "proofPurpose": "authentication", "challenge": NONCE,
                    "domain": CLIENT_ID}}
    with pytest.raises(UnsupportedPresentationFormat) as caught:
        verify_vp_token({"q": [vp]}, dcql_query=LDP_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)
    _assert_names_the_type(caught.value, UnsupportedPresentationFormat,
                           "unsupported Data Integrity cryptosuite list")


# --------------------------------------------------------------------------- #
# the batch APIs: one deep-array item per lane never aborts the call
# --------------------------------------------------------------------------- #

def _deep_batch(issuer):
    """Signed VC-JWT controls around one deep-array item per unauthenticated lane."""
    good = _vc_jwt(issuer)
    return [
        good,
        _vc_jwt_with_alg(issuer, _deep()),                     # VC-JWT alg
        _sd_jwt_with_header(issuer, alg=_deep()),              # SD-JWT issuer alg
        _sd_jwt_with_header(issuer, typ=_deep()),              # SD-JWT issuer typ
        _sd_jwt_signed(issuer, _sd_alg=_deep()),               # SD-JWT _sd_alg
        good,
    ]


_BATCH_ERRORS = [None, UnsupportedAlgorithm, UnsupportedAlgorithm, SdJwtError, SdJwtError,
                 None]
_BATCH_MESSAGES = [None, "algorithm list is not permitted", "algorithm list is not permitted",
                   "unexpected issuer JWT typ list", "unsupported _sd_alg list", None]


def _assert_deep_batch(results):
    assert [r.index for r in results] == list(range(6))
    assert [r.ok for r in results] == [True, False, False, False, False, True]
    for result, cls, message in zip(results, _BATCH_ERRORS, _BATCH_MESSAGES):
        if cls is None:
            assert result.error is None
        else:
            _assert_names_the_type(result.error, cls, message)


def test_verify_many_isolates_deep_array_items(issuer):
    _assert_deep_batch(verify_many(_deep_batch(issuer)))


def test_verify_many_async_isolates_deep_array_items(issuer):
    _assert_deep_batch(asyncio.run(verify_many_async(_deep_batch(issuer))))


def test_verify_many_isolates_a_deep_kb_jwt_alg(issuer, holder):
    policy = VerificationPolicy(audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    good = _good_sd_jwt_presentation(issuer, holder)
    batch = [good, _sd_jwt_with_kb_alg(issuer, holder, _deep()), good]
    for results in (verify_many(batch, policy=policy),
                    asyncio.run(verify_many_async(batch, policy=policy))):
        assert [r.ok for r in results] == [True, False, True]
        _assert_names_the_type(results[1].error, UnsupportedAlgorithm,
                               "KB-JWT algorithm list is not permitted")
