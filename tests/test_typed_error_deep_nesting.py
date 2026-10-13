"""
tests/test_typed_error_deep_nesting.py — a deeply nested JSON value stays inside the
typed-error boundary (#213).

On CPython 3.14 ``json.loads`` accepts about 116k levels of nesting, but ``repr()`` of the
result overflows at about 70k, ``==`` between two such values at about 43k, and a
Python-level walk at about 1000. A value that parsed could therefore raise a bare
``RecursionError`` wherever openvc formatted, compared or walked it. That escaped
``OpenvcError`` and aborted a whole ``verify_many`` batch. The adversarial reviews of
#194 and #214 found more than 40 such sites.

The fix bounds the input, not each site:

* ``openvc._json.loads`` refuses JSON nested deeper than ``MAX_DEPTH`` (100) at every
  untrusted parse, so every wire format fails at the parse, typed, on every interpreter;
* the same bound holds for objects openvc receives already parsed: a credential or a
  ``vp_token`` dict, a Data Integrity suite's input, a DID document or issuer metadata
  from an injected fetch, PyJWT's own claim set, and a relying party's DCQL query;
* a ``RecursionError`` that still reaches the pipeline becomes a typed error (backstop).

Deep values are built in a loop, not through ``json``. Each test asserts the typed class.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import openvc.aio as aio
import openvc.openid4vp as openid4vp
import openvc.verify as verify_mod
from openvc import _json, verify_credential, verify_many, verify_many_async
from openvc.aio import verify_credential_async
from openvc.did.base import DidResolutionError, DidResolverRegistry, parse_did_document
from openvc.did.did_key import DidKeyResolver
from openvc.did.did_web import DidWebResolver
from openvc.jwe import JweMalformed, decrypt_compact
from openvc.jwt_vc_issuer import JwtVcIssuerError, resolve_jwt_vc_issuer_key
from openvc.keys import (
    MLDSASigningKey,
    P256KeyAgreementKey,
    P256SigningKey,
    mldsa_available,
)
from openvc.multibase import encode_multibase
from openvc.openid4vp import VpTokenMalformed, verify_encrypted_vp_response, verify_vp_token
from openvc.proof._verify_common import (
    check_presentation_binding,
    check_validity_window,
    safe_repr,
)
from openvc.proof.data_integrity import DataIntegrityProofSuite
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
from openvc.proof.errors import (
    ClaimsInvalid,
    MalformedTimestamp,
    MalformedToken,
    PresentationBindingError,
    ProofMalformed,
)
from openvc.proof.sd_jwt import SdJwtError, disclosure_digest
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import (
    KeyResolutionFailed,
    UnknownCredentialFormat,
    _resolve_jose_key,
    default_resolver,
)

MAX = _json.MAX_DEPTH
V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
JWT_VC_DCQL = {"credentials": [{"id": "q", "format": "jwt_vc_json"}]}
LDP_VC_DCQL = {"credentials": [{"id": "q", "format": "ldp_vc"}]}

# Just past the bound, and far past what repr() survives on 3.14 (json.loads parses it).
DEPTHS = [pytest.param(MAX + 1, id="just-past-the-bound"),
          pytest.param(100_000, id="100k")]


def _deep(depth: int) -> list:
    """*depth* nested lists, built in a loop (never through json)."""
    deep: list = []
    for _ in range(depth - 1):
        deep = [deep]
    return deep


def _deep_json(depth: int) -> str:
    return "[" * depth + "]" * depth


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _did_key_p256()


def _sign(key, header: dict, payload: str) -> str:
    """A compact JWS over the *payload* text: deep JSON is spliced in as text, because
    ``json.dumps`` of a deep list fails before 3.14."""
    signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(payload.encode())}"
    return f"{signing_input}.{_b64u(key.sign(signing_input.encode()))}"


def _vc_jwt(issuer, *, deep_at: str | None = None, depth: int = 0, extra=None) -> str:
    """A VC-JWT signed by *issuer* (any did:key), with the *deep_at* placeholder string
    replaced by *depth*-deep JSON."""
    key, did = issuer
    now = int(time.time())
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:s"}, **(extra or {})}
    claims = {"iss": did, "sub": "did:example:s", "nbf": now, "iat": now, "vc": vc}
    payload = json.dumps(claims)
    if deep_at is not None:
        payload = payload.replace(json.dumps(deep_at), _deep_json(depth))
    return _sign(key, {"alg": key.alg, "typ": "JWT", "kid": key.kid}, payload)


def _di_doc(suite_id: str, /, **proof) -> dict:
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": "did:example:i",
            "credentialSubject": {"id": "did:example:s"},
            "proof": {"type": "DataIntegrityProof", "cryptosuite": suite_id,
                      "proofPurpose": "assertionMethod",
                      "verificationMethod": "did:example:i#k", "proofValue": "z111",
                      **proof}}


# --------------------------------------------------------------------------- #
# 1. the bounded loader
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("opener, closer", [("[", "]"), ('{"a":', "}")],
                         ids=["arrays", "objects"])
def test_loads_accepts_the_bound_and_refuses_one_past_it(opener, closer):
    def text(depth):
        return opener * depth + "0" + closer * depth
    _json.loads(text(MAX))                                 # exactly the bound: fine
    with pytest.raises(ValueError, match=f"nested deeper than {MAX} levels"):
        _json.loads(text(MAX + 1))


def test_loads_maps_an_unparseable_depth_to_value_error():
    # deeper than any interpreter's json.loads (3.14's bottoms out near 116k)
    with pytest.raises(ValueError, match="too deeply to parse"):
        _json.loads(_deep_json(600_000))


def test_loads_keeps_json_decode_errors():
    with pytest.raises(json.JSONDecodeError):
        _json.loads("{not json")


def test_nesting_exceeds_is_iterative_and_terminates_on_a_cycle():
    assert not _json.nesting_exceeds("x" * 10_000)
    assert not _json.nesting_exceeds(_deep(MAX))
    assert _json.nesting_exceeds(_deep(MAX + 1))
    assert _json.nesting_exceeds(_deep(100_000))            # no recursion on the way
    assert _json.nesting_exceeds((((),),), limit=2)          # tuples count too
    cycle: dict = {}
    cycle["self"] = cycle                                    # Python-built, never JSON
    assert _json.nesting_exceeds(cycle)


# --------------------------------------------------------------------------- #
# 2. every wire format fails at the parse, typed, on every interpreter
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("extra", [
    pytest.param({"issuer": "DEEP"}, id="vc.issuer"),
    pytest.param({"validFrom": "DEEP"}, id="vc.validFrom"),
    # the status entry is parsed on the default pipeline, with no resolver
    pytest.param({"credentialStatus": {
        "type": "BitstringStatusListEntry", "statusListCredential": "https://x.example/1",
        "statusListIndex": "DEEP"}}, id="credentialStatus.statusListIndex"),
])
def test_vc_jwt_deep_claim_is_typed(issuer, depth, extra):
    token = _vc_jwt(issuer, deep_at="DEEP", depth=depth, extra=extra)
    with pytest.raises(MalformedToken):
        verify_credential(token)
    with pytest.raises(MalformedToken):                      # the untrusted peek too
        VcJwtProofSuite().peek_issuer(token)


def test_vc_jwt_suite_holds_pyjwt_claims_to_the_bound(issuer):
    # PyJWT parses the payload itself, past openvc's loader. A depth every interpreter's
    # json.loads accepts, so the post-decode check is what is under test.
    token = _vc_jwt(issuer, deep_at="DEEP", depth=MAX + 20, extra={"x": "DEEP"})
    with pytest.raises(MalformedToken, match="nested deeper than"):
        VcJwtProofSuite().verify(token, public_key_jwk=issuer[0].public_jwk())


def test_vc_jwt_suite_payload_too_deep_to_parse_is_typed(issuer):
    # At the PyJWT 2.13 floor PyJWT's json.loads handler catches only ValueError, so
    # the RecursionError used to escape bare; openvc maps it to MalformedToken. A newer
    # PyJWT maps it to DecodeError itself, which openvc reports as ClaimsInvalid.
    key, did = issuer
    token = _sign(key, {"alg": key.alg, "typ": "JWT"},
                  '{"iss":"%s","x":%s}' % (did, _deep_json(600_000)))
    with pytest.raises((MalformedToken, ClaimsInvalid)):
        VcJwtProofSuite().verify(token, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("depth", DEPTHS)
def test_sd_jwt_deep_disclosure_is_typed(issuer, depth):
    key, did = issuer
    disclosure = _b64u(('["salt","given_name",' + _deep_json(depth) + "]").encode())
    payload = json.dumps({"iss": did, "vct": "urn:example:vct", "iat": int(time.time()),
                          "_sd": [disclosure_digest(disclosure)], "_sd_alg": "sha-256"})
    sd_jwt = _sign(key, {"alg": key.alg, "typ": "dc+sd-jwt", "kid": key.kid},
                   payload) + f"~{disclosure}~"
    with pytest.raises(SdJwtError, match="disclosure"):
        verify_credential(sd_jwt)


@pytest.mark.parametrize("depth", DEPTHS)
def test_vp_jwt_deep_aud_is_typed(depth):
    holder_key, holder_did = _did_key_p256()
    now = int(time.time())
    payload = json.dumps({"iss": holder_did, "aud": "DEEP", "nonce": NONCE, "nbf": now,
                          "vp": {"holder": holder_did}}).replace('"DEEP"', _deep_json(depth))
    vp = _sign(holder_key, {"alg": holder_key.alg, "typ": "JWT", "kid": holder_key.kid},
               payload)
    with pytest.raises(MalformedToken):
        VpJwtProofSuite().verify(vp, audience=CLIENT_ID, nonce=NONCE)
    with pytest.raises(MalformedToken):
        verify_vp_token({"q": [vp]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)


@pytest.mark.parametrize("depth", DEPTHS)
def test_did_jwk_deep_key_member_is_typed(depth):
    # before any crypto: the issuer's own did:jwk carries the deep `kty`
    jwk = '{"kty":' + _deep_json(depth) + ',"crv":"P-256","x":"AA","y":"AA"}'
    did = "did:jwk:" + _b64u(jwk.encode())
    token = _sign(P256SigningKey.generate(kid="_"), {"alg": "ES256", "kid": did + "#0"},
                  json.dumps({"iss": did, "nbf": int(time.time()),
                              "vc": {"issuer": did, "credentialSubject": {}}}))
    with pytest.raises(KeyResolutionFailed):
        verify_credential(token)


@pytest.mark.parametrize("depth", DEPTHS)
def test_jwe_deep_protected_header_is_typed(depth):
    # before decryption, on the HAIP direct_post.jwt entry point
    token = _b64u(('{"alg":' + _deep_json(depth) + ',"enc":"A128GCM"}').encode())
    token += "..AAAA.AAAA.AAAA"
    key = P256KeyAgreementKey.generate(kid="k")
    with pytest.raises(JweMalformed, match="nested"):
        decrypt_compact(token, key=key)
    with pytest.raises(JweMalformed):
        verify_encrypted_vp_response(token, key=key, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                                     client_id=CLIENT_ID)


@pytest.mark.parametrize("depth", DEPTHS)
def test_enveloped_deep_payload_is_typed(depth):
    env = {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
           "id": "data:application/vc+ld+json," + '{"a":' + _deep_json(depth) + "}"}
    with pytest.raises(UnknownCredentialFormat, match="nested deeper than"):
        verify_credential(env)


@pytest.mark.parametrize("depth", DEPTHS)
def test_vp_token_json_string_deep_is_typed(depth):
    with pytest.raises(VpTokenMalformed, match="nested"):
        verify_vp_token('{"q":' + _deep_json(depth) + "}", dcql_query=JWT_VC_DCQL,
                        nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# 3. objects openvc receives already parsed
# --------------------------------------------------------------------------- #

WHOLE_DOCUMENT_SUITES = [
    pytest.param("eddsa-jcs-2022", EddsaJcsProofSuite, id="eddsa-jcs-2022"),
    pytest.param("ecdsa-jcs-2019", EcdsaJcsProofSuite, id="ecdsa-jcs-2019"),
    pytest.param("eddsa-rdfc-2022", DataIntegrityProofSuite, id="eddsa-rdfc-2022"),
    pytest.param("ecdsa-rdfc-2019", EcdsaRdfcProofSuite, id="ecdsa-rdfc-2019"),
]


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("suite_id, suite", WHOLE_DOCUMENT_SUITES)
def test_di_dict_deep_value_is_typed(suite_id, suite, depth):
    doc = _di_doc(suite_id, type=_deep(depth))
    with pytest.raises(UnknownCredentialFormat, match="nested deeper than"):
        verify_credential(doc)
    with pytest.raises(ProofMalformed, match="nested deeper than"):
        suite().verify(doc)


@pytest.mark.parametrize("depth", DEPTHS)
def test_ecdsa_sd_suite_deep_value_is_typed(depth):
    with pytest.raises(ProofMalformed, match="nested deeper than"):
        EcdsaSdProofSuite().verify(_di_doc("ecdsa-sd-2023", cryptosuite=_deep(depth)))


@pytest.mark.parametrize("depth", DEPTHS)
def test_verify_credential_async_deep_dict_is_typed(depth):
    doc = _di_doc("eddsa-jcs-2022", type=_deep(depth))
    with pytest.raises(UnknownCredentialFormat, match="nested deeper than"):
        asyncio.run(verify_credential_async(doc))


@pytest.mark.parametrize("depth", DEPTHS)
def test_vp_token_dict_deep_is_typed(depth):
    # e.g. the LDP-VP proof.domain the DC API lane peeks before any signature check
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],
          "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                    "domain": _deep(depth)}}
    with pytest.raises(VpTokenMalformed, match="nested deeper than"):
        verify_vp_token({"q": [vp]}, dcql_query=LDP_VC_DCQL, nonce=NONCE,
                        expected_origins=["https://verifier.example.org"])


def test_injected_fetch_did_document_is_held_to_the_bound(issuer):
    # an injected fetch returns the DID document already parsed (did:web from the
    # attacker's own host on the default resolver)
    with pytest.raises(DidResolutionError, match="nested deeper than"):
        parse_did_document({"id": _deep(100_000)})
    registry = DidResolverRegistry([DidKeyResolver(), DidWebResolver(
        lambda url: {"id": _deep(100_000)})])
    did = "did:web:evil.example"
    token = _sign(issuer[0], {"alg": "ES256", "kid": did + "#k"},
                  json.dumps({"iss": did, "nbf": int(time.time()),
                              "vc": {"credentialSubject": {}}}))
    with pytest.raises(KeyResolutionFailed, match="nested deeper than"):
        verify_credential(token, resolver=registry)


@pytest.mark.parametrize("metadata", [
    pytest.param(lambda: {"issuer": _deep(100_000)}, id="metadata"),
    pytest.param(lambda: {"issuer": "https://issuer.example",
                          "jwks": {"keys": [{"kid": _deep(100_000)}]}}, id="jwks"),
])
def test_injected_fetch_issuer_metadata_is_held_to_the_bound(metadata):
    with pytest.raises(JwtVcIssuerError, match="nested deeper than"):
        resolve_jwt_vc_issuer_key("https://issuer.example", "k",
                                  fetch=lambda url: metadata())


# --------------------------------------------------------------------------- #
# 4. the backstop: a RecursionError that still reaches the pipeline is typed
# --------------------------------------------------------------------------- #

def _raise_recursion(*args, **kwargs):
    raise RecursionError("maximum recursion depth exceeded")


async def _raise_recursion_async(*args, **kwargs):
    raise RecursionError("maximum recursion depth exceeded")


def test_backstop_maps_a_recursion_error_in_the_pipeline(issuer, monkeypatch):
    good = _vc_jwt(issuer)
    monkeypatch.setattr(verify_mod, "_verify_by_format", _raise_recursion)
    with pytest.raises(UnknownCredentialFormat, match="too deeply to verify"):
        verify_credential(good)
    (result,) = verify_many([good])
    assert isinstance(result.error, UnknownCredentialFormat)


def test_backstop_maps_a_recursion_error_in_the_async_pipeline(issuer, monkeypatch):
    monkeypatch.setattr(aio, "_verify_by_format_async", _raise_recursion_async)
    (result,) = asyncio.run(verify_many_async([_vc_jwt(issuer)]))
    assert isinstance(result.error, UnknownCredentialFormat)


def test_backstop_maps_a_recursion_error_in_verify_vp_token(monkeypatch):
    monkeypatch.setattr(openid4vp, "_verify_one", _raise_recursion)
    with pytest.raises(VpTokenMalformed, match="too deeply to verify"):
        verify_vp_token({"q": ["a.b.c"]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# 5. one hostile item never aborts a batch; the bound rejects nothing real
# --------------------------------------------------------------------------- #

def _batch(issuer):
    good = _vc_jwt(issuer)
    return [good,
            _di_doc("eddsa-jcs-2022", type=_deep(100_000)),
            _vc_jwt(issuer, deep_at="DEEP", depth=100_000, extra={"issuer": "DEEP"}),
            _vc_jwt(issuer, deep_at="DEEP", depth=100_000, extra={"credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusListCredential": "https://x.example/1", "statusListIndex": "DEEP"}}),
            good]


def _assert_batch(results):
    assert [r.ok for r in results] == [True, False, False, False, True]
    assert isinstance(results[1].error, UnknownCredentialFormat)
    assert isinstance(results[2].error, MalformedToken)
    assert isinstance(results[3].error, MalformedToken)


def test_verify_many_isolates_deeply_nested_items(issuer):
    _assert_batch(verify_many(_batch(issuer)))


def test_verify_many_async_isolates_deeply_nested_items(issuer):
    _assert_batch(asyncio.run(verify_many_async(_batch(issuer))))


def test_a_credential_at_exactly_the_bound_still_verifies(issuer):
    # payload (1) > vc (2) > credentialSubject (3) > "data" (4 .. MAX)
    token = _vc_jwt(issuer, deep_at="DEEP", depth=MAX - 3,
                    extra={"credentialSubject": {"id": "did:example:s", "data": "DEEP"}})
    result = verify_credential(token)
    assert _json.nesting_exceeds(result.claims, MAX - 1)
    assert not _json.nesting_exceeds(result.claims, MAX)


# --------------------------------------------------------------------------- #
# 6. defence in depth: the messages never repr() a container
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value, shown", [
    pytest.param("ES256", "'ES256'", id="str"), pytest.param(None, "None", id="null"),
    pytest.param(True, "True", id="bool"), pytest.param(1.5, "1.5", id="float"),
    pytest.param(-7, "-7", id="int"), pytest.param({"a": 1}, "dict", id="object"),
    pytest.param([1], "list", id="array"),
    # repr() of a >4300-digit int raises ValueError (the int-to-str limit)
    pytest.param(10 ** 5000, "int", id="bignum"),
])
def test_safe_repr_shows_only_bounded_scalars(value, shown):
    assert safe_repr(value) == shown


def test_safe_repr_names_a_deep_container_and_cuts_a_long_string():
    assert safe_repr(_deep(100_000)) == "list"
    shown = safe_repr("x" * 10_000)
    assert shown.startswith("'xxx") and shown.endswith("... (10000 chars)")
    assert len(shown) < 300


@pytest.mark.parametrize("field", ["validFrom", "validUntil"])
def test_deep_validity_bound_message_is_typed(field):
    with pytest.raises(MalformedTimestamp, match=f"{field} is not a valid dateTime: list"):
        check_validity_window({field: _deep(100_000)}, {}, now=None, leeway_s=60)


@pytest.mark.parametrize("member, kwargs", [
    ("challenge", {"expected_challenge": NONCE, "expected_domain": None}),
    ("domain", {"expected_challenge": None, "expected_domain": CLIENT_ID}),
])
def test_deep_presentation_binding_message_is_typed(member, kwargs):
    with pytest.raises(PresentationBindingError, match="list"):
        check_presentation_binding({member: _deep(100_000)}, **kwargs)


def test_reconcile_message_names_a_container_by_type(issuer):
    with pytest.raises(ClaimsInvalid, match="vc.issuer list"):
        VcJwtProofSuite._reconcile({"iss": issuer[1]}, {"issuer": _deep(100_000)})


def test_resolve_jose_key_message_cuts_the_did_and_names_the_kid(issuer):
    with pytest.raises(KeyResolutionFailed, match="kid list"):
        _resolve_jose_key(default_resolver(), issuer[1], _deep(100_000))
    long_did = "did:jwk:" + "A" * 5_000
    with pytest.raises(KeyResolutionFailed) as excinfo:
        _resolve_jose_key(default_resolver(), long_did, None)
    assert "(5008 chars)" in str(excinfo.value)


def test_vp_jwt_peek_holder_rejects_a_non_string_kid():
    holder_key, holder_did = _did_key_p256()
    vp = _sign(holder_key, {"alg": "ES256", "kid": 5},
               json.dumps({"iss": holder_did, "aud": CLIENT_ID, "nonce": NONCE}))
    with pytest.raises(MalformedToken, match="kid must be a string"):
        VpJwtProofSuite().peek_holder(vp)


@pytest.mark.skipif(not mldsa_available(), reason="ML-DSA needs OpenSSL >= 3.5")
@pytest.mark.parametrize("claim, message", [("sub", "Subject must be a string"),
                                            ("jti", "JWT ID must be a string")])
def test_mldsa_lane_rejects_a_non_string_sub_or_jti_like_pyjwt(issuer, claim, message):
    # PyJWT parity, so _reconcile never compares two attacker containers with !=
    now = int(time.time())
    claims = {"iss": "did:example:i", "nbf": now, claim: [5], "vc": {}}
    key = MLDSASigningKey.generate(kid="k")
    pq = _sign(key, {"alg": key.alg, "typ": "JWT"}, json.dumps(claims))
    with pytest.raises(ClaimsInvalid, match=message):
        VcJwtProofSuite(allow_pq=True).verify(pq, public_key_jwk=key.public_jwk())
    es = _sign(issuer[0], {"alg": issuer[0].alg, "typ": "JWT"}, json.dumps(claims))
    with pytest.raises(ClaimsInvalid, match=message):
        VcJwtProofSuite().verify(es, public_key_jwk=issuer[0].public_jwk())
