"""
tests/test_typed_error_unhashable_header.py — an unhashable JOSE ``alg`` / ``typ``, an
SD-JWT ``_sd_alg`` or a Data Integrity ``cryptosuite`` stays inside the typed-error
boundary.

Found by the adversarial review of #194. Eight allow-list checks ran
``value not in <frozenset / dict>`` on an attacker-controlled value without first
checking that it was a string. A JSON array or object is unhashable, so the
membership test raised a bare ``TypeError`` that escaped ``OpenvcError``. One such
item aborted a whole ``verify_many`` / ``verify_many_async`` batch instead of becoming
that item's ``error``. None of them needs a trusted key. Most run before any
signature check. The rest need only a signature any ``did:key`` can make:

* the ``alg`` of a VC-JWT (``VcJwtProofSuite``) and of every token verified through
  ``proof._jws.verify_compact``: VP-JWT, the status-list token, the OpenID4VCI key proof;
* the SD-JWT issuer JWT's ``alg`` and ``typ``, and the KB-JWT's ``alg`` (checked after
  the issuer signature);
* the SD-JWT ``_sd_alg`` (issuer-signed);
* the OpenID4VP ``ldp_vc`` holder proof's ``cryptosuite``;
* the OpenID4VCI key proof's ``typ`` and ``alg``.

Each test asserts the **typed class** a well-formed but disallowed value already got,
not just ``OpenvcError``. The error messages also name a container by its type: a
deeply nested array that ``json.loads`` accepts on Python 3.14 overflows ``repr()``.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import verify_credential, verify_many, verify_many_async
from openvc.jwe import JweMalformed, decrypt_compact
from openvc.keys import Ed25519SigningKey, P256KeyAgreementKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vci import verify_credential_request_proofs
from openvc.openid4vp import UnsupportedPresentationFormat, VpTokenMalformed, verify_vp_token
from openvc.proof._jws import sign_compact
from openvc.proof._verify_common import safe_repr
from openvc.proof.errors import ClaimsInvalid, MalformedToken, UnsupportedAlgorithm
from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.rp_registration import RpRegistrationError, parse_rp_registration_certificate
from openvc.status import verify_status_list_token
from openvc.trustlist.errors import TrustListParseError
from openvc.trustlist.lote import consume_lote
from openvc.verify import VerificationPolicy

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
CREDENTIAL_ISSUER = "https://issuer.example.org"
VCT = "https://credentials.example.com/identity_credential"
JWT_VC_DCQL = {"credentials": [{"id": "q", "format": "jwt_vc_json"}]}
LDP_VC_DCQL = {"credentials": [{"id": "q", "format": "ldp_vc"}]}
SD_JWT_DCQL = {"credentials": [{"id": "q", "format": "dc+sd-jwt"}]}

# Unhashable JSON values. Each holds an allowed value, so a test also fails if a fix
# unwrapped the container instead of rejecting it.
UNHASHABLE = [
    pytest.param(["ES256"], id="array"),
    pytest.param({"ES256": True}, id="object"),
    pytest.param([], id="empty-array"),
]


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


def _did_key_ed25519():
    key = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())   # ed25519-pub
    return Ed25519SigningKey(key._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


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


def _vp_claims(holder_did, vcs):
    now = int(time.time())
    return {"iss": holder_did, "aud": CLIENT_ID, "nonce": NONCE, "nbf": now, "iat": now,
            "vp": {"@context": [V2], "type": ["VerifiablePresentation"],
                   "holder": holder_did, "verifiableCredential": vcs}}


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


def _deep_json_array(depth: int = 100_000) -> str:
    return "[" * depth + "]" * depth


# openvc's JSON loader refuses nesting past openvc._json.MAX_DEPTH (#213), so a deep
# header fails at the parse with a typed error on every interpreter. (json.loads alone
# accepts ~116k levels on Python 3.14, where repr() of the result overflows.)


def _deep_header_token(header_prefix: str, *, rest: str = "") -> str:
    """A compact JWS whose header is ``{<header_prefix>"alg": <deep array>}``."""
    header = "{" + header_prefix + '"alg":' + _deep_json_array() + "}"
    return f"{_b64url(header.encode())}.{_seg({'iss': 'did:example:i'})}.AAAA{rest}"


# --------------------------------------------------------------------------- #
# VC-JWT (`VcJwtProofSuite.verify`)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", UNHASHABLE)
def test_vc_jwt_suite_unhashable_alg_is_typed(issuer, alg):
    with pytest.raises(UnsupportedAlgorithm, match="is not permitted"):
        VcJwtProofSuite().verify(_vc_jwt_with_alg(issuer, alg), public_key_jwk={})


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_vc_jwt_pipeline_unhashable_alg_is_typed(issuer, alg):
    with pytest.raises(UnsupportedAlgorithm):
        verify_credential(_vc_jwt_with_alg(issuer, alg))


def test_vc_jwt_unhashable_alg_message_names_the_type(issuer):
    with pytest.raises(UnsupportedAlgorithm, match="algorithm list is not permitted"):
        VcJwtProofSuite().verify(_vc_jwt_with_alg(issuer, ["ES256"]), public_key_jwk={})


def test_vc_jwt_deeply_nested_alg_is_typed():
    token = _deep_header_token('"kid":"did:example:i#k",')
    with pytest.raises(MalformedToken):
        VcJwtProofSuite().verify(token, public_key_jwk={})


# --------------------------------------------------------------------------- #
# the batch APIs: one hostile item no longer aborts the call
# --------------------------------------------------------------------------- #

def _hostile_batch(issuer):
    """Signed VC-JWT controls around one item per unauthenticated pipeline lane."""
    good = _vc_jwt(issuer)
    return [
        good,
        _vc_jwt_with_alg(issuer, ["ES256"]),                  # VC-JWT alg
        _sd_jwt_with_header(issuer, alg={"ES256": True}),     # SD-JWT issuer alg
        _sd_jwt_with_header(issuer, typ=["dc+sd-jwt"]),       # SD-JWT issuer typ
        _sd_jwt_signed(issuer, _sd_alg=["sha-256"]),          # SD-JWT _sd_alg
        good,
    ]


_BATCH_ERRORS = [None, UnsupportedAlgorithm, UnsupportedAlgorithm, SdJwtError, SdJwtError,
                 None]


def test_verify_many_isolates_unhashable_header_values(issuer):
    results = verify_many(_hostile_batch(issuer))
    assert [r.ok for r in results] == [True, False, False, False, False, True]
    assert [type(r.error) if r.error else None for r in results] == _BATCH_ERRORS


def test_verify_many_async_isolates_unhashable_header_values(issuer):
    results = asyncio.run(verify_many_async(_hostile_batch(issuer)))
    assert [r.ok for r in results] == [True, False, False, False, False, True]
    assert [type(r.error) if r.error else None for r in results] == _BATCH_ERRORS


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_verify_many_isolates_an_unhashable_kb_jwt_alg(issuer, holder, alg):
    policy = VerificationPolicy(audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    good = _good_sd_jwt_presentation(issuer, holder)
    results = verify_many([good, _sd_jwt_with_kb_alg(issuer, holder, alg), good],
                          policy=policy)
    assert [r.ok for r in results] == [True, False, True]
    assert type(results[1].error) is UnsupportedAlgorithm
    assert "KB-JWT" in str(results[1].error)


# --------------------------------------------------------------------------- #
# SD-JWT VC
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", UNHASHABLE)
def test_sd_jwt_suite_unhashable_issuer_alg_is_typed(issuer, alg):
    with pytest.raises(UnsupportedAlgorithm, match="is not permitted"):
        SdJwtVcProofSuite().verify(_sd_jwt_with_header(issuer, alg=alg), public_key_jwk={})


@pytest.mark.parametrize("typ", UNHASHABLE)
def test_sd_jwt_suite_unhashable_issuer_typ_is_typed(issuer, typ):
    with pytest.raises(SdJwtError, match="unexpected issuer JWT typ"):
        SdJwtVcProofSuite().verify(_sd_jwt_with_header(issuer, typ=typ), public_key_jwk={})


@pytest.mark.parametrize("sd_alg", UNHASHABLE)
def test_sd_jwt_unhashable_sd_alg_is_typed(issuer, sd_alg):
    # issuer-signed, so this one is past the signature, but any did:key can sign it
    with pytest.raises(SdJwtError, match="unsupported _sd_alg"):
        SdJwtVcProofSuite().verify(_sd_jwt_signed(issuer, _sd_alg=sd_alg),
                                   public_key_jwk=issuer[0].public_jwk())
    with pytest.raises(SdJwtError, match="unsupported _sd_alg"):
        verify_credential(_sd_jwt_signed(issuer, _sd_alg=sd_alg))


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_sd_jwt_unhashable_kb_jwt_alg_is_typed(issuer, holder, alg):
    with pytest.raises(UnsupportedAlgorithm, match="KB-JWT algorithm"):
        SdJwtVcProofSuite().verify(
            _sd_jwt_with_kb_alg(issuer, holder, alg), public_key_jwk=issuer[0].public_jwk(),
            audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_dc_sd_jwt_presentation_unhashable_kb_jwt_alg_is_typed(issuer, holder, alg):
    with pytest.raises(UnsupportedAlgorithm, match="KB-JWT algorithm"):
        verify_vp_token({"q": [_sd_jwt_with_kb_alg(issuer, holder, alg)]},
                        dcql_query=SD_JWT_DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_sd_jwt_well_formed_presentation_still_verifies(issuer, holder):
    result = SdJwtVcProofSuite().verify(
        _good_sd_jwt_presentation(issuer, holder), public_key_jwk=issuer[0].public_jwk(),
        audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    assert result.key_bound and result.claims["given_name"] == "Ada"


# --------------------------------------------------------------------------- #
# VP-JWT and everything else on `proof._jws.verify_compact`
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("alg", UNHASHABLE)
def test_vp_jwt_suite_unhashable_alg_is_typed(holder, alg):
    holder_key, holder_did = holder
    token = _unsigned({"alg": alg, "typ": "JWT", "kid": holder_key.kid},
                      _vp_claims(holder_did, []))
    with pytest.raises(UnsupportedAlgorithm, match="is not permitted"):
        VpJwtProofSuite().verify(token, audience=CLIENT_ID, nonce=NONCE)


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_jwt_vc_json_unhashable_vp_alg_is_typed(issuer, holder, alg):
    holder_key, holder_did = holder
    token = _unsigned({"alg": alg, "typ": "JWT", "kid": holder_key.kid},
                      _vp_claims(holder_did, [_vc_jwt(issuer)]))
    with pytest.raises(UnsupportedAlgorithm):
        verify_vp_token({"q": [token]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_jwt_vc_json_nested_vc_unhashable_alg_is_typed(issuer, holder, alg):
    # the VP is correctly holder-signed; the embedded VC-JWT carries the hostile alg
    holder_key, holder_did = holder
    vp = sign_compact({"alg": holder_key.alg, "typ": "JWT", "kid": holder_key.kid},
                      _vp_claims(holder_did, [_vc_jwt_with_alg(issuer, alg)]),
                      signing_key=holder_key)
    with pytest.raises(UnsupportedAlgorithm):
        verify_vp_token({"q": [vp]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                        client_id=CLIENT_ID)


@pytest.mark.parametrize("alg", UNHASHABLE)
def test_status_list_token_unhashable_alg_is_typed(alg):
    token = _unsigned({"alg": alg, "typ": "statuslist+jwt"},
                      {"sub": "https://status.example/1", "iat": int(time.time())})
    with pytest.raises(UnsupportedAlgorithm, match="is not permitted"):
        verify_status_list_token(token, public_key_jwk={})


# --------------------------------------------------------------------------- #
# OpenID4VP ldp_vc: the holder proof's cryptosuite
# --------------------------------------------------------------------------- #

def _ldp_vp_with_cryptosuite(cryptosuite):
    _, vp_did = _did_key_ed25519()
    return {"@context": [V2], "type": ["VerifiablePresentation"], "holder": vp_did,
            "verifiableCredential": [{}],
            "proof": {"type": "DataIntegrityProof", "cryptosuite": cryptosuite,
                      "proofPurpose": "authentication", "challenge": NONCE,
                      "domain": CLIENT_ID}}


@pytest.mark.parametrize("cryptosuite", [
    pytest.param(["eddsa-jcs-2022"], id="array"),
    pytest.param({"eddsa-jcs-2022": True}, id="object"),
    pytest.param([], id="empty-array"),
])
def test_ldp_vc_unhashable_cryptosuite_is_typed(cryptosuite):
    with pytest.raises(UnsupportedPresentationFormat, match="unsupported Data Integrity"):
        verify_vp_token({"q": [_ldp_vp_with_cryptosuite(cryptosuite)]},
                        dcql_query=LDP_VC_DCQL, nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vc_deeply_nested_cryptosuite_is_typed():
    # a Python-built value skips the JSON loader; the vp_token depth check holds it
    deep: list = []
    for _ in range(100_000):
        deep = [deep]
    with pytest.raises(VpTokenMalformed, match="nested deeper than"):
        verify_vp_token({"q": [_ldp_vp_with_cryptosuite(deep)]},
                        dcql_query=LDP_VC_DCQL, nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# OpenID4VCI key proof: typ
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("typ", [
    pytest.param(["openid4vci-proof+jwt"], id="array"),
    pytest.param({"openid4vci-proof+jwt": True}, id="object"),
    pytest.param([], id="empty-array"),
])
def test_openid4vci_unhashable_proof_typ_is_typed(holder, typ):
    proof = _unsigned({"alg": "ES256", "typ": typ, "jwk": holder[0].public_jwk()},
                      {"aud": CREDENTIAL_ISSUER, "iat": int(time.time()), "nonce": "c"})
    request = {"credential_configuration_id": "x", "proofs": {"jwt": [proof]}}
    with pytest.raises(ClaimsInvalid, match="key proof typ must be"):
        verify_credential_request_proofs(request, credential_issuer=CREDENTIAL_ISSUER,
                                         require_nonce=False)


@pytest.mark.parametrize("alg", [
    pytest.param(["ES256"], id="array"),
    pytest.param({"ES256": True}, id="object"),
    pytest.param([], id="empty-array"),
])
def test_openid4vci_unhashable_proof_alg_is_typed(holder, alg):
    proof = _unsigned({"alg": alg, "typ": "openid4vci-proof+jwt",
                       "jwk": holder[0].public_jwk()},
                      {"aud": CREDENTIAL_ISSUER, "iat": int(time.time()), "nonce": "c"})
    request = {"credential_configuration_id": "x", "proofs": {"jwt": [proof]}}
    with pytest.raises(UnsupportedAlgorithm, match="key proof alg .* is not allow-listed"):
        verify_credential_request_proofs(request, credential_issuer=CREDENTIAL_ISSUER,
                                         require_nonce=False)


# --------------------------------------------------------------------------- #
# The allow-list messages that already type-checked: no repr() of a container
# --------------------------------------------------------------------------- #

def test_jwe_deeply_nested_alg_is_typed():
    header = '{"enc":"A128GCM","alg":' + _deep_json_array() + "}"
    token = f"{_b64url(header.encode())}.." + "AAAA." * 2 + "AAAA"
    with pytest.raises(JweMalformed):
        decrypt_compact(token, key=P256KeyAgreementKey.generate(kid="k"))


def test_wrprc_deeply_nested_alg_is_typed():
    with pytest.raises(RpRegistrationError, match="not a valid compact JWS"):
        parse_rp_registration_certificate(_deep_header_token('"typ":"rc-wrp+jwt",'))


def test_lote_deeply_nested_alg_is_typed():
    with pytest.raises(TrustListParseError):
        consume_lote(_deep_header_token(""), expected_signer_certs=[])


def test_safe_repr_names_containers_by_type():
    deep: list = []
    for _ in range(100_000):
        deep = [deep]
    assert safe_repr(deep) == "list"
    assert safe_repr({"a": 1}) == "dict"
    assert safe_repr("ES256") == "'ES256'"
    assert safe_repr(None) == "None"
    assert safe_repr(-7) == "-7"
    assert safe_repr(True) == "True"
