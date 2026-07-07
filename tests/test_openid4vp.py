"""
tests/test_openid4vp.py — the stateless OpenID4VP 1.0 ``vp_token`` verifier (#18).

Pins the OpenID4VP 1.0 (Final, 2025-07-09) response wire contract and the holder
binding the verifier must enforce:

  * ``vp_token`` is a JSON object keyed by DCQL Credential Query ``id``; each value is
    an **array** (length 1 unless the query set ``multiple:true``) — §8.1;
  * each Presentation is routed by the query's ``format`` — ``dc+sd-jwt`` (SD-JWT VC +
    KB-JWT) and ``jwt_vc_json`` (a W3C VP-JWT); and
  * the transaction ``nonce`` and the **full, prefixed** Client Identifier
    (``x509_san_dns:client.example.org``, not the bare host) are bound — §14.2 / §10.4.

Signed material is minted locally with offline ``did:key`` issuer/holder keys, but the
wire values (nonce ``n-0S6_WzA2Mj``, ``client_id``, the ``my_credential`` query id, the
``credentials.example.com`` vct) are the OpenID4VP 1.0 spec example's, so the shapes
under test match the Recommendation's own fixtures.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import (
    FORMAT_JWT_VC,
    FORMAT_SD_JWT_VC,
    OpenID4VPError,
    UnsupportedPresentationFormat,
    VpTokenMalformed,
    verify_vp_token,
)
from openvc.proof.errors import ClaimsInvalid, SignatureInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
VCT = "https://credentials.example.com/identity_credential"
_MC_P256 = bytes([0x80, 0x24])                     # multicodec p256-pub (0x1200) varint


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(_MC_P256 + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _did_key_p256()


@pytest.fixture(scope="module")
def holder():
    return _did_key_p256()


def _sd_jwt_presentation(issuer, holder, *, audience=CLIENT_ID, nonce=NONCE, vct=VCT):
    issuer_key, issuer_did = issuer
    holder_key, _ = holder
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "given_name": "Ada", "sub": "did:example:alice"},
        signing_key=issuer_key, vct=vct, disclosable=["given_name"],
        holder_jwk=holder_key.public_jwk())
    return SdJwtVcProofSuite().create_presentation(
        issued, holder_key=holder_key, audience=audience, nonce=nonce)


def _vp_jwt(issuer, holder, *, audience=CLIENT_ID, nonce=NONCE):
    issuer_key, issuer_did = issuer
    holder_key, holder_did = holder
    vc = VcJwtProofSuite().sign(
        {"@context": ["https://www.w3.org/ns/credentials/v2"],
         "type": ["VerifiableCredential"], "issuer": issuer_did,
         "credentialSubject": {"id": holder_did}},
        signing_key=issuer_key)
    return VpJwtProofSuite().sign([vc], holder_key=holder_key, audience=audience, nonce=nonce)


def _dcql_sd_jwt(query_id="my_credential", **extra):
    return {"credentials": [
        {"id": query_id, "format": FORMAT_SD_JWT_VC, "meta": {"vct_values": [VCT]}, **extra}]}


# --------------------------------------------------------------------------- #
# happy path — both supported formats verify and bind
# --------------------------------------------------------------------------- #

def test_sd_jwt_vc_presentation_verifies_and_binds(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    result = verify_vp_token(
        {"my_credential": [pres]}, dcql_query=_dcql_sd_jwt(),
        nonce=NONCE, client_id=CLIENT_ID)
    (p,) = result.for_query("my_credential")
    assert p.format == FORMAT_SD_JWT_VC
    assert p.raw.claims["given_name"] == "Ada"       # the disclosed claim
    assert p.raw.vct == VCT
    assert len(p.credentials) == 1


def test_jwt_vc_presentation_verifies_and_cascades(issuer, holder):
    vp = _vp_jwt(issuer, holder)
    result = verify_vp_token(
        {"vp1": [vp]}, dcql_query={"credentials": [{"id": "vp1", "format": FORMAT_JWT_VC}]},
        nonce=NONCE, client_id=CLIENT_ID)
    (p,) = result.for_query("vp1")
    assert p.format == FORMAT_JWT_VC
    assert p.holder == holder[1]                     # the did:key presenter
    assert len(p.credentials) == 1                   # cascaded to the embedded VC
    assert p.credentials[0].issuer == issuer[1]


def test_vp_token_accepts_a_json_string(issuer, holder):
    import json
    pres = _sd_jwt_presentation(issuer, holder)
    result = verify_vp_token(
        json.dumps({"my_credential": [pres]}), dcql_query=_dcql_sd_jwt(),
        nonce=NONCE, client_id=CLIENT_ID)
    assert len(result.presentations) == 1


def test_multiple_true_allows_several_presentations(issuer, holder):
    p1 = _sd_jwt_presentation(issuer, holder)
    p2 = _sd_jwt_presentation(issuer, holder)
    result = verify_vp_token(
        {"my_credential": [p1, p2]}, dcql_query=_dcql_sd_jwt(multiple=True),
        nonce=NONCE, client_id=CLIENT_ID)
    assert len(result.for_query("my_credential")) == 2


# --------------------------------------------------------------------------- #
# holder binding — nonce + the FULL, prefixed client_id (the security core)
# --------------------------------------------------------------------------- #

def test_wrong_nonce_is_rejected(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    with pytest.raises(ClaimsInvalid):
        verify_vp_token({"my_credential": [pres]}, dcql_query=_dcql_sd_jwt(),
                        nonce="a-different-nonce", client_id=CLIENT_ID)


def test_bare_host_client_id_is_rejected(issuer, holder):
    """The audience is the full prefixed Client Identifier — the bare host must not
    verify (OpenID4VP 1.0 §15.11 "full client identifier")."""
    pres = _sd_jwt_presentation(issuer, holder)
    with pytest.raises(ClaimsInvalid):
        verify_vp_token({"my_credential": [pres]}, dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id="client.example.org")


def test_binding_applies_to_jwt_vc_too(issuer, holder):
    vp = _vp_jwt(issuer, holder, nonce="stale")
    with pytest.raises(ClaimsInvalid):
        verify_vp_token({"vp1": [vp]},
                        dcql_query={"credentials": [{"id": "vp1", "format": FORMAT_JWT_VC}]},
                        nonce=NONCE, client_id=CLIENT_ID)


def test_tampered_sd_jwt_fails_closed(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    issuer_jwt, rest = pres.split("~", 1)
    forged = issuer_jwt[:-4] + ("aaaa" if issuer_jwt[-4:] != "aaaa" else "bbbb") + "~" + rest
    with pytest.raises(SignatureInvalid):
        verify_vp_token({"my_credential": [forged]}, dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# wire-shape validation — the vp_token / DCQL contract (fail closed)
# --------------------------------------------------------------------------- #

def test_unknown_vp_token_key_is_rejected(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"not_in_dcql": [pres]}, dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id=CLIENT_ID)


def test_value_must_be_an_array(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    with pytest.raises(VpTokenMalformed):                     # 1.0: always an array
        verify_vp_token({"my_credential": pres}, dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id=CLIENT_ID)


def test_single_valued_query_rejects_multiple(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"my_credential": [pres, pres]}, dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id=CLIENT_ID)


def test_empty_array_is_rejected(issuer, holder):
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"my_credential": []}, dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id=CLIENT_ID)


def test_missing_required_query_is_rejected(issuer, holder):
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({}, dcql_query=_dcql_sd_jwt(), nonce=NONCE, client_id=CLIENT_ID)


@pytest.mark.parametrize("bad_dcql", [
    {},
    {"credentials": []},
    {"credentials": [{"id": "x"}]},                          # no format
    {"credentials": [{"format": "dc+sd-jwt"}]},              # no id
    {"credentials": [{"id": "x", "format": "dc+sd-jwt"}, {"id": "x", "format": "dc+sd-jwt"}]},
], ids=["empty", "no-creds", "no-format", "no-id", "dup-id"])
def test_malformed_dcql_is_rejected(bad_dcql):
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({}, dcql_query=bad_dcql, nonce=NONCE, client_id=CLIENT_ID)


def test_non_string_sd_jwt_presentation_is_rejected():
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"my_credential": [{"not": "a string"}]},
                        dcql_query=_dcql_sd_jwt(), nonce=NONCE, client_id=CLIENT_ID)


def test_invalid_json_string_is_rejected():
    with pytest.raises(VpTokenMalformed):
        verify_vp_token("{not json", dcql_query=_dcql_sd_jwt(),
                        nonce=NONCE, client_id=CLIENT_ID)


@pytest.mark.parametrize("fmt", ["ldp_vc", "mso_mdoc", "jwt_vc_json_ld", "made_up"])
def test_unsupported_format_is_typed(issuer, holder, fmt):
    with pytest.raises(UnsupportedPresentationFormat):
        verify_vp_token({"c": [{}]}, dcql_query={"credentials": [{"id": "c", "format": fmt}]},
                        nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# DCQL meta + required inputs
# --------------------------------------------------------------------------- #

def test_vct_not_in_requested_values_is_rejected(issuer, holder):
    pres = _sd_jwt_presentation(issuer, holder)
    dcql = {"credentials": [{"id": "my_credential", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": ["https://example.com/OtherType"]}}]}
    with pytest.raises(ClaimsInvalid):
        verify_vp_token({"my_credential": [pres]}, dcql_query=dcql,
                        nonce=NONCE, client_id=CLIENT_ID)


@pytest.mark.parametrize("nonce, client_id", [("", CLIENT_ID), (NONCE, "")],
                         ids=["empty-nonce", "empty-client-id"])
def test_empty_binding_inputs_rejected(nonce, client_id):
    with pytest.raises(ClaimsInvalid):
        verify_vp_token({}, dcql_query=_dcql_sd_jwt(), nonce=nonce, client_id=client_id)


def test_holder_binding_can_be_waived_by_the_query(issuer, holder):
    """require_cryptographic_holder_binding:false means a bare SD-JWT (no KB-JWT) is
    accepted — the verifier explicitly opted out of holder binding for this query."""
    issuer_key, issuer_did = issuer
    holder_key, _ = holder
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "given_name": "Ada"}, signing_key=issuer_key, vct=VCT,
        disclosable=["given_name"], holder_jwk=holder_key.public_jwk())   # no KB-JWT presented
    dcql = {"credentials": [{"id": "my_credential", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": [VCT]},
                             "require_cryptographic_holder_binding": False}]}
    result = verify_vp_token({"my_credential": [issued]}, dcql_query=dcql,
                             nonce=NONCE, client_id=CLIENT_ID)
    assert result.for_query("my_credential")[0].format == FORMAT_SD_JWT_VC


def test_errors_share_one_base():
    assert issubclass(VpTokenMalformed, OpenID4VPError)
    assert issubclass(UnsupportedPresentationFormat, OpenID4VPError)


# --------------------------------------------------------------------------- #
# regressions from the adversarial review
# --------------------------------------------------------------------------- #

def test_vc_jwt_smuggled_under_sd_jwt_query_is_rejected(issuer):
    """CRITICAL regression: a plain VC-JWT (no KB-JWT, no nonce) returned under a
    dc+sd-jwt query must NOT be accepted — verify_credential re-detects the format,
    and the VC-JWT path has no nonce binding, so accepting it is a cross-session
    replay with an attacker-chosen unbound holder."""
    issuer_key, issuer_did = issuer
    vc_jwt = VcJwtProofSuite().sign(
        {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"],
         "issuer": issuer_did, "credentialSubject": {"id": "did:example:whoever"}},
        signing_key=issuer_key)
    dcql = {"credentials": [{"id": "c", "format": FORMAT_SD_JWT_VC}]}
    for session_nonce in ("session-A", "session-B"):
        with pytest.raises(VpTokenMalformed):
            verify_vp_token({"c": [vc_jwt]}, dcql_query=dcql,
                            nonce=session_nonce, client_id=CLIENT_ID)


def test_string_without_tilde_under_sd_jwt_query_is_rejected():
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"c": ["not.an.sdjwt"]},
                        dcql_query={"credentials": [{"id": "c", "format": FORMAT_SD_JWT_VC}]},
                        nonce=NONCE, client_id=CLIENT_ID)


def test_empty_vp_token_is_rejected_even_with_credential_sets(issuer, holder):
    # credential_sets short-circuits per-query completeness, but a response with zero
    # presentations must still fail closed (a caller must never read empty as success).
    dcql = {"credentials": [{"id": "my_credential", "format": FORMAT_SD_JWT_VC}],
            "credential_sets": [{"options": [["my_credential"]]}]}
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({}, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID)


@pytest.mark.parametrize("vct_values", ["a-string", [], [123], {"x": 1}],
                         ids=["string", "empty-list", "non-string-item", "dict"])
def test_malformed_vct_values_fails_safe(issuer, holder, vct_values):
    pres = _sd_jwt_presentation(issuer, holder)
    dcql = {"credentials": [{"id": "my_credential", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": vct_values}}]}
    with pytest.raises(VpTokenMalformed):
        verify_vp_token({"my_credential": [pres]}, dcql_query=dcql,
                        nonce=NONCE, client_id=CLIENT_ID)
