"""
tests/test_sd_jwt_vc_dc_typ_ietf_only.py — the ``dc+sd-jwt`` issuer typ always means an IETF
SD-JWT VC, whatever else the payload carries (#272; the other direction is #264).

draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 types an IETF SD-JWT VC ``dc+sd-jwt``: that typ says
the payload follows the SD-JWT VC rules, and §2.2.2.3 makes ``vct`` REQUIRED in it. The
OpenID4VP 1.0 ``dc+sd-jwt`` Credential Format is the same thing: a DCQL query of that
format asks for an IETF SD-JWT VC, not for a W3C VCDM credential. #264 closed one direction:
a ``vc+sd-jwt`` (VC-JOSE-COSE §6.1.3, a VCDM payload and nothing else) needs a VCDM base
``@context``. #272 closes the other two holes:

* **A VCDM ``@context`` waived the ``vct`` of a ``dc+sd-jwt``.** The suite let a payload
  with a VCDM context skip the REQUIRED ``vct`` whatever its typ, so a ``dc+sd-jwt``
  carrying one (or one whose disclosable ``vct`` the holder withheld) verified with
  ``vct=None``. A ``dc+sd-jwt`` now always needs a non-empty string ``vct``
  (``ClaimsInvalid``). One that has both a VCDM ``@context`` and a ``vct`` still verifies,
  and is still held to the VCDM window and the issuer / id / subject consistency. A
  ``vc+sd-jwt`` needs no ``vct`` (it is VCDM, typed by ``type`` instead).
* **A ``vc+sd-jwt`` answered a ``dc+sd-jwt`` query.** The pipeline names every SD-JWT
  ``sd-jwt-vc``, so a VCDM credential secured as ``vc+sd-jwt`` came back from the DCQL lane
  as if it were an IETF SD-JWT VC, with or without ``meta.vct_values``. ``VerifiedSdJwt``
  now reports the verified issuer JWT ``typ`` (``raw.typ`` through the pipeline), and the
  lane refuses (``VpTokenMalformed``) anything but ``dc+sd-jwt``.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; signatures are real P-256;
``asyncio.run`` drives the async pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import secrets
from types import SimpleNamespace

import pytest

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_vp_token,
)
from openvc.keys import P256SigningKey
from openvc.openid4vp import VpTokenMalformed
from openvc.proof.errors import ClaimsInvalid, CredentialExpired, CredentialNotYetValid
from openvc.proof.sd_jwt import (
    SdJwtVcProofSuite,
    VerifiedSdJwt,
    disclosure_digest,
    make_object_disclosure,
)

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
PAST = "2021-01-01T00:00:00Z"
VCT = "https://credentials.example/membership"
NEEDS_VCT = "needs a non-empty string vct"
NOT_IETF = "must be an IETF SD-JWT VC"
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"

VCDM_CONTEXTS = pytest.mark.parametrize("context", [
    [V2, "https://www.w3.org/ns/credentials/examples/v2"],
    V2,
    ["https://example.org/ctx", V2],
    [V1],
], ids=["v2-array", "v2-string", "v2-not-first", "v1"])


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()


def _mint(payload, *, typ="dc+sd-jwt", disclose=()):
    """Issue an SD-JWT by hand with an arbitrary issuer JWT *typ*: ``SdJwtVcProofSuite.issue``
    always writes ``dc+sd-jwt`` and requires a ``vct``. *disclose* moves those top-level
    claims into disclosures (all of them presented)."""
    body = dict(payload)
    disclosures = []
    for name in disclose:
        disclosures.append(make_object_disclosure(_b64(secrets.token_bytes(16)), name,
                                                  body.pop(name)))
    if disclosures:
        body["_sd"] = sorted(disclosure_digest(d) for d in disclosures)
        body["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "typ": typ, "kid": f"{DID}#0"}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    jws = f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}"
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _without(sd_jwt, name):
    """The presentation with the disclosure of top-level claim *name* withheld."""
    issuer_jwt, *rest = sd_jwt.split("~")
    kept = [d for d in rest[:-1]
            if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] != name]
    assert len(kept) == len(rest) - 2, f"no disclosure for {name!r}"
    return issuer_jwt + "~" + "".join(d + "~" for d in kept)


def _ietf(**extra):
    """An IETF SD-JWT VC payload: a ``vct`` and no VCDM vocabulary."""
    claims = {"iss": DID, "vct": VCT, "member_name": "Ada"}
    claims.update(extra)
    return claims


def _vcdm(**extra):
    """A W3C VCDM payload with no ``vct``."""
    doc = {
        "@context": [V2, "https://www.w3.org/ns/credentials/examples/v2"],
        "id": "urn:uuid:5e1d6a3c-cred",
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "iss": DID,
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "alumniOf": "Example University"},
    }
    doc.update(extra)
    return doc


def _vcdm_vct(**extra):
    """The same VCDM payload with a ``vct``: both an IETF and a W3C credential."""
    return _vcdm(vct=VCT, **extra)


def _envelope(sd_jwt, media="application/vc+sd-jwt"):
    return {"@context": [V2], "id": f"data:{media},{sd_jwt}",
            "type": ["EnvelopedVerifiableCredential"]}


FORMS = {
    "bare": lambda sd_jwt: sd_jwt,
    "enveloped": _envelope,
}


def _sync(credential, policy):
    return verify_credential(credential, policy=policy)


def _async(credential, policy):
    return asyncio.run(verify_credential_async(credential, policy=policy))


PIPELINES = {"sync": _sync, "async": _async}


@pytest.fixture(params=sorted(PIPELINES))
def run(request):
    return PIPELINES[request.param]


@pytest.fixture(params=sorted(FORMS))
def form(request):
    return FORMS[request.param]


def _suite_verify(sd_jwt):
    return SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=KEY.public_jwk())


# --------------------------------------------------------------------------- #
# a dc+sd-jwt always needs a vct — a VCDM @context does not waive it
# --------------------------------------------------------------------------- #

@VCDM_CONTEXTS
def test_dc_sd_jwt_with_a_vcdm_context_still_needs_a_vct(run, form, context):
    # Used to verify with vcdm=True, vct=None: the context stood in for the REQUIRED vct.
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT) as excinfo:
        run(form(_mint(_vcdm(**{"@context": context}), typ="dc+sd-jwt")), None)
    assert excinfo.type is ClaimsInvalid


@pytest.mark.parametrize("vct", ["", 0, [], None, {"a": "b"}],
                         ids=["empty", "zero", "empty-array", "null", "object"])
def test_a_vct_that_is_not_a_non_empty_string_does_not_rescue_a_vcdm_dc_sd_jwt(
        run, form, vct):
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(form(_mint(_vcdm(vct=vct), typ="dc+sd-jwt")), None)


def test_a_withheld_vct_on_a_vcdm_dc_sd_jwt_is_refused(run, form):
    # The issuer made vct a disclosure and the holder presents the token without it: the
    # payload looks vct-less, and its VCDM context must not stand in for the vct.
    sd_jwt = _without(_mint(_vcdm_vct(), typ="dc+sd-jwt", disclose=["vct"]), "vct")
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(form(sd_jwt), None)


def test_the_suite_refuses_a_vct_less_vcdm_dc_sd_jwt_directly_not_only_the_pipeline():
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        _suite_verify(_mint(_vcdm(), typ="dc+sd-jwt"))
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        _suite_verify(_without(_mint(_vcdm_vct(), typ="dc+sd-jwt", disclose=["vct"]), "vct"))


def test_the_same_vcdm_payload_needs_a_vct_only_under_the_dc_sd_jwt_typ(
        run, form):
    # The only difference between the two tokens is the typ: a vc+sd-jwt is a VCDM payload
    # (typed by `type`) and needs no vct; a dc+sd-jwt is an IETF SD-JWT VC and does.
    result = run(form(_mint(_vcdm(), typ="vc+sd-jwt")), None)
    assert result.raw.vcdm is True
    assert result.raw.vct is None
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(form(_mint(_vcdm(), typ="dc+sd-jwt")), None)


@pytest.mark.parametrize("media", ["application/vc+sd-jwt", "application/dc+sd-jwt"])
def test_enveloped_media_type_does_not_waive_the_vct_of_a_dc_sd_jwt(run, media):
    # The data: URL's media type is not signed; the token's own typ is what counts.
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(_envelope(_mint(_vcdm(), typ="dc+sd-jwt"), media=media), None)


def test_vct_less_ietf_dc_sd_jwt_without_a_vcdm_context_is_still_refused(run, form):
    # Control: the rule that was already there.
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(form(_mint({"iss": DID, "member_name": "Ada"}, typ="dc+sd-jwt")), None)


# --------------------------------------------------------------------------- #
# a dc+sd-jwt with a VCDM @context AND a vct is both, and is still held to VCDM
# --------------------------------------------------------------------------- #

@VCDM_CONTEXTS
def test_dc_sd_jwt_with_a_vcdm_context_and_a_vct_verifies_as_vcdm(run, form, context):
    result = run(form(_mint(_vcdm_vct(**{"@context": context}), typ="dc+sd-jwt")), None)
    assert result.raw.vcdm is True
    assert result.raw.vct == VCT


def test_dc_sd_jwt_vcdm_expired_valid_until_still_fails(run, form):
    with pytest.raises(CredentialExpired):
        run(form(_mint(_vcdm_vct(validUntil=PAST), typ="dc+sd-jwt")), None)


def test_dc_sd_jwt_vcdm_future_valid_from_still_fails(run, form):
    with pytest.raises(CredentialNotYetValid):
        run(form(_mint(_vcdm_vct(validFrom="2099-01-01T00:00:00Z"), typ="dc+sd-jwt")), None)


def test_dc_sd_jwt_vcdm_window_is_waived_like_before(run, form):
    waived = VerificationPolicy(require_not_expired=False)
    result = run(form(_mint(_vcdm_vct(validUntil=PAST), typ="dc+sd-jwt")), waived)
    assert result.expired is True
    assert result.raw.vcdm is True
    assert result.raw.vct == VCT


def test_dc_sd_jwt_vcdm_issuer_conflict_still_fails(run, form):
    # The consistency rules still bind a dc+sd-jwt that is VCDM by its context.
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm_vct(issuer="did:web:university.example"), typ="dc+sd-jwt")),
            None)


def test_dc_sd_jwt_without_a_vcdm_context_is_still_an_ietf_payload(run, form):
    # Control: the vct is the whole story, no VCDM verdict (and no VCDM window).
    result = run(form(_mint(_ietf(validUntil=PAST), typ="dc+sd-jwt")), None)
    assert result.raw.vcdm is False
    assert result.raw.vct == VCT


# --------------------------------------------------------------------------- #
# VerifiedSdJwt.typ — the verified issuer JWT typ, through the pipeline and the suite
# --------------------------------------------------------------------------- #

def test_typ_is_dc_sd_jwt_for_an_ietf_dc_sd_jwt_token(run, form):
    assert run(form(_mint(_ietf(), typ="dc+sd-jwt")), None).raw.typ == "dc+sd-jwt"


def test_typ_is_dc_sd_jwt_for_a_vcdm_dc_sd_jwt_token_with_a_vct(run, form):
    assert run(form(_mint(_vcdm_vct(), typ="dc+sd-jwt")), None).raw.typ == "dc+sd-jwt"


@pytest.mark.parametrize("with_vct", [False, True], ids=["no-vct", "with-vct"])
def test_typ_is_vc_sd_jwt_for_a_vc_sd_jwt_vcdm_token(run, form, with_vct):
    doc = _vcdm_vct() if with_vct else _vcdm()
    assert run(form(_mint(doc, typ="vc+sd-jwt")), None).raw.typ == "vc+sd-jwt"


@pytest.mark.parametrize("media", ["application/vc+sd-jwt", "application/dc+sd-jwt"])
def test_typ_is_the_signed_header_not_the_enveloped_media_type(run, media):
    # The data: URL's media type is not signed and must not name the typ.
    assert run(_envelope(_mint(_ietf(), typ="dc+sd-jwt"), media=media),
               None).raw.typ == "dc+sd-jwt"
    assert run(_envelope(_mint(_vcdm(), typ="vc+sd-jwt"), media=media),
               None).raw.typ == "vc+sd-jwt"


def test_the_suite_reports_the_typ_directly_not_only_the_pipeline():
    assert _suite_verify(_mint(_ietf(), typ="dc+sd-jwt")).typ == "dc+sd-jwt"
    assert _suite_verify(_mint(_vcdm_vct(), typ="dc+sd-jwt")).typ == "dc+sd-jwt"
    assert _suite_verify(_mint(_vcdm(), typ="vc+sd-jwt")).typ == "vc+sd-jwt"
    assert _suite_verify(_mint(_vcdm_vct(), typ="vc+sd-jwt")).typ == "vc+sd-jwt"


def test_the_suite_reports_dc_sd_jwt_for_a_token_it_issued_itself():
    token = SdJwtVcProofSuite().issue(
        {"iss": DID, "vct": VCT, "member_name": "Ada"}, signing_key=KEY)
    assert _suite_verify(token).typ == "dc+sd-jwt"


# --------------------------------------------------------------------------- #
# OpenID4VP — a dc+sd-jwt query is answered only by an IETF SD-JWT VC
# --------------------------------------------------------------------------- #

def _present(claims, *, typ):
    """A KB-JWT presentation of a hand-minted token, bound to CLIENT_ID and NONCE."""
    holder = P256SigningKey.generate(kid="holder")
    sd_jwt = _mint({**claims, "cnf": {"jwk": holder.public_jwk()}}, typ=typ)
    return SdJwtVcProofSuite().create_presentation(
        sd_jwt, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)


def _answer(presentation, *, vct_values=None):
    query = {"id": "q", "format": "dc+sd-jwt"}
    if vct_values is not None:
        query["meta"] = {"vct_values": vct_values}
    return verify_vp_token({"q": [presentation]}, dcql_query={"credentials": [query]},
                           nonce=NONCE, client_id=CLIENT_ID).for_query("q")[0]


VCT_VALUES = pytest.mark.parametrize("vct_values", [None, [VCT]],
                                     ids=["no-vct-values", "vct-values"])


@pytest.mark.parametrize("claims, vct_values", [
    (_vcdm(), None),
    (_vcdm_vct(), None),
    (_vcdm_vct(), [VCT]),
], ids=["no-vct", "vct-no-vct-values", "vct-matching-vct-values"])
def test_openid4vp_dc_sd_jwt_query_refuses_a_vc_sd_jwt_vcdm_credential(claims, vct_values):
    # A W3C VCDM credential secured as vc+sd-jwt: the pipeline calls it "sd-jwt-vc", and
    # even a vct that matches the query's vct_values does not make it an IETF SD-JWT VC.
    with pytest.raises(VpTokenMalformed, match=NOT_IETF) as excinfo:
        _answer(_present(claims, typ="vc+sd-jwt"), vct_values=vct_values)
    assert excinfo.type is VpTokenMalformed


def test_openid4vp_refusal_names_the_expected_and_the_actual_typ():
    with pytest.raises(VpTokenMalformed,
                       match=r"issuer JWT typ 'dc\+sd-jwt', got 'vc\+sd-jwt'"):
        _answer(_present(_vcdm(), typ="vc+sd-jwt"))


@VCT_VALUES
def test_openid4vp_control_a_dc_sd_jwt_with_a_vct_still_answers(vct_values):
    answer = _answer(_present(_ietf(), typ="dc+sd-jwt"), vct_values=vct_values)
    assert answer.raw.vct == VCT
    assert answer.raw.key_bound is True


@VCT_VALUES
def test_openid4vp_control_a_dc_sd_jwt_with_a_vcdm_context_and_a_vct_still_answers(
        vct_values):
    answer = _answer(_present(_vcdm_vct(), typ="dc+sd-jwt"), vct_values=vct_values)
    assert answer.raw.vct == VCT
    assert answer.raw.vcdm is True
    assert answer.raw.key_bound is True


@VCT_VALUES
def test_openid4vp_dc_sd_jwt_query_refuses_a_vct_less_vcdm_dc_sd_jwt(vct_values):
    # The suite's own rule is the gate here, and it is a different error class: the typ is
    # right (dc+sd-jwt) but the REQUIRED vct is missing.
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        _answer(_present(_vcdm(), typ="dc+sd-jwt"), vct_values=vct_values)


# --------------------------------------------------------------------------- #
# the typ field's default, and the lane failing closed on it
# --------------------------------------------------------------------------- #

def _bare_verified_sd_jwt(**extra):
    return VerifiedSdJwt(claims={}, issuer=DID, vct=VCT, key_bound=False,
                         confirmation=None, **extra)


def test_verified_sd_jwt_constructed_without_a_typ_has_none():
    assert _bare_verified_sd_jwt().typ is None


def test_typ_is_the_last_field_of_verified_sd_jwt_and_defaults_to_none():
    # Appended last so positional construction of the earlier fields keeps working.
    fields = dataclasses.fields(VerifiedSdJwt)
    assert fields[-1].name == "typ"
    assert fields[-1].default is None
    assert [f.name for f in fields[-3:-1]] == ["expired", "vcdm"]


@pytest.mark.parametrize("extra, got", [
    ({}, "None"),
    ({"typ": "vc+sd-jwt"}, "'vc+sd-jwt'"),
    ({"typ": "JWT"}, "'JWT'"),
], ids=["not-set", "vc-sd-jwt", "other"])
def test_openid4vp_lane_fails_closed_on_any_typ_but_dc_sd_jwt(monkeypatch, extra, got):
    # The lane reads raw.typ: a result that does not report exactly dc+sd-jwt is refused,
    # including one built without the field. The pipeline is stubbed so the verdict is the
    # lane's own.
    stub = SimpleNamespace(format="sd-jwt-vc", raw=_bare_verified_sd_jwt(**extra),
                           subject=None)
    monkeypatch.setattr("openvc.verify.verify_credential", lambda *a, **kw: stub)
    with pytest.raises(VpTokenMalformed, match=NOT_IETF) as excinfo:
        _answer("a.b.c~")
    assert f"got {got}" in str(excinfo.value)


def test_openid4vp_lane_accepts_the_stubbed_result_once_the_typ_is_dc_sd_jwt(monkeypatch):
    # The stub itself is sound: only the typ differs from the refused cases above.
    stub = SimpleNamespace(format="sd-jwt-vc", raw=_bare_verified_sd_jwt(typ="dc+sd-jwt"),
                           subject=None)
    monkeypatch.setattr("openvc.verify.verify_credential", lambda *a, **kw: stub)
    answer = _answer("a.b.c~", vct_values=[VCT])
    assert answer.raw.typ == "dc+sd-jwt"
    assert answer.credentials == (stub,)
