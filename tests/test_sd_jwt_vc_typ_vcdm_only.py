"""
tests/test_sd_jwt_vc_typ_vcdm_only.py — the ``vc+sd-jwt`` issuer typ is accepted only for a
W3C VCDM payload (#264).

draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 types an IETF SD-JWT VC ``dc+sd-jwt`` and dropped the
transitional acceptance of the ``vc+sd-jwt`` that drafts before 06 used. W3C VC-JOSE-COSE
§6.1.3 registers ``vc+sd-jwt`` for a VCDM payload, and for nothing else. Before 1.33.0
openvc took the typ itself as a VCDM signal: ``vc+sd-jwt`` with no ``vct`` counted as VCDM.
That was a hole, not a leniency:

* **The REQUIRED ``vct`` could be skipped.** A token typed ``vc+sd-jwt`` with no ``vct`` (or
  with a ``vct`` the issuer made disclosable and the holder withheld) verified as
  ``vcdm=True, vct=None``, where the same payload typed ``dc+sd-jwt`` is refused
  (draft-19 §2.2.2.3). Under an OpenID4VP ``dc+sd-jwt`` query without ``vct_values`` it
  answered the query.
* **A VCDM verdict nobody signed up for.** Such an IETF payload was held to the VCDM window
  and issuer / id / subject reconciliation, reading its own vocabulary as VC properties.

The rule now: ``vc+sd-jwt`` needs a VCDM base context (``@context``, never disclosable,
so the verdict rests on issuer-signed plaintext) and is refused (``SdJwtError``) without
one, a ``vct`` or none. A ``dc+sd-jwt`` is unchanged: an IETF SD-JWT VC needs a non-empty
string ``vct`` (``ClaimsInvalid``) unless it carries a VCDM ``@context``. A ``vc+sd-jwt``
that does carry one is still VCDM, with or without ``vct``, with the validity window.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; ``asyncio.run`` drives the async
pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets

import pytest

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_vp_token,
)
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.proof.errors import ClaimsInvalid, CredentialExpired, CredentialNotYetValid
from openvc.proof.sd_jwt import (
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_object_disclosure,
)

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
PAST = "2021-01-01T00:00:00Z"
VCT = "https://credentials.example/membership"
REFUSED = "needs a W3C VCDM @context"
NEEDS_VCT = "needs a non-empty string vct"
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()


def _mint(payload, *, typ="vc+sd-jwt", disclose=()):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes the IETF
    ``dc+sd-jwt`` typ and requires a ``vct``, so it cannot mint a ``vc+sd-jwt``. *disclose*
    moves those top-level claims into disclosures (all of them presented)."""
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
    claims = {"iss": DID, "vct": VCT, "member_name": "Ada"}
    claims.update(extra)
    return claims


def _vct_less(**extra):
    claims = {"iss": DID, "member_name": "Ada"}
    claims.update(extra)
    return claims


def _vcdm(**extra):
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
# a vct-bearing IETF payload (the pre-draft-06 issuer) is no longer a vc+sd-jwt
# --------------------------------------------------------------------------- #

def test_vct_bearing_ietf_payload_typed_vc_sd_jwt_is_refused(run, form):
    with pytest.raises(SdJwtError, match=REFUSED):
        run(form(_mint(_ietf(), typ="vc+sd-jwt")), None)


def test_the_same_ietf_payload_typed_dc_sd_jwt_verifies(run, form):
    # The only difference from the refused token above is the typ.
    result = run(form(_mint(_ietf(), typ="dc+sd-jwt")), None)
    assert result.raw.vct == VCT
    assert result.raw.vcdm is False


def test_the_suite_refuses_it_directly_not_only_the_pipeline():
    with pytest.raises(SdJwtError, match=REFUSED):
        _suite_verify(_mint(_ietf(), typ="vc+sd-jwt"))
    assert _suite_verify(_mint(_ietf(), typ="dc+sd-jwt")).vct == VCT


def test_the_refusal_names_the_typ_to_use():
    with pytest.raises(SdJwtError, match="typed 'dc\\+sd-jwt'"):
        _suite_verify(_mint(_ietf(), typ="vc+sd-jwt"))


# --------------------------------------------------------------------------- #
# the hole: the typ alone used to say VCDM, which skipped the REQUIRED vct
# --------------------------------------------------------------------------- #

def test_vct_less_vc_sd_jwt_is_not_vcdm_by_typ_alone(run, form):
    # Used to verify with vcdm=True, vct=None.
    with pytest.raises(SdJwtError, match=REFUSED):
        run(form(_mint(_vct_less(), typ="vc+sd-jwt")), None)


@pytest.mark.parametrize("vct", ["", 0, [], None, {"a": "b"}],
                         ids=["empty", "zero", "empty-array", "null", "object"])
def test_a_vct_that_is_not_a_non_empty_string_does_not_rescue_a_vc_sd_jwt(run, form, vct):
    # The old signal read "no vct" as a non-empty string test; every value that fails it
    # is refused on the typ now, whatever it is.
    with pytest.raises(SdJwtError, match=REFUSED):
        run(form(_mint(_ietf(vct=vct), typ="vc+sd-jwt")), None)


def test_vct_less_dc_sd_jwt_still_needs_a_vct(run, form):
    # The IETF typ keeps its own rule (draft-19 §2.2.2.3), a different error class.
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(form(_mint(_vct_less(), typ="dc+sd-jwt")), None)


@pytest.mark.parametrize("context", [
    ["https://example.org/ctx"],
    "https://example.org/ctx",
    [V2 + "/"],
    ["https://WWW.W3.ORG/ns/credentials/v2"],
    [2, None, {"@vocab": V2}],
    {"@vocab": V2},
    [],
], ids=["foreign-array", "foreign-string", "trailing-slash", "case-variant",
        "non-string-entries", "object", "empty-array"])
def test_a_context_that_is_not_a_vcdm_base_context_does_not_rescue_a_vc_sd_jwt(
        run, form, context):
    with pytest.raises(SdJwtError, match=REFUSED):
        run(form(_mint(_vct_less(**{"@context": context}), typ="vc+sd-jwt")), None)


def test_refusal_does_not_depend_on_which_vcdm_member_is_absent(run, form):
    # A full VCDM body minus its @context is just a vc+sd-jwt without VCDM markers.
    doc = _vcdm()
    del doc["@context"]
    with pytest.raises(SdJwtError, match=REFUSED):
        run(form(_mint(doc, typ="vc+sd-jwt")), None)


def test_the_refusal_is_a_typed_openvc_error_of_the_exact_class(run, form):
    # Callers catch OpenvcError; the class is the suite's own, not a bare ValueError or
    # a wrapped ClaimsInvalid.
    with pytest.raises(OpenvcError) as excinfo:
        run(form(_mint(_vct_less(), typ="vc+sd-jwt")), None)
    assert excinfo.type is SdJwtError


@pytest.mark.parametrize("media", ["application/vc+sd-jwt", "application/dc+sd-jwt"])
def test_enveloped_media_type_does_not_talk_the_token_into_verifying(run, media):
    # The data: URL's media type is not signed. Neither the W3C nor the IETF one turns a
    # vct-less, context-less vc+sd-jwt into a verifiable credential.
    with pytest.raises(SdJwtError, match=REFUSED):
        run(_envelope(_mint(_vct_less(), typ="vc+sd-jwt"), media=media), None)


def test_double_envelope_is_refused_too(run):
    inner = _envelope(_mint(_vct_less(), typ="vc+sd-jwt"))
    outer = _envelope(json.dumps(inner), media="application/vc+ld+json")
    with pytest.raises(SdJwtError, match=REFUSED):
        run(outer, None)


# --------------------------------------------------------------------------- #
# a disclosable vct the holder withholds
# --------------------------------------------------------------------------- #

def test_a_withheld_vct_on_a_vc_sd_jwt_is_refused(run, form):
    # The issuer made vct a disclosure; the holder presents the token without it. The
    # payload then looked vct-less, hence VCDM, hence needed no vct.
    sd_jwt = _without(_mint(_ietf(), typ="vc+sd-jwt", disclose=["vct"]), "vct")
    with pytest.raises(SdJwtError, match=REFUSED):
        run(form(sd_jwt), None)


def test_a_withheld_vct_on_a_dc_sd_jwt_is_still_missing(run, form):
    sd_jwt = _without(_mint(_ietf(), typ="dc+sd-jwt", disclose=["vct"]), "vct")
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT):
        run(form(sd_jwt), None)


@pytest.mark.parametrize("typ", ["vc+sd-jwt", "dc+sd-jwt"])
def test_a_presented_disclosable_vct_is_refused_as_a_disclosure(run, form, typ):
    # The other half: not withheld, but still not allowed to be selectively disclosed
    # (draft-19 §2.2.2.3), whatever the typ.
    with pytest.raises(SdJwtError, match="'vct' is selectively disclosed"):
        run(form(_mint(_ietf(), typ=typ, disclose=["vct"])), None)


# --------------------------------------------------------------------------- #
# vc+sd-jwt with a VCDM @context is still a VCDM credential
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("context", [
    [V2, "https://www.w3.org/ns/credentials/examples/v2"],
    V2,
    ["https://example.org/ctx", V2],
    [V1],
], ids=["v2-array", "v2-string", "v2-not-first", "v1"])
@pytest.mark.parametrize("with_vct", [False, True], ids=["no-vct", "with-vct"])
def test_vc_sd_jwt_with_a_vcdm_context_verifies_as_vcdm(run, form, context, with_vct):
    doc = _vcdm(**{"@context": context})
    if with_vct:
        doc["vct"] = VCT
    result = run(form(_mint(doc, typ="vc+sd-jwt")), None)
    assert result.raw.vcdm is True
    assert result.raw.vct == (VCT if with_vct else None)


def test_suite_result_reports_vcdm_for_a_vc_sd_jwt_with_a_vcdm_context():
    result = _suite_verify(_mint(_vcdm(), typ="vc+sd-jwt"))
    assert result.vcdm is True
    assert result.vct is None


def test_vc_sd_jwt_is_vcdm_by_its_context_and_not_by_its_typ():
    # The same VCDM body verifies the same way under either typ; only the context matters.
    for typ in ("vc+sd-jwt", "dc+sd-jwt"):
        assert _suite_verify(_mint(_vcdm(), typ=typ)).vcdm is True


def test_vc_sd_jwt_vcdm_expired_valid_until_still_fails(run, form):
    for extra in ({}, {"vct": VCT}):
        with pytest.raises(CredentialExpired):
            run(form(_mint(_vcdm(validUntil=PAST, **extra), typ="vc+sd-jwt")), None)


def test_vc_sd_jwt_vcdm_future_valid_from_still_fails(run, form):
    with pytest.raises(CredentialNotYetValid):
        run(form(_mint(_vcdm(validFrom="2099-01-01T00:00:00Z"), typ="vc+sd-jwt")), None)


def test_vc_sd_jwt_vcdm_window_is_waived_like_before(run, form):
    waived = VerificationPolicy(require_not_expired=False)
    result = run(form(_mint(_vcdm(validUntil=PAST), typ="vc+sd-jwt")), waived)
    assert result.expired is True
    assert result.raw.vcdm is True


def test_vc_sd_jwt_vcdm_issuer_conflict_still_fails(run, form):
    # The consistency rules still bind a vc+sd-jwt that is VCDM by its context.
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer="did:web:university.example"), typ="vc+sd-jwt")), None)


def test_a_disclosable_context_is_still_refused_on_a_vc_sd_jwt(run, form):
    # @context carries the VCDM verdict, so it may not be withholdable: a presented one is
    # refused as a disclosure, ahead of the typ check.
    with pytest.raises(SdJwtError, match="'@context' is selectively disclosed"):
        run(form(_mint(_vcdm(), typ="vc+sd-jwt", disclose=["@context"])), None)


def test_a_withheld_context_leaves_a_vc_sd_jwt_refused(run):
    # The holder drops a disclosable @context: the payload is then not VCDM, and the
    # vc+sd-jwt typ says it must be. The issuer's mistake cannot downgrade the verdict
    # into an IETF payload that skips its vct.
    sd_jwt = _without(_mint(_vcdm(), typ="vc+sd-jwt", disclose=["@context"]), "@context")
    with pytest.raises(SdJwtError, match=REFUSED):
        run(sd_jwt, None)


# --------------------------------------------------------------------------- #
# OpenID4VP — a vct-less vc+sd-jwt must not answer a dc+sd-jwt query
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


def test_openid4vp_control_a_dc_sd_jwt_answers_a_query_without_vct_values():
    # The harness itself: the IETF typ with a vct is what a dc+sd-jwt query asks for.
    answer = _answer(_present(_ietf(), typ="dc+sd-jwt"))
    assert answer.raw.vct == VCT
    assert answer.raw.key_bound is True


def test_openid4vp_dc_sd_jwt_query_refuses_a_vct_less_vc_sd_jwt():
    # No vct_values, so nothing downstream would have checked the vct: the suite's own
    # rule is the only gate. It used to answer with vct=None.
    with pytest.raises(SdJwtError, match=REFUSED):
        _answer(_present(_vct_less(), typ="vc+sd-jwt"))


def test_openid4vp_dc_sd_jwt_query_refuses_a_vct_bearing_vc_sd_jwt():
    # A legacy (pre-draft-06) issuer's credential, with the vct the query even asks for.
    with pytest.raises(SdJwtError, match=REFUSED):
        _answer(_present(_ietf(), typ="vc+sd-jwt"), vct_values=[VCT])
