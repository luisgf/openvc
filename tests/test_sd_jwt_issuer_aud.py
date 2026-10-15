"""SD-JWT VC issuer JWT ``aud`` — RFC 7519 §4.1.3 (#227, ADR-0008 D4).

"If the principal processing the claim does not identify itself with a value in the
``aud`` claim when this claim is present, then the JWT MUST be rejected." The issuer JWT
of an SD-JWT VC is a JWT, and an issuer that restricted a credential to one relying party
signed that restriction into ``aud``. Through v1.34.0 the SD-JWT lane never read it: the
KB-JWT's ``aud`` binds the *holder's presentation* to a verifier (RFC 9901 §7.3 step 5.6)
and says nothing about the issuer's restriction, so a holder who received a credential for
``other-rp`` could present it, correctly bound, to anyone.

The rule, present-only (the one asymmetry with VC-JWT, whose ``aud`` must be there when an
audience is expected): ``aud`` absent -> unchanged; ``aud`` present -> a string or an array
of strings, and the caller's audience must be one of them, so with no audience a restricted
credential is refused. It is read on the processed payload, after the KB-JWT when binding is
required, and it is not an expiry: no waiver reaches it and no message describes an expiry.

Every case runs under the default policy and ``require_not_expired=False`` where it can.
Helpers are self-contained (tests/ is not a package: nothing is imported from another test
module).
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import verify_vp_token
from openvc.proof import _verify_common
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof._verify_common import check_jwt_audience
from openvc.proof.errors import ClaimsInvalid, SignatureInvalid
from openvc.proof.sd_jwt import (
    SdJwtVcProofSuite,
    disclosure_digest,
    make_array_disclosure,
)
from openvc.proof.vp_jwt import VpJwtProofSuite

V2 = "https://www.w3.org/ns/credentials/v2"
ME = "https://verifier.example"
OTHER = "https://other-rp.example"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
ORIGIN = "https://verifier.example"
VCT = "https://credentials.example.com/identity_credential"
ABSENT = object()                         # the issuer JWT carries no `aud` at all
WAIVED = {"require_not_expired": False}
POLICY_KW = pytest.mark.parametrize("waiver", [{}, WAIVED], ids=["default", "waived"])
# Shapes `aud` may not have (RFC 7519 §4.1.1-§4.1.3), as Python values: issue() writes
# them out as the JSON null / number / object / true / mixed array / nested array.
MALFORMED = pytest.mark.parametrize("aud", [
    pytest.param(None, id="null"),
    pytest.param(5, id="number"),
    pytest.param({}, id="object"),
    pytest.param(True, id="true"),
    pytest.param([ME, 5], id="mixed-array"),
    pytest.param([[ME]], id="nested-array"),
])
# A restriction naming someone else, in every spelling the RFC allows.
RESTRICTED_TO_OTHERS = pytest.mark.parametrize("aud", [
    pytest.param(OTHER, id="string"),
    pytest.param([OTHER], id="array-of-one"),
    pytest.param([OTHER, "https://third.example"], id="array-of-others"),
    pytest.param("", id="empty-string"),
    pytest.param([], id="empty-array"),
])
# Naming the verifier, alone or among others.
NAMING_ME = pytest.mark.parametrize("aud", [
    pytest.param(ME, id="string"),
    pytest.param([ME], id="array-of-one"),
    pytest.param([OTHER, ME], id="array-with-me-second"),
])


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _did_jwk_issuer() -> tuple[P256SigningKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = P256SigningKey(priv, kid="tmp").public_jwk()
    did = "did:jwk:" + _b64(json.dumps(jwk, separators=(",", ":")).encode())
    return P256SigningKey(priv, kid=f"{did}#0"), did


KEY, DID = _did_jwk_issuer()
HOLDER = P256SigningKey.generate(kid="holder")
SUITE = SdJwtVcProofSuite()


def _policy(waiver: dict, **kw) -> VerificationPolicy:
    return VerificationPolicy(**waiver, **kw)


def _kb_policy(waiver: dict, audience: str = ME) -> VerificationPolicy:
    return _policy(waiver, audience=audience, nonce=NONCE, require_key_binding=True)


def _issue(aud=ABSENT, *, disclosable=(), expires_in_s=None, claims=None) -> str:
    """An SD-JWT VC from ``DID``, bound to ``HOLDER``, with the issuer JWT ``aud`` *aud*."""
    body = {"iss": DID, "given_name": "Ada", **(claims or {})}
    if aud is not ABSENT:
        body["aud"] = aud
    return SUITE.issue(
        body, signing_key=KEY, vct=VCT, disclosable=["given_name", *disclosable],
        holder_jwk=HOLDER.public_jwk(), expires_in_s=expires_in_s)


def _present(sd_jwt: str, *, audience: str = ME, nonce: str = NONCE) -> str:
    return SUITE.create_presentation(sd_jwt, holder_key=HOLDER, audience=audience, nonce=nonce)


@pytest.fixture(params=["sync", "async"])
def run(request):
    """The pipeline, sync and async: ``run(token, policy)``."""
    if request.param == "sync":
        return lambda token, policy=None: verify_credential(token, policy=policy)
    return lambda token, policy=None: asyncio.run(verify_credential_async(token, policy=policy))


def _refused(call, *, match: str) -> ClaimsInvalid:
    """*call* raises exactly ``ClaimsInvalid`` (not a subclass, not an earlier failure),
    matching *match*, and the message is not an expiry verdict (wiki/SD-JWT-VC.md; the audiences
    used here never contain the word, which is the only way it could appear)."""
    with pytest.raises(ClaimsInvalid, match=match) as excinfo:
        call()
    assert excinfo.type is ClaimsInvalid
    assert "expired" not in str(excinfo.value)
    return excinfo.value


NO_AUDIENCE = r"restricted to an audience.*RFC 7519 §4\.1\.3"
NOT_NAMED = r"issuer JWT aud does not include"
BAD_SHAPE = r"issuer JWT aud must be a string or an array of strings"


# --------------------------------------------------------------------------- #
# A. the finding: a credential restricted to another relying party
# --------------------------------------------------------------------------- #

@POLICY_KW
@RESTRICTED_TO_OTHERS
def test_aud_without_an_audience_is_rejected_by_the_pipeline(run, aud, waiver):
    # Row 1 of the issue: no audience given, `aud` names someone else.
    _refused(lambda: run(_issue(aud), _policy(waiver)), match=NO_AUDIENCE)


@pytest.mark.parametrize("check_temporal", [True, False], ids=["temporal", "waived"])
@RESTRICTED_TO_OTHERS
def test_aud_without_an_audience_is_rejected_by_the_suite(aud, check_temporal):
    _refused(lambda: SUITE.verify(_issue(aud), public_key_jwk=KEY.public_jwk(),
                                  check_temporal=check_temporal), match=NO_AUDIENCE)


@POLICY_KW
@RESTRICTED_TO_OTHERS
def test_aud_not_naming_the_policy_audience_is_rejected(run, aud, waiver):
    # Row 2: `VerificationPolicy(audience=ME)`, no KB-JWT, `aud` names someone else.
    _refused(lambda: run(_issue(aud), _policy(waiver, audience=ME)), match=NOT_NAMED)


@POLICY_KW
@RESTRICTED_TO_OTHERS
def test_aud_not_naming_the_audience_is_rejected_with_a_correct_kb_jwt(run, aud, waiver):
    # Row 3, the one the KB-JWT used to launder: a KB-JWT correctly bound to ME, a
    # required binding, and an issuer that restricted the credential to someone else.
    token = _present(_issue(aud))
    _refused(lambda: run(token, _kb_policy(waiver)), match=NOT_NAMED)
    # ... and the same on the hosted path (binding not required, KB-JWT present)
    hosted = _policy(waiver, audience=ME, nonce=NONCE)
    _refused(lambda: run(token, hosted), match=NOT_NAMED)


def test_the_suite_rejects_it_too_directly_with_a_correct_kb_jwt():
    token = _present(_issue(OTHER))
    for require in (True, False):
        _refused(lambda: SUITE.verify(
            token, public_key_jwk=KEY.public_jwk(), audience=ME, nonce=NONCE,
            require_key_binding=require), match=NOT_NAMED)


@pytest.mark.parametrize("batch_fn", [
    pytest.param(lambda b, p: verify_many(b, policy=p), id="sync"),
    pytest.param(lambda b, p: asyncio.run(verify_many_async(b, policy=p)), id="async"),
])
@POLICY_KW
def test_batch_isolates_an_audience_restricted_credential(batch_fn, waiver):
    # No audience: the restricted items fail, the unrestricted ones around them verify.
    results = batch_fn([_issue(), _issue(OTHER), _issue(), _issue([ME])], _policy(waiver))
    assert [r.ok for r in results] == [True, False, True, False]
    for r in (results[1], results[3]):
        assert type(r.error) is ClaimsInvalid
        assert re.search(NO_AUDIENCE, str(r.error))
        assert "expired" not in str(r.error)
    # An audience: only the credential that names someone else fails.
    results = batch_fn([_issue(), _issue(ME), _issue(OTHER), _issue([OTHER, ME])],
                       _policy(waiver, audience=ME))
    assert [r.ok for r in results] == [True, True, False, True]
    assert type(results[2].error) is ClaimsInvalid
    assert re.search(NOT_NAMED, str(results[2].error))
    assert "expired" not in str(results[2].error)


# --------------------------------------------------------------------------- #
# B. malformed shapes, with and without an audience
# --------------------------------------------------------------------------- #

@POLICY_KW
@MALFORMED
def test_malformed_aud_is_rejected_with_and_without_an_audience(run, aud, waiver):
    token = _issue(aud)
    _refused(lambda: run(token, _policy(waiver)), match=BAD_SHAPE)
    _refused(lambda: run(token, _policy(waiver, audience=ME)), match=BAD_SHAPE)
    _refused(lambda: run(_present(token), _kb_policy(waiver)), match=BAD_SHAPE)


@MALFORMED
def test_malformed_aud_is_rejected_by_the_suite(aud):
    for audience in (None, ME):
        _refused(lambda: SUITE.verify(_issue(aud), public_key_jwk=KEY.public_jwk(),
                                      audience=audience), match=BAD_SHAPE)


# --------------------------------------------------------------------------- #
# C. naming the verifier verifies
# --------------------------------------------------------------------------- #

@POLICY_KW
@NAMING_ME
def test_aud_naming_the_audience_verifies_hosted(run, aud, waiver):
    result = run(_issue(aud), _policy(waiver, audience=ME))
    assert result.issuer == DID
    assert result.key_bound is False
    assert result.claims["aud"] == aud


@POLICY_KW
@NAMING_ME
def test_aud_naming_the_audience_verifies_with_required_key_binding(run, aud, waiver):
    result = run(_present(_issue(aud)), _kb_policy(waiver))
    assert result.key_bound is True
    assert result.claims["given_name"] == "Ada"


def test_aud_naming_the_audience_verifies_through_the_suite():
    token = _present(_issue([OTHER, ME]))
    result = SUITE.verify(token, public_key_jwk=KEY.public_jwk(), audience=ME, nonce=NONCE,
                          require_key_binding=True)
    assert result.key_bound is True


def test_a_longer_or_differently_cased_audience_is_not_the_one_named():
    # exact string equality, as RFC 7519 §4.1.3 reads it ("a value in the aud claim")
    for near in (ME + "/", ME.upper(), "x" + ME, ME[:-1], " " + ME):
        _refused(lambda: SUITE.verify(
            _issue(ME), public_key_jwk=KEY.public_jwk(), audience=near), match=NOT_NAMED)


# --------------------------------------------------------------------------- #
# D. unchanged: an issuer JWT without `aud` (the interop-critical case)
# --------------------------------------------------------------------------- #

@POLICY_KW
def test_no_aud_verifies_with_and_without_an_audience(run, waiver):
    token = _issue()
    assert run(token, _policy(waiver)).issuer == DID
    assert run(token, _policy(waiver, audience=ME)).issuer == DID
    bound = run(_present(token), _kb_policy(waiver))
    assert bound.key_bound is True
    assert "aud" not in bound.claims


def test_no_aud_is_not_a_reason_to_look_at_the_audience():
    # An absent `aud` is "unchanged", so the expected audience is not even inspected: an
    # empty string with no KB-JWT verified before this rule and still does.
    token = _issue()
    assert SUITE.verify(token, public_key_jwk=KEY.public_jwk(), audience="").issuer == DID
    assert SUITE.verify(token, public_key_jwk=KEY.public_jwk(), audience=None).issuer == DID


@pytest.mark.parametrize("audience", ["", 5, ["https://verifier.example"]],
                         ids=["empty", "number", "list"])
def test_a_present_aud_needs_a_sane_expected_audience(audience):
    # A restriction is matched against what the caller says it is, so that has to be a
    # non-empty string: ClaimsInvalid with the audience's own message, not "does not include".
    _refused(lambda: SUITE.verify(_issue(OTHER), public_key_jwk=KEY.public_jwk(),
                                  audience=audience),
             match="expected audience must be a non-empty string or None")


# --------------------------------------------------------------------------- #
# E. an `aud` the issuer made disclosable
# --------------------------------------------------------------------------- #

def _strip_disclosures(sd_jwt: str) -> str:
    """The issuer JWT alone: every disclosure withheld, no KB-JWT."""
    return sd_jwt.split("~", 1)[0] + "~"


@POLICY_KW
def test_a_disclosed_aud_that_names_someone_else_is_rejected(run, waiver):
    token = _issue(OTHER, disclosable=["aud"])
    assert '"aud"' not in base64.urlsafe_b64decode(
        token.split(".")[1] + "==").decode()             # it really left the signed body
    _refused(lambda: run(token, _policy(waiver)), match=NO_AUDIENCE)
    _refused(lambda: run(token, _policy(waiver, audience=ME)), match=NOT_NAMED)
    _refused(lambda: run(_present(token), _kb_policy(waiver)), match=NOT_NAMED)


@POLICY_KW
def test_a_disclosed_aud_that_names_the_verifier_verifies(run, waiver):
    token = _issue([OTHER, ME], disclosable=["aud"])
    assert run(token, _policy(waiver, audience=ME)).claims["aud"] == [OTHER, ME]
    assert run(_present(token), _kb_policy(waiver)).key_bound is True


@POLICY_KW
def test_a_withheld_aud_disclosure_is_invisible_to_the_verifier(run, waiver):
    # The documented limit, the same as a withheld `exp`: the holder omits the disclosure
    # and the restriction is gone. An issuer must never make `aud` disclosable.
    token = _strip_disclosures(_issue(OTHER, disclosable=["aud"]))
    result = run(token, _policy(waiver, audience=ME))
    assert "aud" not in result.claims


def _digest_array_credential(entries: list[str]) -> tuple[str, dict[str, str]]:
    """An issuer JWT whose `aud` is an array of digests (RFC 9901 §9.7 lets an issuer make
    individual `aud` entries disclosable), plus the disclosure of each entry by value."""
    disclosures = {e: make_array_disclosure(_b64(f"salt-{i}".encode()), e)
                   for i, e in enumerate(entries)}
    aud = [{"...": disclosure_digest(d)} for d in disclosures.values()]
    return _issue(claims={"aud": aud}), disclosures


def _with(token: str, *disclosures: str) -> str:
    return token + "".join(d + "~" for d in disclosures)


def test_a_per_entry_disclosable_aud_is_judged_on_the_entries_disclosed():
    base, d = _digest_array_credential([OTHER, ME])
    jwk = KEY.public_jwk()
    # the verifier's entry is disclosed: verifies, and only that entry is in the claims
    token = _with(base, d[ME])
    assert SUITE.verify(token, public_key_jwk=jwk, audience=ME).claims["aud"] == [ME]
    # both are disclosed: verifies for the verifier named in it
    both = SUITE.verify(_with(base, d[OTHER], d[ME]), public_key_jwk=jwk, audience=ME)
    assert both.claims["aud"] == [OTHER, ME]
    # only someone else's entry is disclosed: not addressed to this verifier
    _refused(lambda: SUITE.verify(_with(base, d[OTHER]), public_key_jwk=jwk, audience=ME),
             match=NOT_NAMED)
    # with no audience a restricted credential is refused, whichever entry shows
    _refused(lambda: SUITE.verify(token, public_key_jwk=jwk), match=NO_AUDIENCE)


@POLICY_KW
def test_a_per_entry_aud_with_every_entry_withheld_fails_closed(run, waiver):
    # `aud: []` once the digests are dropped: present, and nothing in it names anyone.
    base, _ = _digest_array_credential([OTHER, ME])
    _refused(lambda: run(base, _policy(waiver, audience=ME)), match=NOT_NAMED)
    _refused(lambda: run(base, _policy(waiver)), match=NO_AUDIENCE)


@POLICY_KW
def test_a_per_entry_aud_is_not_called_malformed(run, waiver):
    # The digest objects in the *signed* array are not strings, so a check of the issuer
    # JWT body would call a spec-conformant issuer's `aud` malformed. It is the processed
    # payload that is read.
    base, d = _digest_array_credential([OTHER, ME])
    token = _with(base, d[ME])
    assert run(token, _policy(waiver, audience=ME)).claims["aud"] == [ME]
    # refused for being addressed to someone else, never for its shape
    _refused(lambda: run(token, _policy(waiver)), match=NO_AUDIENCE)
    _refused(lambda: run(token, _policy(waiver, audience=OTHER)), match=NOT_NAMED)


def test_the_shared_helper_has_a_present_only_mode():
    # `require_present=False` is the SD-JWT VC issuer JWT's rule; the default is VC-JWT's.
    assert check_jwt_audience({}, ME, require_present=False) is None
    assert check_jwt_audience({}, None, require_present=False) is None
    assert check_jwt_audience({}, "", require_present=False) is None      # not inspected
    with pytest.raises(ClaimsInvalid, match="has no aud claim") as excinfo:
        check_jwt_audience({}, ME)
    assert excinfo.type is ClaimsInvalid
    # present, it is the same rule in both modes
    for require in (True, False):
        assert check_jwt_audience({"aud": [ME]}, ME, require_present=require) is None
        with pytest.raises(ClaimsInvalid, match=NO_AUDIENCE):
            check_jwt_audience({"aud": OTHER}, None, require_present=require)
        with pytest.raises(ClaimsInvalid, match="does not include"):
            check_jwt_audience({"aud": OTHER}, ME, require_present=require)
        with pytest.raises(ClaimsInvalid, match="expected audience must be"):
            check_jwt_audience({"aud": OTHER}, "", require_present=require)


# --------------------------------------------------------------------------- #
# F. the check is not an expiry
# --------------------------------------------------------------------------- #

def test_the_expiry_waiver_does_not_waive_the_audience():
    expired = _issue(OTHER, expires_in_s=-3600)
    waived = _policy(WAIVED, audience=ME)
    # `exp` passed: waived, but the audience restriction is not an expiry
    _refused(lambda: verify_credential(expired, policy=waived), match=NOT_NAMED)
    # control: the same expiry with an `aud` that names the verifier is waived, and reported
    ok = verify_credential(_issue(ME, expires_in_s=-3600), policy=waived)
    assert ok.expired is True
    # and the default policy still reports the expiry first, as an expiry
    with pytest.raises(ClaimsInvalid, match="expired"):
        verify_credential(_issue(OTHER, expires_in_s=-3600),
                          policy=_policy({}, audience=ME))


def test_a_required_binding_checks_the_kb_jwt_before_the_issuer_aud():
    # `require_key_binding=True` verifies the KB-JWT first, so a ClaimsInvalid naming the
    # issuer JWT's aud from such a call means the presentation was bound. A KB-JWT made
    # for another verifier is the KB-JWT's own failure, not the issuer's `aud`.
    token = _issue(OTHER)
    unbound = _present(token, audience="https://elsewhere.example")
    _refused(lambda: SUITE.verify(
        unbound, public_key_jwk=KEY.public_jwk(), audience=ME, nonce=NONCE,
        require_key_binding=True), match="KB-JWT aud does not match")
    bound = _present(token)
    _refused(lambda: SUITE.verify(
        bound, public_key_jwk=KEY.public_jwk(), audience=ME, nonce=NONCE,
        require_key_binding=True), match=NOT_NAMED)


# --------------------------------------------------------------------------- #
# G. nested in a W3C presentation: the presentation's audience
# --------------------------------------------------------------------------- #

def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_ed25519():
    key = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())   # ed25519-pub
    return Ed25519SigningKey(key._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


NESTED_ISSUER = _did_key_p256()
NESTED_HOLDER = _did_key_p256()


def _nested_sd_jwt(aud, *, bound_to=CLIENT_ID):
    """An SD-JWT VC whose issuer JWT has `aud` *aud*, with a KB-JWT over (bound_to, NONCE)."""
    (issuer_key, issuer_did), (holder_key, holder_did) = NESTED_ISSUER, NESTED_HOLDER
    claims = {"iss": issuer_did, "given_name": "Ada", "sub": holder_did}
    if aud is not ABSENT:
        claims["aud"] = aud
    issued = SUITE.issue(claims, signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
                         holder_jwk=holder_key.public_jwk())
    return SUITE.create_presentation(
        issued, holder_key=holder_key, audience=bound_to, nonce=NONCE)


def _vp_jwt(entries, *, audience=CLIENT_ID):
    return VpJwtProofSuite().sign(
        list(entries), holder_key=NESTED_HOLDER[0], audience=audience, nonce=NONCE)


def _ldp_vp(entries, *, domain=CLIENT_ID):
    vp_key, vp_did = _did_key_ed25519()
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": vp_did,
          "verifiableCredential": list(entries)}
    return EddsaJcsProofSuite().add_proof(
        vp, signing_key=vp_key, verification_method=vp_key.kid,
        proof_purpose="authentication", challenge=NONCE, domain=domain)


def _verify_vp(vp, fmt: str, client_id: str = CLIENT_ID):
    dcql = {"credentials": [{"id": "q", "format": fmt}]}
    return verify_vp_token({"q": [vp]}, dcql_query=dcql, nonce=NONCE,
                           client_id=client_id).for_query("q")[0]


@pytest.mark.parametrize("envelope", [False, True], ids=["bare", "enveloped"])
def test_nested_in_a_vp_jwt_the_presentations_audience_is_the_one(envelope):
    def entry(sd_jwt):
        return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
                "id": f"data:application/dc+sd-jwt,{sd_jwt}"} if envelope else sd_jwt

    ok = _vp_jwt([entry(_nested_sd_jwt(CLIENT_ID))])
    (cred,) = _verify_vp(ok, "jwt_vc_json").credentials
    assert cred.key_bound is True
    # the same credential restricted to someone else rejects the whole presentation
    bad = _vp_jwt([entry(_nested_sd_jwt(OTHER))])
    _refused(lambda: _verify_vp(bad, "jwt_vc_json"), match=NOT_NAMED)
    # one restricted entry among good ones fails the whole presentation
    mixed = _vp_jwt([entry(_nested_sd_jwt(CLIENT_ID)), entry(_nested_sd_jwt(OTHER)),
                     entry(_nested_sd_jwt(ABSENT))])
    _refused(lambda: _verify_vp(mixed, "jwt_vc_json"), match=NOT_NAMED)


def test_nested_without_an_aud_is_unchanged():
    vp = _vp_jwt([_nested_sd_jwt(ABSENT), _nested_sd_jwt(CLIENT_ID)])
    assert [c.key_bound for c in _verify_vp(vp, "jwt_vc_json").credentials] == [True, True]


def test_nested_through_the_vp_jwt_suite_directly():
    policy = VerificationPolicy(require_status=False)
    ok = _vp_jwt([_nested_sd_jwt(CLIENT_ID)])
    (cred,) = VpJwtProofSuite().verify(ok, audience=CLIENT_ID, nonce=NONCE,
                                       policy=policy).credentials
    assert cred.key_bound is True
    bad = _vp_jwt([_nested_sd_jwt(OTHER)])
    _refused(lambda: VpJwtProofSuite().verify(bad, audience=CLIENT_ID, nonce=NONCE,
                                              policy=policy), match=NOT_NAMED)


def test_the_policy_audience_does_not_stand_in_for_the_presentations():
    # Nested, the credential is held to the presentation's audience, as its KB-JWT is
    # (the opposite of a nested VC-JWT, ADR-0008): the policy's own `audience` neither
    # admits a credential restricted to someone else nor refuses one that names CLIENT_ID.
    policy = VerificationPolicy(require_status=False, audience=OTHER)
    here = _vp_jwt([_nested_sd_jwt(CLIENT_ID)])
    (cred,) = VpJwtProofSuite().verify(here, audience=CLIENT_ID, nonce=NONCE,
                                       policy=policy).credentials
    assert cred.key_bound is True
    elsewhere = _vp_jwt([_nested_sd_jwt(OTHER)])
    _refused(lambda: VpJwtProofSuite().verify(elsewhere, audience=CLIENT_ID, nonce=NONCE,
                                              policy=policy), match=NOT_NAMED)


@pytest.mark.parametrize("envelope", [False, True], ids=["bare", "enveloped"])
def test_nested_in_a_data_integrity_presentation(envelope):
    def entry(sd_jwt):
        return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
                "id": f"data:application/dc+sd-jwt,{sd_jwt}"} if envelope else sd_jwt

    ok = _ldp_vp([entry(_nested_sd_jwt(CLIENT_ID))])
    (cred,) = _verify_vp(ok, "ldp_vc").credentials
    assert cred.key_bound is True
    bad = _ldp_vp([entry(_nested_sd_jwt(OTHER))])
    _refused(lambda: _verify_vp(bad, "ldp_vc"), match=NOT_NAMED)


# --------------------------------------------------------------------------- #
# H. the OpenID4VP `dc+sd-jwt` lane: client_id, or origin:<origin> on the DC API
# --------------------------------------------------------------------------- #

def test_openid4vp_dc_sd_jwt_aud_naming_the_client_id_verifies():
    token = _nested_sd_jwt(CLIENT_ID)
    result = _verify_vp(token, "dc+sd-jwt")
    assert result.raw.key_bound is True
    assert result.raw.claims["aud"] == CLIENT_ID


def test_openid4vp_dc_sd_jwt_aud_naming_someone_else_is_rejected():
    for aud in (OTHER, [OTHER], "client.example.org", [CLIENT_ID.upper()]):
        _refused(lambda: _verify_vp(_nested_sd_jwt(aud), "dc+sd-jwt"), match=NOT_NAMED)


def test_openid4vp_dc_sd_jwt_without_an_aud_is_unchanged():
    result = _verify_vp(_nested_sd_jwt(ABSENT), "dc+sd-jwt")
    assert result.raw.key_bound is True
    assert "aud" not in result.raw.claims


def _dc_api(token: str):
    dcql = {"credentials": [{"id": "q", "format": "dc+sd-jwt"}]}
    return verify_vp_token({"q": [token]}, dcql_query=dcql, nonce=NONCE,
                           expected_origins=[ORIGIN, "https://second.example"]
                           ).for_query("q")[0]


def test_openid4vp_dc_api_aud_must_name_the_origin_form():
    audience = f"origin:{ORIGIN}"
    ok = _nested_sd_jwt([OTHER, audience], bound_to=audience)
    assert _dc_api(ok).raw.key_bound is True
    # the bare origin is not the audience a DC API presentation is bound to
    _refused(lambda: _dc_api(_nested_sd_jwt(ORIGIN, bound_to=audience)), match=NOT_NAMED)
    _refused(lambda: _dc_api(_nested_sd_jwt("origin:https://second.example",
                                            bound_to=audience)), match=NOT_NAMED)


# --------------------------------------------------------------------------- #
# I. third-party vectors carry no issuer `aud`, and still verify
# --------------------------------------------------------------------------- #

FIX = Path(__file__).parent / "fixtures"
SD = FIX / "interop" / "sd_jwt_vc"
RECORDED_AT = datetime.datetime.fromtimestamp(1783414834, datetime.timezone.utc)
FROZEN_EPOCH = datetime.datetime(2026, 7, 16, tzinfo=datetime.timezone.utc).timestamp()


def _issuer_claims(wire: str) -> dict:
    payload = wire.split("~", 1)[0].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _leaf_public_jwk(pem_path: Path) -> dict:
    from cryptography import x509
    nums = x509.load_pem_x509_certificate(pem_path.read_bytes()).public_key().public_numbers()
    b64 = lambda n: _b64(n.to_bytes(32, "big"))                       # noqa: E731
    return {"kty": "EC", "crv": "P-256", "x": b64(nums.x), "y": b64(nums.y)}


@pytest.fixture
def frozen_clock(monkeypatch):
    monkeypatch.setattr(_verify_common.time, "time", lambda: FROZEN_EPOCH)


@pytest.mark.parametrize("audience", [None, ME], ids=["no-audience", "audience"])
def test_the_rfc9901_a3_vector_has_no_aud_and_verifies(frozen_clock, audience):
    wire = (SD / "rfc9901-a3-sd-jwt-vc.txt").read_text().strip()
    assert "aud" not in _issuer_claims(wire)
    jwk = json.loads((SD / "rfc9901-a5-issuer-key.json").read_text())
    result = SUITE.verify(wire, public_key_jwk=jwk, audience=audience)
    assert result.claims["given_name"] == "Erika"


@pytest.mark.parametrize("audience", [None, ME], ids=["no-audience", "audience"])
def test_the_eudi_pid_vector_has_no_aud_and_verifies(frozen_clock, audience):
    wire = (SD / "eudi-pid-sd-jwt-vc.txt").read_text().strip()
    assert "aud" not in _issuer_claims(wire)
    result = SUITE.verify(wire, public_key_jwk=_leaf_public_jwk(SD / "eudi-pid-issuer.pem"),
                          audience=audience)
    assert result.vct == "urn:eudi:pid:1"


def test_the_openid4vp_capture_has_no_issuer_aud_and_verifies():
    capture = json.loads((FIX / "openid4vp" / "sd_jwt_vc_vp_token.json").read_text())
    (presentation,) = capture["vp_token"]["my_credential"]
    assert "aud" not in _issuer_claims(presentation)
    result = verify_vp_token(
        capture["vp_token"], dcql_query=capture["dcql_query"], nonce=capture["nonce"],
        client_id=capture["client_id"], now=RECORDED_AT)
    (verified,) = result.for_query("my_credential")
    assert verified.raw.claims["given_name"] == capture["expect"]["given_name"]


def test_a_forged_issuer_aud_still_fails_on_the_signature_first():
    # Control: the audience check reads only a signature-verified payload.
    token = _issue(OTHER)
    head, payload, sig = token.split("~", 1)[0].split(".")
    forged_claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    forged_claims["aud"] = ME
    forged = ".".join([head, _b64(json.dumps(forged_claims).encode()), sig])
    forged_token = forged + "~" + token.split("~", 1)[1]
    with pytest.raises(SignatureInvalid) as excinfo:
        SUITE.verify(forged_token, public_key_jwk=KEY.public_jwk(), audience=ME)
    assert excinfo.type is SignatureInvalid


# --------------------------------------------------------------------------- #
# J. a W3C VCDM payload: every `typ` it may carry, with and without `iss` (#290)
# --------------------------------------------------------------------------- #
# The check is not gated on the payload's shape or on `typ`: a W3C credential secured as an
# SD-JWT, typed `vc+sd-jwt` / `vc+ld+json+sd-jwt`, typed `dc+sd-jwt`, or carrying no `typ`
# at all, is held to the issuer's `aud` like an IETF one. A VCDM payload with no `iss` is
# keyed on its `issuer` (#290), and a typ-less one is the shape a bare W3C JWS with a `~`
# appended takes on its way here. `SUITE.issue` writes neither (it always writes `dc+sd-jwt`
# and needs a `vct`), so the token is minted by hand; helpers are copied, not imported.

NO_TYP = None                             # `_mint_vcdm(typ=NO_TYP)`: no `typ` member at all
VCDM_SHAPES = pytest.mark.parametrize("typ, with_iss", [
    pytest.param(NO_TYP, True, id="no-typ-iss"),
    pytest.param(NO_TYP, False, id="no-typ-no-iss"),
    pytest.param("vc+sd-jwt", True, id="vc+sd-jwt-iss"),
    pytest.param("vc+sd-jwt", False, id="vc+sd-jwt-no-iss"),
    pytest.param("vc+ld+json+sd-jwt", True, id="draft-typ-iss"),
    pytest.param("vc+ld+json+sd-jwt", False, id="draft-typ-no-iss"),
    # `dc+sd-jwt` needs an `iss` (the VCDM `issuer` stands in only for a W3C typ or none)
    pytest.param("dc+sd-jwt", True, id="dc+sd-jwt-iss"),
])


def _vcdm_issued(aud=ABSENT, *, typ, with_iss: bool) -> str:
    """A W3C VCDM credential from ``DID`` as an SD-JWT (no disclosures), bound to ``HOLDER``,
    with the issuer JWT ``aud`` *aud*; *typ* ``NO_TYP`` writes no ``typ`` member."""
    body = {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"given_name": "Ada"},
        "cnf": {"jwk": HOLDER.public_jwk()},
    }
    if with_iss:
        body["iss"] = DID
    if typ == "dc+sd-jwt":
        body["vct"] = VCT
    if aud is not ABSENT:
        body["aud"] = aud
    header = {"alg": "ES256", "kid": f"{DID}#0"}
    if typ is not NO_TYP:
        header["typ"] = typ
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    return f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}~"


@POLICY_KW
@VCDM_SHAPES
def test_a_vcdm_credential_restricted_to_others_is_rejected_without_an_audience(
        run, typ, with_iss, waiver):
    token = _vcdm_issued(OTHER, typ=typ, with_iss=with_iss)
    _refused(lambda: run(token, _policy(waiver)), match=NO_AUDIENCE)
    # ... and a restriction that names the verifier is no better off with nobody to be
    named = _vcdm_issued(ME, typ=typ, with_iss=with_iss)
    _refused(lambda: run(named, _policy(waiver)), match=NO_AUDIENCE)


@POLICY_KW
@VCDM_SHAPES
def test_a_vcdm_credential_restricted_to_others_is_rejected_for_the_policy_audience(
        run, typ, with_iss, waiver):
    token = _vcdm_issued(OTHER, typ=typ, with_iss=with_iss)
    _refused(lambda: run(token, _policy(waiver, audience=ME)), match=NOT_NAMED)
    token = _vcdm_issued([OTHER, "https://third.example"], typ=typ, with_iss=with_iss)
    _refused(lambda: run(token, _policy(waiver, audience=ME)), match=NOT_NAMED)


@POLICY_KW
@VCDM_SHAPES
def test_a_vcdm_credential_restricted_to_others_is_rejected_with_a_correct_kb_jwt(
        run, typ, with_iss, waiver):
    token = _present(_vcdm_issued(OTHER, typ=typ, with_iss=with_iss))
    _refused(lambda: run(token, _kb_policy(waiver)), match=NOT_NAMED)
    hosted = _policy(waiver, audience=ME, nonce=NONCE)
    _refused(lambda: run(token, hosted), match=NOT_NAMED)


@VCDM_SHAPES
def test_a_vcdm_credential_restricted_to_others_is_rejected_by_the_suite(typ, with_iss):
    token = _vcdm_issued(OTHER, typ=typ, with_iss=with_iss)
    _refused(lambda: SUITE.verify(token, public_key_jwk=KEY.public_jwk()), match=NO_AUDIENCE)
    _refused(lambda: SUITE.verify(token, public_key_jwk=KEY.public_jwk(), audience=ME),
             match=NOT_NAMED)


@POLICY_KW
@VCDM_SHAPES
def test_a_vcdm_credential_naming_the_audience_verifies(run, typ, with_iss, waiver):
    # Control: the same credential, `aud` naming the verifier, is a W3C credential that
    # verifies, so the rejections above are the audience and not some other refusal.
    for aud in (ME, [OTHER, ME]):
        token = _vcdm_issued(aud, typ=typ, with_iss=with_iss)
        result = run(token, _policy(waiver, audience=ME))
        assert result.raw.vcdm is True
        bound = run(_present(token), _kb_policy(waiver))
        assert bound.raw.vcdm is True and bound.key_bound is True


@POLICY_KW
@VCDM_SHAPES
def test_a_vcdm_credential_without_an_aud_is_unchanged(run, typ, with_iss, waiver):
    token = _vcdm_issued(typ=typ, with_iss=with_iss)
    assert run(token, _policy(waiver)).raw.vcdm is True
    assert run(token, _policy(waiver, audience=ME)).raw.vcdm is True
    assert run(_present(token), _kb_policy(waiver)).key_bound is True
