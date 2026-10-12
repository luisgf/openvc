"""
tests/test_sd_jwt_vcdm_validity.py — a W3C VCDM credential secured as SD-JWT is held
to its own validity window; an IETF SD-JWT VC's claims are not.

W3C VC-JOSE-COSE §3.2.1 secures a VCDM credential as the SD-JWT's claim set itself
(``typ: vc+sd-jwt``), and §3.1.3 says its ``exp`` dates the *signature*, unlike
``validFrom`` / ``validUntil``, which date the data. Through v1.28.1 the SD-JWT lane
read only ``exp`` / ``nbf``, so such a credential whose only expiry was a past
``validUntil`` verified under the default policy. The VC-JWT lane already enforced the
VCDM window; this pins the SD-JWT lane to the same rule, on both pipelines, bare and
inside an ``EnvelopedVerifiableCredential``.

The other direction matters as much: an IETF SD-JWT VC (``dc+sd-jwt``, or the legacy
``vc+sd-jwt`` typ with a ``vct``) that merely carries a claim *named* ``validUntil``
must keep verifying, and must not be flagged ``expired`` under the waiver.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; ``asyncio.run`` drives the
async pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import VerificationPolicy, verify_credential, verify_credential_async
from openvc.keys import P256SigningKey
from openvc.proof.errors import (
    ClaimsInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    MalformedTimestamp,
)
from openvc.proof.sd_jwt import (
    SdJwtVcProofSuite,
    _declares_vcdm,
    disclosure_digest,
    make_object_disclosure,
)

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
WAIVED = VerificationPolicy(require_not_expired=False)
AUD, NONCE = "https://verifier.example", "n-0S6_WzA2Mj"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()


def _mint(payload, *, typ="vc+sd-jwt", disclose=(), key=KEY, did=DID):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes the IETF
    ``dc+sd-jwt`` typ and requires a ``vct``, so it cannot mint a W3C one. *disclose*
    moves those top-level claims into disclosures (all of them presented)."""
    body = dict(payload)
    disclosures = []
    for name in disclose:
        disclosures.append(make_object_disclosure(_b64(secrets.token_bytes(16)), name,
                                                  body.pop(name)))
    if disclosures:
        body["_sd"] = sorted(disclosure_digest(d) for d in disclosures)
        body["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "typ": typ, "kid": f"{did}#0"}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    jws = f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _vcdm(**extra):
    doc = {
        "@context": [V2, "https://www.w3.org/ns/credentials/examples/v2"],
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "iss": DID,
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "alumniOf": "Example University"},
    }
    doc.update(extra)
    return doc


def _ietf(**extra):
    claims = {"iss": DID, "vct": "https://credentials.example/membership",
              "member_name": "Ada"}
    claims.update(extra)
    return claims


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


def _iso(delta_s):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_s)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(params=sorted(PIPELINES))
def run(request):
    return PIPELINES[request.param]


@pytest.fixture(params=sorted(FORMS))
def form(request):
    return FORMS[request.param]


# --------------------------------------------------------------------------- #
# W3C VCDM secured as SD-JWT — the window is enforced
# --------------------------------------------------------------------------- #

def test_vcdm_past_valid_until_is_rejected(run, form):
    # The reported case: no JWT exp at all, the expiry lives only in validUntil.
    with pytest.raises(CredentialExpired):
        run(form(_mint(_vcdm(validUntil=PAST))), None)


def test_vcdm_future_valid_until_verifies(run, form):
    result = run(form(_mint(_vcdm(validUntil=FUTURE))), None)
    assert result.credential["validUntil"] == FUTURE
    assert result.expired is False


def test_waiver_reports_the_vcdm_expiry_identically_on_both_pipelines(form):
    credential = form(_mint(_vcdm(validUntil=PAST)))
    sync, asyncr = _sync(credential, WAIVED), _async(credential, WAIVED)
    assert sync.expired is True
    assert sync == asyncr


def test_vcdm_future_valid_from_is_rejected_even_under_the_waiver(run, form):
    # require_not_expired waives expiry only, never not-yet-valid (as on VC-JWT).
    credential = form(_mint(_vcdm(validFrom=FUTURE)))
    for policy in (None, WAIVED):
        with pytest.raises(CredentialNotYetValid):
            run(credential, policy)


def test_vcdm_malformed_valid_until_fails_closed(run, form):
    # A bound the parser cannot read is not skipped: that would be an expiry bypass.
    credential = form(_mint(_vcdm(validUntil="the first of never")))
    for policy in (None, WAIVED):
        with pytest.raises(MalformedTimestamp):
            run(credential, policy)


def test_vcdm_1_1_expiration_date_is_rejected(run, form):
    doc = _vcdm(expirationDate=PAST)
    doc["@context"] = [V1]
    with pytest.raises(CredentialExpired):
        run(form(_mint(doc)), None)


def test_selectively_disclosed_valid_until_is_enforced(run, form):
    # The window is read on the processed payload, after the disclosures are applied.
    with pytest.raises(CredentialExpired):
        run(form(_mint(_vcdm(validUntil=PAST), disclose=["validUntil"])), None)


def test_withheld_context_does_not_switch_the_window_off():
    # An issuer that (against VC-JOSE-COSE §3.2.1's SHOULD NOT) makes @context disclosable:
    # the holder withholds it, but the vc+sd-jwt typ with no vct still says VCDM.
    sd_jwt = _mint(_vcdm(validUntil=PAST), disclose=["@context"])
    issuer_jwt, context_disclosure, _ = sd_jwt.split("~")
    withheld = issuer_jwt + "~"
    assert context_disclosure
    with pytest.raises(CredentialExpired):
        _sync(withheld, None)


def test_valid_until_inside_the_leeway_verifies(run):
    assert run(_mint(_vcdm(validUntil=_iso(-30))), None).expired is False   # leeway 60 s
    with pytest.raises(CredentialExpired):
        run(_mint(_vcdm(validUntil=_iso(-30))), VerificationPolicy(leeway_s=0))


@pytest.mark.parametrize("typ, context, extra", [
    pytest.param("vc+sd-jwt", V2, {}, id="context-as-a-string"),
    pytest.param("vc+sd-jwt", ["https://example.org/ctx", V2], {}, id="v2-not-first"),
    pytest.param("vc+sd-jwt", None, {}, id="w3c-typ-no-context-no-vct"),
    pytest.param("dc+sd-jwt", [V2], {}, id="ietf-typ-but-vcdm-context"),
    pytest.param("dc+sd-jwt", [V2], {"vct": "urn:x"}, id="vcdm-context-wins-over-vct"),
])
def test_every_vcdm_signal_enforces_the_window(run, typ, context, extra):
    doc = _vcdm(validUntil=PAST, **extra)
    if context is None:
        del doc["@context"]
    else:
        doc["@context"] = context
    with pytest.raises(CredentialExpired):
        run(_mint(doc, typ=typ), None)


def test_envelope_media_type_is_not_consulted_for_a_vcdm_payload(run):
    # An application/dc+sd-jwt envelope cannot talk a VCDM payload out of its window.
    credential = _envelope(_mint(_vcdm(validUntil=PAST)), media="application/dc+sd-jwt")
    with pytest.raises(CredentialExpired):
        run(credential, None)


def test_double_envelope_is_enforced(run):
    inner = _envelope(_mint(_vcdm(validUntil=PAST)))
    outer = _envelope(json.dumps(inner), media="application/vc+ld+json")
    with pytest.raises(CredentialExpired):
        run(outer, None)


def test_window_is_checked_after_key_binding(run):
    # With key binding required, the KB-JWT is verified first (#184): an expiry verdict
    # therefore still means the presentation was bound to this verifier.
    holder = P256SigningKey.generate(kid="holder")
    sd_jwt = _mint(_vcdm(validUntil=PAST, cnf={"jwk": holder.public_jwk()}))
    bound = SdJwtVcProofSuite().create_presentation(
        sd_jwt, holder_key=holder, audience=AUD, nonce=NONCE)
    policy = VerificationPolicy(audience=AUD, nonce=NONCE, require_key_binding=True)
    with pytest.raises(CredentialExpired):
        run(bound, policy)
    with pytest.raises(ClaimsInvalid, match="nonce"):
        run(bound, VerificationPolicy(audience=AUD, nonce="other",
                                      require_key_binding=True))
    lenient = VerificationPolicy(audience=AUD, nonce=NONCE, require_key_binding=True,
                                 require_not_expired=False)
    result = run(bound, lenient)
    assert result.key_bound is True and result.expired is True


def test_suite_enforces_it_directly():
    # SdJwtVcProofSuite.verify is public: the check lives there, not only in the pipeline.
    suite = SdJwtVcProofSuite()
    sd_jwt = _mint(_vcdm(validUntil=PAST))
    with pytest.raises(CredentialExpired):
        suite.verify(sd_jwt, public_key_jwk=KEY.public_jwk())
    waived = suite.verify(sd_jwt, public_key_jwk=KEY.public_jwk(), check_temporal=False)
    assert waived.claims["validUntil"] == PAST


# --------------------------------------------------------------------------- #
# IETF SD-JWT VC — a claim merely named validUntil is not a validity bound
# --------------------------------------------------------------------------- #

IETF_CASES = {
    "past-validUntil": _ietf(validUntil=PAST),
    "future-validFrom": _ietf(validFrom=FUTURE),
    "past-expirationDate": _ietf(expirationDate=PAST),
    "unparseable-validUntil": _ietf(validUntil="next tuesday"),
    "non-vcdm-context": _ietf(validUntil=PAST, **{"@context": ["https://example.org/ctx"]}),
}


@pytest.mark.parametrize("claims", IETF_CASES.values(), ids=IETF_CASES.keys())
@pytest.mark.parametrize("typ", ["dc+sd-jwt", "vc+sd-jwt"])
def test_ietf_sd_jwt_vc_claims_are_not_a_validity_window(run, form, claims, typ):
    # "vc+sd-jwt" here is the pre-draft-06 IETF typ: it comes with a vct.
    credential = form(_mint(claims, typ=typ))
    strict = run(credential, None)
    assert strict.expired is False
    waived = run(credential, WAIVED)
    assert waived.expired is False     # nothing was waived: strict accepted it
    assert waived == strict


def test_ietf_credential_from_the_suites_own_issuer_keeps_verifying(run, form):
    # The everyday IETF path: SdJwtVcProofSuite.issue, a past `validUntil` claim, disclosed.
    sk = ec.generate_private_key(ec.SECP256R1())
    did = "did:jwk:" + _b64(json.dumps(P256SigningKey(sk, kid="-").public_jwk()).encode())
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": did, "validUntil": PAST}, signing_key=P256SigningKey(sk, kid=f"{did}#0"),
        vct="https://credentials.example/membership", disclosable=["validUntil"])
    result = run(form(sd_jwt), None)
    assert result.credential["validUntil"] == PAST
    assert result.expired is False


def test_ietf_jwt_exp_still_enforced(run, form):
    # Not reading validUntil does not loosen the IETF lane: its exp is the gate.
    credential = form(_mint(_ietf(exp=1_600_000_000)))
    with pytest.raises(ClaimsInvalid, match="expired"):
        run(credential, None)
    assert run(credential, WAIVED).expired is True


def test_envelope_media_type_does_not_turn_ietf_claims_into_vcdm(run):
    credential = _envelope(_mint(_ietf(validUntil=PAST), typ="dc+sd-jwt"),
                           media="application/vc+sd-jwt")
    assert run(credential, None).expired is False


# --------------------------------------------------------------------------- #
# the gate itself
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("typ, claims, expected", [
    ("vc+sd-jwt", {"@context": [V2]}, True),
    ("dc+sd-jwt", {"@context": V2}, True),
    ("dc+sd-jwt", {"@context": [V1]}, True),
    ("vc+sd-jwt", {}, True),
    ("vc+sd-jwt", {"vct": None}, True),
    ("vc+sd-jwt", {"vct": "urn:x"}, False),
    ("dc+sd-jwt", {}, False),
    ("dc+sd-jwt", {"@context": ["https://www.w3.org/ns/credentials/v2/"]}, False),
    ("dc+sd-jwt", {"@context": {"@vocab": V2}}, False),
    ("dc+sd-jwt", {"@context": [[V2]]}, False),
    ("dc+sd-jwt", {"@context": [{"@vocab": "x"}, 7, None]}, False),
    ("dc+sd-jwt", {"@context": 7}, False),
    (None, {"@context": [V2]}, True),
    (["vc+sd-jwt"], {}, False),
])
def test_declares_vcdm(typ, claims, expected):
    assert _declares_vcdm(typ, claims) is expected
