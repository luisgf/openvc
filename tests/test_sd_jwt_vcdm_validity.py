"""
tests/test_sd_jwt_vcdm_validity.py — a W3C VCDM credential secured as SD-JWT is held
to its own validity window; an IETF SD-JWT VC's claims are not.

W3C VC-JOSE-COSE §3.2.1 secures a VCDM credential as the SD-JWT's claim set itself
(``typ: vc+sd-jwt``), and §3.1.3 (the JOSE encoding it builds on) says ``exp`` dates
the *signature*, unlike ``validFrom`` / ``validUntil``, which date the data. Through
v1.28.1 the SD-JWT lane
read only ``exp`` / ``nbf``, so such a credential whose only expiry was a past
``validUntil`` verified under the default policy. The VC-JWT lane already enforced the
VCDM window; this pins the SD-JWT lane to the same rule, on both pipelines, bare and
inside an ``EnvelopedVerifiableCredential``.

The other direction matters as much: an IETF SD-JWT VC (``dc+sd-jwt``) that merely
carries a claim *named* ``validUntil`` must keep verifying, and must not be flagged
``expired`` under the waiver.

What makes a payload VCDM is its ``@context`` and nothing else. ``vc+sd-jwt`` is the W3C
typ and is accepted only for such a payload (#264): the typ alone no longer reads as
VCDM, and the pre-draft-06 IETF use of it (a ``vct`` but no VCDM ``@context``) is refused
with ``SdJwtError``, as draft-ietf-oauth-sd-jwt-vc-19 dropped its transitional acceptance.

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
    SdJwtError,
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
    sk = ec.generate_private_key(ec.SECP256R1())
    did = "did:jwk:" + _b64(json.dumps(P256SigningKey(sk, kid="-").public_jwk()).encode())
    return P256SigningKey(sk, kid=f"{did}#0"), did


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


def test_selectively_disclosed_valid_until_is_refused(run, form):
    # #229: a disclosable validUntil is withholdable, so the window would fail open. A
    # presented one is refused as a disclosure (SdJwtError) — before it is read as expired.
    with pytest.raises(SdJwtError, match="'validUntil' is selectively disclosed"):
        run(form(_mint(_vcdm(validUntil=PAST), disclose=["validUntil"])), None)


def test_withheld_context_does_not_switch_the_window_off():
    # An issuer that (against VC-JOSE-COSE §3.2.1's SHOULD NOT) makes @context disclosable:
    # the holder withholds it. Without the @context nothing says VCDM, and the token is
    # refused, not read as a payload with no window: a vc+sd-jwt needs the @context (#264),
    # a dc+sd-jwt needs a vct, which a VCDM payload does not carry.
    for typ, error, message in [
        ("vc+sd-jwt", SdJwtError, "needs a W3C VCDM @context"),
        ("dc+sd-jwt", ClaimsInvalid, "needs a non-empty string vct"),
    ]:
        sd_jwt = _mint(_vcdm(validUntil=PAST), typ=typ, disclose=["@context"])
        issuer_jwt, context_disclosure, _ = sd_jwt.split("~")
        assert context_disclosure
        for pipeline in PIPELINES.values():
            with pytest.raises(error, match=message):
                pipeline(issuer_jwt + "~", None)


def test_valid_until_inside_the_leeway_verifies(run):
    assert run(_mint(_vcdm(validUntil=_iso(-30))), None).expired is False   # leeway 60 s
    with pytest.raises(CredentialExpired):
        run(_mint(_vcdm(validUntil=_iso(-30))), VerificationPolicy(leeway_s=0))


@pytest.mark.parametrize("typ, context, extra", [
    pytest.param("vc+sd-jwt", V2, {}, id="context-as-a-string"),
    pytest.param("vc+sd-jwt", ["https://example.org/ctx", V2], {}, id="v2-not-first"),
    pytest.param("vc+sd-jwt", [V2], {"vct": "urn:x"}, id="w3c-typ-context-and-vct"),
    pytest.param("dc+sd-jwt", [V2], {}, id="ietf-typ-but-vcdm-context"),
    pytest.param("dc+sd-jwt", [V2], {"vct": "urn:x"}, id="vcdm-context-wins-over-vct"),
])
def test_every_vcdm_signal_enforces_the_window(run, typ, context, extra):
    # The @context is the only signal (#264); the typ, either one, does not matter here.
    doc = _vcdm(validUntil=PAST, **extra)
    doc["@context"] = context
    with pytest.raises(CredentialExpired):
        run(_mint(doc, typ=typ), None)


@pytest.mark.parametrize("extra", [
    pytest.param({}, id="no-vct"),
    pytest.param({"vct": ""}, id="empty-vct"),
    pytest.param({"vct": "urn:x"}, id="vct"),
])
def test_w3c_typ_without_a_vcdm_context_is_refused(run, extra):
    # #264: `vc+sd-jwt` used to read as VCDM when the payload had no vct, which let a
    # token skip the REQUIRED vct of an IETF SD-JWT VC and the checks that go with it. It
    # is the W3C typ now and needs a VCDM @context, however the window would have read.
    doc = _vcdm(validUntil=PAST, **extra)
    del doc["@context"]
    for policy in (None, WAIVED):         # refused whole: the waiver waives only the expiry
        with pytest.raises(SdJwtError, match="needs a W3C VCDM @context"):
            run(_mint(doc, typ="vc+sd-jwt"), policy)


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
def test_ietf_sd_jwt_vc_claims_are_not_a_validity_window(run, form, claims):
    credential = form(_mint(claims, typ="dc+sd-jwt"))
    strict = run(credential, None)
    assert strict.expired is False
    waived = run(credential, WAIVED)
    assert waived.expired is False     # nothing was waived: strict accepted it
    assert waived == strict


@pytest.mark.parametrize("claims", IETF_CASES.values(), ids=IETF_CASES.keys())
def test_legacy_vc_sd_jwt_typ_on_an_ietf_payload_is_refused(run, form, claims):
    # "vc+sd-jwt" on a vct-bearing IETF payload is the pre-draft-06 typ. Draft-19 dropped
    # its transitional acceptance and the typ is the W3C one now (#264): refused, not
    # verified as a dc+sd-jwt. The cases above verify with the typ they should carry.
    credential = form(_mint(claims, typ="vc+sd-jwt"))
    for policy in (None, WAIVED):
        with pytest.raises(SdJwtError, match="needs a W3C VCDM @context"):
            run(credential, policy)


def test_w3c_typ_with_a_withheld_vct_is_refused(run, form):
    # vct is non-disclosable, so a presented disclosure of it is refused; a withheld one
    # leaves the payload without a vct, and `vc+sd-jwt` no longer vouches for that (#264).
    sd_jwt = _mint(_ietf(), typ="vc+sd-jwt", disclose=["vct"])
    issuer_jwt, vct_disclosure, _ = sd_jwt.split("~")
    assert vct_disclosure
    with pytest.raises(SdJwtError, match="needs a W3C VCDM @context"):
        run(form(issuer_jwt + "~"), None)


def test_ietf_credential_from_the_suites_own_issuer_keeps_verifying(run, form):
    # The everyday IETF path: SdJwtVcProofSuite.issue, a past `validUntil` claim, disclosed.
    key, did = _issuer()
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": did, "validUntil": PAST}, signing_key=key,
        vct="https://credentials.example/membership", disclosable=["validUntil"])
    result = run(form(sd_jwt), None)
    assert result.credential["validUntil"] == PAST
    assert result.expired is False


def test_ietf_jwt_exp_still_enforced(run, form):
    # Not reading validUntil does not loosen the IETF lane: its exp is the gate.
    credential = form(_mint(_ietf(exp=1_600_000_000), typ="dc+sd-jwt"))
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

@pytest.mark.parametrize("claims, expected", [
    ({"@context": [V2]}, True),
    ({"@context": V2}, True),
    ({"@context": [V1]}, True),
    ({"@context": ["https://example.org/ctx", V2]}, True),
    ({"@context": [V2], "vct": "urn:x"}, True),     # the context wins over a vct
    ({}, False),                                    # the typ no longer counts: no @context
    ({"vct": None}, False),
    ({"vct": ""}, False),
    ({"vct": "urn:x"}, False),
    ({"@context": ["https://www.w3.org/ns/credentials/v2/"]}, False),
    ({"@context": {"@vocab": V2}}, False),
    ({"@context": [[V2]]}, False),
    ({"@context": [{"@vocab": "x"}, 7, None]}, False),
    ({"@context": 7}, False),
])
def test_declares_vcdm(claims, expected):
    assert _declares_vcdm(claims) is expected


# --------------------------------------------------------------------------- #
# adversarial-review regressions
# --------------------------------------------------------------------------- #

def test_policy_now_does_not_move_the_jose_window(run):
    # The SD-JWT VCDM window is judged at the current time, like VC-JWT's and every JOSE
    # `exp`; `policy.now` pins Data Integrity and the KB-JWT window only. The waiver's flag
    # comes from that same check, so strict and waived agree even with `now` pinned.
    lapsed = _mint(_vcdm(validUntil="2025-06-01T00:00:00Z"))
    before = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(CredentialExpired):
        run(lapsed, VerificationPolicy(now=before))
    assert run(lapsed, VerificationPolicy(now=before, require_not_expired=False)).expired

    current = _mint(_vcdm(validUntil=FUTURE))
    after = datetime(2100, 1, 1, tzinfo=timezone.utc)
    assert run(current, VerificationPolicy(now=after)).expired is False
    waived = run(current, VerificationPolicy(now=after, require_not_expired=False))
    assert waived.expired is False


@pytest.mark.parametrize("leeway", [10**12, 10**14, 10**30])
def test_huge_leeway_is_honoured_not_a_crash(run, leeway):
    # `instant ± leeway` used to overflow datetime: a bare OverflowError, not an OpenvcError.
    result = run(_mint(_vcdm(validUntil=PAST)), VerificationPolicy(leeway_s=leeway))
    assert result.expired is False


def test_huge_leeway_does_not_abort_verify_many():
    from openvc import verify_many, verify_many_async
    batch = [_mint(_vcdm(validUntil=PAST)), _mint(_vcdm(validFrom=FUTURE))]
    policy = VerificationPolicy(leeway_s=10**14)
    for results in (verify_many(batch, policy=policy),
                    asyncio.run(verify_many_async(batch, policy=policy))):
        assert [r.ok for r in results] == [True, True]   # the leeway covers both bounds


def test_huge_leeway_on_the_vc_jwt_window(run):
    # The window helper is shared: the VC-JWT lane overflowed the same way.
    from openvc.proof.vc_jwt import VcJwtProofSuite
    token = VcJwtProofSuite().sign(_vcdm(validUntil=PAST), signing_key=KEY)
    with pytest.raises(CredentialExpired):
        run(token, None)
    assert run(token, VerificationPolicy(leeway_s=10**14)).expired is False
