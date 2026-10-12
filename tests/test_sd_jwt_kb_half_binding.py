"""
tests/test_sd_jwt_kb_half_binding.py — a KB-JWT checked against only aud or only nonce (#191).

RFC 9901 §7.3 step 5.6 binds a Key Binding JWT to "the current transaction" and to
"this Verifier" by validating ``nonce`` **and** ``aud``. Until #191 the top-level SD-JWT
verifiers — ``SdJwtVcProofSuite.verify``, ``verify_credential`` and
``verify_credential_async`` — checked each value only when the caller passed it, and
independently. A caller who passed ``audience`` alone accepted a KB-JWT from another of
its own sessions; one who passed ``nonce`` alone accepted a KB-JWT made for another
verifier. Both reported ``key_bound=True``, for a binding that never happened.

The semantics pinned here: a present KB-JWT verified with exactly one of the two values
fails closed (``ClaimsInvalid``) before any KB-JWT crypto runs; the same half-configured
call with **no** KB-JWT still verifies with ``key_bound=False`` (``audience`` alone is a
valid VC-JWT policy); both values, or neither, behave as before. The VP lanes always
pass both and are untouched.
"""
from __future__ import annotations

import asyncio
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import VerificationPolicy, verify_credential, verify_vp_token
from openvc.aio import verify_credential_async
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import FORMAT_SD_JWT_VC
from openvc.proof.errors import ClaimsInvalid, MalformedToken, SignatureInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

ME = "x509_san_dns:verifier.example"
MY_NONCE = "n-0S6_WzA2Mj"
OTHER_AUD = "x509_san_dns:other-verifier.example"
OTHER_NONCE = "nonce-from-another-session"
VCT = "https://credentials.example.com/identity_credential"
HALF = "only (audience|nonce) was given"

# (caller kwargs, KB-JWT (aud, nonce)) — every half-configured call, including the one
# where the single value given DOES match: checking it alone is still not a binding.
HALF_BOUND = [
    pytest.param({"audience": ME}, (ME, OTHER_NONCE), id="aud-only-replayed-session"),
    pytest.param({"audience": ME}, (ME, MY_NONCE), id="aud-only-both-match"),
    pytest.param({"nonce": MY_NONCE}, (OTHER_AUD, MY_NONCE), id="nonce-only-relayed-verifier"),
    pytest.param({"nonce": MY_NONCE}, (ME, MY_NONCE), id="nonce-only-both-match"),
    pytest.param({"audience": ""}, (ME, MY_NONCE), id="empty-aud-only"),
    pytest.param({"nonce": ""}, (ME, MY_NONCE), id="empty-nonce-only"),
]


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def parties():
    issuer_key, issuer_did = _did_key_p256()
    holder_key, holder_did = _did_key_p256()
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "given_name": "Ada", "sub": holder_did},
        signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
        holder_jwk=holder_key.public_jwk())
    return issuer_key, holder_key, issued


def _kb(parties, aud, nonce):
    _, holder_key, issued = parties
    return SdJwtVcProofSuite().create_presentation(
        issued, holder_key=holder_key, audience=aud, nonce=nonce)


def _suite(parties, presentation, **kw):
    return SdJwtVcProofSuite().verify(
        presentation, public_key_jwk=parties[0].public_jwk(), **kw)


def _policy(**kw):
    return VerificationPolicy(require_status=False, **kw)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
# the half-binding fails closed — on every top-level lane
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("given,kb", HALF_BOUND)
def test_suite_rejects_a_half_bound_kb_jwt(parties, given, kb):
    with pytest.raises(ClaimsInvalid, match=HALF):
        _suite(parties, _kb(parties, *kb), **given)


@pytest.mark.parametrize("given,kb", HALF_BOUND)
def test_verify_credential_rejects_a_half_bound_kb_jwt(parties, given, kb):
    with pytest.raises(ClaimsInvalid, match=HALF):
        verify_credential(_kb(parties, *kb), policy=_policy(**given))


@pytest.mark.parametrize("given,kb", HALF_BOUND)
def test_async_pipeline_rejects_a_half_bound_kb_jwt(parties, given, kb):
    with pytest.raises(ClaimsInvalid, match=HALF):
        asyncio.run(verify_credential_async(_kb(parties, *kb), policy=_policy(**given)))


def test_the_error_names_the_value_that_was_given(parties):
    presentation = _kb(parties, ME, MY_NONCE)
    with pytest.raises(ClaimsInvalid, match="only audience was given"):
        _suite(parties, presentation, audience=ME)
    with pytest.raises(ClaimsInvalid, match="only nonce was given"):
        _suite(parties, presentation, nonce=MY_NONCE)


# --------------------------------------------------------------------------- #
# it is a configuration check: it runs before any KB-JWT parsing or crypto
# --------------------------------------------------------------------------- #

def _tampered_signature(presentation):
    head, sig = presentation.rsplit(".", 1)
    return head + "." + ("A" if sig[0] != "A" else "B") + sig[1:]


def _kb_with_header(parties, header):
    _, _, issued = parties
    presented = issued if issued.endswith("~") else issued + "~"
    signing_input = (_b64(json.dumps(header).encode()) + "."
                     + _b64(json.dumps({"aud": ME, "nonce": MY_NONCE}).encode()))
    return presented + signing_input + "." + _b64(b"\x00" * 64)


def test_the_check_runs_before_the_kb_jwt_signature(parties):
    forged = _tampered_signature(_kb(parties, ME, MY_NONCE))
    with pytest.raises(SignatureInvalid):                  # control: both values given
        _suite(parties, forged, audience=ME, nonce=MY_NONCE)
    with pytest.raises(ClaimsInvalid, match=HALF):
        _suite(parties, forged, audience=ME)


def test_the_check_runs_before_the_kb_jwt_is_parsed(parties):
    _, _, issued = parties
    garbage = (issued if issued.endswith("~") else issued + "~") + "not-a-jws"
    with pytest.raises(MalformedToken):                    # control: both values given
        _suite(parties, garbage, audience=ME, nonce=MY_NONCE)
    with pytest.raises(ClaimsInvalid, match=HALF):
        _suite(parties, garbage, nonce=MY_NONCE)


def test_the_check_runs_before_the_kb_jwt_alg_allow_list(parties):
    unsigned = _kb_with_header(parties, {"typ": "kb+jwt", "alg": "none"})
    with pytest.raises(ClaimsInvalid, match=HALF):
        _suite(parties, unsigned, audience=ME)


# --------------------------------------------------------------------------- #
# what does NOT change
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("given", [{"audience": ME}, {"nonce": MY_NONCE}], ids=["aud", "nonce"])
def test_half_configured_call_without_a_kb_jwt_still_verifies_unbound(parties, given):
    # `audience` alone is a valid VC-JWT policy; an SD-JWT with no KB-JWT under it
    # reports key_bound=False — honest, so nothing to reject.
    issued = parties[2]
    assert _suite(parties, issued, **given).key_bound is False
    assert verify_credential(issued, policy=_policy(**given)).key_bound is False
    result = asyncio.run(verify_credential_async(issued, policy=_policy(**given)))
    assert result.key_bound is False


def test_both_values_bind_as_before(parties):
    presentation = _kb(parties, ME, MY_NONCE)
    assert _suite(parties, presentation, audience=ME, nonce=MY_NONCE).key_bound is True
    assert verify_credential(
        presentation, policy=_policy(audience=ME, nonce=MY_NONCE)).key_bound is True
    with pytest.raises(ClaimsInvalid, match="KB-JWT nonce does not match"):
        _suite(parties, _kb(parties, ME, OTHER_NONCE), audience=ME, nonce=MY_NONCE)
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _suite(parties, _kb(parties, OTHER_AUD, MY_NONCE), audience=ME, nonce=MY_NONCE)


def test_neither_value_keeps_the_documented_possession_only_meaning(parties):
    # Documented (wiki SD-JWT-VC, "What key_bound attests"): with neither value the flag
    # proves possession of the cnf key for SOME verifier, not a binding to the caller.
    # Changing that would change a value callers gate on — out of scope for #191.
    presentation = _kb(parties, OTHER_AUD, OTHER_NONCE)
    assert _suite(parties, presentation).key_bound is True
    assert verify_credential(presentation, policy=_policy()).key_bound is True


@pytest.mark.parametrize("given", [{"audience": ME}, {"nonce": MY_NONCE}], ids=["aud", "nonce"])
def test_require_key_binding_still_refuses_a_half_configured_call(parties, given):
    with pytest.raises(ClaimsInvalid, match="no audience/nonce given"):
        _suite(parties, _kb(parties, ME, MY_NONCE), require_key_binding=True, **given)


def test_verify_vp_token_lane_passes_both_and_is_unaffected(parties):
    dcql = {"credentials": [{"id": "pid", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": [VCT]}}]}
    result = verify_vp_token({"pid": [_kb(parties, ME, MY_NONCE)]}, dcql_query=dcql,
                             nonce=MY_NONCE, client_id=ME)
    (presentation,) = result.for_query("pid")
    assert presentation.raw.key_bound is True


def _strip_kb(presentation):
    return presentation[:presentation.rindex("~") + 1]


@pytest.mark.parametrize("given", [{"audience": ME}, {"nonce": MY_NONCE}], ids=["aud", "nonce"])
def test_rejecting_a_half_binding_does_not_make_the_kb_jwt_required(parties, given):
    # The raise stops a misleading key_bound=True; it is not replay protection on its
    # own. Stripping the KB-JWT turns the same relay into an honest key_bound=False,
    # which only require_key_binding (or reading key_bound) refuses.
    stripped = _strip_kb(_kb(parties, OTHER_AUD, OTHER_NONCE))
    assert _suite(parties, stripped, **given).key_bound is False
    with pytest.raises(ClaimsInvalid, match="no KB-JWT present"):
        _suite(parties, stripped, audience=ME, nonce=MY_NONCE, require_key_binding=True)


# --------------------------------------------------------------------------- #
# Fixed before merge — from this change's adversarial review
# --------------------------------------------------------------------------- #

# Both values given, but one of them binds nothing. `nonce=""` (a lost session's
# `session.get("nonce", "")`) accepted any KB-JWT the holder signed with an empty
# nonce for that audience — an audience-only binding in disguise, even when required.
EMPTY_OR_NOT_A_STRING = [
    pytest.param(ME, "", (ME, ""), id="empty-nonce"),
    pytest.param("", MY_NONCE, ("", MY_NONCE), id="empty-aud"),
    pytest.param("", "", ("", ""), id="both-empty"),
    pytest.param([ME], MY_NONCE, ([ME], MY_NONCE), id="list-aud"),
    pytest.param(ME, 1, (ME, True), id="int-nonce-vs-true"),
]
EMPTY = "must be non-empty strings"


@pytest.mark.parametrize("aud,nonce,kb", EMPTY_OR_NOT_A_STRING)
@pytest.mark.parametrize("required", [False, True], ids=["optional", "required"])
def test_an_empty_or_non_string_binding_value_is_refused(parties, aud, nonce, kb, required):
    with pytest.raises(ClaimsInvalid, match=EMPTY):
        _suite(parties, _kb(parties, *kb), audience=aud, nonce=nonce,
               require_key_binding=required)


@pytest.mark.parametrize("aud,nonce,kb", EMPTY_OR_NOT_A_STRING[:3])
def test_an_empty_binding_value_is_refused_on_every_lane(parties, aud, nonce, kb):
    presentation, policy = _kb(parties, *kb), _policy(audience=aud, nonce=nonce)
    with pytest.raises(ClaimsInvalid, match=EMPTY):
        verify_credential(presentation, policy=policy)
    with pytest.raises(ClaimsInvalid, match=EMPTY):
        asyncio.run(verify_credential_async(presentation, policy=policy))


def test_an_empty_binding_value_without_a_kb_jwt_still_verifies_unbound(parties):
    assert _suite(parties, parties[2], audience=ME, nonce="").key_bound is False


def test_nested_binding_replaces_a_half_configured_cascade_policy(parties):
    # The VP cascade binds a nested KB-JWT to the presentation's own (aud, nonce), both
    # of them, overriding the policy's. A cascade policy carrying `audience` alone — to
    # pin a nested VC-JWT's aud — therefore never trips the half-binding check.
    _, holder_key, _ = parties                 # a did:key VM: resolver mode, offline
    vp = VpJwtProofSuite().sign([_kb(parties, ME, MY_NONCE)], holder_key=holder_key,
                                audience=ME, nonce=MY_NONCE)
    verified = VpJwtProofSuite().verify(
        vp, audience=ME, nonce=MY_NONCE, policy=_policy(audience=OTHER_AUD))
    (cred,) = verified.credentials
    assert cred.key_bound is True
