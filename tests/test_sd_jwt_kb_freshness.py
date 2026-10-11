"""
tests/test_sd_jwt_kb_freshness.py — the SD-JWT Key Binding JWT ``iat`` window (#186).

RFC 9901 §4.3 makes the KB-JWT ``iat`` REQUIRED, and §7.3 step 5.5 has the verifier
"check that the creation time of the Key Binding JWT, as determined by the ``iat``
claim, is within an acceptable window" (under the section's MUST). Until #186 openvc
never read that claim: a KB-JWT of any age — or with no ``iat`` at all — verified.
Every self-made test minted a fresh KB-JWT and checked it at once, so no round-trip
could notice; a third-party capture offered on #121 did, with its "an hour later"
control.

These tests craft KB-JWTs by hand so ``iat`` can be anything — missing, a string,
``NaN``, a 400-digit integer, stale, future-dated — and pin the window's edges, the
``now`` pin a verifier uses to re-check an archived presentation, and that the window
reaches every lane: the suite, the ``verify_credential`` policy, the async pipeline and
OpenID4VP ``verify_vp_token``.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import VerificationPolicy, verify_credential, verify_vp_token
from openvc.aio import verify_credential_async
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import FORMAT_SD_JWT_VC
from openvc.proof._verify_common import check_jwt_temporal
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import DEFAULT_KB_MAX_AGE_S, SdJwtError, SdJwtVcProofSuite

T = 1_791_661_760                      # a fixed "verifier now" (2026-10-10T19:49:20Z)
NOW = dt.datetime.fromtimestamp(T, dt.timezone.utc)
LEEWAY = 60                            # the suite default
AUD = "x509_hash:verifier.example"
NONCE = "n-0S6_WzA2Mj"
VCT = "https://credentials.example.com/identity_credential"
_MC_P256 = bytes([0x80, 0x24])         # multicodec p256-pub (0x1200) varint


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(_MC_P256 + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def parties():
    issuer_key, issuer_did = _did_key_p256()
    holder_key = P256SigningKey.generate(kid="holder")
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "given_name": "Ada", "sub": "did:example:alice"},
        signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
        holder_jwk=holder_key.public_jwk())
    return issuer_key, holder_key, issued


_UNSET = object()


def _present(parties, *, iat=_UNSET):
    """The issued SD-JWT plus a hand-made KB-JWT carrying exactly this ``iat``
    (``_UNSET`` leaves the claim out). Signed by the real holder key with a correct
    ``sd_hash``, so the only thing under test is the creation time."""
    _, holder_key, issued = parties
    presented = issued if issued.endswith("~") else issued + "~"
    payload = {"aud": AUD, "nonce": NONCE,
               "sd_hash": _b64(hashlib.sha256(presented.encode("ascii")).digest())}
    if iat is not _UNSET:
        payload["iat"] = iat
    signing_input = (_b64(json.dumps({"typ": "kb+jwt", "alg": "ES256"}).encode())
                     + "." + _b64(json.dumps(payload).encode()))   # NaN allowed on purpose
    signature = holder_key.sign(signing_input.encode("ascii"))
    return presented + signing_input + "." + _b64(signature)


def _verify(parties, presentation, *, now=NOW, required=True, **kw):
    issuer_key, _, _ = parties
    return SdJwtVcProofSuite().verify(
        presentation, public_key_jwk=issuer_key.public_jwk(), audience=AUD, nonce=NONCE,
        require_key_binding=required, now=now, **kw)


# --------------------------------------------------------------------------- #
# the claim itself — required, numeric, finite (fail-closed, always typed)
# --------------------------------------------------------------------------- #

def test_fresh_kb_jwt_verifies(parties):
    result = _verify(parties, _present(parties, iat=T))
    assert result.key_bound is True
    assert result.claims["given_name"] == "Ada"


def test_missing_iat_is_refused(parties):
    with pytest.raises(ClaimsInvalid, match="KB-JWT is missing the required iat"):
        _verify(parties, _present(parties))


@pytest.mark.parametrize("iat", [str(T), True, False, [T], {"t": T}, None])
def test_non_numeric_iat_is_refused(parties, iat):
    # None is an explicit JSON null: as good as absent.
    match = "missing the required iat" if iat is None else "finite numeric timestamp"
    with pytest.raises(ClaimsInvalid, match=match):
        _verify(parties, _present(parties, iat=iat))


@pytest.mark.parametrize("iat", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_iat_is_refused(parties, iat):
    # json.loads accepts NaN/Infinity, and every comparison against NaN is False —
    # without this guard a NaN iat would be *never stale*.
    with pytest.raises(ClaimsInvalid, match="finite numeric timestamp"):
        _verify(parties, _present(parties, iat=iat))


@pytest.mark.parametrize("iat", [10 ** 400, -(10 ** 400)])
def test_bignum_iat_fails_closed_and_typed(parties, iat):
    # math.isfinite casts to float: a 400-digit int used to raise a bare OverflowError,
    # which escapes OpenvcError and aborts verify_many.
    with pytest.raises(ClaimsInvalid, match="finite numeric timestamp"):
        _verify(parties, _present(parties, iat=iat))


# --------------------------------------------------------------------------- #
# the window — both directions, exact edges
# --------------------------------------------------------------------------- #

def test_default_window_is_five_minutes():
    assert DEFAULT_KB_MAX_AGE_S == 300


def test_oldest_accepted_edge(parties):
    _verify(parties, _present(parties, iat=T - DEFAULT_KB_MAX_AGE_S - LEEWAY))


def test_one_second_past_the_window_is_stale(parties):
    with pytest.raises(ClaimsInvalid, match="KB-JWT is too old"):
        _verify(parties, _present(parties, iat=T - DEFAULT_KB_MAX_AGE_S - LEEWAY - 1))


def test_an_hour_old_kb_jwt_is_stale(parties):
    # The control that found #186: the same presentation, verified an hour later.
    presentation = _present(parties, iat=T)
    with pytest.raises(ClaimsInvalid, match="too old"):
        _verify(parties, presentation, now=NOW + dt.timedelta(hours=1))


def test_future_edge_within_leeway_is_accepted(parties):
    _verify(parties, _present(parties, iat=T + LEEWAY))


def test_future_dated_kb_jwt_is_refused(parties):
    # The direction implementations forget: iat = now + 10y never goes stale.
    with pytest.raises(ClaimsInvalid, match="KB-JWT iat is in the future"):
        _verify(parties, _present(parties, iat=T + LEEWAY + 1))
    with pytest.raises(ClaimsInvalid, match="in the future"):
        _verify(parties, _present(parties, iat=T + 10 * 365 * 86400))


def test_kb_max_age_is_configurable(parties):
    old = _present(parties, iat=T - 3600)
    with pytest.raises(ClaimsInvalid, match="too old"):
        _verify(parties, old)
    assert _verify(parties, old, kb_max_age_s=3600).key_bound is True
    with pytest.raises(ClaimsInvalid, match="too old"):            # zero still has leeway
        _verify(parties, _present(parties, iat=T - LEEWAY - 1), kb_max_age_s=0)


@pytest.mark.parametrize("bad", [-1, True, "300", 1.5, None])
def test_kb_max_age_must_be_a_non_negative_int(parties, bad):
    with pytest.raises(SdJwtError, match="kb_max_age_s"):
        _verify(parties, _present(parties, iat=T), kb_max_age_s=bad)


def test_pinned_now_reverifies_an_archived_presentation(parties):
    # Archived on 2026-01-01: unpinned (wall clock) it is stale; pinned to its own
    # instant it verifies — re-verification pins `now`, it never switches the check off.
    archived_at = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    presentation = _present(parties, iat=int(archived_at.timestamp()))
    with pytest.raises(ClaimsInvalid, match="too old"):
        _verify(parties, presentation, now=None)
    assert _verify(parties, presentation, now=archived_at).key_bound is True


def test_a_present_kb_jwt_is_held_to_the_window_even_when_not_required(parties):
    # Hosted path: binding not required, but a KB-JWT that is there is fully validated —
    # a stale one must not come back as key_bound=True.
    with pytest.raises(ClaimsInvalid, match="too old"):
        _verify(parties, _present(parties, iat=T - 3600), required=False)


def test_the_window_runs_before_the_nonce_check(parties):
    # RFC 9901 §7.3 orders step 5.5 (iat) before 5.6 (nonce/aud).
    issuer_key, _, _ = parties
    with pytest.raises(ClaimsInvalid, match="too old"):
        SdJwtVcProofSuite().verify(
            _present(parties, iat=T - 3600), public_key_jwk=issuer_key.public_jwk(),
            audience=AUD, nonce="some-other-nonce", require_key_binding=True, now=NOW)


# --------------------------------------------------------------------------- #
# every lane reaches the window
# --------------------------------------------------------------------------- #

def _policy(**kw):
    return VerificationPolicy(audience=AUD, nonce=NONCE, require_key_binding=True,
                              require_status=False, **kw)


def test_verify_credential_honours_policy_now_and_kb_max_age(parties):
    presentation = _present(parties, iat=T - 3600)
    with pytest.raises(ClaimsInvalid, match="too old"):
        verify_credential(presentation, policy=_policy(now=NOW))
    assert verify_credential(presentation, policy=_policy(now=NOW, kb_max_age_s=3600)).key_bound
    assert verify_credential(
        presentation, policy=_policy(now=NOW - dt.timedelta(hours=1))).key_bound


def test_async_pipeline_reaches_the_window(parties):
    presentation = _present(parties, iat=T - 3600)
    with pytest.raises(ClaimsInvalid, match="too old"):
        asyncio.run(verify_credential_async(presentation, policy=_policy(now=NOW)))
    result = asyncio.run(verify_credential_async(
        presentation, policy=_policy(now=NOW, kb_max_age_s=3600)))
    assert result.key_bound is True


def test_verify_vp_token_reaches_the_window(parties):
    dcql = {"credentials": [{"id": "pid", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": [VCT]}}]}
    vp = {"pid": [_present(parties, iat=T - 3600)]}
    with pytest.raises(ClaimsInvalid, match="too old"):
        verify_vp_token(vp, dcql_query=dcql, nonce=NONCE, client_id=AUD, now=NOW)
    result = verify_vp_token(vp, dcql_query=dcql, nonce=NONCE, client_id=AUD, now=NOW,
                             kb_max_age_s=3600)
    (p,) = result.for_query("pid")
    assert p.raw.key_bound is True


# --------------------------------------------------------------------------- #
# the shared NumericDate rule: a bignum exp/nbf fails closed and typed everywhere
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("claim", ["exp", "nbf"])
def test_bignum_exp_nbf_fail_closed_and_typed(claim):
    with pytest.raises(ClaimsInvalid, match=f"{claim} must be a finite numeric timestamp"):
        check_jwt_temporal({claim: 10 ** 400}, leeway_s=LEEWAY, now=T)


def test_bignum_timestamps_in_openid4vci_fail_closed_and_typed():
    # Same shared rule on the issuer side: the key proof `iat` (now single-sourced with
    # the KB-JWT window) and a key attestation's `iat`/`exp`.
    from openvc.openid4vci import _attestation_timestamp, _check_freshness

    with pytest.raises(ClaimsInvalid, match="key proof iat must be a finite"):
        _check_freshness(10 ** 400, max_age_s=300, leeway_s=LEEWAY, current=T)
    with pytest.raises(ClaimsInvalid, match="key attestation exp must be a finite"):
        _attestation_timestamp(10 ** 400, "exp")


def test_expiry_waiver_does_not_waive_kb_freshness(parties):
    # require_not_expired=False waives the *credential's* expired disposition; it is not
    # a holder-binding knob. A stale KB-JWT is a binding failure, never an "expired"
    # verdict — so the waiver must leave it refused.
    presentation = _present(parties, iat=T - 3600)
    with pytest.raises(ClaimsInvalid, match="too old") as excinfo:
        verify_credential(presentation, policy=_policy(now=NOW, require_not_expired=False))
    assert "expired" not in str(excinfo.value).lower()
