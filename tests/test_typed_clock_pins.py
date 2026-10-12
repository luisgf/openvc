"""
tests/test_typed_clock_pins.py — a misconfigured clock pin fails typed, never bare.

``check_validity_window`` (the Data Integrity lanes, and the VC-JWT body window) read
``now`` with ``now.tzinfo`` and added the leeway with plain datetime arithmetic. An
epoch ``int`` or an ISO string raised a bare ``AttributeError``; a pin within the
leeway of ``datetime.max`` / ``datetime.min`` raised a bare ``OverflowError``. Both
escape ``OpenvcError``, so ``verify_many`` / ``verify_many_async`` aborted the whole
batch instead of failing the one item — while the SD-JWT lane already typed the same
mistake through ``utc_epoch(now, error=...)``.

``utc_instant`` / ``utc_window`` are the datetime-returning siblings of ``utc_epoch``:
one reading (``None`` is the current time, naive is UTC), one typed failure. The x5c,
mdoc and WRPAC/WRPRC lanes now read their pins through them as well; their own tests
pin those lanes' error classes.
"""
from __future__ import annotations

import asyncio
import base64
from datetime import date, datetime, timedelta, timezone, tzinfo

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import VerificationPolicy, verify_credential, verify_many
from openvc.aio import verify_many_async
from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof._verify_common import (
    CredentialExpired,
    CredentialNotYetValid,
    check_validity_window,
    utc_epoch,
    utc_instant,
    utc_window,
)
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ProofError
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite

UTC = timezone.utc
VC2 = "https://www.w3.org/ns/credentials/v2"
NOW_2021 = datetime(2021, 1, 1, tzinfo=UTC)
MINUS_5 = timezone(timedelta(hours=-5))
_WINDOW = {"validFrom": "2020-01-01T00:00:00Z", "validUntil": "2022-01-01T00:00:00Z"}

# Pins that are not an instant at all, or that leave datetime's range once read as UTC
# or widened by the leeway. Every one used to escape as AttributeError/OverflowError.
_BAD_NOWS = [
    pytest.param(1_609_459_200, id="epoch-int"),
    pytest.param(1_609_459_200.0, id="epoch-float"),
    pytest.param("2021-01-01T00:00:00Z", id="iso-string"),
    pytest.param(date(2021, 1, 1), id="date-not-datetime"),
    pytest.param(datetime.max, id="naive-max"),
    pytest.param(datetime.min, id="naive-min"),
    pytest.param(datetime.max.replace(tzinfo=MINUS_5), id="max-at-minus-5h"),
    pytest.param(datetime.min.replace(tzinfo=UTC) + timedelta(seconds=30), id="min-plus-30s"),
]


class _RaisingTz(tzinfo):
    """A caller's tzinfo that cannot answer — its error must not escape untyped."""

    def utcoffset(self, dt):
        raise RuntimeError("no offset for you")

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "BROKEN"


class _NoneTz(tzinfo):
    """A tzinfo answering None is *naive* by Python's definition: read as UTC."""

    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return None


class _ConfigError(OpenvcError):
    """Stands in for a lane's own error class (X5cError, MdocError, ...)."""


# --------------------------------------------------------------------------- #
# utc_instant — the shared reading
# --------------------------------------------------------------------------- #

def test_utc_instant_none_is_the_current_aware_utc_time():
    before = datetime.now(UTC)
    instant = utc_instant(None)
    assert instant.tzinfo is UTC and before <= instant <= datetime.now(UTC)


def test_utc_instant_reads_a_naive_pin_as_utc_not_host_local():
    assert utc_instant(datetime(2021, 1, 1)) == NOW_2021
    assert utc_instant(datetime(2021, 1, 1)).tzinfo is UTC


def test_utc_instant_normalises_an_offset_pin_to_utc():
    instant = utc_instant(datetime(2020, 12, 31, 19, tzinfo=MINUS_5))
    assert instant == NOW_2021 and instant.tzinfo is UTC


def test_utc_instant_reads_a_tzinfo_answering_none_as_utc():
    # the old `now.tzinfo is None` test sent this to astimezone(), i.e. host-local time
    assert utc_instant(datetime(2021, 1, 1, tzinfo=_NoneTz())) == NOW_2021


def test_utc_instant_agrees_with_utc_epoch():
    for pin in (NOW_2021, datetime(2021, 1, 1), datetime(2020, 12, 31, 19, tzinfo=MINUS_5)):
        assert int(utc_instant(pin).timestamp()) == utc_epoch(pin)


# the window-edge pins are fine instants; only utc_window (below) rejects those
_UNREADABLE_NOWS = [p for p in _BAD_NOWS
                    if p.id not in ("naive-max", "naive-min", "min-plus-30s")]


@pytest.mark.parametrize("now", _UNREADABLE_NOWS)
def test_utc_instant_rejects_a_bad_pin_typed(now):
    with pytest.raises(ProofError, match="now"):
        utc_instant(now)


class _SubDatetime(datetime):
    """A caller's datetime subclass (pendulum, pandas and friends)."""


class _NaiveAstimezone(datetime):
    """A subclass whose astimezone() hands back a naive datetime."""

    def astimezone(self, tz=None):
        return datetime(self.year, self.month, self.day, self.hour)


def test_utc_instant_returns_a_plain_utc_datetime_for_a_subclass():
    instant = utc_instant(_SubDatetime(2020, 12, 31, 19, tzinfo=MINUS_5))
    assert type(instant) is datetime and instant.tzinfo is UTC and instant == NOW_2021


def test_utc_instant_rejects_a_subclass_whose_utc_conversion_lies():
    # left naive, it would surface later as a bare "can't compare offset-naive and
    # offset-aware datetimes" TypeError inside the window comparison
    with pytest.raises(ProofError, match="cannot be read"):
        utc_instant(_NaiveAstimezone(2021, 1, 1, tzinfo=MINUS_5))
    with pytest.raises(ProofError):
        check_validity_window(_WINDOW, {}, now=_NaiveAstimezone(2021, 1, 1, tzinfo=MINUS_5),
                              leeway_s=60)


def test_utc_instant_raises_the_callers_error_class():
    with pytest.raises(_ConfigError, match="not int"):
        utc_instant(0, error=_ConfigError)
    with pytest.raises(_ConfigError, match="cannot be read"):
        utc_instant(datetime(2021, 1, 1, tzinfo=_RaisingTz()), error=_ConfigError)


# --------------------------------------------------------------------------- #
# utc_window — the leeway arithmetic, bounds-checked once
# --------------------------------------------------------------------------- #

def test_utc_window_returns_the_instant_and_the_leeway():
    assert utc_window(NOW_2021, 60) == (NOW_2021, timedelta(seconds=60))


def test_utc_window_counts_a_negative_leeway_as_zero():
    assert utc_window(NOW_2021, -60) == (NOW_2021, timedelta(0))


@pytest.mark.parametrize("now", [
    pytest.param(datetime.max.replace(tzinfo=UTC), id="max"),
    pytest.param(datetime.max.replace(tzinfo=UTC) - timedelta(seconds=59), id="max-59s"),
    pytest.param(datetime.min.replace(tzinfo=UTC), id="min"),
    pytest.param(datetime.min.replace(tzinfo=UTC) + timedelta(seconds=59), id="min+59s"),
])
def test_utc_window_rejects_an_edge_beyond_datetimes_range(now):
    with pytest.raises(ProofError, match="does not fit"):
        utc_window(now, 60)


def test_utc_window_accepts_a_pin_exactly_one_leeway_inside_the_range():
    top = datetime.max.replace(tzinfo=UTC) - timedelta(seconds=60)
    bottom = datetime.min.replace(tzinfo=UTC) + timedelta(seconds=60)
    assert utc_window(top, 60)[0] == top
    assert utc_window(bottom, 60)[0] == bottom


@pytest.mark.parametrize("leeway", [
    pytest.param("60", id="string"),
    pytest.param(None, id="none"),
    pytest.param(float("inf"), id="inf"),
    pytest.param(10**12, id="beyond-year-9999"),
    pytest.param(10**30, id="beyond-timedelta"),
])
def test_utc_window_rejects_a_leeway_that_cannot_widen_the_window(leeway):
    with pytest.raises(_ConfigError, match="leeway_s"):
        utc_window(NOW_2021, leeway, error=_ConfigError)


# --------------------------------------------------------------------------- #
# check_validity_window — the Data Integrity temporal check
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("now", _BAD_NOWS)
def test_check_validity_window_types_a_bad_now(now):
    with pytest.raises(ProofError) as info:
        check_validity_window(_WINDOW, {}, now=now, leeway_s=60)
    # a configuration error, not a verdict about the credential
    assert not isinstance(info.value, (CredentialExpired, CredentialNotYetValid))


@pytest.mark.parametrize("now", _BAD_NOWS)
def test_check_validity_window_types_a_bad_now_even_with_expiry_waived(now):
    with pytest.raises(ProofError):
        check_validity_window(_WINDOW, {}, now=now, leeway_s=60, check_temporal=False)


@pytest.mark.parametrize("leeway", ["60", None, float("inf"), 10**12])
def test_check_validity_window_types_a_bad_leeway(leeway):
    with pytest.raises(ProofError, match="leeway_s"):
        check_validity_window(_WINDOW, {}, now=NOW_2021, leeway_s=leeway)


def test_check_validity_window_still_judges_a_good_pin():
    check_validity_window(_WINDOW, {}, now=NOW_2021, leeway_s=60)
    check_validity_window(_WINDOW, {}, now=datetime(2021, 1, 1), leeway_s=60)   # naive = UTC
    with pytest.raises(CredentialExpired):
        check_validity_window(_WINDOW, {}, now=datetime(2023, 1, 1, tzinfo=UTC), leeway_s=60)
    with pytest.raises(CredentialNotYetValid):
        check_validity_window(_WINDOW, {}, now=datetime(2019, 1, 1, tzinfo=UTC), leeway_s=60)


def test_check_validity_window_compares_far_dated_bounds_without_overflow():
    # the leeway widens the verifier's instant, never the credential's own dates
    far = {"validFrom": "0001-01-01T00:00:00Z", "validUntil": "9999-12-31T23:59:59Z"}
    check_validity_window(far, {"expires": "9999-12-31T23:59:59Z"}, now=NOW_2021, leeway_s=60)


# --------------------------------------------------------------------------- #
# verify_many / verify_many_async — one bad pin fails each item, never the batch
# --------------------------------------------------------------------------- #

def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key_signer() -> tuple[Ed25519SigningKey, str]:
    """A fresh Ed25519 key whose kid is its own offline-resolvable did:key method."""
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = base64.urlsafe_b64decode(Ed25519SigningKey(priv, kid="tmp").public_jwk()["x"] + "==")
    did = "did:key:" + encode_multibase(_leb128(0xED) + raw)
    return Ed25519SigningKey(priv, kid=f"{did}#{did[len('did:key:'):]}"), did


def _di_credential() -> dict:
    """An eddsa-jcs-2022 credential signed by a fresh did:key (no network, no pyld)."""
    key, did = _did_key_signer()
    credential = {
        "@context": [VC2],
        "type": ["VerifiableCredential"],
        "issuer": did,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice"},
    }
    return EddsaJcsProofSuite().add_proof(
        credential, signing_key=key, verification_method=key.kid)


@pytest.mark.parametrize("now", _BAD_NOWS)
def test_verify_many_fails_each_item_on_a_bad_now(now):
    batch = [_di_credential(), _di_credential()]
    out = verify_many(batch, policy=VerificationPolicy(require_status=False, now=now))
    assert [r.index for r in out] == [0, 1]
    assert all(not r.ok and isinstance(r.error, ProofError) for r in out)


def test_verify_many_fails_each_item_on_a_bad_leeway():
    out = verify_many([_di_credential()],
                      policy=VerificationPolicy(require_status=False, now=NOW_2021,
                                                leeway_s=10**12))
    assert isinstance(out[0].error, ProofError) and "leeway_s" in str(out[0].error)


@pytest.mark.parametrize("now", [1_609_459_200, datetime.max])
def test_verify_many_with_expiry_waived_still_fails_typed(now):
    out = verify_many([_di_credential()],
                      policy=VerificationPolicy(require_status=False, now=now,
                                                require_not_expired=False))
    assert isinstance(out[0].error, ProofError)


def test_verify_many_still_verifies_with_a_good_pin():
    out = verify_many([_di_credential()],
                      policy=VerificationPolicy(require_status=False, now=NOW_2021))
    assert out[0].ok


@pytest.mark.parametrize("now", [1_609_459_200, "2021-01-01", datetime.max])
def test_verify_many_async_fails_each_item_on_a_bad_now(now):
    batch = [_di_credential(), _di_credential()]
    out = asyncio.run(verify_many_async(
        batch, policy=VerificationPolicy(require_status=False, now=now)))
    assert [r.index for r in out] == [0, 1]
    assert all(not r.ok and isinstance(r.error, ProofError) for r in out)


# --------------------------------------------------------------------------- #
# The expiry waiver — a bad pin is not read as "not expired"
# --------------------------------------------------------------------------- #
# A VC-JWT or SD-JWT VC that expires only by its body `validUntil` (no JWT `exp`) is
# judged under `require_not_expired=False` by the pipeline's `expired` flag, the one
# place those lanes read `policy.now`. That flag swallowed every ProofError, so a pin
# the window check could not evaluate came back as a verified `expired=False`.

def _expired_vc_jwt() -> str:
    key, did = _did_key_signer()
    return VcJwtProofSuite().sign({
        "@context": [VC2],
        "type": ["VerifiableCredential"],
        "issuer": did,
        "validUntil": "2021-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice"},
    }, signing_key=key)


def _expired_sd_jwt() -> str:
    key, did = _did_key_signer()
    return SdJwtVcProofSuite().issue(
        {"iss": did, "sub": "did:example:alice", "given_name": "Ada",
         "validUntil": "2021-01-01T00:00:00Z"},
        signing_key=key, vct="https://credentials.example/id", disclosable=["given_name"])


_JOSE_BODY_EXPIRED = [pytest.param(_expired_vc_jwt, id="vc-jwt"),
                      pytest.param(_expired_sd_jwt, id="sd-jwt")]


@pytest.mark.parametrize("make", _JOSE_BODY_EXPIRED)
def test_expiry_waiver_flags_a_body_expired_jose_credential(make):
    result = verify_credential(make(), policy=VerificationPolicy(
        require_status=False, require_not_expired=False, now=datetime(2026, 1, 1, tzinfo=UTC)))
    assert result.expired is True


@pytest.mark.parametrize("now", [
    pytest.param(1_767_225_600, id="epoch-int"),
    pytest.param("2026-01-01", id="iso-string"),
    pytest.param(datetime.max - timedelta(seconds=30), id="within-leeway-of-max"),
])
@pytest.mark.parametrize("make", _JOSE_BODY_EXPIRED)
def test_expiry_waiver_does_not_read_a_bad_pin_as_not_expired(make, now):
    policy = VerificationPolicy(require_status=False, require_not_expired=False, now=now)
    for out in (verify_many([make()], policy=policy),
                asyncio.run(verify_many_async([make()], policy=policy))):
        assert out[0].result is None                     # never a verified expired=False
        assert isinstance(out[0].error, ProofError)
