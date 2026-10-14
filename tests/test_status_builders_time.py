"""
tests/test_status_builders_time.py — the status builders type their time inputs and
``ttl``, and read a naive ``datetime`` the one way openvc reads it (#255).

#250 (#230) made the issuer-side builders refuse what the verifier refuses on the index,
the pointer strings and the list size. It left the time inputs and ``ttl``::

    build_status_list_token(issued_at="soon")         -> bare ValueError
    build_status_list_token(issued_at=10**400)        -> minted, then refused by openvc
    build_status_list_credential(valid_from="2026-…") -> bare AttributeError
    build_status_list_credential(valid_from=datetime(1, 1, 1, tzinfo=+01:00))
                                                      -> bare OverflowError
    build_status_list_token(ttl=float("nan"))         -> signed, ``"ttl":NaN`` (not JSON)

and, worse, a wrong signed value: ``_epoch`` read a naive ``datetime`` as UTC while ``_iso``
called ``astimezone``, which reads it as the HOST's local time. The same
``datetime(2026, 1, 1, 12, 0)`` minted ``validFrom = 03:00Z`` and ``iat = 12:00Z`` under
``TZ=Asia/Tokyo``. Both builders now read a ``datetime`` through ``utc_instant`` /
``utc_epoch`` (a naive value is UTC), ``issued_at`` / ``expires`` must otherwise pass the
verifier's NumericDate gate, and ``ttl`` is ``None`` or a positive ``int``.

Every refusal is asserted against the EXACT class ``StatusListError`` (it has no
subclasses), never ``ValueError`` / ``TypeError`` / ``OverflowError`` /
``AttributeError``. The token negatives sign with a key whose ``sign`` raises, which proves
the error comes BEFORE ``sign_compact``. The controls show the well-formed inputs still
build and round-trip. Helpers are self-contained (tests/ is not a package: no
cross-import).
"""
from __future__ import annotations

import base64
import enum
import json
import re
import time
from datetime import date, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from fractions import Fraction
from typing import Any, Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey
from openvc.proof._verify_common import (
    _bound,
    check_validity_window,
    utc_epoch,
    utc_instant,
)
from openvc.proof.errors import CredentialExpired, CredentialNotYetValid, ProofError
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import (
    StatusListError,
    build_status_list_credential,
    build_status_list_token,
    new_bitstring,
    new_status_list,
    verify_status_list_token,
)

UTC = timezone.utc
LIST_URL = "https://status.example/w3c/1"
TOKEN_URI = "https://status.example/ietf/1"
ISSUER = "did:example:issuer"
NAN = float("nan")
INF = float("inf")
HUGE = 10 ** 5000          # past sys.get_int_max_str_digits: str()/repr() raise ValueError
PLUS_ONE = timezone(timedelta(hours=1))
PLUS_NINE = timezone(timedelta(hours=9))
MINUS_FIVE = timezone(timedelta(hours=-5))

SK = Ed25519SigningKey.generate(kid="did:key:zTime#zTime")
BITS = new_bitstring(64)
LST = new_status_list(64)

_GLIBC_SAFE_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class _SignedTooEarly(AssertionError):
    pass


class _ExplodingKey:
    """A key that must never be asked to sign: every refusal below has to happen before
    ``sign_compact`` is reached."""

    alg = "EdDSA"
    kid = "did:key:zNever#zNever"

    def sign(self, signing_input: bytes) -> bytes:
        raise _SignedTooEarly("the builder signed a token it should have refused")


def cred(**kw: Any) -> dict[str, Any]:
    return build_status_list_credential(id=LIST_URL, issuer=ISSUER, bitstring=BITS, **kw)


def tok(**kw: Any) -> str:
    return build_status_list_token(signing_key=SK, uri=TOKEN_URI, status_list=LST, **kw)


def tok_unsigned(**kw: Any) -> str:
    return build_status_list_token(
        signing_key=_ExplodingKey(), uri=TOKEN_URI, status_list=LST, **kw)


def claims_of(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def refused(call: Callable[[], Any], *, names: str | None = None) -> StatusListError:
    """Run *call*; it must raise exactly ``StatusListError``, naming *names* if given."""
    with pytest.raises(Exception) as caught:
        call()
    exc = caught.value
    assert type(exc) is StatusListError, f"{type(exc).__name__}: {exc}"
    assert isinstance(exc, OpenvcError)
    if names is not None:
        assert names in str(exc), str(exc)
    return exc


class _RaisingTz(tzinfo):
    """A ``tzinfo`` whose offset lookup raises, as a broken zone database would."""

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        raise RuntimeError("tz database unavailable")

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return "RAISING"


class _NoOffsetTz(tzinfo):
    """Aware by ``tzinfo``, naive by Python's own definition (``utcoffset()`` is None)."""

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        return None

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return None


class _LyingDatetime(datetime):
    """A subclass whose ``astimezone`` says UTC but is not."""

    def astimezone(self, tz: Any = None) -> datetime:           # type: ignore[override]
        return datetime(2000, 1, 1, tzinfo=PLUS_NINE)


# --------------------------------------------------------------------------- #
# What is not a time at all (the three tables of the issue)
# --------------------------------------------------------------------------- #

# Neither a datetime nor a finite number of seconds: refused by BOTH builders.
_NOT_A_TIME = [
    pytest.param("soon", id="str"),
    pytest.param("2026-01-01", id="iso-date-str"),
    pytest.param("2026-01-01T00:00:00Z", id="iso-datetime-str"),
    pytest.param("1700000000", id="digit-str"),
    pytest.param("", id="empty-str"),
    pytest.param(b"1700000000", id="bytes"),
    pytest.param(date(2026, 1, 1), id="date"),
    pytest.param(timedelta(days=1), id="timedelta"),
    pytest.param([], id="list"),
    pytest.param({}, id="dict"),
    pytest.param((1,), id="tuple"),
    pytest.param(object(), id="object"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param(NAN, id="nan"),
    pytest.param(INF, id="inf"),
    pytest.param(-INF, id="-inf"),
    pytest.param(10 ** 400, id="int-1e400"),
    pytest.param(-(10 ** 400), id="int--1e400"),
    pytest.param(HUGE, id="int-1e5000"),
    pytest.param(Decimal("5"), id="decimal"),
    pytest.param(Fraction(5), id="fraction"),
]


@pytest.mark.parametrize("field", ["issued_at", "expires"])
@pytest.mark.parametrize("value", _NOT_A_TIME)
def test_token_refuses_what_is_not_a_time(field, value):
    refused(lambda: tok_unsigned(**{field: value}), names=field)


@pytest.mark.parametrize("field", ["valid_from", "valid_until"])
@pytest.mark.parametrize("value", [
    *_NOT_A_TIME,
    pytest.param(1790000000, id="int-epoch"),
    pytest.param(1.79e9, id="float-epoch"),
    pytest.param(0, id="zero"),
])
def test_credential_refuses_what_is_not_a_datetime(field, value):
    # the signature says ``datetime | None``; an epoch number is not one (the token
    # builder takes it, this one never did: it died with a bare AttributeError)
    refused(lambda: cred(**{field: value}), names=field)


@pytest.mark.parametrize("field", ["valid_from", "valid_until"])
@pytest.mark.parametrize("value", [
    pytest.param(datetime(1, 1, 1, tzinfo=PLUS_ONE), id="year1-at-+01:00"),
    pytest.param(datetime(9999, 12, 31, 23, tzinfo=MINUS_FIVE), id="year9999-at--05:00"),
    pytest.param(datetime(1, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=14))),
                 id="year1-at-+14:00"),
    pytest.param(datetime(2026, 1, 1, tzinfo=_RaisingTz()), id="raising-tzinfo"),
    pytest.param(_LyingDatetime(2026, 1, 1, tzinfo=PLUS_ONE), id="astimezone-lies"),
])
def test_credential_refuses_a_datetime_with_no_utc_reading(field, value):
    # a UTC form outside years 1..9999 was a bare OverflowError; a tzinfo that raises
    # escaped as itself
    refused(lambda: cred(**{field: value}), names=field)


@pytest.mark.parametrize("field", ["issued_at", "expires"])
def test_token_refuses_a_datetime_whose_tzinfo_raises(field):
    refused(lambda: tok_unsigned(**{field: datetime(2026, 1, 1, tzinfo=_RaisingTz())}),
            names=field)


def test_the_error_names_the_parameter_and_the_value_safely():
    # brief() never renders a 5000-digit integer or a container
    assert "a 16610-bit integer" in str(refused(lambda: tok_unsigned(issued_at=HUGE)))
    assert "a list" in str(refused(lambda: cred(valid_until=[1, 2])))
    assert "'soon'" in str(refused(lambda: tok_unsigned(expires="soon")))
    for field in ("valid_from", "valid_until"):
        assert field in str(refused(lambda: cred(**{field: date(2026, 1, 1)})))


# --------------------------------------------------------------------------- #
# ttl: None or a positive int, on both builders
# --------------------------------------------------------------------------- #

_BAD_TTL = [
    pytest.param("5", id="digit-str"),
    pytest.param("soon", id="str"),
    pytest.param("", id="empty-str"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param(1.5, id="float"),
    pytest.param(300.0, id="integral-float"),
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(-(10 ** 400), id="negative-bignum"),
    pytest.param([], id="list"),
    pytest.param({}, id="dict"),
    pytest.param(object(), id="object"),
    pytest.param(10 ** 400, id="int-1e400"),
    pytest.param(HUGE, id="int-1e5000"),
    pytest.param(NAN, id="nan"),
    pytest.param(INF, id="inf"),
    pytest.param(-INF, id="-inf"),
    pytest.param(timedelta(minutes=5), id="timedelta"),
    pytest.param(Decimal("5"), id="decimal"),
    pytest.param(Fraction(5), id="fraction"),
]


@pytest.mark.parametrize("value", _BAD_TTL)
def test_credential_refuses_a_bad_ttl(value):
    refused(lambda: cred(ttl=value), names="ttl")


@pytest.mark.parametrize("value", _BAD_TTL)
def test_token_refuses_a_bad_ttl_before_signing(value):
    refused(lambda: tok_unsigned(ttl=value), names="ttl")


@pytest.mark.parametrize("value", [NAN, INF, -INF], ids=["nan", "inf", "-inf"])
def test_a_non_finite_ttl_never_reaches_a_signed_payload(value):
    # it used to be signed as ``"ttl":NaN`` (not JSON, RFC 8259), and the JOSE verifiers
    # accepted it while the Data Integrity suites refused the same credential
    refused(lambda: tok_unsigned(ttl=value), names="ttl")
    refused(lambda: cred(ttl=value), names="ttl")


def test_ttl_controls_round_trip_on_both_builders():
    token = tok(ttl=300)
    claims = verify_status_list_token(token, public_key_jwk=SK.public_jwk())
    assert claims["ttl"] == 300 and type(claims["ttl"]) is int
    assert cred(ttl=300)["credentialSubject"]["ttl"] == 300
    assert cred(ttl=1)["credentialSubject"]["ttl"] == 1
    assert "ttl" not in claims_of(tok())
    assert "ttl" not in cred()["credentialSubject"]
    assert "ttl" not in cred(ttl=None)["credentialSubject"]


# --------------------------------------------------------------------------- #
# A subclass says one number to the checks and another to whoever reads it later
# --------------------------------------------------------------------------- #

def _lie(name: str, answer: Any) -> Callable[..., Any]:
    def method(self: Any, *args: Any) -> Any:
        return answer
    method.__name__ = name
    return method


class _LiarInt(int):
    """An int that tells the comparisons, the casts and the printers something else."""

    __int__ = _lie("__int__", -1)
    __index__ = _lie("__index__", -1)
    __float__ = _lie("__float__", NAN)
    __str__ = _lie("__str__", "liar")
    __repr__ = _lie("__repr__", "liar")
    __format__ = _lie("__format__", "liar")
    __lt__ = _lie("__lt__", True)
    __le__ = _lie("__le__", True)
    __gt__ = _lie("__gt__", False)
    __ge__ = _lie("__ge__", False)


class _LiarFloat(float):
    __int__ = _lie("__int__", -1)
    __float__ = _lie("__float__", NAN)
    __str__ = _lie("__str__", "liar")
    __repr__ = _lie("__repr__", "liar")
    __lt__ = _lie("__lt__", False)
    __ge__ = _lie("__ge__", False)


class _Slot(enum.IntEnum):
    FIVE_MINUTES = 300


def test_an_int_subclass_ttl_is_emitted_as_the_integer_it_holds():
    for value in (_LiarInt(300), _Slot.FIVE_MINUTES):
        token_ttl = claims_of(tok(ttl=value))["ttl"]
        credential_ttl = cred(ttl=value)["credentialSubject"]["ttl"]
        assert token_ttl == credential_ttl == 300
        assert type(credential_ttl) is int
        assert json.dumps(credential_ttl) == "300"


def test_an_int_subclass_ttl_is_judged_by_the_integer_it_holds_not_what_it_says():
    # says it is a big positive finite number; holds 0 / a bignum
    refused(lambda: cred(ttl=_LiarInt(0)), names="ttl")
    refused(lambda: tok_unsigned(ttl=_LiarInt(0)), names="ttl")
    refused(lambda: cred(ttl=_LiarInt(HUGE)), names="ttl")
    refused(lambda: tok_unsigned(ttl=_LiarInt(10 ** 400)), names="ttl")


def test_a_number_subclass_time_is_signed_as_the_number_it_holds():
    assert claims_of(tok(issued_at=_LiarInt(1700000000)))["iat"] == 1700000000
    assert claims_of(tok(issued_at=_LiarFloat(1.7e9)))["iat"] == 1700000000
    assert claims_of(tok(issued_at=1700000000, expires=_LiarInt(1800000000)))["exp"] == 1800000000
    refused(lambda: tok_unsigned(issued_at=_LiarInt(10 ** 400)), names="issued_at")
    refused(lambda: tok_unsigned(expires=_LiarFloat(NAN)), names="expires")


# --------------------------------------------------------------------------- #
# Controls: what built before still builds, byte for byte
# --------------------------------------------------------------------------- #

def test_aware_utc_valid_from_is_byte_identical_to_before():
    vc = cred(valid_from=datetime(2026, 1, 1, tzinfo=UTC),
              valid_until=datetime(2027, 1, 1, 12, 34, 56, 789012, tzinfo=UTC))
    assert vc["validFrom"] == "2026-01-01T00:00:00Z"
    assert vc["validUntil"] == "2027-01-01T12:34:56Z"          # microseconds are dropped
    assert "validFrom" not in cred() and "validUntil" not in cred()
    assert "validFrom" not in cred(valid_from=None, valid_until=None)


def test_an_aware_offset_is_converted_to_z():
    vc = cred(valid_from=datetime(2026, 1, 1, 9, 0, tzinfo=PLUS_NINE),
              valid_until=datetime(2026, 1, 1, 7, 0, tzinfo=MINUS_FIVE))
    assert vc["validFrom"] == "2026-01-01T00:00:00Z"
    assert vc["validUntil"] == "2026-01-01T12:00:00Z"


@pytest.mark.parametrize("year", [1, 9, 99, 999, 1000, 2026, 9999])
def test_the_year_is_zero_padded_to_four_digits(year):
    # strftime("%Y") does not pad on glibc (the #218 CI failure on Linux 3.10-3.13): the
    # verifier then refuses "999-01-01T00:00:00Z" as a MalformedTimestamp
    vc = cred(valid_from=datetime(year, 1, 1, tzinfo=UTC))
    assert vc["validFrom"] == f"{year:04d}-01-01T00:00:00Z"
    assert _GLIBC_SAFE_Z.match(vc["validFrom"])


def test_time_time_still_works_for_issued_at_and_expires():
    before = int(time.time())
    claims = claims_of(tok(issued_at=time.time(), expires=time.time() + 3600))
    assert before <= claims["iat"] <= int(time.time())
    assert type(claims["iat"]) is int and type(claims["exp"]) is int
    assert claims["exp"] - claims["iat"] in (3599, 3600, 3601)
    assert claims_of(tok())["iat"] >= before                     # the default is now


def test_token_numeric_controls():
    assert claims_of(tok(issued_at=1700000000))["iat"] == 1700000000
    assert claims_of(tok(issued_at=1.7e9))["iat"] == 1700000000     # truncated, as before
    assert claims_of(tok(issued_at=1700000000.9))["iat"] == 1700000000
    assert claims_of(tok(issued_at=0))["iat"] == 0                  # an epoch, not "absent"
    assert claims_of(tok(issued_at=-1))["iat"] == -1
    assert claims_of(tok(issued_at=10 ** 300))["iat"] == 10 ** 300  # a float holds it
    assert "exp" not in claims_of(tok())
    assert "exp" not in claims_of(tok(expires=None))
    assert claims_of(tok(expires=1800000000))["exp"] == 1800000000


def test_token_datetime_controls():
    claims = claims_of(tok(
        issued_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
        expires=datetime(2026, 1, 1, 21, tzinfo=PLUS_NINE)))
    assert claims["iat"] == 1767268800                              # 2026-01-01T12:00:00Z
    assert claims["exp"] == 1767268800                              # 21:00+09:00 is 12:00Z
    # the token reads an aware value as an epoch, so year 1 at +01:00 has one (the
    # credential, which needs a UTC *string*, refuses it)
    assert claims_of(tok(issued_at=datetime(1, 1, 1, tzinfo=PLUS_ONE)))["iat"] == -62135600400


def test_a_tzinfo_with_no_offset_is_naive_so_utc_in_both_builders():
    # Python's own definition of naive is ``utcoffset() is None``: it was a bare
    # TypeError in the token builder and the host's local time in the credential one
    moment = datetime(2026, 1, 1, 12, tzinfo=_NoOffsetTz())
    assert cred(valid_from=moment)["validFrom"] == "2026-01-01T12:00:00Z"
    assert claims_of(tok(issued_at=moment))["iat"] == 1767268800


def test_naive_extremes_are_read_as_utc_so_they_build():
    # a bare ValueError ("year must be in 1..9999") when the naive value was read as local
    vc = cred(valid_from=datetime.min, valid_until=datetime.max)
    assert vc["validFrom"] == "0001-01-01T00:00:00Z"
    assert vc["validUntil"] == "9999-12-31T23:59:59Z"
    assert claims_of(tok(issued_at=datetime.min))["iat"] == -62135596800


# --------------------------------------------------------------------------- #
# One reading of a naive datetime, whatever the host's zone
# --------------------------------------------------------------------------- #

NAIVE_WINTER = datetime(2026, 1, 1, 12, 0)
NAIVE_SUMMER = datetime(2026, 7, 1, 12, 0)
_UTC_ISO = {NAIVE_WINTER: "2026-01-01T12:00:00Z", NAIVE_SUMMER: "2026-07-01T12:00:00Z"}

# POSIX TZ strings need no tzdata, so the pin takes on a bare CI image; the named zones
# are the ones the issue measured and are skipped only where the zone data is not installed.
_HOST_ZONES = [
    pytest.param("UTC", timedelta(0), id="UTC"),
    pytest.param("JST-9", timedelta(hours=9), id="posix-UTC+9"),
    pytest.param("EST5EDT,M3.2.0,M11.1.0", timedelta(hours=-5), id="posix-UTC-5-dst"),
    pytest.param("Asia/Tokyo", timedelta(hours=9), id="Asia-Tokyo"),
    pytest.param("America/New_York", timedelta(hours=-5), id="America-New_York"),
]

needs_tzset = pytest.mark.skipif(
    not hasattr(time, "tzset"), reason="the host zone can be changed only through POSIX tzset")


@pytest.fixture
def host_zone(monkeypatch):
    """Set the process's local zone, and put it back before the next test: ``setenv`` is
    undone by monkeypatch, but the C library re-reads ``TZ`` only on ``tzset``."""
    def pin(spec: str, expected_winter_offset: timedelta) -> None:
        monkeypatch.setenv("TZ", spec)
        time.tzset()
        winter = datetime(2026, 1, 1, 12, 0).astimezone().utcoffset()
        if winter != expected_winter_offset:
            pytest.skip(f"zone {spec!r} not available here (host offset {winter})")
    yield pin
    monkeypatch.undo()
    time.tzset()


def _mint(naive: datetime) -> dict[str, Any]:
    """What every builder mints for *naive*, as plain data."""
    vc = cred(valid_from=naive, valid_until=naive, ttl=300)
    token = tok(issued_at=naive, expires=naive)
    claims = claims_of(token)
    return {"validFrom": vc["validFrom"], "validUntil": vc["validUntil"],
            "iat": claims["iat"], "exp": claims["exp"]}


@needs_tzset
@pytest.mark.parametrize("naive", [NAIVE_WINTER, NAIVE_SUMMER], ids=["winter", "summer"])
@pytest.mark.parametrize("spec, offset", _HOST_ZONES)
def test_a_naive_datetime_is_the_same_instant_in_both_builders_on_any_host(
        host_zone, spec, offset, naive):
    host_zone("UTC", timedelta(0))
    baseline = _mint(naive)
    host_zone(spec, offset)
    got = _mint(naive)

    utc_reading = naive.replace(tzinfo=UTC)
    assert got == baseline, "the host's zone leaked into what was signed"
    assert got["validFrom"] == got["validUntil"] == _UTC_ISO[naive]
    assert got["iat"] == got["exp"] == int(utc_reading.timestamp())
    # the string and the epoch are the one instant: the claim the issue measured apart
    assert datetime.fromisoformat(got["validFrom"][:-1] + "+00:00") == utc_reading
    assert datetime.fromtimestamp(got["iat"], UTC) == utc_reading
    # ...and the verifier's own reading of that string puts the window at 12:00Z, not at
    # the 03:00Z / 17:00Z a host-local reading gave
    vc = cred(valid_from=naive)
    with pytest.raises(CredentialNotYetValid):
        check_validity_window(vc, {}, now=utc_reading - timedelta(seconds=1), leeway_s=0)
    assert check_validity_window(vc, {}, now=utc_reading, leeway_s=0) is False


@needs_tzset
@pytest.mark.parametrize("spec, offset", _HOST_ZONES)
def test_an_aware_datetime_does_not_depend_on_the_host_zone(host_zone, spec, offset):
    aware = datetime(2026, 1, 1, 21, 0, tzinfo=PLUS_NINE)
    host_zone(spec, offset)
    assert cred(valid_from=aware)["validFrom"] == "2026-01-01T12:00:00Z"
    assert claims_of(tok(issued_at=aware))["iat"] == 1767268800


@needs_tzset
def test_the_pin_takes_effect_so_the_zone_test_cannot_pass_vacuously(host_zone):
    # if TZ were ignored, "equal to the UTC output" would hold for any implementation
    host_zone("JST-9", timedelta(hours=9))
    assert datetime(2026, 1, 1, 12).astimezone(UTC).hour == 3          # the host-local reading
    assert cred(valid_from=NAIVE_WINTER)["validFrom"] == "2026-01-01T12:00:00Z"


# --------------------------------------------------------------------------- #
# The name= keyword on the shared clock helpers (verify path of every lane)
# --------------------------------------------------------------------------- #

def test_clock_helpers_keep_their_default_messages():
    for helper in (utc_epoch, utc_instant):
        with pytest.raises(ProofError, match=r"^now must be a datetime or None, not str$"):
            helper("2026-01-01")
        with pytest.raises(ProofError, match=r"^now cannot be read as an instant: "):
            helper(datetime(2026, 1, 1, tzinfo=_RaisingTz()))


def test_clock_helpers_name_the_parameter_when_asked():
    for helper in (utc_epoch, utc_instant):
        with pytest.raises(ValueError, match=r"^valid_from must be a datetime or None, not int$"):
            helper(5, error=ValueError, name="valid_from")
        with pytest.raises(ValueError, match=r"^valid_from cannot be read as an instant: "):
            helper(datetime(2026, 1, 1, tzinfo=_RaisingTz()), error=ValueError,
                   name="valid_from")
    # the reading itself is unchanged
    assert utc_instant(NAIVE_WINTER, name="x") == datetime(2026, 1, 1, 12, tzinfo=UTC)
    assert utc_epoch(NAIVE_WINTER, name="x") == 1767268800
    assert utc_instant(None, name="x").tzinfo is UTC
    assert abs(utc_epoch(None, name="x") - time.time()) < 5


# --------------------------------------------------------------------------- #
# Round trips: build, sign, verify, read the instant back
# --------------------------------------------------------------------------- #

def _now_ish() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _round_trip_credential(valid_from: datetime, valid_until: datetime) -> dict[str, Any]:
    suite = VcJwtProofSuite()
    signed = suite.sign(cred(valid_from=valid_from, valid_until=valid_until), signing_key=SK)
    # VcJwtProofSuite.verify has no ``now=``: the window must contain today
    return suite.verify(signed, public_key_jwk=SK.public_jwk()).credential


@pytest.mark.parametrize("kind", ["aware-utc", "aware-+09:00", "aware--05:00", "naive"])
def test_credential_round_trips_the_instant_it_was_given(kind):
    start, end = _now_ish() - timedelta(hours=1), _now_ish() + timedelta(hours=1)
    shape = {
        "aware-utc": lambda d: d,
        "aware-+09:00": lambda d: d.astimezone(PLUS_NINE),
        "aware--05:00": lambda d: d.astimezone(MINUS_FIVE),
        "naive": lambda d: d.replace(tzinfo=None),         # its UTC value, as a naive one
    }[kind]
    verified = _round_trip_credential(shape(start), shape(end))
    assert _bound(verified, "validFrom") == start
    assert _bound(verified, "validUntil") == end


def test_credential_round_trips_years_1_and_9999():
    verified = _round_trip_credential(
        datetime(1, 1, 1, tzinfo=UTC), datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC))
    assert verified["validFrom"] == "0001-01-01T00:00:00Z"
    assert verified["validUntil"] == "9999-12-31T23:59:59Z"
    assert _bound(verified, "validFrom") == datetime(1, 1, 1, tzinfo=UTC)
    assert _bound(verified, "validUntil") == datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)


def test_credential_window_is_judged_at_the_instant_that_was_given():
    start = datetime(2026, 1, 1, 12)                               # naive: UTC
    end = datetime(2026, 1, 1, 21, tzinfo=PLUS_NINE) + timedelta(hours=1)    # 13:00Z
    vc = cred(valid_from=start, valid_until=end)
    at = lambda **kw: datetime(2026, 1, 1, tzinfo=UTC) + timedelta(**kw)      # noqa: E731
    assert check_validity_window(vc, {}, now=at(hours=12), leeway_s=0) is False
    with pytest.raises(CredentialNotYetValid):
        check_validity_window(vc, {}, now=at(hours=12, seconds=-1), leeway_s=0)
    assert check_validity_window(vc, {}, now=at(hours=13), leeway_s=0) is False
    with pytest.raises(CredentialExpired):
        check_validity_window(vc, {}, now=at(hours=13, seconds=1), leeway_s=0)


_TOKEN_WHEN = [
    pytest.param(datetime(2026, 1, 1, 12, tzinfo=UTC), 1767268800, id="aware-utc"),
    pytest.param(datetime(2026, 1, 1, 21, tzinfo=PLUS_NINE), 1767268800, id="aware-+09:00"),
    pytest.param(datetime(2026, 1, 1, 7, tzinfo=MINUS_FIVE), 1767268800, id="aware--05:00"),
    pytest.param(datetime(2026, 1, 1, 12), 1767268800, id="naive"),
    pytest.param(1767268800, 1767268800, id="int"),
    pytest.param(1767268800.75, 1767268800, id="float"),
    pytest.param(datetime(1, 1, 1, tzinfo=UTC), -62135596800, id="year-1"),
    pytest.param(datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), 253402300799, id="year-9999"),
]


@pytest.mark.parametrize("given, epoch", _TOKEN_WHEN)
def test_token_round_trips_the_instant_it_was_given(given, epoch):
    token = tok(issued_at=given, expires=epoch + 1800)
    claims = verify_status_list_token(
        token, public_key_jwk=SK.public_jwk(), expected_uri=TOKEN_URI, now=epoch)
    assert claims["iat"] == epoch and claims["exp"] == epoch + 1800
    assert type(claims["iat"]) is int
    # the same instant pinned as a datetime reads the same (EPOCH + delta, because
    # fromtimestamp of a negative value is platform-dependent)
    pinned = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=epoch)
    verify_status_list_token(token, public_key_jwk=SK.public_jwk(), now=pinned)
    token = tok(issued_at=epoch - 1800, expires=given)
    claims = verify_status_list_token(token, public_key_jwk=SK.public_jwk(), now=epoch - 60)
    assert claims["exp"] == epoch


# --------------------------------------------------------------------------- #
# Properties
# --------------------------------------------------------------------------- #

_offsets = st.integers(min_value=-14 * 60, max_value=14 * 60).map(
    lambda minutes: timezone(timedelta(minutes=minutes)))
_zones = st.one_of(st.none(), st.just(UTC), _offsets)
_datetimes = st.datetimes(min_value=datetime.min, max_value=datetime.max, timezones=_zones)

_junk = st.one_of(
    st.booleans(), st.integers(), st.integers(10 ** 20, 10 ** 400),   # None is "absent"
    st.integers(min_value=10 ** 4400, max_value=10 ** 4500),
    st.floats(), st.text(max_size=12), st.binary(max_size=8), st.dates(), st.timedeltas(),
    st.lists(st.integers(), max_size=2), st.just(NAN), st.just(INF),
)
_when = st.one_of(
    _datetimes, st.integers(min_value=-2 ** 62, max_value=2 ** 62),
    st.floats(min_value=-1e300, max_value=1e300, allow_nan=False, allow_infinity=False),
)


def _utc_form(value: datetime) -> datetime | None:
    """The aware UTC value of *value*, computed independently of the code under test."""
    try:
        return (value.replace(tzinfo=UTC) if value.utcoffset() is None
                else value.astimezone(UTC))
    except OverflowError:
        return None


def _is_finite_number(value: Any) -> bool:
    """The verifier's NumericDate rule, written out: an int or float, not a bool, that a
    float can hold and that is not NaN or infinite."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        number = float(value)
    except OverflowError:
        return False
    return number == number and number not in (INF, -INF)


@settings(max_examples=300, deadline=None)
@given(value=st.one_of(_datetimes, _junk))
def test_property_credential_accepts_exactly_the_datetimes_with_a_utc_form(value):
    expected = _utc_form(value) if isinstance(value, datetime) else None
    if expected is None:
        refused(lambda: cred(valid_from=value))        # not a datetime, or no UTC reading
        return
    vc = cred(valid_from=value)
    assert _GLIBC_SAFE_Z.match(vc["validFrom"])
    assert _bound(vc, "validFrom") == expected.replace(microsecond=0)    # the verifier's reading


@settings(max_examples=300, deadline=None)
@given(a=_datetimes, b=_datetimes)
def test_property_a_credential_window_the_builder_accepts_is_readable_inside_it(a, b):
    ua, ub = _utc_form(a), _utc_form(b)
    if ua is None or ub is None:
        return                                         # refused above: nothing to read back
    (lo, lo_utc), (hi, _) = sorted([(a, ua), (b, ub)], key=lambda pair: pair[1])
    vc = cred(valid_from=lo, valid_until=hi)
    # now pinned inside the window, to the second: no MalformedTimestamp, not early, not late
    assert check_validity_window(vc, {}, now=lo_utc.replace(microsecond=0), leeway_s=0) is False


@settings(max_examples=300, deadline=None)
@given(a=_when, b=_when)
def test_property_a_token_window_the_builder_accepts_is_readable_inside_it(a, b):
    ea = claims_of(tok(issued_at=a))["iat"]
    eb = claims_of(tok(issued_at=b))["iat"]
    lo, hi = (a, b) if ea <= eb else (b, a)
    token = tok(issued_at=lo, expires=hi)
    claims = claims_of(token)
    assert claims["iat"] <= claims["exp"]
    # pinned at the start of the window: no "finite numeric timestamp" error, not expired
    verify_status_list_token(token, public_key_jwk=SK.public_jwk(), now=claims["iat"])


@settings(max_examples=300, deadline=None)
@given(value=st.one_of(_when, _junk))
def test_property_a_token_time_is_typed_or_read_back_by_the_verifier(value):
    built = isinstance(value, datetime) or _is_finite_number(value)
    for field in ("issued_at", "expires"):
        if not built:
            refused(lambda: tok_unsigned(**{field: value}), names=field)
            continue
        if field == "issued_at":
            token = tok(issued_at=value)
            instant = claims_of(token)["iat"]
        else:
            probe = claims_of(tok(expires=value))["exp"]
            token = tok(issued_at=probe - 10, expires=value)       # a window around it
            instant = probe - 1
        assert type(claims_of(token)["iat" if field == "issued_at" else "exp"]) is int
        verify_status_list_token(token, public_key_jwk=SK.public_jwk(), now=instant)


@settings(max_examples=300, deadline=None)
@given(ttl=st.one_of(
    st.none(), st.booleans(), st.integers(), st.integers(10 ** 290, 10 ** 400),
    st.floats(), st.text(max_size=4), st.lists(st.integers(), max_size=2)))
def test_property_ttl_is_none_or_a_positive_int_on_both_builders(ttl):
    good = ttl is None or (type(ttl) is int and ttl >= 1 and _is_finite_number(ttl))
    if good:
        assert cred(ttl=ttl)["credentialSubject"].get("ttl") == ttl
        assert claims_of(tok(ttl=ttl)).get("ttl") == ttl
    else:
        refused(lambda: cred(ttl=ttl), names="ttl")
        refused(lambda: tok_unsigned(ttl=ttl), names="ttl")        # before the key is asked


def test_every_builder_error_is_an_openvc_error_never_a_builtin():
    # the class a revocation-publishing job catches around a rebuild
    calls = [
        lambda: tok(issued_at="soon"), lambda: tok(expires=NAN), lambda: tok(ttl=0),
        lambda: cred(valid_from="2026-01-01"), lambda: cred(valid_until=1790000000),
        lambda: cred(valid_from=datetime(1, 1, 1, tzinfo=PLUS_ONE)), lambda: cred(ttl=NAN),
    ]
    for call in calls:
        with pytest.raises(OpenvcError):
            call()
