"""
tests/test_clock_reading_subclass.py — a ``datetime`` SUBCLASS cannot change how openvc
reads a clock (#286).

openvc's rule is "a naive ``datetime`` is UTC, whatever zone the host is in" (#187, #255).
``utc_instant`` / ``utc_epoch`` decided "naive" by asking the caller's own object
(``now.utcoffset() is None``), so a subclass answering ``timedelta(0)`` with no ``tzinfo``
was not naive: ``now.astimezone(UTC)`` read its fields as the HOST's local time and the
post-check, which called ``utcoffset()`` on the same subclass, passed. ``datetime(2026, 1,
1, 12)`` of such a class was ``11:00Z`` on a UTC+1 host, ``03:00Z`` on a UTC+9 one: an
expired credential, status list, certificate or MSO accepted east of UTC, a fresh KB-JWT
refused, and a different ``validFrom`` / ``iat`` signed per host. No attacker-controlled
bytes reach it: ``now`` and the builder times are arguments in the caller's own code.

Maintainer decision (2026-10-15): the value is read from its fields and ``tzinfo``
THROUGH THE BASE CLASS (``datetime.date`` + ``datetime.timetz``, called on the class) and
no method of the subclass is called. So a subclass cannot change the reading in either
direction: not into the host's zone, and not into a refusal (#255 refused one whose
``utcoffset()`` was not a ``timedelta``; that now reads as its fields).

How this file avoids passing vacuously:

* the host zone is PINNED (``TZ`` + ``tzset``, POSIX specs that need no tzdata) and the
  fixture asserts the pin took effect; the ``UTC`` host is the row where the bug cannot
  show, and is kept as a control;
* each lane is driven at three instants (inside the window, 15 minutes after it closes,
  15 minutes before it opens). The "late" pin shows on hosts east of UTC and the "early"
  one on hosts west of UTC; "inside" shows on every host that is not UTC;
* every expectation is the EXACT value or the EXACT class (``type(exc) is X``), never "did
  not raise" or ``pytest.raises(OpenvcError)``;
* the controls (a plain naive and a plain aware ``datetime``, a subclass that overrides
  nothing, an aware subclass whose ``utcoffset()`` answers ``timedelta(0)``) must pass
  before and after the change;
* a tripwire subclass records EVERY attribute the code reads off the caller's object, so
  a reading that asks the subclass anything is caught even when it happens to be right.

Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from openvc import VerificationPolicy, verify_credential, verify_vp_token
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import FORMAT_SD_JWT_VC
from openvc.proof._verify_common import utc_epoch, utc_instant
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import (
    ClaimsInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    ProofError,
)
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.status import (
    StatusListError,
    build_status_list_credential,
    build_status_list_token,
    new_bitstring,
    new_status_list,
    verify_status_list_token,
)
from openvc.x5c import X5cError, validate_cert_chain

UTC = timezone.utc
J = timezone(timedelta(hours=9))               # +09:00

# --------------------------------------------------------------------------- #
# The host's zone, pinned
# --------------------------------------------------------------------------- #

# POSIX TZ strings need no tzdata, so the pin holds on a bare CI image. UTC is the control
# row: the bug cannot show there.
_HOSTS = [
    pytest.param(("UTC", timedelta(0)), id="host-UTC"),
    pytest.param(("JST-9", timedelta(hours=9)), id="host-UTC+9"),
    pytest.param(("CET-1", timedelta(hours=1)), id="host-UTC+1"),
    pytest.param(("EST5EDT,M3.2.0,M11.1.0", timedelta(hours=-5)), id="host-UTC-5"),
]


@pytest.fixture(params=_HOSTS)
def host(request, monkeypatch):
    """Set the process's local zone for one test and put it back: ``setenv`` is undone by
    monkeypatch, but the C library re-reads ``TZ`` only on ``tzset``. Yields the zone's
    January offset from UTC. A pin that did not take effect FAILS (it does not skip), so a
    zone test cannot pass because ``TZ`` was ignored."""
    if not hasattr(time, "tzset"):
        pytest.skip("the host zone can be changed only through POSIX tzset")
    spec, january_offset = request.param
    monkeypatch.setenv("TZ", spec)
    time.tzset()
    seen = datetime(2026, 1, 1, 12).astimezone().utcoffset()
    assert seen == january_offset, f"TZ={spec!r} did not take effect (host offset {seen})"
    yield january_offset
    monkeypatch.undo()
    time.tzset()


# --------------------------------------------------------------------------- #
# The subclasses: each lies about, or breaks, one thing openvc used to ask it
# --------------------------------------------------------------------------- #

class NaiveSaysUtc(datetime):
    """tzinfo is None, but utcoffset() says UTC: the reported gap."""

    def utcoffset(self) -> Any:                                  # type: ignore[override]
        return timedelta(0)


class NaiveSaysPlusFive(datetime):
    def utcoffset(self) -> Any:                                  # type: ignore[override]
        return timedelta(hours=5)


class SaysNoOffset(datetime):
    """Aware by ``tzinfo``, naive by its own ``utcoffset()``."""

    def utcoffset(self) -> Any:                                  # type: ignore[override]
        return None


class AwareSaysZero(datetime):
    """The control the fix must not disturb: aware +09:00, ``utcoffset()`` says UTC."""

    def utcoffset(self) -> Any:                                  # type: ignore[override]
        return timedelta(0)


class NaiveTimestamp(datetime):
    """``timestamp()`` answers 86400.0, naive or aware."""

    def timestamp(self) -> float:
        return 86400.0


class AstimezoneLies(datetime):
    def astimezone(self, tz: Any = None) -> Any:                 # type: ignore[override]
        return datetime(2000, 1, 1, tzinfo=J)


class ReplaceLies(datetime):
    def replace(self, *args: Any, **kwargs: Any) -> Any:         # type: ignore[override]
        return datetime(2000, 1, 1, tzinfo=J)


class FieldsLie(datetime):
    """Every field property answers something else; the C fields are what is read."""

    year = property(lambda self: 1999)                           # type: ignore[assignment]
    month = property(lambda self: 7)                             # type: ignore[assignment]
    day = property(lambda self: 9)                               # type: ignore[assignment]
    hour = property(lambda self: 3)                              # type: ignore[assignment]
    minute = property(lambda self: 59)                           # type: ignore[assignment]
    second = property(lambda self: 58)                           # type: ignore[assignment]


class TzinfoLies(datetime):
    """The ``tzinfo`` attribute answers UTC-03:00; the one attached to the value is not."""

    tzinfo = property(lambda self: timezone(timedelta(hours=-3)))  # type: ignore[assignment]


class NoOverride(datetime):
    """Overrides nothing (the pendulum / pandas shape): a control."""


CALLS: list[str] = []


class Tripwire(datetime):
    """Records every attribute read off it. The reading is correct only if CALLS stays
    empty: what is read is the fields and ``tzinfo`` through the base class."""

    def __getattribute__(self, name: str) -> Any:
        CALLS.append(name)
        return datetime.__getattribute__(self, name)


def fields(cls: Callable[..., Any], when: datetime) -> Any:
    """*when*'s wall-clock fields and ``tzinfo`` as an instance of *cls*."""
    return cls(when.year, when.month, when.day, when.hour, when.minute, when.second,
               when.microsecond, tzinfo=when.tzinfo)


# --------------------------------------------------------------------------- #
# The helpers: utc_instant and utc_epoch
# --------------------------------------------------------------------------- #

NOON_Z = datetime(2026, 1, 1, 12, tzinfo=UTC)
NOON_EPOCH = 1767268800                        # 2026-01-01T12:00:00Z
THREE_Z = datetime(2026, 1, 1, 3, tzinfo=UTC)  # 12:00 at +09:00
THREE_EPOCH = 1767236400

# value, the instant utc_instant returns, the epoch utc_epoch returns
_LIARS = [
    pytest.param(NaiveSaysUtc(2026, 1, 1, 12), NOON_Z, NOON_EPOCH,
                 id="naive-utcoffset-says-UTC"),
    pytest.param(NaiveSaysPlusFive(2026, 1, 1, 12), NOON_Z, NOON_EPOCH,
                 id="naive-utcoffset-says-+5h"),
    pytest.param(SaysNoOffset(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="aware+09-utcoffset-says-None"),
    pytest.param(NaiveTimestamp(2026, 1, 1, 12), NOON_Z, NOON_EPOCH,
                 id="naive-timestamp-says-86400"),
    pytest.param(NaiveTimestamp(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="aware+09-timestamp-says-86400"),
    pytest.param(AstimezoneLies(2026, 1, 1, 12), NOON_Z, NOON_EPOCH,
                 id="naive-astimezone-lies"),
    pytest.param(AstimezoneLies(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="aware+09-astimezone-lies"),
    pytest.param(ReplaceLies(2026, 1, 1, 12), NOON_Z, NOON_EPOCH, id="naive-replace-lies"),
    pytest.param(ReplaceLies(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="aware+09-replace-lies"),
    pytest.param(FieldsLie(2026, 1, 1, 12), NOON_Z, NOON_EPOCH, id="naive-fields-lie"),
    pytest.param(FieldsLie(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="aware+09-fields-lie"),
    pytest.param(TzinfoLies(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="aware+09-tzinfo-attribute-lies"),
    pytest.param(TzinfoLies(2026, 1, 1, 12), NOON_Z, NOON_EPOCH,
                 id="naive-tzinfo-attribute-lies"),
]

# What must read the same before and after the change.
_CONTROLS = [
    pytest.param(datetime(2026, 1, 1, 12), NOON_Z, NOON_EPOCH, id="control-plain-naive"),
    pytest.param(datetime(2026, 1, 1, 12, tzinfo=UTC), NOON_Z, NOON_EPOCH,
                 id="control-plain-aware-UTC"),
    pytest.param(datetime(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="control-plain-aware+09"),
    pytest.param(NoOverride(2026, 1, 1, 12), NOON_Z, NOON_EPOCH,
                 id="control-no-override-naive"),
    pytest.param(NoOverride(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="control-no-override-aware+09"),
    pytest.param(AwareSaysZero(2026, 1, 1, 12, tzinfo=J), THREE_Z, THREE_EPOCH,
                 id="control-aware+09-utcoffset-says-UTC"),
]


@pytest.mark.parametrize("value, instant, epoch", [*_LIARS, *_CONTROLS])
def test_utc_instant_reads_the_fields_whatever_the_subclass_says(host, value, instant, epoch):
    got = utc_instant(value)
    assert type(got) is datetime and got.tzinfo is UTC
    assert got == instant
    assert got.isoformat() == instant.isoformat()


@pytest.mark.parametrize("value, instant, epoch", [*_LIARS, *_CONTROLS])
def test_utc_epoch_reads_the_fields_whatever_the_subclass_says(host, value, instant, epoch):
    got = utc_epoch(value)
    assert type(got) is int
    assert got == epoch


def test_the_lie_would_bite_on_this_host(host):
    # the witness that the zone tests below are not vacuous: the old reading of the
    # reported subclass (astimezone on a tzinfo-less value) is the host's local time
    old_reading = NaiveSaysUtc(2026, 1, 1, 12).astimezone(UTC)
    assert old_reading.replace(tzinfo=None) == datetime(2026, 1, 1, 12) - host
    # ...and what openvc reads is not that, on any host
    assert utc_instant(NaiveSaysUtc(2026, 1, 1, 12)) == NOON_Z


def test_the_helpers_ask_the_callers_object_nothing(host):
    for when in (datetime(2026, 1, 1, 12), datetime(2026, 1, 1, 12, tzinfo=J)):
        pin = fields(Tripwire, when)
        expected = (NOON_Z, NOON_EPOCH) if when.tzinfo is None else (THREE_Z, THREE_EPOCH)
        CALLS.clear()
        assert utc_instant(pin) == expected[0]
        assert CALLS == [], f"utc_instant read {CALLS} off the caller's datetime"
        assert utc_epoch(pin) == expected[1]
        assert CALLS == [], f"utc_epoch read {CALLS} off the caller's datetime"


def test_none_is_still_the_current_time():
    before = int(time.time())
    assert before <= utc_epoch(None) <= int(time.time())
    instant = utc_instant(None)
    assert type(instant) is datetime and instant.tzinfo is UTC


class _FoldZone(tzinfo):
    """UTC+02:00 at ``fold=0`` and UTC+01:00 at ``fold=1``: an ambiguous wall time, as in a
    DST fall-back. Needs no tzdata."""

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        return timedelta(hours=1 if dt is not None and dt.fold else 2)

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return "FOLD"


@pytest.mark.parametrize("cls", [datetime, NoOverride, AwareSaysZero])
@pytest.mark.parametrize("fold, hour", [(0, 0), (1, 1)])
def test_fold_survives_the_snapshot(cls, fold, hour):
    # 02:30 on the ambiguous night is 00:30Z the first time and 01:30Z the second
    value = cls(2026, 10, 25, 2, 30, tzinfo=_FoldZone(), fold=fold)
    assert value.fold == fold
    assert utc_instant(value) == datetime(2026, 10, 25, hour, 30, tzinfo=UTC)
    assert utc_epoch(value) == int(datetime(2026, 10, 25, hour, 30, tzinfo=UTC).timestamp())


def test_a_subclass_with_a_raising_tzinfo_is_still_typed():
    class RaisingTz(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta | None:
            raise RuntimeError("tz database unavailable")

        def dst(self, dt: datetime | None) -> timedelta | None:
            return None

        def tzname(self, dt: datetime | None) -> str | None:
            return None

    for helper in (utc_instant, utc_epoch):
        with pytest.raises(ProofError) as caught:
            helper(NoOverride(2026, 1, 1, tzinfo=RaisingTz()))
        assert type(caught.value) is ProofError
        assert str(caught.value) == "now cannot be read as an instant: tz database unavailable"


def test_year_one_at_a_positive_offset_keeps_each_helpers_reading():
    # utc_instant has no UTC form for it (typed); utc_epoch returns the number it always
    # did, and must not be routed through utc_instant
    value = NoOverride(1, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    with pytest.raises(ProofError) as caught:
        utc_instant(value)
    assert type(caught.value) is ProofError and "cannot be read as an instant" in str(caught.value)
    assert utc_epoch(value) == -62135600400
    assert utc_epoch(datetime.min) == -62135596800
    assert utc_epoch(NoOverride(1, 1, 1)) == -62135596800


def test_the_callers_error_class_and_parameter_name_are_kept():
    class LaneError(Exception):
        pass

    class RaisingTz(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta | None:
            raise RuntimeError("boom")

        def dst(self, dt: datetime | None) -> timedelta | None:
            return None

        def tzname(self, dt: datetime | None) -> str | None:
            return None

    for helper in (utc_instant, utc_epoch):
        with pytest.raises(LaneError) as caught:
            helper(NaiveSaysUtc(2026, 1, 1, tzinfo=RaisingTz()), error=LaneError, name="valid_from")
        assert type(caught.value) is LaneError
        assert str(caught.value) == "valid_from cannot be read as an instant: boom"


# --------------------------------------------------------------------------- #
# The entry points. One pin factory per kind of value; every lane is driven with each.
# --------------------------------------------------------------------------- #

def _plain_naive(when: datetime) -> Any:
    return when.replace(tzinfo=None)


def _plain_aware_utc(when: datetime) -> Any:
    return when


def _plain_aware_plus_nine(when: datetime) -> Any:
    return when.astimezone(J)


def _no_override_naive(when: datetime) -> Any:
    return fields(NoOverride, when.replace(tzinfo=None))


def _no_override_aware(when: datetime) -> Any:
    return fields(NoOverride, when.astimezone(J))


def _aware_says_utc(when: datetime) -> Any:
    return fields(AwareSaysZero, when.astimezone(J))


def _naive_says_utc(when: datetime) -> Any:
    return fields(NaiveSaysUtc, when.replace(tzinfo=None))


def _naive_says_plus_five(when: datetime) -> Any:
    return fields(NaiveSaysPlusFive, when.replace(tzinfo=None))


def _aware_says_none(when: datetime) -> Any:
    return fields(SaysNoOffset, when.astimezone(J))


def _naive_timestamp_lies(when: datetime) -> Any:
    return fields(NaiveTimestamp, when.replace(tzinfo=None))


_PINS = [
    pytest.param(_plain_naive, id="control-plain-naive"),
    pytest.param(_plain_aware_utc, id="control-plain-aware-UTC"),
    pytest.param(_plain_aware_plus_nine, id="control-plain-aware+09"),
    pytest.param(_no_override_naive, id="control-no-override-naive"),
    pytest.param(_no_override_aware, id="control-no-override-aware+09"),
    pytest.param(_aware_says_utc, id="control-aware+09-utcoffset-says-UTC"),
    pytest.param(_naive_says_utc, id="naive-utcoffset-says-UTC"),
    pytest.param(_naive_says_plus_five, id="naive-utcoffset-says-+5h"),
    pytest.param(_aware_says_none, id="aware+09-utcoffset-says-None"),
    pytest.param(_naive_timestamp_lies, id="naive-timestamp-says-86400"),
]

_WHEN = ["inside", "late", "early"]


def window_instant(when: str) -> datetime:
    """For a window [12:00Z, 12:30Z]: a pin inside it, 15 minutes after it closes, and 15
    minutes before it opens. The "late" pin shows the bug on hosts east of UTC (the shifted
    pin reads earlier), the "early" one on hosts west; "inside" shows it on every host
    that is not UTC."""
    minutes = {"inside": (12, 15), "late": (12, 45), "early": (11, 45)}[when]
    return datetime(2026, 1, 1, *minutes, tzinfo=UTC)


def _raises(exc_type: type[Exception], match: str, call: Callable[[], Any]) -> None:
    """*call* raises EXACTLY *exc_type*, with *match* in the message."""
    with pytest.raises(Exception) as caught:
        call()
    assert type(caught.value) is exc_type, f"{type(caught.value).__name__}: {caught.value}"
    assert match in str(caught.value), str(caught.value)


# ---- the builders mint the same value on every host -------------------------

LIST_URL = "https://status.example/w3c/1"
TOKEN_URI = "https://status.example/ietf/1"
STATUS_KEY = Ed25519SigningKey.generate(kid="did:key:zClock#zClock")


def _claims_of(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@pytest.mark.parametrize("make", _PINS)
def test_the_builders_sign_the_same_value_on_any_host(host, make):
    start, end = make(window_instant("early") + timedelta(minutes=15)), make(
        window_instant("late") - timedelta(minutes=15))          # 12:00Z and 12:30Z
    vc = build_status_list_credential(
        id=LIST_URL, issuer="did:example:issuer", bitstring=new_bitstring(64),
        valid_from=start, valid_until=end)
    assert vc["validFrom"] == "2026-01-01T12:00:00Z"
    assert vc["validUntil"] == "2026-01-01T12:30:00Z"
    claims = _claims_of(build_status_list_token(
        signing_key=STATUS_KEY, uri=TOKEN_URI, status_list=new_status_list(64),
        issued_at=start, expires=end))
    assert claims["iat"] == NOON_EPOCH and type(claims["iat"]) is int
    assert claims["exp"] == NOON_EPOCH + 1800 and type(claims["exp"]) is int


# ---- verify_status_list_token (IETF Token Status List) ----------------------

STATUS_TOKEN = build_status_list_token(
    signing_key=STATUS_KEY, uri=TOKEN_URI, status_list=new_status_list(64),
    issued_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
    expires=datetime(2026, 1, 1, 12, 30, tzinfo=UTC))

_TOKEN_VERDICT = {                                       # when -> (class, message part)
    "inside": None,
    "late": (StatusListError, "status list token has expired"),
    "early": (StatusListError, "status list token iat is in the future"),
}


@pytest.mark.parametrize("make", _PINS)
@pytest.mark.parametrize("when", _WHEN)
def test_verify_status_list_token_judges_the_pin_at_its_own_instant(host, make, when):
    pin = make(window_instant(when))

    def verify() -> Any:
        return verify_status_list_token(
            STATUS_TOKEN, public_key_jwk=STATUS_KEY.public_jwk(), leeway_s=0, now=pin)

    verdict = _TOKEN_VERDICT[when]
    if verdict is None:
        assert verify()["sub"] == TOKEN_URI
    else:
        _raises(verdict[0], verdict[1], verify)


# ---- verify_credential on a Data Integrity credential -----------------------

def _did_key_ed25519() -> tuple[Ed25519SigningKey, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    mb = encode_multibase(bytes([0xED, 0x01]) + Ed25519SigningKey(priv, "_").public_key_raw())
    return Ed25519SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


DI_KEY, DI_ISSUER = _did_key_ed25519()
DI_VC = EddsaJcsProofSuite().add_proof(
    {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"],
     "issuer": DI_ISSUER, "validFrom": "2026-01-01T12:00:00Z",
     "validUntil": "2026-01-01T12:30:00Z", "credentialSubject": {"id": "did:example:alice"}},
    signing_key=DI_KEY, verification_method=DI_KEY.kid)

_DI_VERDICT = {
    "inside": None,
    "late": (CredentialExpired, "credential expired at"),
    "early": (CredentialNotYetValid, "credential is not valid before"),
}


@pytest.mark.parametrize("make", _PINS)
@pytest.mark.parametrize("when", _WHEN)
def test_verify_credential_judges_the_policy_pin_at_its_own_instant(host, make, when):
    pin = make(window_instant(when))

    def verify() -> Any:
        return verify_credential(
            DI_VC, policy=VerificationPolicy(now=pin, leeway_s=0, require_status=False))

    verdict = _DI_VERDICT[when]
    if verdict is None:
        assert verify().issuer == DI_ISSUER
    else:
        _raises(verdict[0], verdict[1], verify)


# ---- the SD-JWT KB-JWT window, through verify_vp_token ----------------------

T = 1_791_661_760                      # 2026-10-10T19:49:20Z
KB_NOW = datetime.fromtimestamp(T, UTC)
KB_LEEWAY = 60                         # the suite default
KB_MAX_AGE = 300                       # the suite default
AUD = "x509_hash:verifier.example"
NONCE = "n-0S6_WzA2Mj"
VCT = "https://credentials.example.com/identity_credential"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issued_sd_jwt() -> tuple[str, P256SigningKey]:
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)               # multicodec p256-pub
    issuer_key = P256SigningKey(priv, kid=f"did:key:{mb}#{mb}")
    holder_key = P256SigningKey.generate(kid="holder")
    issued = SdJwtVcProofSuite().issue(
        {"iss": f"did:key:{mb}", "given_name": "Ada", "sub": "did:example:alice"},
        signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
        holder_jwk=holder_key.public_jwk())
    presented = issued if issued.endswith("~") else issued + "~"
    payload = {"aud": AUD, "nonce": NONCE, "iat": T,
               "sd_hash": _b64(hashlib.sha256(presented.encode("ascii")).digest())}
    signing_input = (_b64(json.dumps({"typ": "kb+jwt", "alg": "ES256"}).encode())
                     + "." + _b64(json.dumps(payload).encode()))
    return presented + signing_input + "." + _b64(
        holder_key.sign(signing_input.encode("ascii"))), issuer_key


SD_JWT_PRESENTATION, _ = _issued_sd_jwt()

_KB_INSTANT = {
    "inside": KB_NOW,
    "late": KB_NOW + timedelta(seconds=KB_MAX_AGE + KB_LEEWAY) + timedelta(minutes=15),
    "early": KB_NOW - timedelta(seconds=KB_LEEWAY) - timedelta(minutes=15),
}
_KB_VERDICT = {
    "inside": None,
    "late": (ClaimsInvalid, "too old"),
    "early": (ClaimsInvalid, "KB-JWT iat is in the future"),
}


@pytest.mark.parametrize("make", _PINS)
@pytest.mark.parametrize("when", _WHEN)
def test_verify_vp_token_judges_the_kb_jwt_window_at_the_pins_own_instant(host, make, when):
    pin = make(_KB_INSTANT[when])
    dcql = {"credentials": [{"id": "pid", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": [VCT]}}]}

    def verify() -> Any:
        return verify_vp_token({"pid": [SD_JWT_PRESENTATION]}, dcql_query=dcql, nonce=NONCE,
                               client_id=AUD, now=pin)

    verdict = _KB_VERDICT[when]
    if verdict is None:
        (presented,) = verify().for_query("pid")
        assert presented.raw.key_bound is True
    else:
        _raises(verdict[0], verdict[1], verify)


# ---- x5c.validate_cert_chain ------------------------------------------------

def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _chain() -> tuple[x509.Certificate, x509.Certificate]:
    """(leaf valid 12:00Z-12:30Z on 2026-01-01, root valid 2020-2040)."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("root")).issuer_name(_name("root"))
        .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(root_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("leaf")).issuer_name(_name("root"))
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, 12, 0, tzinfo=UTC))
        .not_valid_after(datetime(2026, 1, 1, 12, 30, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256()))
    return leaf, root


LEAF, ROOT = _chain()


@pytest.mark.parametrize("make", _PINS)
@pytest.mark.parametrize("when", _WHEN)
def test_validate_cert_chain_judges_the_pin_at_its_own_instant(host, make, when):
    pin = make(window_instant(when))

    def validate() -> Any:
        return validate_cert_chain(LEAF, [], trust_anchors=[ROOT], now=pin)

    if when == "inside":
        assert validate() is None
    else:
        _raises(X5cError, "did not validate to a trust anchor", validate)
