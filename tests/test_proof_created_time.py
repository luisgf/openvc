"""
tests/test_proof_created_time.py — the Data Integrity issuers read ``created`` the one way
openvc reads a time, and type what they cannot read (#287).

``created=`` was rendered by a private ``_iso`` that called ``astimezone`` — which reads a
NAIVE ``datetime`` as the HOST's local time — while ``utc_instant`` / ``utc_epoch`` (#187,
#218, #255) read it as UTC::

    created=datetime(2026, 1, 1, 12, 0)  ->  12:00:00Z  under TZ=UTC
                                              03:00:00Z  under TZ=Asia/Tokyo
                                              17:00:00Z  under TZ=America/New_York
    created="2026-01-01T00:00:00Z"       ->  bare AttributeError
    created=datetime(1, 1, 1, tzinfo=+01:00)  ->  bare OverflowError
    created=datetime.min                 ->  bare ValueError

on all five issuer entry points (``eddsa-rdfc-2022``, ``ecdsa-rdfc-2019``,
``eddsa-jcs-2022``, ``ecdsa-jcs-2019``, ``ecdsa-sd-2023``). The signed value cannot be
repaired afterwards (``created`` is covered by the signature), and the deterministic
suites signed different bytes per host zone. ``created`` now goes through
``utc_instant`` (a naive value is UTC, one with no UTC form is refused) and is written by
``isoformat``; a value that is not a usable ``datetime`` is ``ProofMalformed`` before
anything is canonicalized or signed.

Every refusal is asserted against the EXACT class ``ProofMalformed`` (never
``AttributeError`` / ``OverflowError`` / ``ValueError`` / ``RuntimeError``), and the
negatives sign with a key whose ``sign`` raises, which proves the error comes BEFORE the
signature. The zone tests pin the host's zone through ``TZ`` + ``tzset`` and are skipped
where that is not possible; one of them proves the zone took effect, so they cannot pass
vacuously. Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone, tzinfo
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from hypothesis import given, settings
from hypothesis import strategies as st

pytest.importorskip("pyld")              # three of the five suites canonicalize with pyld

from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import ProofError, ProofMalformed, UnsupportedCryptosuite  # noqa: E402

UTC = timezone.utc
V2 = "https://www.w3.org/ns/credentials/v2"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
PLUS_ONE = timezone(timedelta(hours=1))
PLUS_NINE = timezone(timedelta(hours=9))
MINUS_FIVE = timezone(timedelta(hours=-5))
NAN = float("nan")
INF = float("inf")


# --------------------------------------------------------------------------- #
# Keys, did:keys and the five entry points
# --------------------------------------------------------------------------- #

_ED_PRIVATE = ed25519.Ed25519PrivateKey.generate()
_ED_RAW = base64.urlsafe_b64decode(
    Ed25519SigningKey(_ED_PRIVATE, kid="tmp").public_jwk()["x"] + "==")
ED_DID = "did:key:" + encode_multibase(bytes((0xED, 0x01)) + _ED_RAW)
ED_VM = f"{ED_DID}#{ED_DID[len('did:key:'):]}"
ED = Ed25519SigningKey(_ED_PRIVATE, kid=ED_VM)

_P256_PRIVATE = ec.generate_private_key(ec.SECP256R1())
_P256_RAW = P256SigningKey(_P256_PRIVATE, kid="tmp").public_key_raw()
P256_DID = "did:key:" + encode_multibase(bytes((0x80, 0x24)) + _P256_RAW)
P256_VM = f"{P256_DID}#{P256_DID[len('did:key:'):]}"
P256 = P256SigningKey(_P256_PRIVATE, kid=P256_VM)


def credential(issuer: str) -> dict[str, Any]:
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer,
            "credentialSubject": {"id": "did:example:alice"}}


@dataclass(frozen=True)
class Entry:
    name: str
    key: Any
    vm: str
    did: str
    add: Callable[..., dict[str, Any]]            # (doc, key, created) -> secured
    check: Callable[[dict[str, Any]], Any]        # secured -> verification (at NOW)

    def issue(self, created: Any, *, doc: dict[str, Any] | None = None,
              key: Any = None) -> dict[str, Any]:
        return self.add(doc if doc is not None else credential(self.did),
                        key if key is not None else self.key, created)

    def created(self, created: Any) -> str:
        return str(self.issue(created)["proof"]["created"])

    def round_trip(self, created: Any) -> str:
        secured = self.issue(created)
        self.check(secured)
        return str(secured["proof"]["created"])


def _add_eddsa_rdfc(doc: dict[str, Any], key: Any, created: Any) -> dict[str, Any]:
    return DataIntegrityProofSuite().add_proof(
        doc, signing_key=key, verification_method=ED_VM, created=created)


def _add_ecdsa_rdfc(doc: dict[str, Any], key: Any, created: Any) -> dict[str, Any]:
    return EcdsaRdfcProofSuite().add_proof(
        doc, signing_key=key, verification_method=P256_VM, created=created)


def _add_eddsa_jcs(doc: dict[str, Any], key: Any, created: Any) -> dict[str, Any]:
    return EddsaJcsProofSuite().add_proof(
        doc, signing_key=key, verification_method=ED_VM, created=created)


def _add_ecdsa_jcs(doc: dict[str, Any], key: Any, created: Any) -> dict[str, Any]:
    return EcdsaJcsProofSuite().add_proof(
        doc, signing_key=key, verification_method=P256_VM, created=created)


def _add_ecdsa_sd(doc: dict[str, Any], key: Any, created: Any) -> dict[str, Any]:
    return EcdsaSdProofSuite().add_base_proof(
        doc, signing_key=key, verification_method=P256_VM,
        mandatory_pointers=["/issuer"], created=created)


def _check_ecdsa_sd(base: dict[str, Any]) -> Any:
    suite = EcdsaSdProofSuite()
    derived = suite.derive_proof(base, selective_pointers=[])
    assert derived["proof"]["created"] == base["proof"]["created"]   # carried verbatim
    return suite.verify(derived, now=NOW)


ENTRIES = [
    Entry("eddsa-rdfc-2022", ED, ED_VM, ED_DID, _add_eddsa_rdfc,
          lambda s: DataIntegrityProofSuite().verify(s, now=NOW)),
    Entry("ecdsa-rdfc-2019", P256, P256_VM, P256_DID, _add_ecdsa_rdfc,
          lambda s: EcdsaRdfcProofSuite().verify(s, now=NOW)),
    Entry("eddsa-jcs-2022", ED, ED_VM, ED_DID, _add_eddsa_jcs,
          lambda s: EddsaJcsProofSuite().verify(s, now=NOW)),
    Entry("ecdsa-jcs-2019", P256, P256_VM, P256_DID, _add_ecdsa_jcs,
          lambda s: EcdsaJcsProofSuite().verify(s, now=NOW)),
    Entry("ecdsa-sd-2023", P256, P256_VM, P256_DID, _add_ecdsa_sd, _check_ecdsa_sd),
]
SUITES = [pytest.param(entry, id=entry.name) for entry in ENTRIES]
DETERMINISTIC = [pytest.param(entry, id=entry.name)
                 for entry in ENTRIES if entry.name.startswith("eddsa-")]


class _NeverSigns:
    """A signing key whose ``sign`` must not be reached: a refusal has to come first."""

    def __init__(self, alg: str) -> None:
        self.alg = alg

    def sign(self, signing_input: bytes) -> bytes:
        raise AssertionError("created was accepted: the key was asked to sign")


def refuses(entry: Entry, created: Any, message: str) -> None:
    """*entry* refuses *created* as EXACTLY ProofMalformed with *message*, before it signs."""
    with pytest.raises(Exception) as caught:
        entry.issue(created, key=_NeverSigns(entry.key.alg))
    exc = caught.value
    assert type(exc) is ProofMalformed, f"{type(exc).__module__}.{type(exc).__name__}: {exc}"
    assert re.search(message, str(exc)), str(exc)


def instant(text: str) -> datetime:
    assert text.endswith("Z")
    return datetime.fromisoformat(text[:-1] + "+00:00")


# --------------------------------------------------------------------------- #
# 1. A created that is not a datetime
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value, typename", [
    pytest.param("2026-01-01T00:00:00Z", "str", id="iso-string"),
    pytest.param("soon", "str", id="word"),
    pytest.param(1767225600, "int", id="epoch-int"),
    pytest.param(1767225600.0, "float", id="epoch-float"),
    pytest.param(NAN, "float", id="nan"),
    pytest.param(INF, "float", id="inf"),
    pytest.param(True, "bool", id="bool"),
    pytest.param(date(2026, 1, 1), "date", id="date"),
    pytest.param(timedelta(days=1), "timedelta", id="timedelta"),
    pytest.param([], "list", id="list"),
    pytest.param(b"x", "bytes", id="bytes"),
])
@pytest.mark.parametrize("entry", SUITES)
def test_a_created_that_is_not_a_datetime_is_proof_malformed(entry, value, typename):
    refuses(entry, value, rf"^created must be a datetime or None, not {typename}$")


# --------------------------------------------------------------------------- #
# 2. A datetime with no UTC reading
# --------------------------------------------------------------------------- #

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


@pytest.mark.parametrize("value", [
    pytest.param(datetime(1, 1, 1, tzinfo=PLUS_ONE), id="year-1-at-plus-1"),
    pytest.param(datetime(9999, 12, 31, 23, tzinfo=MINUS_FIVE), id="year-9999-at-minus-5"),
    pytest.param(datetime(2026, 1, 1, tzinfo=_RaisingTz()), id="tzinfo-raises"),
])
@pytest.mark.parametrize("entry", SUITES)
def test_a_datetime_with_no_utc_reading_is_proof_malformed(entry, value):
    refuses(entry, value, r"^created cannot be read as an instant: ")


@pytest.mark.parametrize("entry", SUITES)
def test_the_refusal_comes_after_the_alg_context_and_proof_checks(entry):
    # "Raise where _iso runs today": a wrong key, a missing @context and an existing
    # proof keep their own errors, whatever created holds
    other = P256 if entry.key is ED else ED
    with pytest.raises(UnsupportedCryptosuite):
        entry.issue("soon", key=other)
    with pytest.raises(ProofMalformed, match="has no @context") as caught:
        entry.issue("soon", doc={"type": ["VerifiableCredential"], "issuer": entry.did})
    assert type(caught.value) is ProofMalformed
    with pytest.raises(ProofMalformed, match="already carries a proof") as caught:
        entry.issue("soon", doc=entry.issue(NOW))
    assert type(caught.value) is ProofMalformed


@pytest.mark.parametrize("entry", SUITES)
def test_the_error_is_in_the_proof_family(entry):
    with pytest.raises(ProofError):
        entry.issue("soon")


# --------------------------------------------------------------------------- #
# 3. A naive datetime is UTC, whatever the host's zone
# --------------------------------------------------------------------------- #

NAIVE_WINTER = datetime(2026, 1, 1, 12, 0)
NAIVE_SUMMER = datetime(2026, 7, 1, 12, 0)

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


_NAIVE_CASES = [
    pytest.param(NAIVE_WINTER, "2026-01-01T12:00:00Z", id="winter"),
    pytest.param(NAIVE_SUMMER, "2026-07-01T12:00:00Z", id="summer-dst"),
    pytest.param(datetime.min, "0001-01-01T00:00:00Z", id="datetime-min"),
    pytest.param(datetime.max, "9999-12-31T23:59:59Z", id="datetime-max"),
    pytest.param(datetime(2026, 1, 1, 12, 0, tzinfo=_NoOffsetTz()), "2026-01-01T12:00:00Z",
                 id="tzinfo-with-no-offset"),
]


@needs_tzset
@pytest.mark.parametrize("entry", SUITES)
@pytest.mark.parametrize("naive, expected", _NAIVE_CASES)
@pytest.mark.parametrize("spec, offset", _HOST_ZONES)
def test_a_naive_datetime_is_its_utc_reading_on_any_host(
        host_zone, spec, offset, naive, expected, entry):
    host_zone(spec, offset)
    assert entry.created(naive) == expected


@needs_tzset
def test_the_pin_takes_effect_so_the_zone_tests_cannot_pass_vacuously(host_zone):
    # if TZ were ignored, "equals the UTC reading" would hold for any implementation
    host_zone("JST-9", timedelta(hours=9))
    assert datetime(2026, 1, 1, 12).astimezone(UTC).hour == 3          # the host-local reading
    assert ENTRIES[0].created(NAIVE_WINTER) == "2026-01-01T12:00:00Z"


@needs_tzset
@pytest.mark.parametrize("entry", DETERMINISTIC)
@pytest.mark.parametrize("spec, offset", _HOST_ZONES)
def test_the_signed_bytes_do_not_depend_on_the_host_zone(host_zone, spec, offset, entry):
    # Ed25519 is deterministic: one call, one proofValue, whatever the zone
    host_zone("UTC", timedelta(0))
    baseline = entry.issue(NAIVE_WINTER)["proof"]
    host_zone(spec, offset)
    got = entry.issue(NAIVE_WINTER)["proof"]
    assert got["created"] == "2026-01-01T12:00:00Z"
    assert got["proofValue"] == baseline["proofValue"], "the host's zone leaked into the bytes"


@needs_tzset
@pytest.mark.parametrize("entry", SUITES)
@pytest.mark.parametrize("spec, offset", _HOST_ZONES)
def test_an_aware_datetime_does_not_depend_on_the_host_zone(host_zone, spec, offset, entry):
    host_zone(spec, offset)
    assert entry.created(datetime(2026, 1, 1, 21, 0, tzinfo=PLUS_NINE)) == "2026-01-01T12:00:00Z"


# --------------------------------------------------------------------------- #
# 4. Round trips: sign, verify, read the instant back
# --------------------------------------------------------------------------- #

_ROUND_TRIPS = [
    pytest.param(NAIVE_WINTER, NOW, id="naive"),
    pytest.param(NOW, NOW, id="aware-utc"),
    pytest.param(datetime(2026, 1, 1, 21, 0, tzinfo=PLUS_NINE), NOW, id="aware-plus-9"),
    pytest.param(datetime(1, 1, 1, tzinfo=UTC), datetime(1, 1, 1, tzinfo=UTC), id="year-1"),
    pytest.param(datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
                 datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), id="year-9999"),
    # no openvc verifier reads created back: a proof dated in 2999 verifies today
    pytest.param(datetime(2999, 1, 1, tzinfo=UTC), datetime(2999, 1, 1, tzinfo=UTC),
                 id="year-2999"),
]


@pytest.mark.parametrize("entry", SUITES)
@pytest.mark.parametrize("created, expected", _ROUND_TRIPS)
def test_sign_verify_and_read_back_the_instant_that_was_passed(entry, created, expected):
    assert instant(entry.round_trip(created)) == expected


# --------------------------------------------------------------------------- #
# 5. Controls: what rendered correctly before still renders byte for byte
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("entry", SUITES)
def test_an_aware_utc_created_is_rendered_byte_for_byte(entry):
    assert entry.created(datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)) == "2026-01-01T12:00:00Z"


@pytest.mark.parametrize("entry", SUITES)
def test_microseconds_are_truncated_not_rounded(entry):
    assert entry.created(datetime(2026, 1, 1, 12, 0, 0, 999999, tzinfo=UTC)) \
        == "2026-01-01T12:00:00Z"
    assert entry.created(datetime(2026, 1, 1, 12, 0, 59, 500000, tzinfo=UTC)) \
        == "2026-01-01T12:00:59Z"


@pytest.mark.parametrize("entry", SUITES)
def test_a_year_below_1000_is_padded_on_every_platform(entry):
    # strftime("%Y") does not pad on glibc (the #218 CI failure on Linux 3.10-3.13)
    assert entry.created(datetime(999, 1, 1, tzinfo=UTC)) == "0999-01-01T00:00:00Z"


@pytest.mark.parametrize("entry", SUITES)
def test_no_created_is_the_current_utc_time(entry):
    before = datetime.now(UTC).replace(microsecond=0)
    text = entry.created(None)
    after = datetime.now(UTC)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", text), text
    assert before <= instant(text) <= after


class _Liar(datetime):
    """A caller's ``datetime`` that answers its renderers with something else."""

    def strftime(self, fmt: str) -> str:
        return "not a date"

    def isoformat(self, sep: str = "T", timespec: str = "auto") -> str:
        return "not a date"


@pytest.mark.parametrize("entry", SUITES)
def test_a_datetime_subclass_cannot_choose_the_signed_string(entry):
    liar = _Liar(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert entry.created(liar) == "2026-01-01T12:00:00Z"


def test_utc_iso_is_exported_with_the_clock_helpers():
    import openvc.proof._verify_common as common
    from openvc.proof._verify_common import utc_iso
    assert "utc_iso" in common.__all__
    assert utc_iso(NAIVE_WINTER, error=ProofMalformed, name="created") == "2026-01-01T12:00:00Z"
    with pytest.raises(ProofMalformed, match=r"^when must be a datetime or None, not int$"):
        utc_iso(1, error=ProofMalformed, name="when")


# --------------------------------------------------------------------------- #
# 6. A differential property against the old rendering, for every aware datetime
# --------------------------------------------------------------------------- #

# Years 1001..9998 keep the UTC form inside 1000..9999 for any offset within +-14 h, where
# strftime("%Y") and isoformat() cannot disagree on any platform.
_OFFSETS = st.timedeltas(min_value=timedelta(hours=-14), max_value=timedelta(hours=14)).map(
    timezone)
_AWARE = st.datetimes(min_value=datetime(1001, 1, 1), max_value=datetime(9998, 12, 31),
                      timezones=_OFFSETS)


@settings(max_examples=300, deadline=None)
@given(moment=_AWARE)
def test_an_aware_created_matches_the_old_astimezone_rendering(moment):
    old = moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert ENTRIES[2].created(moment) == old
