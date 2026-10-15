"""
openvc.proof._verify_common — cross-suite verification policy checks shared by the
proof suites: the Data Integrity family (``eddsa-rdfc-2022`` and ``ecdsa-sd-2023``)
and, for JOSE header policy (``crit``), the JWS lanes.

Where each cryptosuite owns its signature maths, these checks are suite-agnostic —
a credential's validity window, the meaning of ``proofPurpose``, and the DID
verification-relationship binding do not depend on how the proof was signed. They
run **after** the signature verifies (the fields they read are integrity-protected
by that signature), except the key-selection binding, which necessarily precedes
crypto (you cannot verify without first choosing an authorized key), and the
VC-JWT NumericDate shape gate (:func:`check_numeric_dates`), which must run before
PyJWT reads those claims and can only reject.

The JOSE suites (VC-JWT, SD-JWT VC, VP-JWT) check the JWT ``exp``/``nbf``/``iat``
claims through :func:`check_jwt_temporal`, and the VC-JWT ``aud`` through
:func:`check_jwt_audience`. For a W3C VCDM payload they also enforce the validity
window (:func:`check_validity_window`) the Data Integrity suites use, so a credential
is held to the same temporal rules whichever way it is secured.

Every error here subclasses :class:`~openvc.proof.errors.ProofError`, so a caller
can catch the whole verification-failure family with one ``except``.
"""
from __future__ import annotations

import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import _json
from ..multibase import decode_multibase
from ..observability import logger, span
from .errors import (
    ClaimsInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    KeyResolutionError,
    MalformedTimestamp,
    MalformedToken,
    PresentationBindingError,
    ProofMalformed,
    ProofError,
    ProofPurposeMismatch,
    UnsupportedCryptosuite,
)


def reject_unknown_crit(header: dict[str, Any]) -> None:
    """RFC 7515 §4.1.11: a verifier MUST reject a JWS whose ``crit`` names an
    extension parameter it does not process. The JOSE lanes here process none,
    so a ``crit`` member — whatever its shape — fails closed with a typed
    :class:`~openvc.proof.errors.MalformedToken`, matching the stance the COSE
    (``openvc.cose``) and JWE (``openvc.jwe``) paths already take."""
    if "crit" in header:
        raise MalformedToken("JWS 'crit' extensions are not supported")


# The longest string an error message quotes in full; a longer one is cut, so an
# attacker-sized string never becomes an attacker-sized log line.
_SHOWN_MAX = 200


def safe_repr(value: Any) -> str:
    """*value* for an error message, when it is attacker-shaped JSON.

    Only a bounded scalar is shown as ``repr``: a ``str`` (cut past ``_SHOWN_MAX``
    characters), ``None``, a ``bool``, a ``float`` and a 64-bit ``int``. Anything else is
    named by its type. ``json.loads`` on Python 3.14 accepts an array nested deeply
    enough that ``repr()`` of it raises a bare ``RecursionError``, which would escape
    ``OpenvcError`` from the very ``raise`` meant to report the bad value. ``repr()`` of
    an int past the int-to-str digit limit raises ``ValueError`` the same way."""
    if isinstance(value, str):
        if len(value) <= _SHOWN_MAX:
            return repr(value)
        return f"{value[:_SHOWN_MAX]!r}... ({len(value)} chars)"
    if value is None or isinstance(value, (bool, float)):
        return repr(value)
    if isinstance(value, int) and value.bit_length() <= 64:
        return repr(value)
    return type(value).__name__


DEFAULT_LEEWAY_S = 60  # tolerance for clock skew, matching the JOSE suites

# How old an SD-JWT Key Binding JWT's `iat` may be (RFC 9901 §7.3, step 5.5: "within an
# acceptable window" — the size is verifier policy). A KB-JWT is minted when the holder
# submits the presentation, so minutes are generous; same budget as an OpenID4VCI key
# proof (`openvc.openid4vci.DEFAULT_PROOF_MAX_AGE_S`).
DEFAULT_KB_MAX_AGE_S = 300

# Fractional seconds in an XSD/ISO dateTime. Python's fromisoformat only accepted
# exactly 3 or 6 fractional digits before 3.11, so we normalise to microseconds
# (the date has no '.' and a numeric tz offset has none either, so this only ever
# matches the seconds fraction).
_FRACTION = re.compile(r"\.(\d+)")


# The policy-error classes now live in openvc.proof.errors (the canonical proof-error
# home); imported above and re-exported here (and by the suites) for back-compat.


def issuer_identifiers(issuer: Any) -> list[Any]:
    """Every identifier a credential's ``issuer`` carries: the value itself, or each
    of an object's ``id`` / ``@id`` that is present (``id`` aliases ``@id`` in JSON-LD).
    An object with neither identifies no one, like an absent ``issuer``: empty list.
    Shared by the JOSE reconciliation and the status-list issuer check, so both read an
    issuer the same way."""
    if isinstance(issuer, dict):
        return [issuer[key] for key in ("id", "@id") if key in issuer]
    return [issuer]


def _parse_ts(value: Any) -> datetime | None:
    """Parse an XSD/ISO-8601 dateTime into an aware UTC datetime, or None if the
    value is absent or unparseable. Normalises the two forms Python's pre-3.11
    ``fromisoformat`` rejects but XSD allows — a trailing ``Z`` and non-3/6-digit
    fractional seconds — so a validity bound is not silently dropped on 3.10/3.11
    (that would be a fail-open expiry bypass). A naive result is assumed UTC."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _bound(document: dict[str, Any], *keys: str) -> datetime | None:
    """The parsed timestamp for the first *keys* the document actually carries,
    honouring precedence (VCDM 2.0 field before its VCDM 1.1 equivalent). A field
    that is **present but unparseable** fails closed (``MalformedTimestamp``)
    rather than being ignored — otherwise an expired credential whose timestamp
    the parser cannot read would verify. An absent field is skipped."""
    for key in keys:
        raw = document.get(key)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        ts = _parse_ts(raw)
        if ts is None:
            raise MalformedTimestamp(f"{key} is not a valid dateTime: {safe_repr(raw)}")
        return ts
    return None


def check_validity_window(
    document: dict[str, Any],
    proof: dict[str, Any],
    *,
    now: datetime | None,
    leeway_s: int,
    check_temporal: bool = True,
) -> bool:
    """Enforce the credential's validity window and the proof's own expiry.

    Honours both VCDM 2.0 (``validFrom`` / ``validUntil``) and VCDM 1.1
    (``issuanceDate`` / ``expirationDate``), plus the Data Integrity proof's
    optional ``expires``. *now* pins the evaluation instant (``None`` -> current
    UTC time); pinning it lets a conformance vector or an "as of" audit verify
    deterministically regardless of wall-clock. An absent bound is not a
    violation, but a present-but-unparseable one fails closed (see :func:`_bound`).

    *check_temporal* False skips only the two expiry checks; the return value says
    whether one of them would have failed (always False when they ran). Suites
    report it as their ``expired`` field, so a waived expiry is judged by the
    same code, clock and fields as an enforced one.
    """
    instant, leeway = utc_window(now, leeway_s)     # a bad pin is a typed ProofError
    # Compare differences, never `instant ± leeway`: a huge leeway would push that past
    # datetime's range (a bare OverflowError); two datetimes always subtract cleanly.

    not_before = _bound(document, "validFrom", "issuanceDate")
    if not_before is not None and not_before - instant > leeway:
        raise CredentialNotYetValid(
            f"credential is not valid before {not_before.isoformat()}")

    expired = False
    not_after = _bound(document, "validUntil", "expirationDate")
    if not_after is not None and instant - not_after > leeway:
        if check_temporal:
            raise CredentialExpired(f"credential expired at {not_after.isoformat()}")
        expired = True

    proof_expires = _bound(proof, "expires", "expirationDate")
    if proof_expires is not None and instant - proof_expires > leeway:
        if check_temporal:
            raise CredentialExpired(f"proof expired at {proof_expires.isoformat()}")
        expired = True
    return expired


def prepare_di_proof(
    secured: dict[str, Any], *, proof_type: str, cryptosuite: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Shared preamble for the whole-document Data Integrity suites (``eddsa-rdfc-2022``,
    ``ecdsa-rdfc-2019``, and the JCS suites): validate the proof object — a ``proof`` map of
    the expected ``type`` and ``cryptosuite`` carrying a **string** ``proofValue`` — and decode
    that multibase proofValue to a signature. Returns ``(proof, proof_config, signature)``,
    where ``proof_config`` is the proof minus ``proofValue`` with the document ``@context``
    grafted on (what the suites hash). The suites differ only in the canonicalization and the
    key algebra, not this block; single-sourcing it keeps the fail-closed guards (notably the
    string-``proofValue`` check) from drifting between them, byte-for-byte identical to before
    (the golden fixtures pin it)."""
    if _json.nesting_exceeds(secured):            # a dict handed over already parsed
        raise ProofMalformed(f"credential is nested deeper than {_json.MAX_DEPTH} levels")
    proof = secured.get("proof")
    if not isinstance(proof, dict):
        raise ProofMalformed("credential has no proof object")
    if proof.get("type") != proof_type:
        raise ProofMalformed(f"unexpected proof type {safe_repr(proof.get('type'))}")
    if proof.get("cryptosuite") != cryptosuite:
        raise UnsupportedCryptosuite(
            f"unsupported cryptosuite {safe_repr(proof.get('cryptosuite'))}")
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        raise ProofMalformed("proof has no proofValue")
    try:
        signature = decode_multibase(proof_value)
    except Exception as exc:
        raise ProofMalformed(f"invalid proofValue: {exc}") from exc
    proof_config = {k: v for k, v in proof.items() if k != "proofValue"}
    proof_config["@context"] = secured.get("@context")
    return proof, proof_config, signature


def is_numeric_date(value: Any) -> bool:
    """True when *value* is a JSON NumericDate openvc will compare against a clock: an
    ``int`` or ``float``, not a ``bool``, and finite.

    Two traps live here. ``json.loads`` accepts ``NaN``/``Infinity``, and every
    comparison against them is ``False`` — i.e. *never expires*, *never stale*. And it
    accepts arbitrarily large integers (``1`` followed by 400 zeros), which
    :func:`math.isfinite` casts to float and answers with a bare ``OverflowError`` —
    an untyped exception that escapes ``OpenvcError`` and aborts ``verify_many``. Such
    a bignum is read as *not finite*, the same reading the WRPRC parser makes
    (:mod:`openvc.rp_registration`), so it fails closed and typed.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:                   # an int no float can hold
        return False


def check_numeric_dates(
    claims: dict[str, Any], *names: str, subject: str = "token",
) -> None:
    """Reject each of *names* that is **present** in *claims* but not a NumericDate (per
    :func:`is_numeric_date`), raising a typed :class:`~openvc.proof.errors.ClaimsInvalid`.

    This checks shape only and compares nothing against a clock, so an expiry waiver
    cannot switch it off. Presence means the key exists: JSON ``null`` is rejected too,
    because RFC 7519 §2 defines a NumericDate as a JSON number. :func:`check_jwt_temporal`
    runs it first, so every lane that calls it shares the rule. The VC-JWT lane also runs it
    before PyJWT sees the token. PyJWT casts ``exp``/``nbf``/``iat`` with ``int()`` and
    catches only ``ValueError``, so a signed ``"nbf": null`` used to escape as a bare
    ``TypeError``. A string such as ``"1"`` or a bool cast silently instead of failing.
    """
    for name in names:
        if name in claims and not is_numeric_date(claims[name]):
            raise ClaimsInvalid(f"{subject} {name} must be a finite numeric timestamp")


def check_jwt_temporal(
    claims: dict[str, Any], *, leeway_s: int, subject: str = "token",
    now: float | None = None,
    check_temporal: bool = True,
) -> bool:
    """Enforce a JWT's ``exp``/``nbf``/``iat`` NumericDate claims, fail-closed.

    Single-sources the JOSE temporal rule for the SD-JWT VC issuer JWT and KB-JWT,
    VP-JWT, VC-JWT (ML-DSA), status-list token and OpenID4VCI key-proof paths so it
    cannot drift between them. The classic VC-JWT lane applies the same rules through
    PyJWT, behind the same shape gate (PyJWT truncates a fractional date to an ``int``,
    so a verdict can differ within one second of a boundary).

    * **Shape** (:func:`check_numeric_dates`): a present ``exp``/``nbf``/``iat`` that is
      ``null``, a bool, a string, a container, **non-finite** (``NaN``/``Infinity``,
      which ``json.loads`` accepts and which would make every comparison ``False``, i.e.
      *never expire*) or a bignum no float holds is rejected. Skipping it would be a
      fail-open expiry bypass.
    * ``exp``: at or past ``exp`` + *leeway_s* is ``has expired`` (RFC 7519 §4.1.4: the
      current time MUST be before it). This is the only comparison *check_temporal* (the
      expiry waiver) switches off: with it False, the return value says whether it would
      have failed (always False when it ran). See :func:`check_validity_window`.
    * ``nbf``: before it by more than *leeway_s* is ``is not yet valid``.
    * ``iat``: more than *leeway_s* in the future is ``iat is in the future``, the rule
      PyJWT applies on the classic VC-JWT lane. A token minted "later" than now is
      pre-dated, not expired, so the waiver leaves it on. ``iat`` stays optional here;
      no upper bound on its age (that is :func:`check_iat_freshness`, for proofs that
      exist to be fresh).

    *now* pins the instant (epoch seconds) for deterministic tests; ``None`` uses the
    current time, unrounded: truncating it would accept a token with a fractional ``exp``
    up to a second past its window. (A caller that pins *now* through :func:`utc_epoch`
    reads it to the second.) Every comparison is a difference against *leeway_s*, never
    ``current + leeway_s``: a huge leeway would overflow a float sum into a bare
    ``OverflowError`` and abort ``verify_many``.
    """
    check_numeric_dates(claims, "exp", "nbf", "iat", subject=subject)
    current: float = time.time() if now is None else now
    expired = False
    if "exp" in claims and current - claims["exp"] >= leeway_s:
        if check_temporal:
            raise ClaimsInvalid(f"{subject} has expired")
        expired = True
    if "nbf" in claims and claims["nbf"] - current > leeway_s:
        raise ClaimsInvalid(f"{subject} is not yet valid")
    if "iat" in claims and claims["iat"] - current > leeway_s:
        raise ClaimsInvalid(f"{subject} iat is in the future")
    return expired


def check_expected_audience(audience: Any) -> None:
    """Reject an expected *audience* that is not ``None`` or a non-empty string.

    PyJWT would also match a list of audiences, and an empty string would match an
    empty ``aud`` on the ML-DSA lane but not on PyJWT's. Both are a caller
    misconfiguration, refused up front rather than half-supported on one lane.
    """
    if audience is not None and (not isinstance(audience, str) or not audience):
        raise ClaimsInvalid(
            f"the expected audience must be a non-empty string or None, "
            f"not {safe_repr(audience)}")


def check_jwt_audience(
    claims: dict[str, Any], audience: str | None, *, subject: str = "token",
) -> None:
    """Enforce a JWT's ``aud`` claim per RFC 7519 §4.1.3, fail-closed.

    "If the principal processing the claim does not identify itself with a value in the
    ``aud`` claim when this claim is present, then the JWT MUST be rejected." The
    verifier identifies itself only through *audience*, so:

    * ``aud`` absent: accepted when *audience* is ``None``; rejected when the caller
      expects one (the token is not addressed to anyone, let alone to it).
    * ``aud`` present: it must be a string or an array of strings (``null``, a number
      or a mixed array is malformed), and *audience* must be one of them. With no
      *audience* the verifier cannot be one of them, so a token restricted to some
      other relying party is rejected rather than accepted by whoever holds it.

    *audience* itself must be ``None`` or a non-empty string
    (:func:`check_expected_audience`).

    Used by both VC-JWT lanes (ADR-0008). PyJWT, on the classic lane, applies the same
    rule by default; openvc used to pass ``verify_aud=False`` when no audience was given.
    """
    check_expected_audience(audience)
    if "aud" not in claims:
        if audience is not None:
            raise ClaimsInvalid(f"{subject} has no aud claim; expected {audience!r}")
        return
    aud = claims["aud"]
    auds = [aud] if isinstance(aud, str) else aud
    if not isinstance(auds, list) or not all(isinstance(a, str) for a in auds):
        raise ClaimsInvalid(f"{subject} aud must be a string or an array of strings")
    if audience is None:
        raise ClaimsInvalid(
            f"{subject} is restricted to an audience (aud) and no audience was given "
            f"to verify it against (RFC 7519 §4.1.3)")
    if audience not in auds:
        raise ClaimsInvalid(f"{subject} aud does not include {audience!r}")


def _plain_datetime(value: datetime) -> datetime:
    """The wall-clock fields and ``tzinfo`` of *value* as a plain ``datetime``, read
    through the base class: ``datetime.date`` and ``datetime.timetz`` called on the
    class, not on the object. A subclass that overrides ``utcoffset`` / ``astimezone`` /
    ``replace`` / ``timestamp`` / a field cannot change what is read, and none of its
    methods is called, so the reading is the one a plain ``datetime`` with the same fields
    and ``tzinfo`` would get. ``fold`` is kept."""
    return datetime.combine(datetime.date(value), datetime.timetz(value))


def utc_epoch(
    now: Any, *, error: type[Exception] = ProofError, name: str = "now",
) -> int:
    """*now* as integer epoch seconds, read the way every openvc clock check reads it:
    ``None`` is the current time, and a **naive** datetime is UTC — never the host's
    local zone. :func:`utc_instant` is the same reading for the checks that compare
    datetimes; reading a naive pin as local time would shift a freshness window by the
    host's UTC offset (up to 14 h), and in both directions at once: stale accepted,
    fresh refused.

    "Naive" is Python's own definition, ``utcoffset() is None`` — which also covers a
    ``tzinfo`` that answers ``None``. Anything that is not a ``datetime``, or whose
    ``tzinfo`` raises, becomes *error*: typed, so a misconfigured pin cannot escape
    ``verify_many`` as a bare exception.

    The value is read from its fields and ``tzinfo`` through the base class, so a
    ``datetime`` **subclass** is read as the plain ``datetime`` it holds: its own
    ``utcoffset()``, ``timestamp()``, ``replace()`` and ``astimezone()`` are never called,
    and cannot move the pin (a naive subclass whose ``utcoffset()`` said ``timedelta(0)``
    was read in the host's local zone). Only the ``tzinfo`` the caller attached is asked.

    *name* is how the messages call the value (default ``"now"``): a caller that reads
    some other datetime the same way, such as an issuer-side ``valid_from``, passes its
    own parameter name so the error points at it.
    """
    if now is None:
        return int(time.time())
    if not isinstance(now, datetime):
        raise error(f"{name} must be a datetime or None, not {type(now).__name__}")
    try:
        plain = _plain_datetime(now)
        if plain.utcoffset() is None:
            plain = plain.replace(tzinfo=timezone.utc)
        return int(plain.timestamp())
    except Exception as exc:                  # a caller's tzinfo may raise anything
        raise error(f"{name} cannot be read as an instant: {exc}") from exc


def utc_instant(
    now: Any, *, error: type[Exception] = ProofError, name: str = "now",
) -> datetime:
    """*now* as an aware UTC ``datetime``: :func:`utc_epoch`'s reading for the checks
    that compare datetimes (a Data Integrity validity window, an X.509 path-validation
    time, an mdoc ``validityInfo``, a WRPRC window). ``None`` is the current time and a
    naive datetime is UTC.

    Anything that is not a ``datetime`` (an epoch ``int``, an ISO string), whose
    ``tzinfo`` raises, or that has no UTC equivalent (``datetime.max`` at a negative
    offset overflows) becomes *error* — not a bare ``AttributeError`` /
    ``OverflowError`` that would abort ``verify_many`` instead of failing one item.
    The result is a plain ``datetime`` in ``timezone.utc``, so no caller subclass or
    ``tzinfo`` is consulted again by the comparisons downstream.

    The value is read from its fields and ``tzinfo`` through the base class, as in
    :func:`utc_epoch`: a ``datetime`` **subclass** is read as the plain ``datetime`` it
    holds, and none of its methods is called, so one that lies about ``utcoffset()`` or
    ``astimezone()`` cannot change the instant (it used to be read in the host's local
    zone, or refused). Only the ``tzinfo`` the caller attached is asked.

    *name* is how the messages call the value (default ``"now"``), as in
    :func:`utc_epoch`.
    """
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime):
        raise error(f"{name} must be a datetime or None, not {type(now).__name__}")
    try:
        plain = _plain_datetime(now)
        aware = (plain.replace(tzinfo=timezone.utc) if plain.utcoffset() is None
                 else plain.astimezone(timezone.utc))
        return datetime(aware.year, aware.month, aware.day, aware.hour, aware.minute,
                        aware.second, aware.microsecond, tzinfo=timezone.utc)
    except Exception as exc:                  # a caller's tzinfo may raise anything
        raise error(f"{name} cannot be read as an instant: {exc}") from exc


def utc_window(
    now: Any, leeway_s: Any, *, error: type[Exception] = ProofError,
) -> tuple[datetime, timedelta]:
    """``(instant, leeway)`` for a validity window evaluated at *now*: the instant from
    :func:`utc_instant`, and the leeway as a ``timedelta``. A negative or ``NaN`` leeway
    counts as 0, and one wider than ``timedelta`` holds is ``timedelta.max``.

    Compare *differences* against the leeway (``instant - not_after > leeway``), never
    ``instant ± leeway``: that leaves datetime's range for a *now* near
    ``datetime.max`` / ``datetime.min`` or a huge leeway, while two datetimes always
    subtract cleanly. A leeway that is not a number becomes *error* here, not a bare
    ``TypeError`` mid-check.
    """
    instant = utc_instant(now, error=error)
    try:
        leeway = timedelta(seconds=max(0, leeway_s))
    except OverflowError:               # wider than timedelta holds: the widest one, not a
        leeway = timedelta.max          # bare error that would abort verify_many
    except (TypeError, ValueError) as exc:
        raise error(f"leeway_s must be a number of seconds, not "
                    f"{type(leeway_s).__name__}") from exc
    return instant, leeway


def non_negative_seconds(value: Any, *, name: str, error: type[Exception] = ProofError) -> int:
    """Validate a duration knob — a leeway, a maximum age — as a non-negative ``int``
    of seconds (not a ``bool``). A ``NaN``/``Infinity`` leeway would make every window
    comparison ``False``, i.e. switch the window off, and ``None`` or a string would
    surface mid-verification as a bare ``TypeError``."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise error(f"{name} must be a non-negative int (seconds), got {value!r}")
    return value


def check_iat_freshness(
    iat: Any, *, max_age_s: int, leeway_s: int, current: float, subject: str,
) -> int:
    """Require a holder-minted proof's ``iat`` and bound it in **both** directions;
    return it as an ``int``.

    Single-sources the freshness rule for the OpenID4VCI key proof and the SD-JWT Key
    Binding JWT (RFC 9901 §4.3 makes its ``iat`` REQUIRED; §7.3 step 5.5 bounds it).
    :func:`check_jwt_temporal` bounds ``iat`` only from the future and accepts a token
    without one, but these proofs exist to be fresh and are not required to carry
    ``exp``.

    Stale means older than *max_age_s* + *leeway_s* at *current* (epoch seconds). The
    future-dated direction is the one implementations forget: without it a holder
    signs once with ``iat = now + 10y`` and holds a proof that never goes stale.
    """
    if iat is None:
        raise ClaimsInvalid(f"{subject} is missing the required iat")
    if not is_numeric_date(iat):
        raise ClaimsInvalid(f"{subject} iat must be a finite numeric timestamp")
    if current - iat > max_age_s + leeway_s:
        raise ClaimsInvalid(f"{subject} is too old")
    if iat - current > leeway_s:
        raise ClaimsInvalid(f"{subject} iat is in the future")
    return int(iat)


def check_proof_purpose(proof: dict[str, Any], expected: str | None) -> None:
    """Require the proof's declared ``proofPurpose`` to equal *expected*. A DI
    proof MUST declare a purpose, so a missing one fails too. *expected* of
    ``None`` disables the check (caller opts out explicitly)."""
    if expected is None:
        return
    actual = proof.get("proofPurpose")
    if actual != expected:
        raise ProofPurposeMismatch(
            f"proofPurpose {safe_repr(actual)} != expected {expected!r}")


def check_presentation_binding(
    proof: dict[str, Any], *,
    expected_challenge: str | None,
    expected_domain: str | None,
) -> None:
    """For an ``authentication`` (presentation) proof, bind it to this session and
    audience: the proof's ``challenge`` must equal *expected_challenge* and its
    ``domain`` must include *expected_domain* (anti-replay). Both are integrity-
    protected (part of the signed proof config). ``domain`` may be a string or a
    list; ``None`` on either expectation skips that check."""
    if expected_challenge is not None and proof.get("challenge") != expected_challenge:
        raise PresentationBindingError(
            f"proof challenge {safe_repr(proof.get('challenge'))} != expected "
            f"{expected_challenge!r}")
    if expected_domain is not None:
        domain = proof.get("domain")
        ok = domain == expected_domain or (
            isinstance(domain, list) and expected_domain in domain)
        if not ok:
            raise PresentationBindingError(
                f"proof domain {safe_repr(domain)} does not include expected "
                f"{expected_domain!r}")


def resolve_verification_key(
    verification_method: Any,
    *,
    proof_purpose: str | None,
    resolver: Any = None,
) -> dict[str, Any]:
    """Resolve the public JWK for *verification_method*, enforcing the DID
    verification-relationship binding for *proof_purpose*.

    Uses *resolver* (a ``DidResolver`` or ``DidResolverRegistry``) when it handles
    the DID, otherwise falls back to offline ``did:key``. The method is selected by
    its exact absolute ``id`` (``DidDocument.key_for_purpose``); none, or two with
    that ``id``, is a :class:`KeyResolutionError`. When the resolved DID
    document declares the relationship named by *proof_purpose*
    (``assertionMethod`` / ``authentication`` / ...), one of its references must
    resolve to that same ``id`` — a document that separates an assertion key from an
    authentication key then rejects a proof signed by the wrong one with
    :class:`ProofPurposeMismatch`. When the document does not
    declare that relationship at all (a minimal ``did:web`` that only lists
    ``verificationMethod``), the binding cannot be enforced and the key is
    accepted; the ``proofPurpose`` string is still checked separately. A resolver that
    returns its own document type instead of a ``DidDocument`` is used through its
    ``key_for_purpose``, and a refusal is classified by its ``key_by_kid``: no method
    is a :class:`KeyResolutionError`, else :class:`ProofPurposeMismatch`.
    """
    if not isinstance(verification_method, str) or not verification_method:
        raise KeyResolutionError("proof has no verificationMethod to resolve")
    if proof_purpose is not None and not isinstance(proof_purpose, str):
        # read from the proof before its signature is checked: an array/object is
        # unhashable in the relationship lookup and would raise a bare TypeError.
        # Checked before resolving, so a junk purpose never triggers a DID fetch.
        raise ProofMalformed(
            f"proofPurpose must be a string, not {type(proof_purpose).__name__}")

    from ..did.base import DidDocument, DidResolutionError, UnsupportedDidMethod

    did = verification_method.split("#", 1)[0]
    logger.debug("resolve verification method: %s", did)
    doc = None
    with span("openvc.resolve", did=did):
        if resolver is not None:
            supports = getattr(resolver, "supports", None)
            if supports is None or supports(did):
                try:
                    doc = resolver.resolve(did)
                except UnsupportedDidMethod:
                    doc = None
                except DidResolutionError as exc:
                    raise KeyResolutionError(f"could not resolve {did!r}: {exc}") from exc
        if doc is None:
            if not did.startswith("did:key:"):
                raise KeyResolutionError(
                    f"cannot resolve {verification_method!r} offline "
                    f"(pass a resolver, or an injected public_key_jwk)")
            from ..did.did_key import DidKeyResolver
            doc = DidKeyResolver().resolve(did)

    purpose = proof_purpose or "assertionMethod"
    vm = doc.key_for_purpose(verification_method, purpose)
    if vm is None:
        if not isinstance(doc, DidDocument):
            # a resolver's own document type: only its key_for_purpose / key_by_kid
            # are known to exist, so classify the refusal by key_by_kid
            if doc.key_by_kid(verification_method) is None:
                raise KeyResolutionError(
                    f"verificationMethod {safe_repr(verification_method)} not in the "
                    f"DID document")
            raise ProofPurposeMismatch(
                f"verificationMethod {safe_repr(verification_method)} is not authorized "
                f"for proofPurpose {purpose!r}")
        # the same strict, exact-id selection key_for_purpose made (never the JOSE
        # lanes' fragment-tolerant key_by_kid): a method it did not select is a key
        # resolution failure, not a purpose mismatch
        matches = doc._methods_with_id(verification_method, doc._base())
        if not matches:
            raise KeyResolutionError(
                f"verificationMethod {verification_method!r} not in the DID document")
        if len(matches) > 1:
            raise KeyResolutionError(
                f"verificationMethod {safe_repr(verification_method)} names "
                f"{len(matches)} methods in the DID document")
        raise ProofPurposeMismatch(
            f"verificationMethod {verification_method!r} is not authorized for "
            f"proofPurpose {purpose!r}")
    return vm.public_key_jwk


# JOSE alg -> (JWK kty, JWK crv, hashData digest) for the Data Integrity suites that pick
# their signature algorithm from the *resolved key's* curve rather than from anything in
# the proof. ecdsa-*-2019 is curve-dependent (P-256/SHA-256, P-384/SHA-384 —
# vc-di-ecdsa §3.x); eddsa-* is always SHA-256. Single-sourced here so the curve->digest
# rule cannot drift between the JCS (di_jcs) and RDF (di_ecdsa_rdfc) ECDSA suites.
ALG_PROFILE: dict[str, tuple[str, str, str]] = {
    "EdDSA": ("OKP", "Ed25519", "sha256"),
    "ES256": ("EC", "P-256", "sha256"),
    "ES384": ("EC", "P-384", "sha384"),
}


def match_alg(jwk: dict[str, Any], allowed_algs: frozenset[str], *, cryptosuite: str) -> str:
    """The *allowed_algs* member whose (kty, crv) matches *jwk*, or fail closed.

    Selecting the alg — and thus the hashData digest — from the resolved key's own
    (kty, crv), never from an attacker-controlled proof field, is what lets a suite reject
    a cross-type key (e.g. an Ed25519 OKP key resolved under an ECDSA suite) *before* the
    signature check would read a missing JWK member ('y' on an OKP key) and crash past the
    ProofError contract. The accepted curves are disjoint on ``crv``, so at most one alg
    matches. Shared by the whole-document suites (di_jcs, di_ecdsa_rdfc)."""
    kty, crv = jwk.get("kty"), jwk.get("crv")
    for alg in sorted(allowed_algs):
        p_kty, p_crv, _ = ALG_PROFILE[alg]
        if kty == p_kty and crv == p_crv:
            return alg
    raise ProofMalformed(
        f"{cryptosuite} does not accept a kty={safe_repr(kty)} crv={safe_repr(crv)} key")


__all__ = [
    "ALG_PROFILE",
    "CredentialExpired",
    "CredentialNotYetValid",
    "DEFAULT_KB_MAX_AGE_S",
    "DEFAULT_LEEWAY_S",
    "KeyResolutionError",
    "MalformedTimestamp",
    "PresentationBindingError",
    "ProofPurposeMismatch",
    "check_iat_freshness",
    "check_expected_audience",
    "check_jwt_audience",
    "check_jwt_temporal",
    "check_numeric_dates",
    "check_presentation_binding",
    "check_proof_purpose",
    "check_validity_window",
    "prepare_di_proof",
    "is_numeric_date",
    "match_alg",
    "non_negative_seconds",
    "reject_unknown_crit",
    "resolve_verification_key",
    "safe_repr",
    "utc_epoch",
    "utc_instant",
    "utc_window",
]
