"""
tests/test_trustlist_nextupdate_closed.py — a null or unparseable ``NextUpdate``
closes an ETSI TS 119 612 Trusted List (#389; #407 for the tz-naive form).

Clause 5.3.15: ``NextUpdate`` is the instant by which an update shall be issued
"or be null to indicate a closed TL", and a TL "with a Next update occurring in
the past shall be discarded as expired as a measure to reduce the risk of a
substitution by an attacker with an old TL". Clause 5.1.3: every TL date-time is
ISO 8601, **UTC**, second precision, with the ``Z`` designator — the shape the
LoTE lane's ``_DATETIME_Z`` pins; this lane tolerates a fraction and ``+00:00``.

The XML lane used to read a null ``NextUpdate`` — and any ``dateTime`` that
``fromisoformat`` rejected — as *unbounded* validity (anchors kept, no problem),
and let a tz-naive value escape ``walk_lotl`` as a bare ``TypeError``. Now, as
on the LoTE lane (``lote._staleness``): null ⇒ the list is **closed** — zero
anchors and an ``"expired"`` problem naming ``closed TL (null NextUpdate)``; any
value outside that shape — unparseable, naive, another offset or layout — ⇒
``TrustListParseError`` (a ``"parse"`` problem in the walk) — never ``None``, never
read as UTC; only UTC datetimes are ever compared, on every interpreter alike.

Fixtures: the synthetic ``tests/fixtures/trustlist/`` LOTL + DE TL (stub XML
signature verifier; the real XAdES check is the ``[trustlist]`` extra's) and, for
the goldens-unchanged pin, the recorded EU LOTL / ES TL. Self-contained (tests/
is not a package — no cross-import).
"""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone

import pytest

from openvc.trustlist import (
    TrustListParseError,
    consume_trust_list,
    parse_trust_list,
    walk_lotl,
)

_FIX = pathlib.Path(__file__).parent / "fixtures" / "trustlist"
LOTL = (_FIX / "eu-lotl.xml").read_bytes()
DE_TL = (_FIX / "de-tl.xml").read_bytes()

LOTL_URL = "https://ec.example/eu-lotl.xml"
DE_URL = "https://tl.example.de/de-tl.xml"

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)      # the fixtures' NextUpdate is 2099

FUTURE_Z = b"2099-01-01T00:00:00Z"
NEXT_UPDATE = b"<NextUpdate><dateTime>" + FUTURE_Z + b"</dateTime></NextUpdate>"

# Every spelling of "null": the element absent, present without <dateTime>, or with
# an empty / whitespace-only <dateTime> (clause 5.3.15 — a closed TL).
NULL_FORMS = {
    "self-closed element": b"<NextUpdate/>",
    "empty element": b"<NextUpdate></NextUpdate>",
    "empty dateTime": b"<NextUpdate><dateTime></dateTime></NextUpdate>",
    "whitespace dateTime": b"<NextUpdate><dateTime>  \n  </dateTime></NextUpdate>",
    "absent element": b"",
}

# Values outside clause 5.1.3's shape: unparseable, or parseable by `fromisoformat`
# but not the mandated layout — naive (never read as UTC), another offset, the basic
# format, another separator, no seconds — or a field out of range.
MALFORMED = {
    "garbage": b"not-a-date",
    "numeric": b"1767225600",
    "naive, in the past": b"2026-01-01T00:00:00",
    "naive, in the future": b"2099-01-01T00:00:00",
    "date only": b"2099-01-01",
    "Z not trailing": b"Z2099-01-01T00:00:00",
    "offset +01:00": b"2099-01-01T01:00:00+01:00",
    "offset +02:00": b"2099-01-01T02:00:00+02:00",
    "offset -05:00": b"2098-12-31T19:00:00-05:00",
    "offset +0000 (no colon)": b"2099-01-01T00:00:00+0000",
    "basic format": b"20990101T000000Z",
    "space separator": b"2099-01-01 00:00:00Z",
    "no seconds": b"2099-01-01T00:00Z",
    "lowercase z": b"2099-01-01T00:00:00z",
    "hour 24": b"2099-01-01T24:00:00Z",
    "30 February": b"2099-02-30T00:00:00Z",
}
OUT_OF_RANGE = {"hour 24", "30 February"}       # pass the shape, fail the calendar

# The mandated shape, with the two tolerances the lane allows: a fraction of a
# second (truncated past six digits) and `+00:00` as the offset spelling of UTC.
UTC_FUTURE = {
    "Z": (b"2099-01-01T00:00:00Z", datetime(2099, 1, 1, tzinfo=timezone.utc)),
    "+00:00": (b"2099-01-01T00:00:00+00:00", datetime(2099, 1, 1, tzinfo=timezone.utc)),
    "fraction .5Z": (b"2099-01-01T00:00:00.5Z",
                     datetime(2099, 1, 1, 0, 0, 0, 500000, tzinfo=timezone.utc)),
    "fraction .123456+00:00": (b"2099-01-01T00:00:00.123456+00:00",
                               datetime(2099, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)),
    "fraction .1234567Z": (b"2099-01-01T00:00:00.1234567Z",
                           datetime(2099, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)),
}

PAST_Z = b"2020-01-01T00:00:00Z"


def _with_next_update(doc: bytes, replacement: bytes) -> bytes:
    assert doc.count(NEXT_UPDATE) == 1
    return doc.replace(NEXT_UPDATE, replacement)


def _with_date(doc: bytes, value: bytes) -> bytes:
    return _with_next_update(doc, b"<NextUpdate><dateTime>" + value + b"</dateTime></NextUpdate>")


def _ok_sig(_xml, _certs):
    """A stub XML-signature verifier that accepts (the real one is the extra's job)."""
    return None


def _recording_fetch(store):
    fetched: list[str] = []

    def _fetch(url):
        fetched.append(url)
        if url not in store:
            raise KeyError(f"no such TL {url!r}")
        return store[url]
    return _fetch, fetched


def _walk(store):
    fetch, fetched = _recording_fetch(store)
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=fetch, now=NOW)
    return res, fetched


def test_fixtures_carry_the_single_line_next_update_the_tests_rewrite():
    # the mutations below are byte replacements of exactly this element
    assert LOTL.count(NEXT_UPDATE) == 1 and DE_TL.count(NEXT_UPDATE) == 1
    res, _ = _walk({LOTL_URL: LOTL, DE_URL: DE_TL})
    assert len(res.anchors) == 1 and res.problems == ()   # the baseline the positives keep


# --------------------------------------------------------------------------- #
# parse_trust_list: null stays None (the closed signal); anything else aware or refused
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("form", sorted(NULL_FORMS), ids=sorted(NULL_FORMS))
def test_parse_a_null_next_update_is_none(form):
    tl = parse_trust_list(_with_next_update(DE_TL, NULL_FORMS[form]))
    assert tl.next_update is None
    assert len(tl.providers) == 1                 # the rest of the list still parses


@pytest.mark.parametrize("form", sorted(MALFORMED), ids=sorted(MALFORMED))
def test_parse_refuses_a_next_update_outside_the_mandated_utc_shape(form):
    with pytest.raises(TrustListParseError, match="NextUpdate") as info:
        parse_trust_list(_with_date(DE_TL, MALFORMED[form]))
    assert "5.1.3" in str(info.value)            # the clause the refusal rests on
    if form not in OUT_OF_RANGE:                 # a shape failure names the mandated form
        assert "UTC" in str(info.value) and "YYYY-MM-DDThh:mm:ssZ" in str(info.value)


@pytest.mark.parametrize("form", sorted(UTC_FUTURE), ids=sorted(UTC_FUTURE))
def test_parse_keeps_a_utc_next_update_of_the_mandated_shape(form):
    value, expected = UTC_FUTURE[form]
    tl = parse_trust_list(_with_date(DE_TL, value))
    assert tl.next_update == expected
    assert tl.next_update.tzinfo is timezone.utc


def test_parse_message_for_a_huge_garbage_value_is_bounded():
    with pytest.raises(TrustListParseError) as info:
        parse_trust_list(_with_date(DE_TL, b"x" * 100_000))
    assert len(str(info.value)) < 600                 # safe_repr cuts the echoed value


# --------------------------------------------------------------------------- #
# consume_trust_list: authenticity + parse; freshness is the walk's (as consume_lote)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("form", sorted(NULL_FORMS), ids=sorted(NULL_FORMS))
def test_consume_returns_the_closed_signal_for_a_null_next_update(form):
    tl = consume_trust_list(_with_next_update(DE_TL, NULL_FORMS[form]),
                            verify_signature=_ok_sig, expected_signer_certs=["c"])
    assert tl.next_update is None


@pytest.mark.parametrize("form", sorted(MALFORMED), ids=sorted(MALFORMED))
def test_consume_refuses_an_unparseable_or_naive_next_update_after_the_signature(form):
    seen = []

    def _verify(xml, certs):
        seen.append(xml)

    with pytest.raises(TrustListParseError, match="NextUpdate"):
        consume_trust_list(_with_date(DE_TL, MALFORMED[form]),
                           verify_signature=_verify, expected_signer_certs=["c"])
    assert len(seen) == 1                           # verified first, then refused on parse


# --------------------------------------------------------------------------- #
# walk_lotl, national TL: closed / malformed / past contribute nothing, named
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("form", sorted(NULL_FORMS), ids=sorted(NULL_FORMS))
def test_walk_a_closed_national_tl_contributes_nothing(form):
    res, _ = _walk({LOTL_URL: LOTL, DE_URL: _with_next_update(DE_TL, NULL_FORMS[form])})
    assert res.anchors == ()
    assert len(res.problems) == 1
    problem = res.problems[0]
    assert problem.location == DE_URL and problem.stage == "expired"
    assert "closed TL (null NextUpdate)" in problem.detail
    assert "5.3.15" in problem.detail


@pytest.mark.parametrize("form", sorted(MALFORMED), ids=sorted(MALFORMED))
def test_walk_a_national_tl_with_an_unparseable_or_naive_next_update_contributes_nothing(form):
    res, _ = _walk({LOTL_URL: LOTL, DE_URL: _with_date(DE_TL, MALFORMED[form])})
    assert res.anchors == ()
    assert len(res.problems) == 1
    problem = res.problems[0]
    assert problem.location == DE_URL and problem.stage == "parse"
    assert "NextUpdate" in problem.detail


def test_walk_a_naive_next_update_is_a_problem_not_a_type_error():
    # #407: the naive value used to escape walk_lotl as a bare TypeError
    res, _ = _walk({LOTL_URL: LOTL, DE_URL: _with_date(DE_TL, b"2026-01-01T00:00:00")})
    assert res.anchors == () and res.problems[0].stage == "parse"


def test_walk_a_past_next_update_is_still_expired():
    # the control the issue measured: unchanged
    res, _ = _walk({LOTL_URL: LOTL, DE_URL: _with_date(DE_TL, PAST_Z)})
    assert res.anchors == ()
    assert len(res.problems) == 1 and res.problems[0].stage == "expired"
    assert "is in the past" in res.problems[0].detail
    assert "closed" not in res.problems[0].detail      # expired ≠ closed


@pytest.mark.parametrize("form", sorted(UTC_FUTURE), ids=sorted(UTC_FUTURE))
def test_walk_keeps_the_anchors_of_a_national_tl_with_a_future_utc_next_update(form):
    value, _ = UTC_FUTURE[form]
    res, _ = _walk({LOTL_URL: LOTL, DE_URL: _with_date(DE_TL, value)})
    assert len(res.anchors) == 1 and res.problems == ()


# --------------------------------------------------------------------------- #
# walk_lotl, the LOTL itself: a closed / malformed LOTL stops the walk
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("form", sorted(NULL_FORMS), ids=sorted(NULL_FORMS))
def test_walk_a_closed_lotl_stops_with_the_problem(form):
    res, fetched = _walk({LOTL_URL: _with_next_update(LOTL, NULL_FORMS[form]), DE_URL: DE_TL})
    assert res.anchors == ()
    assert len(res.problems) == 1
    problem = res.problems[0]
    assert problem.location == LOTL_URL and problem.stage == "expired"
    assert "closed TL (null NextUpdate)" in problem.detail
    assert fetched == [LOTL_URL]                  # no national TL was even fetched


@pytest.mark.parametrize("form", sorted(MALFORMED), ids=sorted(MALFORMED))
def test_walk_a_lotl_with_an_unparseable_or_naive_next_update_stops_with_the_problem(form):
    res, fetched = _walk({LOTL_URL: _with_date(LOTL, MALFORMED[form]), DE_URL: DE_TL})
    assert res.anchors == ()
    assert len(res.problems) == 1
    assert res.problems[0].location == LOTL_URL and res.problems[0].stage == "parse"
    assert fetched == [LOTL_URL]


@pytest.mark.parametrize("form", sorted(UTC_FUTURE), ids=sorted(UTC_FUTURE))
def test_walk_follows_a_lotl_with_a_future_utc_next_update(form):
    value, _ = UTC_FUTURE[form]
    res, fetched = _walk({LOTL_URL: _with_date(LOTL, value), DE_URL: DE_TL})
    assert len(res.anchors) == 1 and res.problems == ()
    assert fetched == [LOTL_URL, DE_URL]


# --------------------------------------------------------------------------- #
# The recorded EU goldens are unchanged: aware UTC NextUpdate, read as before
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name, expected", [
    ("eu-lotl-seq388.xml", datetime(2026, 11, 18, 12, 16, 35, tzinfo=timezone.utc)),
    ("es-tl-seq187.xml", datetime(2026, 12, 28, 3, 0, 0, tzinfo=timezone.utc)),
])
def test_the_recorded_eu_goldens_still_parse_an_aware_next_update(name, expected):
    tl = parse_trust_list((_FIX / "real" / name).read_bytes())
    assert tl.next_update == expected
    assert tl.next_update.tzinfo is not None
