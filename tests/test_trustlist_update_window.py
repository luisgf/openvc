"""
tests/test_trustlist_update_window.py — the six-month ``NextUpdate`` ceiling on XML
Trusted Lists (#432).

ETSI TS 119 612 clause 5.3.15: "The difference between the 'Next update' date and
time and the 'List issue date and time' shall not exceed six (6) months." A list that
breaks it (a far ``NextUpdate``) would never expire, which defeats the expiry rule's
purpose (substitution with an old TL). ``walk_lotl`` now treats such a list — the LOTL
included — like an expired one: zero anchors, a ``TrustListProblem`` of stage
``"expired"``, the walk continues. An absent / malformed / naive ``ListIssueDateTime``
fails the same way (the window cannot be evaluated), as a problem and not an exception.
The LoTE lane is unchanged (its ceiling lives in the profile).

Fixtures: the synthetic LOTL + DE TL (their ``ListIssueDateTime`` is 2098-10-01 so the
``NextUpdate`` of 2099-01-01 sits inside the window) with a stub signature verifier,
and the recorded real EU LOTL / ES TL for the "real lists are within the ceiling" pin.
Self-contained (tests/ is not a package).
"""
from __future__ import annotations

import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from openvc.trustlist import walk_lotl

_FIX = pathlib.Path(__file__).parent / "fixtures" / "trustlist"
LOTL = (_FIX / "eu-lotl.xml").read_bytes()
DE_TL = (_FIX / "de-tl.xml").read_bytes()
REAL_LOTL = (_FIX / "real" / "eu-lotl-seq388.xml").read_bytes()
REAL_ES = (_FIX / "real" / "es-tl-seq187.xml").read_bytes()

LOTL_URL = "https://ec.example/eu-lotl.xml"
DE_URL = "https://tl.example.de/de-tl.xml"
UTC = timezone.utc

ISSUE = b"<ListIssueDateTime>2098-10-01T00:00:00Z</ListIssueDateTime>"
PINNED_NU = b"<NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>"
NOW = datetime(2030, 1, 1, tzinfo=UTC)
ISSUED = b"2026-01-01T00:00:00Z"          # the issue date the table below uses


def _ok_sig(_xml, _certs):
    return None


def _shape(doc: bytes, issue: bytes | None, next_update: bytes) -> bytes:
    assert doc.count(ISSUE) == 1 and doc.count(PINNED_NU) == 1
    new_issue = (b"" if issue is None
                 else b"<ListIssueDateTime>" + issue + b"</ListIssueDateTime>")
    doc = doc.replace(ISSUE, new_issue)
    return doc.replace(
        PINNED_NU, b"<NextUpdate><dateTime>" + next_update + b"</dateTime></NextUpdate>")


def _walk(lotl: bytes, de_tl: bytes, now: datetime = NOW):
    store = {LOTL_URL: lotl, DE_URL: de_tl}
    return walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                     fetch=lambda url: store[url], now=now)


def _z(dt: datetime) -> bytes:
    return dt.isoformat().replace("+00:00", "Z").encode()    # never strftime("%Y")


def test_baseline_fixtures_are_inside_the_window():
    res = _walk(LOTL, DE_TL)
    assert len(res.anchors) == 1 and res.problems == ()


# ---- the issue's three rows (national TL; the LOTL keeps the same window) -------- #

def test_row_within_window_before_expiry_keeps_the_anchor():
    nu = b"2026-06-30T00:00:00Z"
    res = _walk(_shape(LOTL, ISSUED, nu), _shape(DE_TL, ISSUED, nu),
                now=datetime(2026, 3, 1, tzinfo=UTC))
    assert len(res.anchors) == 1 and res.problems == ()


def test_row_within_window_after_expiry_is_expired():
    nu = b"2026-06-30T00:00:00Z"
    res = _walk(_shape(LOTL, ISSUED, nu), _shape(DE_TL, ISSUED, nu),
                now=datetime(2050, 1, 1, tzinfo=UTC))
    assert res.anchors == ()
    assert [p.stage for p in res.problems] == ["expired"]


def test_row_far_next_update_national_tl_contributes_nothing():
    res = _walk(_shape(LOTL, ISSUED, b"2026-06-30T00:00:00Z"),
                _shape(DE_TL, ISSUED, b"9999-12-31T00:00:00Z"),
                now=datetime(2026, 3, 1, tzinfo=UTC))
    assert res.anchors == ()
    assert len(res.problems) == 1
    p = res.problems[0]
    assert (p.stage, p.location) == ("expired", DE_URL)
    assert "more than 6 months after ListIssueDateTime" in p.detail


def test_far_next_update_lotl_yields_no_anchors_at_all():
    res = _walk(_shape(LOTL, ISSUED, b"9999-12-31T00:00:00Z"),
                _shape(DE_TL, ISSUED, b"2026-06-30T00:00:00Z"),
                now=datetime(2026, 3, 1, tzinfo=UTC))
    assert res.anchors == ()
    assert [(p.stage, p.location) for p in res.problems] == [("expired", LOTL_URL)]
    assert res.problems[0].detail.startswith("LOTL: NextUpdate")


# ---- the boundary: six calendar months to the second ----------------------------- #

@pytest.mark.parametrize("issued,limit", [
    (b"2026-01-01T00:00:00Z", datetime(2026, 7, 1, tzinfo=UTC)),
    (b"2026-08-31T10:00:00Z", datetime(2027, 2, 28, 10, tzinfo=UTC)),   # day clamps
    (b"2026-07-31T23:59:59Z", datetime(2027, 1, 31, 23, 59, 59, tzinfo=UTC)),
])
def test_exactly_six_calendar_months_passes_and_one_second_later_fails(issued, limit):
    now = limit - timedelta(days=2)             # before both NextUpdates
    ok = _z(limit)
    late = _z(limit + timedelta(seconds=1))
    good = _walk(_shape(LOTL, issued, ok), _shape(DE_TL, issued, ok), now=now)
    assert len(good.anchors) == 1 and good.problems == ()
    bad = _walk(_shape(LOTL, issued, ok), _shape(DE_TL, issued, late), now=now)
    assert bad.anchors == () and [p.stage for p in bad.problems] == ["expired"]


# ---- absent / unparseable / naive ListIssueDateTime: a problem, not an exception -- #

BAD_ISSUE = {
    "absent": None,
    "empty": b"",
    "garbage": b"not-a-date",
    "naive": b"2026-01-01T00:00:00",
    "offset +01:00": b"2026-01-01T01:00:00+01:00",
    "date only": b"2026-01-01",
    "30 February": b"2026-02-30T00:00:00Z",
}


@pytest.mark.parametrize("name", sorted(BAD_ISSUE))
def test_unusable_issue_datetime_national_tl_is_a_problem(name):
    nu = b"2026-06-30T00:00:00Z"
    res = _walk(_shape(LOTL, ISSUED, nu), _shape(DE_TL, BAD_ISSUE[name], nu),
                now=datetime(2026, 3, 1, tzinfo=UTC))
    assert res.anchors == ()
    assert [(p.stage, p.location) for p in res.problems] == [("expired", DE_URL)]
    assert "ListIssueDateTime" in res.problems[0].detail


@pytest.mark.parametrize("name", sorted(BAD_ISSUE))
def test_unusable_issue_datetime_lotl_stops_the_walk(name):
    nu = b"2026-06-30T00:00:00Z"
    res = _walk(_shape(LOTL, BAD_ISSUE[name], nu), _shape(DE_TL, ISSUED, nu),
                now=datetime(2026, 3, 1, tzinfo=UTC))
    assert res.anchors == ()
    assert [(p.stage, p.location) for p in res.problems] == [("expired", LOTL_URL)]


def test_issue_datetime_at_the_year_limit_fails_closed_not_with_an_exception():
    res = _walk(_shape(LOTL, ISSUED, b"2026-06-30T00:00:00Z"),
                _shape(DE_TL, b"9999-12-31T00:00:00Z", b"9999-12-31T00:00:00Z"),
                now=datetime(2026, 3, 1, tzinfo=UTC))
    assert res.anchors == ()
    assert [p.stage for p in res.problems] == ["expired"]
    assert "too far in the future" in res.problems[0].detail


# ---- the recorded real lists are inside the ceiling ------------------------------- #

def test_recorded_real_lists_are_within_six_months_and_still_anchor():
    """EU LOTL seq 388 (2026-05-22 -> 2026-11-18) and ES TL seq 187 (2026-07-01 ->
    2026-12-28) are both under the ceiling: no ``expired`` problem for either. (The
    other national pointers are simply not served here: ``fetch`` problems.)"""
    es_url = "https://tsl.digital.gob.es/TSL.xml"
    store = {"https://ec.europa.eu/tools/lotl/eu-lotl.xml": REAL_LOTL, es_url: REAL_ES}

    def fetch(url):
        return store[url]

    res = walk_lotl("https://ec.europa.eu/tools/lotl/eu-lotl.xml",
                    lotl_signer_certs=["c"], verify_signature=_ok_sig, fetch=fetch,
                    now=datetime(2026, 8, 1, tzinfo=UTC))
    assert [p for p in res.problems if p.stage == "expired"] == []
    assert len(res.anchors) > 0
    assert not [p for p in res.problems if p.location == es_url]
