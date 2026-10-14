"""
tests/test_dcql_multiple_boolean.py — a Credential Query's ``multiple`` must be a JSON
boolean, checked for every query, answered or not (#268).

OpenID4VP 1.0 §6.1 defines ``multiple`` as OPTIONAL, a boolean, default ``false``; §8.1
requires exactly one Presentation per query when it is omitted or ``false``. openvc read
it in one place, ``_presentation_list``, by truthiness:

  * a truthy non-boolean (``"false"``, ``"true"``, ``"0"``, ``1``, ``1.0``, ``2``, ``[0]``,
    ``{"a": 1}``) behaved as ``true``, so a wallet could return N Presentations, all
    verified and returned;
  * a falsy non-boolean (``null``, ``""``, ``0``, ``[]``, ``{}``) was read as ``false`` by
    accident, never reported as malformed;
  * a query the wallet did not answer (allowed by ``credential_sets``) never had
    ``multiple`` read at all.

``_index_dcql`` now rejects a non-boolean ``multiple`` on every query, right after the
same check on ``require_cryptographic_holder_binding``, and before any Presentation is
read. The ``dcql_query`` is the verifier's own input, so this is a spec-conformance and
fail-safe fix, not an attacker-reachable bypass.

Negatives first; each one pins the query it names and the exact class
(``Credential Query 'q': multiple must be a boolean``), so it cannot pass on a different
failure, and in particular not on the "single-valued but returned N" message. The
``test_control_*`` tests must pass before the change and after it.
"""
from __future__ import annotations

import contextlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import VpTokenMalformed, verify_vp_token
from openvc.proof.errors import MalformedToken
from openvc.proof.sd_jwt import SdJwtVcProofSuite

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
VCT = "https://credentials.example.com/identity_credential"

SD, MDOC, JWT, LDP = "dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "ldp_vc"

ABSENT = object()       # "the query has no `multiple` member"

# Every non-boolean the issue lists. Python literals, not JSON text, so 1.0 stays a float
# and None is a JSON null. The ids spell out the type: 0, 1 and 1.0 (and False / True)
# compare equal in Python, so only the id tells them apart.
NON_BOOLEANS = [
    pytest.param("false", id="string-false"),
    pytest.param("true", id="string-true"),
    pytest.param("", id="empty-string"),
    pytest.param("0", id="string-zero"),
    pytest.param(0, id="int-zero"),
    pytest.param(1, id="int-one"),
    pytest.param(1.0, id="float-one"),
    pytest.param(2, id="int-two"),
    pytest.param([], id="empty-array"),
    pytest.param([0], id="array-zero"),
    pytest.param({}, id="empty-object"),
    pytest.param({"a": 1}, id="object"),
    pytest.param(None, id="null"),
]

BAD_Q = r"Credential Query 'q': multiple must be a boolean"
BAD_B = r"Credential Query 'b': multiple must be a boolean"


def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def good():
    """A sound dc+sd-jwt Presentation, for the query that is answered."""
    issuer_key, issuer_did = _did_key_p256()
    holder_key, _ = _did_key_p256()
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "sub": "did:example:alice"}, signing_key=issuer_key,
        vct=VCT, holder_jwk=holder_key.public_jwk())
    return SdJwtVcProofSuite().create_presentation(
        issued, holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)


@contextlib.contextmanager
def _exact(cls, match):
    """pytest.raises that also pins the exact class (no subclass, no sibling)."""
    with pytest.raises(cls, match=match) as info:
        yield
    assert type(info.value) is cls


def _query(query_id, fmt, multiple=ABSENT, **extra):
    q = {"id": query_id, "format": fmt, **extra}
    if multiple is not ABSENT:
        q["multiple"] = multiple
    return q


def _one(multiple, fmt=SD):
    """A single query "q", the one the wallet answers."""
    return {"credentials": [_query("q", fmt, multiple)]}


def _two(b_query, *, sets=True, bad_first=False):
    """Query "a" (a sound dc+sd-jwt) beside "b". By default, with credential_sets making
    either one an acceptable answer, so the wallet may leave "b" out."""
    a = _query("a", SD)
    dcql = {"credentials": [b_query, a] if bad_first else [a, b_query]}
    if sets:
        dcql["credential_sets"] = [{"options": [["a"], ["b"]]}]
    return dcql


def _run(vp_token, dcql, **kw):
    if "expected_origins" not in kw:
        kw.setdefault("client_id", CLIENT_ID)
    return verify_vp_token(vp_token, dcql_query=dcql, nonce=NONCE, **kw)


# --------------------------------------------------------------------------- #
# an answered query: a non-boolean is rejected, whatever the wallet sent
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", [1, 2], ids=["one-presentation", "two-presentations"])
@pytest.mark.parametrize("multiple", NON_BOOLEANS)
def test_answered_query_with_a_non_boolean_multiple_is_rejected(good, multiple, n):
    # One Presentation used to verify under all thirteen; two used to verify under the
    # truthy ones (and be "single-valued" under the falsy ones).
    with _exact(VpTokenMalformed, BAD_Q):
        _run({"q": [good] * n}, _one(multiple))


# --------------------------------------------------------------------------- #
# a query the wallet did not answer is checked too
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("multiple", NON_BOOLEANS)
def test_unanswered_query_with_a_non_boolean_multiple_is_rejected(good, multiple):
    with _exact(VpTokenMalformed, BAD_B):
        _run({"a": [good]}, _two(_query("b", SD, multiple)))


@pytest.mark.parametrize("multiple", NON_BOOLEANS)
def test_the_malformed_query_may_come_first(good, multiple):
    # The same, with the broken alternative listed before the one that is answered.
    with _exact(VpTokenMalformed, BAD_B):
        _run({"a": [good]}, _two(_query("b", SD, multiple), bad_first=True))


def test_unanswered_query_of_an_unknown_format_is_checked_too():
    # `multiple` is not format-specific: an unknown format's meta is left unread, its
    # `multiple` is not.
    with _exact(VpTokenMalformed, BAD_B):
        _run({"a": ["junk~"]}, _two(_query("b", "x-unknown-format", "false")))


# --------------------------------------------------------------------------- #
# an earlier query's failure does not mask a later query's malformed multiple
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("multiple", [
    pytest.param("false", id="string-false"),
    pytest.param(1, id="int-one"),
    pytest.param(None, id="null"),
])
def test_an_earlier_presentation_failure_does_not_mask_a_malformed_multiple(
        good, multiple):
    vp_token = {"a": ["junk~"], "b": [good]}
    with _exact(VpTokenMalformed, BAD_B):
        _run(vp_token, _two(_query("b", SD, multiple)))


@pytest.mark.parametrize("multiple", [ABSENT, False, True],
                         ids=["absent", "false", "true"])
def test_control_the_junk_presentation_fails_on_its_own(good, multiple):
    # Control for the test above: with a boolean (or no) `multiple` on "b" the same token
    # fails on "a"'s presentation, so the VpTokenMalformed above is the query's doing.
    vp_token = {"a": ["junk~"], "b": [good]}
    with _exact(MalformedToken, "not a valid compact JWS"):
        _run(vp_token, _two(_query("b", SD, multiple)))


# --------------------------------------------------------------------------- #
# the check does not depend on the format (the count gate ran before the dispatch)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fmt", [MDOC, LDP, JWT])
def test_a_string_multiple_is_rejected_whatever_the_format(fmt):
    # "false" got past the count gate and failed later on the junk Presentation (which of
    # openvc's own errors depended on the format).
    with _exact(VpTokenMalformed, BAD_Q):
        _run({"q": ["AAAA", "AAAA"]}, _one("false", fmt))


@pytest.mark.parametrize("fmt", [MDOC, LDP, JWT])
def test_control_a_boolean_false_stops_at_single_valued_whatever_the_format(fmt):
    with _exact(VpTokenMalformed, "single-valued but returned 2 Presentations"):
        _run({"q": ["AAAA", "AAAA"]}, _one(False, fmt))


# --------------------------------------------------------------------------- #
# ordering: the sibling flag still comes first, and the later shape checks give way
# --------------------------------------------------------------------------- #

def test_control_a_malformed_holder_binding_flag_on_the_same_query_is_reported_first(good):
    dcql = {"credentials": [_query(
        "q", SD, "false", require_cryptographic_holder_binding="no")]}
    with _exact(VpTokenMalformed,
                r"Credential Query 'q': require_cryptographic_holder_binding"):
        _run({"q": [good]}, dcql)


# (vp_token, credential_sets?, what the same token says when "b" is sound)
LATER_CHECKS = [
    pytest.param({"a": ["PLACEHOLDER"]}, False, "missing required Credential Query id",
                 id="missing-required-query-id"),
    pytest.param({"a": ["PLACEHOLDER"], "zzz": ["x"]}, True,
                 "'zzz' is not a Credential Query id", id="unknown-vp-token-key"),
    pytest.param({"a": "not-an-array"}, True, "must be an array of Presentations",
                 id="non-array-presentation-list"),
    pytest.param({"a": []}, True, "is an empty array", id="empty-presentation-list"),
]


def _fill(vp_token, good):
    return {k: [good] if v == ["PLACEHOLDER"] else v for k, v in vp_token.items()}


@pytest.mark.parametrize("vp_token, sets, _later", LATER_CHECKS)
def test_a_malformed_multiple_is_reported_before_the_later_shape_checks(
        good, vp_token, sets, _later):
    with _exact(VpTokenMalformed, BAD_B):
        _run(_fill(vp_token, good), _two(_query("b", SD, "false"), sets=sets))


@pytest.mark.parametrize("vp_token, sets, later", LATER_CHECKS)
def test_control_the_later_shape_checks_fire_on_their_own(good, vp_token, sets, later):
    with _exact(VpTokenMalformed, later):
        _run(_fill(vp_token, good), _two(_query("b", SD, False), sets=sets))


# --------------------------------------------------------------------------- #
# controls: what is unchanged (these pass before the change too)
# --------------------------------------------------------------------------- #

def test_control_multiple_true_allows_two_presentations(good):
    result = _run({"q": [good, good]}, _one(True))
    assert len(result.for_query("q")) == 2


@pytest.mark.parametrize("multiple", [ABSENT, False], ids=["absent", "false"])
def test_control_a_single_valued_query_accepts_one_presentation(good, multiple):
    result = _run({"q": [good]}, _one(multiple))
    assert len(result.for_query("q")) == 1


@pytest.mark.parametrize("multiple", [ABSENT, False], ids=["absent", "false"])
def test_control_a_single_valued_query_rejects_two_as_single_valued(good, multiple):
    # The "single-valued" message is a different failure from the new one: it must not
    # satisfy any negative above, and the new check must not replace it.
    with _exact(VpTokenMalformed, "single-valued but returned 2 Presentations"):
        _run({"q": [good, good]}, _one(multiple))


@pytest.mark.parametrize("multiple", [True, False], ids=["true", "false"])
def test_control_a_boolean_multiple_on_an_unanswered_query_is_accepted(good, multiple):
    result = _run({"a": [good]}, _two(_query("b", SD, multiple)))
    assert [p.query_id for p in result.presentations] == ["a"]


def test_control_an_unanswered_query_of_an_unknown_format_with_multiple_true_is_accepted(
        good):
    result = _run({"a": [good]}, _two(_query("b", "x-unknown-format", True)))
    assert [p.query_id for p in result.presentations] == ["a"]
