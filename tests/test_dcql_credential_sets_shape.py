"""
tests/test_dcql_credential_sets_shape.py — the shape of a DCQL ``credential_sets`` is
validated up front, not read by truthiness (#284).

``verify_vp_token`` used to read ``credential_sets`` in one place, ``_check_completeness``,
as an on/off switch: any truthy value (``true``, ``1``, ``"false"``, ``{"a": 1}``,
``[null]``, ``[[]]``, …) switched the "every Credential Query must be answered" check off,
whatever it held, and a falsy one (``null``, ``false``, ``0``, ``""``, ``[]``, ``{}``) read
as absent by accident. The members were never read: ``required: "false"`` and
``required: true`` were the same thing, and an option naming no query was accepted.

OpenID4VP 1.0 §6.2 defines ``credential_sets`` as OPTIONAL and, when present, a non-empty
array of objects; each one has a REQUIRED ``options`` (a non-empty array of non-empty
arrays of Credential Query ids, each one an entry of ``credentials``) and an OPTIONAL
boolean ``required`` (default ``true``). ``_index_dcql`` now checks exactly that, for every
set, answered or not, after the query walk and before any Presentation is read, and raises
``VpTokenMalformed`` naming the path (never ``repr()`` of the value).

The ``dcql_query`` is the verifier's own input, so this is a fail-safe, not an
attacker-reachable bypass. Negatives first; each one pins the exact class and a ``match``
on the field, so it cannot pass on the "missing required Credential Query id(s)" message
or on another failure. The ``test_control_*`` tests must pass before the change and after.
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
SD = "dc+sd-jwt"


def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def good():
    """A sound dc+sd-jwt Presentation, for the query the wallet answers."""
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


ABSENT = object()


def _dcql(credential_sets=ABSENT, *, credentials=None):
    """Queries "a" and "b", both dc+sd-jwt, with the given ``credential_sets``."""
    dcql = {"credentials": credentials if credentials is not None else [
        {"id": "a", "format": SD}, {"id": "b", "format": SD}]}
    if credential_sets is not ABSENT:
        dcql["credential_sets"] = credential_sets
    return dcql


def _run(vp_token, dcql):
    return verify_vp_token(vp_token, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID)


def _answers(good, answered):
    return {q: [good] for q in answered}


# The wallet leaves "b" out, or answers both queries: neither changes the shape verdict.
SUBSET, EVERYTHING = ("a",), ("a", "b")
ANSWERED = [pytest.param(SUBSET, id="answers-a-only"),
            pytest.param(EVERYTHING, id="answers-every-query")]


def _fill(value, ident):
    """Replace the placeholder "ID" by the query id under test, at any depth."""
    if value == "ID":
        return ident
    if isinstance(value, list):
        return [_fill(v, ident) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, ident) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------- #
# the value of credential_sets itself
# --------------------------------------------------------------------------- #

TOP_LEVEL = [
    pytest.param(None, id="null"),
    pytest.param(False, id="false"),
    pytest.param(True, id="true"),
    pytest.param(0, id="zero"),
    pytest.param(0.0, id="zero-float"),
    pytest.param(1, id="one"),
    pytest.param("", id="empty-string"),
    pytest.param("x", id="string"),
    pytest.param("false", id="string-false"),
    pytest.param([], id="empty-array"),
    pytest.param({}, id="empty-object"),
    pytest.param({"a": 1}, id="object"),
]


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("value", TOP_LEVEL)
def test_credential_sets_must_be_a_non_empty_array(good, value, answered):
    with _exact(VpTokenMalformed, r"dcql_query\.credential_sets must be a non-empty array"):
        _run(_answers(good, answered), _dcql(value))


# --------------------------------------------------------------------------- #
# each entry
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("entry", [
    pytest.param(None, id="null"),
    pytest.param(1, id="number"),
    pytest.param("a", id="string"),
    pytest.param([], id="array"),
    pytest.param([["a"]], id="array-of-arrays"),
])
def test_each_set_must_be_an_object(good, entry, answered):
    with _exact(VpTokenMalformed, r"credential_sets\[0\] must be an object"):
        _run(_answers(good, answered), _dcql([entry]))


@pytest.mark.parametrize("answered", ANSWERED)
def test_every_set_is_checked_not_only_the_first(good, answered):
    # A good set followed by a bad one: the message names the index of the bad one.
    with _exact(VpTokenMalformed, r"credential_sets\[1\] must be an object"):
        _run(_answers(good, answered), _dcql([{"options": [["a"]]}, 5]))


@pytest.mark.parametrize("answered", ANSWERED)
def test_every_set_is_checked_to_the_last(good, answered):
    sets = [{"options": [["a"]]}, {"options": [["b"]]}, {"options": [["a"]], "required": 1}]
    with _exact(VpTokenMalformed, r"credential_sets\[2\]\.required must be a boolean"):
        _run(_answers(good, answered), _dcql(sets))


# --------------------------------------------------------------------------- #
# options
# --------------------------------------------------------------------------- #

NOT_AN_ARRAY_OF_OPTIONS = [
    pytest.param({}, id="missing"),
    pytest.param({"options": None}, id="null"),
    pytest.param({"options": "a"}, id="string"),
    pytest.param({"options": []}, id="empty-array"),
    pytest.param({"options": {}}, id="empty-object"),
    pytest.param({"options": {"a": ["a"]}}, id="object"),
    pytest.param({"options": 1}, id="number"),
]


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("entry", NOT_AN_ARRAY_OF_OPTIONS)
def test_options_must_be_a_non_empty_array(good, entry, answered):
    with _exact(VpTokenMalformed, r"credential_sets\[0\]\.options must be a non-empty array"):
        _run(_answers(good, answered), _dcql([entry]))


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("options", [
    pytest.param([[]], id="empty-option"),
    pytest.param(["a"], id="flat-array-of-ids"),
    pytest.param([None], id="null-option"),
    pytest.param([{"a": 1}], id="object-option"),
])
def test_each_option_must_be_a_non_empty_array(good, options, answered):
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[0\] must be a non-empty array"):
        _run(_answers(good, answered), _dcql([{"options": options}]))


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("ident", ["a", "b"])       # the answered query / the unanswered one
@pytest.mark.parametrize("bad", [
    pytest.param(1, id="number"),
    pytest.param(None, id="null"),
    pytest.param(True, id="bool"),
    pytest.param(["ID"], id="nested-array"),
    pytest.param({"id": "ID"}, id="object"),
])
def test_an_option_holds_only_strings(good, ident, bad, answered):
    # The nested array is [[["a"]]] in the issue's terms: an array where an id belongs.
    # The unhashable value must not escape as a TypeError from the query-table lookup.
    bad = _fill(bad, ident)
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[0\] must hold only Credential Query ids"):
        _run(_answers(good, answered), _dcql([{"options": [[ident, bad]]}]))
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[0\] must hold only Credential Query ids"):
        _run(_answers(good, answered), _dcql([{"options": [[bad]]}]))


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("unknown", ["zzz", "", "A", "a ", "a\u0000"])
def test_an_option_must_name_a_credential_query(good, unknown, answered):
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[0\] names Credential Query .*"
                r"which is not in dcql_query\.credentials"):
        _run(_answers(good, answered), _dcql([{"options": [[unknown]]}]))


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("ident", ["a", "b"])
def test_an_unknown_id_beside_a_real_one_is_still_unknown(good, ident, answered):
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[0\] names Credential Query 'zzz'"):
        _run(_answers(good, answered), _dcql([{"options": [[ident, "zzz"]]}]))


@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("ident", ["a", "b"])
def test_every_option_is_checked_not_only_the_first(good, ident, answered):
    # A good option followed by a bad one: the message names the index of the bad one.
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[1\] must be a non-empty array"):
        _run(_answers(good, answered), _dcql([{"options": [[ident], []]}]))
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[1\] names Credential Query 'zzz'"):
        _run(_answers(good, answered), _dcql([{"options": [[ident], ["zzz"]]}]))


@pytest.mark.parametrize("answered", ANSWERED)
def test_every_id_of_an_option_is_checked_not_only_the_first(good, answered):
    with _exact(VpTokenMalformed,
                r"credential_sets\[0\]\.options\[0\] names Credential Query 'zzz'"):
        _run(_answers(good, answered), _dcql([{"options": [["a", "b", "zzz"]]}]))


@pytest.mark.parametrize("answered", ANSWERED)
def test_the_set_index_is_the_one_that_is_bad(good, answered):
    sets = [{"options": [["a"]]}, {"options": [["b"], ["zzz"]]}]
    with _exact(VpTokenMalformed,
                r"credential_sets\[1\]\.options\[1\] names Credential Query 'zzz'"):
        _run(_answers(good, answered), _dcql(sets))


# --------------------------------------------------------------------------- #
# required
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("answered", ANSWERED)
@pytest.mark.parametrize("required", [
    pytest.param("false", id="string-false"),
    pytest.param("true", id="string-true"),
    pytest.param(None, id="null"),
    pytest.param(0, id="zero"),
    pytest.param(0.0, id="zero-float"),
    pytest.param(1, id="one"),
    pytest.param(1.0, id="one-float"),
    pytest.param([], id="empty-array"),
    pytest.param({}, id="empty-object"),
])
def test_required_must_be_a_json_boolean(good, required, answered):
    with _exact(VpTokenMalformed, r"credential_sets\[0\]\.required must be a boolean"):
        _run(_answers(good, answered), _dcql([{"options": [["a"]], "required": required}]))


# --------------------------------------------------------------------------- #
# ordering: the shape check sits after the query walk and before the response is read
# --------------------------------------------------------------------------- #

BAD_SETS = [{"options": []}]            # any malformed credential_sets will do
SETS_MSG = r"credential_sets\[0\]\.options must be a non-empty array"


@pytest.mark.parametrize("bad_query, message", [
    pytest.param({"id": "b", "format": SD, "multiple": "false"},
                 r"Credential Query 'b': multiple must be a boolean", id="multiple"),
    pytest.param({"id": "b", "format": SD, "require_cryptographic_holder_binding": None},
                 r"Credential Query 'b': require_cryptographic_holder_binding must be",
                 id="holder-binding-flag"),
    pytest.param({"id": "b", "format": SD, "meta": None},
                 r"Credential Query 'b': meta", id="meta"),
    pytest.param({"format": SD}, r"needs a non-empty string id", id="later-query-without-id"),
])
def test_a_query_shape_error_is_reported_before_a_malformed_credential_sets(
        good, bad_query, message):
    credentials = [{"id": "a", "format": SD}, bad_query]
    with _exact(VpTokenMalformed, message):
        _run(_answers(good, SUBSET), _dcql(BAD_SETS, credentials=credentials))


@pytest.mark.parametrize("sound_query", [
    pytest.param({"id": "b", "format": SD, "multiple": False}, id="multiple"),
    pytest.param({"id": "b", "format": SD, "require_cryptographic_holder_binding": True},
                 id="holder-binding-flag"),
    pytest.param({"id": "b", "format": SD, "meta": {"vct_values": [VCT]}}, id="meta"),
    pytest.param({"id": "b", "format": SD}, id="later-query-with-id"),
])
def test_the_credential_sets_error_is_reported_when_the_queries_are_sound(
        good, sound_query):
    # Counterpart of the test above: the same dcql_query with the later query made sound
    # fails on credential_sets, so the earlier message is the query's doing.
    credentials = [{"id": "a", "format": SD}, sound_query]
    with _exact(VpTokenMalformed, SETS_MSG):
        _run(_answers(good, SUBSET), _dcql(BAD_SETS, credentials=credentials))


@pytest.mark.parametrize("vp_token", [
    pytest.param({"a": "PLACEHOLDER", "zzz": "PLACEHOLDER"}, id="unknown-vp-token-key"),
    pytest.param({"a": "not-an-array"}, id="non-array-presentation-list"),
    pytest.param({"a": []}, id="empty-presentation-list"),
    pytest.param({"a": ["junk~"]}, id="junk-presentation"),
])
def test_a_malformed_credential_sets_is_reported_before_the_response_is_read(
        good, vp_token):
    token = {k: [good] if v == "PLACEHOLDER" else v for k, v in vp_token.items()}
    with _exact(VpTokenMalformed, SETS_MSG):
        _run(token, _dcql(BAD_SETS))


@pytest.mark.parametrize("vp_token, cls, message", [
    pytest.param({"a": "PLACEHOLDER", "zzz": "PLACEHOLDER"}, VpTokenMalformed,
                 "'zzz' is not a Credential Query id", id="unknown-vp-token-key"),
    pytest.param({"a": "not-an-array"}, VpTokenMalformed,
                 "must be an array of Presentations", id="non-array-presentation-list"),
    pytest.param({"a": []}, VpTokenMalformed, "is an empty array",
                 id="empty-presentation-list"),
    pytest.param({"a": ["junk~"]}, MalformedToken, "not a valid compact JWS",
                 id="junk-presentation"),
])
def test_control_the_response_checks_fire_on_their_own(good, vp_token, cls, message):
    # Control for the test above: with a sound credential_sets the same token fails on
    # its own check, so the credential_sets error above is the shape check's doing.
    token = {k: [good] if v == "PLACEHOLDER" else v for k, v in vp_token.items()}
    with _exact(cls, message):
        _run(token, _dcql([{"options": [["a"], ["b"]]}]))


def test_an_empty_vp_token_is_still_reported_first():
    # The container is checked before any query is read: unchanged.
    with _exact(VpTokenMalformed, "vp_token contains no presentations"):
        _run({}, _dcql(BAD_SETS))


# --------------------------------------------------------------------------- #
# controls: what is unchanged (these pass before the change too)
# --------------------------------------------------------------------------- #

def test_control_an_absent_credential_sets_still_requires_every_query(good):
    # Plain VpTokenMalformed today; #285 narrows it to the subclass VpTokenIncomplete, so
    # this control matches the message and not the exact class.
    with pytest.raises(VpTokenMalformed,
                       match=r"missing required Credential Query id\(s\): \['b'\]"):
        _run(_answers(good, SUBSET), _dcql())


def test_control_an_absent_credential_sets_accepts_a_complete_response(good):
    result = _run(_answers(good, EVERYTHING), _dcql())
    assert [p.query_id for p in result.presentations] == ["a", "b"]


@pytest.mark.parametrize("answered", ANSWERED)
def test_control_a_well_formed_set_accepts_the_response(good, answered):
    result = _run(_answers(good, answered), _dcql([{"options": [["a"], ["b"]]}]))
    assert [p.query_id for p in result.presentations] == list(answered)


@pytest.mark.parametrize("required", [True, False])
def test_control_required_true_and_false_are_accepted(good, required):
    sets = [{"options": [["a"]], "required": required}]
    result = _run(_answers(good, SUBSET), _dcql(sets))
    assert [p.query_id for p in result.presentations] == ["a"]


@pytest.mark.parametrize("purpose", [
    pytest.param("to prove your age", id="string"),
    pytest.param(42, id="number"),
    pytest.param({"en": "to prove your age"}, id="object"),
    pytest.param(None, id="null"),
])
def test_control_purpose_is_not_read(good, purpose):
    sets = [{"options": [["a"]], "purpose": purpose}]
    result = _run(_answers(good, SUBSET), _dcql(sets))
    assert [p.query_id for p in result.presentations] == ["a"]


def test_control_unknown_members_of_a_set_are_not_read(good):
    sets = [{"options": [["a"]], "x-extension": [1, None, "?"]}]
    result = _run(_answers(good, SUBSET), _dcql(sets))
    assert [p.query_id for p in result.presentations] == ["a"]


def test_control_a_duplicate_id_inside_one_option_is_accepted(good):
    result = _run(_answers(good, SUBSET), _dcql([{"options": [["a", "a"]]}]))
    assert [p.query_id for p in result.presentations] == ["a"]
