"""
tests/test_dcql_meta_upfront.py — every Credential Query's ``meta`` is validated up front,
answered or not (#254).

#224 made a malformed type constraint (``meta.vct_values``, ``meta.doctype_value``,
``meta.type_values``) fail safe as ``VpTokenMalformed`` instead of reading as "no
constraint". But ``verify_vp_token`` read a query's ``meta`` only when that query's own
Presentation came up in the ``vp_token`` loop, so:

  (a) a query the wallet did not answer (allowed by ``credential_sets``) was never checked;
  (b) an earlier query's presentation failure was reported before a later query's
      malformed ``meta``;
  (c) the order inside one query differed by format: for ``mso_mdoc`` the constraint was
      read after ``expected_origins``, ``trust_anchors`` and the "must be a string" check.

``_index_dcql`` now checks every query's constraint, after the per-query checks it already
did and before any Presentation is read. The ``pyld`` requirement of ``type_values`` moved
to the point of use, so a well-formed ``type_values`` on an unanswered query still needs no
``pyld``.

The ``dcql_query`` is the verifier's own input, so this is defence in depth, not an
attacker-reachable bypass. Negatives first; each one pins the query it names
(``Credential Query 'b': meta``) and the exact class, so it cannot pass on a different
failure. The ``test_control_*`` tests must pass before the change and after it.
"""
from __future__ import annotations

import contextlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import (
    OpenID4VPError,
    UnsupportedPresentationFormat,
    VpTokenMalformed,
    verify_vp_token,
)
from openvc.proof.errors import ClaimsInvalid, MalformedToken
from openvc.proof.sd_jwt import SdJwtVcProofSuite

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
ORIGIN = "https://verifier.example"
VCT = "https://credentials.example.com/identity_credential"
DOCTYPE = "org.iso.18013.5.1.mDL"
VC_IRI = "https://www.w3.org/2018/credentials#VerifiableCredential"

SD, MDOC, JWT, LDP = "dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "ldp_vc"
FORMATS = [SD, MDOC, JWT, LDP]

# A well-formed constraint per format, and the meta key each format reads.
SOUND = {
    SD: {"vct_values": [VCT]},
    MDOC: {"doctype_value": DOCTYPE},
    JWT: {"type_values": [[VC_IRI]]},
    LDP: {"type_values": [[VC_IRI]]},
}
OWN_KEY = {SD: "vct_values", MDOC: "doctype_value",
           JWT: "type_values", LDP: "type_values"}


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


# What a wallet might send for query "b" in each format. It is never read: the malformed
# query is rejected before, and the sound one is not answered or fails earlier.
def _placeholder(fmt, good):
    return {SD: good, MDOC: "AAAA", JWT: "not-a-jwt",
            LDP: {"type": ["VerifiablePresentation"]}}[fmt]


@contextlib.contextmanager
def _exact(cls, match):
    """pytest.raises that also pins the exact class (no subclass, no sibling)."""
    with pytest.raises(cls, match=match) as info:
        yield
    assert type(info.value) is cls


def _query(query_id, fmt, **extra):
    return {"id": query_id, "format": fmt, **extra}


def _b(fmt, meta):
    return _query("b", fmt, meta=meta)


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


def _tv_cases(fmt):
    return [
        pytest.param(fmt, {"type_values": None}, id=f"{fmt}-null-type-values"),
        pytest.param(fmt, {"type_values": []}, id=f"{fmt}-empty-type-values"),
        pytest.param(fmt, {"type_values": [[]]}, id=f"{fmt}-empty-alternative"),
        pytest.param(fmt, {"type_values": [VC_IRI]}, id=f"{fmt}-flat-list"),
        pytest.param(fmt, {"type_values": [[5]]}, id=f"{fmt}-non-string-iri"),
        pytest.param(fmt, {"type_values": "x"}, id=f"{fmt}-string-type-values"),
        pytest.param(fmt, "x", id=f"{fmt}-meta-string"),
        pytest.param(fmt, [], id=f"{fmt}-meta-empty-array"),
        pytest.param(fmt, None, id=f"{fmt}-meta-null"),
    ]


# Falsy metas included: a `meta or {}` shortcut would turn them into "no constraint".
MALFORMED = (
    [pytest.param(SD, meta, id=f"{SD}-{label}") for label, meta in [
        ("meta-null", None), ("meta-empty-array", []), ("meta-string", "x"),
        ("meta-zero", 0), ("meta-false", False),
        ("null-vct-values", {"vct_values": None}),
        ("empty-vct-values", {"vct_values": []}),
        ("string-vct-values", {"vct_values": VCT}),
        ("non-string-vct-value", {"vct_values": [VCT, 1]}),
        ("object-vct-values", {"vct_values": {"a": 1}}),
    ]]
    + [pytest.param(MDOC, meta, id=f"{MDOC}-{label}") for label, meta in [
        ("meta-null", None), ("meta-empty-array", []), ("meta-empty-string", ""),
        ("null-doctype-value", {"doctype_value": None}),
        ("empty-doctype-value", {"doctype_value": ""}),
        ("number-doctype-value", {"doctype_value": 5}),
        ("array-doctype-value", {"doctype_value": [DOCTYPE]}),
        ("false-doctype-value", {"doctype_value": False}),
    ]]
    + _tv_cases(JWT) + _tv_cases(LDP)
)


# --------------------------------------------------------------------------- #
# (a) a query the wallet did not answer is checked too
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fmt, meta", MALFORMED)
def test_unanswered_query_with_a_malformed_meta_is_rejected(good, fmt, meta):
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta"):
        _run({"a": [good]}, _two(_b(fmt, meta)))


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_malformed_query_may_come_first(good, fmt):
    # The same, with the broken alternative listed before the one that is answered.
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta"):
        _run({"a": [good]}, _two(_b(fmt, None), bad_first=True))


@pytest.mark.parametrize("fmt", [SD, JWT, LDP])
def test_control_answered_query_with_a_malformed_meta_is_still_rejected(good, fmt):
    # Both queries answered: the broken one was rejected once its own Presentation came
    # up, and still is. (mso_mdoc is not here: with a client_id it failed earlier, which
    # is case (c) below.)
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta"):
        _run({"a": [good], "b": [_placeholder(fmt, good)]}, _two(_b(fmt, None), sets=False))


# --------------------------------------------------------------------------- #
# (b) an earlier query's failure does not mask a later query's malformed meta
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fmt, meta", MALFORMED)
def test_an_earlier_presentation_failure_does_not_mask_a_malformed_meta(good, fmt, meta):
    vp_token = {"a": ["junk~"], "b": [_placeholder(fmt, good)]}
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta"):
        _run(vp_token, _two(_b(fmt, meta)))


@pytest.mark.parametrize("fmt", FORMATS)
def test_control_the_junk_presentation_fails_on_its_own(good, fmt):
    # Control for the test above: with a sound constraint on "b" the same token fails on
    # "a"'s presentation, so the VpTokenMalformed above is the query's doing.
    vp_token = {"a": ["junk~"], "b": [_placeholder(fmt, good)]}
    with _exact(MalformedToken, "not a valid compact JWS"):
        _run(vp_token, _two(_b(fmt, SOUND[fmt])))


# --------------------------------------------------------------------------- #
# (c) the order inside one query no longer depends on the format
# --------------------------------------------------------------------------- #

MDOC_BAD_META = [
    pytest.param(None, id="meta-null"),
    pytest.param({"doctype_value": None}, id="null-doctype-value"),
    pytest.param({"doctype_value": ""}, id="empty-doctype-value"),
    pytest.param({"doctype_value": 5}, id="number-doctype-value"),
]


def _mdoc_dcql(meta):
    return {"credentials": [_query("q", MDOC, meta=meta)]}


@pytest.mark.parametrize("meta", MDOC_BAD_META)
def test_mdoc_constraint_is_read_before_expected_origins(meta):
    # client_id is given, so the call is valid up to _verify_one: a sound query would be
    # UnsupportedPresentationFormat for the missing expected_origins.
    with _exact(VpTokenMalformed, r"Credential Query 'q': meta"):
        _run({"q": ["AAAA"]}, _mdoc_dcql(meta))


@pytest.mark.parametrize("meta", MDOC_BAD_META)
def test_mdoc_constraint_is_read_before_trust_anchors(meta):
    with _exact(VpTokenMalformed, r"Credential Query 'q': meta"):
        _run({"q": ["AAAA"]}, _mdoc_dcql(meta), expected_origins=[ORIGIN])


@pytest.mark.parametrize("meta", MDOC_BAD_META)
def test_mdoc_constraint_is_read_before_the_presentation_is_typed(meta):
    # The old failure here was also a VpTokenMalformed, so the message is what tells the
    # two apart: "must be a base64url string" before, the query's own meta now.
    with _exact(VpTokenMalformed, r"Credential Query 'q': meta"):
        _run({"q": [5]}, _mdoc_dcql(meta), expected_origins=[ORIGIN], trust_anchors=[])


def test_sd_jwt_and_mdoc_agree_on_a_null_meta_and_a_non_string_presentation():
    messages = {}
    for fmt in (SD, MDOC):
        dcql = {"credentials": [_query("q", fmt, meta=None)]}
        with pytest.raises(VpTokenMalformed) as info:
            _run({"q": [5]}, dcql, expected_origins=[ORIGIN], trust_anchors=[])
        assert type(info.value) is VpTokenMalformed
        messages[fmt] = str(info.value)
    assert messages[SD] == messages[MDOC] == \
        "Credential Query 'q': meta must be a JSON object"


def test_control_a_sound_mdoc_constraint_keeps_the_old_order():
    # A well-formed doctype_value changes nothing: the later checks run in their order.
    dcql = _mdoc_dcql({"doctype_value": DOCTYPE})
    with _exact(UnsupportedPresentationFormat, "expected_origins"):
        _run({"q": ["AAAA"]}, dcql)
    with _exact(ClaimsInvalid, "trust_anchors"):
        _run({"q": ["AAAA"]}, dcql, expected_origins=[ORIGIN])
    with _exact(VpTokenMalformed, "must be a base64url string"):
        _run({"q": [5]}, dcql, expected_origins=[ORIGIN], trust_anchors=[])


# --------------------------------------------------------------------------- #
# a malformed meta also wins over the checks that run after _index_dcql
# --------------------------------------------------------------------------- #

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
def test_a_malformed_meta_is_reported_before_the_later_shape_checks(
        good, vp_token, sets, _later):
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta"):
        _run(_fill(vp_token, good), _two(_b(SD, None), sets=sets))


@pytest.mark.parametrize("vp_token, sets, later", LATER_CHECKS)
def test_control_the_later_shape_checks_fire_on_their_own(good, vp_token, sets, later):
    with _exact(VpTokenMalformed, later):
        _run(_fill(vp_token, good), _two(_b(SD, SOUND[SD]), sets=sets))


# --------------------------------------------------------------------------- #
# controls: what is unchanged (these pass before the change too)
# --------------------------------------------------------------------------- #

def _foreign_keys(fmt, value_of):
    """The meta keys of every format that does not read *fmt*'s own key."""
    return {OWN_KEY[o]: value_of(o) for o in FORMATS if OWN_KEY[o] != OWN_KEY[fmt]}


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("shape", ["no-meta", "empty-meta", "other-keys",
                                   "other-keys-malformed"])
def test_control_unanswered_query_without_its_own_key_is_accepted(good, fmt, shape):
    # Absent means no constraint, and the keys of another format are not read, malformed
    # or not: each format reads only its own.
    metas = {
        "no-meta": None,
        "empty-meta": {},
        "other-keys": _foreign_keys(fmt, lambda o: SOUND[o][OWN_KEY[o]]),
        "other-keys-malformed": _foreign_keys(fmt, lambda o: None),
    }
    meta = metas[shape]
    query = _query("b", fmt) if meta is None else _b(fmt, meta)
    result = _run({"a": [good]}, _two(query))
    assert [p.query_id for p in result.presentations] == ["a"]


@pytest.mark.parametrize("fmt", FORMATS)
def test_control_unanswered_query_with_a_sound_constraint_is_accepted(good, fmt):
    result = _run({"a": [good]}, _two(_b(fmt, SOUND[fmt])))
    assert [p.query_id for p in result.presentations] == ["a"]


def test_control_malformed_keys_of_other_formats_are_ignored_when_answered(good):
    meta = {"doctype_value": None, "type_values": None}
    result = _run({"a": [good]}, {"credentials": [_query("a", SD, meta=meta)]})
    assert [p.query_id for p in result.presentations] == ["a"]


@pytest.mark.parametrize("meta", [None, [], "x", {"vct_values": None}])
def test_control_unanswered_query_of_an_unknown_format_is_ignored(good, meta):
    # A format openvc does not know is left alone: its meta is not read.
    result = _run({"a": [good]}, _two(_b("x-unknown-format", meta)))
    assert [p.query_id for p in result.presentations] == ["a"]


def test_control_answered_query_of_an_unknown_format_is_still_unsupported():
    with _exact(UnsupportedPresentationFormat, "unknown format"):
        _run({"b": ["x"]}, {"credentials": [_b("x-unknown-format", None)]})


# --------------------------------------------------------------------------- #
# controls: pyld is demanded where type_values is matched, not where it is checked
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fmt", [JWT, LDP])
def test_control_valid_type_values_on_an_unanswered_query_needs_no_pyld(
        good, fmt, monkeypatch):
    monkeypatch.setitem(sys.modules, "pyld", None)
    result = _run({"a": [good]}, _two(_b(fmt, {"type_values": [[VC_IRI]]})))
    assert [p.query_id for p in result.presentations] == ["a"]


@pytest.mark.parametrize("fmt", [JWT, LDP])
def test_malformed_type_values_on_an_unanswered_query_is_rejected_without_pyld(
        good, fmt, monkeypatch):
    # The shape check does not depend on pyld, so it runs (and fails) the same without it.
    monkeypatch.setitem(sys.modules, "pyld", None)
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta\.type_values"):
        _run({"a": [good]}, _two(_b(fmt, {"type_values": [[]]})))


@pytest.mark.parametrize("fmt", [JWT, LDP])
def test_control_malformed_type_values_beats_the_pyld_requirement_when_answered(
        fmt, monkeypatch):
    # Answered, with pyld hidden: the shape is judged first, so the verifier's bug is
    # reported as such rather than as a missing extra.
    monkeypatch.setitem(sys.modules, "pyld", None)
    dcql = {"credentials": [_query("b", fmt, meta={"type_values": [[]]})]}
    with _exact(VpTokenMalformed, r"Credential Query 'b': meta\.type_values"):
        _run({"b": [_placeholder(fmt, None)]}, dcql)


@pytest.mark.parametrize("fmt", [JWT, LDP])
def test_control_answered_type_values_without_pyld_is_a_typed_error(
        fmt, monkeypatch):
    monkeypatch.setitem(sys.modules, "pyld", None)
    dcql = {"credentials": [_query("b", fmt, meta={"type_values": [[VC_IRI]]})]}
    with _exact(OpenID4VPError, "data-integrity"):
        _run({"b": [_placeholder(fmt, None)]}, dcql)
