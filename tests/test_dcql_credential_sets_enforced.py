"""
tests/test_dcql_credential_sets_enforced.py — the required DCQL ``credential_sets`` are
enforced (#285).

With a ``credential_sets`` in the query, ``verify_vp_token`` used to skip the completeness
check altogether: any non-empty ``vp_token`` whose Presentations all verified was accepted,
whatever the sets required, so a holder could leave out a credential the verifier had
marked as required. OpenID4VP 1.0 says what a response must contain:

  * §6.2: ``options`` lists the Credential Query ids that satisfy a set together; the
    boolean ``required`` defaults to ``true``;
  * §6.4.2: with no ``credential_sets`` the Verifier requests every Credential Query;
    otherwise it requests presentations satisfying every set whose ``required`` is true
    or omitted, and optionally any of the others; a set is satisfied by presentations
    that match one of its ``options``;
  * §8.6: the last validation step checks that the set of Presentations returned
    satisfies all requirements of the request (§6.4); when a check on the response
    fails, the VP Token MUST be rejected.

``_check_completeness`` now checks every required set (``required`` true or omitted) and
raises ``VpTokenIncomplete`` (a ``VpTokenMalformed``) naming the set when none of its
options has every Credential Query id answered. An optional set, and a query that no set
references, may be left out (§6.4.2 read literally); extra answers are still accepted and
verified. The no-``credential_sets`` message raises the same class now.

Negatives first; each one pins the exact class and a ``match`` on the set index, so it
cannot pass on a shape error or a Presentation failure. The ``test_control_*`` tests must
pass before the change and after it, except the two that pin the exact new class on the
no-``credential_sets`` path (a deliberate change: ``VpTokenIncomplete`` replaces the plain
``VpTokenMalformed`` there).
"""
from __future__ import annotations

import base64
import contextlib
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import openvc.openid4vp as openid4vp
from openvc import verify_encrypted_vp_response
from openvc.jwe import ALLOWED_ENC, _concat_kdf
from openvc.keys import P256KeyAgreementKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import (
    OpenID4VPError,
    VpTokenIncomplete,
    VpTokenMalformed,
    verify_vp_token,
)
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
    """A sound dc+sd-jwt Presentation, reused for every query the wallet answers."""
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


IDS = ("pid", "age")


def _dcql(credential_sets=None, ids=IDS, **query_extra):
    dcql = {"credentials": [{"id": i, "format": SD, **query_extra} for i in ids]}
    if credential_sets is not None:
        dcql["credential_sets"] = credential_sets
    return dcql


def _opt(*options, required=None):
    """A credential set: ``_opt(["pid", "age"], ["age"])`` has two options."""
    entry = {"options": [list(o) for o in options]}
    if required is not None:
        entry["required"] = required
    return entry


def _run(vp_token, dcql):
    return verify_vp_token(vp_token, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID)


def _answers(good, answered):
    return {q: [good] for q in answered}


def _counts(result, ids):
    return {i: len(result.for_query(i)) for i in ids}


# --------------------------------------------------------------------------- #
# negatives: a required set the response does not satisfy is rejected
# --------------------------------------------------------------------------- #

# (name, credential_sets, answered, the set the message names)
UNSATISFIED = [
    # B: one required set whose only option needs both queries
    pytest.param([_opt(["pid", "age"])], ["pid"], 0, id="B-one-option-needs-both"),
    # C: the same, with required: true spelled out
    pytest.param([_opt(["pid", "age"], required=True)], ["pid"], 0, id="C-required-true"),
    # D: two required sets; the second is the one left out
    pytest.param([_opt(["pid"]), _opt(["age"])], ["pid"], 1, id="D-second-set-left-out"),
    # E: the only required set wants age, the wallet answers pid
    pytest.param([_opt(["age"])], ["pid"], 0, id="E-another-query-answered"),
    # F: two options, neither answered in full
    pytest.param([_opt(["pid", "age"], ["age"])], ["pid"], 0, id="F-no-option-answered"),
    # a required set followed by an optional one: the required one is the unsatisfied one
    pytest.param([_opt(["age"]), _opt(["pid"], required=False)], ["pid"], 0,
                 id="required-then-optional"),
    # the optional set first: the index is still the required one's
    pytest.param([_opt(["pid"], required=False), _opt(["age"])], ["pid"], 1,
                 id="optional-then-required"),
    # a two-id option of which the wallet answers the second id only
    pytest.param([_opt(["pid", "age"])], ["age"], 0, id="second-id-of-an-option-only"),
    # a two-id option of which the wallet answers the first id only
    pytest.param([_opt(["age", "pid"])], ["pid"], 0, id="first-id-of-an-option-only"),
    # an option answered in full does not satisfy ANOTHER required set
    pytest.param([_opt(["pid"]), _opt(["age"])], ["age"], 0, id="first-set-left-out"),
    # every answer sits in a query no option names
    pytest.param([_opt(["age"])], ["pid"], 0, id="answer-outside-every-option"),
]


@pytest.mark.parametrize("sets, answered, index", UNSATISFIED)
def test_a_required_set_the_response_does_not_satisfy_is_rejected(
        good, sets, answered, index):
    with _exact(VpTokenIncomplete, rf"does not satisfy credential_sets\[{index}\]"):
        _run(_answers(good, answered), _dcql(sets))


def test_the_last_of_three_required_sets_is_checked(good):
    ids = ("pid", "age", "res")
    sets = [_opt(["pid"]), _opt(["age"]), _opt(["res"])]
    with _exact(VpTokenIncomplete, r"does not satisfy credential_sets\[2\]"):
        _run(_answers(good, ["pid", "age"]), _dcql(sets, ids=ids))


def test_every_set_is_checked_not_only_the_first(good):
    # Three required sets, the middle one left out: checking only sets[0] or only the
    # last would accept it.
    ids = ("pid", "age", "res")
    sets = [_opt(["pid"]), _opt(["age"]), _opt(["res"])]
    with _exact(VpTokenIncomplete, r"does not satisfy credential_sets\[1\]"):
        _run(_answers(good, ["pid", "res"]), _dcql(sets, ids=ids))


def test_control_every_option_is_checked_not_only_the_first(good):
    # The second option is the one that is answered in full: it satisfies the set.
    result = _run(_answers(good, ["age"]), _dcql([_opt(["pid", "age"], ["age"])]))
    assert _counts(result, IDS) == {"pid": 0, "age": 1}


def test_the_message_names_the_closest_option_and_what_it_lacks(good):
    # options[0] lacks two ids, options[1] one: the closest is options[1].
    ids = ("pid", "age", "res")
    sets = [_opt(["age", "res"], ["age"])]
    with _exact(VpTokenIncomplete,
                r"credential_sets\[0\].*closest is options\[1\].*\['age'\]"):
        _run(_answers(good, ["pid"]), _dcql(sets, ids=ids))
    # A tie goes to the first option; its ids are listed sorted.
    with _exact(VpTokenIncomplete,
                r"credential_sets\[0\].*closest is options\[0\].*\['age', 'res'\]"):
        _run(_answers(good, ["pid"]),
             _dcql([_opt(["res", "age"], ["age", "res"])], ids=ids))


def test_the_message_does_not_repr_the_callers_structure(good):
    sets = [_opt(["age"])]
    with pytest.raises(VpTokenIncomplete) as info:
        _run(_answers(good, ["pid"]), _dcql(sets))
    message = str(info.value)
    assert "options" in message and "{" not in message and "[[" not in message


# --------------------------------------------------------------------------- #
# the same check through verify_encrypted_vp_response (HAIP direct_post.jwt)
# --------------------------------------------------------------------------- #

def _encrypt_response(recipient_jwk, payload_obj, enc="A128GCM"):
    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    eph = ec.generate_private_key(ec.SECP256R1())
    rx = int.from_bytes(base64.urlsafe_b64decode(recipient_jwk["x"] + "=="), "big")
    ry = int.from_bytes(base64.urlsafe_b64decode(recipient_jwk["y"] + "=="), "big")
    z = eph.exchange(ec.ECDH(),
                     ec.EllipticCurvePublicNumbers(rx, ry, ec.SECP256R1()).public_key())
    en = eph.public_key().public_numbers()
    header = {"alg": "ECDH-ES", "enc": enc,
              "epk": {"kty": "EC", "crv": "P-256",
                      "x": b64u(en.x.to_bytes(32, "big")), "y": b64u(en.y.to_bytes(32, "big"))}}
    cek = _concat_kdf(z, ALLOWED_ENC[enc] * 8, enc.encode(), b"", b"")
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())
    iv = os.urandom(12)
    ct_tag = AESGCM(cek).encrypt(iv, json.dumps(payload_obj).encode(), protected.encode())
    return f"{protected}..{b64u(iv)}.{b64u(ct_tag[:-16])}.{b64u(ct_tag[-16:])}"


def _encrypted(good, answered):
    key = P256KeyAgreementKey.generate(kid="verifier#enc")
    jwe = _encrypt_response(key.public_jwk(), {"vp_token": _answers(good, answered)})
    return key, jwe


def test_an_encrypted_response_that_leaves_a_required_set_out_is_rejected(good):
    key, jwe = _encrypted(good, ["pid"])
    with _exact(VpTokenIncomplete, r"does not satisfy credential_sets\[0\]"):
        verify_encrypted_vp_response(
            jwe, key=key, dcql_query=_dcql([_opt(["pid", "age"])]),
            nonce=NONCE, client_id=CLIENT_ID)


def test_control_an_encrypted_response_that_satisfies_the_sets_is_accepted(good):
    key, jwe = _encrypted(good, ["pid"])
    result = verify_encrypted_vp_response(
        jwe, key=key, dcql_query=_dcql([_opt(["pid"]), _opt(["age"], required=False)]),
        nonce=NONCE, client_id=CLIENT_ID)
    assert _counts(result, IDS) == {"pid": 1, "age": 0}


# --------------------------------------------------------------------------- #
# the error class
# --------------------------------------------------------------------------- #

def test_the_incomplete_error_is_a_vp_token_malformed_and_exported():
    assert issubclass(VpTokenIncomplete, VpTokenMalformed)
    assert issubclass(VpTokenIncomplete, OpenID4VPError)
    assert "VpTokenIncomplete" in openid4vp.__all__
    assert VpTokenIncomplete.__doc__


def test_an_unsatisfied_set_is_still_caught_as_vp_token_malformed(good):
    with pytest.raises(VpTokenMalformed):
        _run(_answers(good, ["pid"]), _dcql([_opt(["pid", "age"])]))


def test_no_credential_sets_raises_the_incomplete_error(good):
    # Row A: every query is required. Same message as before, the narrower class (#285).
    with _exact(VpTokenIncomplete,
                r"vp_token is missing required Credential Query id\(s\): \['age'\]"):
        _run(_answers(good, ["pid"]), _dcql())


def test_control_no_credential_sets_is_still_caught_as_vp_token_malformed(good):
    # Passes before and after: every `except VpTokenMalformed` keeps working.
    with pytest.raises(VpTokenMalformed,
                       match=r"vp_token is missing required Credential Query id\(s\)"):
        _run(_answers(good, ["pid"]), _dcql())


def test_control_no_credential_sets_accepts_a_complete_response(good):
    result = _run(_answers(good, ["pid", "age"]), _dcql())
    assert _counts(result, IDS) == {"pid": 1, "age": 1}


# --------------------------------------------------------------------------- #
# ordering
# --------------------------------------------------------------------------- #

# The bad entry is on "pid", so it cannot satisfy the required set [["age"]]: with the
# bad entry on "age" the key's presence would satisfy the set and prove nothing.
AFTER_SETS = [
    pytest.param({"pid": "not-an-array"}, id="non-array-presentation-list"),
    pytest.param({"pid": []}, id="empty-presentation-list"),
    pytest.param({"pid": ["junk~"]}, id="junk-presentation"),
    pytest.param({"pid": "GOOD", "zzz": "GOOD"}, id="unknown-vp-token-key"),
]


def _fill(good, vp_token):
    return {k: [good] if v == "GOOD" else v for k, v in vp_token.items()}


@pytest.mark.parametrize("vp_token", AFTER_SETS)
def test_an_unsatisfied_set_is_reported_before_the_response_is_read(good, vp_token):
    with _exact(VpTokenIncomplete, r"does not satisfy credential_sets\[0\]"):
        _run(_fill(good, vp_token), _dcql([_opt(["age"])]))


@pytest.mark.parametrize("vp_token, cls, message", [
    pytest.param({"pid": "not-an-array"}, VpTokenMalformed,
                 "must be an array of Presentations", id="non-array-presentation-list"),
    pytest.param({"pid": []}, VpTokenMalformed, "is an empty array",
                 id="empty-presentation-list"),
    pytest.param({"pid": ["junk~"]}, MalformedToken, "not a valid compact JWS",
                 id="junk-presentation"),
    pytest.param({"pid": "GOOD", "zzz": "GOOD"}, VpTokenMalformed,
                 "'zzz' is not a Credential Query id", id="unknown-vp-token-key"),
])
def test_control_the_response_checks_fire_on_their_own(good, vp_token, cls, message):
    # Control for the test above: with a set the token DOES satisfy, the same token
    # fails on its own check, so the VpTokenIncomplete above is the set's doing.
    with _exact(cls, message):
        _run(_fill(good, vp_token), _dcql([_opt(["pid"])]))


def test_a_malformed_credential_sets_is_reported_before_an_unsatisfied_set(good):
    # Set 0 is unsatisfied, set 1 is malformed: the shape error (#284) wins.
    with _exact(VpTokenMalformed, r"credential_sets\[1\] must be an object"):
        _run(_answers(good, ["pid"]), _dcql([_opt(["age"]), 5]))


def test_a_malformed_query_member_is_reported_before_an_unsatisfied_set(good):
    with _exact(VpTokenMalformed, r"Credential Query 'age': multiple must be a boolean"):
        dcql = {"credentials": [{"id": "pid", "format": SD},
                                {"id": "age", "format": SD, "multiple": "false"}],
                "credential_sets": [_opt(["age"])]}
        _run(_answers(good, ["pid"]), dcql)


def test_an_empty_vp_token_is_still_reported_first():
    with _exact(VpTokenMalformed, "vp_token contains no presentations"):
        _run({}, _dcql([_opt(["pid", "age"])]))


def test_an_empty_vp_token_is_rejected_when_every_set_is_optional():
    # Out of scope for #285: openvc keeps rejecting it, as before.
    with _exact(VpTokenMalformed, "vp_token contains no presentations"):
        _run({}, _dcql([_opt(["pid"], required=False)]))


# --------------------------------------------------------------------------- #
# controls: what is accepted, before and after
# --------------------------------------------------------------------------- #

def test_control_G_a_required_set_answered_and_an_optional_one_left_out(good):
    sets = [_opt(["pid"]), _opt(["age"], required=False)]
    result = _run(_answers(good, ["pid"]), _dcql(sets))
    assert _counts(result, IDS) == {"pid": 1, "age": 0}


def test_control_H_the_second_option_of_a_set_answers_it(good):
    result = _run(_answers(good, ["age"]), _dcql([_opt(["pid"], ["age"])]))
    assert _counts(result, IDS) == {"pid": 0, "age": 1}


def test_control_I_a_set_answered_in_full(good):
    result = _run(_answers(good, ["pid", "age"]), _dcql([_opt(["pid", "age"])]))
    assert _counts(result, IDS) == {"pid": 1, "age": 1}


def test_control_J_a_query_that_no_set_references_may_be_left_out(good):
    # OpenID4VP 1.0 §6.4.2, read literally: with credential_sets present the Verifier
    # requests what satisfies the required sets, and a query no set names is not asked
    # for. Decision 1 of #285: follow the spec.
    ids = ("pid", "age", "x")
    result = _run(_answers(good, ["pid"]), _dcql([_opt(["pid"])], ids=ids))
    assert _counts(result, ids) == {"pid": 1, "age": 0, "x": 0}


@pytest.mark.parametrize("answered", [["pid"], ["age"], ["pid", "age"], ["x"]])
def test_control_every_set_optional_accepts_any_non_empty_answer(good, answered):
    ids = ("pid", "age", "x")
    sets = [_opt(["pid"], required=False), _opt(["age"], required=False)]
    result = _run(_answers(good, answered), _dcql(sets, ids=ids))
    assert sorted(p.query_id for p in result.presentations) == sorted(answered)


def test_control_a_set_satisfied_by_its_second_option_among_several_sets(good):
    sets = [_opt(["pid"]), _opt(["x", "age"], ["age"])]
    result = _run(_answers(good, ["pid", "age"]), _dcql(sets, ids=("pid", "age", "x")))
    assert _counts(result, ("pid", "age", "x")) == {"pid": 1, "age": 1, "x": 0}


def test_control_extra_answers_are_accepted_and_returned(good):
    # Both options of a set answered, and a query outside every option answered too.
    ids = ("pid", "age", "x")
    sets = [_opt(["pid"], ["age"])]
    result = _run(_answers(good, ["pid", "age", "x"]), _dcql(sets, ids=ids))
    assert _counts(result, ids) == {"pid": 1, "age": 1, "x": 1}


def test_control_a_duplicate_id_inside_an_option_is_satisfied_by_one_answer(good):
    result = _run(_answers(good, ["pid"]), _dcql([_opt(["pid", "pid"])]))
    assert _counts(result, IDS) == {"pid": 1, "age": 0}


def test_control_required_false_may_be_left_out_entirely_for_that_set(good):
    # `required` false on the only set that names "age" and a required set on "pid".
    sets = [_opt(["pid"], required=True), _opt(["age"], required=False)]
    result = _run(_answers(good, ["pid"]), _dcql(sets))
    assert _counts(result, IDS) == {"pid": 1, "age": 0}


def test_control_an_omitted_required_means_true(good):
    # The default of §6.2 is true: omitted and spelled-out `true` behave the same, and
    # both differ from `false`.
    omitted, explicit = [_opt(["age"])], [_opt(["age"], required=True)]
    for sets in (omitted, explicit):
        with _exact(VpTokenIncomplete, r"does not satisfy credential_sets\[0\]"):
            _run(_answers(good, ["pid"]), _dcql(sets))
    optional = [_opt(["age"], required=False), _opt(["pid"])]
    assert _counts(_run(_answers(good, ["pid"]), _dcql(optional)), IDS)["pid"] == 1
