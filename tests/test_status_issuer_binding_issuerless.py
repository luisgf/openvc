"""
tests/test_status_issuer_binding_issuerless.py — an issuer-less status list is bound to
the signer it was verified for (#226, extending ADR-0006 and #221).

``VerificationPolicy(require_status_issuer_binding=True)`` compares the ``issuer`` named
in the resolved list's **body** with the credential's issuer. A status list secured as a
VC-JWT in the VCDM 1.1 JWT encoding may carry its issuer only in the JWT ``iss``: the
body has no ``issuer``, or an object with no ``id`` such as ``{"name": ...}``. The
pipeline authenticated that issuer (``result.issuer``), but the default resolvers returned
the body as it was, so the binding refused a list its own issuer had signed (fail-closed
interop, not a vulnerability). ``_authenticated_list`` now fills in the *verified signer*
where the body names no one, on a copy. Everything else is unchanged:

* a present identifier is compared with the signer, as #221 made it (``StatusListError``
  on a ``dc+sd-jwt`` list; the VC-JWT and ``vc+sd-jwt`` lanes reconcile ``iss`` and
  ``issuer`` first and raise ``ClaimsInvalid``);
* an attacker-signed issuer-less list gets the **attacker's** id filled in, so the binding
  still refuses it, naming the attacker, unless the attacker is allow-listed;
* ``_enforce_status_issuer`` and the contract of a custom ``resolve_status_list`` are not
  relaxed: an issuer-less body from a custom resolver still fails closed;
* the IETF Token Status List path binds on the token's ``iss`` and is unaffected, and a
  Data Integrity list cannot be issuer-less (``IssuerBindingError`` earlier).

Helpers are self-contained (tests/ is not a package: no cross-import). Issuers are
``did:jwk`` (resolved offline by the default resolvers) and, for the Data Integrity case,
``did:key``; ``asyncio.run`` drives the async pipeline (pytest-asyncio is not a
dependency). Hostile-input tests use a resolvable issuer and pin the exact error class.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
)
from openvc.aio import verify_many_async
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ClaimsInvalid
from openvc.resolvers import (
    _authenticated_list,
    default_status_list_resolver,
    default_status_list_resolver_async,
    default_status_list_token_resolver,
    default_status_list_token_resolver_async,
)
from openvc.status import CredentialRevoked, StatusListError
from openvc.status.bitstring import encode_bitstring, new_bitstring, set_status_bit
from openvc.status.token_status_list import encode_status_list, new_status_list, set_status
from openvc.verify import IssuerBindingError, StatusListIssuerUntrusted

V2 = "https://www.w3.org/ns/credentials/v2"
URL = "https://status.university.example/lists/1"
OTHER_URL = "https://status.university.example/lists/2"
TOKEN_URL = "https://status.university.example/tokens/1"
INDEX = 7
PIPELINES = ("sync", "async")
BINDING = VerificationPolicy(require_status_issuer_binding=True)
BINDING_WAIVED = VerificationPolicy(require_status_issuer_binding=True,
                                    require_not_revoked=False)
ABSENT = object()                    # the body carries no `issuer` member at all


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _party(label: str):
    key = P256SigningKey.generate(kid=label)
    return key, "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())


def _jws(key, did, header, body, tail=""):
    head = {"alg": "ES256", "kid": f"{did}#0", **header}
    signing_input = (f"{_b64(json.dumps(head).encode())}."
                     f"{_b64(json.dumps(body).encode())}")
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}{tail}"


VICTIM_KEY, VICTIM = _party("victim")
ATTACKER_KEY, ATTACKER = _party("attacker")
DELEGATE_KEY, DELEGATE = _party("delegate")
BYSTANDER = "did:jwk:bystander"


def _subject(url=URL, *, revoked=True):
    bits = new_bitstring(131072)
    if revoked:
        set_status_bit(bits, INDEX, 1)
    return {"id": url + "#list", "type": "BitstringStatusList", "statusPurpose": "revocation",
            "encodedList": encode_bitstring(bytes(bits))}


def _credential(key, did, url=URL):
    """A VC-JWT signed by *did*, whose `credentialStatus` points at *url*."""
    return _jws(key, did, {"typ": "vc+jwt"}, {"iss": did, "vc": {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
        "credentialSubject": {"id": "did:example:alice"},
        "credentialStatus": {"type": "BitstringStatusListEntry",
                             "statusPurpose": "revocation", "statusListIndex": str(INDEX),
                             "statusListCredential": url}}})


CREDENTIAL = _credential(VICTIM_KEY, VICTIM)


def vc_jwt_list(key, did, issuer=ABSENT, *, url=URL, revoked=True):
    vc = {"@context": [V2], "id": url, "credentialSubject": _subject(url, revoked=revoked),
          "type": ["VerifiableCredential", "BitstringStatusListCredential"]}
    if issuer is not ABSENT:
        vc["issuer"] = issuer
    return _jws(key, did, {"typ": "vc+jwt"}, {"iss": did, "vc": vc})


def dc_sd_jwt_list(key, did, issuer=ABSENT, *, url=URL, revoked=True):
    """An IETF SD-JWT VC list (`vct` is required): its `issuer` claim is nobody's but the
    signer's own vocabulary, and is not reconciled with `iss`."""
    body = {"iss": did, "vct": "urn:example:status-list",
            "credentialSubject": _subject(url, revoked=revoked)}
    if issuer is not ABSENT:
        body["issuer"] = issuer
    return _jws(key, did, {"typ": "dc+sd-jwt"}, body, "~")


def vcdm_sd_jwt_list(key, did, issuer=ABSENT, *, url=URL, revoked=True):
    body = {"@context": [V2], "iss": did, "id": url,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": _subject(url, revoked=revoked)}
    if issuer is not ABSENT:
        body["issuer"] = issuer
    return _jws(key, did, {"typ": "vc+sd-jwt"}, body, "~")


BUILDERS = {"vc-jwt": vc_jwt_list, "dc+sd-jwt": dc_sd_jwt_list,
            "vc+sd-jwt": vcdm_sd_jwt_list}
# The shapes that name no one: the issuer is absent, or an object without id / @id.
ISSUERLESS = {"absent": ABSENT, "name-only": {"name": "Example University"}}


def _lists(signer_key, signer):
    return {f"{lane}-{shape}": builder(signer_key, signer, issuer)
            for lane, builder in BUILDERS.items() for shape, issuer in ISSUERLESS.items()}


ATTACKER_LISTS = _lists(ATTACKER_KEY, ATTACKER)
VICTIM_LISTS = _lists(VICTIM_KEY, VICTIM)


def _verify(pipeline, served, policy=BINDING, *, credential=CREDENTIAL, **resolver_kw):
    if pipeline == "sync":
        return verify_credential(
            credential, policy=policy,
            resolve_status_list=default_status_list_resolver(
                fetch=lambda url: served, **resolver_kw))

    async def fetch(url):
        return served
    return asyncio.run(verify_credential_async(
        credential, policy=policy,
        resolve_status_list=default_status_list_resolver_async(fetch=fetch, **resolver_kw)))


def _resolved(pipeline, served):
    """What the default resolver hands the pipeline for *served*."""
    if pipeline == "sync":
        return default_status_list_resolver(fetch=lambda url: served)(URL)

    async def fetch(url):
        return served
    return asyncio.run(default_status_list_resolver_async(fetch=fetch)(URL))


def _exact(excinfo, cls):
    assert type(excinfo.value) is cls, (type(excinfo.value), str(excinfo.value))
    return excinfo.value


# --------------------------------------------------------------------------- #
# Still refused: a list signed by someone else is never the credential issuer's
# (these pass on the code before #226 too — they are the control)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", list(ATTACKER_LISTS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_attacker_signed_issuerless_list_is_untrusted(pipeline, name):
    with pytest.raises(StatusListIssuerUntrusted) as caught:
        _verify(pipeline, ATTACKER_LISTS[name])
    _exact(caught, StatusListIssuerUntrusted)


@pytest.mark.parametrize("name", list(ATTACKER_LISTS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_the_refusal_names_the_attacker_who_signed_it(pipeline, name):
    # The filled-in issuer is the one the list was verified for: the verdict is "this list
    # is the attacker's", not "this list names no one".
    expected = f"status list issuer {ATTACKER!r} is not the credential issuer {VICTIM!r}"
    with pytest.raises(StatusListIssuerUntrusted, match=re.escape(expected)) as caught:
        _verify(pipeline, ATTACKER_LISTS[name])
    _exact(caught, StatusListIssuerUntrusted)


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_victim_credential_cannot_be_cleared_by_an_attacker_list_with_a_decoy_name(pipeline):
    # An id-less object keeps its other members; none of them is read as an issuer.
    served = dc_sd_jwt_list(ATTACKER_KEY, ATTACKER, {"name": VICTIM, "url": VICTIM},
                            revoked=False)
    with pytest.raises(StatusListIssuerUntrusted, match=re.escape(repr(ATTACKER))) as caught:
        _verify(pipeline, served)
    _exact(caught, StatusListIssuerUntrusted)


# --------------------------------------------------------------------------- #
# Still refused (#221): a present identifier that is not the signer
# --------------------------------------------------------------------------- #

NAMES_THE_VICTIM = {
    "string": VICTIM,
    "id": {"id": VICTIM},
    "@id": {"@id": VICTIM},
    "id-with-members": {"id": VICTIM, "name": "Example University"},
    "name-with-@id": {"name": "Example University", "@id": VICTIM},
}


@pytest.mark.parametrize("shape", list(NAMES_THE_VICTIM))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_present_issuer_that_is_not_the_signer_is_refused(pipeline, shape):
    served = dc_sd_jwt_list(ATTACKER_KEY, ATTACKER, NAMES_THE_VICTIM[shape], revoked=False)
    with pytest.raises(StatusListError, match="but is signed by") as caught:
        _verify(pipeline, served)
    assert ATTACKER in str(caught.value)
    _exact(caught, StatusListError)


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_one_wrong_identifier_among_two_is_refused(pipeline):
    served = dc_sd_jwt_list(ATTACKER_KEY, ATTACKER, {"id": ATTACKER, "@id": VICTIM},
                            revoked=False)
    with pytest.raises(StatusListError, match="but is signed by") as caught:
        _verify(pipeline, served)
    _exact(caught, StatusListError)


@pytest.mark.parametrize("lane", ["vc-jwt", "vc+sd-jwt"])
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_w3c_list_that_names_another_issuer_never_gets_that_far(pipeline, lane):
    # The VC-JWT lane reconciles `iss` and `issuer` at verification (VC-JOSE-COSE §4.1.2),
    # and #221 gave a W3C `vc+sd-jwt` the same reconciliation: both raise `ClaimsInvalid`
    # from the inner verification, before `_authenticated_list` is reached (which is where
    # the `dc+sd-jwt` lane, with no such reconciliation, raises `StatusListError`).
    served = BUILDERS[lane](ATTACKER_KEY, ATTACKER, VICTIM, revoked=False)
    with pytest.raises(ClaimsInvalid, match="issuer") as caught:
        _verify(pipeline, served)
    _exact(caught, ClaimsInvalid)


# --------------------------------------------------------------------------- #
# Now accepted: the credential's own issuer signed the list, and says so only in `iss`
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", list(VICTIM_LISTS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_list_the_credential_issuer_signed_is_bound_and_its_bit_is_read(pipeline, name):
    with pytest.raises(CredentialRevoked) as caught:
        _verify(pipeline, VICTIM_LISTS[name])
    _exact(caught, CredentialRevoked)


@pytest.mark.parametrize("name", list(VICTIM_LISTS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_the_waived_verdict_carries_the_revoked_status(pipeline, name):
    result = _verify(pipeline, VICTIM_LISTS[name], BINDING_WAIVED)
    assert result.issuer == VICTIM
    assert result.status is not None and result.status.revoked is True


@pytest.mark.parametrize("lane", list(BUILDERS))
@pytest.mark.parametrize("shape", list(ISSUERLESS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_clear_bit_verifies_under_the_binding(pipeline, shape, lane):
    served = BUILDERS[lane](VICTIM_KEY, VICTIM, ISSUERLESS[shape], revoked=False)
    result = _verify(pipeline, served)
    assert result.issuer == VICTIM
    assert result.status is not None and result.status.revoked is False


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_an_issuer_less_list_passes_with_the_resolvers_expected_issuer(pipeline):
    # `expected_issuer` is a skip-work pre-check on the claimed issuer; it never admits a
    # list, and an issuer-less one still reaches the authenticated binding.
    result = _verify(pipeline, VICTIM_LISTS["vc-jwt-absent"], BINDING_WAIVED,
                     expected_issuer=VICTIM)
    assert result.status is not None and result.status.revoked is True
    with pytest.raises(StatusListError, match="does not match expected issuer") as caught:
        _verify(pipeline, ATTACKER_LISTS["vc-jwt-absent"], BINDING_WAIVED,
                expected_issuer=VICTIM)
    _exact(caught, StatusListError)


# --------------------------------------------------------------------------- #
# Delegation: an allow-listed signer is admitted, any other is not
# --------------------------------------------------------------------------- #

DELEGATE_LISTS = _lists(DELEGATE_KEY, DELEGATE)


@pytest.mark.parametrize("name", list(DELEGATE_LISTS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_an_allow_listed_delegate_may_sign_an_issuerless_list(pipeline, name):
    policy = VerificationPolicy(require_status_issuer_binding=True, require_not_revoked=False,
                                status_issuer_allowlist=frozenset({DELEGATE}))
    result = _verify(pipeline, DELEGATE_LISTS[name], policy)
    assert result.issuer == VICTIM
    assert result.status is not None and result.status.revoked is True


@pytest.mark.parametrize("name", list(DELEGATE_LISTS))
@pytest.mark.parametrize("allow", [None, frozenset(), frozenset({BYSTANDER}),
                                   frozenset({ATTACKER})], ids=["none", "empty", "other",
                                                                "attacker"])
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_the_same_list_without_the_delegate_allow_listed_is_untrusted(pipeline, name, allow):
    policy = VerificationPolicy(require_status_issuer_binding=True, require_not_revoked=False,
                                status_issuer_allowlist=allow)
    with pytest.raises(StatusListIssuerUntrusted, match=re.escape(repr(DELEGATE))) as caught:
        _verify(pipeline, DELEGATE_LISTS[name], policy)
    _exact(caught, StatusListIssuerUntrusted)


# --------------------------------------------------------------------------- #
# Shape preserved, nothing mutated
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("pipeline", PIPELINES)
def test_the_resolved_body_gets_the_signer_as_its_issuer(pipeline):
    body = _resolved(pipeline, VICTIM_LISTS["vc-jwt-absent"])
    assert body["issuer"] == VICTIM


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_an_id_less_issuer_object_keeps_its_members_and_gains_the_id(pipeline):
    body = _resolved(pipeline, vc_jwt_list(VICTIM_KEY, VICTIM, {"name": "Uni"}))
    assert body["issuer"] == {"name": "Uni", "id": VICTIM}
    assert body["credentialSubject"]["statusPurpose"] == "revocation"


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_body_that_names_the_signer_is_returned_as_it_is(pipeline):
    body = _resolved(pipeline, vc_jwt_list(VICTIM_KEY, VICTIM, {"id": VICTIM, "name": "Uni"}))
    assert body["issuer"] == {"id": VICTIM, "name": "Uni"}
    assert _resolved(pipeline, vc_jwt_list(VICTIM_KEY, VICTIM, VICTIM))["issuer"] == VICTIM


def _fake_result(credential, issuer):
    return SimpleNamespace(credential=credential, issuer=issuer)


def test_the_verified_claim_set_is_never_written_to():
    absent = {"type": ["VerifiableCredential"], "credentialSubject": {"x": 1}}
    result = _fake_result(absent, VICTIM)
    returned = _authenticated_list(result)
    assert returned is not absent
    assert returned == {**absent, "issuer": VICTIM}
    assert absent == {"type": ["VerifiableCredential"], "credentialSubject": {"x": 1}}

    named = {"issuer": {"name": "Uni"}, "credentialSubject": {"x": 1}}
    result = _fake_result(named, VICTIM)
    returned = _authenticated_list(result)
    assert returned is not named
    assert returned["issuer"] == {"name": "Uni", "id": VICTIM}
    assert returned["issuer"] is not named["issuer"]
    assert named == {"issuer": {"name": "Uni"}, "credentialSubject": {"x": 1}}


def test_a_body_with_an_identifier_is_the_same_object():
    for issuer in (VICTIM, {"id": VICTIM}, {"@id": VICTIM}, {"id": VICTIM, "@id": VICTIM}):
        credential = {"issuer": issuer}
        assert _authenticated_list(_fake_result(credential, VICTIM)) is credential
        assert credential == {"issuer": issuer}


def test_an_at_id_only_issuer_is_left_to_the_binding_as_before():
    # `{"@id": <signer>}` names the signer, so the body is returned untouched; the binding
    # reads `id` only and still fails it closed. Nothing here fills `id` in beside `@id`.
    # This is a known interop gap, left on purpose (CHANGELOG 1.35.0): the end-to-end
    # consequence is pinned below.
    body = _authenticated_list(_fake_result({"issuer": {"@id": VICTIM}}, VICTIM))
    assert body == {"issuer": {"@id": VICTIM}}


@pytest.mark.parametrize("lane", list(BUILDERS))
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_an_at_id_only_issuer_is_still_refused_under_the_binding(pipeline, lane):
    # The victim itself signed this list and the body names the victim, by `@id` alone. The
    # binding reads `id`, and `_authenticated_list` has nothing to fill in (the body names
    # someone), so it fails closed, as it did before #226. Changing that is a decision, not
    # a side effect: if `@id` is ever read or copied into `id`, this test changes with it.
    served = BUILDERS[lane](VICTIM_KEY, VICTIM, {"@id": VICTIM})
    # Control: the list is valid and the victim's own, so without the binding its bit is read.
    with pytest.raises(CredentialRevoked) as read:
        _verify(pipeline, served, VerificationPolicy())
    _exact(read, CredentialRevoked)
    with pytest.raises(StatusListIssuerUntrusted, match="no issuer to bind against") as caught:
        _verify(pipeline, served)
    _exact(caught, StatusListIssuerUntrusted)


@pytest.mark.parametrize("signer", [None, "", 5, ["did:ex:a"], {"id": "did:ex:a"}],
                         ids=["none", "empty", "int", "list", "dict"])
def test_a_signer_that_is_no_identity_is_never_filled_in(signer):
    absent = {"x": 1}
    assert _authenticated_list(_fake_result(absent, signer)) is absent
    assert "issuer" not in absent
    named = {"issuer": {"name": "Uni"}}
    assert _authenticated_list(_fake_result(named, signer)) is named
    assert named == {"issuer": {"name": "Uni"}}


@pytest.mark.parametrize("issuer", [
    None, "", 0, False, [], [VICTIM], {"id": None}, {"id": ""}, {"id": 5}, {"@id": 5},
    {"id": [VICTIM]}, {"id": {"id": VICTIM}}, {"@id": [[VICTIM]]},
    {"id": VICTIM, "@id": "did:ex:other"},
], ids=repr)
def test_a_hostile_issuer_shape_is_a_typed_refusal(issuer):
    # Every one of these carries an identifier that is not the signer (or a value that
    # identifies no one, as `issuer_identifiers` reads it): a typed error, not a TypeError.
    secured = {"issuer": issuer}
    snapshot = json.dumps(secured, sort_keys=True)
    with pytest.raises(StatusListError, match="but is signed by") as caught:
        _authenticated_list(_fake_result(secured, VICTIM))
    _exact(caught, StatusListError)
    assert json.dumps(secured, sort_keys=True) == snapshot


def test_a_deeply_nested_id_less_issuer_is_filled_without_recursing_into_it():
    nest: dict = {}
    for _ in range(5000):
        nest = {"n": nest}
    credential = {"issuer": {"name": nest}}
    returned = _authenticated_list(_fake_result(credential, VICTIM))
    assert returned["issuer"]["id"] == VICTIM
    assert returned["issuer"]["name"] is nest
    assert "id" not in credential["issuer"]


# --------------------------------------------------------------------------- #
# A custom resolver keeps today's contract: the binding is not relaxed
# --------------------------------------------------------------------------- #

def _issuerless_body(issuer=ABSENT):
    body = {"type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": {"statusPurpose": "revocation",
                                  "encodedList": _subject()["encodedList"]}}
    if issuer is not ABSENT:
        body["issuer"] = issuer
    return body


@pytest.mark.parametrize("issuer", [ABSENT, {"name": "Uni"}, {}, None, ""],
                         ids=["absent", "name-only", "empty-object", "null", "empty-string"])
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_custom_resolver_that_returns_an_issuerless_body_still_fails_closed(pipeline, issuer):
    body = _issuerless_body(issuer)
    if pipeline == "sync":
        def call():
            return verify_credential(CREDENTIAL, policy=BINDING,
                                     resolve_status_list=lambda url: body)
    else:
        async def resolve(url):
            return body

        def call():
            return asyncio.run(verify_credential_async(
                CREDENTIAL, policy=BINDING, resolve_status_list=resolve))
    with pytest.raises(StatusListIssuerUntrusted, match="no issuer to bind against") as caught:
        call()
    _exact(caught, StatusListIssuerUntrusted)


# --------------------------------------------------------------------------- #
# No binding: every row behaves as it did (the bit is read, the issuer is not asked)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", list(VICTIM_LISTS))
@pytest.mark.parametrize("who", ["victim", "attacker"])
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_without_the_binding_the_bit_is_read_whoever_signed(pipeline, who, name):
    served = (VICTIM_LISTS if who == "victim" else ATTACKER_LISTS)[name]
    with pytest.raises(CredentialRevoked) as caught:
        _verify(pipeline, served, VerificationPolicy())
    _exact(caught, CredentialRevoked)
    result = _verify(pipeline, served, VerificationPolicy(require_not_revoked=False))
    assert result.status is not None and result.status.revoked is True


# --------------------------------------------------------------------------- #
# The IETF Token Status List path binds on `iss` and is unaffected
# --------------------------------------------------------------------------- #

def _token_credential():
    return _jws(VICTIM_KEY, VICTIM, {"typ": "vc+jwt"}, {
        "iss": VICTIM, "status": {"status_list": {"idx": INDEX, "uri": TOKEN_URL}},
        "vc": {"@context": [V2], "type": ["VerifiableCredential"], "issuer": VICTIM,
               "credentialSubject": {"id": "did:example:alice"}}})


def _status_token(key, did):
    packed = new_status_list(1024)
    set_status(packed, INDEX, 1)
    return _jws(key, did, {"typ": "statuslist+jwt"}, {
        "iss": did, "sub": TOKEN_URL, "iat": int(time.time()),
        "status_list": {"bits": 1, "lst": encode_status_list(bytes(packed))}})


def _verify_token(pipeline, served, policy):
    credential = _token_credential()
    if pipeline == "sync":
        return verify_credential(
            credential, policy=policy,
            resolve_status_list_token=default_status_list_token_resolver(
                fetch=lambda uri: served))

    async def fetch(uri):
        return served
    return asyncio.run(verify_credential_async(
        credential, policy=policy,
        resolve_status_list_token=default_status_list_token_resolver_async(fetch=fetch)))


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_token_the_credential_issuer_signed_is_read(pipeline):
    result = _verify_token(pipeline, _status_token(VICTIM_KEY, VICTIM), BINDING_WAIVED)
    assert result.status is not None and result.status.revoked is True


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_token_another_issuer_signed_is_untrusted(pipeline):
    expected = f"status list issuer {ATTACKER!r} is not the credential issuer {VICTIM!r}"
    with pytest.raises(StatusListIssuerUntrusted, match=re.escape(expected)) as caught:
        _verify_token(pipeline, _status_token(ATTACKER_KEY, ATTACKER), BINDING_WAIVED)
    _exact(caught, StatusListIssuerUntrusted)


# --------------------------------------------------------------------------- #
# A Data Integrity list cannot be issuer-less: the lane refuses it earlier
# --------------------------------------------------------------------------- #

def _did_key():
    private = ed25519.Ed25519PrivateKey.generate()
    raw = base64.urlsafe_b64decode(Ed25519SigningKey(private, kid="t").public_jwk()["x"] + "==")
    did = "did:key:" + encode_multibase(bytes([0xED, 0x01]) + raw)
    vm = f"{did}#{did[len('did:key:'):]}"
    return Ed25519SigningKey(private, kid=vm), did, vm


def _di(key, vm, document):
    return json.dumps(EddsaJcsProofSuite().add_proof(document, signing_key=key,
                                                     verification_method=vm))


def _di_list(key, vm, issuer=ABSENT):
    document = {"@context": [V2], "id": URL, "validFrom": "2020-01-01T00:00:00Z",
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "credentialSubject": _subject()}
    if issuer is not ABSENT:
        document["issuer"] = issuer
    return _di(key, vm, document)


def _di_credential(key, did, vm):
    return json.loads(_di(key, vm, {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
        "validFrom": "2020-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:alice"},
        "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
                             "statusListIndex": str(INDEX), "statusListCredential": URL}}))


@pytest.mark.parametrize("issuer", [ABSENT, {"name": "Example University"}],
                         ids=["absent", "name-only"])
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_an_issuerless_data_integrity_list_is_never_resolved(pipeline, issuer):
    key, did, vm = _did_key()
    with pytest.raises(IssuerBindingError, match="no issuer to bind the key to") as caught:
        _verify(pipeline, _di_list(key, vm, issuer), credential=_di_credential(key, did, vm))
    _exact(caught, IssuerBindingError)


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_data_integrity_list_that_names_its_signer_is_still_read(pipeline):
    key, did, vm = _did_key()
    with pytest.raises(CredentialRevoked) as caught:
        _verify(pipeline, _di_list(key, vm, did), credential=_di_credential(key, did, vm))
    _exact(caught, CredentialRevoked)


# --------------------------------------------------------------------------- #
# verify_many / verify_many_async: each item gets its own outcome
# --------------------------------------------------------------------------- #

def _served_by_url(lists):
    def fetch(url):
        return lists[url]

    async def fetch_async(url):
        return lists[url]
    return fetch, fetch_async


def _batch(pipeline, credentials, lists):
    fetch, fetch_async = _served_by_url(lists)
    if pipeline == "sync":
        return verify_many(credentials, policy=BINDING_WAIVED,
                           resolve_status_list=default_status_list_resolver(fetch=fetch))
    return asyncio.run(verify_many_async(
        credentials, policy=BINDING_WAIVED,
        resolve_status_list=default_status_list_resolver_async(fetch=fetch_async)))


@pytest.mark.parametrize("flip", [False, True], ids=["victim-first", "attacker-first"])
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_batch_binds_each_item_to_its_own_credential_issuer(pipeline, flip):
    lists = {
        URL: vc_jwt_list(VICTIM_KEY, VICTIM, url=URL),                   # issuer-less, victim's
        OTHER_URL: vc_jwt_list(ATTACKER_KEY, ATTACKER, url=OTHER_URL),   # issuer-less, attacker's
    }
    items = [
        ("victim credential, victim list", _credential(VICTIM_KEY, VICTIM, URL)),
        ("victim credential, attacker list", _credential(VICTIM_KEY, VICTIM, OTHER_URL)),
        ("attacker credential, victim list", _credential(ATTACKER_KEY, ATTACKER, URL)),
    ]
    if flip:
        items.reverse()
    outcomes = _batch(pipeline, [credential for _, credential in items], lists)
    assert [o.index for o in outcomes] == [0, 1, 2]
    by_label = {label: outcome for (label, _), outcome in zip(items, outcomes)}

    ok = by_label["victim credential, victim list"]
    assert ok.error is None and ok.result is not None
    assert ok.result.issuer == VICTIM and ok.result.status.revoked is True

    wrong_list = by_label["victim credential, attacker list"]
    assert type(wrong_list.error) is StatusListIssuerUntrusted
    assert f"status list issuer {ATTACKER!r} is not the credential issuer {VICTIM!r}" \
        in str(wrong_list.error)

    wrong_credential = by_label["attacker credential, victim list"]
    assert type(wrong_credential.error) is StatusListIssuerUntrusted
    assert f"status list issuer {VICTIM!r} is not the credential issuer {ATTACKER!r}" \
        in str(wrong_credential.error)


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_a_batch_shares_one_filled_list_between_items_that_point_at_it(pipeline):
    lists = {URL: vc_jwt_list(VICTIM_KEY, VICTIM, {"name": "Uni"}, url=URL)}
    outcomes = _batch(pipeline, [_credential(VICTIM_KEY, VICTIM, URL)] * 3, lists)
    assert [o.index for o in outcomes] == [0, 1, 2]
    assert all(o.error is None and o.result.status.revoked is True for o in outcomes)
