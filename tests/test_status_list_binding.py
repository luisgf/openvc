"""
tests/test_status_list_binding.py — a resolved W3C status list is bound to the entry
that named it (#377).

After a status list's proof verifies, the check used to read only
``credentialSubject.encodedList`` (and ``statusPurpose`` when present). Nothing compared
the list's ``id`` with the entry's ``statusListCredential``, and nothing required the
list's ``type`` or its ``credentialSubject.type`` (Bitstring Status List v1.0 §2.1, §2.2
MUSTs). The IETF lane pins its token to the fetched URI (``sub == uri``); the W3C lane
had no counterpart, and the issuer binding of ADR-0006 proves who signed a list, not
which list it is. So another list of the same issuer, served at the entry's URL, read
as the entry's list — with ``require_status_issuer_binding=True`` on.

Now the list's types must be the entry family's, and its ``id``, when it carries one,
must equal the entry's URL. A VC-JWT list in the VCDM 1.1 JWT encoding carries its id
only in ``jti``: the default resolvers surface it as ``id`` so that shape is bound too.
A list with no ``id`` at all stays bound by issuer and types only (the documented
residual, ADR-0006 addendum).

Every list here is a real VC-JWT signed by a ``did:jwk`` issuer and resolved through
the blessed resolvers, so each refusal is of a list whose signature verified.
"""
from __future__ import annotations

import asyncio
import base64
import json

import pytest

from openvc import VerificationPolicy, verify_credential
from openvc.aio import verify_credential_async
from openvc.keys import P256SigningKey
from openvc.resolvers import (
    default_status_list_resolver,
    default_status_list_resolver_async,
)
from openvc.status import (
    CredentialRevoked,
    StatusListError,
    check_credential_status,
    check_credential_status_async,
    encode_bitstring,
    new_bitstring,
    parse_status_entries,
    set_status_bit,
)

V2 = "https://www.w3.org/ns/credentials/v2"
LIST_URL = "https://status.university.example/lists/1"
LIST_URL_B = "https://status.university.example/lists/2"
INDEX = 7
BIND = VerificationPolicy(require_status_issuer_binding=True)

BITSTRING = ("BitstringStatusListEntry", "BitstringStatusListCredential", "BitstringStatusList")
LEGACY = ("StatusList2021Entry", "StatusList2021Credential", "StatusList2021")


# --------------------------------------------------------------------------- #
# helpers: a did:jwk issuer, hand-built VC-JWTs (so a list can carry its id in `jti` only)
# --------------------------------------------------------------------------- #

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _party():
    key = P256SigningKey.generate(kid="issuer")
    return key, "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())


def _jws(key, did, body: dict) -> str:
    head = {"alg": "ES256", "kid": f"{did}#0", "typ": "vc+jwt"}
    signing_input = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(body).encode())}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"


KEY, DID = _party()


def _entry(url: str = LIST_URL, *, entry_type: str = BITSTRING[0]) -> dict:
    return {"type": entry_type, "statusPurpose": "revocation",
            "statusListIndex": str(INDEX), "statusListCredential": url}


def _credential(entry: dict) -> str:
    """A VC-JWT signed by the issuer whose credentialStatus is *entry*."""
    return _jws(KEY, DID, {"iss": DID, "vc": {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
        "credentialSubject": {"id": "did:example:alice"}, "credentialStatus": entry}})


def _subject(url: str, *, revoked: bool, subject_type=BITSTRING[2]) -> dict:
    bits = new_bitstring(131072)
    if revoked:
        set_status_bit(bits, INDEX, 1)
    subject = {"id": url + "#list", "statusPurpose": "revocation",
               "encodedList": encode_bitstring(bytes(bits))}
    if subject_type is not None:
        subject["type"] = subject_type
    return subject


_ABSENT = object()


def _list(url: str = LIST_URL, *, revoked: bool = True, list_id=_ABSENT,
          types=_ABSENT, subject_type=BITSTRING[2], issuer=DID) -> dict:
    """An unsigned status-list credential: by default a conformant list whose ``id`` is
    *url*. ``list_id=None`` leaves the credential with no ``id``."""
    vc = {"@context": [V2], "issuer": issuer,
          "type": (["VerifiableCredential", BITSTRING[1]] if types is _ABSENT else types),
          "credentialSubject": _subject(url, revoked=revoked, subject_type=subject_type)}
    if types is None:
        del vc["type"]
    if list_id is _ABSENT:
        vc["id"] = url
    elif list_id is not None:
        vc["id"] = list_id
    return vc


def _signed_list(vc: dict, *, jti=None) -> str:
    """*vc* as a VC-JWT; *jti* sets the envelope's ``jti`` (the VCDM 1.1 JWT encoding
    carries the credential's id there)."""
    body = {"iss": DID, "vc": vc}
    if jti is not None:
        body["jti"] = jti
    return _jws(KEY, DID, body)


def _served(text: str):
    """A fetch that serves *text* whatever URL is asked, as a hostile status host does."""
    return lambda url: text


def _served_async(text: str):
    async def fetch(url: str) -> str:
        return text
    return fetch


def _verify(credential: str, served: str, policy=BIND):
    return verify_credential(
        credential, policy=policy,
        resolve_status_list=default_status_list_resolver(fetch=_served(served)))


def _verify_async(credential: str, served: str, policy=BIND):
    return asyncio.run(verify_credential_async(
        credential, policy=policy,
        resolve_status_list=default_status_list_resolver_async(fetch=_served_async(served))))


def _check(entry: dict, resolved) -> bool:
    """The pure check: the bit the resolved object yields for *entry*."""
    return check_credential_status({"credentialStatus": entry},
                                   resolve_status_list=lambda url: resolved).revoked


def _check_async(entry: dict, resolved) -> bool:
    async def resolve(url: str):
        return resolved
    return asyncio.run(check_credential_status_async(
        {"credentialStatus": entry}, resolve_status_list=resolve)).revoked


# --------------------------------------------------------------------------- #
# the swap: another list of the same issuer, served at the entry's URL
# --------------------------------------------------------------------------- #

LIST_A = _signed_list(_list(LIST_URL, revoked=True))         # the entry's list: bit set
LIST_B = _signed_list(_list(LIST_URL_B, revoked=False))      # the issuer's other list: clear
CREDENTIAL = _credential(_entry(LIST_URL))


def test_control_the_entry_list_at_its_url_is_read_and_revokes():
    with pytest.raises(CredentialRevoked):
        _verify(CREDENTIAL, LIST_A)
    with pytest.raises(CredentialRevoked):
        _verify_async(CREDENTIAL, LIST_A)


def test_another_list_of_the_same_issuer_at_the_entry_url_is_refused():
    """The advisory's swap: list B (id /lists/2, same signer, bit clear) served at
    /lists/1 cleared the revocation under require_status_issuer_binding=True."""
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify(CREDENTIAL, LIST_B)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify_async(CREDENTIAL, LIST_B)
    # the binding off changes nothing here: the id rule is the status check's, not the policy's
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify(CREDENTIAL, LIST_B, policy=VerificationPolicy())


def test_the_pure_check_refuses_the_swapped_list_on_both_pipelines():
    swapped = _list(LIST_URL_B, revoked=False)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _check(_entry(LIST_URL), swapped)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _check_async(_entry(LIST_URL), swapped)
    assert _check(_entry(LIST_URL_B), swapped) is False          # at its own URL it reads


@pytest.mark.parametrize("list_id", [5, ["https://status.university.example/lists/1"],
                                     {"id": LIST_URL}, None, ""],
                         ids=["int", "array", "object", "null", "empty"])
def test_a_present_id_that_is_not_the_url_string_is_refused(list_id):
    # A present `id` of another shape is malformed, never "no id": an array or an object
    # must not fall into the id-less residual.
    vc = _list(LIST_URL, revoked=False, list_id=None)
    vc["id"] = list_id
    with pytest.raises(StatusListError, match="status-list credential id"):
        _check(_entry(LIST_URL), vc)


def test_the_message_is_bounded_whatever_the_id_is():
    vc = _list(LIST_URL, revoked=False, list_id="https://evil.example/" + "x" * 100_000)
    with pytest.raises(StatusListError) as excinfo:
        _check(_entry(LIST_URL), vc)
    assert len(str(excinfo.value)) < 200


def test_ids_are_compared_as_strings_without_normalisation():
    for variant in (LIST_URL + "/", LIST_URL.upper(), LIST_URL + "#list", " " + LIST_URL):
        with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
            _check(_entry(LIST_URL), _list(LIST_URL, revoked=False, list_id=variant))


# --------------------------------------------------------------------------- #
# the types: a verified credential with an encodedList is not thereby a status list
# --------------------------------------------------------------------------- #

def test_a_credential_typed_only_verifiable_credential_is_refused():
    plain = _signed_list(_list(LIST_URL, revoked=False, types=["VerifiableCredential"]))
    with pytest.raises(StatusListError, match="needs type BitstringStatusListCredential"):
        _verify(CREDENTIAL, plain)
    with pytest.raises(StatusListError, match="needs type BitstringStatusListCredential"):
        _verify_async(CREDENTIAL, plain)


@pytest.mark.parametrize("types", [
    None, ["VerifiableCredential"], ["VerifiableCredential", "AlumniCredential"],
    "VerifiableCredential", [], 5, {"BitstringStatusListCredential": True},
    [5, None], ["BitstringStatusListCredential "], "BitstringStatusListCredential\u0000",
], ids=["absent", "vc-only", "other", "string", "empty", "int", "object-keys",
        "non-strings", "trailing-space", "nul"])
def test_a_list_without_the_credential_type_is_refused(types):
    with pytest.raises(StatusListError, match="needs type BitstringStatusListCredential"):
        _check(_entry(LIST_URL), _list(LIST_URL, revoked=False, types=types))


@pytest.mark.parametrize("subject_type", [None, "Other", ["Other"], 5, {"a": 1}, [None], ""],
                         ids=["absent", "other", "other-array", "int", "object", "null-member",
                              "empty"])
def test_a_subject_without_the_subject_type_is_refused(subject_type):
    with pytest.raises(StatusListError, match="needs type BitstringStatusList,"):
        _check(_entry(LIST_URL), _list(LIST_URL, revoked=False, subject_type=subject_type))


def test_a_subject_without_the_subject_type_is_refused_end_to_end():
    served = _signed_list(_list(LIST_URL, revoked=False, subject_type=None,
                                types=["VerifiableCredential", "AlumniCredential"]))
    with pytest.raises(StatusListError, match="needs type"):
        _verify(CREDENTIAL, served)


def test_an_entry_of_one_family_does_not_read_a_list_of_the_other():
    bitstring_list = _list(LIST_URL, revoked=True)
    legacy_list = _list(LIST_URL, revoked=True, types=["VerifiableCredential", LEGACY[1]],
                        subject_type=LEGACY[2])
    with pytest.raises(StatusListError, match="for a StatusList2021Entry needs type"):
        _check(_entry(LIST_URL, entry_type=LEGACY[0]), bitstring_list)
    with pytest.raises(StatusListError, match="for a BitstringStatusListEntry needs type"):
        _check(_entry(LIST_URL, entry_type=BITSTRING[0]), legacy_list)
    # a list typed with both families' credential types but one subject type is still
    # refused for the other family: both MUSTs are checked
    both = _list(LIST_URL, revoked=True, types=["VerifiableCredential", BITSTRING[1], LEGACY[1]])
    with pytest.raises(StatusListError, match="credentialSubject for a StatusList2021Entry"):
        _check(_entry(LIST_URL, entry_type=LEGACY[0]), both)


def test_the_shape_checks_still_come_first():
    # the messages the message-helper battery pins are unchanged: an unreadable shape
    # is reported before the types are looked at
    with pytest.raises(StatusListError, match="must be an object"):
        _check(_entry(LIST_URL), "a string")
    with pytest.raises(StatusListError, match="has no credentialSubject"):
        _check(_entry(LIST_URL), {"id": LIST_URL})
    with pytest.raises(StatusListError, match="purpose"):
        _check(_entry(LIST_URL), {"credentialSubject": {"statusPurpose": "suspension",
                                                        "encodedList": "u"}})
    with pytest.raises(StatusListError, match="has no encodedList string"):
        _check(_entry(LIST_URL), {"credentialSubject": {"statusPurpose": "revocation"}})


# --------------------------------------------------------------------------- #
# what is still accepted
# --------------------------------------------------------------------------- #

def test_the_id_carried_in_jti_only_is_surfaced_and_bound():
    """A VCDM 1.1 VC-JWT list keeps its id in `jti`; the lane never copies it into
    `vc.id`, so the default resolvers do, on a copy, and the check binds it."""
    bound = _signed_list(_list(LIST_URL, revoked=False, list_id=None), jti=LIST_URL)
    assert _verify(CREDENTIAL, bound).status.revoked is False
    assert _verify_async(CREDENTIAL, bound).status.revoked is False
    resolved = default_status_list_resolver(fetch=_served(bound))(LIST_URL)
    assert resolved["id"] == LIST_URL
    resolved_async = asyncio.run(
        default_status_list_resolver_async(fetch=_served_async(bound))(LIST_URL))
    assert resolved_async["id"] == LIST_URL

    swapped = _signed_list(_list(LIST_URL_B, revoked=False, list_id=None), jti=LIST_URL_B)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify(CREDENTIAL, swapped)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify_async(CREDENTIAL, swapped)


def test_a_present_id_is_not_overwritten_by_jti():
    # the lane refuses a jti that differs from vc.id (ClaimsInvalid) before the status
    # check sees the list; an equal one is simply redundant
    agreeing = _signed_list(_list(LIST_URL, revoked=False), jti=LIST_URL)
    assert _verify(CREDENTIAL, agreeing).status.revoked is False
    assert default_status_list_resolver(fetch=_served(agreeing))(LIST_URL)["id"] == LIST_URL
    with pytest.raises(Exception):                               # ClaimsInvalid, the lane's
        _verify(CREDENTIAL, _signed_list(_list(LIST_URL, revoked=False), jti=LIST_URL_B))


def test_a_list_with_no_id_at_all_is_accepted_bound_by_issuer_and_types():
    # the documented residual (ADR-0006 addendum): neither vc.id nor jti
    idless = _signed_list(_list(LIST_URL, revoked=False, list_id=None))
    assert _verify(CREDENTIAL, idless).status.revoked is False
    assert "id" not in default_status_list_resolver(fetch=_served(idless))(LIST_URL)
    assert _check(_entry(LIST_URL), _list(LIST_URL, revoked=True, list_id=None)) is True


@pytest.mark.parametrize("jti", [5, "", None, [LIST_URL]], ids=["int", "empty", "null", "array"])
def test_a_jti_that_is_no_identifier_fills_nothing_in(jti):
    # not a string, or empty: the body stays id-less rather than gaining a non-URL id
    body = {"iss": DID, "vc": _list(LIST_URL, revoked=False, list_id=None), "jti": jti}
    served = _jws(KEY, DID, body)
    try:
        resolved = default_status_list_resolver(fetch=_served(served))(LIST_URL)
    except Exception as exc:                                   # the lane may refuse the jti
        assert type(exc).__name__ in {"ClaimsInvalid", "MalformedToken"}, exc
        return
    assert "id" not in resolved


def test_the_statuslist2021_spellings_are_accepted_for_a_legacy_entry():
    legacy_entry = _entry(LIST_URL, entry_type=LEGACY[0])
    legacy_list = _list(LIST_URL, revoked=True, types=["VerifiableCredential", LEGACY[1]],
                        subject_type=LEGACY[2])
    assert _check(legacy_entry, legacy_list) is True
    assert _check_async(legacy_entry, legacy_list) is True
    with pytest.raises(CredentialRevoked):
        _verify(_credential(legacy_entry), _signed_list(legacy_list))
    # and the swap is refused on this family too
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _check(legacy_entry, _list(LIST_URL_B, revoked=False,
                                   types=["VerifiableCredential", LEGACY[1]],
                                   subject_type=LEGACY[2]))


def test_type_as_a_bare_string_and_subject_type_as_an_array_are_accepted():
    vc = _list(LIST_URL, revoked=True, types="BitstringStatusListCredential",
               subject_type=["BitstringStatusList"])
    assert _check(_entry(LIST_URL), vc) is True
    # an unrelated extra type on either side does not matter
    vc = _list(LIST_URL, revoked=True, types=["VerifiableCredential", "Other", BITSTRING[1]],
               subject_type=["Other", BITSTRING[2]])
    assert _check(_entry(LIST_URL), vc) is True


def test_an_entry_carrying_both_recognised_types_reads_as_a_bitstring_entry():
    # deterministic, whatever the process's set order
    entries = parse_status_entries({"credentialStatus": dict(
        _entry(LIST_URL), type=["StatusList2021Entry", "BitstringStatusListEntry"])})
    assert [e.entry_type for e in entries] == ["BitstringStatusListEntry"]
    assert _check(dict(_entry(LIST_URL), type=["StatusList2021Entry", "BitstringStatusListEntry"]),
                  _list(LIST_URL, revoked=True)) is True


def test_a_builder_list_verifies_at_its_own_url_and_nowhere_else():
    from openvc.proof.vc_jwt import VcJwtProofSuite
    from openvc.status import build_status_list_credential, build_status_list_entry

    bits = new_bitstring(64)
    set_status_bit(bits, INDEX, 1)
    signer = P256SigningKey(KEY._sk, kid=f"{DID}#0")  # the suite signs with the kid
    built = VcJwtProofSuite().sign(
        build_status_list_credential(id=LIST_URL, issuer=DID, bitstring=bits), signing_key=signer)
    entry = build_status_list_entry(status_list_credential=LIST_URL, index=INDEX)
    with pytest.raises(CredentialRevoked):
        _verify(_credential(entry), built)
    other = build_status_list_entry(status_list_credential=LIST_URL_B, index=INDEX)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify(_credential(other), built)


# --------------------------------------------------------------------------- #
# review F4: the list id under its JSON-LD spelling `@id`
# --------------------------------------------------------------------------- #

def test_an_id_spelled_at_id_is_read_as_the_list_id():
    # `@id` is what `id` aliases in JSON-LD; read as "no id" it dropped the binding
    swapped = _list(LIST_URL_B, revoked=False, list_id=None)
    swapped["@id"] = LIST_URL_B
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _check(_entry(LIST_URL), swapped)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify(CREDENTIAL, _signed_list(swapped))
    named = _list(LIST_URL, revoked=True, list_id=None)
    named["@id"] = LIST_URL
    assert _check(_entry(LIST_URL), named) is True
    with pytest.raises(StatusListError, match="status-list credential id"):
        _check(_entry(LIST_URL), dict(named, **{"@id": 5}))


def test_id_and_at_id_together_must_agree():
    agreeing = _list(LIST_URL, revoked=True)
    agreeing["@id"] = LIST_URL
    assert _check(_entry(LIST_URL), agreeing) is True
    disagreeing = _list(LIST_URL, revoked=True)
    disagreeing["@id"] = LIST_URL_B
    with pytest.raises(StatusListError, match="id .* != @id"):
        _check(_entry(LIST_URL), disagreeing)
    with pytest.raises(StatusListError, match="id .* != @id"):
        _check(_entry(LIST_URL_B), disagreeing)         # whichever URL the entry names


def test_jti_is_reconciled_with_an_at_id_too():
    from openvc.proof.errors import ClaimsInvalid
    body = _list(LIST_URL, revoked=False, list_id=None)
    body["@id"] = LIST_URL
    assert _verify(CREDENTIAL, _signed_list(body, jti=LIST_URL)).status.revoked is False
    assert "id" not in default_status_list_resolver(
        fetch=_served(_signed_list(body, jti=LIST_URL)))(LIST_URL)   # @id is the id: not filled
    with pytest.raises(ClaimsInvalid, match="jti"):
        _verify(CREDENTIAL, _signed_list(body, jti=LIST_URL_B))
    both = dict(body, id=LIST_URL_B)                                   # id != @id
    with pytest.raises(ClaimsInvalid, match="id .* != @id"):
        _verify(CREDENTIAL, _signed_list(both))


# --------------------------------------------------------------------------- #
# review F2: a custom resolver is correct through the public helper
# --------------------------------------------------------------------------- #

def test_a_custom_resolver_built_on_the_public_helper_refuses_the_swap():
    from openvc.resolvers import authenticated_status_list

    jti_only_b = _signed_list(_list(LIST_URL_B, revoked=False, list_id=None), jti=LIST_URL_B)
    jti_only_a = _signed_list(_list(LIST_URL, revoked=True, list_id=None), jti=LIST_URL)

    def resolver(served):
        def resolve(url):
            return authenticated_status_list(verify_credential(
                served, policy=VerificationPolicy(require_status=False)))
        return resolve

    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        verify_credential(CREDENTIAL, policy=BIND, resolve_status_list=resolver(jti_only_b))
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        verify_credential(CREDENTIAL, resolve_status_list=resolver(jti_only_b))
    with pytest.raises(CredentialRevoked):
        verify_credential(CREDENTIAL, policy=BIND, resolve_status_list=resolver(jti_only_a))
    # the helper is the resolvers' own function under its public name
    from openvc import resolvers
    assert resolvers._authenticated_list is authenticated_status_list
    assert "authenticated_status_list" in resolvers.__all__


def test_a_custom_resolver_that_returns_the_bare_credential_keeps_the_residual():
    # The contract (ResolveStatusList): the pipeline fills nothing in. A resolver that
    # returns `result.credential` hands the check an id-less VCDM 1.1 list, bound by
    # issuer and types only — the documented duty of a custom resolver (#377).
    jti_only_b = _signed_list(_list(LIST_URL_B, revoked=False, list_id=None), jti=LIST_URL_B)

    def bare(url):
        result = verify_credential(jti_only_b, policy=VerificationPolicy(require_status=False))
        return result.credential

    verdict = verify_credential(CREDENTIAL, policy=BIND, resolve_status_list=bare)
    assert verdict.status.revoked is False


def test_verify_many_binds_the_list_through_the_batch_resolver():
    from openvc import verify_many

    swapped = _signed_list(_list(LIST_URL_B, revoked=False, list_id=None), jti=LIST_URL_B)
    outcomes = verify_many([CREDENTIAL, CREDENTIAL], policy=BIND,
                           resolve_status_list=default_status_list_resolver(fetch=_served(swapped)))
    assert [type(o.error).__name__ for o in outcomes] == ["StatusListError", "StatusListError"]
    bound = _signed_list(_list(LIST_URL, revoked=False, list_id=None), jti=LIST_URL)
    outcomes = verify_many([CREDENTIAL], policy=BIND,
                           resolve_status_list=default_status_list_resolver(fetch=_served(bound)))
    assert outcomes[0].error is None and outcomes[0].result.status.revoked is False


# --------------------------------------------------------------------------- #
# review F1: a status list secured as SD-JWT is never selectively disclosable
# --------------------------------------------------------------------------- #

def _sd_jwt(body: dict, disclosable: list[str], *, typ: str = "vc+sd-jwt", decoys: int = 0):
    """A hand-built SD-JWT: *disclosable* top-level claims leave the body for disclosures,
    *decoys* adds digests nothing discloses. Returns (full, disclosures-withheld)."""
    import hashlib
    import os
    payload = {k: v for k, v in body.items() if k not in disclosable}
    discs, digests = [], []
    for name in disclosable:
        disc = _b64(json.dumps([_b64(os.urandom(16)), name, body[name]]).encode())
        discs.append(disc)
        digests.append(_b64(hashlib.sha256(disc.encode("ascii")).digest()))
    for _ in range(decoys):
        digests.append(_b64(os.urandom(32)))
    if digests:
        payload["_sd"] = sorted(digests)
        payload["_sd_alg"] = "sha-256"
    head = {"alg": "ES256", "kid": f"{DID}#0", "typ": typ}
    si = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(payload).encode())}"
    jwt = f"{si}.{_b64(KEY.sign(si.encode('ascii')))}"
    return jwt + "~" + "".join(d + "~" for d in discs), jwt + "~"


def _vcdm_sd_body(url: str, *, revoked: bool) -> dict:
    return {"@context": [V2], "id": url, "iss": DID, "issuer": DID,
            "type": ["VerifiableCredential", BITSTRING[1]],
            "credentialSubject": _subject(url, revoked=revoked)}


def _dc_sd_body(url: str, *, revoked: bool) -> dict:
    return {"iss": DID, "vct": "urn:example:status-list", "jti": url,
            "type": ["VerifiableCredential", BITSTRING[1]],
            "credentialSubject": _subject(url, revoked=revoked)}


@pytest.mark.parametrize("claim", ["id", "jti", "type", "credentialSubject", "statusPurpose"])
def test_issue_refuses_a_disclosable_claim_on_a_status_list(claim):
    from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
    signer = P256SigningKey(KEY._sk, kid=f"{DID}#0")
    body = {**_dc_sd_body(LIST_URL, revoked=False), "statusPurpose": "revocation"}
    with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
        SdJwtVcProofSuite().issue(body, signing_key=signer, disclosable=[claim])
    legacy = dict(body, type=["VerifiableCredential", LEGACY[1]])
    with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
        SdJwtVcProofSuite().issue(legacy, signing_key=signer, disclosable=[claim])


def test_issue_refuses_decoys_on_a_status_list_and_issues_a_plain_one():
    from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
    signer = P256SigningKey(KEY._sk, kid=f"{DID}#0")
    body = _dc_sd_body(LIST_URL, revoked=True)
    with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
        SdJwtVcProofSuite().issue(body, signing_key=signer, decoys=1)
    plain = SdJwtVcProofSuite().issue(body, signing_key=signer)
    assert "_sd" not in json.loads(base64.urlsafe_b64decode(plain.split(".")[1] + "=="))
    with pytest.raises(CredentialRevoked):                       # it verifies, and binds
        _verify(CREDENTIAL, plain)
    with pytest.raises(StatusListError, match="is not the entry's statusListCredential"):
        _verify(CREDENTIAL, SdJwtVcProofSuite().issue(
            _dc_sd_body(LIST_URL_B, revoked=False), signing_key=signer))
    # a credential that is not a status list keeps its disclosures
    other = {"iss": DID, "vct": "urn:example:degree", "type": ["VerifiableCredential"],
             "name": "Alice", "degree": "MSc"}
    assert SdJwtVcProofSuite().issue(other, signing_key=signer, disclosable=["name"],
                                     decoys=2).count("~") == 2


@pytest.mark.parametrize("typ, body_of, claim", [
    ("vc+sd-jwt", _vcdm_sd_body, "id"),
    ("vc+sd-jwt", _vcdm_sd_body, "jti"),
    ("dc+sd-jwt", _dc_sd_body, "jti"),
    ("dc+sd-jwt", _dc_sd_body, "id"),
], ids=["vcdm-id", "vcdm-jti", "dc-jti", "dc-id"])
def test_a_withheld_identifier_disclosure_no_longer_reaches_the_residual(typ, body_of, claim):
    """The review's WITHHELD rows: the status host (the list's "holder") drops the
    disclosure that names the list; the id-less residual used to read list B for entry A."""
    from openvc.proof.sd_jwt import SdJwtError
    body = body_of(LIST_URL_B, revoked=False)
    if claim == "jti" and "jti" not in body:
        body["jti"] = body.pop("id")
    if claim == "id" and "id" not in body:
        body["id"] = body.pop("jti")
    full, withheld = _sd_jwt(body, [claim], typ=typ)
    for served in (full, withheld):
        with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
            _verify(CREDENTIAL, served)
        with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
            _verify(CREDENTIAL, served, policy=VerificationPolicy())
        with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
            _verify_async(CREDENTIAL, served)


def test_decoys_alone_and_a_nested_digest_are_refused_on_a_status_list():
    from openvc.proof.sd_jwt import SdJwtError
    _, decoys_only = _sd_jwt(_vcdm_sd_body(LIST_URL, revoked=True), [], decoys=2)
    with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
        _verify(CREDENTIAL, decoys_only)
    nested = _vcdm_sd_body(LIST_URL, revoked=True)
    nested["credentialSubject"] = {**nested["credentialSubject"], "_sd": [_b64(b"x" * 32)]}
    _, served = _sd_jwt(nested, [])
    with pytest.raises(SdJwtError, match="must not be selectively disclosable"):
        _verify(CREDENTIAL, served)


def test_a_plain_sd_jwt_status_list_still_verifies_on_both_typs():
    for typ, body_of in (("vc+sd-jwt", _vcdm_sd_body), ("dc+sd-jwt", _dc_sd_body)):
        full, _ = _sd_jwt(body_of(LIST_URL, revoked=True), [], typ=typ)
        with pytest.raises(CredentialRevoked):
            _verify(CREDENTIAL, full)
        with pytest.raises(CredentialRevoked):
            _verify_async(CREDENTIAL, full)
        full, _ = _sd_jwt(body_of(LIST_URL, revoked=False), [], typ=typ)
        assert _verify(CREDENTIAL, full).status.revoked is False
    # a non-status SD-JWT with a withheld disclosure is unaffected by the rule
    from openvc.proof.sd_jwt import SdJwtVcProofSuite
    signer = P256SigningKey(KEY._sk, kid=f"{DID}#0")
    tok = SdJwtVcProofSuite().issue(
        {"iss": DID, "vct": "urn:example:degree", "name": "Alice"}, signing_key=signer,
        disclosable=["name"])
    withheld = tok.split("~")[0] + "~"
    assert "name" not in SdJwtVcProofSuite().verify(
        withheld, public_key_jwk=KEY.public_jwk()).claims


def test_the_sd_jwt_status_list_types_mirror_the_status_modules():
    from openvc.proof.sd_jwt import _STATUS_LIST_TYPES
    from openvc.status.status_list import _LIST_TYPES
    assert _STATUS_LIST_TYPES == frozenset(credential for credential, _ in _LIST_TYPES.values())
