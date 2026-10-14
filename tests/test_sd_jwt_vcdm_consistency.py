"""
tests/test_sd_jwt_vcdm_consistency.py — a W3C VCDM credential secured as SD-JWT gets the
VC-JWT lane's consistency rules: ``iss`` / ``issuer``, ``jti`` / ``id`` and
``sub`` / ``credentialSubject.id`` are reconciled, and ``policy.expected_types`` is
enforced.

Found by the adversarial review of #199 (pre-existing). Through v1.30.1 the SD-JWT lane
applied neither rule, on both pipelines:

* **Issuer impersonation in the credential body.** A VCDM SD-JWT signed by the
  attacker's own ``did:jwk`` (``iss`` = attacker) could carry
  ``"issuer": "did:web:university.example"``. It verified with ``result.issuer`` = the
  attacker and ``result.credential["issuer"]`` = the university. VC-JOSE-COSE §4.1.2:
  ``iss``, if present, MUST match ``issuer`` (or ``issuer.id``); §3.1.3 (non-normative)
  advises the same for ``jti`` / ``id`` and ``sub`` / ``credentialSubject.id``. The
  VC-JWT lane already rejects all three conflicts (``VcJwtProofSuite`` reconciliation).
* **``expected_types`` failed open.** ``_verify_sd_jwt`` never checked it, so a policy
  pinning a type accepted any SD-JWT. VC-JOSE-COSE §5.4: claims that are understood
  MUST be evaluated against the verifier's policy. A VCDM payload now gets the same
  ``TypeMismatch`` as VC-JWT and Data Integrity. An IETF SD-JWT VC is typed by ``vct``,
  not ``type``: a policy that sets ``expected_types`` rejects it (``TypeMismatch``,
  pointing at ``expected_vct``) instead of ignoring the pin. Ignoring it would also let
  a holder dodge the pin by withholding a disclosable ``@context``.

IETF SD-JWT VCs keep their behaviour otherwise: a claim merely *named* ``issuer`` / ``id``
/ ``type`` there is the issuer's own vocabulary, and ``result.issuer`` (the verified
``iss``) stays the only authenticated issuer on every lane.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; ``asyncio.run`` drives the async
pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets

import pytest

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
)
from openvc.keys import P256SigningKey
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import (
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_object_disclosure,
)
from openvc.verify import TypeMismatch

V2 = "https://www.w3.org/ns/credentials/v2"
UNIVERSITY = "did:web:university.example"
VCT = "https://credentials.example/membership"
AUD, NONCE = "https://verifier.example", "n-0S6_WzA2Mj"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()            # the attacker: any key it holds verifies as itself


def _mint(payload, *, typ="vc+sd-jwt", disclose=()):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes the IETF
    ``dc+sd-jwt`` typ and requires a ``vct``, so it cannot mint a W3C one. *disclose*
    moves those top-level claims into disclosures (all of them presented)."""
    body = dict(payload)
    disclosures = []
    for name in disclose:
        disclosures.append(make_object_disclosure(_b64(secrets.token_bytes(16)), name,
                                                  body.pop(name)))
    if disclosures:
        body["_sd"] = sorted(disclosure_digest(d) for d in disclosures)
        body["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "typ": typ, "kid": f"{DID}#0"}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    jws = f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}"
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _without(sd_jwt, name):
    """The presentation with the disclosure of top-level claim *name* withheld."""
    issuer_jwt, *rest = sd_jwt.split("~")
    kept = [d for d in rest[:-1]
            if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] != name]
    assert len(kept) == len(rest) - 2, f"no disclosure for {name!r}"
    return issuer_jwt + "~" + "".join(d + "~" for d in kept)


def _vcdm(**extra):
    doc = {
        "@context": [V2, "https://www.w3.org/ns/credentials/examples/v2"],
        "id": "urn:uuid:5e1d6a3c-cred",
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "iss": DID,
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "alumniOf": "Example University"},
    }
    doc.update(extra)
    return doc


def _ietf(**extra):
    claims = {"iss": DID, "vct": VCT, "member_name": "Ada"}
    claims.update(extra)
    return claims


def _envelope(sd_jwt, media="application/vc+sd-jwt"):
    return {"@context": [V2], "id": f"data:{media},{sd_jwt}",
            "type": ["EnvelopedVerifiableCredential"]}


FORMS = {
    "bare": lambda sd_jwt: sd_jwt,
    "enveloped": _envelope,
}


def _sync(credential, policy):
    return verify_credential(credential, policy=policy)


def _async(credential, policy):
    return asyncio.run(verify_credential_async(credential, policy=policy))


PIPELINES = {"sync": _sync, "async": _async}


def _types(*expected):
    return VerificationPolicy(expected_types=list(expected))


@pytest.fixture(params=sorted(PIPELINES))
def run(request):
    return PIPELINES[request.param]


@pytest.fixture(params=sorted(FORMS))
def form(request):
    return FORMS[request.param]


# --------------------------------------------------------------------------- #
# W3C VCDM secured as SD-JWT — the body must not contradict the JWT claims
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("issuer", [UNIVERSITY, {"id": UNIVERSITY, "name": "Uni"}],
                         ids=["string", "object"])
def test_vcdm_issuer_impersonation_is_rejected(run, form, issuer):
    # The reported case: the attacker signs with its own did:jwk (iss = attacker) and
    # names the university as the credential's issuer (§4.1.2: iss MUST match issuer).
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer=issuer))), None)


def test_vcdm_selectively_disclosed_issuer_is_reconciled(run, form):
    # Read on the processed payload: a disclosed issuer counts like a signed one.
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer=UNIVERSITY), disclose=["issuer"])), None)


def test_vcdm_issuer_conflict_is_rejected_when_typed_only_by_vc_sd_jwt(run, form):
    # VCDM by the second signal (vc+sd-jwt, no vct, no @context): reconciled all the same.
    doc = _vcdm(issuer=UNIVERSITY)
    del doc["@context"]
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(doc)), None)


def test_vcdm_issuer_conflict_is_rejected_under_a_dc_sd_jwt_typ(run, form):
    # VCDM by its @context, whatever the typ says.
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer=UNIVERSITY), typ="dc+sd-jwt")), None)


def test_vcdm_jti_conflicting_with_id_is_rejected(run, form):
    with pytest.raises(ClaimsInvalid, match="jti"):
        run(form(_mint(_vcdm(jti="urn:uuid:another-credential"))), None)


def test_vcdm_sub_conflicting_with_credential_subject_id_is_rejected(run, form):
    with pytest.raises(ClaimsInvalid, match="credentialSubject"):
        run(form(_mint(_vcdm(sub="did:example:mallory"))), None)


def test_expiry_waiver_does_not_waive_the_issuer_conflict(run, form):
    # The waiver is about dates; it never relaxes authenticity. (Without it this expired
    # credential raises CredentialExpired first: the window runs before the
    # reconciliation, in the same order as on the VC-JWT lane.)
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer=UNIVERSITY, validUntil="2021-01-01T00:00:00Z"))),
            VerificationPolicy(require_not_expired=False))


def test_vcdm_issuer_conflict_is_rejected_with_key_binding(run):
    holder = P256SigningKey.generate(kid="holder")
    sd_jwt = _mint(_vcdm(issuer=UNIVERSITY, cnf={"jwk": holder.public_jwk()}))
    presentation = SdJwtVcProofSuite().create_presentation(
        sd_jwt, holder_key=holder, audience=AUD, nonce=NONCE)
    policy = VerificationPolicy(require_key_binding=True, audience=AUD, nonce=NONCE)
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(presentation, policy)


def test_suite_rejects_vcdm_issuer_impersonation():
    # SdJwtVcProofSuite.verify itself, not only the pipelines.
    with pytest.raises(ClaimsInvalid, match="issuer"):
        SdJwtVcProofSuite().verify(_mint(_vcdm(issuer=UNIVERSITY)),
                                   public_key_jwk=KEY.public_jwk())


def test_verify_many_types_the_impersonation_and_keeps_going():
    good = _mint(_vcdm())
    bad = _mint(_vcdm(issuer=UNIVERSITY))
    results = verify_many([bad, good])
    assert isinstance(results[0].error, ClaimsInvalid)
    assert results[1].ok


@pytest.mark.parametrize("issuer", [DID, {"id": DID, "name": "Example University"}],
                         ids=["string", "object"])
def test_vcdm_consistent_claims_verify(run, form, issuer):
    doc = _vcdm(issuer=issuer, jti="urn:uuid:5e1d6a3c-cred", sub="did:example:alice")
    result = run(form(_mint(doc)), None)
    assert result.issuer == DID
    assert result.credential["issuer"] == issuer


# --------------------------------------------------------------------------- #
# W3C VCDM secured as SD-JWT — expected_types is enforced
# --------------------------------------------------------------------------- #

def test_vcdm_missing_expected_type_is_rejected(run, form):
    with pytest.raises(TypeMismatch, match="UniversityDegreeCredential"):
        run(form(_mint(_vcdm())), _types("UniversityDegreeCredential"))


def test_vcdm_withheld_type_is_rejected(run, form):
    # A holder that withholds a disclosable `type` presents no type at all.
    sd_jwt = _without(_mint(_vcdm(), disclose=["type"]), "type")
    with pytest.raises(TypeMismatch):
        run(form(sd_jwt), _types("ExampleAlumniCredential"))


@pytest.mark.parametrize("hostile", [None, 5, True, {"ExampleAlumniCredential": 1}],
                         ids=["null", "number", "bool", "object-keys"])
def test_vcdm_hostile_type_shape_is_a_typed_mismatch(run, hostile):
    # Never a bare TypeError, and never an object whose KEYS pass the membership test.
    with pytest.raises(TypeMismatch):
        run(_mint(_vcdm(type=hostile)), _types("ExampleAlumniCredential"))


def test_vcdm_expected_types_present_verify(run, form):
    result = run(form(_mint(_vcdm())),
                 _types("VerifiableCredential", "ExampleAlumniCredential"))
    assert "ExampleAlumniCredential" in result.credential["type"]


# --------------------------------------------------------------------------- #
# IETF SD-JWT VC — typed by vct; its claim names are its own vocabulary
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("typ", ["dc+sd-jwt", "vc+sd-jwt"], ids=["dc", "legacy-vc"])
def test_ietf_rejects_a_policy_that_sets_expected_types(run, typ):
    # A pin the lane cannot check is a rejection, not a silent pass: point at vct.
    with pytest.raises(TypeMismatch, match="expected_vct"):
        run(_mint(_ietf(), typ=typ), _types("ExampleAlumniCredential"))


def test_ietf_type_claim_does_not_satisfy_expected_types(run):
    # A claim named `type` is not the VCDM `type` property outside a VCDM payload.
    claims = _ietf(type=["VerifiableCredential", "ExampleAlumniCredential"])
    with pytest.raises(TypeMismatch, match="expected_vct"):
        run(_mint(claims, typ="dc+sd-jwt"), _types("ExampleAlumniCredential"))


@pytest.mark.parametrize("extra, error", [
    ({}, ClaimsInvalid),                # no vct left either: an IETF SD-JWT VC needs one (#229)
    ({"vct": VCT}, TypeMismatch),       # a vct: an IETF SD-JWT VC, and the type pin refuses it
], ids=["no-vct", "with-vct"])
def test_withheld_context_cannot_dodge_expected_types(run, extra, error):
    # A dc+sd-jwt VCDM credential with a disclosable @context: withheld, the payload no
    # longer reads as VCDM. Ignoring expected_types there would be a holder-side bypass.
    sd_jwt = _without(_mint(_vcdm(**extra), typ="dc+sd-jwt", disclose=["@context"]),
                      "@context")
    with pytest.raises(error):
        run(sd_jwt, _types("ExampleAlumniCredential"))


def test_presented_disclosable_context_is_refused(run):
    # #229: the same credential with @context presented — the issuer made the VCDM
    # switch withholdable, so the disclosure itself is refused.
    sd_jwt = _mint(_vcdm(), typ="dc+sd-jwt", disclose=["@context"])
    with pytest.raises(SdJwtError, match="'@context' is selectively disclosed"):
        run(sd_jwt, None)


@pytest.mark.parametrize("expected", [None, []], ids=["unset", "empty"])
def test_ietf_without_a_type_pin_still_verifies(run, expected):
    result = run(_mint(_ietf(), typ="dc+sd-jwt"),
                 VerificationPolicy(expected_types=expected, expected_vct=VCT))
    assert result.raw.vct == VCT


@pytest.mark.parametrize("typ", ["dc+sd-jwt", "vc+sd-jwt"], ids=["dc", "legacy-vc"])
def test_ietf_claims_named_like_vcdm_properties_are_not_reconciled(run, typ):
    # An IETF SD-JWT VC may legitimately carry an `issuer` (say, the authority behind an
    # underlying document) that is not its `iss`. Unchanged: it verifies, and the
    # authenticated issuer is result.issuer — the verified iss — never the claim.
    claims = _ietf(issuer=UNIVERSITY, id="urn:uuid:other", jti="urn:uuid:jti",
                   sub="did:example:alice",
                   credentialSubject={"id": "did:example:mallory"})
    result = run(_mint(claims, typ=typ), None)
    assert result.issuer == DID
    assert result.credential["issuer"] == UNIVERSITY


def test_verify_many_rejects_only_the_ietf_item_under_a_type_pin():
    results = verify_many([_mint(_ietf(), typ="dc+sd-jwt"), _mint(_vcdm())],
                          policy=_types("ExampleAlumniCredential"))
    assert isinstance(results[0].error, TypeMismatch)
    assert results[1].ok


# --------------------------------------------------------------------------- #
# A present issuer must name the verified iss — whatever its shape (both JOSE lanes)
# --------------------------------------------------------------------------- #
# Adversarial review of this change: the reconciliation compared only a truthy string
# `issuer` / `issuer.id`, so any other shape skipped it. `{"@id": UNI}` is the
# university to a JSON-LD processor (`id` is an alias of `@id`), and a null / "" /
# non-string identifier is one a looser reader may resolve. Every identifier a present
# issuer carries must be iss. An object with no id identifies no one, like an absent
# issuer: any signer may already pair its own id with any `name`.

UNREADABLE_ISSUERS = {
    "at-id": {"@id": UNIVERSITY},
    "id-and-at-id": {"id": DID, "@id": UNIVERSITY},
    "empty-string": "",
    "list": [UNIVERSITY],
    "null": None,
    "id-null": {"id": None, "name": "Example University"},
    "id-empty": {"id": ""},
    "id-number": {"id": 0},
}


def _vc_jwt(vc, *, iss=DID):
    """A VC-JWT signed by the attacker key with `iss` = its own DID, minted by hand —
    ``VcJwtProofSuite.sign`` derives `iss` from `issuer`, so it cannot mint a conflict."""
    header = {"alg": "ES256", "typ": "vc+jwt", "kid": f"{DID}#0"}
    body = {"iss": iss, "vc": vc}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    return f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}"


@pytest.mark.parametrize("issuer", list(UNREADABLE_ISSUERS.values()),
                         ids=list(UNREADABLE_ISSUERS))
def test_vcdm_sd_jwt_unreadable_issuer_is_rejected(run, form, issuer):
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer=issuer))), None)


@pytest.mark.parametrize("issuer", list(UNREADABLE_ISSUERS.values()),
                         ids=list(UNREADABLE_ISSUERS))
def test_vc_jwt_unreadable_issuer_is_rejected(run, issuer):
    vc = _vcdm(issuer=issuer)
    del vc["iss"]
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(_vc_jwt(vc), None)


@pytest.mark.parametrize("drop", [True, False], ids=["absent", "object-without-id"])
def test_issuer_that_identifies_no_one_still_verifies(run, drop):
    # Neither names anyone: the VCDM 1.1 JWT encoding moves the issuer's id to `iss`,
    # which may leave nothing, or {"name": ...}, behind.
    doc = _vcdm()
    if drop:
        del doc["issuer"]
    else:
        doc["issuer"] = {"name": "Example University"}
    assert run(_mint(doc), None).issuer == DID
    del doc["iss"]
    assert run(_vc_jwt(doc), None).issuer == DID


# --------------------------------------------------------------------------- #
# The status-list issuer binding reads only an authenticated issuer (ADR-0006)
# --------------------------------------------------------------------------- #
# Adversarial review of this change: `require_status_issuer_binding` compares the
# resolved list's body `issuer` with the credential's, and the default resolvers return
# the verified list's body. An IETF SD-JWT's `issuer` claim is not reconciled with its
# `iss`, so a compromised status host could serve a dc+sd-jwt list signed by its own key
# that names the victim issuer and clears the revocation bit.

STATUS_URL = "https://status.university.example/lists/1"
STATUS_INDEX = 7
BINDING = VerificationPolicy(require_status_issuer_binding=True)


def _did_key():
    return _issuer()


def _status_subject(revoked):
    from openvc.status.bitstring import encode_bitstring, new_bitstring, set_status_bit
    bits = new_bitstring(131072)
    if revoked:
        set_status_bit(bits, STATUS_INDEX, 1)
    return {"id": STATUS_URL + "#list", "type": "BitstringStatusList",
            "statusPurpose": "revocation", "encodedList": encode_bitstring(bytes(bits))}


def _signed_vc_jwt(key, did, vc):
    header = {"alg": "ES256", "typ": "vc+jwt", "kid": f"{did}#0"}
    body = {"iss": did, "vc": vc}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"


def _signed_sd_jwt(key, did, body, typ):
    header = {"alg": "ES256", "typ": typ, "kid": f"{did}#0"}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}~"


VICTIM_KEY, VICTIM = _did_key()
REVOKED_VC = _signed_vc_jwt(VICTIM_KEY, VICTIM, {
    "@context": [V2], "type": ["VerifiableCredential"], "issuer": VICTIM,
    "credentialSubject": {"id": "did:example:alice"},
    "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
                         "statusListIndex": str(STATUS_INDEX),
                         "statusListCredential": STATUS_URL},
})
GENUINE_LIST = _signed_vc_jwt(VICTIM_KEY, VICTIM, {
    "@context": [V2], "id": STATUS_URL,
    "type": ["VerifiableCredential", "BitstringStatusListCredential"],
    "issuer": VICTIM, "credentialSubject": _status_subject(revoked=True)})
FORGED_LISTS = {      # signed by the attacker's own key (DID), naming the victim
    "ietf-with-vct": _signed_sd_jwt(KEY, DID, {
        "iss": DID, "vct": "urn:example:status", "issuer": VICTIM,
        "credentialSubject": _status_subject(revoked=False)}, "dc+sd-jwt"),
    "dc-no-vct-issuer-object": _signed_sd_jwt(KEY, DID, {
        "iss": DID, "issuer": {"id": VICTIM},
        "credentialSubject": _status_subject(revoked=False)}, "dc+sd-jwt"),
    "dc-with-vct-issuer-object": _signed_sd_jwt(KEY, DID, {
        "iss": DID, "vct": "urn:example:status", "issuer": {"id": VICTIM},
        "credentialSubject": _status_subject(revoked=False)}, "dc+sd-jwt"),
    "vcdm": _signed_sd_jwt(KEY, DID, {
        "@context": [V2], "iss": DID, "issuer": VICTIM, "type": ["VerifiableCredential"],
        "credentialSubject": _status_subject(revoked=False)}, "vc+sd-jwt"),
}


def _with_status(served, policy, pipeline):
    from openvc.resolvers import (
        default_status_list_resolver,
        default_status_list_resolver_async,
    )
    if pipeline == "sync":
        return verify_credential(REVOKED_VC, policy=policy, resolve_status_list=(
            default_status_list_resolver(fetch=lambda url: served)))

    async def fetch(url):
        return served
    return asyncio.run(verify_credential_async(REVOKED_VC, policy=policy, resolve_status_list=(
        default_status_list_resolver_async(fetch=fetch))))


@pytest.mark.parametrize("pipeline", sorted(PIPELINES))
def test_genuine_status_list_still_revokes(pipeline):
    from openvc.status import CredentialRevoked
    with pytest.raises(CredentialRevoked):
        _with_status(GENUINE_LIST, BINDING, pipeline)


@pytest.mark.parametrize("forged", list(FORGED_LISTS.values()), ids=list(FORGED_LISTS))
@pytest.mark.parametrize("pipeline", sorted(PIPELINES))
def test_forged_sd_jwt_status_list_cannot_borrow_the_victim_issuer(pipeline, forged):
    from openvc.errors import OpenvcError
    # #229: a dc+sd-jwt with no vct (and no VCDM @context) is refused before the binding
    # runs — vct is REQUIRED; "dc-with-vct-issuer-object" keeps the binding's own case.
    match = "vct" if forged is FORGED_LISTS["dc-no-vct-issuer-object"] else "issuer"
    with pytest.raises(OpenvcError, match=match) as caught:
        _with_status(forged, BINDING, pipeline)
    assert type(caught.value).__name__ != "CredentialRevoked"


# --------------------------------------------------------------------------- #
# A bare-string expected_types is one type, not a run of characters
# --------------------------------------------------------------------------- #

def test_string_type_pin_is_not_satisfied_by_its_characters(run):
    doc = _vcdm(type=list("ExampleAlumniCredential"))
    with pytest.raises(TypeMismatch):
        run(_mint(doc), VerificationPolicy(expected_types="ExampleAlumniCredential"))


def test_string_type_pin_matches_the_whole_type(run):
    result = run(_mint(_vcdm()), VerificationPolicy(expected_types="ExampleAlumniCredential"))
    assert result.issuer == DID


# --------------------------------------------------------------------------- #
# VerifiedSdJwt.vcdm reports which rules the suite applied
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sd_jwt, vcdm", [
    (_mint(_vcdm()), True),
    (_mint(_ietf(), typ="dc+sd-jwt"), False),
    (_mint(_ietf(), typ="vc+sd-jwt"), False),
], ids=["vcdm", "ietf-dc", "ietf-legacy-vc"])
def test_vcdm_flag_is_the_suites_verdict(run, sd_jwt, vcdm):
    assert SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=KEY.public_jwk()).vcdm is vcdm
    assert run(sd_jwt, None).raw.vcdm is vcdm
