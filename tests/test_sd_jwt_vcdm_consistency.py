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

Since #275 a ``vc+sd-jwt`` (and the draft-era and absent ``typ``) has to be read as a W3C
credential before the pin is looked at: its ``type`` must include ``VerifiableCredential``
and not ``VerifiablePresentation`` (VCDM 2.0 §4.5, §4.13) and the base ``@context`` must be
the first entry (§4.3). A ``type`` that is withheld or is no array of names (a number, a
bool, an object, a string that is not ``VerifiableCredential``, an empty array, ``null``)
is therefore ``SdJwtError`` at that gate, where it used to reach the pin and be a
``TypeMismatch``. The pin still sees every ``type`` the gate lets through (an array that
includes ``VerifiableCredential`` with hostile entries beside it) and, with no type rule
for it, every ``dc+sd-jwt`` payload with a VCDM ``@context``.

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


def test_vc_sd_jwt_without_a_vcdm_context_is_refused_before_reconciliation(run, form):
    # #264: `vc+sd-jwt` is the W3C VCDM typ (VC-JOSE-COSE §6.1.3) and the typ alone no
    # longer makes a payload VCDM, so a vct-less, @context-less token is refused outright
    # (it used to be reconciled as VCDM, and the issuer conflict below was what rejected it).
    doc = _vcdm(issuer=UNIVERSITY)
    del doc["@context"]
    with pytest.raises(SdJwtError, match="needs a W3C VCDM @context"):
        run(form(_mint(doc)), None)


def test_vcdm_issuer_conflict_is_rejected_under_a_dc_sd_jwt_typ(run, form):
    # VCDM by its @context, whatever the typ says. A dc+sd-jwt needs a vct whatever else it
    # carries (#272), so this one has it: the conflict, not a missing vct, is what fails.
    with pytest.raises(ClaimsInvalid, match="!= issuer"):
        run(form(_mint(_vcdm(issuer=UNIVERSITY, vct=VCT), typ="dc+sd-jwt")), None)


def test_a_vct_less_dc_sd_jwt_is_refused_for_its_vct_before_the_conflict_is_read(run, form):
    # The same payload without the vct fails the IETF rule first (#272): what is checked
    # is the missing vct, not the issuer conflict, which is never reached.
    with pytest.raises(ClaimsInvalid, match="needs a non-empty string vct"):
        run(form(_mint(_vcdm(issuer=UNIVERSITY), typ="dc+sd-jwt")), None)


def _vct_withheld(claims):
    # the issuer made vct a disclosure and the holder presents the token without it
    return _without(_mint(claims, typ="vc+sd-jwt", disclose=["vct"]), "vct")


@pytest.mark.parametrize("make", [
    lambda: _mint(_ietf(), typ="vc+sd-jwt"),                         # pre-draft-06 issuer
    lambda: _mint({"iss": DID, "member_name": "Ada"}, typ="vc+sd-jwt"),
    lambda: _mint(_ietf(vct=""), typ="vc+sd-jwt"),
    lambda: _vct_withheld(_ietf()),
], ids=["with-vct", "no-vct", "empty-vct", "vct-withheld"])
def test_vc_sd_jwt_typ_refuses_an_ietf_payload(run, form, make):
    # #264: draft-ietf-oauth-sd-jwt-vc-19 dropped the transitional acceptance of
    # `vc+sd-jwt`; an IETF SD-JWT VC is typed `dc+sd-jwt`. Neither a vct-bearing payload
    # nor one that reads as vct-less (the old typ-only VCDM signal, which skipped the
    # REQUIRED vct) gets through on the W3C typ.
    with pytest.raises(SdJwtError, match="needs a W3C VCDM @context"):
        run(form(make()), None)


def test_vc_sd_jwt_typ_refusal_is_the_suites():
    # SdJwtVcProofSuite.verify itself, not only the pipelines.
    with pytest.raises(SdJwtError, match="'dc\\+sd-jwt'"):
        SdJwtVcProofSuite().verify(_mint(_ietf(), typ="vc+sd-jwt"),
                                   public_key_jwk=KEY.public_jwk())


@pytest.mark.parametrize("extra", [{}, {"vct": VCT}], ids=["no-vct", "with-vct"])
def test_vc_sd_jwt_with_a_vcdm_context_still_verifies(run, form, extra):
    # The W3C typ with a VCDM @context is the case it exists for, vct or not.
    result = run(form(_mint(_vcdm(**extra))), None)
    assert result.raw.vcdm is True


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
    # A holder that withholds a disclosable `type` presents no type at all. Until #275 the
    # pin caught it (TypeMismatch); a vc+sd-jwt is now refused one step earlier, as a
    # payload that does not say it is a credential (VCDM 2.0 §4.5), with or without a pin.
    sd_jwt = _without(_mint(_vcdm(), disclose=["type"]), "type")
    for policy in (_types("ExampleAlumniCredential"), None):
        with pytest.raises(SdJwtError, match="includes VerifiableCredential") as excinfo:
            run(form(sd_jwt), policy)
        assert excinfo.type is SdJwtError
        assert "typ 'vc+sd-jwt'" in str(excinfo.value)


def test_vcdm_presented_type_disclosure_meets_the_gate_and_the_pin(run, form):
    # The twin of the refusal above: the same token with the disclosure presented (the shape
    # of the Recommendation's Example 4) verifies, and the pin reads the disclosed `type`.
    sd_jwt = _mint(_vcdm(), disclose=["type"])
    result = run(form(sd_jwt), _types("ExampleAlumniCredential"))
    assert result.credential["type"] == ["VerifiableCredential", "ExampleAlumniCredential"]
    with pytest.raises(TypeMismatch, match="UniversityDegreeCredential"):
        run(form(sd_jwt), _types("UniversityDegreeCredential"))


def test_a_withheld_type_on_a_dc_sd_jwt_vcdm_payload_is_still_a_mismatch(run, form):
    # What the test above used to prove about the pin, through the typ that has no `type`
    # rule (#275): a dc+sd-jwt with a vct and a VCDM @context is VCDM, the holder withholds
    # the disclosable `type`, and the pin, not the gate, is what stops the dodge.
    sd_jwt = _without(_mint(_vcdm(vct=VCT), typ="dc+sd-jwt", disclose=["type"]), "type")
    with pytest.raises(TypeMismatch, match="ExampleAlumniCredential") as excinfo:
        run(form(sd_jwt), _types("ExampleAlumniCredential"))
    assert excinfo.type is TypeMismatch
    assert run(form(sd_jwt), None).raw.vcdm is True        # with no pin it verifies


@pytest.mark.parametrize("hostile", [
    None, 5, True, {"ExampleAlumniCredential": 1},
    {}, "ExampleAlumniCredential", [],
], ids=["null", "number", "bool", "object-keys", "empty-object", "string-without-vc",
        "empty-array"])
def test_vcdm_hostile_type_shape_is_refused_at_the_gate(run, hostile):
    # Never a bare TypeError, and never an object whose KEYS pass the membership test. Until
    # #275 the first four reached the pin and were a TypeMismatch; none of these says
    # "VerifiableCredential" (VCDM 2.0 §4.5), so a vc+sd-jwt is refused before the pin is
    # read (SdJwtError, a different class), whether or not the policy sets one.
    for policy in (_types("ExampleAlumniCredential"), None):
        with pytest.raises(SdJwtError, match="includes VerifiableCredential") as excinfo:
            run(_mint(_vcdm(type=hostile)), policy)
        assert excinfo.type is SdJwtError


@pytest.mark.parametrize("hostile", [
    ["VerifiableCredential", 7],
    ["VerifiableCredential", None],
    ["VerifiableCredential", True],
    ["VerifiableCredential", {"a": 1}],
    ["VerifiableCredential", {"ExampleAlumniCredential": 1}],
    ["VerifiableCredential", ["ExampleAlumniCredential"]],
], ids=["number-entry", "null-entry", "bool-entry", "object-entry", "object-keys-entry",
        "nested-array-entry"])
def test_vcdm_hostile_type_shape_is_a_typed_mismatch(run, hostile):
    # The shapes the gate lets through, because the array includes VerifiableCredential, and
    # the pin reads: a TypeMismatch, never a bare TypeError (an unhashable entry) and never
    # an entry whose KEYS or members pass the membership test.
    with pytest.raises(TypeMismatch) as excinfo:
        run(_mint(_vcdm(type=hostile)), _types("ExampleAlumniCredential"))
    assert excinfo.type is TypeMismatch
    # and with no pin the same payload verifies: the gate does not mind the extra entries
    assert run(_mint(_vcdm(type=hostile)), None).raw.vcdm is True


@pytest.mark.parametrize("hostile", [None, 5, True, {"ExampleAlumniCredential": 1}],
                         ids=["null", "number", "bool", "object-keys"])
def test_vcdm_hostile_type_shape_on_a_dc_sd_jwt_is_a_typed_mismatch(run, hostile):
    # The four shapes the test above (until #275) held to the pin, through the typ that has no
    # `type` rule: a dc+sd-jwt with a vct and a VCDM @context is VCDM and the pin reads them.
    with pytest.raises(TypeMismatch) as excinfo:
        run(_mint(_vcdm(type=hostile, vct=VCT), typ="dc+sd-jwt"),
            _types("ExampleAlumniCredential"))
    assert excinfo.type is TypeMismatch


def test_vcdm_expected_types_present_verify(run, form):
    result = run(form(_mint(_vcdm())),
                 _types("VerifiableCredential", "ExampleAlumniCredential"))
    assert "ExampleAlumniCredential" in result.credential["type"]


# --------------------------------------------------------------------------- #
# IETF SD-JWT VC — typed by vct; its claim names are its own vocabulary
# --------------------------------------------------------------------------- #

def test_ietf_rejects_a_policy_that_sets_expected_types(run):
    # A pin the lane cannot check is a rejection, not a silent pass: point at vct.
    with pytest.raises(TypeMismatch, match="expected_vct"):
        run(_mint(_ietf(), typ="dc+sd-jwt"), _types("ExampleAlumniCredential"))


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


def test_ietf_claims_named_like_vcdm_properties_are_not_reconciled(run):
    # An IETF SD-JWT VC may legitimately carry an `issuer` (say, the authority behind an
    # underlying document) that is not its `iss`. Unchanged: it verifies, and the
    # authenticated issuer is result.issuer — the verified iss — never the claim.
    claims = _ietf(issuer=UNIVERSITY, id="urn:uuid:other", jti="urn:uuid:jti",
                   sub="did:example:alice",
                   credentialSubject={"id": "did:example:mallory"})
    result = run(_mint(claims, typ="dc+sd-jwt"), None)
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
    # The characters ride beside VerifiableCredential so that the payload meets the gate
    # (#275) and the pin is what refuses it: iterating the bare string would match them all.
    doc = _vcdm(type=["VerifiableCredential", *"ExampleAlumniCredential"])
    with pytest.raises(TypeMismatch) as excinfo:
        run(_mint(doc), VerificationPolicy(expected_types="ExampleAlumniCredential"))
    assert excinfo.type is TypeMismatch


def test_a_type_of_nothing_but_the_pins_characters_is_refused_at_the_gate(run):
    # The shape this test used to hold to the pin: no VerifiableCredential among the
    # characters, so a vc+sd-jwt is refused before the pin is read (#275, SdJwtError).
    doc = _vcdm(type=list("ExampleAlumniCredential"))
    with pytest.raises(SdJwtError, match="includes VerifiableCredential") as excinfo:
        run(_mint(doc), VerificationPolicy(expected_types="ExampleAlumniCredential"))
    assert excinfo.type is SdJwtError


def test_string_type_pin_matches_the_whole_type(run):
    result = run(_mint(_vcdm()), VerificationPolicy(expected_types="ExampleAlumniCredential"))
    assert result.issuer == DID


# --------------------------------------------------------------------------- #
# VerifiedSdJwt.vcdm reports which rules the suite applied
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sd_jwt, vcdm", [
    (_mint(_vcdm()), True),
    (_mint(_vcdm(vct=VCT)), True),               # the @context decides, vct or not
    (_mint(_ietf(), typ="dc+sd-jwt"), False),
], ids=["vcdm", "vcdm-with-vct", "ietf-dc"])
def test_vcdm_flag_is_the_suites_verdict(run, sd_jwt, vcdm):
    assert SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=KEY.public_jwk()).vcdm is vcdm
    assert run(sd_jwt, None).raw.vcdm is vcdm
