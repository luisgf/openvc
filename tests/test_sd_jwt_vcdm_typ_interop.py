"""
tests/test_sd_jwt_vcdm_typ_interop.py — a W3C VCDM credential secured with SD-JWT verifies
when its issuer JWT has no ``typ`` member, or carries the draft-era ``vc+ld+json+sd-jwt``
(#288, #289). #264 and #272 are the other directions of the same ``typ`` gate: #264 made
``vc+sd-jwt`` need a VCDM base ``@context``, and #272 made ``dc+sd-jwt`` always need a
``vct`` and the only typ the OpenID4VP ``dc+sd-jwt`` format answers. Those rules have their
own files (test_sd_jwt_vc_typ_vcdm_only.py, test_sd_jwt_vc_dc_typ_ietf_only.py); this one
pins what #288 and #289 let through, and what they must keep out.

W3C VC-JOSE-COSE (Recommendation of 13 October 2026, https://www.w3.org/TR/vc-jose-cose/)
makes the SD-JWT ``typ`` a SHOULD (§3.2.1), and its verification algorithm (§5.2) takes the
media type as an input instead of reading it from the header. Its examples show it: Examples
4 and 5 carry the header ``{"kid", "alg"}`` and no ``typ``, and Example 21 carries
``typ: vc+ld+json+sd-jwt``, the name the 2023 Working Drafts gave the media type before
``vc+sd-jwt`` (§6.1.3) replaced it. openvc refused both before any crypto ("unexpected
issuer JWT typ"). The credentials of Examples 4 and 5 carry no ``iss`` either, which this
lane needs to select the key, so they still do not verify end to end (#290). RFC 9901
§9.11 recommends explicit typing for SD-JWT, so the gate is relaxed, not removed. What
``SdJwtVcProofSuite.verify`` does now:

* **No ``typ`` member.** Accepted only if the processed payload declares a W3C VCDM base
  ``@context`` (VCDM 2.0 or 1.1, as a string or anywhere in an array) and carries no ``vc``
  or ``vp`` claim (§3.1.3). It then gets the VCDM validity window and the issuer / id /
  subject reconciliation, exactly like ``vc+sd-jwt``, and reports ``typ is None``. Without
  a VCDM ``@context`` it is ``SdJwtError``, a ``vct``-bearing IETF payload included: an
  IETF SD-JWT VC is typed ``dc+sd-jwt``. With a ``vc`` or ``vp`` claim it is ``SdJwtError``.
* **``vc+ld+json+sd-jwt``, exactly.** Treated like ``vc+sd-jwt``: it needs a VCDM
  ``@context``, or it is ``SdJwtError``.
* **A ``typ`` that is present and anything else** is ``SdJwtError`` ("unexpected issuer JWT
  typ"): ``null``, any non-string, ``""``, ``JWT``, ``kb+jwt``, ``vc+jwt``, a case or
  whitespace variant, an ``application/`` prefix. A ``"typ": null`` member is present, not
  absent. Matching is exact.
* **``dc+sd-jwt`` is unchanged**: a non-empty string ``vct``, whatever the ``@context``.
* **The VC-JWT lane is untouched.** A token with no ``typ`` that this lane accepts has no
  ``vc`` claim, so its ``~`` tail dropped is a compact JWS that the VC-JWT lane refuses
  ("no embedded ``vc`` object"); one typed ``vc+ld+json+sd-jwt`` is refused there by its
  ``+sd-jwt`` suffix (#189). A token with a ``vc`` object and no ``typ``, which this lane
  refuses, still verifies there with its tail dropped, as on ``main`` (#291).
* **OpenID4VP.** The ``dc+sd-jwt`` DCQL lane still answers only an issuer JWT typed
  ``dc+sd-jwt`` (#272), so neither new case answers a ``dc+sd-jwt`` query.

Two real tokens of the Recommendation sit in tests/fixtures/vc_jose_cose/ (section I).

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; signatures are real P-256 (P-384 for
Example 21); ``asyncio.run`` drives the async pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
from pathlib import Path

import pytest

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_vp_token,
)
from openvc.keys import P256SigningKey, P384SigningKey
from openvc.openid4vp import VpTokenMalformed
from openvc.proof.errors import (
    ClaimsInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    MalformedToken,
    SignatureInvalid,
)
from openvc.proof.sd_jwt import (
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_object_disclosure,
)

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
EXAMPLES_V2 = "https://www.w3.org/ns/credentials/examples/v2"
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
VCT = "https://credentials.example/membership"
DRAFT_TYP = "vc+ld+json+sd-jwt"        # Example 21 of VC-JOSE-COSE: a 2023 draft's media type
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"
ABSENT = object()                       # `_mint(typ=ABSENT)`: a header with no `typ` member

# What the suite (SdJwtError) and the lanes around it say, as regexes. The first three are
# the typ gate's refusals of a payload with no VCDM @context (under no typ, then under
# the draft-era typ) and of a `vc` / `vp` claim under no typ: keep them apart.
NO_TYP_NEEDS_CONTEXT = (r"issuer JWT without a typ needs a W3C VCDM @context; "
                        r"an IETF SD-JWT VC is typed 'dc\+sd-jwt'")
DRAFT_TYP_NEEDS_CONTEXT = (r"issuer JWT typ 'vc\+ld\+json\+sd-jwt' needs a W3C VCDM "
                           r"@context; an IETF SD-JWT VC is typed 'dc\+sd-jwt'")
NO_TYP_NO_VC_CLAIM = (r"issuer JWT without a typ must not carry a `vc` or `vp` claim "
                      r"\(VC-JOSE-COSE §3\.1\.3\)")
UNEXPECTED_TYP = "unexpected issuer JWT typ"
CONTEXT_DISCLOSED = "'@context' is selectively disclosed"
VCT_DISCLOSED = "'vct' is selectively disclosed"
NEEDS_VCT = "needs a non-empty string vct"
NOT_IETF = "must be an IETF SD-JWT VC"            # OpenID4VP, VpTokenMalformed
NO_VC_OBJECT = "no embedded `vc` object"          # VC-JWT lane, ClaimsInvalid
NOT_A_VC_JWT = "is not a VC-JWT"                  # VC-JWT lane, MalformedToken


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()


def _mint(payload, *, typ=ABSENT, disclose=()):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes ``dc+sd-jwt`` and
    requires a ``vct``. *typ* is this file's one departure from the sibling helpers, and has
    three states: ``ABSENT`` (the default) writes no ``typ`` member; ``None`` writes
    ``"typ": null``, a member that is present and wrong; any other value is written as is.
    *disclose* moves those top-level claims into disclosures (all of them presented)."""
    body = dict(payload)
    disclosures = []
    for name in disclose:
        disclosures.append(make_object_disclosure(_b64(secrets.token_bytes(16)), name,
                                                  body.pop(name)))
    if disclosures:
        body["_sd"] = sorted(disclosure_digest(d) for d in disclosures)
        body["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "kid": f"{DID}#0"}
    if typ is not ABSENT:
        header["typ"] = typ
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    jws = f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}"
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _decode(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _header(sd_jwt):
    return _decode(sd_jwt.split(".")[0])


def _payload(sd_jwt):
    return _decode(sd_jwt.split(".")[1])


def _without(sd_jwt, name):
    """The presentation with the disclosure of top-level claim *name* withheld."""
    issuer_jwt, *rest = sd_jwt.split("~")
    kept = [d for d in rest[:-1]
            if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] != name]
    assert len(kept) == len(rest) - 2, f"no disclosure for {name!r}"
    return issuer_jwt + "~" + "".join(d + "~" for d in kept)


def _tail_dropped(sd_jwt):
    """The issuer JWT alone: the SD-JWT with its ``~`` and everything after it removed, which
    is a compact JWS and goes to the VC-JWT lane."""
    return sd_jwt.split("~", 1)[0]


def _ietf(**extra):
    """An IETF SD-JWT VC payload: a ``vct`` and no VCDM vocabulary."""
    claims = {"iss": DID, "vct": VCT, "member_name": "Ada"}
    claims.update(extra)
    return claims


def _vct_less(**extra):
    claims = {"iss": DID, "member_name": "Ada"}
    claims.update(extra)
    return claims


def _vcdm(**extra):
    """A W3C VCDM payload with no ``vct``."""
    doc = {
        "@context": [V2, EXAMPLES_V2],
        "id": "urn:uuid:5e1d6a3c-cred",
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "iss": DID,
        "issuer": DID,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "alumniOf": "Example University"},
    }
    doc.update(extra)
    return doc


def _vcdm_vct(**extra):
    """The same VCDM payload with a ``vct``: both an IETF and a W3C credential."""
    return _vcdm(vct=VCT, **extra)


# What an issuer of the VCDM 1.1 JWT encoding puts under `vc` / `vp`.
EMBEDDED_VC = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
               "validFrom": "2020-01-01T00:00:00Z",
               "credentialSubject": {"id": "did:example:alice"}}
EMBEDDED_VP = {"@context": [V2], "type": ["VerifiablePresentation"],
               "holder": "did:example:alice"}
EMBEDDED = {"vc": EMBEDDED_VC, "vp": EMBEDDED_VP}


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


@pytest.fixture(params=sorted(PIPELINES))
def run(request):
    return PIPELINES[request.param]


@pytest.fixture(params=sorted(FORMS))
def form(request):
    return FORMS[request.param]


def _suite_verify(sd_jwt):
    return SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=KEY.public_jwk())


def _present(claims, *, typ):
    """A KB-JWT presentation of a hand-minted token, bound to CLIENT_ID and NONCE."""
    holder = P256SigningKey.generate(kid="holder")
    sd_jwt = _mint({**claims, "cnf": {"jwk": holder.public_jwk()}}, typ=typ)
    return SdJwtVcProofSuite().create_presentation(
        sd_jwt, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)


def _answer(presentation, *, vct_values=None):
    query = {"id": "q", "format": "dc+sd-jwt"}
    if vct_values is not None:
        query["meta"] = {"vct_values": vct_values}
    return verify_vp_token({"q": [presentation]}, dcql_query={"credentials": [query]},
                           nonce=NONCE, client_id=CLIENT_ID).for_query("q")[0]


VCDM_CONTEXTS = pytest.mark.parametrize("context", [
    [V2, EXAMPLES_V2],
    V2,
    ["https://example.org/ctx", V2],
    [V1],
], ids=["v2-array", "v2-string", "v2-not-first", "v1"])

NOT_VCDM_CONTEXTS = pytest.mark.parametrize("context", [
    ["https://example.org/ctx"],
    "https://example.org/ctx",
    [V2 + "/"],
    ["https://WWW.W3.ORG/ns/credentials/v2"],
    [2, None, {"@vocab": V2}],
    {"@vocab": V2},
    [],
    None,
    "",
], ids=["foreign-array", "foreign-string", "trailing-slash", "case-variant",
        "non-string-entries", "object", "empty-array", "null", "empty-string"])

WITH_VCT = pytest.mark.parametrize("with_vct", [False, True], ids=["no-vct", "with-vct"])

VCT_VALUES = pytest.mark.parametrize("vct_values", [None, [VCT]],
                                     ids=["no-vct-values", "vct-values"])

# The media type of an EnvelopedVerifiableCredential's `data:` URL: unsigned, so it is
# whatever the sender wrote. The middle one is the draft-era name of vc+sd-jwt.
MEDIA_TYPES = pytest.mark.parametrize("media", [
    "application/vc+sd-jwt",
    "application/vc+ld+json+sd-jwt",
    "application/dc+sd-jwt",
], ids=["vc-sd-jwt", "draft-era", "dc-sd-jwt"])

# A `typ` member that is present and not one of dc+sd-jwt / vc+sd-jwt / vc+ld+json+sd-jwt.
# The arrays and objects are unhashable (a bare `in frozenset` would raise TypeError); the
# rest are the near-misses a lenient matcher would let through.
WRONG_TYPS = pytest.mark.parametrize("typ", [
    pytest.param(None, id="null"),
    pytest.param(0, id="zero"),
    pytest.param(1, id="one"),
    pytest.param(1.5, id="float"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param([], id="empty-array"),
    pytest.param(["vc+sd-jwt"], id="array-of-vc-sd-jwt"),
    pytest.param(["dc+sd-jwt"], id="array-of-dc-sd-jwt"),
    pytest.param({}, id="empty-object"),
    pytest.param({"typ": "vc+sd-jwt"}, id="object"),
    pytest.param("", id="empty-string"),
    pytest.param("JWT", id="jwt"),
    pytest.param("kb+jwt", id="kb-jwt"),
    pytest.param("vc+jwt", id="vc-jwt"),
    pytest.param("vp+sd-jwt", id="vp-sd-jwt"),
    pytest.param("vp+ld+json+sd-jwt", id="vp-draft-typ"),
    pytest.param("sd-jwt", id="sd-jwt"),
    pytest.param("VC+SD-JWT", id="upper-case-vc"),
    pytest.param("Vc+Sd-Jwt", id="mixed-case-vc"),
    pytest.param("DC+SD-JWT", id="upper-case-dc"),
    pytest.param("application/vc+sd-jwt", id="media-type-vc"),
    pytest.param("application/dc+sd-jwt", id="media-type-dc"),
    pytest.param(" vc+sd-jwt", id="leading-space-vc"),
    pytest.param("vc+sd-jwt ", id="trailing-space-vc"),
    pytest.param("dc+sd-jwt ", id="trailing-space-dc"),
    pytest.param("vc+sd-jwt\n", id="trailing-newline-vc"),
    pytest.param("v" + chr(0x0441) + "+sd-jwt", id="cyrillic-es"),   # U+0441 looks like "c"
])

# The draft-era typ, nearly: none of these is it.
DRAFT_NEAR_MISSES = pytest.mark.parametrize("typ", [
    pytest.param("VC+LD+JSON+SD-JWT", id="upper-case"),
    pytest.param("Vc+Ld+Json+Sd-Jwt", id="mixed-case"),
    pytest.param("vc+ld+json+sd-jwt ", id="trailing-space"),
    pytest.param(" vc+ld+json+sd-jwt", id="leading-space"),
    pytest.param("vc+ld+json+sd-jwt\n", id="trailing-newline"),
    pytest.param("application/vc+ld+json+sd-jwt", id="media-type"),
    pytest.param("vc+ld+json+jwt", id="jwt-not-sd-jwt"),
    pytest.param("vc+ld+json", id="no-sd-jwt-suffix"),
    pytest.param("ld+json+sd-jwt", id="no-vc-prefix"),
])

# Whatever the value, a `vc` / `vp` member is present, and §3.1.3 says it MUST NOT be.
CLAIM_VALUES = pytest.mark.parametrize("value", [
    pytest.param(EMBEDDED_VC, id="credential-object"),
    pytest.param({}, id="empty-object"),
    pytest.param(None, id="null"),
    pytest.param(False, id="false"),
    pytest.param(0, id="zero"),
    pytest.param("", id="empty-string"),
    pytest.param([], id="empty-array"),
    pytest.param("did:example:vc", id="string"),
])


# --------------------------------------------------------------------------- #
# the helper: three states of `typ`, so the tests below mean what they say
# --------------------------------------------------------------------------- #

def test_the_helper_writes_no_typ_member_by_default_a_null_one_or_the_given_string():
    assert "typ" not in _header(_mint(_vcdm()))
    assert "typ" in _header(_mint(_vcdm(), typ=None))
    assert _header(_mint(_vcdm(), typ=None))["typ"] is None
    assert _header(_mint(_vcdm(), typ="vc+sd-jwt"))["typ"] == "vc+sd-jwt"


# --------------------------------------------------------------------------- #
# A. no typ member and a VCDM @context: accepted as VCDM (#288)
# --------------------------------------------------------------------------- #

@VCDM_CONTEXTS
@WITH_VCT
def test_a_vcdm_sd_jwt_with_no_typ_verifies_as_vcdm(run, form, context, with_vct):
    # VC-JOSE-COSE §3.2.1: the typ is a SHOULD, and Examples 4 and 5 omit it.
    doc = _vcdm(**{"@context": context})
    if with_vct:
        doc["vct"] = VCT
    result = run(form(_mint(doc)), None)
    assert result.format == "sd-jwt-vc"
    assert result.raw.vcdm is True
    assert result.raw.typ is None
    assert result.raw.vct == (VCT if with_vct else None)
    assert result.issuer == DID
    assert result.expired is False


def test_the_suite_reports_no_typ_directly_not_only_the_pipeline():
    for doc in (_vcdm(), _vcdm_vct()):
        result = _suite_verify(_mint(doc))
        assert result.typ is None
        assert result.vcdm is True


def test_disclosed_vcdm_claims_are_reconstructed_on_a_token_with_no_typ(run, form):
    # The Recommendation's own examples make `id`, `type` and the subject disclosable.
    sd_jwt = _mint(_vcdm(), disclose=["id", "type", "credentialSubject"])
    result = run(form(sd_jwt), None)
    assert result.claims["id"] == "urn:uuid:5e1d6a3c-cred"
    assert result.claims["type"] == ["VerifiableCredential", "ExampleAlumniCredential"]
    assert result.claims["credentialSubject"]["alumniOf"] == "Example University"
    assert result.raw.typ is None
    assert result.raw.vcdm is True


@pytest.mark.parametrize("typ", [ABSENT, DRAFT_TYP], ids=["no-typ", "draft-typ"])
def test_key_binding_still_binds_a_token_with_no_typ_or_the_draft_typ(run, typ):
    # The typ is not what binds a presentation to its holder, a KB-JWT is: a token whose
    # typ says nothing is held to require_key_binding like any other.
    policy = VerificationPolicy(audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    presentation = _present(_vcdm(), typ=typ)
    result = run(presentation, policy)
    assert result.raw.key_bound is True
    assert result.raw.typ == (None if typ is ABSENT else typ)
    without_kb_jwt = presentation.rsplit("~", 1)[0] + "~"
    with pytest.raises(ClaimsInvalid, match="key binding required") as excinfo:
        run(without_kb_jwt, policy)
    assert excinfo.type is ClaimsInvalid


@MEDIA_TYPES
@pytest.mark.parametrize("typ", [ABSENT, DRAFT_TYP], ids=["no-typ", "draft-typ"])
def test_the_media_type_of_an_envelope_is_not_the_typ(run, media, typ):
    # The data: URL's media type is not signed. The verified typ is the issuer JWT
    # header's, absent or not, whichever name the envelope gives its content.
    result = run(_envelope(_mint(_vcdm(), typ=typ), media=media), None)
    assert result.raw.typ == (None if typ is ABSENT else typ)
    assert result.raw.vcdm is True


# --------------------------------------------------------------------------- #
# B. a token with no typ keeps every VCDM check
# --------------------------------------------------------------------------- #

@WITH_VCT
def test_no_typ_vcdm_expired_valid_until_still_fails(run, form, with_vct):
    extra = {"vct": VCT} if with_vct else {}
    with pytest.raises(CredentialExpired):
        run(form(_mint(_vcdm(validUntil=PAST, **extra))), None)


@WITH_VCT
def test_no_typ_vcdm_future_valid_from_still_fails(run, form, with_vct):
    extra = {"vct": VCT} if with_vct else {}
    with pytest.raises(CredentialNotYetValid):
        run(form(_mint(_vcdm(validFrom=FUTURE, **extra))), None)


def test_no_typ_vcdm_expiry_is_waived_and_reported(run, form):
    waived = VerificationPolicy(require_not_expired=False)
    result = run(form(_mint(_vcdm(validUntil=PAST))), waived)
    assert result.expired is True
    assert result.raw.vcdm is True
    assert result.raw.typ is None


def test_the_expiry_waiver_does_not_waive_a_future_valid_from(run, form):
    waived = VerificationPolicy(require_not_expired=False)
    with pytest.raises(CredentialNotYetValid):
        run(form(_mint(_vcdm(validFrom=FUTURE))), waived)


def test_no_typ_vcdm_1_1_names_are_enforced_too(run, form):
    doc = _vcdm(**{"@context": [V1]})
    del doc["validFrom"]
    with pytest.raises(CredentialExpired):
        run(form(_mint({**doc, "issuanceDate": PAST, "expirationDate": PAST})), None)
    with pytest.raises(CredentialNotYetValid):
        run(form(_mint({**doc, "issuanceDate": FUTURE})), None)


def test_no_typ_vcdm_issuer_conflict_still_fails(run, form):
    with pytest.raises(ClaimsInvalid, match="issuer") as excinfo:
        run(form(_mint(_vcdm(issuer="did:web:university.example"))), None)
    assert excinfo.type is ClaimsInvalid


def test_no_typ_vcdm_jti_and_sub_conflicts_still_fail(run, form):
    with pytest.raises(ClaimsInvalid, match="jti"):
        run(form(_mint(_vcdm(jti="urn:uuid:another-credential"))), None)
    with pytest.raises(ClaimsInvalid, match="sub"):
        run(form(_mint(_vcdm(sub="did:example:bob"))), None)


# --------------------------------------------------------------------------- #
# C. no typ and no VCDM @context (or a vc / vp claim): refused
# --------------------------------------------------------------------------- #

def test_an_ietf_payload_with_a_vct_and_no_typ_is_refused(run, form):
    # An IETF SD-JWT VC is typed dc+sd-jwt (draft-19 §2.2.1): no typ is not "any typ".
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_ietf())), None)
    assert excinfo.type is SdJwtError


@MEDIA_TYPES
def test_a_media_type_does_not_talk_an_ietf_payload_with_no_typ_into_verifying(run, media):
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(_envelope(_mint(_ietf()), media=media), None)
    assert excinfo.type is SdJwtError


def test_the_same_ietf_payload_typed_dc_sd_jwt_verifies(run, form):
    # The only difference from the refused token above is the typ.
    result = run(form(_mint(_ietf(), typ="dc+sd-jwt")), None)
    assert result.raw.vct == VCT
    assert result.raw.vcdm is False


def test_a_payload_with_neither_a_vct_nor_a_context_and_no_typ_is_refused(run, form):
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_vct_less())), None)
    assert excinfo.type is SdJwtError


def test_the_suite_refuses_a_token_with_no_typ_and_no_context_directly():
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT):
        _suite_verify(_mint(_ietf()))
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT):
        _suite_verify(_mint(_vct_less()))


def test_a_withheld_vct_leaves_a_token_with_no_typ_refused(run, form):
    # The issuer made vct a disclosure and the holder drops it: nothing is left to say
    # "VCDM", and with no typ nothing says "IETF" either.
    sd_jwt = _without(_mint(_ietf(), disclose=["vct"]), "vct")
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError


def test_a_presented_disclosable_vct_is_refused_as_a_disclosure_with_no_typ(run, form):
    with pytest.raises(SdJwtError, match=VCT_DISCLOSED) as excinfo:
        run(form(_mint(_ietf(), disclose=["vct"])), None)
    assert excinfo.type is SdJwtError


@NOT_VCDM_CONTEXTS
def test_a_context_that_is_not_a_vcdm_base_context_does_not_rescue_a_token_with_no_typ(
        run, form, context):
    # A full VCDM body, vct and all: only the @context differs from a token that verifies.
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_vcdm_vct(**{"@context": context}))), None)
    assert excinfo.type is SdJwtError


def test_a_vcdm_body_minus_its_context_is_refused_with_no_typ(run, form):
    doc = _vcdm_vct()
    del doc["@context"]
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT):
        run(form(_mint(doc)), None)


def test_a_withheld_context_leaves_a_vcdm_token_with_no_typ_refused(run, form):
    # The issuer made @context a disclosure and the holder drops it: the payload is then
    # not VCDM, so it cannot be admitted as one (and its VCDM window would be off).
    sd_jwt = _without(_mint(_vcdm(), disclose=["@context"]), "@context")
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError


def test_a_presented_context_disclosure_is_refused_as_a_disclosure_with_no_typ(run, form):
    # Refused on the disclosure rule, ahead of the typ gate: a different message from the
    # withheld case above, so neither test can pass on the other's path.
    with pytest.raises(SdJwtError, match=CONTEXT_DISCLOSED) as excinfo:
        run(form(_mint(_vcdm(), disclose=["@context"])), None)
    assert excinfo.type is SdJwtError
    assert "needs a W3C VCDM @context" not in str(excinfo.value)


@pytest.mark.parametrize("name", ["vc", "vp"])
@CLAIM_VALUES
def test_a_plaintext_vc_or_vp_claim_is_refused_with_no_typ(run, form, name, value):
    # §3.1.3 bans the claim names. With no typ for the VC-JWT lane to refuse, a `vc` object
    # would make this token both an SD-JWT VC here and a VC-JWT there once its `~` tail is
    # dropped (#189). It is refused so that no token accepted here can be downgraded so.
    with pytest.raises(SdJwtError, match=NO_TYP_NO_VC_CLAIM) as excinfo:
        run(form(_mint(_vcdm(**{name: value}))), None)
    assert excinfo.type is SdJwtError


@pytest.mark.parametrize("name", ["vc", "vp"])
def test_a_disclosed_and_presented_vc_or_vp_claim_is_refused_with_no_typ(run, form, name):
    # The ban reads the processed payload, so a claim the issuer put in a disclosure counts
    # once the holder presents it.
    sd_jwt = _mint(_vcdm(**{name: EMBEDDED[name]}), disclose=[name])
    with pytest.raises(SdJwtError, match=NO_TYP_NO_VC_CLAIM) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError


@pytest.mark.parametrize("extra", [
    pytest.param({"vc": EMBEDDED_VC, "vp": EMBEDDED_VP}, id="both"),
    pytest.param({"vc": EMBEDDED_VC, "vct": VCT}, id="vc-with-a-vct"),
    pytest.param({"vp": EMBEDDED_VP, "vct": VCT}, id="vp-with-a-vct"),
])
def test_the_vc_and_vp_ban_holds_for_both_claims_together_and_with_a_vct(run, form, extra):
    with pytest.raises(SdJwtError, match=NO_TYP_NO_VC_CLAIM) as excinfo:
        run(form(_mint(_vcdm(**extra))), None)
    assert excinfo.type is SdJwtError


def test_a_vc_member_nested_in_the_subject_is_not_the_claim_the_ban_is_about(run, form):
    # §3.1.3 bans the JWT claims `vc` and `vp`, i.e. top-level members; a credential may
    # carry any property, `vc` included, inside its subject.
    doc = _vcdm(credentialSubject={"id": "did:example:alice", "vc": EMBEDDED_VC})
    result = run(form(_mint(doc)), None)
    assert result.raw.vcdm is True
    assert result.claims["credentialSubject"]["vc"] == EMBEDDED_VC


# --------------------------------------------------------------------------- #
# D. a typ that is present and wrong is refused, null included (rule 3)
# --------------------------------------------------------------------------- #

@WRONG_TYPS
def test_a_present_typ_outside_the_closed_set_is_refused(run, form, typ):
    # A VCDM payload with a vct, so no accepted typ would object to it: the typ is the only
    # defect, and a token that gets through verifies.
    with pytest.raises(SdJwtError, match=UNEXPECTED_TYP) as excinfo:
        run(form(_mint(_vcdm_vct(), typ=typ)), None)
    assert excinfo.type is SdJwtError


@WRONG_TYPS
def test_the_suite_refuses_a_present_wrong_typ_directly(typ):
    with pytest.raises(SdJwtError, match=UNEXPECTED_TYP) as excinfo:
        _suite_verify(_mint(_vcdm_vct(), typ=typ))
    assert excinfo.type is SdJwtError


def test_a_null_typ_is_a_present_typ_not_an_absent_one(run, form):
    # The same VCDM payload: no typ member verifies, `"typ": null` does not, and the refusal
    # is the typ's own (it names None), not the "without a typ" one.
    assert run(form(_mint(_vcdm())), None).raw.typ is None
    with pytest.raises(SdJwtError, match=rf"{UNEXPECTED_TYP} None") as excinfo:
        run(form(_mint(_vcdm(), typ=None)), None)
    assert excinfo.type is SdJwtError
    assert "without a typ" not in str(excinfo.value)


def test_a_null_typ_is_refused_for_an_ietf_payload_too(run, form):
    with pytest.raises(SdJwtError, match=rf"{UNEXPECTED_TYP} None"):
        run(form(_mint(_ietf(), typ=None)), None)


@pytest.mark.parametrize("typ", ["vc+sd-jwt", DRAFT_TYP, "dc+sd-jwt"],
                         ids=["vc-sd-jwt", "draft-typ", "dc-sd-jwt"])
def test_control_the_payload_of_the_wrong_typ_tests_verifies_under_each_accepted_typ(
        run, form, typ):
    # The control for the refusals above: the same payload under each accepted typ.
    result = run(form(_mint(_vcdm_vct(), typ=typ)), None)
    assert result.raw.typ == typ
    assert result.raw.vcdm is True


# --------------------------------------------------------------------------- #
# E. vc+ld+json+sd-jwt: treated like vc+sd-jwt (#289)
# --------------------------------------------------------------------------- #

@VCDM_CONTEXTS
@WITH_VCT
def test_the_draft_era_typ_verifies_as_vcdm_with_a_vcdm_context(run, form, context, with_vct):
    doc = _vcdm(**{"@context": context})
    if with_vct:
        doc["vct"] = VCT
    result = run(form(_mint(doc, typ=DRAFT_TYP)), None)
    assert result.raw.typ == DRAFT_TYP
    assert result.raw.vcdm is True
    assert result.raw.vct == (VCT if with_vct else None)


def test_the_suite_reports_the_draft_era_typ_directly():
    for doc in (_vcdm(), _vcdm_vct()):
        result = _suite_verify(_mint(doc, typ=DRAFT_TYP))
        assert result.typ == DRAFT_TYP
        assert result.vcdm is True


@WITH_VCT
def test_draft_typ_vcdm_expired_valid_until_still_fails(run, form, with_vct):
    extra = {"vct": VCT} if with_vct else {}
    with pytest.raises(CredentialExpired):
        run(form(_mint(_vcdm(validUntil=PAST, **extra), typ=DRAFT_TYP)), None)


def test_draft_typ_vcdm_future_valid_from_still_fails(run, form):
    with pytest.raises(CredentialNotYetValid):
        run(form(_mint(_vcdm(validFrom=FUTURE), typ=DRAFT_TYP)), None)


def test_draft_typ_vcdm_expiry_is_waived_and_reported(run, form):
    waived = VerificationPolicy(require_not_expired=False)
    result = run(form(_mint(_vcdm(validUntil=PAST), typ=DRAFT_TYP)), waived)
    assert result.expired is True
    assert result.raw.typ == DRAFT_TYP


def test_draft_typ_vcdm_issuer_conflict_still_fails(run, form):
    with pytest.raises(ClaimsInvalid, match="issuer"):
        run(form(_mint(_vcdm(issuer="did:web:university.example"), typ=DRAFT_TYP)), None)


def test_a_vct_bearing_ietf_payload_typed_with_the_draft_typ_is_refused(run, form):
    # The draft-era name says "W3C VC", not "IETF SD-JWT VC": a vct does not make it one.
    with pytest.raises(SdJwtError, match=DRAFT_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_ietf(), typ=DRAFT_TYP)), None)
    assert excinfo.type is SdJwtError


def test_a_payload_with_no_vct_and_no_context_typed_with_the_draft_typ_is_refused(run, form):
    with pytest.raises(SdJwtError, match=DRAFT_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_vct_less(), typ=DRAFT_TYP)), None)
    assert excinfo.type is SdJwtError


def test_a_withheld_context_leaves_a_draft_typ_token_refused(run, form):
    sd_jwt = _without(_mint(_vcdm(), typ=DRAFT_TYP, disclose=["@context"]), "@context")
    with pytest.raises(SdJwtError, match=DRAFT_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError


def test_a_presented_context_disclosure_is_refused_as_a_disclosure_with_the_draft_typ(
        run, form):
    with pytest.raises(SdJwtError, match=CONTEXT_DISCLOSED) as excinfo:
        run(form(_mint(_vcdm(), typ=DRAFT_TYP, disclose=["@context"])), None)
    assert excinfo.type is SdJwtError


@NOT_VCDM_CONTEXTS
def test_a_foreign_context_does_not_rescue_a_draft_typ_token(run, form, context):
    with pytest.raises(SdJwtError, match=DRAFT_TYP_NEEDS_CONTEXT):
        run(form(_mint(_vcdm_vct(**{"@context": context}), typ=DRAFT_TYP)), None)


@DRAFT_NEAR_MISSES
def test_a_near_miss_of_the_draft_typ_is_refused_as_an_unexpected_typ(run, form, typ):
    # Exact matching: a VCDM payload that would verify under the real name is refused.
    with pytest.raises(SdJwtError, match=UNEXPECTED_TYP) as excinfo:
        run(form(_mint(_vcdm_vct(), typ=typ)), None)
    assert excinfo.type is SdJwtError


@DRAFT_NEAR_MISSES
def test_the_suite_refuses_a_draft_typ_near_miss_directly(typ):
    with pytest.raises(SdJwtError, match=UNEXPECTED_TYP):
        _suite_verify(_mint(_vcdm_vct(), typ=typ))


# --------------------------------------------------------------------------- #
# F. dc+sd-jwt is unchanged (#272)
# --------------------------------------------------------------------------- #

def test_a_dc_sd_jwt_ietf_token_still_verifies(run, form):
    result = run(form(_mint(_ietf(), typ="dc+sd-jwt")), None)
    assert result.raw.typ == "dc+sd-jwt"
    assert result.raw.vct == VCT
    assert result.raw.vcdm is False


@VCDM_CONTEXTS
def test_a_dc_sd_jwt_vcdm_payload_with_no_vct_is_still_refused_for_the_vct(
        run, form, context):
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT) as excinfo:
        run(form(_mint(_vcdm(**{"@context": context}), typ="dc+sd-jwt")), None)
    assert excinfo.type is ClaimsInvalid


def test_a_dc_sd_jwt_with_neither_a_vct_nor_a_context_is_still_refused_for_the_vct(run, form):
    with pytest.raises(ClaimsInvalid, match=NEEDS_VCT) as excinfo:
        run(form(_mint(_vct_less(), typ="dc+sd-jwt")), None)
    assert excinfo.type is ClaimsInvalid


def test_a_dc_sd_jwt_with_a_vcdm_context_and_a_vct_still_verifies_as_vcdm(run, form):
    result = run(form(_mint(_vcdm_vct(), typ="dc+sd-jwt")), None)
    assert result.raw.typ == "dc+sd-jwt"
    assert result.raw.vcdm is True
    assert result.raw.vct == VCT


# --------------------------------------------------------------------------- #
# G. the VC-JWT lane is untouched: an issuer JWT whose ~ tail is dropped
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("disclose", [(), ("credentialSubject",)],
                         ids=["plain", "with-disclosures"])
@WITH_VCT
def test_a_no_typ_vcdm_sd_jwt_without_its_tail_is_refused_for_having_no_vc_claim(
        run, form, disclose, with_vct):
    # A compact JWS goes to the VC-JWT lane. The payload is a VCDM credential itself, not a
    # JWT carrying one under `vc`, so that lane has nothing to verify.
    jws = _tail_dropped(_mint(_vcdm_vct() if with_vct else _vcdm(), disclose=disclose))
    assert "~" not in jws
    with pytest.raises(ClaimsInvalid, match=NO_VC_OBJECT) as excinfo:
        run(form(jws), None)
    assert excinfo.type is ClaimsInvalid


@pytest.mark.parametrize("typ", ["vc+sd-jwt", DRAFT_TYP, "dc+sd-jwt"],
                         ids=["vc-sd-jwt", "draft-typ", "dc-sd-jwt"])
@pytest.mark.parametrize("carries_vc", [False, True], ids=["no-vc-claim", "vc-claim"])
def test_a_typed_sd_jwt_without_its_tail_is_refused_by_the_vc_jwt_lane(
        run, form, typ, carries_vc):
    # `_reject_sd_jwt_typ` (#189) refuses any `+sd-jwt` typ, so the draft-era one is fenced
    # off the VC-JWT lane like the registered one, even when the payload has a `vc` object
    # that lane would otherwise take.
    doc = _vcdm_vct(vc=EMBEDDED_VC) if carries_vc else _vcdm_vct()
    jws = _tail_dropped(_mint(doc, typ=typ))
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        run(form(jws), None)
    assert excinfo.type is MalformedToken


@pytest.mark.parametrize("media", [
    "application/vc+sd-jwt", "application/vc+ld+json+sd-jwt", "application/vc+jwt",
    "application/jwt",
], ids=["vc-sd-jwt", "draft-era", "vc-jwt", "jwt"])
@pytest.mark.parametrize("typ, error, message", [
    pytest.param(ABSENT, ClaimsInvalid, NO_VC_OBJECT, id="no-typ"),
    pytest.param(DRAFT_TYP, MalformedToken, NOT_A_VC_JWT, id="draft-typ"),
])
def test_the_media_type_of_an_envelope_does_not_change_the_vc_jwt_lane_verdict(
        run, media, typ, error, message):
    # Whatever the unsigned media type says, a compact JWS is a VC-JWT to the pipeline, and
    # the lane refuses these two for the reasons above.
    jws = _tail_dropped(_mint(_vcdm_vct(), typ=typ))
    with pytest.raises(error, match=message) as excinfo:
        run(_envelope(jws, media=media), None)
    assert excinfo.type is error


# --------------------------------------------------------------------------- #
# H. OpenID4VP: neither new case answers a dc+sd-jwt query (#272)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("typ, got", [(ABSENT, "None"), (DRAFT_TYP, "'vc+ld+json+sd-jwt'")],
                         ids=["no-typ", "draft-typ"])
@pytest.mark.parametrize("claims, vct_values", [
    pytest.param(_vcdm(), None, id="no-vct-no-vct-values"),
    pytest.param(_vcdm_vct(), None, id="vct-no-vct-values"),
    pytest.param(_vcdm_vct(), [VCT], id="vct-matching-vct-values"),
])
def test_openid4vp_dc_sd_jwt_query_refuses_a_vcdm_credential_with_no_typ_or_the_draft_typ(
        typ, got, claims, vct_values):
    # The pipeline names every SD-JWT "sd-jwt-vc"; the dc+sd-jwt format is the IETF SD-JWT
    # VC, whose issuer JWT is typed dc+sd-jwt. The lane names what it saw.
    with pytest.raises(VpTokenMalformed, match=NOT_IETF) as excinfo:
        _answer(_present(claims, typ=typ), vct_values=vct_values)
    assert excinfo.type is VpTokenMalformed
    assert f"issuer JWT typ 'dc+sd-jwt', got {got}" in str(excinfo.value)


@VCT_VALUES
def test_openid4vp_an_ietf_credential_with_no_typ_is_refused_by_the_suite_first(vct_values):
    # Even a vct that matches the query's vct_values does not rescue it: the suite refuses
    # an untyped token without a VCDM context before the lane looks at the typ.
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        _answer(_present(_ietf(), typ=ABSENT), vct_values=vct_values)
    assert excinfo.type is SdJwtError


@VCT_VALUES
def test_openid4vp_control_a_dc_sd_jwt_with_a_vct_still_answers(vct_values):
    answer = _answer(_present(_ietf(), typ="dc+sd-jwt"), vct_values=vct_values)
    assert answer.raw.typ == "dc+sd-jwt"
    assert answer.raw.vct == VCT
    assert answer.raw.key_bound is True


@VCT_VALUES
def test_openid4vp_control_a_dc_sd_jwt_with_a_vcdm_context_and_a_vct_still_answers(
        vct_values):
    answer = _answer(_present(_vcdm_vct(), typ="dc+sd-jwt"), vct_values=vct_values)
    assert answer.raw.typ == "dc+sd-jwt"
    assert answer.raw.vcdm is True
    assert answer.raw.key_bound is True


# --------------------------------------------------------------------------- #
# I. real tokens of the W3C Recommendation
# --------------------------------------------------------------------------- #

# Provenance. Both tokens are copied from "Securing Verifiable Credentials using JOSE and
# COSE", the W3C Recommendation of 13 October 2026, https://www.w3.org/TR/vc-jose-cose/ :
#
#   rec-example5-no-typ.sd-jwt
#       Example 5, section 3.2.2 (an SD-JWT presentation of an EnvelopedVerifiableCredential):
#       the SD-JWT-secured credential in the `data:application/vc+sd-jwt,` URL of its `id`.
#       Header {kid, alg: ES256} and no typ (typ is a SHOULD, section 3.2.1); 6 disclosures.
#   rec-example21-vc-ld-json-sd-jwt-typ.sd-jwt
#       Example 21, section 8.4 "Data URIs": the SD-JWT-secured credential of a URI-encoded
#       example. Header {alg: ES384, kid, typ: vc+ld+json+sd-jwt, cty: vc+ld+json}; 6
#       disclosures. (The draft-era media type name; the section 6.1.3 name is vc+sd-jwt.)
#
# The Recommendation publishes no signing key for either, so neither can verify here. Each
# is verified against an unrelated key of the right curve with check_temporal=False, and
# must fail at the signature (`SignatureInvalid`), which comes right after the typ gate: that
# pins that a real W3C header gets through the gate. The suite is called directly, not the
# pipeline: Example 5's payload names its issuer only in `issuer`, with no `iss` claim, and
# the pipeline selects the key from `iss` (peek_issuer), as does the suite afterwards; and
# Example 21's `iss` is an https URL, which the offline DID resolvers do not resolve. A P-256
# key for the ES384 token would be a ProofError ("malformed public key"), not a bad
# signature, which is why Example 21 gets a P-384 one.
FIXTURES = Path(__file__).parent / "fixtures" / "vc_jose_cose"
EXAMPLE_5 = "rec-example5-no-typ.sd-jwt"
EXAMPLE_21 = "rec-example21-vc-ld-json-sd-jwt-typ.sd-jwt"

REAL_TOKENS = pytest.mark.parametrize("name, key_class", [
    pytest.param(EXAMPLE_5, P256SigningKey, id="example-5"),
    pytest.param(EXAMPLE_21, P384SigningKey, id="example-21"),
])

# The same two, each with a typ that is not its own and is refused: for the control below.
RETYPED_REAL_TOKENS = pytest.mark.parametrize("name, key_class, wrong_typ", [
    pytest.param(EXAMPLE_5, P256SigningKey, "JWT", id="example-5"),
    pytest.param(EXAMPLE_21, P384SigningKey, DRAFT_TYP + " ", id="example-21"),
])


def _fixture(name):
    """A token as the Recommendation prints it, without the file's trailing newline."""
    return (FIXTURES / name).read_text(encoding="ascii").rstrip("\n")


def _retyped(token, typ):
    """The real token with its header's typ replaced and everything else as published."""
    jws, rest = token.split("~", 1)
    header_b64, payload_b64, signature = jws.split(".")
    header = _decode(header_b64)
    header["typ"] = typ
    header_b64 = _b64(json.dumps(header, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}.{signature}~{rest}"


def _resigned(token, key, *, amend=None):
    """The real token's header and payload (the payload amended by *amend*, if given, and
    re-serialised then) under *key*'s signature, disclosures untouched: the ``_sd`` digests
    hash the disclosures, not the payload, so they still match."""
    jws, rest = token.split("~", 1)
    header_b64, payload_b64, _ = jws.split(".")
    if amend is not None:
        payload = _decode(payload_b64)
        amend(payload)
        payload_b64 = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}~{rest}"


def test_example_5_of_the_recommendation_has_a_header_with_no_typ():
    token = _fixture(EXAMPLE_5)
    header = _header(token)
    assert "typ" not in header
    assert set(header) == {"kid", "alg"}
    assert header["alg"] == "ES256"
    payload = _payload(token)
    assert V2 in payload["@context"]
    assert "vc" not in payload and "vp" not in payload
    assert len(token.split("~")) == 8 and token.endswith("~")       # 6 disclosures, no KB-JWT


def test_example_21_of_the_recommendation_has_the_draft_era_typ():
    token = _fixture(EXAMPLE_21)
    header = _header(token)
    assert header["typ"] == DRAFT_TYP
    assert header["alg"] == "ES384"
    assert header["cty"] == "vc+ld+json"
    payload = _payload(token)
    assert V2 in payload["@context"]
    assert "vc" not in payload and "vp" not in payload
    assert len(token.split("~")) == 8 and token.endswith("~")


@REAL_TOKENS
def test_a_real_w3c_header_gets_past_the_typ_gate_and_fails_only_at_the_signature(
        name, key_class):
    stranger = key_class.generate(kid="stranger")
    with pytest.raises(SignatureInvalid) as excinfo:
        SdJwtVcProofSuite().verify(_fixture(name), public_key_jwk=stranger.public_jwk(),
                                   check_temporal=False)
    assert excinfo.type is SignatureInvalid


@RETYPED_REAL_TOKENS
def test_the_typ_gate_is_live_on_the_same_real_token(name, key_class, wrong_typ):
    # The control for the test above. Only the header's typ is changed, and the verdict
    # moves from the signature to the gate: the unamended token really did clear it.
    stranger = key_class.generate(kid="stranger")
    with pytest.raises(SdJwtError, match=UNEXPECTED_TYP) as excinfo:
        SdJwtVcProofSuite().verify(_retyped(_fixture(name), wrong_typ),
                                   public_key_jwk=stranger.public_jwk(), check_temporal=False)
    assert excinfo.type is SdJwtError


def test_example_21_verifies_end_to_end_under_a_key_of_our_own():
    # Header, payload and disclosures are the Recommendation's; only the signature is ours.
    key = P384SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_21), key)
    suite = SdJwtVcProofSuite()
    # The example's own `exp` (2024-10-14) has passed: that is why the tests waive it.
    with pytest.raises(ClaimsInvalid, match="expired"):
        suite.verify(token, public_key_jwk=key.public_jwk())
    result = suite.verify(token, public_key_jwk=key.public_jwk(), check_temporal=False)
    assert result.typ == DRAFT_TYP
    assert result.vcdm is True
    assert result.expired is True
    assert result.issuer == "https://university.example/issuers/565049"
    claims = result.claims
    assert claims["id"] == "http://university.example/credentials/1872"
    assert claims["type"] == ["VerifiableCredential", "ExampleAlumniCredential"]
    assert claims["credentialSubject"]["id"] == "did:example:123"
    assert claims["credentialSubject"]["degree"]["type"] == "BachelorDegree"
    assert claims["credentialSchema"] == {"id": "https://example.org/examples/degree.json",
                                          "type": "JsonSchema"}


def _example_21_and_the_metadata_of_its_issuer():
    """Example 21 re-signed by a key of ours, and the JWT VC Issuer Metadata that publishes
    that key for the example's https issuer under the example's `kid`."""
    token = _fixture(EXAMPLE_21)
    kid = _header(token)["kid"]
    key = P384SigningKey.generate(kid=kid)
    metadata = {"issuer": _payload(token)["iss"],
                "jwks": {"keys": [{**key.public_jwk(), "kid": kid}]}}
    return _resigned(token, key), metadata


ISSUER_METADATA_URL = "https://university.example/.well-known/jwt-vc-issuer/issuers/565049"


def test_example_21_verifies_through_the_sync_pipeline_with_its_https_issuer_resolved(form):
    # The whole path for a real token: format detection, `iss` as an https URL, the issuer's
    # key by `kid` from its metadata (a stub of the fetch), the draft-era typ, the VCDM
    # window (waived: the example's `exp` has passed).
    token, metadata = _example_21_and_the_metadata_of_its_issuer()
    fetched = []

    def fetch(url):
        fetched.append(url)
        return metadata

    result = verify_credential(form(token), policy=VerificationPolicy(require_not_expired=False),
                               jwt_vc_issuer_fetch=fetch)
    assert fetched == [ISSUER_METADATA_URL]
    assert result.format == "sd-jwt-vc"
    assert result.issuer == "https://university.example/issuers/565049"
    assert result.raw.typ == DRAFT_TYP
    assert result.raw.vcdm is True
    assert result.expired is True


def test_example_21_verifies_through_the_async_pipeline_with_its_https_issuer_resolved(form):
    token, metadata = _example_21_and_the_metadata_of_its_issuer()
    fetched = []

    async def fetch(url):
        fetched.append(url)
        return metadata

    result = asyncio.run(verify_credential_async(
        form(token), policy=VerificationPolicy(require_not_expired=False),
        jwt_vc_issuer_fetch=fetch))
    assert fetched == [ISSUER_METADATA_URL]
    assert result.raw.typ == DRAFT_TYP
    assert result.raw.vcdm is True
    assert result.expired is True


def test_example_5_verifies_end_to_end_once_its_issuer_is_named_in_iss():
    # Example 5 has no `iss` claim, and this lane reads the verified issuer from `iss`, so
    # the published token cannot verify under any key. The one amendment here adds `iss`
    # (equal to the payload's `issuer`); every other member of the header, payload and
    # disclosures is the Recommendation's, and the signature is ours.
    key = P256SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_5), key,
                      amend=lambda payload: payload.__setitem__("iss", payload["issuer"]))
    result = SdJwtVcProofSuite().verify(token, public_key_jwk=key.public_jwk())
    assert result.typ is None
    assert result.vcdm is True
    assert result.expired is False
    assert result.issuer == "https://university.example/issuers/565049"
    claims = result.claims
    assert claims["id"] == "http://university.example/credentials/1872"
    assert claims["type"] == ["VerifiableCredential", "ExampleAlumniCredential"]
    assert claims["credentialSubject"]["id"] == "did:example:123"
    assert claims["credentialSubject"]["degree"]["type"] == "BachelorDegree"
