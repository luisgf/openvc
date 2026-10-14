"""
tests/test_sd_jwt_vcdm_typ_interop.py — a W3C VCDM credential secured with SD-JWT verifies
when its issuer JWT has no ``typ`` member, or carries the draft-era ``vc+ld+json+sd-jwt``
(#288, #289). #264 and #272 are the other directions of the same ``typ`` gate: #264 made
``vc+sd-jwt`` need a VCDM base ``@context``, and #272 made ``dc+sd-jwt`` always need a
``vct`` and the only typ the OpenID4VP ``dc+sd-jwt`` format answers. Those rules have their
own files (test_sd_jwt_vc_typ_vcdm_only.py, test_sd_jwt_vc_dc_typ_ietf_only.py); this one
pins what #288 and #289 let through, and what they must keep out. A VCDM presentation
secured with SD-JWT is the first of those: it has the ``@context`` of a credential and no
``vp`` claim, so with no ``typ`` nothing else tells it from a credential (#293). #275 then
holds every typ that reads as W3C (``vc+sd-jwt``, the draft-era one and an absent ``typ``)
to the same two requirements, and only ``dc+sd-jwt`` is exempt: the base URL is the FIRST
``@context`` entry (VCDM 2.0 §4.3) and the ``type`` includes ``VerifiableCredential`` and
not ``VerifiablePresentation`` (§4.5, §4.13).

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
  ``@context`` (VCDM 2.0 or 1.1, as a string or anywhere in an array: the lax test that
  turns the validity window on for every typ), carries no ``vc`` or ``vp`` claim (§3.1.3),
  and conforms to VCDM (#275): the base URL is the FIRST ``@context`` entry (§4.3, a bare
  string is its own first item), and the ``type`` (a string or an array) includes
  ``VerifiableCredential`` and not ``VerifiablePresentation`` (§4.5, §4.13). It then gets the
  VCDM validity window and the issuer / id / subject reconciliation, exactly like
  ``vc+sd-jwt``, and reports ``typ is None``. Without a VCDM ``@context`` anywhere it is
  ``SdJwtError``, a ``vct``-bearing IETF payload included: an IETF SD-JWT VC is typed
  ``dc+sd-jwt``. With a ``vc`` or ``vp`` claim it is ``SdJwtError``, and so it is with the
  base URL in second place or without that ``type`` (#293, #275), each with a message that
  names the requirement that failed. The ``type`` test is positive: a ``type`` that is absent,
  malformed or withheld (Example 4 of the Recommendation makes it selectively disclosable)
  is refused, like one that says "presentation" or names both. Every typ but ``dc+sd-jwt``
  is held to both: a ``vc+sd-jwt`` or ``vc+ld+json+sd-jwt`` says it is a credential, and the
  payload has to agree.
* **``vc+ld+json+sd-jwt``, exactly.** Treated like ``vc+sd-jwt``: it needs a VCDM
  ``@context`` that starts with the base URL and a credential ``type``, or it is
  ``SdJwtError``.
* **A ``typ`` that is present and anything else** is ``SdJwtError`` ("unexpected issuer JWT
  typ"): ``null``, any non-string, ``""``, ``JWT``, ``kb+jwt``, ``vc+jwt``, a case or
  whitespace variant, an ``application/`` prefix. A ``"typ": null`` member is present, not
  absent. Matching is exact.
* **``dc+sd-jwt`` is unchanged**: a non-empty string ``vct``, whatever the ``@context``
  (the base URL in second place included) and whatever the ``type``, absent or withheld.
* **The claim rules do not depend on the typ** (section K). Under no ``typ`` and the
  draft-era one, as under ``vc+sd-jwt``: a presented disclosure of a validity claim, of
  ``exp``, ``nbf``, ``cnf``, ``status``, ``credentialStatus``, ``aka_vcts`` or
  ``vct#integrity``, or of a sub-claim of one, is ``SdJwtError``; a disclosed ``iat`` is
  checked on the processed payload; ``expected_vct`` and ``aka_vcts`` are enforced; and the
  ``@context`` reader compares each entry exactly. A ``cty`` is never read as a ``typ``.
* **The VC-JWT lane is untouched.** A token with no ``typ`` that this lane accepts has no
  ``vc`` claim, so its ``~`` tail dropped is a compact JWS that the VC-JWT lane refuses
  ("no embedded ``vc`` object"); one typed ``vc+ld+json+sd-jwt`` is refused there by its
  ``+sd-jwt`` suffix (#189). A token with a ``vc`` object and no ``typ``, which this lane
  refuses, still verifies there with its tail dropped, as on ``main`` (#291). Every typ
  ``verify()`` accepts is refused by that filter, so a new one cannot slip through it.
* **OpenID4VP.** The ``dc+sd-jwt`` DCQL lane still answers only an issuer JWT typed
  ``dc+sd-jwt`` (#272), so neither new case answers a ``dc+sd-jwt`` query.

Two real tokens of the Recommendation sit in tests/fixtures/vc_jose_cose/ (section I).
Section J is the #293 type rule, widened by #275 to every typ but ``dc+sd-jwt``; K and L pin
the rules around the typ gate that a token with no ``typ``, or with the draft-era one, must
not get round.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; signatures are real P-256 (P-384 for
Example 21); ``asyncio.run`` drives the async pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
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
    _ACCEPTED_ISSUER_TYP,
    _OPENVC_NON_DISCLOSABLE,
    _SD_JWT_VC_NON_DISCLOSABLE,
    _VCDM_VALIDITY_CLAIMS,
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_object_disclosure,
)
from openvc.proof.vc_jwt import _reject_sd_jwt_typ

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
EXAMPLES_V2 = "https://www.w3.org/ns/credentials/examples/v2"
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
PAST_EPOCH = 1609459200                 # 2021-01-01T00:00:00Z, as a NumericDate
FUTURE_EPOCH = 4070908800               # 2099-01-01T00:00:00Z
VCT = "https://credentials.example/membership"
OTHER_VCT = "https://credentials.example/other"
ALIAS_VCT = "https://credentials.example/alias"
DRAFT_TYP = "vc+ld+json+sd-jwt"        # Example 21 of VC-JOSE-COSE: a 2023 draft's media type
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"
ABSENT = object()                       # `_mint(typ=ABSENT)`: a header with no `typ` member

# What the suite (SdJwtError) and the lanes around it say, as regexes. The first four are
# the typ gate's refusals of a payload with no VCDM @context (under no typ, then under
# the two W3C typs), the fifth its refusal of a `vc` / `vp` claim under no typ, and the
# sixth its refusal of a payload that does not say it is a credential under no typ (#293).
# Since #275 the last two requirements are asked of every typ but dc+sd-jwt, and the
# message names the typ it judged (`_first_context_refusal` / `_credential_type_refusal`
# below build the regexes): keep all of them apart.
NO_TYP_NEEDS_CONTEXT = (r"issuer JWT without a typ needs a W3C VCDM @context; "
                        r"an IETF SD-JWT VC is typed 'dc\+sd-jwt'")
VC_TYP_NEEDS_CONTEXT = (r"issuer JWT typ 'vc\+sd-jwt' needs a W3C VCDM @context; "
                        r"an IETF SD-JWT VC is typed 'dc\+sd-jwt'")
DRAFT_TYP_NEEDS_CONTEXT = (r"issuer JWT typ 'vc\+ld\+json\+sd-jwt' needs a W3C VCDM "
                           r"@context; an IETF SD-JWT VC is typed 'dc\+sd-jwt'")
NO_TYP_NO_VC_CLAIM = (r"issuer JWT without a typ must not carry a `vc` or `vp` claim "
                      r"\(VC-JOSE-COSE §3\.1\.3\)")
NO_TYP_NEEDS_CREDENTIAL_TYPE = (r"issuer JWT without a typ needs a `type` that includes "
                                r"VerifiableCredential and not VerifiablePresentation "
                                r"\(VCDM 2\.0 §4\.5, §4\.13\)")
# How the typ gate says which typ it judged (the `shown` of its messages), for the helpers.
SHOWN_NO_TYP = "without a typ"
SHOWN_DRAFT_TYP = f"typ '{DRAFT_TYP}'"
FIRST_CONTEXT = "first `@context` entry"            # a fragment that names the requirement
CREDENTIAL_TYPE = "includes VerifiableCredential"   # the other one
UNEXPECTED_TYP = "unexpected issuer JWT typ"
CONTEXT_DISCLOSED = "'@context' is selectively disclosed"
VCT_DISCLOSED = "'vct' is selectively disclosed"
NEEDS_VCT = "needs a non-empty string vct"
VALIDITY_DISCLOSED = "the W3C VCDM validity window openvc enforces"
IAT_IN_FUTURE = "iat is in the future"
IAT_NOT_A_NUMBER = "iat must be a finite numeric timestamp"
AKA_SHAPE = "aka_vcts must be a non-empty array of non-empty strings"
AKA_HAS_VCT = "aka_vcts must not contain the credential's vct"
NO_ISS_TO_PEEK = "no iss in the issuer-signed JWT"             # the pipeline, MalformedToken
NO_ISS_CLAIM = "iss claim is missing or not a string"          # the suite, ClaimsInvalid
NOT_IETF = "must be an IETF SD-JWT VC"            # OpenID4VP, VpTokenMalformed
NO_VC_OBJECT = "no embedded `vc` object"          # VC-JWT lane, ClaimsInvalid
SD_JWT_MARKERS = "carries SD-JWT markers"         # VC-JWT lane, MalformedToken (#291)
NOT_A_VC_JWT = "is not a VC-JWT"                  # VC-JWT lane, MalformedToken


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()


def _mint(payload, *, typ=ABSENT, cty=ABSENT, disclose=(), disclose_in=()):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes ``dc+sd-jwt`` and
    requires a ``vct``. *typ* is this file's one departure from the sibling helpers, and has
    three states: ``ABSENT`` (the default) writes no ``typ`` member; ``None`` writes
    ``"typ": null``, a member that is present and wrong; any other value is written as is.
    *cty* is the header member the tests add beside it, with two states: ``ABSENT`` (the
    default) writes none, anything else is written as is. *disclose* moves those top-level
    claims into disclosures (all of them presented); *disclose_in*, pairs ``(claim, name)``,
    does the same to the member *name* of the top-level object *claim*."""
    body = dict(payload)
    disclosures = []
    for name in disclose:
        disclosures.append(make_object_disclosure(_b64(secrets.token_bytes(16)), name,
                                                  body.pop(name)))
    if disclosures:
        body["_sd"] = sorted(disclosure_digest(d) for d in disclosures)
    for claim, name in disclose_in:
        inner = dict(body[claim])
        disclosure = make_object_disclosure(_b64(secrets.token_bytes(16)), name, inner.pop(name))
        inner["_sd"] = [disclosure_digest(disclosure)]
        body[claim] = inner
        disclosures.append(disclosure)
    if disclosures:
        body["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "kid": f"{DID}#0"}
    if typ is not ABSENT:
        header["typ"] = typ
    if cty is not ABSENT:
        header["cty"] = cty
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


def _first_context_refusal(shown):
    """The #275 refusal of a payload whose base VCDM context is not its first ``@context``
    entry, as the typ gate words it for the typ *shown*."""
    return re.escape(f"issuer JWT {shown} needs a VCDM base context as the first "
                     "`@context` entry (VCDM 2.0 §4.3), not just somewhere in it")


def _credential_type_refusal(shown):
    """The refusal of a payload whose ``type`` does not include VerifiableCredential (and not
    VerifiablePresentation), as the typ gate words it for the typ *shown* (#293, #275)."""
    return re.escape(f"issuer JWT {shown} needs a `type` that includes VerifiableCredential "
                     "and not VerifiablePresentation (VCDM 2.0 §4.5, §4.13)")


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


def _suite_verify(sd_jwt, **kwargs):
    return SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=KEY.public_jwk(), **kwargs)


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


# A payload that names a VCDM base context anywhere in `@context` (the lax test that turns the
# validity window on, and the only context rule of dc+sd-jwt). The second marker is those of
# the first that also CONFORM (#275): the base URL first, or alone as a string. The third is
# the one that does not, which every typ but dc+sd-jwt refuses.
VCDM_CONTEXTS = pytest.mark.parametrize("context", [
    [V2, EXAMPLES_V2],
    V2,
    ["https://example.org/ctx", V2],
    [V1],
], ids=["v2-array", "v2-string", "v2-not-first", "v1"])

CONFORMING_CONTEXTS = pytest.mark.parametrize("context", [
    [V2, EXAMPLES_V2],
    V2,
    [V1],
], ids=["v2-array", "v2-string", "v1"])

NOT_FIRST_CONTEXTS = pytest.mark.parametrize("context", [
    pytest.param(["https://example.org/ctx", V2], id="v2-not-first"),
])

# Not a VCDM base context, though several of them look like one: the reader compares each
# entry as a string, exactly, and only the entries of an array (never the keys of an object,
# never the entries of a nested array).
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
    " " + V2,
    V2 + " ",
    V2 + "\n",
    {V2: {}},
    EXAMPLES_V2,
    [EXAMPLES_V2],
    "http://www.w3.org/ns/credentials/v2",
    "http://www.w3.org/2018/credentials/v1",
    V2 + "/",
    V1 + "/",
    "https://www.w3.org/NS/credentials/V2",
    "HTTPS://www.w3.org/ns/credentials/v2",
    [[V2]],
], ids=["foreign-array", "foreign-string", "trailing-slash", "case-variant",
        "non-string-entries", "object", "empty-array", "null", "empty-string",
        "leading-space", "trailing-space", "trailing-newline", "object-keyed-by-the-url",
        "examples-context-alone", "examples-context-array", "http-v2", "http-v1",
        "trailing-slash-string", "trailing-slash-v1", "case-variant-path",
        "case-variant-scheme", "nested-array"])

WITH_VCT = pytest.mark.parametrize("with_vct", [False, True], ids=["no-vct", "with-vct"])

# The typ states under which a VCDM payload verifies: the rules of section K hold for each.
VCDM_TYPS = pytest.mark.parametrize("typ", [ABSENT, "vc+sd-jwt", DRAFT_TYP],
                                    ids=["no-typ", "vc-sd-jwt", "draft-typ"])

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


def test_the_helper_writes_no_cty_member_unless_asked_and_leaves_the_typ_alone():
    assert "cty" not in _header(_mint(_vcdm()))
    assert "cty" not in _header(_mint(_vcdm(), typ="vc+sd-jwt"))
    header = _header(_mint(_vcdm(), cty="vc"))
    assert header["cty"] == "vc"
    assert "typ" not in header
    header = _header(_mint(_vcdm(), typ=DRAFT_TYP, cty="vc+ld+json"))
    assert (header["typ"], header["cty"]) == (DRAFT_TYP, "vc+ld+json")


# --------------------------------------------------------------------------- #
# A. no typ member and a conforming VCDM payload: accepted as VCDM (#288, #275)
# --------------------------------------------------------------------------- #

@CONFORMING_CONTEXTS
@WITH_VCT
def test_a_vcdm_sd_jwt_with_no_typ_verifies_as_vcdm(run, form, context, with_vct):
    # VC-JOSE-COSE §3.2.1: the typ is a SHOULD, and Examples 4 and 5 omit it. The base URL is
    # the first `@context` entry (VCDM 2.0 §4.3) and the `type` says credential (#275).
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


@NOT_FIRST_CONTEXTS
@WITH_VCT
def test_a_vcdm_sd_jwt_with_no_typ_and_the_context_not_first_is_refused(
        run, form, context, with_vct):
    # The row that was "v2-not-first" in the test above until #275: a base URL somewhere in
    # `@context` is enough to turn the VCDM window on, not to be read as a credential
    # (VCDM 2.0 §4.3 makes it the first item). SdJwtError, naming that requirement.
    def mint(entries):
        doc = _vcdm(**{"@context": entries})
        if with_vct:
            doc["vct"] = VCT
        return form(_mint(doc))

    assert run(mint(context[::-1]), None).raw.vcdm is True      # the control: only the order
    with pytest.raises(SdJwtError, match=_first_context_refusal(SHOWN_NO_TYP)) as excinfo:
        run(mint(context), None)
    assert excinfo.type is SdJwtError
    assert "needs a W3C VCDM @context" not in str(excinfo.value)
    assert CREDENTIAL_TYPE not in str(excinfo.value)             # the `type` was fine


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

@CONFORMING_CONTEXTS
@WITH_VCT
def test_the_draft_era_typ_verifies_as_vcdm_with_a_vcdm_context(run, form, context, with_vct):
    doc = _vcdm(**{"@context": context})
    if with_vct:
        doc["vct"] = VCT
    result = run(form(_mint(doc, typ=DRAFT_TYP)), None)
    assert result.raw.typ == DRAFT_TYP
    assert result.raw.vcdm is True
    assert result.raw.vct == (VCT if with_vct else None)


@NOT_FIRST_CONTEXTS
@WITH_VCT
def test_the_draft_era_typ_with_the_context_not_first_is_refused(run, form, context, with_vct):
    # The draft-era twin of the refusal in section A (#275, the row that was "v2-not-first" in
    # the test above): the same requirement, worded for the typ it judged.
    def mint(entries):
        doc = _vcdm(**{"@context": entries})
        if with_vct:
            doc["vct"] = VCT
        return form(_mint(doc, typ=DRAFT_TYP))

    assert run(mint(context[::-1]), None).raw.typ == DRAFT_TYP   # the control: only the order
    with pytest.raises(SdJwtError, match=_first_context_refusal(SHOWN_DRAFT_TYP)) as excinfo:
        run(mint(context), None)
    assert excinfo.type is SdJwtError
    assert "needs a W3C VCDM @context" not in str(excinfo.value)


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


@VCDM_CONTEXTS
def test_a_dc_sd_jwt_has_no_context_position_rule_and_keeps_the_lax_vcdm_reading(
        run, form, context):
    # #275 holds the other typs to "the base URL is the FIRST `@context` entry"; the IETF
    # rules have no such rule, so the base URL anywhere (v2-not-first included) still makes
    # the payload VCDM, and a VCDM payload keeps its validity window: a holder cannot switch
    # the window off by moving the URL out of first place.
    doc = _vcdm_vct(**{"@context": context})
    result = run(form(_mint(doc, typ="dc+sd-jwt")), None)
    assert result.raw.typ == "dc+sd-jwt"
    assert result.raw.vcdm is True
    assert result.raw.vct == VCT
    with pytest.raises(CredentialExpired):
        run(form(_mint({**doc, "validUntil": PAST}, typ="dc+sd-jwt")), None)


# --------------------------------------------------------------------------- #
# G. the VC-JWT lane is untouched: an issuer JWT whose ~ tail is dropped
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("disclose, error, message", [
    pytest.param((), ClaimsInvalid, NO_VC_OBJECT, id="plain"),
    pytest.param(("credentialSubject",), MalformedToken, SD_JWT_MARKERS, id="with-disclosures"),
])
@WITH_VCT
def test_a_no_typ_vcdm_sd_jwt_without_its_tail_is_refused_by_the_vc_jwt_lane(
        run, form, disclose, error, message, with_vct):
    # A compact JWS goes to the VC-JWT lane. The payload is a VCDM credential itself, not a
    # JWT carrying one under `vc`, so with no disclosure that lane has nothing to verify
    # ("no embedded vc object"); with one, its `_sd` / `_sd_alg` markers say it is an SD-JWT
    # issuer JWT and the lane refuses it before that (#291).
    jws = _tail_dropped(_mint(_vcdm_vct() if with_vct else _vcdm(), disclose=disclose))
    assert "~" not in jws
    with pytest.raises(error, match=message) as excinfo:
        run(form(jws), None)
    assert excinfo.type is error


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


# --------------------------------------------------------------------------- #
# J. the payload has to say it is a credential, not a presentation (#293; #275 asks it of
#    every typ but dc+sd-jwt, not only of a token with no typ)
# --------------------------------------------------------------------------- #

def _vcdm_presentation(**extra):
    """A VCDM 2.0 presentation secured with SD-JWT by its holder, who stands here for the
    signer of every other token in this file: the ``@context`` of a credential, an ``aud``
    and a ``nonce`` addressed to one verifier, an enveloped credential, a ``type`` of
    ``VerifiablePresentation``, and no ``vp`` claim for the §3.1.3 ban to find."""
    doc = {
        "@context": [V2],
        "type": ["VerifiablePresentation"],
        "iss": DID,
        "holder": DID,
        "aud": CLIENT_ID,
        "nonce": NONCE,
        "verifiableCredential": [_envelope(_mint(_vcdm(), typ="vc+sd-jwt"))],
    }
    doc.update(extra)
    return doc


def _with_type(declared):
    """A VCDM payload whose ``type`` is *declared*, or that has no ``type`` (``ABSENT``)."""
    doc = _vcdm()
    if declared is ABSENT:
        del doc["type"]
    else:
        doc["type"] = declared
    return doc


# A `type` that includes VerifiableCredential and not VerifiablePresentation, by exact name.
CREDENTIAL_TYPES = pytest.mark.parametrize("declared", [
    pytest.param("VerifiableCredential", id="string"),
    pytest.param(["VerifiableCredential"], id="array-of-one"),
    pytest.param(["VerifiableCredential", "ExampleAlumniCredential"], id="array-with-more"),
    pytest.param(["ExampleAlumniCredential", "VerifiableCredential"], id="not-first"),
    pytest.param(["VerifiableCredential", "VerifiablePresentationReceipt"],
                 id="another-name-that-starts-like-a-presentation"),
])

# Every other `type`: one that is missing, malformed, a presentation's or both at once, and
# the near-misses a lenient reader (a substring, a case fold, a dict's keys) would accept.
NOT_CREDENTIAL_TYPES = pytest.mark.parametrize("declared", [
    pytest.param(ABSENT, id="absent"),
    pytest.param([], id="empty-array"),
    pytest.param(None, id="null"),
    pytest.param(5, id="number"),
    pytest.param(True, id="true"),
    pytest.param({}, id="empty-object"),
    pytest.param({"VerifiableCredential": True}, id="object-keyed-by-the-name"),
    pytest.param([1, None, {}], id="array-of-non-strings"),
    pytest.param([["VerifiableCredential"]], id="nested-array"),
    pytest.param("", id="empty-string"),
    pytest.param("VerifiablePresentation", id="presentation-string"),
    pytest.param(["VerifiablePresentation"], id="presentation-array"),
    pytest.param(["VerifiableCredential", "VerifiablePresentation"], id="both"),
    pytest.param(["VerifiablePresentation", "VerifiableCredential"], id="both-reversed"),
    pytest.param("verifiablecredential", id="lower-case"),
    pytest.param(" VerifiableCredential", id="leading-space"),
    pytest.param(["VerifiableCredential "], id="trailing-space"),
    pytest.param("MyVerifiableCredential", id="another-name-that-ends-like-a-credential"),
    pytest.param("VerifiableCredential VerifiablePresentation", id="both-in-one-string"),
    pytest.param(["ExampleAlumniCredential"], id="another-type-only"),
])


def test_a_vcdm_presentation_with_no_typ_is_refused_not_verified_as_a_credential(run, form):
    # The hole of #293. A VCDM 2.0 presentation has the @context of a credential and no `vp`
    # claim, so with no typ to tell the two apart it used to come out as a credential "issued"
    # by its holder: its aud and nonce, meant for one verifier, read as the credential's claims.
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        run(form(_mint(_vcdm_presentation())), None)
    assert excinfo.type is SdJwtError


def test_the_suite_refuses_a_vcdm_presentation_with_no_typ_directly():
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        _suite_verify(_mint(_vcdm_presentation()))
    assert excinfo.type is SdJwtError


def test_control_the_presentation_payload_verifies_once_its_type_says_credential(run, form):
    # Only the `type` differs from the refused presentation: the aud, the nonce, the holder
    # and the enveloped credential in it are not what the refusal above is about.
    result = run(form(_mint(_vcdm_presentation(type=["VerifiableCredential"]))), None)
    assert result.raw.typ is None
    assert result.raw.vcdm is True
    assert result.issuer == DID


@pytest.mark.parametrize("typ", ["vp+sd-jwt", "vp+ld+json+sd-jwt"],
                         ids=["vp-sd-jwt", "vp-draft-typ"])
def test_a_vcdm_presentation_typed_as_one_is_refused_for_its_typ(run, form, typ):
    # A presentation that names itself is no credential either: the typ gate refuses it before
    # the payload is read, so the type rule is not what stands in its way.
    with pytest.raises(SdJwtError, match=UNEXPECTED_TYP) as excinfo:
        run(form(_mint(_vcdm_presentation(), typ=typ)), None)
    assert excinfo.type is SdJwtError
    assert "without a typ" not in str(excinfo.value)


@CREDENTIAL_TYPES
def test_a_token_with_no_typ_whose_type_includes_verifiable_credential_verifies(
        run, form, declared):
    result = run(form(_mint(_with_type(declared))), None)
    assert result.raw.typ is None
    assert result.raw.vcdm is True
    assert result.claims["type"] == declared


@NOT_CREDENTIAL_TYPES
def test_a_token_with_no_typ_whose_type_does_not_say_credential_is_refused(run, form, declared):
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        run(form(_mint(_with_type(declared))), None)
    assert excinfo.type is SdJwtError


@NOT_CREDENTIAL_TYPES
def test_the_suite_refuses_a_type_that_does_not_say_credential_directly(declared):
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        _suite_verify(_mint(_with_type(declared)))
    assert excinfo.type is SdJwtError


def test_a_withheld_type_leaves_a_token_with_no_typ_refused(run, form):
    # The Recommendation's Example 4 makes `type` selectively disclosable, and a holder may
    # drop any disclosure (RFC 9901 §9.7). A rule that only refused a `type` saying
    # "presentation" would wave this through: what is not there cannot be refused. The rule
    # asks for the credential's type instead of for the absence of the presentation's.
    sd_jwt = _without(_mint(_vcdm(), disclose=["type"]), "type")
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError


def test_a_presented_type_disclosure_that_says_credential_verifies(run, form):
    # The same token with the disclosure presented: the shape of Example 4.
    result = run(form(_mint(_vcdm(), disclose=["type"])), None)
    assert result.claims["type"] == ["VerifiableCredential", "ExampleAlumniCredential"]
    assert result.raw.typ is None
    assert result.raw.vcdm is True


def test_a_presented_type_disclosure_that_says_presentation_is_refused(run, form):
    sd_jwt = _mint(_vcdm_presentation(), disclose=["type"])
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError


@pytest.mark.parametrize("typ", ["vc+sd-jwt", DRAFT_TYP], ids=["vc-sd-jwt", "draft-typ"])
@pytest.mark.parametrize("how", ["absent", "withheld"])
def test_the_type_rule_is_for_every_typ_but_dc_sd_jwt(run, form, typ, how):
    # This was "for a token with no typ only" until #275: `vc+sd-jwt` and `vc+ld+json+sd-jwt`
    # say the payload is a credential, and a payload that is not must not pass under a typ
    # that says it is. A `type` that is missing or withheld (a holder may drop it, Example 4
    # makes it disclosable) is their defect too: SdJwtError, worded for the typ it judged.
    if how == "absent":
        sd_jwt = _mint(_with_type(ABSENT), typ=typ)
    else:
        sd_jwt = _without(_mint(_vcdm(), typ=typ, disclose=["type"]), "type")
    # The control: the same token with its `type` there verifies under the same typ.
    assert run(form(_mint(_vcdm(), typ=typ)), None).raw.typ == typ
    with pytest.raises(SdJwtError, match=_credential_type_refusal(f"typ {typ!r}")) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is SdJwtError
    assert CREDENTIAL_TYPE in str(excinfo.value)
    assert FIRST_CONTEXT not in str(excinfo.value)           # the `@context` was fine


@pytest.mark.parametrize("typ", ["vc+sd-jwt", DRAFT_TYP], ids=["vc-sd-jwt", "draft-typ"])
def test_a_presented_type_disclosure_that_says_credential_verifies_under_each_w3c_typ(
        run, form, typ):
    # The twin of the withheld refusal above, as the one for a token with no typ is of its own
    # (the shape of Example 4): the same token with the disclosure presented.
    result = run(form(_mint(_vcdm(), typ=typ, disclose=["type"])), None)
    assert result.claims["type"] == ["VerifiableCredential", "ExampleAlumniCredential"]
    assert result.raw.typ == typ
    assert result.raw.vcdm is True


@pytest.mark.parametrize("how", ["absent", "withheld"])
def test_a_dc_sd_jwt_has_no_type_rule(run, form, how):
    # The IETF rules make `vct` REQUIRED (draft-19 §2.2.2.3) and have no `type` rule: the
    # same payloads that the two W3C typs refuse above still verify as `dc+sd-jwt` (with
    # their vct), VCDM by the lax reading of their `@context`, and with no `type` to report.
    if how == "absent":
        sd_jwt = _mint({**_with_type(ABSENT), "vct": VCT}, typ="dc+sd-jwt")
    else:
        sd_jwt = _without(_mint(_vcdm_vct(), typ="dc+sd-jwt", disclose=["type"]), "type")
    result = run(form(sd_jwt), None)
    assert result.raw.typ == "dc+sd-jwt"
    assert result.raw.vcdm is True
    assert result.raw.vct == VCT
    assert "type" not in result.claims


# --------------------------------------------------------------------------- #
# K. no typ and the draft typ hold the claim rules vc+sd-jwt holds
# --------------------------------------------------------------------------- #
# Every rule below runs after the typ gate, and none of them reads the typ. A token that gets
# through the gate by leaving its typ out, or by naming the draft one, must not get round
# one: whoever signs it would otherwise choose, by what the header says, which rules apply.

# (claim, a value that verifies in plaintext, the VCDM @context that names it)
VALIDITY_ROWS = [
    ("validFrom", PAST, V2),
    ("validUntil", FUTURE, V2),
    ("issuanceDate", PAST, V1),
    ("expirationDate", FUTURE, V1),
]
VALIDITY_CLAIMS = pytest.mark.parametrize(
    "name, value, context", VALIDITY_ROWS, ids=[row[0] for row in VALIDITY_ROWS])

# (claim, a value it could carry): every claim the suite refuses to see disclosed except `iss`,
# which never gets that far (see the test on it below).
UNDISCLOSABLE_ROWS = [
    ("exp", FUTURE_EPOCH),
    ("nbf", PAST_EPOCH),
    ("cnf", {"jwk": KEY.public_jwk()}),
    ("status", {"status_list": {"idx": 3, "uri": "https://status.example/lists/1"}}),
    ("credentialStatus", {"id": "https://status.example/lists/1#3",
                          "type": "BitstringStatusListEntry", "statusPurpose": "revocation",
                          "statusListIndex": "3",
                          "statusListCredential": "https://status.example/lists/1"}),
    ("aka_vcts", [ALIAS_VCT]),
    ("vct#integrity", "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="),
    ("vct", VCT),
    ("@context", [V2, EXAMPLES_V2]),
]
UNDISCLOSABLE_VALUES = dict(UNDISCLOSABLE_ROWS)
UNDISCLOSABLE_CLAIMS = pytest.mark.parametrize(
    "name, value", UNDISCLOSABLE_ROWS, ids=[row[0] for row in UNDISCLOSABLE_ROWS])

# The sub-claims of the objects among them: (claim, the member of it that is disclosed).
UNDISCLOSABLE_SUB_CLAIMS = pytest.mark.parametrize("claim, member", [
    pytest.param("cnf", "jwk", id="cnf"),
    pytest.param("status", "status_list", id="status"),
    pytest.param("credentialStatus", "statusListIndex", id="credentialStatus"),
])

BAD_AKA_VCTS = pytest.mark.parametrize("aka, message", [
    pytest.param([], AKA_SHAPE, id="empty-array"),
    pytest.param(ALIAS_VCT, AKA_SHAPE, id="string"),
    pytest.param({"vct": ALIAS_VCT}, AKA_SHAPE, id="object"),
    pytest.param([1], AKA_SHAPE, id="non-string-entry"),
    pytest.param([ALIAS_VCT, 1], AKA_SHAPE, id="one-non-string-entry"),
    pytest.param([""], AKA_SHAPE, id="empty-string-entry"),
    pytest.param([VCT], AKA_HAS_VCT, id="the-vct"),
    pytest.param([ALIAS_VCT, VCT], AKA_HAS_VCT, id="the-vct-among-others"),
])

# `expected_vct` is VCT; what the token carries instead, and what the refusal names.
WRONG_VCTS = pytest.mark.parametrize("doc, got", [
    pytest.param(_vcdm(vct=OTHER_VCT), OTHER_VCT, id="another-vct"),
    pytest.param(_vcdm(), None, id="no-vct"),
])


def _with_validity(name, value, context):
    doc = _vcdm(**{"@context": [context]})
    del doc["validFrom"]
    doc[name] = value
    return doc


def _vct_mismatch(got):
    return re.escape(f"vct {got!r} != expected {VCT!r}")


def test_the_table_of_validity_claims_is_the_suites_own():
    assert {row[0] for row in VALIDITY_ROWS} == _VCDM_VALIDITY_CLAIMS


def test_the_table_of_undisclosable_claims_is_the_suites_own():
    # `iss` is the one left out: see the test on it below.
    assert ({row[0] for row in UNDISCLOSABLE_ROWS} | {"iss"}
            == _SD_JWT_VC_NON_DISCLOSABLE | _OPENVC_NON_DISCLOSABLE)


@VCDM_TYPS
@VALIDITY_CLAIMS
def test_a_presented_validity_claim_disclosure_is_refused_whatever_the_vcdm_typ(
        run, form, typ, name, value, context):
    # The suite enforces these claims as the credential's validity window, so a disclosable one
    # could be left out by its holder and the window with it (RFC 9901 §9.7): once presented, it
    # is refused. The same claim in plaintext is the control.
    doc = _with_validity(name, value, context)
    assert run(form(_mint(doc, typ=typ)), None).raw.vcdm is True
    refusal = rf"'{name}' is selectively disclosed \({VALIDITY_DISCLOSED}\)"
    with pytest.raises(SdJwtError, match=refusal) as excinfo:
        run(form(_mint(doc, typ=typ, disclose=[name])), None)
    assert excinfo.type is SdJwtError


@VCDM_TYPS
@UNDISCLOSABLE_CLAIMS
def test_a_presented_disclosure_of_an_undisclosable_claim_is_refused_whatever_the_vcdm_typ(
        run, form, typ, name, value):
    doc = {**_vcdm_vct(), name: value}
    assert _suite_verify(_mint(doc, typ=typ)).vcdm is True               # the control
    refusal = rf"claim '{re.escape(name)}' is selectively disclosed"
    with pytest.raises(SdJwtError, match=refusal) as excinfo:
        run(form(_mint(doc, typ=typ, disclose=[name])), None)
    assert excinfo.type is SdJwtError


@VCDM_TYPS
@UNDISCLOSABLE_SUB_CLAIMS
def test_a_presented_sub_claim_disclosure_of_an_undisclosable_claim_is_refused_too(
        run, form, typ, claim, member):
    doc = {**_vcdm_vct(), claim: UNDISCLOSABLE_VALUES[claim]}
    assert member in doc[claim]
    refusal = rf"a sub-claim of '{claim}' is selectively disclosed"
    with pytest.raises(SdJwtError, match=refusal) as excinfo:
        run(form(_mint(doc, typ=typ, disclose_in=[(claim, member)])), None)
    assert excinfo.type is SdJwtError


@VCDM_TYPS
@pytest.mark.parametrize("name, value", [("exp", PAST_EPOCH), ("nbf", FUTURE_EPOCH)])
def test_a_presented_exp_or_nbf_disclosure_is_refused_as_a_disclosure_not_by_the_clock(
        run, form, typ, name, value):
    # Were it plaintext, this `exp` would have expired and this `nbf` not yet begun, and the
    # verdict would be a ClaimsInvalid from the clock. Presented in a disclosure, it is the
    # disclosure that is refused, with SdJwtError, before the processed payload is dated.
    with pytest.raises(SdJwtError, match=rf"claim '{name}' is selectively disclosed") as excinfo:
        run(form(_mint(_vcdm_vct(**{name: value}), typ=typ, disclose=[name])), None)
    assert excinfo.type is SdJwtError


@VCDM_TYPS
def test_a_disclosed_iss_never_gets_as_far_as_the_disclosure_rule(run, form, typ):
    # `iss` is on the suite's list, but a token whose `iss` is in a disclosure is out before
    # that rule runs: the pipeline finds no issuer to select a key with, and the suite no `iss`
    # claim to verify. A holder cannot present it either way.
    sd_jwt = _mint(_vcdm_vct(), typ=typ, disclose=["iss"])
    with pytest.raises(MalformedToken, match=NO_ISS_TO_PEEK) as excinfo:
        run(form(sd_jwt), None)
    assert excinfo.type is MalformedToken
    with pytest.raises(ClaimsInvalid, match=NO_ISS_CLAIM) as excinfo:
        _suite_verify(sd_jwt)
    assert excinfo.type is ClaimsInvalid


@VCDM_TYPS
def test_a_presented_iat_disclosure_is_checked_on_the_processed_payload(run, form, typ):
    # `iat` MAY be disclosable (draft-19 §2.2.2.3), so the issuer JWT's own claims do not show
    # it. Only the check of the processed payload sees it, and a token with no typ gets it too.
    past = _mint(_vcdm(iat=PAST_EPOCH), typ=typ, disclose=["iat"])
    assert run(form(past), None).raw.vcdm is True
    with pytest.raises(ClaimsInvalid, match=IAT_IN_FUTURE) as excinfo:
        run(form(_mint(_vcdm(iat=FUTURE_EPOCH), typ=typ, disclose=["iat"])), None)
    assert excinfo.type is ClaimsInvalid


@VCDM_TYPS
@pytest.mark.parametrize("iat", [None, "2021-01-01T00:00:00Z", True, [PAST_EPOCH], 10**400],
                         ids=["null", "string", "true", "array", "bignum"])
def test_a_presented_iat_disclosure_that_is_not_a_number_is_refused(run, form, typ, iat):
    with pytest.raises(ClaimsInvalid, match=IAT_NOT_A_NUMBER) as excinfo:
        run(form(_mint(_vcdm(iat=iat), typ=typ, disclose=["iat"])), None)
    assert excinfo.type is ClaimsInvalid


@VCDM_TYPS
@WRONG_VCTS
def test_expected_vct_pins_a_vcdm_token_whatever_its_typ(run, form, typ, doc, got):
    policy = VerificationPolicy(expected_vct=VCT)
    assert run(form(_mint(_vcdm_vct(), typ=typ)), policy).raw.vct == VCT
    with pytest.raises(ClaimsInvalid, match=_vct_mismatch(got)) as excinfo:
        run(form(_mint(doc, typ=typ)), policy)
    assert excinfo.type is ClaimsInvalid


@VCDM_TYPS
@WRONG_VCTS
def test_the_suite_pins_a_vcdm_token_by_expected_vct_whatever_its_typ(typ, doc, got):
    assert _suite_verify(_mint(_vcdm_vct(), typ=typ), expected_vct=VCT).vct == VCT
    with pytest.raises(ClaimsInvalid, match=_vct_mismatch(got)) as excinfo:
        _suite_verify(_mint(doc, typ=typ), expected_vct=VCT)
    assert excinfo.type is ClaimsInvalid


@VCDM_TYPS
@BAD_AKA_VCTS
def test_a_bad_aka_vcts_is_refused_whatever_the_vcdm_typ(run, form, typ, aka, message):
    with pytest.raises(ClaimsInvalid, match=message) as excinfo:
        run(form(_mint(_vcdm_vct(aka_vcts=aka), typ=typ)), None)
    assert excinfo.type is ClaimsInvalid


@VCDM_TYPS
def test_a_good_aka_vcts_verifies_whatever_the_vcdm_typ(run, form, typ):
    result = run(form(_mint(_vcdm_vct(aka_vcts=[ALIAS_VCT]), typ=typ)), None)
    assert result.claims["aka_vcts"] == [ALIAS_VCT]
    assert result.raw.vct == VCT


@NOT_VCDM_CONTEXTS
def test_a_foreign_context_does_not_rescue_a_vc_sd_jwt_token(run, form, context):
    # The registered typ, where #264 started: the lookalikes of the table are not VCDM to it.
    with pytest.raises(SdJwtError, match=VC_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_vcdm_vct(**{"@context": context}), typ="vc+sd-jwt")), None)
    assert excinfo.type is SdJwtError


@NOT_VCDM_CONTEXTS
def test_a_foreign_context_does_not_make_a_dc_sd_jwt_vcdm(run, form, context):
    # The same entries under dc+sd-jwt, which needs no VCDM @context: nothing is refused, but
    # the payload is not read as VCDM, so a `validUntil` in the past is an ordinary claim.
    doc = _ietf(**{"@context": context, "validUntil": PAST})
    assert run(form(_mint(doc, typ="dc+sd-jwt")), None).raw.vcdm is False


# --------------------------------------------------------------------------- #
# L. the typ is the header's typ alone, and the VC-JWT lane fences off every accepted one
# --------------------------------------------------------------------------- #

# Content types of the payload (RFC 7515 §4.1.10), among them every name a typ could take.
CTYS = pytest.mark.parametrize("cty", [
    "vc+sd-jwt", "dc+sd-jwt", "vc+ld+json+sd-jwt", "vc", "vc+ld+json", "JWT",
], ids=["vc-sd-jwt", "dc-sd-jwt", "draft-typ", "vc", "vc-ld-json", "jwt"])


@CTYS
def test_a_cty_is_not_read_as_the_typ_of_a_token_with_no_typ(run, form, cty):
    # Example 21 carries a `cty` beside its typ. A token with a `cty` and no `typ` is still a
    # token with no typ: judged as one, and reported as one.
    result = run(form(_mint(_vcdm(), cty=cty)), None)
    assert result.raw.typ is None
    assert result.raw.vcdm is True


@CTYS
@pytest.mark.parametrize("name", ["vc", "vp"])
def test_a_cty_does_not_lift_the_vc_and_vp_ban_from_a_token_with_no_typ(run, form, cty, name):
    with pytest.raises(SdJwtError, match=NO_TYP_NO_VC_CLAIM) as excinfo:
        run(form(_mint(_vcdm_vct(**{name: EMBEDDED[name]}), cty=cty)), None)
    assert excinfo.type is SdJwtError


@CTYS
def test_a_cty_does_not_make_an_ietf_payload_with_no_typ_an_sd_jwt_vc(run, form, cty):
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CONTEXT) as excinfo:
        run(form(_mint(_ietf(), cty=cty)), None)
    assert excinfo.type is SdJwtError


@CTYS
def test_a_cty_does_not_turn_a_presentation_with_no_typ_into_a_credential(run, form, cty):
    with pytest.raises(SdJwtError, match=NO_TYP_NEEDS_CREDENTIAL_TYPE) as excinfo:
        run(form(_mint(_vcdm_presentation(), cty=cty)), None)
    assert excinfo.type is SdJwtError


@pytest.mark.parametrize("typ", sorted(_ACCEPTED_ISSUER_TYP))
def test_every_accepted_issuer_typ_is_fenced_off_the_vc_jwt_lane(typ):
    # The lanes divide the JWS space by typ: a JWS typed as an SD-JWT issuer JWT is never a
    # VC-JWT, because its `~` tail dropped would verify there with no key binding (#189). A
    # typ that verify() starts to accept has to be added to that filter too, or the
    # tail-dropped form of its tokens verifies as a VC-JWT.
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        _reject_sd_jwt_typ({"alg": "ES256", "typ": typ})
    assert excinfo.type is MalformedToken


@pytest.mark.parametrize("header", [
    pytest.param({"alg": "ES256"}, id="no-typ"),
    pytest.param({"alg": "ES256", "typ": None}, id="null"),
    pytest.param({"alg": "ES256", "typ": "JWT"}, id="jwt"),
    pytest.param({"alg": "ES256", "typ": "vc+jwt"}, id="vc-jwt"),
    pytest.param({"alg": "ES256", "typ": "vc+ld+jwt"}, id="vc-ld-jwt"),
    pytest.param({"alg": "ES256", "typ": "application/vc+ld+json+jwt"}, id="media-type"),
])
def test_control_the_vc_jwt_filter_lets_a_typ_that_is_not_an_sd_jwt_one_through(header):
    # So the test above is not vacuous, and no typ of the VC-JWT lane can join the accepted set.
    assert _reject_sd_jwt_typ(header) is None
    assert header.get("typ") not in _ACCEPTED_ISSUER_TYP
