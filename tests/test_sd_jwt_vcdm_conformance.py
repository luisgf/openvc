"""
tests/test_sd_jwt_vcdm_conformance.py — an SD-JWT issuer JWT is *read as* a W3C VCDM
credential only when the payload conforms to VCDM, not merely when a base URL appears in it
(#275). The other typ-gate files pin the rest of the story: #264 made ``vc+sd-jwt`` need a
VCDM base ``@context`` (test_sd_jwt_vc_typ_vcdm_only.py), #272 made ``dc+sd-jwt`` need a
``vct`` (test_sd_jwt_vc_dc_typ_ietf_only.py), #288 / #289 let a token with no ``typ`` and the
draft-era ``vc+ld+json+sd-jwt`` through (test_sd_jwt_vcdm_typ_interop.py) and #293 made an
untyped one say it is a credential. This file pins what #275 adds on top, for every issuer
JWT ``typ`` that is not ``dc+sd-jwt`` (``vc+sd-jwt``, ``vc+ld+json+sd-jwt``, no ``typ``).

The rule, in the order the refusals are made:

1. No VCDM base context (``https://www.w3.org/ns/credentials/v2`` or ``.../2018/credentials/v1``)
   anywhere in ``@context``: "needs a W3C VCDM @context; an IETF SD-JWT VC is typed
   'dc+sd-jwt'" (unchanged).
2. No ``typ`` and a ``vc`` or ``vp`` claim: "must not carry a `vc` or `vp` claim"
   (VC-JOSE-COSE §3.1.3; unchanged).
3. The FIRST ``@context`` entry is not a VCDM base context: "needs a VCDM base context as the
   first `@context` entry" (VCDM 2.0 §4.3: an ordered set whose first item is the base URL; a
   bare string context is its own first item; an object, a number, a nested array, an empty
   array or a look-alike URL in first place fails).
4. ``type`` does not include ``VerifiableCredential`` or includes ``VerifiablePresentation``:
   "needs a `type` that includes VerifiableCredential and not VerifiablePresentation"
   (VCDM 2.0 §4.5, §4.13; the compact term only, entries that are not strings are ignored).
   A withheld selectively-disclosable ``type`` (the Recommendation's Example 4 makes it
   disclosable) fails this one too, for a typed token as well as for an untyped one.

**Lax drives the window, strict decides the reading.** ``_declares_vcdm`` stays lax on
purpose: a base URL ANYWHERE in ``@context`` still turns on the validity window
(``validFrom`` / ``validUntil`` / ``issuanceDate`` / ``expirationDate``), the issuer / id /
subject consistency checks, the refusal of a disclosable validity claim and the
``vcdm`` flag, for EVERY ``typ`` including ``dc+sd-jwt`` — otherwise a holder could switch
the window off by moving the URL to second place. The strict gate decides only whether the
payload is accepted as a W3C credential, and ``dc+sd-jwt`` (an IETF SD-JWT VC: ``vct``
required, no ``type`` rule, no ``@context`` position rule) never meets it.

W3C VC-JOSE-COSE (Recommendation of 13 October 2026, https://www.w3.org/TR/vc-jose-cose/):
§3.2.1 (the SD-JWT ``typ`` is a SHOULD and the payload is the credential), §6.1.3
(``vc+sd-jwt``), §3.1.3 (no ``vc`` / ``vp`` claim). Examples 4 and 5 are typ-less and Example
21 is typed ``vc+ld+json+sd-jwt``; two real tokens sit in tests/fixtures/vc_jose_cose/ and must
keep being read as credentials (section E).

Sections: A the matrix (typ x ``@context`` x ``type``, checked against an oracle that does not
import the source predicates); B the order of the refusals; C ``dc+sd-jwt`` is unchanged and
the window and the consistency checks are lax; D a withheld disclosable ``type``; E the
Recommendation's own tokens; F ``expected_types`` (the exception class moves from
``TypeMismatch`` to ``SdJwtError``); G OpenID4VP; H ``issue()``; I the key-bound paths (the
gate also runs when the binding is REQUIRED); J near-miss first entries and a ``type`` that
names both a credential and a presentation, by name; K an array ELEMENT made disclosable
(the documented limit of judging the processed payload); L the gate before the window, and
``verify_many``.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk``, resolved offline by the default resolvers; signatures are real P-256 (P-384 for
Example 21); ``asyncio.run`` drives the async pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import copy
import json
import secrets
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.keys import P256SigningKey, P384SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import VpTokenMalformed, verify_vp_token
from openvc.proof.di_jcs import EcdsaJcsProofSuite
from openvc.proof.errors import (
    ClaimsInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    SignatureInvalid,
)
from openvc.proof.sd_jwt import (
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_array_disclosure,
    make_object_disclosure,
)
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import TypeMismatch

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
EXAMPLES_V2 = "https://www.w3.org/ns/credentials/examples/v2"
DID_V1 = "https://www.w3.org/ns/did/v1"
EXTRA = "https://example.org/ctx"
VOCAB = {"@vocab": "https://example.org/vocab#"}
BASES = (V2, V1)                       # the oracle's own copy of the two base contexts
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
VCT = "https://credentials.example/membership"
DRAFT_TYP = "vc+ld+json+sd-jwt"        # Example 21 of VC-JOSE-COSE: a 2023 draft's media type
DC_TYP = "dc+sd-jwt"
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"
ABSENT = object()                       # no `typ` member / no claim at all
CREDENTIAL = ["VerifiableCredential", "ExampleAlumniCredential"]

# The three issuer JWT typs the new gate applies to, and how a refusal names them.
TYPS = [ABSENT, "vc+sd-jwt", DRAFT_TYP]
TYP_IDS = ["no-typ", "vc-sd-jwt", "draft-typ"]
TYP = pytest.mark.parametrize("typ", TYPS, ids=TYP_IDS)

# What the suite says, by requirement (the part after "issuer JWT <shown> ").
SAYS = {
    "context": "needs a W3C VCDM @context; an IETF SD-JWT VC is typed 'dc+sd-jwt'",
    "first": ("needs a VCDM base context as the first `@context` entry (VCDM 2.0 §4.3), "
              "not just somewhere in it"),
    "type": ("needs a `type` that includes VerifiableCredential and not "
             "VerifiablePresentation (VCDM 2.0 §4.5, §4.13)"),
}
NO_VC_CLAIM = ("issuer JWT without a typ must not carry a `vc` or `vp` claim "
               "(VC-JOSE-COSE §3.1.3)")
VALIDITY_DISCLOSED = "the W3C VCDM validity window openvc enforces"
NOT_IETF = "must be an IETF SD-JWT VC"            # OpenID4VP, VpTokenMalformed
MISSING_TYPE = r"credential is missing required type\(s\)"


def _shown(typ):
    return "without a typ" if typ is ABSENT else f"typ {typ!r}"


def _says(requirement, typ):
    """The whole message of the refusal for *requirement* ("context" / "first" / "type")."""
    return f"issuer JWT {_shown(typ)} {SAYS[requirement]}"


# --------------------------------------------------------------------------- #
# helpers: a real issuer, hand-minted tokens, the pipelines
# --------------------------------------------------------------------------- #

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issuer():
    key = P256SigningKey.generate(kid="k")
    did = "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())
    return key, did


KEY, DID = _issuer()


def _mint(payload, *, typ=ABSENT, disclose=()):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes ``dc+sd-jwt``
    and requires a ``vct``. *typ*: ``ABSENT`` (the default) writes no ``typ`` member, any
    other value is written as is. *disclose* moves those top-level claims into disclosures
    (all of them presented)."""
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


def _without(sd_jwt, name):
    """The presentation with the disclosure of top-level claim *name* withheld."""
    issuer_jwt, *rest = sd_jwt.split("~")
    kept = [d for d in rest[:-1] if _decode(d)[1] != name]
    assert len(kept) == len(rest) - 2, f"no disclosure for {name!r}"
    return issuer_jwt + "~" + "".join(d + "~" for d in kept)


def _w3c(context=ABSENT, type_=ABSENT, **extra):
    """A W3C VCDM payload that is consistent in every other respect (so that a verdict is
    about *context* and *type_* alone). A claim left ``ABSENT`` is not written at all."""
    doc = {
        "iss": DID,
        "issuer": DID,
        "id": "urn:uuid:5e1d6a3c-cred",
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "alumniOf": "Example University"},
    }
    if context is not ABSENT:
        doc["@context"] = context
    if type_ is not ABSENT:
        doc["type"] = type_
    doc.update(extra)
    return doc


def _good(**extra):
    """A payload that conforms: base context first, a credential type."""
    return _w3c([V2, EXAMPLES_V2], CREDENTIAL, **extra)


def _dc(context=ABSENT, type_=ABSENT, **extra):
    """The same payload as an IETF SD-JWT VC: a ``vct``, typed ``dc+sd-jwt`` when minted."""
    return _w3c(context, type_, vct=VCT, **extra)


def _envelope(sd_jwt, media="application/vc+sd-jwt"):
    return {"@context": [V2], "id": f"data:{media},{sd_jwt}",
            "type": ["EnvelopedVerifiableCredential"]}


FORMS = {"bare": lambda sd_jwt: sd_jwt, "enveloped": _envelope}


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


def _suite_outcome(sd_jwt):
    """What the suite does with *sd_jwt*, as comparable data: ``("ok", vcdm, typ)`` or
    ``(exception class, message)``. Any exception is caught, so a TypeError from a hostile
    payload is reported as a failing cell rather than aborting the whole grid."""
    try:
        result = _suite_verify(sd_jwt)
    except Exception as exc:     # the cell's verdict is the exception itself
        return type(exc), str(exc)
    return "ok", result.vcdm, result.typ


def _present(claims, *, typ):
    """A KB-JWT presentation of a hand-minted token, bound to CLIENT_ID and NONCE."""
    holder = P256SigningKey.generate(kid="holder")
    sd_jwt = _mint({**claims, "cnf": {"jwk": holder.public_jwk()}}, typ=typ)
    return SdJwtVcProofSuite().create_presentation(
        sd_jwt, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)


# --------------------------------------------------------------------------- #
# the oracle: written down here, importing none of the source predicates
# --------------------------------------------------------------------------- #

def _oracle_context_class(context):
    """"none": no entry is a base context (the lax test fails); "later": one is, but not as
    the first entry; "first": the first entry is one. An entry counts only when it is a
    string equal to a base URL, and a context that is not an array is a one-entry array."""
    entries = context if isinstance(context, list) else [context]
    hits = [i for i, entry in enumerate(entries) if isinstance(entry, str) and entry in BASES]
    if not hits:
        return "none"
    return "first" if hits[0] == 0 else "later"


def _oracle_type_ok(declared):
    """VCDM 2.0 §4.5 / §4.13: the (compact) term VerifiableCredential is there and
    VerifiablePresentation is not. A bare string is a one-entry array; entries that are not
    strings are ignored."""
    entries = declared if isinstance(declared, list) else [declared]
    names = [entry for entry in entries if isinstance(entry, str)]
    return "VerifiableCredential" in names and "VerifiablePresentation" not in names


def _verdict(context_class, type_ok):
    """The refusal the gate makes of a payload (or "ok"), by the order of the rule: the lax
    test first, then the position of the first entry, then the type."""
    if context_class == "none":
        return "context"
    if context_class == "later":
        return "first"
    return "ok" if type_ok else "type"


def _oracle(payload):
    """The verdict for a whole payload dict, an absent claim read as absent."""
    context = payload.get("@context", ABSENT)
    return _verdict(_oracle_context_class(context),
                    _oracle_type_ok(payload.get("type", ABSENT)))


def _expected(verdict, typ):
    """What ``_suite_outcome`` returns for a token with *typ* whose payload earns *verdict*."""
    if verdict == "ok":
        return "ok", True, None if typ is ABSENT else typ
    return SdJwtError, _says(verdict, typ)


# --------------------------------------------------------------------------- #
# the axes of the matrix: (id, value, class / ok) — the class is hand-annotated, and the
# first test below checks every annotation against the oracle's own computation
# --------------------------------------------------------------------------- #

CONTEXTS = [
    ("bare-v2", V2, "first"),
    ("v2", [V2], "first"),
    ("v2-extra", [V2, EXTRA], "first"),
    ("v2-examples", [V2, EXAMPLES_V2], "first"),
    ("v1-2018", [V1], "first"),
    ("v1-v2", [V1, V2], "first"),
    ("v2-v1", [V2, V1], "first"),
    ("extra-v2", [EXTRA, V2], "later"),
    ("object-v2", [VOCAB, V2], "later"),
    ("object-with-id-v2", [{"id": V2}, V2], "later"),
    ("nested-array-then-v2", [[V2], V2], "later"),
    ("number-then-v2", [7, V2], "later"),
    ("null-then-v2", [None, V2], "later"),
    ("empty-string-then-v2", ["", V2], "later"),
    ("lookalike-then-v2", [V2 + "/", V2], "later"),
    ("v1-lookalike-then-v1", [V1 + "/", V1], "later"),
    # first-place near misses of the base context (#275): a string that merely starts like it,
    # differs from it by a character, or is another W3C context. `lookalike-then-v2` above is
    # the eighth of the family.
    ("examples-v2-then-v2", [EXAMPLES_V2, V2], "later"),
    ("did-v1-then-v2", [DID_V1, V2], "later"),
    ("fragment-then-v2", [V2 + "#", V2], "later"),
    ("trailing-space-then-v2", [V2 + " ", V2], "later"),
    ("upper-case-then-v2", [V2.upper(), V2], "later"),
    ("http-scheme-then-v2", [V2.replace("https", "http"), V2], "later"),
    ("v1-lookalike-then-v2", [V1 + "/", V2], "later"),
    ("object-id-only", [{"id": V2}], "none"),
    ("empty-array", [], "none"),
    ("null-entry", [None], "none"),
    ("number-entry", [7], "none"),
    ("other-string", EXTRA, "none"),
    ("other-array", [EXTRA], "none"),
    ("nested-array", [[V2]], "none"),
    ("trailing-slash", [V2 + "/"], "none"),
    ("trailing-slash-string", V2 + "/", "none"),
    ("case-variant", ["https://WWW.W3.ORG/ns/credentials/v2"], "none"),
    ("http-scheme", ["http://www.w3.org/ns/credentials/v2"], "none"),
    ("leading-space", [" " + V2], "none"),
    ("object-keyed-by-the-url", {V2: {}}, "none"),
    ("object-context", VOCAB, "none"),
    ("null", None, "none"),
    ("absent", ABSENT, "none"),
]

TYPE_VALUES = [
    ("credential", ["VerifiableCredential"], True),
    ("credential-string", "VerifiableCredential", True),
    ("credential-and-x", ["VerifiableCredential", "X"], True),
    ("x-and-credential", ["X", "VerifiableCredential"], True),
    ("credential-and-number", ["VerifiableCredential", 7], True),
    ("credential-and-object", ["VerifiableCredential", {"a": 1}], True),
    ("null-and-credential", [None, "VerifiableCredential"], True),
    ("presentation", ["VerifiablePresentation"], False),
    ("presentation-string", "VerifiablePresentation", False),
    ("credential-and-presentation", ["VerifiableCredential", "VerifiablePresentation"], False),
    ("presentation-and-credential", ["VerifiablePresentation", "VerifiableCredential"], False),
    ("presentation-and-number", ["VerifiablePresentation", 7], False),
    ("empty-array", [], False),
    ("empty-string", "", False),
    ("x-string", "X", False),
    ("x", ["X"], False),
    ("number", 7, False),
    ("true", True, False),
    ("null", None, False),
    ("object-keyed-by-the-term", {"VerifiableCredential": 1}, False),
    ("nested-array", [["VerifiableCredential"]], False),
    ("absent", ABSENT, False),
    ("full-iri", ["https://www.w3.org/2018/credentials#VerifiableCredential"], False),
    ("prefixed", ["vc:VerifiableCredential"], False),
    ("lower-case", ["verifiablecredential"], False),
    ("trailing-space", ["VerifiableCredential "], False),
]

CONTEXT_PARAMS = pytest.mark.parametrize(
    "cid, context, klass", CONTEXTS, ids=[c[0] for c in CONTEXTS])
# A few contexts of each class, for the tests that need some of them rather than the grid.
LATER = [pytest.param([EXTRA, V2], id="extra-v2"), pytest.param([VOCAB, V2], id="object-v2"),
         pytest.param([[V2], V2], id="nested-then-v2"), pytest.param([7, V2], id="number-v2")]
NONE = [pytest.param([EXTRA], id="other"), pytest.param([V2 + "/"], id="trailing-slash"),
        pytest.param([[V2]], id="nested"), pytest.param([], id="empty")]


# --------------------------------------------------------------------------- #
# A. the matrix: typ x @context x type
# --------------------------------------------------------------------------- #

def test_the_hand_annotated_axes_agree_with_the_position_oracle():
    # The expected verdicts below rest on the annotations, so check the annotations against
    # an independent computation of the same thing, cell by cell, before trusting either.
    for cid, context, klass in CONTEXTS:
        assert _oracle_context_class(context) == klass, cid
    for tid, declared, type_ok in TYPE_VALUES:
        assert _oracle_type_ok(declared) is type_ok, tid
    for cid, context, klass in CONTEXTS:
        for tid, declared, type_ok in TYPE_VALUES:
            assert _oracle(_w3c(context, declared)) == _verdict(klass, type_ok), (cid, tid)
    # and the grid really has every verdict in it, so a verdict cannot go untested
    seen = {_verdict(k, ok) for _, _, k in CONTEXTS for _, _, ok in TYPE_VALUES}
    assert seen == {"ok", "context", "first", "type"}


@TYP
@CONTEXT_PARAMS
def test_the_grid_of_contexts_and_types_by_typ(typ, cid, context, klass):
    # 3 typs x 39 contexts x 26 types, through the suite: the verdict is the class and the
    # exact message, never "ok" for a payload the oracle refuses nor the reverse.
    wrong = []
    for tid, declared, type_ok in TYPE_VALUES:
        got = _suite_outcome(_mint(_w3c(context, declared), typ=typ))
        want = _expected(_verdict(klass, type_ok), typ)
        if got != want:
            wrong.append(f"{cid} x {tid}: expected {want!r}, got {got!r}")
    assert not wrong, "\n".join(wrong)


# The cases that matter most, each named for what a lax or reordered gate would let through.
# (typ, @context, type, verdict).
HAND = [
    pytest.param("vc+sd-jwt", V2, "VerifiableCredential", "ok", id="bare-string-context"),
    pytest.param("vc+sd-jwt", [V2, EXTRA], ["VerifiableCredential"], "ok",
                 id="base-first-then-another"),
    pytest.param(DRAFT_TYP, [V1], CREDENTIAL, "ok", id="vcdm-1-1-base-first"),
    pytest.param(ABSENT, [V1, V2], ["X", "VerifiableCredential"], "ok", id="no-typ-v1-then-v2"),
    pytest.param("vc+sd-jwt", [EXTRA, V2], CREDENTIAL, "first", id="vc-sd-jwt-base-second"),
    pytest.param(DRAFT_TYP, [EXTRA, V2], CREDENTIAL, "first", id="draft-typ-base-second"),
    pytest.param(ABSENT, [EXTRA, V2], CREDENTIAL, "first", id="no-typ-base-second"),
    pytest.param("vc+sd-jwt", [VOCAB, V2], CREDENTIAL, "first", id="object-first"),
    pytest.param("vc+sd-jwt", [V2 + "/", V2], CREDENTIAL, "first", id="lookalike-first"),
    pytest.param("vc+sd-jwt", [V2], ["VerifiableCredential", "VerifiablePresentation"],
                 "type", id="credential-and-presentation"),
    pytest.param(DRAFT_TYP, [V2], ["X"], "type", id="unrelated-type"),
    pytest.param(ABSENT, [V2], ABSENT, "type", id="no-type-claim"),
    pytest.param("vc+sd-jwt", [V2 + "/"], CREDENTIAL, "context", id="no-base-context-at-all"),
]


@pytest.mark.parametrize("typ, context, declared, verdict", HAND)
def test_the_cases_that_matter_most_through_both_pipelines_and_both_forms(
        run, form, typ, context, declared, verdict):
    assert _oracle(_w3c(context, declared)) == verdict       # the table is not its own oracle
    token = form(_mint(_w3c(context, declared), typ=typ))
    if verdict == "ok":
        result = run(token, None)
        assert result.format == "sd-jwt-vc"
        assert result.raw.vcdm is True
        assert result.raw.typ == (None if typ is ABSENT else typ)
        assert result.issuer == DID
        return
    with pytest.raises(SdJwtError) as excinfo:
        run(token, None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says(verdict, typ)


def test_the_cases_that_matter_most_cover_every_typ_and_every_requirement():
    assert {p.values[0] for p in HAND} == set(TYPS)
    assert {p.values[3] for p in HAND} == {"ok", "context", "first", "type"}


@TYP
def test_a_waived_expiry_does_not_waive_the_conformance_gate(run, typ):
    # `require_not_expired=False` waives the expiry only; the gate decides the reading first.
    waived = VerificationPolicy(require_not_expired=False)
    with pytest.raises(SdJwtError) as excinfo:
        run(_mint(_w3c([EXTRA, V2], CREDENTIAL, validUntil=PAST), typ=typ), waived)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("first", typ)
    with pytest.raises(SdJwtError) as excinfo:
        _suite_verify(_mint(_w3c([V2], ["VerifiablePresentation"], validUntil=PAST), typ=typ),
                      check_temporal=False)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


# --------------------------------------------------------------------------- #
# B. the order of the refusals
# --------------------------------------------------------------------------- #

EMBEDDED_VC = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
               "validFrom": "2020-01-01T00:00:00Z",
               "credentialSubject": {"id": "did:example:alice"}}
EMBEDDED_VP = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": "did:example:a"}


@TYP
@pytest.mark.parametrize("context", [
    pytest.param([EXTRA], id="foreign"), pytest.param([V2 + "/", EXTRA], id="lookalike"),
    pytest.param([[V2]], id="nested"), pytest.param(ABSENT, id="absent"),
])
def test_no_base_context_anywhere_is_refused_before_every_other_requirement(run, typ, context):
    # Everything else is wrong too (a `vc` claim, a presentation type, and for the fourth
    # context no `@context` at all), and the first thing the suite says is the oldest rule.
    doc = _w3c(context, ["VerifiablePresentation"], vc=EMBEDDED_VC, vp=EMBEDDED_VP)
    with pytest.raises(SdJwtError) as excinfo:
        run(_mint(doc, typ=typ), None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("context", typ)


@pytest.mark.parametrize("claim", ["vc", "vp"])
@pytest.mark.parametrize("context, declared", [
    pytest.param([EXTRA, V2], ABSENT, id="base-second-and-no-type"),
    pytest.param([EXTRA, V2], ["VerifiablePresentation"], id="base-second-and-presentation"),
    pytest.param([V2], ["VerifiablePresentation"], id="presentation-type"),
    pytest.param([V2], ABSENT, id="no-type"),
    pytest.param([V2], CREDENTIAL, id="nothing-else-wrong"),
])
def test_a_vc_or_vp_claim_with_no_typ_is_refused_before_the_gate(run, claim, context, declared):
    value = EMBEDDED_VC if claim == "vc" else EMBEDDED_VP
    with pytest.raises(SdJwtError) as excinfo:
        run(_mint(_w3c(context, declared, **{claim: value}), typ=ABSENT), None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == NO_VC_CLAIM


@TYP
def test_the_position_of_the_context_is_refused_before_the_type(run, typ):
    for declared in (["VerifiablePresentation"], ABSENT, "X", 7, ["VerifiableCredential"]):
        doc = _w3c([EXTRA, V2], declared)
        with pytest.raises(SdJwtError) as excinfo:
            run(_mint(doc, typ=typ), None)
        assert excinfo.type is SdJwtError
        assert str(excinfo.value) == _says("first", typ)


@TYP
def test_the_type_is_refused_only_once_the_context_is_in_place(run, typ):
    with pytest.raises(SdJwtError) as excinfo:
        run(_mint(_w3c([V2, EXTRA], ["VerifiablePresentation"]), typ=typ), None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


# --------------------------------------------------------------------------- #
# C. dc+sd-jwt is unchanged, and the lax test still drives the window and the consistency
# --------------------------------------------------------------------------- #

@CONTEXT_PARAMS
def test_dc_sd_jwt_meets_no_context_position_rule(cid, context, klass):
    # An IETF SD-JWT VC with a vct: every context verifies. It is VCDM (`vcdm`) exactly when
    # a base URL is anywhere in the array, which is the lax test, and no `type` was asked for.
    result = _suite_verify(_mint(_dc(context), typ=DC_TYP))
    assert result.typ == DC_TYP
    assert result.vct == VCT
    assert result.vcdm is (klass != "none")


@pytest.mark.parametrize("tid, declared, type_ok", TYPE_VALUES, ids=[t[0] for t in TYPE_VALUES])
def test_dc_sd_jwt_meets_no_type_rule(tid, declared, type_ok):
    for context in ([V2], [EXTRA, V2]):
        result = _suite_verify(_mint(_dc(context, declared), typ=DC_TYP))
        assert result.typ == DC_TYP
        assert result.vcdm is True


def test_dc_sd_jwt_with_the_base_context_second_verifies_through_both_pipelines(run, form):
    result = run(form(_mint(_dc([EXTRA, V2]), typ=DC_TYP)), None)
    assert result.format == "sd-jwt-vc"
    assert result.raw.typ == DC_TYP
    assert result.raw.vct == VCT
    assert result.raw.vcdm is True
    assert result.issuer == DID
    assert result.expired is False


@pytest.mark.parametrize("context", LATER)
def test_dc_sd_jwt_with_the_base_context_second_is_key_bound_like_any_other(run, context):
    policy = VerificationPolicy(audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    result = run(_present(_dc(context), typ=DC_TYP), policy)
    assert result.raw.key_bound is True
    assert result.raw.typ == DC_TYP
    assert result.raw.vcdm is True


@pytest.mark.parametrize("context", LATER)
def test_a_base_url_in_second_place_still_enforces_the_window_on_dc_sd_jwt(run, form, context):
    # The lax test drives the window: moving the base URL to second place must not be a way
    # to switch an expired or not-yet-valid credential's window off.
    with pytest.raises(CredentialExpired) as excinfo:
        run(form(_mint(_dc(context, validUntil=PAST), typ=DC_TYP)), None)
    assert excinfo.type is CredentialExpired
    with pytest.raises(CredentialNotYetValid) as excinfo:
        run(form(_mint(_dc(context, validFrom=FUTURE), typ=DC_TYP)), None)
    assert excinfo.type is CredentialNotYetValid


def test_the_expiry_waiver_reports_a_dc_sd_jwt_with_the_base_context_second_as_expired(run):
    waived = VerificationPolicy(require_not_expired=False)
    result = run(_mint(_dc([EXTRA, V2], validUntil=PAST), typ=DC_TYP), waived)
    assert result.expired is True
    assert result.raw.vcdm is True
    assert result.raw.expired is True
    with pytest.raises(CredentialNotYetValid):
        run(_mint(_dc([EXTRA, V2], validFrom=FUTURE), typ=DC_TYP), waived)


@pytest.mark.parametrize("extra, match", [
    pytest.param({"issuer": "did:web:university.example"}, "issuer", id="issuer"),
    pytest.param({"jti": "urn:uuid:another-credential"}, "jti", id="jti"),
    pytest.param({"sub": "did:example:bob"}, "sub", id="sub"),
])
@pytest.mark.parametrize("context", LATER)
def test_a_base_url_in_second_place_still_reconciles_issuer_and_subject_on_dc_sd_jwt(
        run, form, context, extra, match):
    with pytest.raises(ClaimsInvalid, match=match) as excinfo:
        run(form(_mint(_dc(context, **extra), typ=DC_TYP)), None)
    assert excinfo.type is ClaimsInvalid


@pytest.mark.parametrize("context", NONE)
def test_a_dc_sd_jwt_with_no_vcdm_context_has_no_window_and_no_reconciliation(run, context):
    # Its claims are named validFrom / validUntil / issuer, and in its vocabulary they mean
    # nothing: not read as a bound, not reconciled with `iss`. `vcdm` is False.
    doc = _dc(context, validUntil=PAST, validFrom=FUTURE, issuer="did:web:elsewhere.example",
              jti="urn:uuid:another-credential", sub="did:example:bob")
    result = run(_mint(doc, typ=DC_TYP), None)
    assert result.raw.vcdm is False
    assert result.expired is False
    assert result.claims["validUntil"] == PAST
    assert result.claims["issuer"] == "did:web:elsewhere.example"


@TYP
def test_a_conforming_w3c_token_still_has_the_window_enforced(run, form, typ):
    with pytest.raises(CredentialExpired) as excinfo:
        run(form(_mint(_good(validUntil=PAST), typ=typ)), None)
    assert excinfo.type is CredentialExpired
    with pytest.raises(CredentialNotYetValid) as excinfo:
        run(form(_mint(_good(validFrom=FUTURE), typ=typ)), None)
    assert excinfo.type is CredentialNotYetValid
    waived = VerificationPolicy(require_not_expired=False)
    result = run(form(_mint(_good(validUntil=PAST), typ=typ)), waived)
    assert result.expired is True
    assert result.raw.vcdm is True


@TYP
@pytest.mark.parametrize("extra, match", [
    pytest.param({"issuer": "did:web:university.example"}, "issuer", id="issuer"),
    pytest.param({"jti": "urn:uuid:another-credential"}, "jti", id="jti"),
    pytest.param({"sub": "did:example:bob"}, "sub", id="sub"),
])
def test_a_conforming_w3c_token_still_has_issuer_and_subject_reconciled(
        run, form, typ, extra, match):
    with pytest.raises(ClaimsInvalid, match=match) as excinfo:
        run(form(_mint(_good(**extra), typ=typ)), None)
    assert excinfo.type is ClaimsInvalid


@pytest.mark.parametrize("typ", [DC_TYP, "vc+sd-jwt", DRAFT_TYP, ABSENT],
                         ids=["dc-sd-jwt", "vc-sd-jwt", "draft-typ", "no-typ"])
@pytest.mark.parametrize("context", LATER)
def test_a_disclosable_validity_claim_is_refused_whatever_the_position_of_the_base_url(
        typ, context):
    # The lax test also decides which claims may be selectively disclosed, and that refusal is
    # made before the gate: the message is the disclosure one even for a payload the gate
    # would refuse (and for dc+sd-jwt, which the gate never sees, it is the only refusal).
    doc = _dc(context, validUntil=FUTURE) if typ == DC_TYP else _w3c(
        context, CREDENTIAL, validUntil=FUTURE)
    with pytest.raises(SdJwtError, match=VALIDITY_DISCLOSED) as excinfo:
        _suite_verify(_mint(doc, typ=typ, disclose=["validUntil"]))
    assert excinfo.type is SdJwtError
    assert "'validUntil' is selectively disclosed" in str(excinfo.value)


def test_a_validity_claim_stays_disclosable_on_a_dc_sd_jwt_with_no_vcdm_context():
    doc = _dc([EXTRA], validUntil=PAST)
    result = _suite_verify(_mint(doc, typ=DC_TYP, disclose=["validUntil"]))
    assert result.vcdm is False
    assert result.claims["validUntil"] == PAST


# --------------------------------------------------------------------------- #
# D. a withheld selectively-disclosable `type` (the Recommendation's Example 4 shape)
# --------------------------------------------------------------------------- #

@TYP
def test_a_disclosed_type_is_read_and_a_withheld_one_is_refused(run, form, typ):
    token = _mint(_good(), typ=typ, disclose=["type"])
    result = run(form(token), None)
    assert result.raw.vcdm is True
    assert result.raw.typ == (None if typ is ABSENT else typ)
    assert result.credential["type"] == CREDENTIAL
    with pytest.raises(SdJwtError) as excinfo:
        run(form(_without(token, "type")), None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


@TYP
def test_a_disclosed_type_that_says_presentation_is_refused(run, typ):
    token = _mint(_w3c([V2], ["VerifiablePresentation"]), typ=typ, disclose=["type"])
    with pytest.raises(SdJwtError) as excinfo:
        run(token, None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


@TYP
def test_the_withheld_type_is_refused_by_the_suite_directly_too(typ):
    token = _mint(_good(), typ=typ, disclose=["type"])
    assert _suite_verify(token).vcdm is True
    with pytest.raises(SdJwtError) as excinfo:
        _suite_verify(_without(token, "type"))
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


def test_a_withheld_type_on_a_dc_sd_jwt_verifies_either_way(run, form):
    token = _mint(_dc([V2, EXAMPLES_V2], CREDENTIAL), typ=DC_TYP, disclose=["type"])
    shown = run(form(token), None)
    assert shown.claims["type"] == CREDENTIAL
    withheld = run(form(_without(token, "type")), None)
    assert "type" not in withheld.claims
    for result in (shown, withheld):
        assert result.raw.typ == DC_TYP
        assert result.raw.vcdm is True
        assert result.raw.vct == VCT


# --------------------------------------------------------------------------- #
# E. the Recommendation's own tokens are still read as credentials
# --------------------------------------------------------------------------- #

# Both tokens are copied from "Securing Verifiable Credentials using JOSE and COSE" (W3C
# Recommendation, 13 October 2026): Example 5 (no typ) and Example 21 (typ vc+ld+json+sd-jwt);
# see test_sd_jwt_vcdm_typ_interop.py section I for the provenance. The Recommendation
# publishes no key. `verify()` checks the signature BEFORE it reads the payload, so a stranger's
# key only proves the header gets past the typ gate and says nothing about the payload gate.
# What does is a token that verifies: the header, the payload and the disclosures are the
# Recommendation's, only the signature is ours.
FIXTURES = Path(__file__).parent / "fixtures" / "vc_jose_cose"
EXAMPLE_5 = "rec-example5-no-typ.sd-jwt"
EXAMPLE_21 = "rec-example21-vc-ld-json-sd-jwt-typ.sd-jwt"
REAL = pytest.mark.parametrize("name, key_class, typ", [
    pytest.param(EXAMPLE_5, P256SigningKey, ABSENT, id="example-5"),
    pytest.param(EXAMPLE_21, P384SigningKey, DRAFT_TYP, id="example-21"),
])


def _fixture(name):
    return (FIXTURES / name).read_text(encoding="ascii").rstrip("\n")


def _resigned(token, key, *, amend=None):
    """The real token's header and payload (amended by *amend*, if given) under *key*, the
    disclosures untouched: the `_sd` digests hash the disclosures, not the payload."""
    jws, rest = token.split("~", 1)
    header_b64, payload_b64, _ = jws.split(".")
    if amend is not None:
        payload = _decode(payload_b64)
        amend(payload)
        payload_b64 = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}~{rest}"


def _processed(token):
    """The payload as the gate sees it: the body with the TOP-LEVEL disclosures merged in
    (the nested `type` disclosures of the schema and the degree are not top-level claims)."""
    jws, *rest = token.split("~")
    body = _decode(jws.split(".")[1])
    digests = set(body["_sd"])
    for disclosure in rest[:-1]:
        parts = _decode(disclosure)
        if len(parts) == 3 and disclosure_digest(disclosure) in digests:
            body[parts[1]] = parts[2]
    return body


def _add_iss(payload):
    # Example 5 names its issuer only in `issuer`, and this lane reads the verified issuer
    # from `iss`: the one amendment that lets it verify at all (#290).
    payload.setdefault("iss", payload["issuer"])


@REAL
def test_the_oracle_reads_the_recommendations_tokens_as_conforming(name, key_class, typ):
    payload = _processed(_fixture(name))
    assert payload["@context"][0] == V2
    assert payload["type"] == CREDENTIAL
    assert _oracle(payload) == "ok"
    assert ("vc" in payload or "vp" in payload) is False


@REAL
def test_a_stranger_key_fails_at_the_signature_not_at_the_typ_gate(name, key_class, typ):
    stranger = key_class.generate(kid="stranger")
    with pytest.raises(SignatureInvalid) as excinfo:
        SdJwtVcProofSuite().verify(_fixture(name), public_key_jwk=stranger.public_jwk(),
                                   check_temporal=False)
    assert excinfo.type is SignatureInvalid


@REAL
def test_the_recommendations_tokens_verify_as_credentials_under_a_key_of_our_own(
        name, key_class, typ):
    key = key_class.generate(kid="resigned")
    token = _resigned(_fixture(name), key, amend=_add_iss)
    # The examples' own `exp` is long past: waive the expiry only
    result = SdJwtVcProofSuite().verify(token, public_key_jwk=key.public_jwk(),
                                        check_temporal=False)
    assert result.vcdm is True
    assert result.typ == (None if typ is ABSENT else typ)
    assert result.claims["type"] == CREDENTIAL
    assert result.claims["@context"][0] == V2
    assert result.issuer == "https://university.example/issuers/565049"


@REAL
def test_the_gate_is_live_on_the_same_real_tokens(name, key_class, typ):
    # The control for the test above: amend the Recommendation's payload in one respect each,
    # re-sign, and the verdict moves from "verifies" to the matching refusal.
    key = key_class.generate(kid="resigned")

    def misplace(payload):
        _add_iss(payload)
        payload["@context"].insert(0, EXTRA)

    def not_a_context(payload):
        _add_iss(payload)
        payload["@context"] = [EXTRA, EXAMPLES_V2]

    suite = SdJwtVcProofSuite()
    for amend, requirement in ((misplace, "first"), (not_a_context, "context")):
        with pytest.raises(SdJwtError) as excinfo:
            suite.verify(_resigned(_fixture(name), key, amend=amend),
                         public_key_jwk=key.public_jwk(), check_temporal=False)
        assert excinfo.type is SdJwtError
        assert str(excinfo.value) == _says(requirement, typ)


@REAL
def test_the_recommendations_tokens_are_refused_when_their_type_is_withheld(
        name, key_class, typ):
    # Example 4's shape: the top-level `type` is a disclosure the holder may keep back.
    key = key_class.generate(kid="resigned")
    token = _resigned(_fixture(name), key, amend=_add_iss)
    jws, *rest = token.split("~")
    kept = [d for d in rest[:-1] if _decode(d)[1:] != ["type", CREDENTIAL]]
    assert len(kept) == len(rest) - 2
    withheld = jws + "~" + "".join(d + "~" for d in kept)
    with pytest.raises(SdJwtError) as excinfo:
        SdJwtVcProofSuite().verify(withheld, public_key_jwk=key.public_jwk(),
                                   check_temporal=False)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


# --------------------------------------------------------------------------- #
# F. VerificationPolicy(expected_types=...): a non-conforming token never reaches the pin
# --------------------------------------------------------------------------- #

def _pin(*expected):
    return VerificationPolicy(expected_types=list(expected))


@TYP
def test_a_conforming_token_meets_a_matching_pin_and_fails_a_wrong_one_as_before(
        run, form, typ):
    token = form(_mint(_good(), typ=typ))
    assert run(token, _pin("ExampleAlumniCredential")).raw.vcdm is True
    assert run(token, _pin("VerifiableCredential", "ExampleAlumniCredential")).raw.vcdm is True
    with pytest.raises(TypeMismatch, match=MISSING_TYPE) as excinfo:
        run(token, _pin("UniversityDegreeCredential"))
    assert excinfo.type is TypeMismatch
    with pytest.raises(TypeMismatch, match="UniversityDegreeCredential") as excinfo:
        run(token, _pin("ExampleAlumniCredential", "UniversityDegreeCredential"))
    assert excinfo.type is TypeMismatch


@TYP
@pytest.mark.parametrize("declared", [
    pytest.param(7, id="number"),
    pytest.param(True, id="bool"),
    pytest.param(None, id="null"),
    pytest.param({"ExampleAlumniCredential": 1}, id="object-keyed-by-the-pin"),
    pytest.param("ExampleAlumniCredential", id="string-without-verifiable-credential"),
    pytest.param(["ExampleAlumniCredential"], id="array-without-verifiable-credential"),
    pytest.param(["VerifiablePresentation", "ExampleAlumniCredential"], id="presentation"),
    pytest.param(ABSENT, id="absent"),
])
def test_a_non_credential_type_is_refused_at_the_gate_before_the_pin_looks(
        run, form, typ, declared):
    # Each of these used to reach `_check_types` and raise TypeMismatch under a pin (and the
    # three that name the pinned type used to PASS it); now the suite refuses first. The class
    # is exact: SdJwtError is not a TypeMismatch.
    with pytest.raises(SdJwtError) as excinfo:
        run(form(_mint(_w3c([V2], declared), typ=typ)), _pin("ExampleAlumniCredential"))
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)


@TYP
def test_a_misplaced_context_is_refused_at_the_gate_whatever_the_pin(run, typ):
    for pin in (_pin("ExampleAlumniCredential"), _pin("UniversityDegreeCredential"), None):
        with pytest.raises(SdJwtError) as excinfo:
            run(_mint(_w3c([EXTRA, V2], CREDENTIAL), typ=typ), pin)
        assert excinfo.type is SdJwtError
        assert str(excinfo.value) == _says("first", typ)


@pytest.mark.parametrize("declared", [7, "X", None, ["VerifiablePresentation"]],
                         ids=["number", "string", "null", "presentation"])
def test_a_dc_sd_jwt_is_not_gated_so_its_type_still_meets_the_pin_as_before(run, declared):
    # dc+sd-jwt (even with a lax VCDM context) keeps the old path: the pin is read against
    # its `type` claim and a mismatch is a TypeMismatch, not an SdJwtError.
    with pytest.raises(TypeMismatch) as excinfo:
        run(_mint(_dc([EXTRA, V2], declared), typ=DC_TYP), _pin("ExampleAlumniCredential"))
    assert excinfo.type is TypeMismatch
    result = run(_mint(_dc([EXTRA, V2], CREDENTIAL), typ=DC_TYP), _pin("ExampleAlumniCredential"))
    assert result.raw.vcdm is True


# --------------------------------------------------------------------------- #
# G. OpenID4VP
# --------------------------------------------------------------------------- #

def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline, a VP-JWT holder
    and an ``ecdsa-jcs-2019`` VP signer."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


HOLDER = _did_key_p256()


def _answer_dc(presentation, *, vct_values=None):
    query = {"id": "q", "format": "dc+sd-jwt"}
    if vct_values is not None:
        query["meta"] = {"vct_values": vct_values}
    return verify_vp_token({"q": [presentation]}, dcql_query={"credentials": [query]},
                           nonce=NONCE, client_id=CLIENT_ID).for_query("q")[0]


@pytest.mark.parametrize("context", [pytest.param(ABSENT, id="no-context"),
                                     pytest.param([EXTRA, V2], id="base-second"),
                                     pytest.param([VOCAB, V2], id="object-first")])
def test_a_dc_sd_jwt_query_answers_an_ietf_token_as_before(context):
    answer = _answer_dc(_present(_dc(context), typ=DC_TYP), vct_values=[VCT])
    assert answer.raw.typ == DC_TYP
    assert answer.raw.vct == VCT
    assert answer.raw.key_bound is True
    assert answer.raw.vcdm is (context is not ABSENT)


@TYP
def test_a_dc_sd_jwt_query_still_refuses_a_conforming_w3c_token(typ):
    # Unchanged by #275 (#272): the dc+sd-jwt format is the IETF SD-JWT VC, typed dc+sd-jwt.
    with pytest.raises(VpTokenMalformed, match=NOT_IETF) as excinfo:
        _answer_dc(_present(_good(vct=VCT), typ=typ))
    assert excinfo.type is VpTokenMalformed


def _w3c_vp(lane, sd_jwt):
    """A presentation, by *lane*, of one SD-JWT, signed by the did:key holder."""
    holder_key, holder_did = HOLDER
    if lane == "jwt_vc_json":
        return VpJwtProofSuite().sign([sd_jwt], holder_key=holder_key,
                                      audience=CLIENT_ID, nonce=NONCE)
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": holder_did,
          "verifiableCredential": [sd_jwt]}
    return EcdsaJcsProofSuite().add_proof(
        vp, signing_key=holder_key, verification_method=holder_key.kid,
        proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)


def _bound_sd_jwt(payload, typ, form):
    """The hand-minted token bound (``cnf``) to HOLDER and presented with a KB-JWT for this
    exchange, in *form* (a bare SD-JWT or an EnvelopedVerifiableCredential)."""
    holder_key, _ = HOLDER
    token = _mint({**payload, "cnf": {"jwk": holder_key.public_jwk()}}, typ=typ)
    presented = SdJwtVcProofSuite().create_presentation(
        token, holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)
    return form(presented)


def _nested(lane, sd_jwt):
    query = {"credentials": [{"id": "q", "format": lane}]}
    return verify_vp_token({"q": [_w3c_vp(lane, sd_jwt)]}, dcql_query=query, nonce=NONCE,
                           client_id=CLIENT_ID).for_query("q")[0]


LANES = pytest.mark.parametrize("lane", ["jwt_vc_json", "ldp_vc"])


@LANES
@TYP
def test_a_conforming_w3c_sd_jwt_nested_in_a_presentation_still_verifies(lane, form, typ):
    answer = _nested(lane, _bound_sd_jwt(_good(), typ, form))
    (credential,) = answer.credentials
    assert credential.key_bound is True
    assert credential.credential["type"] == CREDENTIAL
    assert credential.credential["@context"][0] == V2


@LANES
@TYP
@pytest.mark.parametrize("payload, requirement", [
    pytest.param(_w3c([EXTRA, V2], CREDENTIAL), "first", id="base-second"),
    pytest.param(_w3c([VOCAB, V2], CREDENTIAL), "first", id="object-first"),
    pytest.param(_w3c([V2], ["VerifiablePresentation"]), "type", id="presentation-type"),
    pytest.param(_w3c([V2]), "type", id="no-type"),
    pytest.param(_w3c([V2 + "/"], CREDENTIAL), "context", id="no-base-context"),
])
def test_a_non_conforming_w3c_sd_jwt_nested_in_a_presentation_is_refused(
        lane, form, typ, payload, requirement):
    with pytest.raises(SdJwtError) as excinfo:
        _nested(lane, _bound_sd_jwt(payload, typ, form))
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says(requirement, typ)


@LANES
def test_a_dc_sd_jwt_nested_in_a_presentation_meets_no_gate(lane):
    answer = _nested(lane, _bound_sd_jwt(_dc([EXTRA, V2]), DC_TYP, lambda token: token))
    (credential,) = answer.credentials
    assert credential.key_bound is True


# --------------------------------------------------------------------------- #
# H. issue() mints dc+sd-jwt only, and does not apply the conformance gate
# --------------------------------------------------------------------------- #

def test_issue_refuses_a_disclosable_validity_claim_under_a_base_url_in_second_place():
    # The lax test, not the gate, decides it: `type` is not even present, and the payload
    # would not conform, but the window it would switch off is the point.
    for context in ([EXTRA, V2], [V2], [VOCAB, V2]):
        with pytest.raises(SdJwtError, match=VALIDITY_DISCLOSED) as excinfo:
            SdJwtVcProofSuite().issue(
                {"iss": DID, "@context": context, "validUntil": FUTURE},
                signing_key=KEY, vct=VCT, disclosable=["validUntil"])
        assert excinfo.type is SdJwtError
        assert "'validUntil' must not be selectively disclosable" in str(excinfo.value)


def test_issue_mints_a_payload_the_gate_would_refuse_as_a_dc_sd_jwt():
    # The payload has the base URL in second place and no `type`: it does not conform, and
    # issue() does not say so. It is an IETF SD-JWT VC (typ dc+sd-jwt, a vct), which the gate
    # never judges, and the suite reads it back as VCDM for the window.
    token = SdJwtVcProofSuite().issue(
        {"iss": DID, "@context": [EXTRA, V2], "validFrom": "2020-01-01T00:00:00Z",
         "name": "Ada"},
        signing_key=KEY, vct=VCT, disclosable=["name"])
    assert _header(token)["typ"] == DC_TYP
    result = _suite_verify(token)
    assert result.typ == DC_TYP
    assert result.vcdm is True
    assert result.vct == VCT
    assert result.claims["name"] == "Ada"


def test_issue_leaves_a_validity_claim_disclosable_when_no_vcdm_context_makes_it_a_window():
    token = SdJwtVcProofSuite().issue(
        {"iss": DID, "@context": [V2 + "/"], "validUntil": PAST},
        signing_key=KEY, vct=VCT, disclosable=["validUntil"])
    result = _suite_verify(token)
    assert result.vcdm is False
    assert result.claims["validUntil"] == PAST


# --------------------------------------------------------------------------- #
# I. the key-bound paths: the gate runs when the binding is REQUIRED too
# --------------------------------------------------------------------------- #

# `verify(require_key_binding=True)` takes a different road from the hosted one: the KB-JWT is
# verified BEFORE the expiry, and the gate comes after both. A refusal that is only made on the
# other road would let a holder present a non-conforming issuer JWT with a perfectly valid
# KB-JWT. Every token below is bound (`cnf`) and presented WITH a valid KB-JWT for this
# exchange, so what refuses it is the gate, and the same shapes with their conforming twin
# verify bound. The control is the same token with its KB-JWT stripped: it fails on the
# BINDING (ClaimsInvalid) on every road, which is the in-file proof that the binding is
# REQUIRED there (`key_bound` alone proves nothing: the optional road sets it too), so the
# gate's verdict was reached by the required-binding road.
# A: base URL second; B: no type; C: presentation type; D: the same with no `typ`;
# E: the draft-era `typ` with A's shape. (typ, payload, requirement, conforming twin)
KB_SHAPES = [
    pytest.param("vc+sd-jwt", _w3c([EXTRA, V2], ["VerifiableCredential"]), "first",
                 _w3c([V2, EXTRA], ["VerifiableCredential"]), id="a-base-second"),
    pytest.param("vc+sd-jwt", _w3c([V2]), "type",
                 _w3c([V2], ["VerifiableCredential"]), id="b-no-type"),
    pytest.param("vc+sd-jwt", _w3c([V2], ["VerifiablePresentation"]), "type",
                 _w3c([V2], ["VerifiableCredential"]), id="c-presentation-type"),
    pytest.param(ABSENT, _w3c([V2], ["VerifiablePresentation"]), "type",
                 _w3c([V2], ["VerifiableCredential"]), id="d-no-typ-presentation-type"),
    pytest.param(DRAFT_TYP, _w3c([EXTRA, V2], ["VerifiableCredential"]), "first",
                 _w3c([V2, EXTRA], ["VerifiableCredential"]), id="e-draft-typ-base-second"),
]
KB_SHAPE = pytest.mark.parametrize("typ, payload, requirement, twin", KB_SHAPES)
NO_KB_JWT = "key binding required but no KB-JWT present"


def _kb_policy():
    return VerificationPolicy(require_key_binding=True, audience=CLIENT_ID, nonce=NONCE)


def _suite_bound(sd_jwt):
    return _suite_verify(sd_jwt, require_key_binding=True, audience=CLIENT_ID, nonce=NONCE)


def _stripped(presentation):
    """The presentation without its KB-JWT (the part after the last `~`)."""
    return presentation.rsplit("~", 1)[0] + "~"


def test_the_key_bound_shapes_cover_every_typ_and_both_requirements():
    assert {p.values[0] for p in KB_SHAPES} == set(TYPS)
    assert {p.values[2] for p in KB_SHAPES} == {"first", "type"}
    for p in KB_SHAPES:
        typ, payload, requirement, twin = p.values
        assert _oracle(payload) == requirement, p.id         # the table is not its own oracle
        assert _oracle(twin) == "ok", p.id


@KB_SHAPE
def test_the_suite_refuses_a_non_conforming_token_when_the_binding_is_required(
        typ, payload, requirement, twin):
    with pytest.raises(SdJwtError) as excinfo:
        _suite_bound(_present(payload, typ=typ))
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says(requirement, typ)


@KB_SHAPE
def test_the_suite_verifies_the_conforming_twin_bound(typ, payload, requirement, twin):
    result = _suite_bound(_present(twin, typ=typ))
    assert result.key_bound is True
    assert result.vcdm is True
    assert result.typ == (None if typ is ABSENT else typ)


@KB_SHAPE
def test_the_suite_requires_the_binding_it_is_asked_for(typ, payload, requirement, twin):
    # The control: the same tokens with the KB-JWT stripped fail on the binding, before the
    # gate is reached (the KB-JWT is verified first on this road), conforming or not.
    for claims in (payload, twin):
        with pytest.raises(ClaimsInvalid, match=NO_KB_JWT) as excinfo:
            _suite_bound(_stripped(_present(claims, typ=typ)))
        assert excinfo.type is ClaimsInvalid


@KB_SHAPE
def test_a_non_conforming_token_is_refused_through_the_pipelines_when_the_binding_is_required(
        run, form, typ, payload, requirement, twin):
    with pytest.raises(SdJwtError) as excinfo:
        run(form(_present(payload, typ=typ)), _kb_policy())
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says(requirement, typ)


@KB_SHAPE
def test_the_conforming_twin_verifies_bound_through_the_pipelines(
        run, form, typ, payload, requirement, twin):
    result = run(form(_present(twin, typ=typ)), _kb_policy())
    assert result.raw.key_bound is True
    assert result.raw.vcdm is True
    assert result.raw.typ == (None if typ is ABSENT else typ)
    assert result.issuer == DID


@KB_SHAPE
def test_the_pipelines_require_the_binding_they_are_asked_for(
        run, form, typ, payload, requirement, twin):
    for claims in (payload, twin):
        with pytest.raises(ClaimsInvalid, match=NO_KB_JWT) as excinfo:
            run(form(_stripped(_present(claims, typ=typ))), _kb_policy())
        assert excinfo.type is ClaimsInvalid


@LANES
@KB_SHAPE
def test_a_non_conforming_token_nested_in_a_presentation_is_refused_whatever_the_shape(
        lane, form, typ, payload, requirement, twin):
    # jwt_vc_json: the SD-JWT inside a VP-JWT; ldp_vc: inside a Data Integrity VP. The query
    # requires the holder binding (the default), so this is the required-binding road.
    with pytest.raises(SdJwtError) as excinfo:
        _nested(lane, _bound_sd_jwt(payload, typ, form))
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says(requirement, typ)


@LANES
@KB_SHAPE
def test_the_conforming_twin_nested_in_a_presentation_verifies_bound(
        lane, form, typ, payload, requirement, twin):
    (credential,) = _nested(lane, _bound_sd_jwt(twin, typ, form)).credentials
    assert credential.key_bound is True
    assert credential.raw.vcdm is True
    assert credential.raw.typ == (None if typ is ABSENT else typ)


@LANES
@KB_SHAPE
def test_a_presentation_query_requires_the_binding_of_the_nested_token(
        lane, form, typ, payload, requirement, twin):
    def strip_then_form(sd_jwt):
        return form(_stripped(sd_jwt))

    for claims in (payload, twin):
        with pytest.raises(ClaimsInvalid, match=NO_KB_JWT) as excinfo:
            _nested(lane, _bound_sd_jwt(claims, typ, strip_then_form))
        assert excinfo.type is ClaimsInvalid


# --------------------------------------------------------------------------- #
# J. the near misses of the first entry, and a `type` naming both, by name
# --------------------------------------------------------------------------- #

# The grid (section A) runs all of these under every typ and every `type`; this section names
# the family and the message, so that a failure reads as what it is. The first seven are rows
# of CONTEXTS; `lookalike-then-v2` is the eighth.
NEAR_MISSES = [
    pytest.param([EXAMPLES_V2, V2], id="examples-v2"),
    pytest.param([DID_V1, V2], id="did-v1"),
    pytest.param([V2 + "/", V2], id="trailing-slash"),
    pytest.param([V2 + "#", V2], id="empty-fragment"),
    pytest.param([V2 + " ", V2], id="trailing-space"),
    pytest.param([V2.upper(), V2], id="upper-case"),
    pytest.param([V2.replace("https", "http"), V2], id="http-scheme"),
    pytest.param([V1 + "/", V2], id="v1-with-a-slash"),
]
FIRST_ENTRY = "first `@context` entry"
INCLUDES_VC = "includes VerifiableCredential"


def test_the_near_misses_are_all_in_the_grid_of_contexts_once():
    grid = [context for _, context, _ in CONTEXTS]
    for near in NEAR_MISSES:
        context = near.values[0]
        assert grid.count(context) == 1, near.id
        assert _oracle(_w3c(context, ["VerifiableCredential"])) == "first", near.id
    assert len(NEAR_MISSES) == len({repr(n.values[0]) for n in NEAR_MISSES}) == 8


@TYP
@pytest.mark.parametrize("context", NEAR_MISSES)
def test_a_near_miss_of_the_base_context_in_first_place_is_refused(typ, context):
    with pytest.raises(SdJwtError, match=FIRST_ENTRY) as excinfo:
        _suite_verify(_mint(_w3c(context, ["VerifiableCredential"]), typ=typ))
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("first", typ)


@TYP
@pytest.mark.parametrize("context", NEAR_MISSES)
def test_a_near_miss_of_the_base_context_in_first_place_is_refused_through_the_pipelines(
        run, form, typ, context):
    with pytest.raises(SdJwtError, match=FIRST_ENTRY) as excinfo:
        run(form(_mint(_w3c(context, ["VerifiableCredential"]), typ=typ)), None)
    assert excinfo.type is SdJwtError


@TYP
@pytest.mark.parametrize("declared", [
    pytest.param(["VerifiableCredential", "VerifiablePresentation"], id="credential-first"),
    pytest.param(["VerifiablePresentation", "VerifiableCredential"], id="presentation-first"),
])
def test_a_type_naming_both_a_credential_and_a_presentation_is_refused(run, form, typ, declared):
    with pytest.raises(SdJwtError, match=INCLUDES_VC) as excinfo:
        run(form(_mint(_w3c([V2], declared), typ=typ)), None)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says("type", typ)
    with pytest.raises(SdJwtError, match=INCLUDES_VC) as excinfo:
        _suite_verify(_mint(_w3c([V2, EXTRA], declared), typ=typ))
    assert excinfo.type is SdJwtError


# --------------------------------------------------------------------------- #
# K. an array ELEMENT made disclosable: the documented limit of judging the processed payload
# --------------------------------------------------------------------------- #

def _mint_elements(payload, claim, index, *, typ):
    """(presented, withheld): the token whose top-level array *claim* has its element at
    *index* replaced by a digest object (RFC 9901 §4.2.2: ``{"...": digest}``) the issuer
    signed, with the disclosure of that element presented and withheld."""
    body = copy.deepcopy(payload)
    disclosure = make_array_disclosure(_b64(secrets.token_bytes(16)), body[claim][index])
    body[claim][index] = {"...": disclosure_digest(disclosure)}
    withheld = _mint(body, typ=typ)
    return withheld + disclosure + "~", withheld


# The gate judges the PROCESSED payload, so when an issuer makes an array element of
# `@context` or of `type` selectively disclosable, the verdict depends on what the holder
# presents. This is a documented limit (the same one RFC 9901 §9.7 states for any claim:
# withholding is indistinguishable from a decoy) and not a hole: every accepting flip below
# needs the SIGNER to have made that very element disclosable, so the holder gains nothing
# the signer did not grant, and the processed payload still has to meet the whole rule. The
# payload stays VCDM (`vcdm` True, a base URL is still there), so the validity window and the
# issuer / subject consistency still run on the accepted side, which is pinned below too.
# (payload, claim, index, the side that verifies, how the other side is refused: "disclosure"
# is the refusal of a presented `@context` sub-claim, "type" the gate's own.)
FLIPS = [
    # (i) a context entry before the base URL: presented, `@context` is a disclosed sub-claim
    # (refused as any `@context` disclosure is); withheld, the gate sees [V2] and it conforms
    pytest.param(_w3c([EXTRA, V2], CREDENTIAL), "@context", 0, "withheld", "disclosure",
                 id="context-entry-before-the-base-url"),
    # (ii) a `VerifiablePresentation` among the types: presented, the gate refuses it (a `type`
    # sub-claim is no disclosure refusal); withheld, the type is [VerifiableCredential]
    pytest.param(_w3c([V2], ["VerifiableCredential", "VerifiablePresentation"]), "type", 1,
                 "withheld", "type", id="presentation-type-entry"),
    # (iii) the `VerifiableCredential` entry itself: presented, it conforms; withheld, the
    # types are [ExampleAlumniCredential] and the gate refuses that
    pytest.param(_w3c([V2], ["VerifiableCredential", "ExampleAlumniCredential"]), "type", 0,
                 "presented", "type", id="credential-type-entry"),
]
FLIP = pytest.mark.parametrize("payload, claim, index, accepted, refusal", FLIPS)
SUB_CLAIM = ("a sub-claim of '@context' is selectively disclosed "
             "(openvc enforces it on SD-JWT)")


def _refused_side(excinfo, refusal, typ):
    assert excinfo.type is SdJwtError
    if refusal == "disclosure":
        assert str(excinfo.value).startswith(SUB_CLAIM)
    else:
        assert str(excinfo.value) == _says("type", typ)


@TYP
@FLIP
def test_array_element_disclosure_documented_limit_the_verdict_follows_the_presentation(
        run, typ, payload, claim, index, accepted, refusal):
    presented, withheld = _mint_elements(payload, claim, index, typ=typ)
    sides = {"presented": presented, "withheld": withheld}
    other = "presented" if accepted == "withheld" else "withheld"
    result = run(sides[accepted], None)
    assert result.raw.vcdm is True
    assert result.raw.typ == (None if typ is ABSENT else typ)
    kept = [entry for i, entry in enumerate(payload[claim])
            if accepted == "presented" or i != index]
    assert result.credential[claim] == kept
    with pytest.raises(SdJwtError) as excinfo:
        run(sides[other], None)
    _refused_side(excinfo, refusal, typ)


@TYP
@FLIP
def test_array_element_disclosure_documented_limit_the_accepted_side_still_has_the_window(
        run, typ, payload, claim, index, accepted, refusal):
    # `vcdm` stays True on the side that verifies, so the window and the consistency checks
    # run on it as on any other W3C credential: the holder's choice of what to present does
    # not switch them off.
    def side(**extra):
        presented, withheld = _mint_elements({**payload, **extra}, claim, index, typ=typ)
        return presented if accepted == "presented" else withheld

    with pytest.raises(CredentialExpired) as excinfo:
        run(side(validUntil=PAST), None)
    assert excinfo.type is CredentialExpired
    with pytest.raises(CredentialNotYetValid) as excinfo:
        run(side(validFrom=FUTURE), None)
    assert excinfo.type is CredentialNotYetValid
    with pytest.raises(ClaimsInvalid, match="issuer") as excinfo:
        run(side(issuer="did:web:university.example"), None)
    assert excinfo.type is ClaimsInvalid
    result = run(side(validUntil=PAST), VerificationPolicy(require_not_expired=False))
    assert result.expired is True
    assert result.raw.vcdm is True


@TYP
@FLIP
def test_array_element_disclosure_documented_limit_the_refused_side_stays_refused_waived(
        run, typ, payload, claim, index, accepted, refusal):
    # The waiver of the expiry does not turn the refused presentation into an accepted one.
    presented, withheld = _mint_elements({**payload, "validUntil": PAST}, claim, index, typ=typ)
    refused = withheld if accepted == "presented" else presented
    with pytest.raises(SdJwtError) as excinfo:
        run(refused, VerificationPolicy(require_not_expired=False))
    _refused_side(excinfo, refusal, typ)


# --------------------------------------------------------------------------- #
# L. the gate comes before the window, with no policy as with the waiver; verify_many
# --------------------------------------------------------------------------- #

@TYP
@pytest.mark.parametrize("window, window_error", [
    pytest.param({"validUntil": PAST}, CredentialExpired, id="expired"),
    pytest.param({"validFrom": FUTURE}, CredentialNotYetValid, id="not-yet-valid"),
])
@pytest.mark.parametrize("policy", [None, VerificationPolicy(require_not_expired=False)],
                         ids=["no-policy", "expiry-waived"])
@pytest.mark.parametrize("context, declared, requirement", [
    pytest.param([EXTRA, V2], CREDENTIAL, "first", id="base-second"),
    pytest.param([V2], ["VerifiablePresentation"], "type", id="presentation-type"),
    pytest.param([V2], ABSENT, "type", id="no-type"),
])
def test_a_non_conforming_token_is_refused_by_the_gate_before_its_window_is_read(
        run, typ, window, window_error, policy, context, declared, requirement):
    # Gate first: the verdict is SdJwtError, never CredentialExpired / CredentialNotYetValid,
    # whether or not the expiry is waived (the waiver covers the expiry only, so a window
    # that is not yet open would otherwise be the first thing said).
    with pytest.raises(SdJwtError) as excinfo:
        run(_mint(_w3c(context, declared, **window), typ=typ), policy)
    assert excinfo.type is SdJwtError
    assert str(excinfo.value) == _says(requirement, typ)
    # and the window really is there to be read: the conforming twin meets it
    with pytest.raises(window_error) as excinfo:
        run(_mint(_good(**window), typ=typ), None)
    assert excinfo.type is window_error


@TYP
def test_verify_many_gives_a_verdict_per_item_when_the_first_context_entry_is_not_a_string(typ):
    # An object (or an array) in first place is unhashable: it must reach the gate as a typed
    # refusal of that one item, not as a bare TypeError that aborts the batch.
    good = _mint(_good(), typ=typ)
    for context in ([VOCAB, V2], [[V2], V2], [{"id": V2}, V2]):
        bad = _mint(_w3c(context, CREDENTIAL), typ=typ)
        presentation = _mint(_w3c([V2], ["VerifiablePresentation"]), typ=typ)
        batch = [bad, good, presentation, good]
        for results in (verify_many(batch), asyncio.run(verify_many_async(batch))):
            assert [r.index for r in results] == [0, 1, 2, 3]
            assert type(results[0].error) is SdJwtError
            assert str(results[0].error) == _says("first", typ)
            assert results[1].ok
            assert type(results[2].error) is SdJwtError
            assert str(results[2].error) == _says("type", typ)
            assert results[3].ok
            assert results[1].result.raw.vcdm is True
