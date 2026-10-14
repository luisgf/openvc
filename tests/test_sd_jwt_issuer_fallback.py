"""
tests/test_sd_jwt_issuer_fallback.py — an SD-JWT-secured W3C credential names its issuer in
the VCDM ``issuer`` property when its issuer JWT has no ``iss`` (#290).

W3C VC-JOSE-COSE (Recommendation of 13 October 2026, https://www.w3.org/TR/vc-jose-cose/)
makes the JOSE ``iss`` claim optional: §4.1.2 says that when ``iss`` is present it MUST match
the VCDM ``issuer``, and §4.2 that when it is absent the issuer is identified by ``issuer``
and the ``kid`` is an absolute URL. The Recommendation's own SD-JWT credential (Examples 4
and 5) has an ``issuer`` and no ``iss``. openvc selected the issuer key from ``iss`` only, so
the Recommendation's own example could not verify. What ``SdJwtVcProofSuite`` does now, for
an issuer JWT whose ``typ`` is a W3C state (absent, ``vc+sd-jwt`` or the draft-era
``vc+ld+json+sd-jwt``) and whose BODY has no ``iss`` member at all:

* **The issuer is the body's ``issuer``**: a non-empty string, or an object whose ``id`` /
  ``@id`` members that are present are all the same non-empty string. ``peek_issuer`` returns
  it (that is what selects the key), ``verify`` reports it as ``VerifiedSdJwt.issuer`` and
  reconciles the credential against it as if it had been ``iss``.
* **Body only.** An ``issuer`` inside a disclosure is never used (the token is refused as
  before, and one that names ``issuer`` both in the body and in a disclosure is refused as a
  claim overwrite).
* **Only when ``iss`` is ABSENT.** A present ``iss`` that is null, empty, a number, an array
  or an object is still refused, with no fallback to ``issuer`` (``verify`` refuses an empty
  one too, as ``peek_issuer`` always did); one that is present and valid is unchanged (a
  different ``issuer`` is a ``ClaimsInvalid``).
* **Only for a ``typ`` that is a W3C state.** A header ``"typ": null`` is a PRESENT ``typ``, so
  it is not one: ``peek_issuer`` does not fall back for it (and nothing is resolved), and
  ``verify`` refuses it as an unexpected ``typ``.
* **``dc+sd-jwt`` keeps requiring ``iss``**, with the old messages.
* **The refusal names the fallback only when it was available.** The clause ``(and no usable
  VCDM `issuer` for a W3C credential)`` ends the two "no usable issuer" sentences exactly
  when ``iss`` is absent from the body and the ``typ`` is a W3C state; a present-but-invalid
  ``iss``, a ``dc+sd-jwt`` and any other ``typ`` get the bare old sentence.
* **No new key-resolution path**: the same DID / https ``jwt-vc-issuer`` / ``x5c`` resolution
  runs on the identifier, exactly once.

Section order: A accepts, B refuses (the shapes of ``iss`` and ``issuer``), C is ``dc+sd-jwt``,
D is body-only, E is the Recommendation's own tokens (tests/fixtures/vc_jose_cose/), F is key
resolution, G is the ``typ`` guards, H is what still runs on a fallback token (the status
issuer binding, the window, the consistency and conformance gates, the reconciliation of a
partly disclosed issuer, the disclosed ``sub`` / ``jti``, the key-bound suite path), I is
OpenID4VP. Messages are asserted whole (``\\A..\\Z``) wherever the clause is the point.

Helpers are self-contained (tests/ is not a package — no cross-import); issuers are
``did:jwk`` resolved offline by the default resolvers, ``did:example`` identifiers resolved by
a static resolver, or https URLs resolved by a stubbed ``jwt_vc_issuer_fetch``; signatures
are real P-256 (P-384 for Example 21); ``asyncio.run`` drives the async pipeline
(pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import re
import secrets
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_vp_token,
)
from openvc.did.base import DidResolutionError, parse_did_document
from openvc.keys import P256SigningKey, P384SigningKey
from openvc.multibase import encode_multibase
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
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.status import CredentialRevoked, encode_bitstring, set_status_bit
from openvc.verify import KeyResolutionFailed, StatusListIssuerUntrusted, TypeMismatch

V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"
EXAMPLES_V2 = "https://www.w3.org/ns/credentials/examples/v2"
PAST = "2021-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
DRAFT_TYP = "vc+ld+json+sd-jwt"         # Example 21 of VC-JOSE-COSE: a 2023 draft's media type
VCT = "https://credentials.example/membership"
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"
ABSENT = object()                       # a header / payload member that is not written at all

# What the code says. The two "no usable issuer" sentences keep their old text and gain the
# clause exactly when the fallback was available (no `iss` member in the body, a W3C `typ`
# state) and found nothing usable: it is absent for a dc+sd-jwt, for any other `typ` (a null
# one included) and for a present-but-invalid `iss`, where `issuer` was never going to be read.
NO_ISS_TO_PEEK = "no iss in the issuer-signed JWT"             # MalformedToken (peek_issuer)
NO_ISS_CLAIM = "iss claim is missing or not a string"          # ClaimsInvalid (verify)
NO_ISSUER_CLAUSE = " (and no usable VCDM `issuer` for a W3C credential)"
UNEXPECTED_TYP = "unexpected issuer JWT typ"
OVERWRITE = "disclosure would overwrite claim 'issuer'"
ISS_DISCLOSED = "claim 'iss' is selectively disclosed"
ISS_MISMATCH = r"iss '[^']*' != issuer "


def _only(text):
    """A pattern that matches *text* and nothing else (the whole message, no extras)."""
    return rf"\A{re.escape(text)}\Z"


# The four whole messages: the clause is present or it is not, nothing in between.
PEEK_BARE = _only(NO_ISS_TO_PEEK)
PEEK_CLAUSE = _only(NO_ISS_TO_PEEK + NO_ISSUER_CLAUSE)
VERIFY_BARE = _only(NO_ISS_CLAIM)
VERIFY_CLAUSE = _only(NO_ISS_CLAIM + NO_ISSUER_CLAUSE)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _party():
    key = P256SigningKey.generate(kid="k")
    return key, "did:jwk:" + _b64(json.dumps(key.public_jwk()).encode())


KEY, DID = _party()
OTHER_KEY, OTHER_DID = _party()
KID = f"{DID}#0"


def _salt() -> str:
    return _b64(secrets.token_bytes(16))


def _mint(payload, *, typ=ABSENT, key=KEY, kid=ABSENT, header=None, disclose=(),
          disclose_in=(), also_disclose=()):
    """Issue an SD-JWT by hand — ``SdJwtVcProofSuite.issue`` always writes ``dc+sd-jwt``,
    requires a ``vct`` and an ``iss``. *typ*: ``ABSENT`` (default) writes no ``typ`` member,
    ``None`` writes ``"typ": null``, anything else is written as is. *kid*: ``ABSENT`` writes
    this file's DID as the key id, ``None`` writes none. *header* adds members to the header.
    *disclose* moves those top-level claims into disclosures (all of them presented);
    *disclose_in*, pairs ``(claim, name)``, does the same to the member *name* of the
    top-level object *claim*; *also_disclose*, pairs ``(name, value)``, adds a disclosure of a
    claim the body ALSO carries (or does not) without moving anything."""
    body = dict(payload)
    disclosures: list[str] = []
    digests: list[str] = []
    for name in disclose:
        disclosures.append(make_object_disclosure(_salt(), name, body.pop(name)))
    digests.extend(disclosure_digest(d) for d in disclosures)
    for name, value in also_disclose:
        disclosure = make_object_disclosure(_salt(), name, value)
        disclosures.append(disclosure)
        digests.append(disclosure_digest(disclosure))
    for claim, name in disclose_in:
        inner = dict(body[claim])
        disclosure = make_object_disclosure(_salt(), name, inner.pop(name))
        inner["_sd"] = [disclosure_digest(disclosure)]
        body[claim] = inner
        disclosures.append(disclosure)
    if digests:
        body["_sd"] = sorted(digests)
    if disclosures:
        body["_sd_alg"] = "sha-256"
    head: dict = {"alg": "ES256"}
    if kid is not None:
        head["kid"] = KID if kid is ABSENT else kid
    if typ is not ABSENT:
        head["typ"] = typ
    head.update(header or {})
    signing_input = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(body).encode())}"
    jws = f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _decode(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _header(sd_jwt):
    return _decode(sd_jwt.split(".")[0])


def _payload(sd_jwt):
    return _decode(sd_jwt.split(".")[1])


def _presented_without_disclosures(sd_jwt):
    """The issuer JWT alone: every disclosure withheld."""
    return sd_jwt.split("~", 1)[0] + "~"


def _without(sd_jwt, name):
    """The presentation with the disclosure of top-level claim *name* withheld."""
    issuer_jwt, *rest = sd_jwt.split("~")
    kept = [d for d in rest[:-1]
            if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] != name]
    assert len(kept) == len(rest) - 2, f"no disclosure for {name!r}"
    return issuer_jwt + "~" + "".join(d + "~" for d in kept)


def _cred(issuer=DID, **extra):
    """A conforming VCDM 2.0 payload (the v2 context first, a credential `type`) with NO
    ``iss``: *issuer* is written as given, or not at all when it is ``ABSENT``."""
    doc = {
        "@context": [V2, EXAMPLES_V2],
        "id": "urn:uuid:5e1d6a3c-cred",
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:alice", "alumniOf": "Example University"},
    }
    if issuer is not ABSENT:
        doc["issuer"] = issuer
    doc.update(extra)
    return doc


def _with_iss(iss, **kwargs):
    """The same payload with an ``iss`` member written as given."""
    return {**_cred(**kwargs), "iss": iss}


def _ietf(**extra):
    """An IETF SD-JWT VC payload: a ``vct`` and a claim that happens to be called ``issuer``."""
    claims = {"vct": VCT, "member_name": "Ada", "issuer": DID}
    claims.update(extra)
    return claims


# --------------------------------------------------------------------------- #
# the harness: a static resolver, three pipelines, two forms
# --------------------------------------------------------------------------- #

class Reg:
    """A static resolver of identifiers (``did:example`` style, no DID method behind them)
    to JWKs, which records every identifier that reaches it."""

    def __init__(self, mapping):
        self.mapping = dict(mapping)
        self.resolved: list[str] = []

    def supports(self, did):
        return True

    def resolve(self, did):
        self.resolved.append(did)
        jwk = self.mapping.get(did)
        if jwk is None:
            raise DidResolutionError(f"unknown identifier {did!r}")
        return parse_did_document({
            "id": did,
            "verificationMethod": [{"id": f"{did}#0", "type": "JsonWebKey2020",
                                    "controller": did, "publicKeyJwk": jwk}]})


class _AsyncView:
    """The async pipeline's view of a :class:`Reg` (same record)."""

    def __init__(self, reg):
        self._reg = reg

    def supports(self, did):
        return self._reg.supports(did)

    async def resolve(self, did):
        return self._reg.resolve(did)


def _as_async(fn):
    async def run(arg):
        return fn(arg)
    return run


def _via_sync(credential, *, reg=None, fetch=None, **kwargs):
    return verify_credential(credential, resolver=reg, jwt_vc_issuer_fetch=fetch, **kwargs)


def _via_async(credential, *, reg=None, fetch=None, **kwargs):
    if "resolve_status_list" in kwargs:
        kwargs["resolve_status_list"] = _as_async(kwargs["resolve_status_list"])
    return asyncio.run(verify_credential_async(
        credential, resolver=None if reg is None else _AsyncView(reg),
        jwt_vc_issuer_fetch=None if fetch is None else _as_async(fetch), **kwargs))


def _via_many(credential, *, reg=None, fetch=None, **kwargs):
    (item,) = verify_many([credential], resolver=reg, jwt_vc_issuer_fetch=fetch, **kwargs)
    if item.error is not None:
        raise item.error
    return item.result


PIPELINES = {"sync": _via_sync, "async": _via_async, "many": _via_many}


def _envelope(sd_jwt, media="application/vc+sd-jwt"):
    return {"@context": [V2], "id": f"data:{media},{sd_jwt}",
            "type": ["EnvelopedVerifiableCredential"]}


FORMS = {"bare": lambda sd_jwt: sd_jwt, "enveloped": _envelope}


@pytest.fixture(params=sorted(PIPELINES))
def call(request):
    return PIPELINES[request.param]


@pytest.fixture(params=sorted(FORMS))
def form(request):
    return FORMS[request.param]


def _refused(call_, credential, cls, match, **kwargs):
    """*call_* raises exactly *cls* (not a subclass) whose message matches *match*."""
    with pytest.raises(cls, match=match) as excinfo:
        call_(credential, **kwargs)
    assert excinfo.type is cls
    return excinfo.value


def _peek_refused(sd_jwt, cls, match):
    with pytest.raises(cls, match=match) as excinfo:
        SdJwtVcProofSuite().peek_issuer(sd_jwt)
    assert excinfo.type is cls


def _verify_refused(sd_jwt, cls, match, *, key=KEY, **kwargs):
    with pytest.raises(cls, match=match) as excinfo:
        SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=key.public_jwk(), **kwargs)
    assert excinfo.type is cls


def _suite_verify(sd_jwt, *, key=KEY, **kwargs):
    return SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=key.public_jwk(), **kwargs)


# The typ states of a W3C credential: no typ member, the registered name, the draft-era one.
W3C_TYPS = pytest.mark.parametrize("typ", [ABSENT, "vc+sd-jwt", DRAFT_TYP],
                                   ids=["no-typ", "vc-sd-jwt", "draft-typ"])


def _typ_of(typ):
    return None if typ is ABSENT else typ


# What `issuer` can look like when it names DID: the string and every object that names it.
ISSUER_SHAPES = pytest.mark.parametrize("shape", [
    pytest.param(lambda did: did, id="string"),
    pytest.param(lambda did: {"id": did}, id="object-id"),
    pytest.param(lambda did: {"@id": did}, id="object-at-id"),
    pytest.param(lambda did: {"id": did, "@id": did}, id="object-id-and-at-id"),
    pytest.param(lambda did: {"id": did, "name": "Example University"}, id="object-id-and-name"),
])


# --------------------------------------------------------------------------- #
# A. accepted: no iss, a usable issuer, a W3C typ
# --------------------------------------------------------------------------- #

@W3C_TYPS
@ISSUER_SHAPES
def test_a_w3c_sd_jwt_with_no_iss_verifies_under_the_key_of_its_issuer(call, form, typ, shape):
    issuer = shape(DID)
    token = _mint(_cred(issuer=issuer), typ=typ)
    assert "iss" not in _payload(token)
    result = call(form(token))
    assert result.format == "sd-jwt-vc"
    assert result.issuer == DID
    assert result.raw.issuer == DID
    assert result.raw.vcdm is True
    assert result.raw.typ == _typ_of(typ)
    assert result.claims["issuer"] == issuer              # the claim set is what was signed
    assert "iss" not in result.claims
    assert result.expired is False


@W3C_TYPS
@ISSUER_SHAPES
def test_the_suite_peeks_and_verifies_the_vcdm_issuer_when_there_is_no_iss(typ, shape):
    token = _mint(_cred(issuer=shape(DID)), typ=typ)
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)
    result = _suite_verify(token)
    assert result.issuer == DID
    assert result.vcdm is True
    assert result.typ == _typ_of(typ)


@W3C_TYPS
def test_the_signature_must_be_under_the_key_resolved_for_the_issuer(call, form, typ):
    # The holder of OTHER_KEY names DID as the issuer and signs with its own key: the key that
    # is resolved is DID's, so this is a bad signature, not an issuer substitution.
    token = _mint(_cred(issuer=DID), typ=typ, key=OTHER_KEY)
    _refused(call, form(token), SignatureInvalid, ".")
    _verify_refused(token, SignatureInvalid, ".")
    # ... and the same token checked against its signer's own key shows it is well formed
    assert _suite_verify(token, key=OTHER_KEY).issuer == DID


@W3C_TYPS
def test_a_kid_of_another_did_does_not_change_which_issuer_is_resolved(call, typ):
    # The key is resolved for the issuer the credential names, never for the kid's DID.
    token = _mint(_cred(issuer=DID), typ=typ, key=OTHER_KEY, kid=f"{OTHER_DID}#0")
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, f"{OTHER_DID}#0")
    _refused(call, token, SignatureInvalid, ".")


@W3C_TYPS
def test_an_iss_equal_to_the_issuer_is_unchanged(call, form, typ):
    for issuer in (DID, {"id": DID}, {"@id": DID}, {"id": DID, "@id": DID}):
        result = call(form(_mint(_with_iss(DID, issuer=issuer), typ=typ)))
        assert result.issuer == DID
        assert result.claims["iss"] == DID
    assert SdJwtVcProofSuite().peek_issuer(_mint(_with_iss(DID), typ=typ)) == (DID, KID)


@W3C_TYPS
def test_an_iss_next_to_an_issuer_that_names_no_one_is_unchanged(call, form, typ):
    # The VCDM 1.1 JWT encoding moves the issuer's id to `iss`: what is left names no one.
    for issuer in (ABSENT, {"name": "Example University"}, {}):
        result = call(form(_mint(_with_iss(DID, issuer=issuer), typ=typ)))
        assert result.issuer == DID


# --------------------------------------------------------------------------- #
# B. refused
# --------------------------------------------------------------------------- #

# An `issuer` that names no one usable. ABSENT is the member missing altogether.
NO_USABLE_ISSUER = [
    pytest.param(ABSENT, id="absent"),
    pytest.param(None, id="null"),
    pytest.param("", id="empty-string"),
    pytest.param(0, id="zero"),
    pytest.param(5, id="number"),
    pytest.param(False, id="false"),
    pytest.param(True, id="true"),
    pytest.param([], id="empty-array"),
    pytest.param([DID], id="array-of-the-did"),
    pytest.param([{"id": DID}], id="array-of-an-object"),
    pytest.param({}, id="empty-object"),
    pytest.param({"name": "Example University"}, id="object-with-no-id"),
    pytest.param({"id": ""}, id="id-empty-string"),
    pytest.param({"@id": ""}, id="at-id-empty-string"),
    pytest.param({"id": "", "@id": ""}, id="both-empty-strings"),
    pytest.param({"id": DID, "@id": ""}, id="id-and-an-empty-at-id"),
    pytest.param({"id": "", "@id": DID}, id="empty-id-and-an-at-id"),
    pytest.param({"id": 5}, id="id-number"),
    pytest.param({"id": True}, id="id-true"),
    pytest.param({"id": [DID]}, id="id-array"),
    pytest.param({"id": {"id": DID}}, id="id-object"),
    pytest.param({"id": None}, id="id-null"),
    pytest.param({"@id": None}, id="at-id-null"),
    pytest.param({"@id": 5}, id="at-id-number"),
    pytest.param({"id": DID, "@id": None}, id="id-and-a-null-at-id"),
    pytest.param({"id": DID, "@id": 5}, id="id-and-a-numeric-at-id"),
    pytest.param({"id": [DID], "@id": [DID]}, id="two-arrays"),
    pytest.param({"id": DID, "@id": OTHER_DID}, id="disagreeing"),
    pytest.param({"id": OTHER_DID, "@id": DID}, id="disagreeing-reversed"),
]


@W3C_TYPS
@pytest.mark.parametrize("issuer", NO_USABLE_ISSUER)
def test_an_issuer_that_names_no_one_usable_leaves_nothing_to_select_a_key_with(
        call, typ, issuer):
    # The pipeline cannot select a key: peek_issuer refuses, whatever the entry point.
    token = _mint(_cred(issuer=issuer), typ=typ)
    assert "iss" not in _payload(token)
    _refused(call, token, MalformedToken, PEEK_CLAUSE)


@W3C_TYPS
@pytest.mark.parametrize("issuer", NO_USABLE_ISSUER)
def test_the_suite_refuses_an_issuer_that_names_no_one_usable_at_both_entry_points(
        typ, issuer):
    # peek_issuer: the MalformedToken the pipeline raises. verify(), called directly with a
    # key and reached only after the signature: the ClaimsInvalid. Neither falls back to
    # anything, an empty string included (it is a str, so only the non-empty test refuses it).
    token = _mint(_cred(issuer=issuer), typ=typ)
    _peek_refused(token, MalformedToken, PEEK_CLAUSE)
    _verify_refused(token, ClaimsInvalid, VERIFY_CLAUSE)


# Whether the refusal carries the clause, case by case: (typ, `iss` member, `issuer` member,
# clause). The clause is for the one situation where the fallback WAS available and found
# nothing usable: no `iss` member in the body and a typ that is absent or W3C.
CLAUSE_SCOPE = [
    pytest.param(ABSENT, ABSENT, ABSENT, True, id="no-typ-no-iss-no-issuer"),
    pytest.param(ABSENT, ABSENT, "", True, id="no-typ-no-iss-empty-issuer"),
    pytest.param("vc+sd-jwt", ABSENT, {"name": "x"}, True, id="vc-sd-jwt-no-iss-nameless-issuer"),
    pytest.param(DRAFT_TYP, ABSENT, {}, True, id="draft-typ-no-iss-empty-object"),
    pytest.param(DRAFT_TYP, ABSENT, ABSENT, True, id="draft-typ-no-iss-no-issuer"),
    pytest.param("dc+sd-jwt", ABSENT, DID, False, id="dc-sd-jwt-no-iss-usable-issuer"),
    pytest.param("dc+sd-jwt", ABSENT, ABSENT, False, id="dc-sd-jwt-no-iss-no-issuer"),
    pytest.param(ABSENT, None, DID, False, id="no-typ-null-iss-usable-issuer"),
    pytest.param(ABSENT, "", DID, False, id="no-typ-empty-iss-usable-issuer"),
    pytest.param("vc+sd-jwt", 0, DID, False, id="vc-sd-jwt-zero-iss-usable-issuer"),
    pytest.param("vc+sd-jwt", False, ABSENT, False, id="vc-sd-jwt-false-iss-no-issuer"),
    pytest.param(DRAFT_TYP, [], DID, False, id="draft-typ-array-iss-usable-issuer"),
    pytest.param(DRAFT_TYP, {}, DID, False, id="draft-typ-object-iss-usable-issuer"),
    pytest.param(DRAFT_TYP, "", ABSENT, False, id="draft-typ-empty-iss-no-issuer"),
]


@pytest.mark.parametrize("typ, iss, issuer, clause", CLAUSE_SCOPE)
def test_the_clause_is_there_exactly_when_the_fallback_was_available(typ, iss, issuer, clause):
    payload = _cred(issuer=issuer)
    if typ == "dc+sd-jwt":
        payload["vct"] = VCT
    if iss is not ABSENT:
        payload["iss"] = iss
    token = _mint(payload, typ=typ)
    # a clause-bearing sentence is the bare one plus the clause: nothing else differs
    _peek_refused(token, MalformedToken, PEEK_CLAUSE if clause else PEEK_BARE)
    _verify_refused(token, ClaimsInvalid, VERIFY_CLAUSE if clause else VERIFY_BARE)


# A present `iss` that is no usable string, next to a perfectly good `issuer`.
INVALID_ISS = [
    pytest.param(None, id="null"),
    pytest.param("", id="empty-string"),
    pytest.param(0, id="zero"),
    pytest.param(5, id="number"),
    pytest.param(False, id="false"),
    pytest.param(True, id="true"),
    pytest.param([], id="empty-array"),
    pytest.param([DID], id="array"),
    pytest.param({}, id="empty-object"),
    pytest.param({"id": DID}, id="object"),
]


@W3C_TYPS
@pytest.mark.parametrize("iss", INVALID_ISS)
def test_a_present_but_invalid_iss_is_refused_with_no_fallback_to_issuer(call, typ, iss):
    token = _mint(_with_iss(iss, issuer=DID), typ=typ)
    # The sentences are the old ones, whole: the clause says "no usable issuer", which is
    # not what happened here (the issuer is fine, it is just not allowed to stand in), and the
    # fallback was never available because `iss` is there. An empty `iss` is no different:
    # peek_issuer always refused it, and verify() now refuses it as it does the rest instead
    # of returning '' as the issuer or leaving it to the reconciliation.
    _refused(call, token, MalformedToken, PEEK_BARE)
    _peek_refused(token, MalformedToken, PEEK_BARE)
    _verify_refused(token, ClaimsInvalid, VERIFY_BARE)


@W3C_TYPS
@pytest.mark.parametrize("iss", INVALID_ISS)
def test_a_present_but_invalid_iss_is_refused_even_when_the_issuer_is_an_object(typ, iss):
    token = _mint(_with_iss(iss, issuer={"id": DID}), typ=typ)
    _peek_refused(token, MalformedToken, PEEK_BARE)
    _verify_refused(token, ClaimsInvalid, VERIFY_BARE)


@W3C_TYPS
@pytest.mark.parametrize("issuer", [ABSENT, "", {}, {"name": "x"}],
                         ids=["no-issuer", "empty-issuer", "empty-object", "object-with-no-id"])
def test_verify_refuses_an_empty_iss_when_there_is_no_usable_issuer_either(typ, issuer):
    # verify() called directly. An empty `iss` is a str, so it used to be returned as the
    # issuer '' (and reconciled against nothing when `issuer` names no one): a verified
    # credential from the issuer ''. It is refused now, with the bare sentence because `iss`
    # is present and so the fallback was never available.
    token = _mint(_with_iss("", issuer=issuer), typ=typ)
    assert _payload(token)["iss"] == ""
    _verify_refused(token, ClaimsInvalid, VERIFY_BARE)
    _peek_refused(token, MalformedToken, PEEK_BARE)


def test_verify_refuses_an_empty_iss_of_a_dc_sd_jwt():
    token = _mint({**_ietf(), "iss": ""}, typ="dc+sd-jwt")
    _verify_refused(token, ClaimsInvalid, VERIFY_BARE)
    _peek_refused(token, MalformedToken, PEEK_BARE)
    for payload in (_ietf(iss=None), _ietf(iss=0), _ietf(iss=[]), _ietf(iss={"id": DID})):
        _verify_refused(_mint(payload, typ="dc+sd-jwt"), ClaimsInvalid, VERIFY_BARE)


@W3C_TYPS
@pytest.mark.parametrize("issuer", [
    pytest.param(OTHER_DID, id="string"),
    pytest.param({"id": OTHER_DID}, id="object-id"),
    pytest.param({"@id": OTHER_DID}, id="object-at-id"),
    pytest.param({"id": DID, "@id": OTHER_DID}, id="object-one-member-differs"),
    pytest.param({"id": OTHER_DID, "@id": DID}, id="object-the-other-member-differs"),
])
def test_an_iss_that_differs_from_the_issuer_is_a_conflict_as_before(call, form, typ, issuer):
    token = _mint(_with_iss(DID, issuer=issuer), typ=typ)
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)       # `iss` selects the key
    _refused(call, form(token), ClaimsInvalid, ISS_MISMATCH)
    _verify_refused(token, ClaimsInvalid, ISS_MISMATCH)


@W3C_TYPS
def test_an_attacker_cannot_name_a_victim_as_the_issuer_and_sign_for_itself(call, form, typ):
    # `iss` names the attacker (so the attacker's key is the one resolved), `issuer` the
    # victim: the conflict. Dropping `iss` does not help either: the victim's key is resolved.
    attacker_key, attacker = OTHER_KEY, OTHER_DID
    with_iss = _mint(_with_iss(attacker, issuer=DID), typ=typ, key=attacker_key,
                     kid=f"{attacker}#0")
    _refused(call, form(with_iss), ClaimsInvalid, ISS_MISMATCH)
    without_iss = _mint(_cred(issuer=DID), typ=typ, key=attacker_key, kid=f"{attacker}#0")
    _refused(call, form(without_iss), SignatureInvalid, ".")


# --------------------------------------------------------------------------- #
# C. dc+sd-jwt is unchanged: it requires iss
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload", [
    pytest.param({"vct": VCT, "member_name": "Ada"}, id="ietf-claims-no-issuer-at-all"),
    pytest.param(_ietf(), id="ietf-claims-with-an-issuer-claim"),
    pytest.param(_cred(vct=VCT), id="vcdm-with-a-vct"),
    pytest.param(_cred(vct=VCT, issuer={"id": DID}), id="vcdm-with-an-issuer-object"),
    pytest.param(_cred(vct=VCT, issuer=ABSENT), id="vcdm-with-a-vct-and-no-issuer"),
])
def test_a_dc_sd_jwt_with_no_iss_is_refused_with_the_old_messages(call, payload):
    token = _mint(payload, typ="dc+sd-jwt")
    assert "iss" not in _payload(token)
    # the old text, exactly: no clause about a VCDM issuer for a typ that never had one
    _refused(call, token, MalformedToken, rf"\A{re.escape(NO_ISS_TO_PEEK)}\Z")
    _peek_refused(token, MalformedToken, rf"\A{re.escape(NO_ISS_TO_PEEK)}\Z")
    _verify_refused(token, ClaimsInvalid, rf"\A{re.escape(NO_ISS_CLAIM)}\Z")


@pytest.mark.parametrize("payload", [
    pytest.param(_ietf(), id="ietf-claims-with-an-issuer-claim"),
    pytest.param(_cred(vct=VCT), id="vcdm-with-a-vct"),
])
def test_a_dc_sd_jwt_with_a_normal_iss_is_unchanged(call, form, payload):
    token = _mint({**payload, "iss": DID}, typ="dc+sd-jwt")
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)
    result = call(form(token))
    assert result.issuer == DID
    assert result.raw.typ == "dc+sd-jwt"
    assert result.raw.vct == VCT


def test_a_dc_sd_jwt_claim_called_issuer_is_still_not_reconciled_with_iss(call, form):
    # An IETF SD-JWT VC's `issuer` is its own vocabulary: `iss` alone is the issuer.
    token = _mint({**_ietf(issuer=OTHER_DID), "iss": DID}, typ="dc+sd-jwt")
    assert call(form(token)).issuer == DID


# --------------------------------------------------------------------------- #
# D. body only
# --------------------------------------------------------------------------- #

@W3C_TYPS
def test_an_issuer_that_sits_in_a_disclosure_is_never_the_issuer(call, typ):
    token = _mint(_cred(issuer=DID), typ=typ, disclose=["issuer"])
    assert "issuer" not in _payload(token) and "iss" not in _payload(token)
    _refused(call, token, MalformedToken, PEEK_CLAUSE)
    _peek_refused(token, MalformedToken, PEEK_CLAUSE)
    # verify() called directly, with the right key and every disclosure presented: the
    # presented disclosure is not read for the issuer either
    _verify_refused(token, ClaimsInvalid, VERIFY_CLAUSE)


@W3C_TYPS
@pytest.mark.parametrize("claim", ["id", "@id"])
def test_an_issuer_id_that_sits_in_a_disclosure_is_never_the_issuer(call, typ, claim):
    token = _mint(_cred(issuer={claim: DID, "name": "Example University"}), typ=typ,
                  disclose_in=[("issuer", claim)])
    assert claim not in _payload(token)["issuer"]
    _refused(call, token, MalformedToken, PEEK_CLAUSE)
    _verify_refused(token, ClaimsInvalid, VERIFY_CLAUSE)


@W3C_TYPS
def test_a_disclosure_naming_issuer_again_is_refused_as_an_overwrite(call, typ):
    # The body names DID; a disclosure names OTHER_DID. The key is selected from the body
    # (peek), the signature is DID's, and the disclosure cannot replace the claim.
    token = _mint(_cred(issuer=DID), typ=typ, also_disclose=[("issuer", OTHER_DID)])
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)
    _refused(call, token, SdJwtError, re.escape(OVERWRITE))
    _verify_refused(token, SdJwtError, re.escape(OVERWRITE))


@W3C_TYPS
def test_a_disclosure_naming_the_same_issuer_again_is_still_an_overwrite(call, typ):
    token = _mint(_cred(issuer=DID), typ=typ, also_disclose=[("issuer", DID)])
    _refused(call, token, SdJwtError, re.escape(OVERWRITE))


@W3C_TYPS
def test_a_presented_iss_disclosure_does_not_stand_in_for_the_issuer(call, typ):
    # The body names DID and has no `iss`; a disclosure carries an `iss`. The key is DID's,
    # the signature verifies, and the presented disclosure of `iss` is refused as such.
    token = _mint(_cred(issuer=DID), typ=typ, also_disclose=[("iss", OTHER_DID)])
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)
    _refused(call, token, SdJwtError, re.escape(ISS_DISCLOSED))
    _verify_refused(token, SdJwtError, re.escape(ISS_DISCLOSED))


@W3C_TYPS
def test_a_withheld_iss_disclosure_leaves_the_body_issuer_as_the_issuer(call, typ):
    token = _mint(_cred(issuer=DID), typ=typ, also_disclose=[("iss", OTHER_DID)])
    result = call(_presented_without_disclosures(token))
    assert result.issuer == DID
    assert "iss" not in result.claims


@W3C_TYPS
def test_disclosures_elsewhere_in_the_credential_do_not_disturb_the_fallback(call, form, typ):
    token = _mint(_cred(issuer={"id": DID, "name": "Example University"}), typ=typ,
                  disclose_in=[("issuer", "name")])
    result = call(form(token))
    assert result.issuer == DID
    assert result.claims["issuer"] == {"id": DID, "name": "Example University"}


# --------------------------------------------------------------------------- #
# E. the Recommendation's own tokens
# --------------------------------------------------------------------------- #

# Provenance (the same two tokens as tests/test_sd_jwt_vcdm_typ_interop.py, section I): both
# are copied from https://www.w3.org/TR/vc-jose-cose/ . Example 5 (section 3.2.2) has the
# header {kid, alg: ES256}, NO typ, and a payload with `issuer` and NO `iss`. Example 21
# (section 8.4) has the draft-era typ, ES384, and BOTH `iss` and `issuer`. The Recommendation
# publishes no signing key, so each is re-signed under a key of ours; header, payload and
# disclosures are the Recommendation's, and the issuer is an https URL.
FIXTURES = Path(__file__).parent / "fixtures" / "vc_jose_cose"
EXAMPLE_5 = "rec-example5-no-typ.sd-jwt"
EXAMPLE_21 = "rec-example21-vc-ld-json-sd-jwt-typ.sd-jwt"
UNIVERSITY = "https://university.example/issuers/565049"
UNIVERSITY_METADATA_URL = "https://university.example/.well-known/jwt-vc-issuer/issuers/565049"


def _fixture(name):
    return (FIXTURES / name).read_text(encoding="ascii").rstrip("\n")


def _resigned(token, key, *, amend=None):
    """The real token's header and payload (the payload amended by *amend*, if given) under
    *key*'s signature, disclosures untouched."""
    jws, rest = token.split("~", 1)
    header_b64, payload_b64, _ = jws.split(".")
    if amend is not None:
        payload = _decode(payload_b64)
        amend(payload)
        payload_b64 = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}~{rest}"


def _publishes(token, key):
    """The JWT VC Issuer Metadata that publishes *key* for the token's issuer under its kid."""
    kid = _header(token)["kid"]
    issuer = _payload(token).get("iss") or _payload(token)["issuer"]
    return {"issuer": issuer, "jwks": {"keys": [{**key.public_jwk(), "kid": kid}]}}


def _recording_fetch(metadata):
    fetched: list[str] = []

    def fetch(url):
        fetched.append(url)
        return metadata
    return fetched, fetch


def test_example_5_has_an_issuer_and_no_iss():
    payload = _payload(_fixture(EXAMPLE_5))
    assert payload["issuer"] == UNIVERSITY
    assert "iss" not in payload
    assert "typ" not in _header(_fixture(EXAMPLE_5))


def test_example_5_as_published_verifies_without_adding_an_iss():
    key = P256SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_5), key)
    assert "iss" not in _payload(token)                      # nothing was amended
    assert SdJwtVcProofSuite().peek_issuer(token) == (UNIVERSITY, _header(token)["kid"])
    result = _suite_verify(token, key=key)
    assert result.typ is None
    assert result.vcdm is True
    assert result.expired is False
    assert result.issuer == UNIVERSITY
    claims = result.claims
    assert claims["issuer"] == UNIVERSITY
    assert claims["id"] == "http://university.example/credentials/1872"
    assert claims["credentialSubject"]["id"] == "did:example:123"
    assert claims["credentialSubject"]["degree"]["type"] == "BachelorDegree"


def test_example_5_as_published_verifies_through_every_pipeline(call, form):
    key = P256SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_5), key)
    fetched, fetch = _recording_fetch(_publishes(token, key))
    result = call(form(token), fetch=fetch)
    assert fetched == [UNIVERSITY_METADATA_URL]
    assert result.format == "sd-jwt-vc"
    assert result.issuer == UNIVERSITY
    assert result.raw.typ is None
    assert result.raw.vcdm is True


def test_example_5_as_published_still_fails_at_the_signature_under_a_stranger_key(call, form):
    stranger = P256SigningKey.generate(kid="stranger")
    token = _fixture(EXAMPLE_5)
    _verify_refused(token, SignatureInvalid, ".", key=stranger, check_temporal=False)
    # through the pipeline: the issuer's key (published by a stub) is not the signer's
    fetched, fetch = _recording_fetch(_publishes(token, stranger))
    _refused(call, form(token), SignatureInvalid, ".", fetch=fetch)
    assert fetched == [UNIVERSITY_METADATA_URL]


def test_example_5_without_a_fetch_cannot_resolve_its_https_issuer(call, form):
    key = P256SigningKey.generate(kid="resigned")
    _refused(call, form(_resigned(_fixture(EXAMPLE_5), key)), KeyResolutionFailed,
             r"pass (an async )?jwt_vc_issuer_fetch")


def test_example_21_already_carries_an_iss_and_an_equal_issuer():
    payload = _payload(_fixture(EXAMPLE_21))
    assert payload["iss"] == payload["issuer"] == UNIVERSITY


def test_example_21_without_its_iss_verifies_by_its_issuer_under_the_draft_typ(call, form):
    key = P384SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_21), key, amend=lambda payload: payload.pop("iss"))
    assert "iss" not in _payload(token)
    fetched, fetch = _recording_fetch(_publishes(token, key))
    # the example's own `exp` (2024-10-14) has passed: the tests waive it
    result = call(form(token), fetch=fetch,
                  policy=VerificationPolicy(require_not_expired=False))
    assert fetched == [UNIVERSITY_METADATA_URL]
    assert result.issuer == UNIVERSITY
    assert result.raw.typ == DRAFT_TYP
    assert result.raw.vcdm is True
    assert result.expired is True


def test_example_21_without_its_iss_still_fails_at_the_signature_under_a_stranger_key(call):
    stranger = P384SigningKey.generate(kid="stranger")
    signer = P384SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_21), signer, amend=lambda payload: payload.pop("iss"))
    fetched, fetch = _recording_fetch(_publishes(token, stranger))
    _refused(call, token, SignatureInvalid, ".", fetch=fetch,
             policy=VerificationPolicy(require_not_expired=False))
    assert fetched == [UNIVERSITY_METADATA_URL]


def test_example_21_with_an_iss_and_an_issuer_that_differ_is_a_conflict(call):
    key = P384SigningKey.generate(kid="resigned")
    token = _resigned(_fixture(EXAMPLE_21), key,
                      amend=lambda payload: payload.__setitem__("issuer", "https://other.example"))
    fetched, fetch = _recording_fetch(_publishes(token, key))
    _refused(call, token, ClaimsInvalid, ISS_MISMATCH, fetch=fetch,
             policy=VerificationPolicy(require_not_expired=False))
    assert fetched == [UNIVERSITY_METADATA_URL]                  # `iss` selected the key


# --------------------------------------------------------------------------- #
# F. key resolution: the identifier, once, by the lane that identifier belongs to
# --------------------------------------------------------------------------- #

EXAMPLE_DID = "did:example:university"
EXAMPLE_KID = f"{EXAMPLE_DID}#0"


def _example_registry():
    return Reg({EXAMPLE_DID: KEY.public_jwk()})


@W3C_TYPS
@ISSUER_SHAPES
def test_the_pipeline_resolves_exactly_the_issuer_and_exactly_once(call, form, typ, shape):
    reg = _example_registry()
    token = _mint(_cred(issuer=shape(EXAMPLE_DID)), typ=typ, kid=EXAMPLE_KID)
    result = call(form(token), reg=reg)
    assert reg.resolved == [EXAMPLE_DID]
    assert result.issuer == EXAMPLE_DID
    assert result.raw.typ == _typ_of(typ)


@W3C_TYPS
def test_an_iss_token_and_a_fallback_token_resolve_the_same_identifier(call, typ):
    by_iss, by_issuer = _example_registry(), _example_registry()
    call(_mint(_with_iss(EXAMPLE_DID, issuer=EXAMPLE_DID), typ=typ, kid=EXAMPLE_KID),
         reg=by_iss)
    call(_mint(_cred(issuer=EXAMPLE_DID), typ=typ, kid=EXAMPLE_KID), reg=by_issuer)
    assert by_iss.resolved == by_issuer.resolved == [EXAMPLE_DID]


@pytest.mark.parametrize("shape", [lambda value: value, lambda value: {"id": value}],
                         ids=["string", "object"])
@pytest.mark.parametrize("issuer", [" " + EXAMPLE_DID, EXAMPLE_DID + " ", EXAMPLE_DID + "\n"],
                         ids=["leading-space", "trailing-space", "trailing-newline"])
def test_the_issuer_identifier_is_taken_verbatim_and_never_trimmed(call, issuer, shape):
    # An `iss` is not normalised and neither is the identifier that stands in for it: the
    # whitespace-padded one is another identifier, not the registered one. peek_issuer returns
    # it as written, the pipeline asks the resolver for exactly that, and the suite reports it
    # (the key given directly) as the verified issuer.
    for payload in (_cred(issuer=shape(issuer)), _with_iss(issuer, issuer=shape(issuer))):
        token = _mint(payload, kid=EXAMPLE_KID)
        assert SdJwtVcProofSuite().peek_issuer(token) == (issuer, EXAMPLE_KID)
        reg = _example_registry()
        _refused(call, token, KeyResolutionFailed, "could not resolve issuer DID", reg=reg)
        assert reg.resolved == [issuer]
        assert _suite_verify(token).issuer == issuer


def test_an_unknown_issuer_is_a_resolution_failure_for_the_issuer_not_for_anything_else(call):
    reg = Reg({EXAMPLE_DID: KEY.public_jwk()})
    token = _mint(_cred(issuer="did:example:stranger"), kid="did:example:stranger#0")
    _refused(call, token, KeyResolutionFailed, "could not resolve issuer DID", reg=reg)
    assert reg.resolved == ["did:example:stranger"]


def test_verify_many_resolves_the_issuer_of_a_fallback_batch_once_and_isolates_a_bad_item():
    reg = _example_registry()
    good = [_mint(_cred(issuer=EXAMPLE_DID, id=f"urn:uuid:{n}"), kid=EXAMPLE_KID)
            for n in range(3)]
    with_iss = _mint(_with_iss(EXAMPLE_DID, issuer=EXAMPLE_DID), kid=EXAMPLE_KID)
    no_issuer = _mint(_cred(issuer={"id": EXAMPLE_DID, "@id": OTHER_DID}), kid=EXAMPLE_KID)
    batch = [good[0], no_issuer, good[1], with_iss, good[2]]
    results = verify_many(batch, resolver=reg)
    assert [r.ok for r in results] == [True, False, True, True, True]
    assert type(results[1].error) is MalformedToken
    assert all(r.result.issuer == EXAMPLE_DID for r in results if r.ok)
    assert reg.resolved == [EXAMPLE_DID]                       # one distinct issuer, one resolve


HTTPS_ISSUER = "https://issuer.example/issuers/1"
HTTPS_METADATA_URL = "https://issuer.example/.well-known/jwt-vc-issuer/issuers/1"
HTTPS_KID = "key-1"


def _https_metadata(issuer=HTTPS_ISSUER):
    return {"issuer": issuer,
            "jwks": {"keys": [{**KEY.public_jwk(), "kid": HTTPS_KID}]}}


@W3C_TYPS
@pytest.mark.parametrize("shape", [lambda url: url, lambda url: {"id": url}],
                         ids=["string", "object"])
def test_an_https_issuer_goes_through_the_fetch_an_https_iss_goes_through(
        call, form, typ, shape):
    fallback = _mint(_cred(issuer=shape(HTTPS_ISSUER)), typ=typ, kid=HTTPS_KID)
    with_iss = _mint(_with_iss(HTTPS_ISSUER, issuer=HTTPS_ISSUER), typ=typ, kid=HTTPS_KID)
    fetched, fetch = _recording_fetch(_https_metadata())
    first = call(form(fallback), fetch=fetch)
    assert fetched == [HTTPS_METADATA_URL]
    fetched.clear()
    second = call(form(with_iss), fetch=fetch)
    assert fetched == [HTTPS_METADATA_URL]
    assert first.issuer == second.issuer == HTTPS_ISSUER


def test_an_https_issuer_needs_the_fetch_exactly_as_an_https_iss_does(call, form):
    for token in (_mint(_cred(issuer=HTTPS_ISSUER), kid=HTTPS_KID),
                  _mint(_with_iss(HTTPS_ISSUER, issuer=HTTPS_ISSUER), kid=HTTPS_KID)):
        error = _refused(call, form(token), KeyResolutionFailed,
                         r"pass (an async )?jwt_vc_issuer_fetch")
        assert HTTPS_ISSUER in str(error)


def test_the_metadata_of_an_https_issuer_must_name_that_issuer(call):
    # Anti-substitution, applied to the identifier that selected the key
    token = _mint(_cred(issuer=HTTPS_ISSUER), kid=HTTPS_KID)
    fetched, fetch = _recording_fetch(_https_metadata(issuer="https://other.example"))
    _refused(call, token, KeyResolutionFailed, "could not resolve issuer key", fetch=fetch)
    assert fetched == [HTTPS_METADATA_URL]


def test_the_metadata_must_publish_the_kid_of_the_token(call):
    token = _mint(_cred(issuer=HTTPS_ISSUER), kid="another-key")
    _fetched, fetch = _recording_fetch(_https_metadata())
    _refused(call, token, KeyResolutionFailed, "could not resolve issuer key", fetch=fetch)


def test_an_https_issuer_object_with_two_members_that_differ_resolves_nothing(call):
    fetched, fetch = _recording_fetch(_https_metadata())
    token = _mint(_cred(issuer={"id": HTTPS_ISSUER, "@id": "https://other.example"}),
                  kid=HTTPS_KID)
    _refused(call, token, MalformedToken, PEEK_CLAUSE, fetch=fetch)
    assert fetched == []


# x5c: the chain is validated to the anchors and its leaf bound to the identifier, which is
# the `issuer` here as it is `iss` elsewhere. A chain wins over any fetch or DID.
X5C_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
X5C_ISSUER = "https://sede.uc3m.es"
_CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)


def _x5c_cert(subject, issuer_cn, issuer_key, subject_pub, *, ca, san=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_pub).serial_number(x509.random_serial_number())
        .not_valid_before(X5C_NOW - dt.timedelta(days=1))
        .not_valid_after(X5C_NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(_CA_KEY_USAGE, critical=True)
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _x5c_world(*, san=X5C_ISSUER):
    """(the leaf's signing key, the x5c header value, the root anchor)."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _x5c_cert("root", "root", root_key, root_key.public_key(), ca=True)
    leaf_private = ec.generate_private_key(ec.SECP256R1())
    leaf = _x5c_cert("signer", "root", root_key, leaf_private.public_key(), ca=False,
                     san=[x509.UniformResourceIdentifier(san)])
    x5c = [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode("ascii")]
    return P256SigningKey(leaf_private, kid="signer"), x5c, root


X5C_POLICY = VerificationPolicy(require_status=False, now=X5C_NOW)


@W3C_TYPS
def test_an_x5c_leaf_is_bound_to_the_issuer_when_there_is_no_iss(call, form, typ):
    leaf_key, x5c, root = _x5c_world()
    token = _mint(_cred(issuer=X5C_ISSUER), typ=typ, key=leaf_key, kid=None,
                  header={"x5c": x5c})
    assert "iss" not in _payload(token) and "kid" not in _header(token)
    result = call(form(token), x5c_trust_anchors=[root], policy=X5C_POLICY)
    assert result.issuer == X5C_ISSUER
    assert result.raw.vcdm is True


def test_an_x5c_leaf_for_another_host_is_refused_as_for_an_iss(call):
    leaf_key, x5c, root = _x5c_world(san="https://attacker.example")
    for payload in (_cred(issuer=X5C_ISSUER), _with_iss(X5C_ISSUER, issuer=X5C_ISSUER)):
        token = _mint(payload, key=leaf_key, kid=None, header={"x5c": x5c})
        _refused(call, token, KeyResolutionFailed, "x5c key resolution failed",
                 x5c_trust_anchors=[root], policy=X5C_POLICY)


def test_an_x5c_chain_to_an_unknown_anchor_is_refused_as_for_an_iss(call):
    leaf_key, x5c, _root = _x5c_world()
    _other_key, _other_x5c, stranger_root = _x5c_world()
    token = _mint(_cred(issuer=X5C_ISSUER), key=leaf_key, kid=None, header={"x5c": x5c})
    _refused(call, token, KeyResolutionFailed, "x5c key resolution failed",
             x5c_trust_anchors=[stranger_root], policy=X5C_POLICY)


def test_an_x5c_leaf_is_bound_to_the_issuer_not_to_a_kid_or_a_resolver(call):
    # The issuer is a DID that no registry knows: the chain was never about it, so the
    # leaf's SAN (an https URL) cannot be bound to it.
    leaf_key, x5c, root = _x5c_world()
    token = _mint(_cred(issuer="did:example:nobody"), key=leaf_key, kid=None,
                  header={"x5c": x5c})
    _refused(call, token, KeyResolutionFailed, "x5c key resolution failed",
             x5c_trust_anchors=[root], policy=X5C_POLICY, reg=Reg({}))


# --------------------------------------------------------------------------- #
# G. the typ guards: the header is not verified yet when peek_issuer reads it
# --------------------------------------------------------------------------- #

# A `typ` that is not one of the three accepted names, the unhashable ones included (a bare
# `in frozenset` on them is a TypeError), and the near-misses a lenient matcher would take.
# `null` has its own test below.
NOT_A_TYP = [
    pytest.param(0, id="zero"),
    pytest.param(1, id="one"),
    pytest.param(1.5, id="float"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param([], id="empty-array"),
    pytest.param(["vc+sd-jwt"], id="array-of-vc-sd-jwt"),
    pytest.param({}, id="empty-object"),
    pytest.param({"typ": "vc+sd-jwt"}, id="object"),
    pytest.param("", id="empty-string"),
    pytest.param("JWT", id="jwt"),
    pytest.param("kb+jwt", id="kb-jwt"),
    pytest.param("vc+jwt", id="vc-jwt"),
    pytest.param("VC+SD-JWT", id="upper-case-vc"),
    pytest.param("Vc+Sd-Jwt", id="mixed-case-vc"),
    pytest.param("VC+LD+JSON+SD-JWT", id="upper-case-draft"),
    pytest.param("application/vc+sd-jwt", id="media-type-vc"),
    pytest.param("application/vc+ld+json+sd-jwt", id="media-type-draft"),
    pytest.param(" vc+sd-jwt", id="leading-space"),
    pytest.param("vc+sd-jwt ", id="trailing-space"),
    pytest.param("vc+sd-jwt\n", id="trailing-newline"),
    pytest.param("DC+SD-JWT", id="upper-case-dc"),
    pytest.param("dc+sd-jwt ", id="trailing-space-dc"),
]


@pytest.mark.parametrize("typ", NOT_A_TYP)
def test_a_typ_that_is_not_a_w3c_state_gets_no_fallback_and_never_a_bare_error(call, typ):
    token = _mint(_cred(issuer=DID), typ=typ)
    # The sentence is the old one, whole: `issuer` is usable, and the fallback is not
    # available for this typ, so the clause ("no usable VCDM `issuer`") would be a lie.
    _peek_refused(token, MalformedToken, PEEK_BARE)
    # the pipeline stops at peek, with the same typed error
    _refused(call, token, MalformedToken, PEEK_BARE)


@pytest.mark.parametrize("issuer", [DID, ABSENT], ids=["usable-issuer", "no-issuer"])
@pytest.mark.parametrize("typ", NOT_A_TYP)
def test_the_typ_gate_of_verify_comes_before_any_issuer_is_read(typ, issuer):
    # verify() called directly: the typ is refused as a typ, never as a missing issuer
    token = _mint(_cred(issuer=issuer), typ=typ)
    _verify_refused(token, SdJwtError, UNEXPECTED_TYP)


@pytest.mark.parametrize("typ", NOT_A_TYP)
def test_a_typ_that_is_no_typ_does_not_matter_when_iss_is_there(call, typ):
    # peek_issuer takes `iss` without looking at the typ (verify() is where it is refused)
    token = _mint(_with_iss(DID, issuer=DID), typ=typ)
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)
    _refused(call, token, SdJwtError, UNEXPECTED_TYP)


@pytest.mark.parametrize("issuer", [EXAMPLE_DID, {"id": EXAMPLE_DID}], ids=["string", "object"])
def test_a_null_typ_is_a_present_typ_so_peek_does_not_fall_back_and_nothing_is_resolved(
        call, form, issuer):
    # `"typ": null` is a PRESENT member, not a W3C state, so the VCDM `issuer` does not stand
    # in for the missing `iss` (peek_issuer used to read null like no member, resolve a key,
    # and leave verify() to refuse the typ). The refusal is the bare typed MalformedToken
    # (the fallback was not available, so no clause), and the pipelines stop before any
    # resolver is asked: a counting resolver sees nothing.
    token = _mint(_cred(issuer=issuer), typ=None, kid=EXAMPLE_KID)
    assert _header(token)["typ"] is None
    assert "iss" not in _payload(token)
    _peek_refused(token, MalformedToken, PEEK_BARE)
    reg = _example_registry()
    _refused(call, form(token), MalformedToken, PEEK_BARE, reg=reg)
    assert reg.resolved == []
    # verify() called directly, which is where the typ is refused: as an unexpected typ,
    # before any issuer is read
    _verify_refused(token, SdJwtError, _only("unexpected issuer JWT typ None"))


def test_a_null_typ_next_to_an_iss_is_selected_by_peek_and_refused_by_the_typ_gate(call):
    # With an `iss` there was never a fallback to take: peek_issuer selects the key from it
    # and verify() refuses the typ, as it does for every typ that is not accepted.
    token = _mint(_with_iss(EXAMPLE_DID, issuer=EXAMPLE_DID), typ=None, kid=EXAMPLE_KID)
    assert SdJwtVcProofSuite().peek_issuer(token) == (EXAMPLE_DID, EXAMPLE_KID)
    reg = _example_registry()
    _refused(call, token, SdJwtError, _only("unexpected issuer JWT typ None"), reg=reg)
    assert reg.resolved == [EXAMPLE_DID]
    _verify_refused(token, SdJwtError, _only("unexpected issuer JWT typ None"))


@pytest.mark.parametrize("issuer", [ABSENT, "", {}, {"name": "x"}],
                         ids=["no-issuer", "empty-issuer", "empty-object", "object-with-no-id"])
def test_a_null_typ_with_no_usable_issuer_is_a_typed_peek_error_without_the_clause(
        call, issuer):
    # The fallback is not available for a null typ, so the sentence stays the bare old one
    # (the clause is for a W3C typ whose `issuer` was looked at and found wanting).
    token = _mint(_cred(issuer=issuer), typ=None)
    _peek_refused(token, MalformedToken, PEEK_BARE)
    _refused(call, token, MalformedToken, PEEK_BARE)
    _verify_refused(token, SdJwtError, _only("unexpected issuer JWT typ None"))


def test_neither_spelling_of_dc_sd_jwt_gets_the_fallback_from_peek():
    # `dc+sd-jwt` is not a W3C state; its upper-case spelling is not a state at all
    for typ in ("dc+sd-jwt", "DC+SD-JWT"):
        _peek_refused(_mint(_cred(vct=VCT), typ=typ), MalformedToken,
                      re.escape(NO_ISS_TO_PEEK))


# --------------------------------------------------------------------------- #
# H. what still runs on a fallback token
# --------------------------------------------------------------------------- #

STATUS_URL = "https://status-host.example/1"
STATUS_INDEX = 17
CREDENTIAL_STATUS = {"id": f"{STATUS_URL}#{STATUS_INDEX}", "type": "BitstringStatusListEntry",
                     "statusPurpose": "revocation", "statusListIndex": str(STATUS_INDEX),
                     "statusListCredential": STATUS_URL}


def _status_list(issuer, *, set_indices=()):
    bits = bytearray(32)
    for index in set_indices:
        set_status_bit(bits, index, 1)
    document = {"type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "issuer": issuer,
                "credentialSubject": {"statusPurpose": "revocation",
                                      "encodedList": encode_bitstring(bytes(bits))}}
    asked: list[str] = []

    def resolve(uri):
        asked.append(uri)
        return document
    return asked, resolve


BINDING = VerificationPolicy(require_status_issuer_binding=True)


@W3C_TYPS
def test_the_status_issuer_is_bound_to_the_issuer_a_fallback_token_names(call, form, typ):
    asked, resolve = _status_list(DID)
    token = _mint(_cred(credentialStatus=CREDENTIAL_STATUS), typ=typ)
    result = call(form(token), resolve_status_list=resolve, policy=BINDING)
    assert asked == [STATUS_URL]
    assert result.issuer == DID
    assert result.status is not None and result.status.revoked is False


@W3C_TYPS
def test_a_status_list_of_another_issuer_is_untrusted_for_a_fallback_token(call, form, typ):
    _asked, resolve = _status_list(OTHER_DID)
    token = _mint(_cred(credentialStatus=CREDENTIAL_STATUS), typ=typ)
    error = _refused(call, form(token), StatusListIssuerUntrusted,
                     re.escape(f"is not the credential issuer {DID!r}"),
                     resolve_status_list=resolve, policy=BINDING)
    assert OTHER_DID in str(error)


def test_an_allow_listed_delegate_may_issue_the_status_list_of_a_fallback_token(call):
    _asked, resolve = _status_list(OTHER_DID)
    token = _mint(_cred(credentialStatus=CREDENTIAL_STATUS))
    policy = VerificationPolicy(require_status_issuer_binding=True,
                                status_issuer_allowlist=frozenset({OTHER_DID}))
    assert call(token, resolve_status_list=resolve, policy=policy).issuer == DID


def test_the_status_issuer_binding_of_an_iss_token_is_the_same_decision(call):
    # The same list, the same policy, the same verdict whichever member names the issuer
    _asked, resolve = _status_list(OTHER_DID)
    by_iss = _mint(_with_iss(DID, issuer=DID, credentialStatus=CREDENTIAL_STATUS))
    by_issuer = _mint(_cred(credentialStatus=CREDENTIAL_STATUS))
    for token in (by_iss, by_issuer):
        _refused(call, token, StatusListIssuerUntrusted, "nor an allow-listed delegate",
                 resolve_status_list=resolve, policy=BINDING)


def test_a_revoked_fallback_token_is_revoked(call):
    _asked, resolve = _status_list(DID, set_indices=[STATUS_INDEX])
    token = _mint(_cred(credentialStatus=CREDENTIAL_STATUS))
    _refused(call, token, CredentialRevoked, "is revoked", resolve_status_list=resolve)


def test_a_fallback_token_with_a_status_and_no_resolver_fails_closed(call):
    from openvc.verify import StatusUnavailable
    token = _mint(_cred(credentialStatus=CREDENTIAL_STATUS))
    _refused(call, token, StatusUnavailable, "resolve_status_list")


@W3C_TYPS
def test_the_validity_window_still_runs_on_a_fallback_token(call, form, typ):
    _refused(call, form(_mint(_cred(validUntil=PAST), typ=typ)), CredentialExpired, ".")
    _refused(call, form(_mint(_cred(validFrom=FUTURE), typ=typ)), CredentialNotYetValid, ".")
    waived = call(form(_mint(_cred(validUntil=PAST), typ=typ)),
                  policy=VerificationPolicy(require_not_expired=False))
    assert waived.expired is True
    assert waived.issuer == DID
    still = VerificationPolicy(require_not_expired=False)
    _refused(call, form(_mint(_cred(validFrom=FUTURE), typ=typ)), CredentialNotYetValid, ".",
             policy=still)


@W3C_TYPS
def test_the_consistency_checks_still_run_on_a_fallback_token(call, form, typ):
    _refused(call, form(_mint(_cred(jti="urn:uuid:another-credential"), typ=typ)),
             ClaimsInvalid, "jti")
    _refused(call, form(_mint(_cred(sub="did:example:bob"), typ=typ)), ClaimsInvalid, "sub")
    agreeing = _mint(_cred(jti="urn:uuid:5e1d6a3c-cred", sub="did:example:alice"), typ=typ)
    assert call(form(agreeing)).issuer == DID


def _partly_disclosed_issuer(disclosed, value, *, typ, named_by):
    """A token whose body issuer is ``{<the other member>: DID, "_sd": [digest]}`` and whose
    disclosure is ``[salt, disclosed, value]`` (``disclosed`` is ``id`` or ``@id``): the
    body alone names DID, the presented disclosure names *value*. *named_by*: ``issuer``
    (no ``iss`` member, the fallback) or ``iss`` (equal to DID)."""
    in_body = "@id" if disclosed == "id" else "id"
    issuer = {in_body: DID, disclosed: value}
    payload = _cred(issuer=issuer) if named_by == "issuer" else _with_iss(DID, issuer=issuer)
    token = _mint(payload, typ=typ, disclose_in=[("issuer", disclosed)])
    body = _payload(token)
    assert body["issuer"][in_body] == DID and disclosed not in body["issuer"]
    assert len(body["issuer"]["_sd"]) == 1 and ("iss" in body) == (named_by == "iss")
    return token


@W3C_TYPS
@pytest.mark.parametrize("disclosed", ["id", "@id"])
@pytest.mark.parametrize("named_by", ["issuer", "iss"])
def test_a_presented_issuer_member_that_names_another_issuer_is_a_conflict(
        call, form, typ, disclosed, named_by):
    # The body names DID (so DID's key is selected and verifies the signature) and the holder
    # presents a disclosure that makes the processed issuer ALSO name OTHER_DID: the issuer is
    # reconciled against what was PROCESSED, with or without an `iss`.
    token = _partly_disclosed_issuer(disclosed, OTHER_DID, typ=typ, named_by=named_by)
    assert SdJwtVcProofSuite().peek_issuer(token) == (DID, KID)
    _refused(call, form(token), ClaimsInvalid, ISS_MISMATCH)
    _verify_refused(token, ClaimsInvalid, ISS_MISMATCH)
    # the holder withholding it leaves the body alone, which names DID (RFC 9901 §9.7 limit)
    assert call(form(_presented_without_disclosures(token))).issuer == DID


@W3C_TYPS
@pytest.mark.parametrize("disclosed", ["id", "@id"])
@pytest.mark.parametrize("named_by", ["issuer", "iss"])
def test_a_presented_issuer_member_that_names_the_same_issuer_verifies(
        call, form, typ, disclosed, named_by):
    # The control: same shape, the disclosure agrees with the body
    token = _partly_disclosed_issuer(disclosed, DID, typ=typ, named_by=named_by)
    result = call(form(token))
    assert result.issuer == DID
    assert result.claims["issuer"] == {"id": DID, "@id": DID}
    assert _suite_verify(token).issuer == DID


@W3C_TYPS
@pytest.mark.parametrize("named_by", ["issuer", "iss"])
@pytest.mark.parametrize("claim, contradicting, agreeing, match", [
    pytest.param("sub", "did:example:bob", "did:example:alice",
                 r"\Asub .* != credentialSubject\.id ", id="sub"),
    pytest.param("jti", "urn:uuid:another-credential", "urn:uuid:5e1d6a3c-cred",
                 r"\Ajti .* != vc\.id ", id="jti"),
])
def test_a_disclosed_sub_or_jti_is_reconciled_with_the_credential_like_a_body_one(
        call, form, typ, named_by, claim, contradicting, agreeing, match):
    # draft-19 lets `sub` be selectively disclosed, and `jti` is not on the list of claims
    # that may not be, so the holder can present one that the body does not carry. The
    # reconciliation reads the PROCESSED claims, as it reads a `sub` / `jti` of the body.
    def token(value):
        extra = {claim: value}
        payload = _cred(**extra) if named_by == "issuer" else _with_iss(DID, **extra)
        minted = _mint(payload, typ=typ, disclose=[claim])
        assert claim not in _payload(minted)
        return minted
    contradiction = token(contradicting)
    _refused(call, form(contradiction), ClaimsInvalid, match)
    _verify_refused(contradiction, ClaimsInvalid, match)
    agreement = token(agreeing)
    assert call(form(agreement)).issuer == DID
    assert _suite_verify(agreement).issuer == DID


@pytest.mark.parametrize("typ, shown", [
    pytest.param(ABSENT, "without a typ", id="no-typ"),
    pytest.param("vc+sd-jwt", "typ 'vc+sd-jwt'", id="vc-sd-jwt"),
    pytest.param(DRAFT_TYP, f"typ '{DRAFT_TYP}'", id="draft-typ"),
])
def test_the_conformance_gate_still_runs_on_a_fallback_token(call, typ, shown):
    misplaced = re.escape(f"issuer JWT {shown} needs a VCDM base context as the first "
                          "`@context` entry (VCDM 2.0 §4.3), not just somewhere in it")
    _refused(call, _mint(_cred(**{"@context": ["https://example.org/ctx", V2]}), typ=typ),
             SdJwtError, misplaced)
    presentation = re.escape(f"issuer JWT {shown} needs a `type` that includes "
                             "VerifiableCredential and not VerifiablePresentation "
                             "(VCDM 2.0 §4.5, §4.13)")
    _refused(call, _mint(_cred(type=["VerifiablePresentation"]), typ=typ), SdJwtError,
             presentation)
    withheld = _without(_mint(_cred(), typ=typ, disclose=["type"]), "type")
    _refused(call, withheld, SdJwtError, presentation)


@pytest.mark.parametrize("typ, shown", [
    pytest.param(ABSENT, "without a typ", id="no-typ"),
    pytest.param("vc+sd-jwt", "typ 'vc+sd-jwt'", id="vc-sd-jwt"),
])
def test_an_ietf_payload_with_an_issuer_claim_is_not_rescued_by_the_fallback(call, typ, shown):
    # It has an `issuer` and no `iss`, so a key is resolved for it; then the typ gate asks
    # for a VCDM @context, which an IETF SD-JWT VC does not have.
    token = _mint(_ietf(), typ=typ)
    _refused(call, token, SdJwtError,
             re.escape(f"issuer JWT {shown} needs a W3C VCDM @context; "
                       "an IETF SD-JWT VC is typed 'dc+sd-jwt'"))


def test_a_vc_claim_still_refuses_a_fallback_token_with_no_typ(call):
    token = _mint(_cred(vc={"issuer": DID}))
    _refused(call, token, SdJwtError, re.escape("must not carry a `vc` or `vp` claim"))


def test_expected_types_is_enforced_on_a_fallback_token(call):
    token = _mint(_cred())
    assert call(token, policy=VerificationPolicy(
        expected_types=["ExampleAlumniCredential"])).issuer == DID
    _refused(call, token, TypeMismatch, "missing required type",
             policy=VerificationPolicy(expected_types=["SomethingElse"]))


def test_key_binding_still_binds_a_fallback_token():
    holder = P256SigningKey.generate(kid="holder")
    token = _mint(_cred(cnf={"jwk": holder.public_jwk()}))
    presentation = SdJwtVcProofSuite().create_presentation(
        token, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)
    policy = VerificationPolicy(audience=CLIENT_ID, nonce=NONCE, require_key_binding=True)
    for entry in PIPELINES.values():
        result = entry(presentation, policy=policy)
        assert result.key_bound is True
        assert result.issuer == DID
    other = VerificationPolicy(audience="x509_san_dns:other.example", nonce=NONCE,
                               require_key_binding=True)
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        verify_credential(presentation, policy=other)


# The suite called directly with a KB-JWT required: `iss` and `issuer` are read BEFORE the
# key binding on this path (so a refused issuer is never reported as a binding failure), and
# it is its own branch of verify().
KEY_BOUND = {"require_key_binding": True, "audience": CLIENT_ID, "nonce": NONCE}


def _bound(payload, *, typ=ABSENT):
    """*payload* with the holder's `cnf`, minted and presented with a valid KB-JWT."""
    holder = P256SigningKey.generate(kid="holder")
    token = _mint({**payload, "cnf": {"jwk": holder.public_jwk()}}, typ=typ)
    presentation = SdJwtVcProofSuite().create_presentation(
        token, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)
    assert presentation.rsplit("~", 1)[1]                      # the KB-JWT is there
    return presentation


@W3C_TYPS
@ISSUER_SHAPES
def test_key_binding_required_a_fallback_token_verifies_bound_to_the_holder(typ, shape):
    presentation = _bound(_cred(issuer=shape(DID)), typ=typ)
    assert "iss" not in _payload(presentation)
    result = _suite_verify(presentation, **KEY_BOUND)
    assert result.key_bound is True
    assert result.issuer == DID
    assert result.vcdm is True
    assert result.typ == _typ_of(typ)


@W3C_TYPS
@pytest.mark.parametrize("iss", INVALID_ISS)
def test_key_binding_required_a_present_invalid_iss_gets_no_fallback_to_issuer(typ, iss):
    # The same refusal as without key binding, and the bare sentence (the fallback was never
    # available): a falsy `iss` (null, '', 0, false, [], {}) is NOT treated as an absent one
    # on this branch either, so the usable `issuer` next to it does not rescue the token.
    presentation = _bound(_with_iss(iss, issuer=DID), typ=typ)
    assert "iss" in _payload(presentation)
    _verify_refused(presentation, ClaimsInvalid, VERIFY_BARE, **KEY_BOUND)
    _peek_refused(presentation, MalformedToken, PEEK_BARE)


@pytest.mark.parametrize("payload", [
    pytest.param(_ietf(), id="ietf-claims-with-an-issuer-claim"),
    pytest.param(_cred(vct=VCT), id="vcdm-with-a-vct-and-an-issuer"),
    pytest.param(_cred(vct=VCT, issuer={"id": DID}), id="vcdm-with-a-vct-and-an-issuer-object"),
])
def test_key_binding_required_a_dc_sd_jwt_with_an_issuer_and_no_iss_gets_no_fallback(payload):
    presentation = _bound(payload, typ="dc+sd-jwt")
    assert "iss" not in _payload(presentation)
    _verify_refused(presentation, ClaimsInvalid, VERIFY_BARE, **KEY_BOUND)
    _peek_refused(presentation, MalformedToken, PEEK_BARE)


@W3C_TYPS
@pytest.mark.parametrize("issuer", [ABSENT, "", {}, {"name": "x"}, {"id": DID, "@id": OTHER_DID}],
                         ids=["absent", "empty", "empty-object", "no-id", "disagreeing"])
def test_key_binding_required_a_fallback_with_nothing_usable_gets_the_clause(typ, issuer):
    presentation = _bound(_cred(issuer=issuer), typ=typ)
    _verify_refused(presentation, ClaimsInvalid, VERIFY_CLAUSE, **KEY_BOUND)
    _peek_refused(presentation, MalformedToken, PEEK_CLAUSE)


# --------------------------------------------------------------------------- #
# I. OpenID4VP
# --------------------------------------------------------------------------- #

def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    private = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(private, kid="_").public_key_raw(compressed=True)
    multibase = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(private, kid=f"did:key:{multibase}#{multibase}"), f"did:key:{multibase}"


def _present(claims, *, typ):
    holder = P256SigningKey.generate(kid="holder")
    sd_jwt = _mint({**claims, "cnf": {"jwk": holder.public_jwk()}}, typ=typ)
    return SdJwtVcProofSuite().create_presentation(
        sd_jwt, holder_key=holder, audience=CLIENT_ID, nonce=NONCE)


def _answer(presentation, query=None):
    query = {"id": "q", "format": "dc+sd-jwt", **(query or {})}
    return verify_vp_token({"q": [presentation]}, dcql_query={"credentials": [query]},
                           nonce=NONCE, client_id=CLIENT_ID).for_query("q")[0]


def test_openid4vp_a_dc_sd_jwt_with_an_iss_still_answers_a_dc_sd_jwt_query():
    answer = _answer(_present({**_ietf(), "iss": DID}, typ="dc+sd-jwt"))
    assert answer.raw.typ == "dc+sd-jwt"
    assert answer.raw.issuer == DID
    assert answer.raw.key_bound is True
    (credential,) = answer.credentials
    assert credential.issuer == DID


def test_openid4vp_a_dc_sd_jwt_with_an_issuer_and_no_iss_is_not_answered():
    with pytest.raises(MalformedToken) as excinfo:
        _answer(_present(_ietf(), typ="dc+sd-jwt"))
    assert excinfo.type is MalformedToken
    assert str(excinfo.value) == NO_ISS_TO_PEEK


@pytest.mark.parametrize("typ", [ABSENT, DRAFT_TYP, "vc+sd-jwt"],
                         ids=["no-typ", "draft-typ", "vc-sd-jwt"])
def test_openid4vp_a_fallback_token_is_still_not_a_dc_sd_jwt_credential(typ):
    # The credential verifies (the issuer is resolved from `issuer`) but the dc+sd-jwt
    # format is the IETF SD-JWT VC, whose issuer JWT is typed dc+sd-jwt: still refused.
    with pytest.raises(VpTokenMalformed, match="must be an IETF SD-JWT VC") as excinfo:
        _answer(_present(_cred(), typ=typ))
    assert excinfo.type is VpTokenMalformed
    assert "issuer JWT typ 'dc+sd-jwt', got " in str(excinfo.value)


def test_openid4vp_a_fallback_token_nested_in_a_vp_jwt_verifies_as_jwt_vc_json():
    # The VP-JWT is signed by the holder (a did:key); the nested credential has no `iss`,
    # names DID in `issuer`, and carries a KB-JWT bound to this exchange.
    holder_key, _holder_did = _did_key_p256()
    presentation = _present(_cred(), typ="vc+sd-jwt")
    vp = VpJwtProofSuite().sign([presentation], holder_key=holder_key,
                                audience=CLIENT_ID, nonce=NONCE)
    dcql = {"credentials": [{"id": "q", "format": "jwt_vc_json"}]}
    (credential,) = verify_vp_token({"q": [vp]}, dcql_query=dcql, nonce=NONCE,
                                    client_id=CLIENT_ID).for_query("q")[0].credentials
    assert credential.issuer == DID
    assert credential.key_bound is True
    assert credential.raw.vcdm is True
    assert credential.raw.typ == "vc+sd-jwt"
    assert "iss" not in credential.claims
