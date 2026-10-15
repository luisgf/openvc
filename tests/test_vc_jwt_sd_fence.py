"""
tests/test_vc_jwt_sd_fence.py — an SD-JWT issuer JWT is fenced off the VC-JWT and VP-JWT
lanes by what it CARRIES, not only by the ``typ`` it declares (#291; #189 did the typed half).

The rule. RFC 8725 §3.11 asks for explicit typing, and ``_reject_sd_jwt_typ`` enforces it
(#189): a JWS typed ``sd-jwt``, ``*+sd-jwt`` or ``kb+jwt`` is no VC-JWT. Typing only works
while the issuer sets a ``typ`` the filter knows. An SD-JWT issuer JWT with no ``typ`` (VC-JOSE-COSE
§3.2.1 makes it a SHOULD), or with one such as ``JWT``, and a ``vc`` object in its payload,
verified on the VC-JWT lane once a holder dropped its ``~`` tail, with no key binding at all.
RFC 9901 reserves three names inside an SD-JWT payload: ``_sd`` (§4.1 item 7, the digests of
the disclosures of an object's members), ``_sd_alg`` (§4.1.1, the hash function, top level only)
and ``...`` (§4.1 item 7 and §4.2.4.2, the digest object that stands for an array element). A
VC-JWT never carries one, so a payload that does, at ANY depth (an issuer that keeps a ``vc``
object keeps its disclosable claims INSIDE it), is an SD-JWT issuer JWT whatever its ``typ``.
Both lanes now refuse it, with ``MalformedToken``, before any signature is checked (the
VP-JWT lane also before the holder key is resolved; on the VC-JWT lane the verify_credential
pipeline has already resolved the issuer key, and the suite builds its verification key only
after the fence):

* ``VcJwtProofSuite.verify`` (so ``verify_credential``, ``verify_credential_async`` and
  ``verify_many`` on a compact JWS) calls ``_reject_sd_jwt_payload`` on the peeked payload.
* ``VpJwtProofSuite.verify`` (so OpenID4VP ``jwt_vc_json``) calls ``_reject_sd_jwt_typ`` and
  ``_reject_sd_jwt_payload`` on the peeked VP-JWT, before the holder key is resolved. That lane
  never looked at ``typ`` at all before this change.

``_carries_sd_jwt_marker`` is iterative: the payload is attacker-controlled, and a recursive
walk of a hostile list raises a bare ``RecursionError`` that escapes ``OpenvcError``.

THE DOCUMENTED RESIDUAL (#291, pinned in section C, not fixed). A zero-disclosure SD-JWT
issuer JWT with no ``typ``, a ``vc`` object and a ``cnf`` carries none of ``_sd``, ``_sd_alg``,
``...``, so nothing tells it from a VC-JWT that carries a ``cnf``, and the VC-JWT lane never
enforces ``cnf`` (it has no key binding to enforce). With its ``~`` tail dropped it still
verifies as a VC-JWT. Whoever closes that gap has to change the test that says so.

A. each marker, alone, at each position, is refused, and before the signature is checked
B. controls: a VC-JWT without markers, and payloads with look-alike names, still verify
C. the #291 repro through the pipeline, and the residual
D. ``verify_many`` isolates a marker-carrying item
E. the VP-JWT lane: the typ filter and the marker fence, before any key resolution
F. OpenID4VP ``jwt_vc_json``
G. ``_carries_sd_jwt_marker`` itself: finds every planted marker, finds none that is not
   there, and does not recurse
H. the ML-DSA lane (``allow_pq=True``) is fenced as the classic one, key or no key
I. markers in sibling claims (outside ``vc``, outside ``credentialSubject``)
J. wide payloads: no node budget, no array-length cut-off, linear time
K. the VP-JWT order of checks: algorithm, ``crit``, ``typ``, markers, and only then the key
L. a hostile ``typ`` is echoed bounded, on both lanes

Helpers are self-contained (tests/ is not a package, no cross-import); the issuer is a
``did:jwk`` the default resolvers answer offline, the signatures are real P-256, and
``asyncio.run`` drives the async pipeline (pytest-asyncio is not a dependency).
"""
from __future__ import annotations

import asyncio
import base64
import functools
import json
import random
import secrets
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import (
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
    verify_vp_token,
)
from openvc._json import nesting_exceeds
from openvc.keys import MLDSASigningKey, P256SigningKey, mldsa_available
from openvc.proof.errors import (
    MalformedToken,
    ProofError,
    SignatureInvalid,
    UnsupportedAlgorithm,
)
from openvc.proof.sd_jwt import disclosure_digest, make_object_disclosure
from openvc.proof.vc_jwt import (
    VcJwtProofSuite,
    _carries_sd_jwt_marker,
    _reject_sd_jwt_payload,
)
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import default_resolver

V1 = "https://www.w3.org/2018/credentials/v1"
V2 = "https://www.w3.org/ns/credentials/v2"
NBF = 1609459200                      # 2021-01-01T00:00:00Z, long past
AUD = "x509_san_dns:verifier.example"
NONCE = "n-0S6_WzA2Mj"
DIGEST = "f" * 43                     # the shape of a sha-256 digest (43 base64url characters)
ABSENT = object()                     # `typ=ABSENT`: a header with no `typ` member

# What the lanes say. The first is the marker fence (this file's subject), the second the
# shared typ filter, whose wording is the VC-JWT lane's even when the VP-JWT lane calls it.
SD_JWT_MARKERS = "carries SD-JWT markers"
NOT_A_VC_JWT = "is not a VC-JWT"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _keypair():
    """(P256SigningKey keyed to ``<did>#0``, did) for a ``did:jwk`` the default resolvers
    answer offline."""
    private = ec.generate_private_key(ec.SECP256R1())
    probe = P256SigningKey(private, kid="_")
    did = "did:jwk:" + _b64(json.dumps(probe.public_jwk()).encode())
    return P256SigningKey(private, kid=f"{did}#0"), did


KEY, DID = _keypair()
# Same curve on purpose: a P-384 key would trip the curve pin (ProofError), not the
# signature check, and muddy the "wrong key" control.
STRANGER, _ = _keypair()
HOLDER_KEY, HOLDER_DID = _keypair()


def _jws(payload, *, key=KEY, typ=ABSENT, kid=None):
    """Sign *payload* (a dict, or JSON TEXT when the test needs a spelling ``json.dumps``
    would not write, such as an escaped underscore) with *key* under a header naming
    ``<DID>#0`` (the issuer's), so a *key* other than ``KEY`` is a wrong-key signature."""
    header = {"alg": "ES256", "kid": kid or f"{DID}#0"}
    if typ is not ABSENT:
        header["typ"] = typ
    text = payload if isinstance(payload, str) else json.dumps(payload)
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(text.encode())}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"


def _vc(**subject):
    return {"@context": [V1], "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "did:example:alice", "name": "Ada", **subject}}


def _claims(vc=None, **extra):
    """A VCDM 1.1 style VC-JWT payload: the issuer in ``iss``, the credential under ``vc``."""
    return {"iss": DID, "nbf": NBF, "vc": vc if vc is not None else _vc(), **extra}


def _with_subject(**subject):
    return _claims(_vc(**subject))


# --------------------------------------------------------------------------- #
# the entry points: the sync and async pipelines, and the suite itself
# --------------------------------------------------------------------------- #

def _sync(token):
    return verify_credential(token)


def _async(token):
    return asyncio.run(verify_credential_async(token))


def _suite(token):
    return VcJwtProofSuite().verify(token, public_key_jwk=KEY.public_jwk())


PIPELINES = {"sync": _sync, "async": _async}
ENTRY_POINTS = {**PIPELINES, "suite": _suite}


@pytest.fixture(params=sorted(ENTRY_POINTS))
def run(request):
    return ENTRY_POINTS[request.param]


@pytest.fixture(params=sorted(PIPELINES))
def pipeline(request):
    return PIPELINES[request.param]


# --------------------------------------------------------------------------- #
# A. each marker, alone, at each position
# --------------------------------------------------------------------------- #

def _depth(tree):
    """How many levels of containers *tree* nests, iteratively."""
    deepest, stack = 0, [(tree, 1)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, dict):
            children = list(node.values())
        elif isinstance(node, list):
            children = node
        else:
            continue
        deepest = max(deepest, level)
        stack.extend((child, level + 1) for child in children)
    return deepest


def _nested(depth, leaf):
    node = leaf
    for _ in range(depth):
        node = {"n": node}
    return node


def _raw(claims, spelling):
    """The JSON text of *claims*, with each placeholder KEY replaced by its spelling (a JSON
    escape ``json.dumps`` would never write): the decoded member name is the marker."""
    text = json.dumps(claims)
    for placeholder, escaped in spelling.items():
        assert text.count(f'"{placeholder}"') == 1
        text = text.replace(f'"{placeholder}"', f'"{escaped}"')
    return text


# Each case carries ONE marker and no other, or a mutant that stops looking for it would
# survive on the strength of its neighbour: `_sd_alg` is not added next to `_sd`.
MARKER_CASES = [
    pytest.param(lambda: _claims(**{"_sd": [DIGEST]}), id="top-level-_sd"),
    pytest.param(lambda: _claims(**{"_sd_alg": "sha-256"}), id="top-level-_sd_alg-alone"),
    pytest.param(lambda: _claims(**{"...": DIGEST}), id="top-level-ellipsis"),
    pytest.param(lambda: _with_subject(**{"_sd": [DIGEST]}), id="_sd-in-credentialSubject"),
    pytest.param(lambda: _with_subject(**{"_sd_alg": "sha-256"}),
                 id="_sd_alg-in-credentialSubject"),
    pytest.param(lambda: _with_subject(degrees=[{"type": "BachelorDegree"},
                                                {"school": {"_sd": [DIGEST]}}]),
                 id="_sd-in-an-object-in-an-array"),
    pytest.param(lambda: _with_subject(nationalities=["ES", {"...": DIGEST}]),
                 id="array-element-digest"),
    pytest.param(lambda: _with_subject(rows=[[{"x": 1}, [{"...": DIGEST}]]]),
                 id="array-element-digest-in-nested-arrays"),
    pytest.param(lambda: _with_subject(deep=_nested(88, {"_sd": [DIGEST]})),
                 id="_sd-at-depth-92"),
    pytest.param(lambda: _with_subject(deep=_nested(96, {"_sd": DIGEST})),
                 id="_sd-at-depth-100-the-loaders-maximum"),
    pytest.param(lambda: _raw(_with_subject(**{"@sd": [DIGEST]}), {"@sd": r"_sd"}),
                 id="_sd-spelled-with-a-unicode-escape"),
    pytest.param(lambda: _raw(_with_subject(**{"@alg": "sha-256"}),
                              {"@alg": r"_sd_alg"}),
                 id="_sd_alg-spelled-with-unicode-escapes"),
    pytest.param(lambda: _raw(_with_subject(nationalities=["ES", {"@e": DIGEST}]),
                              {"@e": r"..."}),
                 id="ellipsis-spelled-with-unicode-escapes"),
]

WRONG_OR_RIGHT = pytest.mark.parametrize("signer", [KEY, STRANGER],
                                         ids=["right-key", "wrong-key"])


@WRONG_OR_RIGHT
@pytest.mark.parametrize("payload", MARKER_CASES)
def test_a_payload_carrying_an_sd_jwt_marker_is_not_a_vc_jwt(run, payload, signer):
    # The signature is valid for the right key, so only the marker refuses it. For the wrong
    # key it is the SAME refusal: the fence runs before the signature is checked, so the
    # verdict does not depend on a key (SignatureInvalid would mean the order was lost).
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        run(_jws(payload(), key=signer))
    assert excinfo.type is MalformedToken


def test_the_wrong_key_is_otherwise_a_signature_failure(run):
    # The control that gives the wrong-key cases above their meaning: without a marker the
    # same signer fails the signature check, so MalformedToken there came from the fence.
    with pytest.raises(SignatureInvalid) as excinfo:
        run(_jws(_claims(), key=STRANGER))
    assert excinfo.type is SignatureInvalid


def test_the_fence_runs_before_the_verification_key_is_loaded():
    # The suite is handed a JWK it cannot load. A marker still gets the fence's verdict; a
    # payload without one gets as far as the key.
    garbage = {"kty": "oct", "k": "AAAA"}
    marked = _jws(_with_subject(**{"_sd": [DIGEST]}))
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        VcJwtProofSuite().verify(marked, public_key_jwk=garbage)
    assert excinfo.type is MalformedToken
    with pytest.raises(ProofError, match="requires an EC P-256 key") as excinfo:
        VcJwtProofSuite().verify(_jws(_claims()), public_key_jwk=garbage)
    assert excinfo.type is ProofError


@pytest.mark.parametrize("wrappers, leaf, depth", [(88, {"_sd": [DIGEST]}, 93),
                                                   (96, {"_sd": DIGEST}, 100)])
def test_the_deep_cases_sit_inside_the_json_loaders_cap(wrappers, leaf, depth):
    # So the refusals above are the fence's, not the loader's ("not valid base64url JSON").
    # The second is the deepest payload the loader takes: a few more levels and it refuses.
    payload = _with_subject(deep=_nested(wrappers, leaf))
    assert _depth(payload) == depth
    assert not nesting_exceeds(payload)
    assert nesting_exceeds(_with_subject(deep=_nested(wrappers + 8, leaf))) is True


def test_reject_sd_jwt_payload_names_the_markers():
    with pytest.raises(MalformedToken) as excinfo:
        _reject_sd_jwt_payload(_with_subject(**{"_sd": [DIGEST]}))
    assert excinfo.type is MalformedToken
    message = str(excinfo.value)
    assert "SD-JWT issuer JWT, not a VC-JWT" in message
    assert all(name in message for name in ("_sd", "_sd_alg", '"..."'))
    assert _reject_sd_jwt_payload(_claims()) is None


# --------------------------------------------------------------------------- #
# B. controls: what is not a marker still verifies
# --------------------------------------------------------------------------- #

def _verified(result):
    assert result.issuer == DID
    assert result.subject == "did:example:alice"
    return result


@pytest.mark.parametrize("typ", [ABSENT, "JWT", "vc+jwt"], ids=["no-typ", "JWT", "vc+jwt"])
def test_a_vc_jwt_without_markers_verifies(run, typ):
    _verified(run(_jws(_claims(), typ=typ)))


def test_a_vc_jwt_signed_by_the_library_verifies(run):
    token = VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
         "credentialSubject": {"id": "did:example:alice", "name": "Ada"}}, signing_key=KEY)
    _verified(run(token))


# Names that look like a marker and are not one. The comparison is on the decoded member
# name, exact: no case folding, no trimming, no prefix or suffix match, no Unicode folding.
LOOK_ALIKE_NAMES = pytest.mark.parametrize("name", [
    "_sdx", "sd", "_SD", "_sd ", " _sd", "_sd_", "__sd", "_sd_algo", "_SD_ALG", "_sd_alg ",
    "..", "....", "…", ". . .",
], ids=repr)

PLACES = pytest.mark.parametrize("place", ["top-level", "subject", "in-an-array"])


def _place(place, member):
    """A VC-JWT payload carrying *member* (a one-entry dict) at *place*."""
    if place == "top-level":
        return _claims(**member)
    if place == "subject":
        return _with_subject(**member)
    return _with_subject(rows=[{"x": 1}, member, [member]])


@PLACES
@LOOK_ALIKE_NAMES
def test_a_look_alike_member_name_is_not_a_marker(run, name, place):
    _verified(run(_jws(_place(place, {name: DIGEST}))))


@PLACES
@pytest.mark.parametrize("value", ["_sd", "...", "_sd_alg"], ids=repr)
def test_a_string_value_that_spells_a_marker_is_not_a_marker(run, value, place):
    # Only a member NAME is reserved. A claim whose value is the string "_sd" is data.
    if place == "in-an-array":
        payload = _with_subject(rows=[value, [value]], note=value)
    else:
        payload = _place(place, {"note": value})
    _verified(run(_jws(payload)))


# --------------------------------------------------------------------------- #
# C. the #291 repro, and the residual
# --------------------------------------------------------------------------- #

def _holder_bound_sd_jwt(*, typ, shape="vc"):
    """A hand-minted, holder-bound SD-JWT whose issuer JWT holds a ``vc`` object and a
    ``cnf``. *shape* says where its one selectively disclosable claim lives: ``"vc"``,
    inside ``vc.credentialSubject``; ``"top"``, a top-level claim; ``"none"``, nowhere (a
    zero-disclosure SD-JWT: no ``_sd``, no ``_sd_alg``)."""
    vc = _vc()
    claims = {"iss": DID, "nbf": NBF, "cnf": {"jwk": HOLDER_KEY.public_jwk()}, "vc": vc,
              "member_since": 2019}
    disclosures = []
    if shape == "vc":
        disclosures.append(make_object_disclosure(
            _b64(secrets.token_bytes(16)), "name", vc["credentialSubject"].pop("name")))
        vc["credentialSubject"]["_sd"] = [disclosure_digest(disclosures[0])]
    elif shape == "top":
        disclosures.append(make_object_disclosure(
            _b64(secrets.token_bytes(16)), "member_since", claims.pop("member_since")))
        claims["_sd"] = [disclosure_digest(disclosures[0])]
    if disclosures:
        claims["_sd_alg"] = "sha-256"
    return _jws(claims, typ=typ) + "~" + "".join(d + "~" for d in disclosures)


def _tail_dropped(sd_jwt):
    """The issuer JWT alone: what a holder who drops the ``~`` tail hands to the VC-JWT lane."""
    return sd_jwt.split("~", 1)[0]


UNTYPED_OR_UNKNOWN_TYPS = pytest.mark.parametrize("typ", [
    ABSENT, "JWT", "vc+jwt", "example+jwt", "", None, 123,
], ids=["no-typ", "JWT", "vc+jwt", "example+jwt", "empty", "null", "number"])


@pytest.mark.parametrize("shape", ["vc", "top"])
@UNTYPED_OR_UNKNOWN_TYPS
def test_the_291_repro_an_untyped_holder_bound_sd_jwt_without_its_tail_is_refused(
        run, typ, shape):
    # The hole: with no `typ` (or one the typ filter does not know) the issuer JWT of a
    # holder-bound SD-JWT that holds a `vc` object verified on the VC-JWT lane once the
    # tail was dropped, and nothing asked for the key binding. It carries `_sd` and
    # `_sd_alg`, which a VC-JWT never does.
    sd_jwt = _holder_bound_sd_jwt(typ=typ, shape=shape)
    assert sd_jwt.endswith("~") and sd_jwt.count("~") == 2
    jws = _tail_dropped(sd_jwt)
    assert "~" not in jws
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        run(jws)
    assert excinfo.type is MalformedToken


@pytest.mark.parametrize("typ", ["vc+sd-jwt", "dc+sd-jwt", "vc+ld+json+sd-jwt", "sd-jwt"])
def test_a_typed_zero_disclosure_sd_jwt_is_still_refused_by_its_typ(run, typ):
    # What #189 closed, for contrast with the residual below: the typ names it.
    jws = _tail_dropped(_holder_bound_sd_jwt(typ=typ, shape="none"))
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        run(jws)
    assert excinfo.type is MalformedToken


@UNTYPED_OR_UNKNOWN_TYPS
def test_documented_limitation_291_a_zero_disclosure_untyped_sd_jwt_still_verifies_as_a_vc_jwt(
        pipeline, typ):
    # THE DOCUMENTED LIMITATION OF #291, PINNED ON PURPOSE. A zero-disclosure SD-JWT issuer
    # JWT with no `typ`, a `vc` object and a `cnf` has no `_sd`, no `_sd_alg` and no `...`:
    # it is byte for byte a VC-JWT that carries a `cnf`, and the VC-JWT lane has no key
    # binding to enforce. It verifies, and it says no key was bound (`key_bound is None`).
    # Whoever makes the lane refuse it (by reading `cnf`, say) must change THIS test.
    sd_jwt = _holder_bound_sd_jwt(typ=typ, shape="none")
    assert sd_jwt.count("~") == 1                       # the issuer JWT, `~`, no disclosure
    result = pipeline(_tail_dropped(sd_jwt))
    assert result.format == "vc-jwt"
    assert result.issuer == DID
    assert result.key_bound is None
    assert "cnf" in result.claims


def test_the_same_zero_disclosure_token_is_not_a_vc_jwt_once_it_has_a_disclosure():
    # The other side of the limitation: one selectively disclosable claim is enough.
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        verify_credential(_tail_dropped(_holder_bound_sd_jwt(typ=ABSENT, shape="vc")))
    assert excinfo.type is MalformedToken


# --------------------------------------------------------------------------- #
# D. verify_many keeps going
# --------------------------------------------------------------------------- #

def _many(credentials):
    return verify_many(credentials)


def _many_async(credentials):
    return asyncio.run(verify_many_async(credentials))


@pytest.fixture(params=["sync", "async"])
def batch(request):
    return {"sync": _many, "async": _many_async}[request.param]


def test_a_batch_with_a_marker_carrying_jws_returns_per_item_results(batch):
    good_one = _jws(_claims())
    marked = _jws(_with_subject(degrees=[{"school": {"_sd": [DIGEST]}}]))
    good_two = _jws(_claims(), typ="JWT")
    results = batch([good_one, marked, good_two])
    assert [item.index for item in results] == [0, 1, 2]
    assert [item.ok for item in results] == [True, False, True]
    assert results[0].result.issuer == DID and results[2].result.issuer == DID
    assert results[1].result is None
    assert type(results[1].error) is MalformedToken
    assert SD_JWT_MARKERS in str(results[1].error)


# --------------------------------------------------------------------------- #
# E. the VP-JWT lane: typ and markers, before the holder key is resolved
# --------------------------------------------------------------------------- #

class _Tripwire:
    """A resolver that fails the test when it is reached, and records that it was."""

    def __init__(self):
        self.calls = []

    def resolve(self, did):
        self.calls.append(did)
        raise AssertionError(f"the resolver was reached for {did!r}")


class _Counting:
    """The default offline resolver, recording what it was asked."""

    def __init__(self):
        self._inner = default_resolver()
        self.calls = []

    def resolve(self, did):
        self.calls.append(did)
        return self._inner.resolve(did)


def _vp_claims(credentials=(), **extra):
    now = int(time.time())              # a future `iat` is refused, so no fixed epoch
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],
          "verifiableCredential": list(credentials), "holder": HOLDER_DID}
    return {"iss": HOLDER_DID, "aud": AUD, "nonce": NONCE, "nbf": now, "iat": now, "vp": vp,
            **extra}


def _vp_jws(claims, *, typ=ABSENT, key=HOLDER_KEY):
    header = {"alg": "ES256", "kid": f"{HOLDER_DID}#0"}
    if typ is not ABSENT:
        header["typ"] = typ
    text = claims if isinstance(claims, str) else json.dumps(claims)
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(text.encode())}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"


def _embedded_vc():
    return VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": DID,
         "credentialSubject": {"id": HOLDER_DID, "name": "Ada"}}, signing_key=KEY)


def _vp_verify(vp_jwt, resolver, **kwargs):
    return VpJwtProofSuite().verify(vp_jwt, audience=AUD, nonce=NONCE, resolver=resolver,
                                    **kwargs)


SD_JWT_TYPS = pytest.mark.parametrize("typ", [
    "vc+sd-jwt", "dc+sd-jwt", "vc+ld+json+sd-jwt", "kb+jwt", "sd-jwt",
    "application/vc+sd-jwt", "VC+SD-JWT",
], ids=repr)


def test_the_tripwire_is_on_the_path_of_a_well_formed_vp_jwt():
    # Without this, "the resolver was not called" below would be true of a resolver nothing
    # ever calls.
    tripwire = _Tripwire()
    vp_jwt = VpJwtProofSuite().sign([_embedded_vc()], holder_key=HOLDER_KEY, audience=AUD,
                                    nonce=NONCE)
    with pytest.raises(AssertionError, match="the resolver was reached"):
        _vp_verify(vp_jwt, tripwire)
    assert tripwire.calls == [HOLDER_DID]


@SD_JWT_TYPS
def test_a_vp_jwt_typed_as_an_sd_jwt_is_refused_before_any_key_is_resolved(typ):
    tripwire = _Tripwire()
    vp_jwt = _vp_jws(_vp_claims([_embedded_vc()]), typ=typ)
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        _vp_verify(vp_jwt, tripwire)
    assert excinfo.type is MalformedToken
    assert tripwire.calls == []


@SD_JWT_TYPS
def test_a_vp_jwt_typed_as_an_sd_jwt_is_refused_before_the_signature_too(typ):
    # A pinned holder key and a signature by someone else: still the typ verdict.
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        _vp_verify(_vp_jws(_vp_claims(), typ=typ, key=STRANGER), _Tripwire(),
                   holder_key_jwk=HOLDER_KEY.public_jwk())
    assert excinfo.type is MalformedToken


VP_MARKER_CASES = [
    pytest.param(lambda: _vp_claims(**{"_sd": [DIGEST]}), id="top-level-_sd"),
    pytest.param(lambda: _vp_claims(**{"_sd_alg": "sha-256"}), id="top-level-_sd_alg-alone"),
    pytest.param(lambda: {**_vp_claims(), "vp": {**_vp_claims()["vp"], "_sd": [DIGEST]}},
                 id="_sd-in-vp"),
    pytest.param(lambda: _vp_claims([{"@context": [V2], "type": ["VerifiableCredential"],
                                      "credentialSubject": {"degrees": [{"_sd": [DIGEST]}]}}]),
                 id="_sd-in-an-embedded-credential-object"),
    pytest.param(lambda: _vp_claims(["urn:example:c", {"...": DIGEST}]),
                 id="array-element-digest-in-verifiableCredential"),
    pytest.param(lambda: _vp_claims(deep=_nested(85, {"_sd": [DIGEST]})),
                 id="_sd-at-depth-87"),
]


@pytest.mark.parametrize("typ", [ABSENT, "JWT", "vp+jwt"], ids=["no-typ", "JWT", "vp+jwt"])
@pytest.mark.parametrize("payload", VP_MARKER_CASES)
def test_a_vp_jwt_payload_carrying_a_marker_is_refused_before_any_key_is_resolved(
        payload, typ):
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        _vp_verify(_vp_jws(payload(), typ=typ), tripwire)
    assert excinfo.type is MalformedToken
    assert tripwire.calls == []


@pytest.mark.parametrize("payload", VP_MARKER_CASES)
def test_a_vp_jwt_payload_carrying_a_marker_is_refused_before_the_signature_too(payload):
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        _vp_verify(_vp_jws(payload(), key=STRANGER), _Tripwire(),
                   holder_key_jwk=HOLDER_KEY.public_jwk())
    assert excinfo.type is MalformedToken


def test_a_vp_jwt_by_the_wrong_key_is_otherwise_a_signature_failure():
    # The control for the two "before the signature" tests above.
    with pytest.raises(SignatureInvalid) as excinfo:
        _vp_verify(_vp_jws(_vp_claims(), key=STRANGER), _Tripwire(),
                   holder_key_jwk=HOLDER_KEY.public_jwk())
    assert excinfo.type is SignatureInvalid


def _library_signed():
    return VpJwtProofSuite().sign([_embedded_vc()], holder_key=HOLDER_KEY, audience=AUD,
                                  nonce=NONCE)


@pytest.mark.parametrize("build", [
    pytest.param(_library_signed, id="library-signed-typ-JWT"),
    pytest.param(lambda: _vp_jws(_vp_claims([_embedded_vc()])), id="no-typ"),
    pytest.param(lambda: _vp_jws(_vp_claims([_embedded_vc()]), typ="JWT"), id="typ-JWT"),
    pytest.param(lambda: _vp_jws(_vp_claims([_embedded_vc()]), typ="vp+jwt"), id="typ-vp+jwt"),
])
def test_a_vp_jwt_without_markers_or_an_sd_jwt_typ_still_verifies(build):
    counting = _Counting()
    result = _vp_verify(build(), counting)
    assert result.holder == HOLDER_DID
    (credential,) = result.credentials
    assert credential.issuer == DID
    assert counting.calls[0] == HOLDER_DID               # the holder key was resolved


# --------------------------------------------------------------------------- #
# F. OpenID4VP: a jwt_vc_json Presentation goes through the same fence
# --------------------------------------------------------------------------- #

DCQL = {"credentials": [{"id": "vp1", "format": "jwt_vc_json"}]}


def _answer(vp_jwt):
    return verify_vp_token({"vp1": [vp_jwt]}, dcql_query=DCQL, nonce=NONCE, client_id=AUD)


def test_a_jwt_vc_json_presentation_still_verifies():
    (presentation,) = _answer(_vp_jws(_vp_claims([_embedded_vc()]), typ="JWT")).for_query("vp1")
    assert presentation.format == "jwt_vc_json"
    assert presentation.holder == HOLDER_DID
    assert presentation.credentials[0].issuer == DID


@SD_JWT_TYPS
def test_a_jwt_vc_json_presentation_typed_as_an_sd_jwt_is_refused(typ):
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        _answer(_vp_jws(_vp_claims([_embedded_vc()]), typ=typ))
    assert excinfo.type is MalformedToken


@pytest.mark.parametrize("payload", VP_MARKER_CASES)
def test_a_jwt_vc_json_presentation_carrying_a_marker_is_refused(payload):
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        _answer(_vp_jws(payload()))
    assert excinfo.type is MalformedToken


# --------------------------------------------------------------------------- #
# G. _carries_sd_jwt_marker itself
# --------------------------------------------------------------------------- #

MARKER_NAMES = ["_sd", "_sd_alg", "..."]
# Values that look like markers but are strings, and names that are not markers.
DECOY_VALUES = [None, True, 7, 1.5, "x", "_sd", "_sd_alg", "..."]
DECOY_NAMES = ["a", "_sdx", "sd", "_SD", "_sd ", "....", "…", "vc", "_sd_algo"]


def _random_tree(rng, depth, spine):
    """A marker-free JSON-like tree. *spine* is a guaranteed path down to *depth* levels;
    every other branch is shallow and random."""
    if depth <= 1:
        return rng.choice(DECOY_VALUES)
    children = [_random_tree(rng, rng.randint(0, min(2, depth - 1)), False)
                for _ in range(rng.randint(0, 2))]
    if spine:
        children.insert(rng.randint(0, len(children)), _random_tree(rng, depth - 1, True))
    if rng.random() < 0.5:
        first = rng.randrange(len(DECOY_NAMES))        # distinct names: no child is overwritten
        return {DECOY_NAMES[(first + i) % len(DECOY_NAMES)]: child
                for i, child in enumerate(children)}
    return children


def _containers(tree):
    """Every dict and list in *tree*, iteratively."""
    found, stack = [], [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            found.append(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            found.append(node)
            stack.extend(node)
    return found


@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("depth", [2, 5, 20, 50])
def test_a_marker_is_found_at_every_position_and_never_when_it_is_not_there(seed, depth):
    rng = random.Random(f"{seed}/{depth}")
    tree = _random_tree(rng, depth + 1, True)          # `depth` levels of containers
    assert _depth(tree) == depth
    assert _carries_sd_jwt_marker(tree) is False
    containers = _containers(tree)
    assert len(containers) >= depth
    planted = 0
    for container in containers:
        for name in MARKER_NAMES:
            if isinstance(container, dict):
                container[name] = [DIGEST]
                assert _carries_sd_jwt_marker(tree) is True, (name, "as a member")
                del container[name]
            else:
                container.append({name: DIGEST})
                assert _carries_sd_jwt_marker(tree) is True, (name, "as an array element")
                container.pop()
            planted += 1
            assert _carries_sd_jwt_marker(tree) is False
    assert planted == 3 * len(containers)


@pytest.mark.parametrize("depth", [1, 2, 10, 50])
@pytest.mark.parametrize("name", MARKER_NAMES)
def test_a_marker_at_the_end_of_a_chain_is_found_whatever_the_chain_is_made_of(depth, name):
    for link in (lambda inner: {"k": inner}, lambda inner: [inner],
                 lambda inner: [{"k": [inner]}]):
        with_marker, without = {name: DIGEST}, {"a": DIGEST}
        for _ in range(depth):
            with_marker, without = link(with_marker), link(without)
        assert _carries_sd_jwt_marker(with_marker) is True
        assert _carries_sd_jwt_marker(without) is False


@pytest.mark.parametrize("node", [None, True, 7, "_sd", "...", "_sd_alg", [], {}, [[]], {"a": {}}],
                         ids=repr)
def test_a_value_with_no_marker_is_clean(node):
    assert _carries_sd_jwt_marker(node) is False


@pytest.mark.parametrize("link", [
    pytest.param(lambda inner: [inner], id="lists"),
    pytest.param(lambda inner: {"k": inner}, id="dicts"),
    pytest.param(lambda inner: [{"k": inner}], id="lists-and-dicts"),
])
def test_the_walk_does_not_recurse(link):
    # Built by hand, 5000 levels deep: the JSON loader would refuse it (its cap is 100), and
    # a recursive walk would hit the interpreter's recursion limit first.
    with_marker, without = {"_sd": [DIGEST]}, {"a": DIGEST}
    for _ in range(5000):
        with_marker, without = link(with_marker), link(without)
    assert nesting_exceeds(with_marker)
    assert _carries_sd_jwt_marker(with_marker) is True
    assert _carries_sd_jwt_marker(without) is False


# --------------------------------------------------------------------------- #
# H. the ML-DSA lane is fenced too
# --------------------------------------------------------------------------- #

needs_mldsa = pytest.mark.skipif(
    not mldsa_available(), reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")


def _pq_jws(payload, key, *, typ=ABSENT):
    """Sign *payload* with the ML-DSA *key*, under a header naming the issuer's ``<DID>#0``."""
    header = {"alg": key.alg, "kid": f"{DID}#0"}
    if typ is not ABSENT:
        header["typ"] = typ
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    return f"{signing_input}.{_b64(key.sign(signing_input.encode('ascii')))}"


@pytest.fixture(scope="module")
def pq_key():
    return MLDSASigningKey.generate(kid=f"{DID}#0", alg="ML-DSA-65")


@pytest.fixture(scope="module")
def pq_stranger():
    return MLDSASigningKey.generate(kid=f"{DID}#0", alg="ML-DSA-65")


def _pq_verification_key(which, key, stranger):
    """What the suite is handed to verify with: the right key, a wrong ML-DSA key of the same
    parameter set, and three public JWKs the primitive cannot load."""
    return {
        "right-key": key.public_jwk(),
        "wrong-key": stranger.public_jwk(),
        "no-pub": {"kty": "AKP", "alg": key.alg},
        "short-pub": {"kty": "AKP", "alg": key.alg, "pub": "AAAA"},
        "not-akp": {"kty": "oct", "k": "AAAA"},
    }[which]


PQ_KEYS = pytest.mark.parametrize(
    "which", ["right-key", "wrong-key", "no-pub", "short-pub", "not-akp"])

PQ_MARKER_CASES = [
    pytest.param(lambda: _with_subject(**{"_sd": [DIGEST]}), id="_sd-in-credentialSubject"),
    pytest.param(lambda: _claims(**{"_sd_alg": "sha-256"}), id="top-level-_sd_alg-alone"),
    pytest.param(lambda: _with_subject(nationalities=["ES", {"...": DIGEST}]),
                 id="array-element-digest"),
]


@needs_mldsa
@PQ_KEYS
@pytest.mark.parametrize("payload", PQ_MARKER_CASES)
def test_an_ml_dsa_vc_jwt_carrying_an_sd_jwt_marker_is_refused_whatever_key_it_meets(
        payload, which, pq_key, pq_stranger):
    # The fence sits on the `allow_pq=True` branch too (not only the classic `else:` one),
    # and before the key is loaded: the same verdict for the right key, a wrong one and a
    # JWK that cannot be loaded at all (the controls below say what those are otherwise).
    token = _pq_jws(payload(), pq_key)
    jwk = _pq_verification_key(which, pq_key, pq_stranger)
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        VcJwtProofSuite(allow_pq=True).verify(token, public_key_jwk=jwk)
    assert excinfo.type is MalformedToken


@needs_mldsa
def test_an_ml_dsa_vc_jwt_without_markers_verifies(pq_key):
    # The control: the same signer, the same suite, no marker.
    result = VcJwtProofSuite(allow_pq=True).verify(
        _pq_jws(_claims(), pq_key), public_key_jwk=pq_key.public_jwk())
    assert result.issuer == DID
    assert result.subject == "did:example:alice"


@needs_mldsa
@pytest.mark.parametrize("which", ["wrong-key", "no-pub", "short-pub", "not-akp"])
def test_without_a_marker_an_ml_dsa_vc_jwt_meets_its_key(which, pq_key, pq_stranger):
    # The control that gives the cases above their meaning: absent a marker, each of these
    # keys is a failure at the key or the signature, so MalformedToken came from the fence.
    jwk = _pq_verification_key(which, pq_key, pq_stranger)
    with pytest.raises(SignatureInvalid) as excinfo:
        VcJwtProofSuite(allow_pq=True).verify(_pq_jws(_claims(), pq_key), public_key_jwk=jwk)
    assert excinfo.type is SignatureInvalid


@needs_mldsa
def test_the_default_suite_refuses_ml_dsa_at_the_allow_list_before_the_fence(pq_key):
    # ADR-0004: without `allow_pq` the algorithm is refused before anything else is read.
    token = _pq_jws(_with_subject(**{"_sd": [DIGEST]}), pq_key)
    with pytest.raises(UnsupportedAlgorithm, match="is not permitted") as excinfo:
        VcJwtProofSuite().verify(token, public_key_jwk=pq_key.public_jwk())
    assert excinfo.type is UnsupportedAlgorithm


# --------------------------------------------------------------------------- #
# I. markers in sibling claims
# --------------------------------------------------------------------------- #

def _vc_with(**members):
    vc = _vc()
    vc.update(members)
    return vc


SIBLING_CASES = [
    pytest.param(lambda: _claims(address={"street": "1 Main St", "_sd": [DIGEST]}),
                 id="top-level-address"),
    pytest.param(lambda: _claims(cnf={"jwk": HOLDER_KEY.public_jwk(), "_sd": [DIGEST]}),
                 id="_sd-in-cnf"),
    pytest.param(lambda: _claims(cnf={"_sd": [DIGEST]}), id="_sd-alone-in-cnf"),
    pytest.param(lambda: _claims(evidence=[{"id": "urn:e:1"}, {"_sd": [DIGEST]}]),
                 id="_sd-in-a-top-level-evidence-element"),
    pytest.param(lambda: _claims(evidence=[{"id": "urn:e:1"}, {"...": DIGEST}]),
                 id="array-element-digest-in-a-top-level-evidence-element"),
    pytest.param(lambda: _claims(extra={"a": [{"b": {"_sd_alg": "sha-256"}}]}),
                 id="_sd_alg-deep-in-a-top-level-claim"),
    pytest.param(lambda: _claims(_vc_with(evidence=[{"type": ["DocumentVerification"]},
                                                    {"_sd": [DIGEST]}])),
                 id="_sd-in-vc.evidence-element"),
    pytest.param(lambda: _claims(_vc_with(issuer={"id": DID, "_sd": [DIGEST]})),
                 id="_sd-in-vc.issuer"),
    pytest.param(lambda: _claims(_vc_with(credentialStatus={"type": "x", "_sd_alg": "sha-256"})),
                 id="_sd_alg-in-vc.credentialStatus"),
]


@WRONG_OR_RIGHT
@pytest.mark.parametrize("payload", SIBLING_CASES)
def test_a_marker_in_a_claim_other_than_the_credential_subject_is_refused(run, payload, signer):
    # The walk covers the whole payload, not `vc` and not `credentialSubject` alone.
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        run(_jws(payload(), key=signer))
    assert excinfo.type is MalformedToken


@pytest.mark.parametrize("payload", [
    pytest.param(lambda: _claims(address={"street": "1 Main St"}), id="address"),
    pytest.param(lambda: _claims(cnf={"jwk": HOLDER_KEY.public_jwk()}), id="cnf"),
    pytest.param(lambda: _claims(evidence=[{"id": "urn:e:1"}, {"id": "urn:e:2"}]),
                 id="evidence"),
])
def test_the_same_sibling_claims_without_a_marker_verify(run, payload):
    _verified(run(_jws(payload())))


# --------------------------------------------------------------------------- #
# J. wide payloads
# --------------------------------------------------------------------------- #

WIDE = 400_000                        # elements in the sibling array


def _wide(placement):
    """A payload whose marker is visited AFTER (the walk is LIFO) or BEFORE (a FIFO mutant)
    the 400 000 small integers of a sibling array."""
    marker, ints = {"_sd": [DIGEST]}, [0] * WIDE
    if placement == "first-in-the-array":              # popped last by the real walk
        return _claims(extra=[marker] + ints)
    if placement == "last-in-the-array":               # popped last by a pop(0) walk
        return _claims(extra=ints + [marker])
    if placement == "member-before-the-array":         # dict order: popped after the array
        return _claims(note=marker, extra=ints)
    return _claims(extra=ints, note=marker)            # member-after-the-array


@functools.lru_cache(maxsize=None)
def _wide_jws(placement):
    return _jws(_wide(placement))


WIDE_PLACEMENTS = pytest.mark.parametrize("placement", [
    "first-in-the-array", "last-in-the-array", "member-before-the-array",
    "member-after-the-array",
])


@WIDE_PLACEMENTS
def test_a_marker_after_a_wide_sibling_array_is_still_refused(run, placement):
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        run(_wide_jws(placement))
    assert excinfo.type is MalformedToken


def test_the_wide_payload_without_the_marker_verifies(run):
    # The control: 400 000 integers are no reason to refuse (no size cut-off either way).
    _verified(run(_jws(_claims(extra=[0] * WIDE))))


@pytest.mark.parametrize("position", ["last", "first"])
@pytest.mark.parametrize("length", [10_002, 10_001])
def test_an_array_element_digest_in_a_long_array_is_refused(run, length, position):
    # 10 000 elements is no limit: the digest object sits at either end of a longer array.
    digest, filler = {"...": DIGEST}, [0] * (length - 1)
    rows = filler + [digest] if position == "last" else [digest] + filler
    assert len(rows) == length
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        run(_jws(_with_subject(rows=rows)))
    assert excinfo.type is MalformedToken
    assert _carries_sd_jwt_marker(rows) is True


def test_a_wide_array_is_walked_in_linear_time():
    # The real walk takes about 0.01 s here; one that pops from the FRONT of its work list
    # is quadratic and takes tens of seconds. Both orders of the marker, and no marker.
    for tree, expected in (({"extra": [0] * WIDE}, False),
                           ({"extra": [{"_sd": [DIGEST]}] + [0] * WIDE}, True),
                           ({"extra": [0] * WIDE + [{"...": DIGEST}]}, True)):
        started = time.perf_counter()
        found = _carries_sd_jwt_marker(tree)
        elapsed = time.perf_counter() - started
        assert found is expected
        assert elapsed < 5, f"walking {WIDE} elements took {elapsed:.1f} s"


# --------------------------------------------------------------------------- #
# K. the VP-JWT order of checks: algorithm, crit, typ, markers, then the key
# --------------------------------------------------------------------------- #

def _vp_raw(header, claims):
    """A VP-JWT-shaped token whose header is written as given. The signature is a dummy: every
    test using it is refused before a signature is looked at (or must be)."""
    text = claims if isinstance(claims, str) else json.dumps(claims)
    return f"{_b64(json.dumps(header).encode())}.{_b64(text.encode())}.{_b64(bytes(64))}"


def _vp_header(**members):
    return {"alg": "ES256", "kid": f"{HOLDER_DID}#0", **members}


def _vp_claims_without_vp(**extra):
    now = int(time.time())
    return {"iss": HOLDER_DID, "aud": AUD, "nonce": NONCE, "nbf": now, "iat": now, **extra}


CRIT_MESSAGE = "'crit' extensions are not supported"


@pytest.mark.parametrize("header", [
    pytest.param({"alg": "none"}, id="alg-none"),
    pytest.param({"alg": "none", "typ": "vc+sd-jwt"}, id="alg-none-and-an-sd-jwt-typ"),
    pytest.param({"alg": "none", "typ": "vc+sd-jwt", "crit": ["x"], "x": 1},
                 id="alg-none-sd-jwt-typ-and-crit"),
    pytest.param({"alg": "HS256", "typ": "kb+jwt"}, id="alg-HS256-and-an-sd-jwt-typ"),
    pytest.param({"typ": "vc+sd-jwt"}, id="no-alg"),
    pytest.param({"alg": ["ES256"]}, id="alg-an-array"),
    pytest.param({"alg": "ML-DSA-65", "typ": "vc+sd-jwt"}, id="alg-ML-DSA-65-not-opted-in"),
])
@pytest.mark.parametrize("payload", VP_MARKER_CASES[:3])
def test_the_vp_jwt_algorithm_allow_list_runs_before_the_typ_and_marker_fences(
        header, payload):
    # Same order as the VC-JWT lane: the allow-list first. A fence moved above it would
    # answer MalformedToken (typ or marker) to a token whose algorithm is the first problem.
    tripwire = _Tripwire()
    with pytest.raises(UnsupportedAlgorithm, match="is not permitted") as excinfo:
        _vp_verify(_vp_raw(header, payload()), tripwire)
    assert excinfo.type is UnsupportedAlgorithm
    assert tripwire.calls == []


@pytest.mark.parametrize("header", [
    pytest.param(_vp_header(crit=["x"], x=1), id="crit-unknown"),
    pytest.param(_vp_header(crit=["x"], x=1, typ="vc+sd-jwt"), id="crit-and-an-sd-jwt-typ"),
    pytest.param(_vp_header(crit=[]), id="crit-empty"),
])
@pytest.mark.parametrize("payload", VP_MARKER_CASES[:3])
def test_the_vp_jwt_crit_check_runs_before_the_typ_and_marker_fences(header, payload):
    # After the algorithm, `crit` is the next verdict, and it is the lane's own wording:
    # neither the typ message nor the marker message. Before any key is resolved.
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=CRIT_MESSAGE) as excinfo:
        _vp_verify(_vp_raw(header, payload()), tripwire)
    assert excinfo.type is MalformedToken
    assert NOT_A_VC_JWT not in str(excinfo.value)
    assert SD_JWT_MARKERS not in str(excinfo.value)
    assert tripwire.calls == []


def test_a_vp_jwt_with_an_unknown_crit_is_refused_before_any_key_is_resolved():
    # With no marker and no typ at all: the `crit` refusal is not the fences' doing.
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=CRIT_MESSAGE) as excinfo:
        _vp_verify(_vp_raw(_vp_header(crit=["x"], x=1), _vp_claims()), tripwire)
    assert excinfo.type is MalformedToken
    assert tripwire.calls == []


@pytest.mark.parametrize("typ", ["vc+sd-jwt", "kb+jwt"])
@pytest.mark.parametrize("payload", VP_MARKER_CASES[:3])
def test_a_vp_jwt_with_a_bad_typ_and_a_marker_gets_the_typ_verdict(typ, payload):
    # Typ before markers, as on the VC-JWT lane: both are present, the typ message wins.
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        _vp_verify(_vp_raw(_vp_header(typ=typ), payload()), tripwire)
    assert excinfo.type is MalformedToken
    assert SD_JWT_MARKERS not in str(excinfo.value)
    assert tripwire.calls == []


def test_the_vc_jwt_lane_gives_a_bad_typ_and_a_marker_the_same_typ_verdict():
    # The order the VP-JWT lane copies.
    token = _jws(_with_subject(**{"_sd": [DIGEST]}), typ="vc+sd-jwt")
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        VcJwtProofSuite().verify(token, public_key_jwk=KEY.public_jwk())
    assert SD_JWT_MARKERS not in str(excinfo.value)
    assert excinfo.type is MalformedToken


def _holderless_claims(**extra):
    claims = _vp_claims(**extra)
    del claims["iss"]
    del claims["vp"]["holder"]
    return claims


@pytest.mark.parametrize("claims", [
    pytest.param(lambda: _holderless_claims(**{"_sd": [DIGEST]}), id="no-holder"),
    pytest.param(lambda: _vp_claims_without_vp(**{"_sd": [DIGEST], "iss": "did:example:nobody"}),
                 id="an-issuer-no-resolver-knows"),
])
def test_a_vp_jwt_whose_holder_cannot_be_resolved_still_gets_the_marker_verdict(claims):
    # The holder is the lane's second problem here: the marker is refused first, and nothing
    # is resolved (a tripwire resolver would fail the test, and "no holder" is another text).
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        _vp_verify(_vp_jws(claims()), tripwire)
    assert excinfo.type is MalformedToken
    assert "no holder" not in str(excinfo.value)
    assert tripwire.calls == []


def test_a_vp_jwt_with_no_holder_and_no_marker_says_so():
    # The control for the test above.
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match="has no holder") as excinfo:
        _vp_verify(_vp_jws(_holderless_claims()), tripwire)
    assert excinfo.type is MalformedToken
    assert tripwire.calls == []


# A payload with NO `vp` object: the fence reads the whole payload, not `vp`.
NO_VP_MARKER_CASES = [
    pytest.param(lambda: _vp_claims_without_vp(**{"_sd": [DIGEST]}), id="top-level-_sd"),
    pytest.param(lambda: _vp_claims_without_vp(**{"_sd_alg": "sha-256"}),
                 id="top-level-_sd_alg-alone"),
    pytest.param(lambda: _vp_claims_without_vp(**{"...": DIGEST}), id="top-level-ellipsis"),
    pytest.param(lambda: _vp_claims_without_vp(cnf={"_sd": [DIGEST]}), id="_sd-in-cnf"),
    pytest.param(lambda: _vp_claims_without_vp(vp="a string", **{"_sd": [DIGEST]}),
                 id="vp-a-string"),
    pytest.param(lambda: _vp_claims_without_vp(vp=[{"_sd": [DIGEST]}]), id="vp-an-array"),
]


@pytest.mark.parametrize("claims", NO_VP_MARKER_CASES)
def test_a_vp_jwt_payload_with_no_vp_object_is_fenced_all_the_same(claims):
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=SD_JWT_MARKERS) as excinfo:
        _vp_verify(_vp_jws(claims()), tripwire)
    assert excinfo.type is MalformedToken
    assert tripwire.calls == []


def test_a_vp_jwt_payload_with_no_vp_object_and_no_marker_reaches_the_resolver():
    # The control: the tripwire is on this path, so "zero calls" above is not vacuous.
    tripwire = _Tripwire()
    with pytest.raises(AssertionError, match="the resolver was reached"):
        _vp_verify(_vp_jws(_vp_claims_without_vp()), tripwire)
    assert tripwire.calls == [HOLDER_DID]


# --------------------------------------------------------------------------- #
# L. a hostile typ is echoed bounded
# --------------------------------------------------------------------------- #

HUGE_TYP = "x" * 1_000_000 + "+sd-jwt"
BOUND = 500                           # characters: the message names the problem, not the typ


def test_a_huge_typ_is_echoed_bounded_by_the_vc_jwt_lane(run):
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        run(_jws(_claims(), typ=HUGE_TYP))
    assert excinfo.type is MalformedToken
    assert len(str(excinfo.value)) < BOUND


def test_a_huge_typ_is_echoed_bounded_by_the_vp_jwt_lane():
    tripwire = _Tripwire()
    with pytest.raises(MalformedToken, match=NOT_A_VC_JWT) as excinfo:
        _vp_verify(_vp_jws(_vp_claims(), typ=HUGE_TYP), tripwire)
    assert excinfo.type is MalformedToken
    assert len(str(excinfo.value)) < BOUND
    assert tripwire.calls == []


def test_a_short_typ_is_still_quoted_in_full():
    # The bound cuts hostile input, not an ordinary typ: the message still names it.
    with pytest.raises(MalformedToken, match=r"typed 'vc\+sd-jwt' is not a VC-JWT"):
        VcJwtProofSuite().verify(_jws(_claims(), typ="vc+sd-jwt"),
                                 public_key_jwk=KEY.public_jwk())
