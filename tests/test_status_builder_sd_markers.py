"""
tests/test_status_builder_sd_markers.py — the status-list credential builder refuses an
``issuer`` object or an inline ``@context`` object that carries an SD-JWT marker (#309).

``VcJwtProofSuite.verify`` refuses a payload with a member named ``_sd``, ``_sd_alg`` or
``"..."`` at ANY depth (it is an SD-JWT issuer JWT, not a VC-JWT: #189, #291), and
``build_status_list_credential`` accepted any member of an ``issuer`` or context object, so the
builder minted a list that its own default resolver then refused::

    issuer = {"...": None, "id": "did:a:0"}          # also {"_sd": []}, {"_sd_alg": "sha-256"}
    vc = build_status_list_credential(issuer=issuer, ...)
    wire = VcJwtProofSuite().sign(vc, signing_key=key)
    default_status_list_resolver(...)(LIST_URL)      # MalformedToken: carries SD-JWT markers

The builder cannot know which lane will secure the list and VC-JWT is the default, so the rule
holds on every lane: ``StatusListError`` at build time, before anything is signed, naming the
field and the three reserved keys and never echoing the object. The test is the lane's own
predicate (``vc_jwt._carries_sd_jwt_marker``), run on the JSON the object encodes to, so a
``tuple`` (an array on the wire, which the predicate does not walk as a Python object) cannot
carry a marker through, and a cycle (which the predicate would never leave) is a typed error
instead of a hang.

A. Negatives: each of the three keys, at the top of the issuer, nested, in a list, in a tuple,
   deep, in a ``dict`` subclass, under a ``str``-subclass key, and in an inline context object
   (the same placements), asserted against the EXACT class ``StatusListError`` with a key that
   fails the test if it is ever asked to sign, plus a 60 KB sentinel that must not reach the
   message.
B. Controls that must still build, sign and verify (VC-JWT and ``eddsa-jcs-2022``, through the
   default resolver): an ordinary issuer object, the marker as a VALUE, near-miss names, a
   tuple, an int key, ordinary context objects; and a member that is not JSON, which builds and
   fails at sign as before.
C. Cycles, past-the-limit nesting and keys that are no scalar: a typed error, never a hang.
D. Parity with the lane: for each object, the builder refuses it exactly when the same object
   signed by hand (around the builder) is refused by the default resolver.
E. The end-to-end property: whatever the builder accepts, the pipeline accepts, with the
   counterexample of #309 pinned as an ``@example``.

Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import example, given, settings
from hypothesis import strategies as st

from openvc.did.base import parse_did_document
from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import MalformedToken
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.resolvers import default_status_list_resolver
from openvc.status import StatusListError, build_status_list_credential, new_bitstring

VC2 = "https://www.w3.org/ns/credentials/v2"
VC1 = "https://www.w3.org/2018/credentials/v1"
LIST_URL = "https://status.example/w3c/1"
BIG = "S" * 60_000          # a 60 KB sentinel: must never reach an error message
MARKERS = ("_sd", "_sd_alg", "...")

PRIV = ed25519.Ed25519PrivateKey.generate()
JWK = Ed25519SigningKey(PRIV, "_").public_jwk()
DID = "did:jwk:" + base64.urlsafe_b64encode(json.dumps(JWK).encode()).rstrip(b"=").decode()
SK = Ed25519SigningKey(PRIV, f"{DID}#0")
BITS = new_bitstring(64)


class _SignedTooEarly(AssertionError):
    pass


class _ExplodingKey:
    """A key that must never be asked to sign: every refusal below has to happen at build
    time, before ``VcJwtProofSuite.sign`` reaches it."""

    alg = "EdDSA"
    kid = f"{DID}#0"

    def sign(self, signing_input: bytes) -> bytes:
        raise _SignedTooEarly("the builder minted an artefact it should have refused")


class _AnyDid:
    """A registry that serves the test key for ANY DID string, so key resolution cannot mask
    the field under test."""

    def supports(self, did: str) -> bool:
        return True

    def resolve(self, did: str) -> Any:
        method = f"{did}#0"
        return parse_did_document({
            "id": did,
            "verificationMethod": [{"id": method, "type": "JsonWebKey2020",
                                    "controller": did, "publicKeyJwk": JWK}],
            "assertionMethod": [method],
            "authentication": [method],
        })


def cred(**kw: Any) -> dict[str, Any]:
    kw.setdefault("issuer", DID)
    return build_status_list_credential(id=LIST_URL, bitstring=BITS, **kw)


def build_then_sign_unsigned(**kw: Any) -> str:
    """Build, then sign with a key that explodes: a builder that accepted the input fails the
    test with ``_SignedTooEarly``, never with the class we assert."""
    return VcJwtProofSuite().sign(cred(**kw), signing_key=_ExplodingKey())


def refused(call: Any, *, names: str | None = None) -> StatusListError:
    with pytest.raises(Exception) as caught:
        call()
    exc = caught.value
    assert type(exc) is StatusListError, f"{type(exc).__name__}: {exc}"
    assert isinstance(exc, OpenvcError)
    if names is not None:
        assert names in str(exc), str(exc)
    return exc


def sign_and_resolve(vc: dict[str, Any], lane: str) -> dict[str, Any]:
    """Secure *vc* on *lane* and read it back through ``default_status_list_resolver``."""
    issuer = vc["issuer"]
    did = issuer if isinstance(issuer, str) else issuer["id"]
    key = Ed25519SigningKey(PRIV, f"{did}#0")
    if lane == "vc-jwt":
        wire = VcJwtProofSuite().sign(vc, signing_key=key)
    else:
        wire = json.dumps(EddsaJcsProofSuite().add_proof(
            vc, signing_key=key, verification_method=f"{did}#0"))
    return default_status_list_resolver(resolver=_AnyDid(), fetch=lambda u: wire)(LIST_URL)


class _DictSub(dict):
    """A ``dict`` subclass: the encoder reads it through ``items()``."""


class _StrKey(str):
    """A ``str`` subclass used as a key: the encoder writes the characters it holds."""


# --------------------------------------------------------------------------- #
# A. Negatives: the issuer
# --------------------------------------------------------------------------- #

def _placements(marker: str, sentinel: Any = BIG) -> dict[str, dict[str, Any]]:
    """Issuer objects that are well formed apart from a *marker* member, at each depth."""
    return {
        "top": {"id": DID, marker: sentinel},
        "top-list-value": {"id": DID, marker: [sentinel]},
        "nested-dict": {"id": DID, "n": {marker: sentinel}},
        "nested-deep": {"id": DID, "a": {"b": {"c": {"d": {marker: sentinel}}}}},
        "in-list": {"id": DID, "n": [1, "x", {marker: sentinel}]},
        "list-in-list": {"id": DID, "n": [[{marker: sentinel}]]},
        "in-tuple": {"id": DID, "n": (1, {marker: sentinel})},
        "tuple-in-tuple": {"id": DID, "n": ((({marker: sentinel},),),)},
        "dict-subclass": {"id": DID, "n": _DictSub({marker: sentinel})},
        "str-subclass-key": {"id": DID, "n": {_StrKey(marker): sentinel}},
        "beside-name": {"id": DID, "name": "Example issuer", "n": {marker: sentinel}},
    }


_ISSUER_CASES = [pytest.param(marker, where, id=f"{marker}-{where}")
                 for marker in MARKERS for where in _placements("x")]


@pytest.mark.parametrize(("marker", "where"), _ISSUER_CASES)
def test_the_issuer_refuses_a_marker_member_at_any_depth(marker, where):
    issuer = _placements(marker)[where]
    exc = refused(lambda: build_then_sign_unsigned(issuer=issuer), names="issuer")
    message = str(exc)
    assert all(f"`{m}`" in message for m in MARKERS)         # it names the three reserved keys
    assert "S" * 40 not in message and DID not in message     # and never echoes the object
    assert len(message) < 600


@pytest.mark.parametrize("marker", MARKERS)
def test_the_refusal_is_the_builders_and_comes_before_the_key_is_asked(marker):
    # no signing at all: the credential builder itself raises, for every lane.
    refused(lambda: cred(issuer={"id": DID, marker: None}), names="issuer")
    refused(lambda: cred(issuer={"id": DID, "n": {marker: None}}, subject_id="x", ttl=5),
            names="issuer")


def test_the_issuer_is_not_mutated_by_the_refusal():
    issuer = {"id": DID, "n": {"_sd": []}}
    refused(lambda: cred(issuer=issuer))
    assert issuer == {"id": DID, "n": {"_sd": []}}


@pytest.mark.parametrize("marker", MARKERS)
def test_every_marker_is_refused_with_the_others_beside_ordinary_members(marker):
    issuer = {"id": DID, "name": "x", "url": "https://x/", "logo": {"id": "https://x/l.png"},
              "tags": ["a", "b"], "n": {"deep": [{"k": "v"}, {marker: 1}]}}
    refused(lambda: cred(issuer=issuer), names="issuer")


# --------------------------------------------------------------------------- #
# A. Negatives: an inline @context object
# --------------------------------------------------------------------------- #

def _context_cases() -> list[Any]:
    out: list[Any] = []
    for marker in MARKERS:
        for where, ctx in {
            "top": {marker: BIG},
            "beside-vocab": {"@vocab": "https://example.org/terms#", marker: BIG},
            "nested": {"@vocab": "https://example.org/terms#", "n": {marker: BIG}},
            "in-list": {"n": [{"k": 1}, {marker: BIG}]},
            "in-tuple": {"n": ({marker: BIG},)},
            "dict-subclass": _DictSub({"n": {marker: BIG}}),
        }.items():
            out.append(pytest.param(marker, ctx, id=f"{marker}-{where}"))
    return out


@pytest.mark.parametrize(("marker", "ctx"), _context_cases())
def test_a_context_object_refuses_a_marker_member_at_any_depth(marker, ctx):
    exc = refused(lambda: build_then_sign_unsigned(contexts=[VC2, ctx]), names="contexts[1]")
    message = str(exc)
    assert all(f"`{m}`" in message for m in MARKERS)
    assert "S" * 40 not in message and len(message) < 600


@pytest.mark.parametrize("marker", MARKERS)
def test_the_position_of_the_offending_context_entry_is_named(marker):
    contexts = [VC2, "https://example.org/ctx", {"@vocab": "https://example.org/terms#"},
                {"n": {marker: 1}}]
    refused(lambda: cred(contexts=contexts), names="contexts[3]")
    refused(lambda: cred(contexts=tuple(contexts)), names="contexts[3]")


@pytest.mark.parametrize("marker", MARKERS)
def test_a_marker_in_either_input_is_refused_when_the_other_is_fine(marker):
    refused(lambda: cred(issuer={"id": DID, marker: 1}, contexts=[VC2, {"@vocab": "https://x/"}]),
            names="issuer")
    refused(lambda: cred(issuer={"id": DID, "name": "ok"}, contexts=[VC2, {marker: 1}]),
            names="contexts[1]")


# --------------------------------------------------------------------------- #
# B. Controls: what must still build, sign and verify
# --------------------------------------------------------------------------- #

_CONTROL_ISSUERS = {
    "string": DID,
    "id-only": {"id": DID},
    "name": {"id": DID, "name": "Example issuer"},
    "marker-as-a-value": {"id": DID, "name": "..."},
    "marker-names-as-values": {"id": DID, "a": "_sd", "b": "_sd_alg", "c": "..."},
    "marker-names-as-array-elements": {"id": DID, "a": ["...", "_sd", "_sd_alg"]},
    "marker-names-as-nested-values": {"id": DID, "x": {"name": "_sd", "kind": "..."}},
    "near-miss-names": {"id": DID, "sd": 1, "_sdx": 2, "x_sd": 3, "_SD": 4, "..": 5,
                        "....": 6, "_sd_alg ": 7, " _sd": 8, "…": 9, "_sd-alg": 10},
    "ordinary-nesting": {"id": DID, "logo": {"id": "https://x/l.png", "alt": [1, {"a": 2}]}},
    "a-tuple": {"id": DID, "tags": ("a", ("b", "c"))},
    "a-dict-subclass": {"id": DID, "n": _DictSub({"k": "v"})},
    "null-and-numbers": {"id": DID, "a": None, "b": 1.5, "c": True, "d": [None, 0]},
}


@pytest.mark.parametrize("lane", ["vc-jwt", "eddsa-jcs-2022"])
@pytest.mark.parametrize("name", list(_CONTROL_ISSUERS))
def test_an_ordinary_issuer_builds_signs_and_verifies(name, lane):
    issuer = _CONTROL_ISSUERS[name]
    vc = cred(issuer=issuer)
    assert vc["issuer"] == (issuer if isinstance(issuer, str) else dict(issuer))
    json.dumps(vc, allow_nan=False)
    got = sign_and_resolve(vc, lane)
    assert got["credentialSubject"]["id"] == vc["credentialSubject"]["id"]


def test_an_int_key_still_builds_and_the_vc_jwt_lane_writes_it_as_a_string():
    # not a marker, and not the builder's call: json writes ``1`` as "1" (the JCS lane, which
    # accepts string keys only, refuses it at add_proof, as before #309).
    vc = cred(issuer={"id": DID, 1: "one"})
    assert sign_and_resolve(vc, "vc-jwt")["credentialSubject"]["id"] == f"{LIST_URL}#list"


_CONTROL_CONTEXTS = {
    "default": None,
    "vocab": [VC2, {"@vocab": "https://example.org/terms#"}],
    "url-and-object": [VC2, "https://example.org/ctx", {"ex": "https://example.org/ns#"}],
    "marker-as-a-value": [VC2, {"@vocab": "...", "term": "_sd"}],
    "marker-names-as-array-elements": [VC2, {"n": ["...", "_sd", "_sd_alg"]}],
    "near-miss-names": [VC2, {"sd": 1, "_sdx": 2, "..": 3, "....": 4}],
    "tuple": (VC2, {"@vocab": "https://example.org/terms#"}),
    "vc1-first": [VC1, {"@vocab": "https://example.org/terms#"}],
}


@pytest.mark.parametrize("lane", ["vc-jwt", "eddsa-jcs-2022"])
@pytest.mark.parametrize("name", list(_CONTROL_CONTEXTS))
def test_ordinary_context_objects_build_sign_and_verify(name, lane):
    contexts = _CONTROL_CONTEXTS[name]
    vc = cred(contexts=contexts)
    assert vc["@context"] == ([VC2] if contexts is None else list(contexts))
    got = sign_and_resolve(vc, lane)
    assert got["@context"] == vc["@context"]


def test_the_marker_in_a_string_context_or_issuer_string_is_a_value():
    # only member NAMES are markers: the strings carry the same text and build.
    vc = cred(issuer="...", contexts=[VC2, "_sd", "_sd_alg", "..."])
    assert vc["issuer"] == "..." and vc["@context"] == [VC2, "_sd", "_sd_alg", "..."]


def test_a_member_that_is_not_json_still_builds_and_fails_at_sign():
    # unchanged by #309 and documented (wiki/Status-Lists.md): the builder does not decide
    # what is JSON; it only refuses the markers it can see in what the encoder would write.
    issuer = {"id": DID, "raw": b"x", "set": {1, 2}}
    vc = cred(issuer=issuer)
    assert vc["issuer"]["raw"] == b"x"
    with pytest.raises(TypeError):
        VcJwtProofSuite().sign(vc, signing_key=SK)


def test_a_member_that_is_not_json_does_not_hide_a_marker_beside_it():
    refused(lambda: cred(issuer={"id": DID, "raw": b"x", "n": {"_sd": []}}), names="issuer")
    refused(lambda: cred(contexts=[VC2, {"raw": b"x", "n": {"...": 1}}]), names="contexts[1]")


# --------------------------------------------------------------------------- #
# C. Cycles, nesting past the limit, keys that are no scalar: typed, never a hang
# --------------------------------------------------------------------------- #

def test_a_cyclic_issuer_is_a_typed_error_not_a_hang():
    issuer: dict[str, Any] = {"id": DID}
    issuer["self"] = issuer
    refused(lambda: cred(issuer=issuer), names="issuer")


def test_a_cyclic_list_in_the_issuer_is_a_typed_error_not_a_hang():
    loop: list[Any] = []
    loop.append(loop)
    refused(lambda: cred(issuer={"id": DID, "loop": loop}), names="issuer")
    refused(lambda: cred(contexts=[VC2, {"loop": loop}]), names="contexts[1]")


def test_a_cyclic_context_object_is_a_typed_error_not_a_hang():
    ctx: dict[str, Any] = {"@vocab": "https://x/"}
    ctx["me"] = ctx
    refused(lambda: cred(contexts=[VC2, ctx]), names="contexts[1]")


def test_nesting_past_the_interpreters_limit_is_a_typed_error():
    deep: Any = {"_sd": []}
    for _ in range(200_000):
        deep = {"n": deep}
    refused(lambda: cred(issuer={"id": DID, "deep": deep}), names="issuer")


@pytest.mark.parametrize("key", [(1, 2), frozenset({1}), b"k", object()])
def test_a_key_that_is_no_scalar_is_a_typed_error(key):
    refused(lambda: cred(issuer={"id": DID, key: 1}), names="issuer")
    refused(lambda: cred(contexts=[VC2, {key: 1}]), names="contexts[1]")


# --------------------------------------------------------------------------- #
# D. Parity with the lane: the builder refuses exactly what the lane refuses
# --------------------------------------------------------------------------- #

def _lane_refuses(issuer: Any = None, contexts: Any = None) -> bool:
    """Whether the default resolver refuses a VC-JWT list that carries *issuer* / *contexts*,
    secured around the builder (the object goes into the credential as given)."""
    vc = cred()
    if issuer is not None:
        vc["issuer"] = issuer
    if contexts is not None:
        vc["@context"] = list(contexts)
    did = DID if issuer is None else issuer["id"]
    wire = VcJwtProofSuite().sign(vc, signing_key=Ed25519SigningKey(PRIV, f"{did}#0"))
    try:
        default_status_list_resolver(resolver=_AnyDid(), fetch=lambda u: wire)(LIST_URL)
    except MalformedToken as exc:
        assert "SD-JWT markers" in str(exc), str(exc)
        return True
    return False


def _builder_refuses(**kw: Any) -> bool:
    try:
        cred(**kw)
    except StatusListError:
        return True
    return False


def _parity_issuers() -> list[Any]:
    cases: list[Any] = []
    for marker in MARKERS:
        for where, issuer in _placements(marker, sentinel=0).items():
            cases.append(pytest.param(issuer, id=f"{marker}-{where}"))
    for name, issuer in _CONTROL_ISSUERS.items():
        if isinstance(issuer, dict):
            cases.append(pytest.param(issuer, id=f"control-{name}"))
    return cases


@pytest.mark.parametrize("issuer", _parity_issuers())
def test_the_builder_refuses_an_issuer_exactly_when_the_lane_does(issuer):
    assert _builder_refuses(issuer=issuer) == _lane_refuses(issuer=issuer)


def _parity_contexts() -> list[Any]:
    cases: list[Any] = []
    for marker in MARKERS:
        for where, ctx in {"top": {marker: 0}, "nested": {"n": {marker: 0}},
                           "in-list": {"n": [{marker: 0}]}, "in-tuple": {"n": ({marker: 0},)}
                           }.items():
            cases.append(pytest.param([VC2, ctx], id=f"{marker}-{where}"))
    for name, contexts in _CONTROL_CONTEXTS.items():
        if contexts is not None:
            cases.append(pytest.param(list(contexts), id=f"control-{name}"))
    return cases


@pytest.mark.parametrize("contexts", _parity_contexts())
def test_the_builder_refuses_a_context_exactly_when_the_lane_does(contexts):
    assert _builder_refuses(contexts=contexts) == _lane_refuses(contexts=contexts)


def test_the_premise_the_lane_still_refuses_the_issue_example():
    # If the VC-JWT lane ever stops refusing a marker, this is the test that says the builder
    # rule is no longer needed (and the parity tests above say it is now too strict).
    assert _lane_refuses(issuer={"...": None, "id": "did:a:0"}) is True
    assert _lane_refuses(issuer={"id": "did:a:0", "name": "..."}) is False


# --------------------------------------------------------------------------- #
# E. The end-to-end property: whatever the builder accepts, the pipeline accepts
# --------------------------------------------------------------------------- #

_DID_ST = st.from_regex(r"did:[a-z]{1,6}:[A-Za-z0-9._-]{1,30}", fullmatch=True)
_LEAF = st.one_of(st.none(), st.booleans(), st.integers(-2 ** 53, 2 ** 53),
                  st.text(max_size=8), st.sampled_from(list(MARKERS)))
_JSON = st.recursive(
    _LEAF, lambda inner: st.lists(inner, max_size=3) | st.tuples(inner, inner)
    | st.dictionaries(st.sampled_from(["a", "b", "name", *MARKERS]), inner, max_size=3),
    max_leaves=8)
_OBJECT = st.dictionaries(st.sampled_from(["a", "b", "name", "url", *MARKERS]), _JSON, max_size=3)
_ISSUER = st.one_of(
    _DID_ST, st.builds(lambda i, extra: {**extra, "id": i}, _DID_ST, _OBJECT))
_CONTEXT = st.one_of(
    st.none(),
    st.builds(lambda rest: [VC2, *rest],
              st.lists(st.one_of(st.text(min_size=1, max_size=8), _OBJECT), max_size=3)))


def _has_marker(node: Any) -> bool:
    """A model of the rule, written out and not imported: a dict with a member named like a
    marker, at any depth (the strategies above only build dicts, lists and tuples)."""
    if isinstance(node, dict):
        return any(k in MARKERS or _has_marker(v) for k, v in node.items())
    if isinstance(node, (list, tuple)):
        return any(_has_marker(v) for v in node)
    return False


@settings(max_examples=150, deadline=None)
@example(lane="vc-jwt", issuer={"...": None, "id": "did:a:0"}, contexts=None)
@example(lane="vc-jwt", issuer={"_sd": [], "id": "did:a:0"}, contexts=None)
@example(lane="vc-jwt", issuer={"_sd_alg": "sha-256", "id": "did:a:0"}, contexts=None)
@example(lane="vc-jwt", issuer={"id": "did:a:0", "t": ({"...": 1},)}, contexts=None)
@example(lane="eddsa-jcs-2022", issuer={"...": None, "id": "did:a:0"}, contexts=None)
@example(lane="vc-jwt", issuer="did:a:0", contexts=[VC2, {"n": {"_sd": []}}])
@given(lane=st.sampled_from(["vc-jwt", "eddsa-jcs-2022"]), issuer=_ISSUER, contexts=_CONTEXT)
def test_property_a_list_the_builder_accepts_is_a_list_the_pipeline_accepts(
        lane, issuer, contexts):
    """Built => secured and read back by ``default_status_list_resolver``. Refused => the
    refusal is the builder's own ``StatusListError``, raised before a key is asked, and the
    input does carry a marker. (The strategies draw the marker names often, unlike the
    property of ``test_status_builders_inputs.py`` whose strategy used to draw them by
    luck.)"""
    try:
        vc = cred(issuer=issuer, contexts=contexts)
    except StatusListError:
        assert _has_marker(issuer) or _has_marker(contexts)
        refused(lambda: build_then_sign_unsigned(issuer=issuer, contexts=contexts))
        return
    assert not (_has_marker(issuer) or _has_marker(contexts))
    got = sign_and_resolve(vc, lane)
    assert got["credentialSubject"]["id"] == vc["credentialSubject"]["id"]
    assert got["@context"] == json.loads(json.dumps(vc["@context"]))   # a tuple is an array
