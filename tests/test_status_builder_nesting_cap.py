"""
tests/test_status_builder_nesting_cap.py — the status-list credential builder refuses an
``issuer`` object or an inline ``@context`` object nested past the loader's cap (#311).

The VC-JWT lane reads the signed payload through the bounded loader (``openvc._json.loads``,
#213), which refuses nesting past 100 levels in the WHOLE payload. ``build_status_list_credential``
accepted an ``issuer`` or context object of any depth, so the builder minted a list that its
own default resolver then refused::

    issuer = {"id": did, "x": {"x": {...}}}              # 99 levels, no marker, no cycle
    vc = build_status_list_credential(issuer=issuer, ...)
    wire = VcJwtProofSuite().sign(vc, signing_key=key)
    default_status_list_resolver(...)(LIST_URL)          # MalformedToken: not valid base64url JSON

Where the object sits decides how much of the 100 it may use. The payload is
``{"iss": ..., "vc": {"issuer": <object>, "@context": [<entry>, ...]}}``: the issuer object is the
third container (payload, vc, issuer) and a context entry the fourth (payload, vc, @context,
entry), so, counting the object's own root as level 1, the limits are MEASURED here against the
real lane, not derived: an ``issuer`` of up to 98 levels and a context entry of up to 97 verify,
one level more is refused (``MalformedToken``). ``eddsa-jcs-2022`` (the credential is the
root) takes one more level in each field (99 and 98) and refuses the next at ``add_proof``. The
builder cannot know the lane and VC-JWT is the default, so it holds every lane to the VC-JWT
limit and refuses exactly one level that JCS would accept: the same decision #309 recorded for
the SD-JWT markers (the rule is the same on every lane), pinned in B.

The check runs on the JSON the object encodes to (a ``tuple`` is an array; a ``Mapping`` the
encoder cannot write is ``null``), the loader's own ``nesting_exceeds``, so the two limits cannot
drift and a value whose depth as a Python object differs from its depth as JSON is judged by the
JSON, which is what the lane decodes.

A. Parity: for dict, list, tuple and mixed chains, depths 95 to 102, both fields, the builder
   refuses exactly when the real VC-JWT lane does, and the table is the measured one.
B. The eddsa-jcs-2022 asymmetry, pinned: the first depth the builder refuses is one JCS accepts.
C. Negatives: exact class ``StatusListError`` before anything is signed, naming the field and the
   cap and never echoing the object; containers that are subclasses; hostile nested values;
   depth together with a marker; depths past what the interpreter encodes.
D. Controls: ordinary objects and objects AT the cap still build, sign and verify.
E. A property over random mixes of dict / list / tuple levels around the cap.

Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import base64
import collections.abc
import json
import types
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import given, settings
from hypothesis import strategies as st

from openvc.did.base import parse_did_document
from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import MalformedToken, ProofMalformed
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.resolvers import default_status_list_resolver
from openvc.status import StatusListError, build_status_list_credential, new_bitstring

VC2 = "https://www.w3.org/ns/credentials/v2"
VC1 = "https://www.w3.org/2018/credentials/v1"
LIST_URL = "https://status.example/w3c/1"
BIG = "S" * 60_000          # a 60 KB sentinel: must never reach an error message

# The measured table (see the module docstring): the deepest object, counting its own root as
# level 1, that the real lane reads back. Written out, not derived from openvc._json.MAX_DEPTH:
# the parity test compares it with the lane, so a change of the loader's cap fails loudly here.
CAP = {"issuer": 98, "context": 97}          # VC-JWT lane
JCS_CAP = {"issuer": 99, "context": 98}      # eddsa-jcs-2022: exactly one level looser
FIELDS = ["issuer", "context"]
KINDS = ["dict", "list", "tuple", "mixed"]

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


class _DictSub(dict):
    """A ``dict`` subclass: the encoder reads it through ``items()``."""


class _ListSub(list):
    """A ``list`` subclass."""


class _ItemsOnly(dict):
    """A ``dict`` whose storage is shallow but whose ``items()`` (what the encoder reads)
    holds the deep members: its depth as a Python object is not its depth as JSON."""

    def __init__(self, members: dict[str, Any]) -> None:
        super().__init__({"n": 1})
        self._members = members

    def items(self) -> Any:
        return list(self._members.items())


class _RaisingItems(dict):
    """A ``dict`` whose ``items()`` raises: the encoder cannot write it."""

    def items(self) -> Any:
        raise RuntimeError("hostile items()")


class _HostileMapping(collections.abc.Mapping):
    """A ``Mapping`` that is not a ``dict``: the encoder never walks it (it is ``null`` on the
    wire), and every accessor raises, so a walk of the Python object would raise."""

    def __getitem__(self, key: Any) -> Any:
        raise RuntimeError("hostile __getitem__")

    def __iter__(self) -> Any:
        raise RuntimeError("hostile __iter__")

    def __len__(self) -> int:
        raise RuntimeError("hostile __len__")


def wrap(kind: str, index: int, node: Any) -> Any:
    """One more level of *kind* around *node*."""
    if kind == "dict":
        return {"n": node}
    if kind == "list":
        return [node]
    if kind == "tuple":
        return (node,)
    if kind == "dict-sub":
        return _DictSub({"n": node})
    if kind == "list-sub":
        return _ListSub([node])
    if kind == "mixed":
        return {"n": node} if index % 2 == 0 else [node]
    raise AssertionError(kind)


def below(levels: int, kind: str, leaf: Any = "leaf") -> Any:
    """*leaf* wrapped in *levels* containers of *kind* (iterative: never recurses)."""
    node = leaf
    for index in range(levels):
        node = wrap(kind, index, node)
    return node


def depth_of(node: Any) -> int:
    """The nesting of a dict / list / tuple tree, its own root counted as level 1: written out
    here and not imported, so the numbers of the table are not read through openvc's helper."""
    deepest = 0
    stack = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            children: Any = current.values()
        elif isinstance(current, (list, tuple)):
            children = current
        else:
            continue
        deepest = max(deepest, depth)
        stack.extend((child, depth + 1) for child in children)
    return deepest


def make(field: str, n: int, kind: str, leaf: Any = "leaf") -> dict[str, Any]:
    """An issuer object (it needs its ``id``) or an inline context object whose OWN nesting is
    exactly *n* levels, the object itself being level 1."""
    inner = below(n - 1, kind, leaf) if n > 1 else leaf
    obj = {"id": DID, "x": inner} if field == "issuer" else {"x": inner}
    assert depth_of(obj) == n, (depth_of(obj), n)
    return obj


def kw(field: str, obj: Any) -> dict[str, Any]:
    """The builder keyword that carries *obj* for *field*."""
    return {"issuer": obj} if field == "issuer" else {"contexts": [VC2, obj]}


def names(field: str) -> str:
    return "issuer" if field == "issuer" else "contexts[1]"


def cred(**extra: Any) -> dict[str, Any]:
    extra.setdefault("issuer", DID)
    return build_status_list_credential(id=LIST_URL, bitstring=BITS, **extra)


def build_then_sign_unsigned(**extra: Any) -> str:
    """Build, then sign with a key that explodes: a builder that accepted the input fails the
    test with ``_SignedTooEarly``, never with the class we assert."""
    return VcJwtProofSuite().sign(cred(**extra), signing_key=_ExplodingKey())


def refused(call: Any, *, names: str | None = None) -> StatusListError:
    with pytest.raises(Exception) as caught:
        call()
    exc = caught.value
    assert type(exc) is StatusListError, f"{type(exc).__name__}: {exc}"
    assert isinstance(exc, OpenvcError)
    if names is not None:
        assert names in str(exc), str(exc)
    return exc


def around_builder(field: str, obj: Any) -> dict[str, Any]:
    """A credential from the builder with *obj* put in AFTER it, as given: what a caller who
    secures the list by hand, or a build that did not check, would sign."""
    vc = cred()
    if field == "issuer":
        vc["issuer"] = obj
    else:
        vc["@context"] = [VC2, obj]
    return vc


def secure(vc: dict[str, Any], lane: str) -> str:
    if lane == "vc-jwt":
        return VcJwtProofSuite().sign(vc, signing_key=SK)
    return json.dumps(EddsaJcsProofSuite().add_proof(
        vc, signing_key=SK, verification_method=f"{DID}#0"))


def read_back(wire: str) -> dict[str, Any]:
    return default_status_list_resolver(resolver=_AnyDid(), fetch=lambda u: wire)(LIST_URL)


def lane_refuses(field: str, obj: Any) -> bool:
    """Whether the default resolver refuses a VC-JWT list that carries *obj*."""
    wire = secure(around_builder(field, obj), "vc-jwt")
    try:
        read_back(wire)
    except MalformedToken as exc:
        # the loader's refusal, not the SD-JWT marker fence's: the parity must not pass for
        # the wrong reason
        assert "not valid base64url JSON" in str(exc), str(exc)
        return True
    return False


def builder_refuses(field: str, obj: Any) -> bool:
    try:
        cred(**kw(field, obj))
    except StatusListError:
        return True
    return False


# --------------------------------------------------------------------------- #
# A. Parity with the real lane, and the measured table
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", range(95, 103))
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("field", FIELDS)
def test_the_builder_refuses_exactly_when_the_vc_jwt_lane_does(field, kind, n):
    obj = make(field, n, kind)
    lane = lane_refuses(field, obj)
    assert lane == (n > CAP[field]), (
        f"the VC-JWT lane's measured limit for {field} is no longer {CAP[field]}")
    assert builder_refuses(field, obj) == lane


def test_the_two_limits_differ_by_one_because_a_context_entry_sits_one_container_deeper():
    # an object of 98 levels is an issuer the lane reads and a context entry it does not.
    assert not builder_refuses("issuer", make("issuer", 98, "dict"))
    assert builder_refuses("context", make("context", 98, "dict"))
    assert not builder_refuses("context", make("context", 97, "dict"))
    assert builder_refuses("issuer", make("issuer", 99, "dict"))


@pytest.mark.parametrize("position", [1, 2, 3])
def test_the_limit_holds_for_a_context_entry_wherever_it_sits(position):
    others = ["https://example.org/ctx", {"@vocab": "https://example.org/terms#"}]
    entries: list[Any] = [VC2, *others[:position - 1]]
    entries.append(make("context", CAP["context"], "dict"))
    assert cred(contexts=entries)["@context"][position] == entries[position]
    entries[position] = make("context", CAP["context"] + 1, "dict")
    refused(lambda: cred(contexts=entries), names=f"contexts[{position}]")
    refused(lambda: cred(contexts=tuple(entries)), names=f"contexts[{position}]")


# --------------------------------------------------------------------------- #
# B. The eddsa-jcs-2022 asymmetry, pinned (the #309 decision: one rule on every lane)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", ["dict", "list"])
@pytest.mark.parametrize("field", FIELDS)
def test_eddsa_jcs_takes_exactly_one_more_level_than_the_builder_allows(field, kind):
    first_refused = CAP[field] + 1
    assert JCS_CAP[field] == first_refused
    obj = make(field, first_refused, kind)
    # the builder and the VC-JWT lane agree that this is too deep ...
    assert builder_refuses(field, obj) and lane_refuses(field, obj)
    # ... and eddsa-jcs-2022 signs it and reads it back (the builder is one level stricter
    # than that lane, by decision: it cannot know the lane)
    got = read_back(secure(around_builder(field, obj), "eddsa-jcs-2022"))
    assert got["credentialSubject"]["id"] == f"{LIST_URL}#list"
    # one level further and that lane refuses too, at add_proof
    deeper = make(field, first_refused + 1, kind)
    with pytest.raises(ProofMalformed):
        secure(around_builder(field, deeper), "eddsa-jcs-2022")
    assert builder_refuses(field, deeper)


# --------------------------------------------------------------------------- #
# C. Negatives: a typed error before anything is signed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", [*KINDS, "dict-sub", "list-sub"])
@pytest.mark.parametrize("field", FIELDS)
def test_one_level_past_the_cap_is_a_typed_error_before_anything_is_signed(field, kind):
    obj = make(field, CAP[field] + 1, kind, leaf=BIG)
    exc = refused(lambda: build_then_sign_unsigned(**kw(field, obj)), names=names(field))
    message = str(exc)
    assert str(CAP[field]) in message                      # it names the cap
    assert "S" * 40 not in message and DID not in message  # and never echoes the object
    assert len(message) < 600


@pytest.mark.parametrize("levels", [101, 102, 150, 300])
@pytest.mark.parametrize("field", FIELDS)
def test_the_message_names_the_cap_for_every_depth_past_it_not_just_the_first(field, levels):
    # past the loader's own 100 a parser that shares its cap would fail first, with a message
    # that names neither the field's limit nor the reason; the probe is parsed without one.
    obj = make(field, levels, "dict", leaf=BIG)
    exc = refused(lambda: cred(**kw(field, obj)), names=names(field))
    assert f"deeper than {CAP[field]} levels" in str(exc), str(exc)
    assert "S" * 40 not in str(exc) and len(str(exc)) < 600


@pytest.mark.parametrize("field", FIELDS)
def test_the_refusal_is_the_builders_own_and_comes_before_any_signing(field):
    refused(lambda: cred(**kw(field, make(field, CAP[field] + 1, "dict"))), names=names(field))
    refused(lambda: cred(subject_id="x", ttl=5, **kw(field, make(field, 200, "list"))),
            names=names(field))


@pytest.mark.parametrize("field", FIELDS)
def test_a_dict_subclass_root_is_refused_too(field):
    root = _DictSub(make(field, CAP[field] + 1, "dict"))
    refused(lambda: build_then_sign_unsigned(**kw(field, root)), names=names(field))


@pytest.mark.parametrize("field", FIELDS)
def test_the_refusal_does_not_mutate_the_object(field):
    obj = make(field, CAP[field] + 1, "dict")
    before = json.dumps(obj)
    refused(lambda: cred(**kw(field, obj)))
    assert json.dumps(obj) == before


@pytest.mark.parametrize("field", FIELDS)
def test_depth_in_a_late_member_beside_shallow_ones_is_found(field):
    obj = make(field, CAP[field] + 1, "dict")
    obj = {**{f"k{i}": {"a": [1, {"b": 2}]} for i in range(20)}, **obj, "z": [1, 2, 3]}
    refused(lambda: cred(**kw(field, obj)), names=names(field))


@pytest.mark.parametrize("field", FIELDS)
def test_a_deep_value_inside_a_dict_subclass_that_hides_it_from_values_is_found(field):
    # what the encoder (and so the lane) reads is items(), not the storage values() shows.
    deep = below(CAP[field] - 1, "dict")                 # + the _ItemsOnly level = CAP + 1
    obj = make(field, 2, "dict")
    obj["hidden"] = _ItemsOnly({"n": deep})
    assert depth_of(obj) == 2                            # as a Python object it is shallow
    assert builder_refuses(field, obj) and lane_refuses(field, obj)   # as JSON it is not


@pytest.mark.parametrize("field", FIELDS)
def test_a_dict_subclass_whose_items_raises_is_a_typed_error(field):
    obj = make(field, 3, "dict")
    obj["bad"] = _RaisingItems({"n": 1})
    exc = refused(lambda: build_then_sign_unsigned(**kw(field, obj)), names=names(field))
    assert "RuntimeError" in str(exc) and "hostile" not in str(exc)


@pytest.mark.parametrize("field", FIELDS)
def test_depth_and_a_marker_together_are_still_refused(field):
    deep_with_marker_beside = make(field, CAP[field] + 1, "dict")
    deep_with_marker_beside["_sd"] = []
    refused(lambda: build_then_sign_unsigned(**kw(field, deep_with_marker_beside)),
            names=names(field))
    deep_with_marker_at_the_bottom = make(field, CAP[field] + 5, "dict")
    cursor = deep_with_marker_at_the_bottom
    while isinstance(cursor.get("x"), dict) or isinstance(cursor.get("n"), dict):
        cursor = cursor["x"] if "x" in cursor else cursor["n"]
    cursor["..."] = 1
    refused(lambda: build_then_sign_unsigned(**kw(field, deep_with_marker_at_the_bottom)),
            names=names(field))


@pytest.mark.parametrize("levels", [1_000, 30_000, 200_000])
@pytest.mark.parametrize("kind", ["dict", "list"])
@pytest.mark.parametrize("field", FIELDS)
def test_nesting_far_past_the_cap_is_a_typed_error_not_a_crash(field, kind, levels):
    # 30 000 levels was measured to build and sign before the fix; 200 000 is past what the
    # interpreter can encode. Either way: the class, bounded, and never the object.
    inner = below(levels, kind, leaf=BIG)
    obj = {"id": DID, "x": inner} if field == "issuer" else {"x": inner}
    exc = refused(lambda: build_then_sign_unsigned(**kw(field, obj)), names=names(field))
    assert "S" * 40 not in str(exc) and len(str(exc)) < 600


# --------------------------------------------------------------------------- #
# D. Controls: what must still build, sign and verify
# --------------------------------------------------------------------------- #

def _wire_form(value: Any) -> Any:
    """What the object is after a trip through JSON (a tuple is an array)."""
    return json.loads(json.dumps(value))


@pytest.mark.parametrize("lane", ["vc-jwt", "eddsa-jcs-2022"])
@pytest.mark.parametrize("n", [1, 2, 3, 10, 50, 96, "cap"])
@pytest.mark.parametrize("kind", [*KINDS, "dict-sub", "list-sub"])
@pytest.mark.parametrize("field", FIELDS)
def test_an_object_up_to_the_cap_builds_signs_and_verifies(field, kind, n, lane):
    n = CAP[field] if n == "cap" else n
    obj = make(field, n, kind)
    vc = cred(**kw(field, obj))
    got = read_back(secure(vc, lane))
    if field == "issuer":
        assert got["issuer"] == _wire_form(obj)
    else:
        assert got["@context"] == _wire_form([VC2, obj])


@pytest.mark.parametrize("field", FIELDS)
def test_the_object_at_the_cap_is_what_the_credential_carries(field):
    obj = make(field, CAP[field], "dict")
    vc = cred(**kw(field, obj))
    carried = vc["issuer"] if field == "issuer" else vc["@context"][1]
    assert carried == obj and depth_of(carried) == CAP[field]


def test_an_object_at_the_cap_in_both_fields_at_once_still_verifies():
    vc = cred(issuer=make("issuer", CAP["issuer"], "mixed"),
              contexts=[VC2, make("context", CAP["context"], "mixed")])
    got = read_back(secure(vc, "vc-jwt"))
    assert depth_of(got["issuer"]) == CAP["issuer"]


@pytest.mark.parametrize("field", FIELDS)
def test_width_is_not_depth(field):
    # five thousand members and a five-thousand-element array, two levels deep.
    wide = {f"k{i}": i for i in range(5_000)}
    wide["list"] = [{"a": i} for i in range(5_000)]
    obj = {"id": DID, **wide} if field == "issuer" else dict(wide)
    vc = cred(**kw(field, obj))
    got = read_back(secure(vc, "vc-jwt"))
    carried = got["issuer"] if field == "issuer" else got["@context"][1]
    assert len(carried["list"]) == 5_000


def test_the_vc1_base_context_with_an_object_at_the_cap_builds():
    vc = cred(contexts=[VC1, make("context", CAP["context"], "dict")])
    assert vc["@context"][0] == VC1


def test_a_string_issuer_and_string_contexts_are_unaffected():
    vc = cred(issuer=DID, contexts=[VC2, "https://example.org/ctx"])
    assert read_back(secure(vc, "vc-jwt"))["issuer"] == DID


@pytest.mark.parametrize("field", FIELDS)
def test_a_deep_python_object_that_is_shallow_json_is_judged_as_json(field):
    # types.MappingProxyType is a Mapping, not a dict: the encoder writes it as null, so on
    # the wire this member is one level, however deep the Python object is. The builder reads
    # the wire. (It is not JSON, so it still fails at sign, as before: a documented limit.)
    deep_mapping: Any = 1
    for _ in range(150):
        deep_mapping = types.MappingProxyType({"n": deep_mapping})
    obj = make(field, 2, "dict")
    obj["m"] = deep_mapping
    vc = cred(**kw(field, obj))
    with pytest.raises(TypeError):
        VcJwtProofSuite().sign(vc, signing_key=SK)


@pytest.mark.parametrize("field", FIELDS)
def test_a_hostile_mapping_is_never_walked(field):
    # every accessor raises: a walk of the Python object would raise it, bare. The encoder
    # does not walk a Mapping that is not a dict, so neither does the builder.
    obj = make(field, 3, "dict")
    obj["m"] = _HostileMapping()
    vc = cred(**kw(field, obj))
    assert (vc["issuer"] if field == "issuer" else vc["@context"][1])["m"] is obj["m"]
    with pytest.raises(TypeError):
        VcJwtProofSuite().sign(vc, signing_key=SK)


# --------------------------------------------------------------------------- #
# E. The property: random mixes of levels around the cap
# --------------------------------------------------------------------------- #

_LEVEL = st.sampled_from(["dict", "list", "tuple"])


@settings(max_examples=80, deadline=None)
@given(field=st.sampled_from(FIELDS), n=st.integers(90, 104),
       levels=st.lists(_LEVEL, min_size=104, max_size=104))
def test_property_the_builder_refuses_exactly_when_the_vc_jwt_lane_does(field, n, levels):
    inner: Any = "leaf"
    for kind in reversed(levels[:n - 1]):
        inner = wrap(kind, 0, inner)
    obj = {"id": DID, "x": inner} if field == "issuer" else {"x": inner}
    assert depth_of(obj) == n
    lane = lane_refuses(field, obj)
    assert lane == (n > CAP[field])
    assert builder_refuses(field, obj) == lane
