"""
tests/test_ebsi_credential_types_shape.py — the credential ``type`` that ``verify_ebsi_badge``
reads for the trust decision is a string or a list of strings, or the refusal is typed (#359).

``_credential_types`` in ``openvc_ebsi/verify.py`` treated a ``str`` as one type and otherwise
iterated the value. The value is the signed credential's, so it is the issuer's; it is read
after the signature verified and before the trust decision, in both trust modes and with
``require_trust=False``. Measured on ``main`` at 4b25b9d (v1.38.1) through ``verify_ebsi_badge``
with a real P-256 signature, the default ``expected_types=None``:

  * ``7``, ``null``, ``true``, ``1.5`` — a bare ``TypeError`` (``'int' object is not iterable``)
    in both trust modes, with ``require_trust=False`` too, and out of ``EbsiNodeClient.run``,
    whose failover loop catches ``EbsiError`` only;
  * ``{"OpenBadgeCredential": 1}`` — read as ``["OpenBadgeCredential"]`` (an object's keys) and
    TRUSTED in single-level mode;
  * ``["X", 3]`` — read as ``["X"]`` (the non-string dropped in silence).

VCDM 1.1 and 2.0 both define ``type`` as a string or an array of strings. Now a ``type`` of any
other shape is :class:`openvc_ebsi.verify.CredentialTypeMalformed`, an ``EbsiVerificationError``,
with a bounded message (``safe_repr``); a list with one non-string entry is rejected, not
filtered (fail closed, #352's rule: a shape the reader does not know is not read in part). The
check runs before any registry request. The core suite's own ``expected_types`` check runs
first and is unchanged: with ``expected_types`` given, a scalar or object ``type`` is still its
``ClaimsInvalid`` (core reads those as no types), and a list that carries the expected string
beside a non-string reaches the new class.

Not changed, pinned as controls: ``""`` is one type that no accreditation lists
(``IssuerNotTrusted`` / ``NoTrustedAnchor``, without the "names no specific type" note); ``[]``
and an absent ``type`` are no types (the #367 note, before any registry request in recursive
mode); a string is a one-element list; a well-formed list is trusted; a 100 000-character string
and a list of 100 000 entries are refused with a bounded message in linear time.

The class under test is read when a test runs, not imported at the top: the file then collects
against a tree without it (the differential run against ``main``), where each negative fails on
its own and the controls still pass. Self-contained: ``tests/`` is not a package.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

import openvc_ebsi.verify as verify_module
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.multibase import b58btc_encode
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc_ebsi.errors import EbsiError
from openvc_ebsi.http import HttpNotFound
from openvc_ebsi.node_client import NoHealthyNode, for_nodes
from openvc_ebsi.nodes import Accepted, Node, VerifiedNodeList
from openvc_ebsi.trust import NoTrustedAnchor
from openvc_ebsi.verify import (
    EbsiVerificationError,
    IssuerNotTrusted,
    VerifiedEbsiBadge,
    verify_ebsi_badge,
)
from openvc_ebsi.versioning import (
    DidEbsiResolver,
    DidRegistryCoreV1,
    DidRegistryV5,
    TirCoreV1,
    TirV4,
)

SUITE = VcJwtProofSuite()
PEEK = SUITE.peek_claims
BASE = "https://api-pilot.ebsi.eu"
OBC = "OpenBadgeCredential"
GOOD_TYPES = ["VerifiableCredential", "VerifiableAttestation", OBC]
ACCREDITED_FOR = [{"schemaId": "https://schemas.example/openbadge",
                   "types": ["VerifiableCredential", "VerifiableAttestation", OBC]}]
MESSAGE_BOUND = 400              # a message is bounded whatever the credential carries
BIG = 100_000                    # the size the issue asks for
LINEAR_BUDGET_S = 5.0            # one pass over 100 000 entries is milliseconds; CI-safe slack
ABSENT = object()                # "no `type` member at all"


def _did(seed: int) -> str:
    # a well-formed did:ebsi identifier (#266): `z` + base58btc(version byte 1 || 16 bytes)
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, ROOT = _did(0xA1), _did(0xC3)
LEAF_SK = P256SigningKey.generate(kid=f"{LEAF}#key-1")
ROOT_SK = P256SigningKey.generate(kid=f"{ROOT}#key-1")


# --------------------------------------------------------------------------- #
# Harness: LEAF accredited by ROOT for OpenBadgeCredential, on the v4 lane
# --------------------------------------------------------------------------- #

class StubFetch:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url: str) -> Any:
        self.calls.append(url)
        try:
            return self.routes[url]
        except KeyError:
            raise HttpNotFound("no stub route", url=url) from None


def _did_doc(did: str, sk: P256SigningKey) -> dict[str, Any]:
    return {"didDocument": {"id": did, "verificationMethod": [{
        "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
        "publicKeyJwk": sk.public_jwk()}], "assertionMethod": [f"{did}#key-1"]}}


def _accreditation() -> str:
    """A ROOT-signed accreditation of LEAF for OpenBadgeCredential (the leaf kind, #368)."""
    return SUITE.sign({"id": "urn:uuid:acc-1",
                       "type": ["VerifiableCredential", "VerifiableAccreditationToAttest"],
                       "issuer": ROOT,
                       "credentialSubject": {"id": LEAF, "accreditedFor": ACCREDITED_FOR}},
                      signing_key=ROOT_SK)


def _world() -> tuple[StubFetch, DidEbsiResolver]:
    """Both DID documents and LEAF's TIR record (v4: the attributes inline)."""
    tir, didr = TirV4(), DidRegistryV5()
    routes = {
        didr.identifiers_url(BASE, LEAF): _did_doc(LEAF, LEAF_SK),
        didr.identifiers_url(BASE, ROOT): _did_doc(ROOT, ROOT_SK),
        tir.issuer_url(BASE, LEAF): {"did": LEAF, "attributes": [
            {"hash": "0x1", "issuerType": "TI", "tao": ROOT, "rootTao": ROOT,
             "body": _accreditation()}]},
    }
    fetch = StubFetch(routes)
    return fetch, DidEbsiResolver(fetch, PEEK, base=BASE, didr=didr, tir=tir)


def badge(type_value: Any) -> str:
    """A LEAF-signed badge whose ``type`` is *type_value* (``ABSENT``: no member)."""
    credential: dict[str, Any] = {
        "@context": ["https://www.w3.org/2018/credentials/v1"], "id": "urn:uuid:badge-1",
        "issuer": LEAF, "credentialSubject": {"id": "did:key:z6MkSubject"}}
    if type_value is not ABSENT:
        credential["type"] = type_value
    return SUITE.sign(credential, signing_key=LEAF_SK)


# the four trust modes of `verify_ebsi_badge`
MODES = [
    pytest.param({}, id="single-level"),
    pytest.param({"require_trust": False}, id="single-level-require-false"),
    pytest.param({"trust_anchors": {ROOT}}, id="recursive"),
    pytest.param({"trust_anchors": {ROOT}, "require_trust": False}, id="recursive-require-false"),
]


def verify(token: str, resolver: DidEbsiResolver, **kwargs: Any) -> VerifiedEbsiBadge:
    return verify_ebsi_badge(token, resolver=resolver, proof_suite=SUITE, **kwargs)


def _malformed_class() -> type[EbsiVerificationError]:
    """``CredentialTypeMalformed``, read at call time (see the module docstring)."""
    cls = getattr(verify_module, "CredentialTypeMalformed")
    assert issubclass(cls, EbsiVerificationError)
    return cls


def _is_malformed(exc: BaseException) -> None:
    assert type(exc) is _malformed_class()                      # the exact class
    assert isinstance(exc, EbsiVerificationError)
    assert isinstance(exc, EbsiError) and isinstance(exc, OpenvcError)
    assert len(str(exc)) <= MESSAGE_BOUND, len(str(exc))


def _p(value: Any) -> Any:
    text = repr(value)
    return pytest.param(value, id=f"{type(value).__name__}-{text[:20]}")


# --------------------------------------------------------------------------- #
# Negatives: the issue's rows, in every trust mode
# --------------------------------------------------------------------------- #

# (value, the whole message)
NOT_A_LIST = [
    pytest.param(7, "credential type is neither a string nor a list of strings: 7", id="int"),
    pytest.param(None, "credential type is neither a string nor a list of strings: None",
                 id="null"),
    pytest.param(True, "credential type is neither a string nor a list of strings: True",
                 id="true"),
    pytest.param(1.5, "credential type is neither a string nor a list of strings: 1.5",
                 id="float"),
    pytest.param({"a": 1}, "credential type is neither a string nor a list of strings: dict",
                 id="object"),
    pytest.param({OBC: 1}, "credential type is neither a string nor a list of strings: dict",
                 id="object-keyed-by-the-accredited-type"),
    pytest.param({}, "credential type is neither a string nor a list of strings: dict",
                 id="empty-object"),
    pytest.param(False, "credential type is neither a string nor a list of strings: False",
                 id="false"),
    pytest.param(0, "credential type is neither a string nor a list of strings: 0", id="zero"),
]

# (value, the whole message): a list with a non-string entry names the entry, not the list
BAD_ENTRY = [
    pytest.param(["X", 3], "credential type[1] is not a string: 3", id="str-then-int"),
    pytest.param([3], "credential type[0] is not a string: 3", id="int"),
    pytest.param([None], "credential type[0] is not a string: None", id="null"),
    pytest.param([True], "credential type[0] is not a string: True", id="true"),
    pytest.param([1.5], "credential type[0] is not a string: 1.5", id="float"),
    pytest.param([[OBC]], "credential type[0] is not a string: list", id="nested-list"),
    pytest.param([{"a": 1}], "credential type[0] is not a string: dict", id="object-entry"),
    pytest.param(GOOD_TYPES + [None], "credential type[3] is not a string: None",
                 id="good-types-then-null"),
    pytest.param([OBC, 3], "credential type[1] is not a string: 3",
                 id="accredited-type-then-int"),
]


@pytest.mark.parametrize("kwargs", MODES)
@pytest.mark.parametrize("value,message", NOT_A_LIST)
def test_a_type_that_is_not_a_string_or_a_list_is_typed_in_every_trust_mode(
        kwargs: dict[str, Any], value: Any, message: str) -> None:
    # on main a bare TypeError for the scalars, and the object's keys read as its types
    fetch, resolver = _world()
    with pytest.raises(EbsiVerificationError) as info:
        verify(badge(value), resolver, **kwargs)
    _is_malformed(info.value)
    assert str(info.value) == message
    # after the signature (the issuer's key was resolved), before any registry request
    assert fetch.calls == [DidRegistryV5().identifiers_url(BASE, LEAF)]


@pytest.mark.parametrize("kwargs", MODES)
@pytest.mark.parametrize("value,message", BAD_ENTRY)
def test_a_list_with_a_non_string_entry_is_rejected_not_filtered(
        kwargs: dict[str, Any], value: Any, message: str) -> None:
    # on main `["X", 3]` read as `["X"]`; the entry is now named and the whole list refused
    fetch, resolver = _world()
    with pytest.raises(EbsiVerificationError) as info:
        verify(badge(value), resolver, **kwargs)
    _is_malformed(info.value)
    assert str(info.value) == message
    assert fetch.calls == [DidRegistryV5().identifiers_url(BASE, LEAF)]


def test_the_class_sits_under_the_verification_error_family() -> None:
    cls = _malformed_class()
    assert cls.__mro__[1] is EbsiVerificationError
    assert issubclass(cls, EbsiError) and issubclass(cls, OpenvcError)
    assert cls is not IssuerNotTrusted             # malformed is not "untrusted"
    assert cls.__doc__ and "list of strings" in cls.__doc__


# --------------------------------------------------------------------------- #
# The core suite's `expected_types` check runs first and is unchanged
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [_p(v) for v in (7, None, True, 1.5, {OBC: 1}, {"a": 1})])
def test_with_expected_types_a_scalar_or_object_type_is_still_the_suite_s_claims_invalid(
        value: Any) -> None:
    # the core suite reads these as no types and refuses before verify.py reads the value
    _, resolver = _world()
    with pytest.raises(ClaimsInvalid, match="credential missing required type"):
        verify(badge(value), resolver, expected_types=[OBC])


@pytest.mark.parametrize("kwargs", MODES)
def test_with_expected_types_a_list_that_carries_it_beside_a_non_string_is_malformed(
        kwargs: dict[str, Any]) -> None:
    # the suite finds the expected string and passes; the trust reader then refuses the list
    _, resolver = _world()
    with pytest.raises(EbsiVerificationError) as info:
        verify(badge([OBC, 3]), resolver, expected_types=[OBC], **kwargs)
    _is_malformed(info.value)
    assert str(info.value) == "credential type[1] is not a string: 3"


# --------------------------------------------------------------------------- #
# Through `EbsiNodeClient.run` (the production client, Core v1): typed, never bare
# --------------------------------------------------------------------------- #

NODE = "https://api.ebsi.node-a.example"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)


def _node_client() -> Any:
    """A one-node client whose node serves LEAF's DID document and a TIR record with no
    attributes (an unaccredited issuer: trust is not the question here)."""
    result = VerifiedNodeList(
        environment="prod", version=4, keys_version=1, issued=NOW - timedelta(days=30),
        expires=NOW + timedelta(days=60),
        nodes=(Node(NODE, NODE[len("https://"):], "XX", "Example"),),
        accepted_list=Accepted(4, "0" * 64), accepted_keys=Accepted(1, "0" * 64))
    client = for_nodes(result, clock=lambda: NOW, decode_jwt=PEEK, address_guard=None)
    routes = {
        DidRegistryCoreV1().identifiers_url(NODE, LEAF): _did_doc(LEAF, LEAF_SK),
        TirCoreV1().issuer_url(NODE, LEAF): {"did": LEAF, "hasAttributes": False},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/alive":
            return httpx.Response(200, json={"health_global": 1})
        body = routes.get(str(request.url))
        return httpx.Response(404 if body is None else 200, json=body)

    client.http._client.close()
    client.http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


@pytest.mark.parametrize("require_trust", [True, False], ids=["require-trust", "no-require"])
@pytest.mark.parametrize("value", [_p(v) for v in (7, None, True, 1.5, {"a": 1}, ["X", 3])])
def test_the_issue_table_reaches_the_node_client_caller_as_the_typed_class(
        value: Any, require_trust: bool) -> None:
    # on main a bare TypeError out of `run` (its failover loop catches EbsiError only)
    client = _node_client()
    try:
        with pytest.raises(EbsiVerificationError) as info:
            client.run(lambda session: verify_ebsi_badge(
                badge(value), resolver=session.resolver, proof_suite=SUITE,
                require_trust=require_trust))
        _is_malformed(info.value)
        assert not isinstance(info.value, NoHealthyNode)
        # the node was not blamed: the next walk runs on it
        result = client.run(lambda session: verify_ebsi_badge(
            badge(GOOD_TYPES), resolver=session.resolver, proof_suite=SUITE,
            require_trust=False))
        assert result.trusted is False                 # no attributes: untrusted, no error
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# Controls: `""`, `[]`, absent and the well-formed shapes keep today's meaning
# --------------------------------------------------------------------------- #

def test_an_empty_string_is_one_type_that_no_accreditation_lists() -> None:
    fetch, resolver = _world()
    with pytest.raises(IssuerNotTrusted) as single:
        verify(badge(""), resolver)
    assert type(single.value) is IssuerNotTrusted
    assert "types ['']" in str(single.value)
    assert "names no specific type" not in str(single.value)   # it IS a specific type
    assert fetch.calls[-1] == TirV4().issuer_url(BASE, LEAF)   # the registry was consulted
    with pytest.raises(NoTrustedAnchor) as recursive:
        verify(badge(""), resolver, trust_anchors={ROOT})
    assert type(recursive.value) is NoTrustedAnchor
    assert "has no valid accreditation for the credential's types" in str(recursive.value)
    assert verify(badge(""), resolver, require_trust=False).trusted is False
    assert verify(badge(""), resolver, trust_anchors={ROOT},
                  require_trust=False).trusted is False


@pytest.mark.parametrize("value", [pytest.param([], id="empty-list"),
                                   pytest.param(ABSENT, id="absent")])
def test_an_empty_list_and_an_absent_type_are_no_types(value: Any) -> None:
    # nothing to be accredited for (#367): untrusted, with the note, never malformed
    fetch, resolver = _world()
    with pytest.raises(IssuerNotTrusted) as single:
        verify(badge(value), resolver)
    assert type(single.value) is IssuerNotTrusted
    assert "types []" in str(single.value)
    assert "names no specific type" in str(single.value)
    fetch.calls.clear()
    with pytest.raises(NoTrustedAnchor) as recursive:
        verify(badge(value), resolver, trust_anchors={ROOT})
    assert type(recursive.value) is NoTrustedAnchor
    assert "name no specific type" in str(recursive.value)
    assert fetch.calls == [DidRegistryV5().identifiers_url(BASE, LEAF)]   # no registry request
    assert verify(badge(value), resolver, require_trust=False).trusted is False
    assert verify(badge(value), resolver, trust_anchors={ROOT},
                  require_trust=False).trusted is False


@pytest.mark.parametrize("kwargs", MODES)
@pytest.mark.parametrize("value", [pytest.param(GOOD_TYPES, id="list"),
                                   pytest.param(OBC, id="string-is-a-one-element-list")])
def test_a_well_formed_type_is_trusted_in_every_mode(kwargs: dict[str, Any],
                                                     value: Any) -> None:
    result = verify(badge(value), resolver=_world()[1], **kwargs)
    assert result.trusted is True
    assert result.accreditation is not None
    assert OBC in result.accreditation.credential_types
    assert result.credential["type"] == value           # the credential is returned as signed


# --------------------------------------------------------------------------- #
# Size: a 100 000-character string and a list of 100 000 entries, bounded and linear
# --------------------------------------------------------------------------- #

def _timed(fn: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    try:
        return fn(), time.perf_counter() - started
    except BaseException as exc:
        return exc, time.perf_counter() - started


@pytest.mark.parametrize("kwargs,cls", [
    pytest.param({}, IssuerNotTrusted, id="single-level"),
    pytest.param({"trust_anchors": {ROOT}}, NoTrustedAnchor, id="recursive"),
])
def test_a_huge_string_type_is_refused_with_a_bounded_message(
        kwargs: dict[str, Any], cls: type) -> None:
    _, resolver = _world()
    exc, elapsed = _timed(lambda: verify(badge("A" * BIG), resolver, **kwargs))
    assert type(exc) is cls, exc
    assert len(str(exc)) <= MESSAGE_BOUND, len(str(exc))
    assert elapsed < LINEAR_BUDGET_S


@pytest.mark.parametrize("kwargs,cls", [
    pytest.param({}, IssuerNotTrusted, id="single-level"),
    pytest.param({"trust_anchors": {ROOT}}, NoTrustedAnchor, id="recursive"),
])
def test_a_huge_list_of_strings_is_refused_with_a_bounded_message(
        kwargs: dict[str, Any], cls: type) -> None:
    _, resolver = _world()
    types = [f"T{i}" for i in range(BIG)]
    exc, elapsed = _timed(lambda: verify(badge(types), resolver, **kwargs))
    assert type(exc) is cls, exc
    assert len(str(exc)) <= MESSAGE_BOUND, len(str(exc))
    assert elapsed < LINEAR_BUDGET_S


@pytest.mark.parametrize("kwargs", MODES)
def test_a_huge_list_whose_last_entry_is_not_a_string_is_malformed_in_linear_time(
        kwargs: dict[str, Any]) -> None:
    _, resolver = _world()
    types: list[Any] = [f"T{i}" for i in range(BIG)] + [3]
    exc, elapsed = _timed(lambda: verify(badge(types), resolver, **kwargs))
    assert isinstance(exc, BaseException)
    _is_malformed(exc)
    assert str(exc) == f"credential type[{BIG}] is not a string: 3"
    assert elapsed < LINEAR_BUDGET_S


def test_a_huge_list_of_non_strings_names_the_first_entry() -> None:
    _, resolver = _world()
    exc, elapsed = _timed(lambda: verify(badge([1] * BIG), resolver))
    assert isinstance(exc, BaseException)
    _is_malformed(exc)
    assert str(exc) == "credential type[0] is not a string: 1"
    assert elapsed < LINEAR_BUDGET_S


@pytest.mark.parametrize("value,message", [
    pytest.param(["A" * BIG, 7], "credential type[1] is not a string: 7",
                 id="long-string-then-int-shows-the-int"),
    pytest.param([10 ** 100], "credential type[0] is not a string: int",
                 id="int-past-64-bits-is-named-by-type"),
    pytest.param(10 ** 100, "credential type is neither a string nor a list of strings: int",
                 id="scalar-int-past-64-bits"),
    pytest.param([[[[[[[[[[OBC]]]]]]]]]], "credential type[0] is not a string: list",
                 id="deeply-nested-list"),
    pytest.param({"k" * BIG: 1}, "credential type is neither a string nor a list of strings: dict",
                 id="object-with-a-huge-key"),
])
def test_the_message_shows_the_offending_value_through_safe_repr(value: Any,
                                                                 message: str) -> None:
    _, resolver = _world()
    with pytest.raises(EbsiVerificationError) as info:
        verify(badge(value), resolver)
    _is_malformed(info.value)
    assert str(info.value) == message
