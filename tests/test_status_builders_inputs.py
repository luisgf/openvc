"""
tests/test_status_builders_inputs.py — the status builders type the strings an artefact
names: the credential's ``issuer``, ``subject_id`` and ``contexts``, an entry's ``id`` and
the token's ``issuer`` (#269).

#250 (#230) made the builders refuse what the verifier refuses on the index, the pointer
strings and the list; #255 did the time inputs and ``ttl``. This is the rest, and the
verdict used to depend on the proof lane, so no single place failed::

    contexts="https://x/"      -> @context ['h', 't', 't', 'p', 's', ':', '/', '/', 'x', '/']
    contexts=5                 -> bare TypeError: 'int' object is not iterable
    contexts=[]                -> silently [VC2]       (list(contexts) if contexts else ...)
    subject_id=5               -> VC-JWT rejects, eddsa-jcs ACCEPTS, eddsa-rdfc refused
    subject_id=0               -> silently the default "<id>#list"   (subject_id or ...)
    issuer=5 / {} / b"did:x"   -> minted; a bare TypeError at VcJwtProofSuite.sign for bytes
    build_status_list_entry(id=5)       -> minted; accepted by VC-JWT and eddsa-jcs
    build_status_list_token(issuer=5)   -> minted; the default token resolver rejects it

Each is now a ``StatusListError`` at build time, before anything is signed. The rules mirror
what openvc's own verifier requires and add no policy: a credential ``issuer`` is a
non-empty ``str`` or an object with a non-empty string ``id`` and no ``@id`` (``id`` is the
one spelling every lane reads the same); ``subject_id``, the entry ``id`` and the token
``issuer`` are ``None`` (the default) or a non-empty ``str``; ``contexts`` is ``None`` or a
non-empty ``list`` / ``tuple`` whose first entry is a VC base context and whose others are a
non-empty ``str`` or an object. Maintainer decisions: (a) a falsy value that is not ``None``
is an error, not the default; (b) the first ``@context`` entry must be a VC base context;
(c) no URI-shape check.

Every refusal is asserted against the EXACT class ``StatusListError`` (it has no subclasses),
never ``TypeError`` / ``AttributeError`` / ``ValueError``, and each negative signs with a key
whose ``sign`` fails the test, which proves the error comes BEFORE the key is asked. The
controls show the well-formed inputs still build, sign and verify on the VC-JWT,
``eddsa-jcs-2022`` and (with ``pyld``) ``eddsa-rdfc-2022`` lanes. Helpers are self-contained
(tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import base64
import collections
import json
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import given, settings
from hypothesis import strategies as st

from openvc import VerificationPolicy, verify_credential
from openvc.did.base import parse_did_document
from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.resolvers import default_status_list_resolver, default_status_list_token_resolver
from openvc.status import (
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    build_status_list_token,
    build_token_status_reference,
    new_bitstring,
    new_status_list,
    parse_status_entries,
)
from openvc.status._index import brief

VC2 = "https://www.w3.org/ns/credentials/v2"
VC1 = "https://www.w3.org/2018/credentials/v1"
LIST_URL = "https://status.example/w3c/1"
TOKEN_URI = "https://status.example/ietf/1"
NAN = float("nan")
INF = float("inf")
HUGE = 10 ** 5000          # past sys.get_int_max_str_digits: str()/repr() raise ValueError
BIG = "x" * 60_000         # a 60 KB string: must never reach an error message

PRIV = ed25519.Ed25519PrivateKey.generate()
JWK = Ed25519SigningKey(PRIV, "_").public_jwk()
DID = "did:jwk:" + base64.urlsafe_b64encode(json.dumps(JWK).encode()).rstrip(b"=").decode()
VM = f"{DID}#0"
SK = Ed25519SigningKey(PRIV, VM)        # the key the did:jwk DID above resolves to
BITS = new_bitstring(64)
LST = new_status_list(64)


class _SignedTooEarly(AssertionError):
    pass


class _ExplodingKey:
    """A key that must never be asked to sign: every refusal below has to happen before
    ``sign`` is reached (``VcJwtProofSuite.sign`` and ``sign_compact`` both call it)."""

    alg = "EdDSA"
    kid = VM

    def sign(self, signing_input: bytes) -> bytes:
        raise _SignedTooEarly("the builder minted an artefact it should have refused")


def cred(**kw: Any) -> dict[str, Any]:
    kw.setdefault("issuer", DID)
    return build_status_list_credential(id=LIST_URL, bitstring=BITS, **kw)


def cred_unsigned(**kw: Any) -> str:
    """Build and then sign with a key that explodes: a builder that accepted the input
    fails the test with ``_SignedTooEarly``, never with the class we assert."""
    return VcJwtProofSuite().sign(cred(**kw), signing_key=_ExplodingKey())


def entry(**kw: Any) -> dict[str, Any]:
    return build_status_list_entry(status_list_credential=LIST_URL, index=1, **kw)


def tok(**kw: Any) -> str:
    return build_status_list_token(signing_key=SK, uri=TOKEN_URI, status_list=LST, **kw)


def tok_unsigned(**kw: Any) -> str:
    return build_status_list_token(
        signing_key=_ExplodingKey(), uri=TOKEN_URI, status_list=LST, **kw)


def claims_of(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def refused(call: Callable[[], Any], *, names: str | None = None) -> StatusListError:
    """Run *call*; it must raise exactly ``StatusListError``, naming *names* if given."""
    with pytest.raises(Exception) as caught:
        call()
    exc = caught.value
    assert type(exc) is StatusListError, f"{type(exc).__name__}: {exc}"
    assert isinstance(exc, OpenvcError)
    if names is not None:
        assert names in str(exc), str(exc)
    return exc


# --------------------------------------------------------------------------- #
# The values that are no identifier at all
# --------------------------------------------------------------------------- #

# Neither a string nor a dict nor None: refused wherever a string is wanted.
_NEITHER = [
    pytest.param(5, id="int"),
    pytest.param(0, id="zero"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param(1.5, id="float"),
    pytest.param(NAN, id="nan"),
    pytest.param(INF, id="inf"),
    pytest.param(HUGE, id="int-1e5000"),
    pytest.param(b"did:x", id="bytes"),
    pytest.param(bytearray(b"did:x"), id="bytearray"),
    pytest.param(object(), id="object"),
    pytest.param([], id="empty-list"),
    pytest.param(["a"], id="list"),
    pytest.param([DID], id="list-of-did"),
    pytest.param((), id="empty-tuple"),
    pytest.param((DID,), id="tuple"),
    pytest.param({DID}, id="set"),
    pytest.param(frozenset({DID}), id="frozenset"),
]

# Where a string is wanted, ``None`` is "absent" (the default) and ``""`` is not.
_NOT_TEXT = [*_NEITHER, pytest.param("", id="empty-str"), pytest.param({}, id="empty-dict"),
             pytest.param({"id": "x"}, id="dict")]


@pytest.mark.parametrize("value", _NOT_TEXT)
def test_subject_id_refuses_what_is_not_a_string(value):
    # includes the four falsy values that used to fall back to the default: "", 0, [], {}
    refused(lambda: cred_unsigned(subject_id=value), names="subject_id")


@pytest.mark.parametrize("value", _NOT_TEXT)
def test_entry_id_refuses_what_is_not_a_string(value):
    refused(lambda: entry(id=value), names="id")


@pytest.mark.parametrize("value", _NOT_TEXT)
def test_token_issuer_refuses_what_is_not_a_string(value):
    refused(lambda: tok_unsigned(issuer=value), names="issuer")


# The credential's issuer: ``None`` is no issuer at all, and an object must name itself.
_ISSUER_BAD = [
    *_NEITHER,
    pytest.param(None, id="none"),
    pytest.param("", id="empty-str"),
    pytest.param({}, id="empty-dict"),
    pytest.param({"id": 5}, id="id-int"),
    pytest.param({"id": ""}, id="id-empty"),
    pytest.param({"id": None}, id="id-none"),
    pytest.param({"id": True}, id="id-true"),
    pytest.param({"id": [DID]}, id="id-list"),
    pytest.param({"id": b"did:x"}, id="id-bytes"),
    pytest.param({"id": {"id": DID}}, id="id-dict"),
    pytest.param({"ID": DID}, id="id-wrong-case"),
    pytest.param({"name": "no id"}, id="only-a-name"),
    pytest.param({"@id": DID}, id="at-id-only"),
    pytest.param({"@id": ""}, id="at-id-empty"),
    pytest.param({"id": DID, "@id": "did:other"}, id="id-and-different-at-id"),
    pytest.param({"id": DID, "@id": DID}, id="id-and-equal-at-id"),
    pytest.param({"id": DID, "@id": ""}, id="id-and-empty-at-id"),
    pytest.param({"id": DID, "@id": None}, id="id-and-null-at-id"),
    pytest.param([{"id": DID}], id="list-of-object"),
]


@pytest.mark.parametrize("value", _ISSUER_BAD)
def test_credential_issuer_refuses_what_names_no_one(value):
    refused(lambda: cred_unsigned(issuer=value), names="issuer")


# --------------------------------------------------------------------------- #
# contexts: None, or a non-empty list/tuple that starts with a VC base context
# --------------------------------------------------------------------------- #

_CONTEXTS_BAD = [
    pytest.param("https://x/", id="str"),
    pytest.param(VC2, id="str-vc2"),
    pytest.param("", id="empty-str"),
    pytest.param(5, id="int"),
    pytest.param(0, id="zero"),
    pytest.param(True, id="true"),
    pytest.param(NAN, id="nan"),
    pytest.param(object(), id="object"),
    pytest.param(b"https://x/", id="bytes"),
    pytest.param(bytearray(VC2.encode()), id="bytearray"),
    pytest.param({}, id="empty-dict"),
    pytest.param({VC2: 1}, id="dict-of-keys"),
    pytest.param({"@vocab": "https://x/#"}, id="vocab-object"),
    pytest.param({VC2}, id="set"),
    pytest.param(frozenset({VC2}), id="frozenset"),
    pytest.param(iter([VC2]), id="iterator"),
    pytest.param((c for c in [VC2]), id="generator"),
    pytest.param(range(3), id="range"),
    pytest.param(collections.deque([VC2]), id="deque"),
    pytest.param([], id="empty-list"),
    pytest.param((), id="empty-tuple"),
    # an entry that is not a context at all
    pytest.param([5], id="list-int"),
    pytest.param([None], id="list-none"),
    pytest.param([""], id="list-empty-str"),
    pytest.param([[VC2]], id="list-nested-list"),
    pytest.param([b"x"], id="list-bytes"),
    pytest.param([VC2, ""], id="empty-second"),
    pytest.param([VC2, 5], id="int-second"),
    pytest.param([VC2, None], id="none-second"),
    pytest.param([VC2, b"https://x/"], id="bytes-second"),
    pytest.param([VC2, [VC2]], id="list-second"),
    pytest.param([VC2, object()], id="object-second"),
    pytest.param([VC2, "https://x/ctx", 5], id="int-third"),
    pytest.param((VC2, None), id="tuple-none-second"),
    # decision (b): the first entry is a VC base context
    pytest.param(["https://x/"], id="no-base-context"),
    pytest.param(["https://x/", VC2], id="base-context-second"),
    pytest.param([{"@vocab": "https://x/#"}], id="object-first"),
    pytest.param([{"@vocab": "https://x/#"}, VC2], id="object-first-then-base"),
    pytest.param([{}], id="empty-object-first"),
    pytest.param([VC2 + "/"], id="base-context-with-slash"),
    pytest.param([VC2.replace("https", "http")], id="base-context-http"),
    pytest.param([VC2.upper()], id="base-context-upper"),
    pytest.param([" " + VC2], id="base-context-space"),
    pytest.param([VC2[:-1]], id="base-context-truncated"),
    pytest.param([VC2.encode()], id="base-context-bytes"),
    pytest.param((BIG,), id="tuple-no-base-context"),
]


@pytest.mark.parametrize("value", _CONTEXTS_BAD)
def test_contexts_refuses_what_is_not_a_context_list(value):
    refused(lambda: cred_unsigned(contexts=value), names="contexts")


def test_contexts_str_is_not_read_one_character_at_a_time():
    # the issue's headline row: ``list("https://x/")``
    exc = refused(lambda: cred(contexts="https://x/"))
    assert "'h', 't'" not in str(exc)


def test_contexts_error_names_the_offending_position():
    assert "contexts[2]" in str(refused(lambda: cred(contexts=[VC2, "https://x/c", 5])))
    assert "first contexts entry" in str(refused(lambda: cred(contexts=["https://x/"])))
    assert "empty" in str(refused(lambda: cred(contexts=[])))


# --------------------------------------------------------------------------- #
# Decision (a): a falsy value that is not None is an error, never the default
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", ["", 0, [], {}])
def test_falsy_subject_id_is_an_error_not_the_default(value):
    refused(lambda: cred(subject_id=value), names="subject_id")


@pytest.mark.parametrize("value", [[], "", 0, {}])
def test_falsy_contexts_is_an_error_not_the_default(value):
    refused(lambda: cred(contexts=value), names="contexts")


def test_none_still_gives_the_defaults():
    vc = cred(subject_id=None, contexts=None)
    assert vc["credentialSubject"]["id"] == f"{LIST_URL}#list"
    assert vc["@context"] == [VC2]
    assert cred()["credentialSubject"]["id"] == f"{LIST_URL}#list"
    assert cred()["@context"] == [VC2]
    assert "id" not in entry()
    assert "id" not in entry(id=None)
    assert "iss" not in claims_of(tok())
    assert "iss" not in claims_of(tok(issuer=None))


# --------------------------------------------------------------------------- #
# Bounded messages: a 60 KB value never reaches the error text (brief())
# --------------------------------------------------------------------------- #

def test_a_60kb_value_gives_a_short_message():
    refusals = [
        lambda: cred(issuer=[BIG]),
        lambda: cred(issuer=BIG.encode()),
        lambda: cred(issuer={"id": [BIG]}),
        lambda: cred(issuer={"id": BIG, "@id": BIG}),
        lambda: cred(issuer={"id": BIG.encode()}),
        lambda: cred(subject_id=[BIG]),
        lambda: cred(subject_id=BIG.encode()),
        lambda: cred(contexts=BIG),
        lambda: cred(contexts=[BIG]),
        lambda: cred(contexts=(BIG, VC2)),
        lambda: cred(contexts=[VC2, BIG.encode()]),
        lambda: cred(contexts=[VC2, [BIG]]),
        lambda: entry(id=[BIG]),
        lambda: entry(id=BIG.encode()),
        lambda: tok_unsigned(issuer=[BIG]),
        lambda: tok_unsigned(issuer=BIG.encode()),
    ]
    for call in refusals:
        assert len(str(refused(call))) < 400


def test_a_5000_digit_integer_gives_a_short_message():
    for call in (lambda: cred(issuer=HUGE), lambda: cred(subject_id=HUGE),
                 lambda: cred(contexts=HUGE), lambda: entry(id=HUGE),
                 lambda: tok_unsigned(issuer=HUGE)):
        assert "a 16610-bit integer" in str(refused(call))


# --------------------------------------------------------------------------- #
# Controls: what is well formed still builds, signs and verifies
# --------------------------------------------------------------------------- #

def test_controls_credential_issuer():
    assert cred(issuer=DID)["issuer"] == DID
    obj = {"id": DID, "name": "Acme", "image": {"type": "Image"}}
    vc = cred(issuer=obj)
    assert vc["issuer"] == obj
    assert cred(issuer={"id": "did:example:x"})["issuer"] == {"id": "did:example:x"}
    assert cred(issuer=collections.OrderedDict(id=DID))["issuer"] == {"id": DID}


def test_controls_subject_id():
    assert cred()["credentialSubject"]["id"] == f"{LIST_URL}#list"
    assert cred(subject_id="https://status.example/w3c/1#mine")["credentialSubject"]["id"] \
        == "https://status.example/w3c/1#mine"
    assert cred(subject_id="urn:uuid:1")["credentialSubject"]["id"] == "urn:uuid:1"


_CONTEXT_CONTROLS = [
    pytest.param(None, [VC2], id="none"),
    pytest.param([VC2], [VC2], id="list"),
    pytest.param((VC2,), [VC2], id="tuple"),
    pytest.param([VC1], [VC1], id="vc-1.1"),
    pytest.param([VC2, {"@vocab": "https://x/#"}], [VC2, {"@vocab": "https://x/#"}],
                 id="vocab-object"),
    pytest.param([VC2, "https://x/ctx"], [VC2, "https://x/ctx"], id="context-url"),
    pytest.param((VC2, "https://x/ctx", {"@vocab": "https://y/#"}),
                 [VC2, "https://x/ctx", {"@vocab": "https://y/#"}], id="tuple-of-three"),
    pytest.param([VC2, {"term": "https://x/#term"}], [VC2, {"term": "https://x/#term"}],
                 id="object-with-term"),
]


@pytest.mark.parametrize("given, expected", _CONTEXT_CONTROLS)
def test_controls_contexts(given, expected):
    context = cred(contexts=given)["@context"]
    assert context == expected
    assert type(context) is list


def test_controls_entry_id():
    assert "id" not in entry()
    built = entry(id="https://status.example/w3c/1#94567")
    assert built["id"] == "https://status.example/w3c/1#94567"
    assert parse_status_entries({"credentialStatus": built})


def test_controls_token_issuer():
    assert claims_of(tok(issuer=DID))["iss"] == DID
    assert "iss" not in claims_of(tok())


def test_a_token_without_an_issuer_is_still_refused_by_the_default_resolver():
    # ``issuer=None`` stays allowed (tests/test_resolvers.py pins this): the token is
    # built, and the resolver that has to find its key says why it cannot
    token = tok()
    exc = refused(lambda: default_status_list_token_resolver(fetch=lambda u: token)(TOKEN_URI))
    assert "iss" in str(exc)


# Decision (c): no URI-shape rule, as in #250 for the other pointer strings. The JOSE and JCS
# lanes and the check side have none (key resolution refuses an unresolvable issuer), and
# only the RDF suites require an IRI, refusing with a typed error at ``add_proof``.
def test_no_uri_shape_is_checked():
    assert cred(issuer="not a uri")["issuer"] == "not a uri"
    assert cred(issuer={"id": "not a uri"})["issuer"] == {"id": "not a uri"}
    assert cred(subject_id="not a uri")["credentialSubject"]["id"] == "not a uri"
    assert entry(id="not a uri")["id"] == "not a uri"
    assert claims_of(tok(issuer="not a uri"))["iss"] == "not a uri"
    assert cred(contexts=[VC2, "not a uri"])["@context"] == [VC2, "not a uri"]
    # and no length cap: a 60 KB identifier is the caller's to send
    assert cred(issuer=BIG)["issuer"] == BIG
    assert entry(id=BIG)["id"] == BIG
    assert cred(contexts=[VC2, BIG])["@context"] == [VC2, BIG]


def test_the_inputs_are_not_mutated_and_the_artefact_does_not_alias_them():
    issuer = {"id": DID, "name": "Acme", "image": {"type": "Image"}}
    before_issuer = json.dumps(issuer, sort_keys=True)
    contexts = [VC2, {"@vocab": "https://x/#"}]
    before_contexts = json.dumps(contexts, sort_keys=True)
    vc = cred(issuer=issuer, contexts=contexts)
    assert json.dumps(issuer, sort_keys=True) == before_issuer
    assert json.dumps(contexts, sort_keys=True) == before_contexts
    assert vc["issuer"] is not issuer and vc["@context"] is not contexts
    # the artefact's own top-level containers are the caller's no longer
    vc["issuer"]["id"] = "did:example:changed"
    vc["@context"].append("https://x/late")
    assert issuer["id"] == DID and contexts == [VC2, {"@vocab": "https://x/#"}]
    again = cred(issuer=issuer, contexts=contexts)
    assert again["issuer"]["id"] == DID and again["@context"] == contexts


# --------------------------------------------------------------------------- #
# Hostile containers: the value checked is the value emitted
# --------------------------------------------------------------------------- #

class _BrokenDict(dict):
    """A ``dict`` whose iteration protocol raises, as a broken subclass would."""

    def __iter__(self):
        raise RuntimeError("iteration is broken")

    def keys(self):
        raise RuntimeError("keys() is broken")


class _BrokenList(list):
    def __iter__(self):
        raise RuntimeError("iteration is broken")


class _LyingDict(dict):
    """Answers a valid issuer through every accessor, and holds another one."""

    def __getitem__(self, key):
        return DID if key == "id" else super().__getitem__(key)

    def get(self, key, default=None):
        return DID if key == "id" else super().get(key, default)

    def __contains__(self, key):
        return key == "id"


class _LyingList(list):
    """Reads as a valid context list through ``__getitem__`` and holds another."""

    def __getitem__(self, index):
        return VC2 if index == 0 else super().__getitem__(index)


def test_a_broken_dict_subclass_is_typed():
    refused(lambda: cred_unsigned(issuer=_BrokenDict(id=DID)), names="issuer")


def test_a_broken_list_subclass_is_typed():
    refused(lambda: cred_unsigned(contexts=_BrokenList([VC2])), names="contexts")


def test_a_dict_subclass_is_refused_for_what_it_holds_not_for_what_it_says():
    # it answers ``id`` and denies ``@id``, but its storage has no id and an @id
    lying = _LyingDict({"@id": "did:other", "name": "x"})
    refused(lambda: cred_unsigned(issuer=lying), names="issuer")


def test_a_list_subclass_is_refused_for_what_it_holds_not_for_what_it_says():
    refused(lambda: cred_unsigned(contexts=_LyingList(["https://x/"])), names="contexts")


def test_what_is_emitted_is_what_was_checked_for_a_container_subclass():
    vc = cred(issuer=_LyingDict({"id": DID, "name": "x"}), contexts=_LyingList([VC2, "u"]))
    assert type(vc["issuer"]) is dict and vc["issuer"] == {"id": DID, "name": "x"}
    assert type(vc["@context"]) is list and vc["@context"] == [VC2, "u"]
    json.dumps(vc)


class _KeysRaiseDict(dict):
    """Overrides ``keys()`` alone: ``dict()`` copies a dict subclass from its storage and
    never asks."""

    def keys(self):
        raise RuntimeError("keys() is broken")


class _IterRaiseDict(dict):
    """Overrides ``__iter__`` alone: ``dict()`` then asks the inherited ``dict.keys()``."""

    def __iter__(self):
        raise RuntimeError("iteration is broken")


class _GetitemRaiseDict(dict):
    """Overrides ``__getitem__`` alone: the copy reads the storage, not the accessor."""

    def __getitem__(self, key):
        raise RuntimeError("__getitem__ is broken")


@pytest.mark.parametrize("subclass", [_KeysRaiseDict, _IterRaiseDict, _GetitemRaiseDict],
                         ids=["keys-only", "iter-only", "getitem-only"])
def test_a_dict_subclass_that_overrides_one_accessor_is_copied_from_its_storage(subclass):
    # the claim in the docstring and the CHANGELOG: only a COPY that raises is typed
    # (``_BrokenDict`` above overrides both); the other overrides are never consulted
    vc = cred(issuer=subclass({"id": DID, "name": "x"}))
    assert type(vc["issuer"]) is dict and vc["issuer"] == {"id": DID, "name": "x"}


class _IterGetitemRaiseDict(dict):
    """Overrides ``__iter__`` (delegating) and ``__getitem__``: ``dict()`` then reads it
    through its accessors, and the first of them raises."""

    def __iter__(self):
        return super().__iter__()

    def __getitem__(self, key):
        raise RuntimeError("__getitem__ is broken")


class _IterGetitemLiesDict(dict):
    def __iter__(self):
        return super().__iter__()

    def __getitem__(self, key):
        return DID if key == "id" else super().__getitem__(key)


class _IterKeysHidesDict(dict):
    def __iter__(self):
        return super().__iter__()

    def keys(self):
        return [key for key in super().keys() if key != "@id"]


def test_a_dict_subclass_that_overrides_iter_is_read_through_its_accessors():
    # the rule in the docstring: an ``__iter__`` override sends ``dict()`` through the
    # subclass's own ``keys()`` / ``__getitem__``; a raise there is typed, and whatever the
    # copy returns is what is checked AND emitted (an ``@id`` that ``keys()`` hides is
    # neither seen nor written)
    refused(lambda: cred_unsigned(issuer=_IterGetitemRaiseDict(id=DID)), names="issuer")
    lying = cred(issuer=_IterGetitemLiesDict({"id": "did:example:stored", "name": "x"}))
    assert type(lying["issuer"]) is dict and lying["issuer"] == {"id": DID, "name": "x"}
    hidden = cred(issuer=_IterKeysHidesDict({"id": DID, "@id": "did:other"}))
    assert hidden["issuer"] == {"id": DID}


class _HiddenKey(str):
    """A key whose hash is not its characters': ``"@id" in issuer`` cannot find it, and the
    encoder writes it as ``@id`` all the same."""

    def __hash__(self):
        return 12345


def test_a_key_that_hides_from_lookup_is_copied_as_a_plain_str():
    hidden = {"id": DID, _HiddenKey("@id"): "did:other"}
    assert "@id" not in hidden                     # the premise: the lookup is blind to it
    refused(lambda: cred_unsigned(issuer=hidden), names="issuer")
    lone = {_HiddenKey("id"): DID}
    assert "id" not in lone
    vc = cred(issuer=lone)                         # found by its characters, emitted as such
    assert vc["issuer"] == {"id": DID} and type(next(iter(vc["issuer"]))) is str


# --------------------------------------------------------------------------- #
# Hostile strings: the characters are what is tested and what is emitted
# --------------------------------------------------------------------------- #
# A ``str`` subclass can answer ``len()``, ``bool()``, ``[]``, ``==``, ``hash()``, ``str()``
# and ``format()`` however it likes, but the JSON encoder writes the characters it holds.
# The builders copy every string to a plain ``str`` (``plain_str``, the counterpart of
# ``plain_int``) before testing it and emit the copy, so a subclass can neither escape as a
# bare exception nor be checked as one value and written as another.

REAL = "did:example:real"


class _LenRaises(str):
    def __len__(self):
        raise RuntimeError("__len__ is broken")


class _BoolRaises(str):
    def __bool__(self):
        raise RuntimeError("__bool__ is broken")


class _GetitemRaises(str):
    def __getitem__(self, index):
        raise RuntimeError("__getitem__ is broken")


class _EqHashRaise(str):
    def __eq__(self, other):
        raise RuntimeError("__eq__ is broken")

    def __hash__(self):
        raise RuntimeError("__hash__ is broken")


class _SaysEmpty(str):
    """Holds characters and claims it is empty and something else."""

    def __len__(self):
        return 0

    def __bool__(self):
        return False

    def __str__(self):
        return "LIE"

    def __repr__(self):
        return "LIE"

    def __format__(self, spec):
        return "LIE"

    def __eq__(self, other):
        return False

    def __hash__(self):
        return 0


class _SaysFull(str):
    """Holds no character and claims it is not empty."""

    def __len__(self):
        return 5

    def __bool__(self):
        return True

    def __getitem__(self, index):
        return "x"

    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0


_HOLDING = [_LenRaises, _BoolRaises, _GetitemRaises, _EqHashRaise, _SaysEmpty]

# Each way a string reaches an artefact: the output holds what the encoder would write.
# The first six are this change's parameters, the rest are #250's, which share ``_text``.
_STRING_SLOTS = {
    "issuer": lambda v: cred(issuer=v)["issuer"],
    "issuer-id": lambda v: cred(issuer={"id": v})["issuer"]["id"],
    "subject_id": lambda v: cred(subject_id=v)["credentialSubject"]["id"],
    "contexts-second": lambda v: cred(contexts=[VC2, v])["@context"][1],
    "entry-id": lambda v: entry(id=v)["id"],
    "token-issuer": lambda v: claims_of(tok(issuer=v))["iss"],
    "credential-id": lambda v: build_status_list_credential(
        id=v, issuer=DID, bitstring=BITS)["id"],
    "status-purpose": lambda v: build_status_list_credential(
        id=LIST_URL, issuer=DID, bitstring=BITS,
        status_purpose=v)["credentialSubject"]["statusPurpose"],
    "entry-credential": lambda v: build_status_list_entry(
        status_list_credential=v, index=1)["statusListCredential"],
    "token-uri": lambda v: claims_of(
        build_status_list_token(signing_key=SK, uri=v, status_list=LST))["sub"],
    "reference-uri": lambda v: build_token_status_reference(
        uri=v, index=1)["status"]["status_list"]["uri"],
}


@pytest.mark.parametrize("slot", _STRING_SLOTS)
@pytest.mark.parametrize("subclass", _HOLDING)
def test_a_str_subclass_is_read_by_its_characters_and_emitted_as_a_plain_str(slot, subclass):
    got = _STRING_SLOTS[slot](subclass(REAL))
    assert type(got) is str and got == REAL


@pytest.mark.parametrize("slot", _STRING_SLOTS)
def test_a_str_subclass_that_claims_to_hold_something_is_empty_when_it_is(slot):
    refused(lambda: _STRING_SLOTS[slot](_SaysFull("")))


def test_a_lying_format_does_not_reach_the_default_subject():
    # ``f"{id}#list"``: a ``__format__`` / ``__str__`` that lies must not be asked
    vc = build_status_list_credential(id=_SaysEmpty(LIST_URL), issuer=DID, bitstring=BITS)
    assert vc["credentialSubject"]["id"] == f"{LIST_URL}#list"
    assert type(vc["id"]) is str and vc["id"] == LIST_URL


@pytest.mark.parametrize("subclass", _HOLDING)
def test_a_str_subclass_as_the_first_context_is_tested_by_its_characters(subclass):
    got = cred(contexts=[subclass(VC2), subclass("https://x/ctx")])["@context"]
    assert got == [VC2, "https://x/ctx"] and {type(c) for c in got} == {str}


class _ClaimsToBeVc2(str):
    """Holds another URL and claims, through ``__eq__`` and ``__hash__``, to be the VC 2.0
    context: a set lookup believes it."""

    def __hash__(self):
        return hash(VC2)

    def __eq__(self, other):
        return other == VC2


@pytest.mark.parametrize("first", [
    pytest.param(_ClaimsToBeVc2("https://x/"), id="claims-to-be-vc2"),
    pytest.param(_GetitemRaises("https://x/"), id="getitem-raises"),
    pytest.param(_LenRaises("https://x/"), id="len-raises"),
    pytest.param(_EqHashRaise("https://x/"), id="eq-hash-raise"),
    pytest.param(_SaysFull(""), id="says-full"),
])
def test_a_str_subclass_that_is_not_a_base_context_is_refused(first):
    exc = refused(lambda: cred_unsigned(contexts=[first]), names="first contexts entry")
    assert len(str(exc)) < 400


def test_a_str_subclass_in_a_message_is_rendered_from_its_characters():
    long = _GetitemRaises("x" * 50)
    assert brief(long) == repr("x" * 32) + "..."
    assert brief(_SaysEmpty("abc")) == "'abc'"
    refused(lambda: cred(subject_id=_SaysFull("")), names="subject_id")


# --------------------------------------------------------------------------- #
# Lane agreement: the controls are accepted by every lane, not decided per lane
# --------------------------------------------------------------------------- #

def _secure(lane: str, credential: dict[str, Any], *, extra_contexts: Any = None) -> Any:
    if lane == "vc-jwt":
        artefact = VcJwtProofSuite().sign(credential, signing_key=SK)
        return lambda url: artefact
    if lane == "eddsa-jcs-2022":
        document = EddsaJcsProofSuite().add_proof(
            credential, signing_key=SK, verification_method=VM)
    else:
        pytest.importorskip("pyld")
        from openvc.proof.data_integrity import DataIntegrityProofSuite
        document = DataIntegrityProofSuite().add_proof(
            credential, signing_key=SK, verification_method=VM,
            extra_contexts=extra_contexts)
    text = json.dumps(document)
    return lambda url: text


_LANES = ["vc-jwt", "eddsa-jcs-2022", "eddsa-rdfc-2022"]

_LANE_CONTROLS = [
    pytest.param({}, id="defaults"),
    pytest.param({"issuer": {"id": DID, "name": "Acme"}}, id="issuer-object"),
    pytest.param({"subject_id": f"{LIST_URL}#mine"}, id="subject-id"),
    pytest.param({"contexts": [VC2]}, id="contexts-list"),
    pytest.param({"contexts": (VC2,)}, id="contexts-tuple"),
    pytest.param({"contexts": [VC2, {"@vocab": "https://x/#"}]}, id="contexts-vocab"),
]


@pytest.mark.parametrize("lane", _LANES)
@pytest.mark.parametrize("kw", _LANE_CONTROLS)
def test_controls_are_accepted_on_every_lane(lane, kw):
    built = cred(**kw)
    fetch = _secure(lane, built)
    got = default_status_list_resolver(fetch=fetch)(LIST_URL)
    assert got["credentialSubject"]["id"] == built["credentialSubject"]["id"]
    assert got["@context"] == built["@context"]


@pytest.mark.parametrize("lane", _LANES)
def test_controls_also_pass_the_whole_pipeline(lane):
    # verify_credential, not only the resolver that wraps it
    fetch = _secure(lane, cred(issuer={"id": DID, "name": "Acme"}))
    artefact = fetch(LIST_URL)
    result = verify_credential(
        artefact if lane == "vc-jwt" else json.loads(artefact),
        policy=VerificationPolicy(require_status=False))
    assert result.issuer == DID


@pytest.mark.parametrize("contexts", [
    pytest.param([VC2, "https://x/ctx"], id="context-url"),
    pytest.param([VC1], id="vc-1.1"),            # no BitstringStatusList term: RDF needs v2
])
@pytest.mark.parametrize("lane", ["vc-jwt", "eddsa-jcs-2022"])
def test_a_shape_only_context_is_accepted_on_the_lanes_that_load_nothing(lane, contexts):
    built = cred(contexts=contexts)
    got = default_status_list_resolver(fetch=_secure(lane, built))(LIST_URL)
    assert got["@context"] == contexts


def test_a_context_url_needs_extra_contexts_on_the_rdf_lane():
    pytest.importorskip("pyld")
    extra = {"https://x/ctx": {"@context": {"@vocab": "https://x/#"}}}
    built = cred(contexts=[VC2, "https://x/ctx"])
    fetch = _secure("eddsa-rdfc-2022", built, extra_contexts=extra)
    got = default_status_list_resolver(fetch=fetch, extra_contexts=extra)(LIST_URL)
    assert got["@context"] == [VC2, "https://x/ctx"]


def test_the_token_with_an_issuer_is_accepted_by_the_default_resolver():
    token = tok(issuer=DID)
    claims = default_status_list_token_resolver(fetch=lambda u: token)(TOKEN_URI)
    assert claims["iss"] == DID and claims["sub"] == TOKEN_URI


# --------------------------------------------------------------------------- #
# Properties: whatever the builders accept, the artefact is JSON and the pipeline takes it
# --------------------------------------------------------------------------- #

class _AnyDid:
    """A registry that serves the test key for ANY DID string, so key resolution cannot
    mask the field under test. (An ``https://`` issuer is routed to the jwt-vc-issuer
    path and never reaches a registry, which is why issuers here are ``did:`` strings.)"""

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


_DID = st.from_regex(r"did:[a-z]{1,6}:[A-Za-z0-9._-]{1,30}", fullmatch=True)
_LEAF = st.one_of(
    st.none(), st.booleans(), st.integers(-2 ** 53, 2 ** 53), st.text(max_size=12),
    st.floats(allow_nan=False, allow_infinity=False))
_JSON = st.recursive(
    _LEAF, lambda inner: st.lists(inner, max_size=3) | st.dictionaries(
        st.text(max_size=6), inner, max_size=3), max_leaves=6)
_JSON_OBJECT = st.dictionaries(st.text(max_size=6), _JSON, max_size=3)
# Values that are never an identifier (an object is one only for ``contexts`` / ``issuer``,
# so it is added separately where it can be well formed).
_JUNK_BASE = st.one_of(
    st.none(), st.booleans(), st.integers(), st.floats(), st.binary(max_size=8),
    st.just(""), st.lists(_JSON, max_size=3), st.sets(st.integers(), max_size=2))
_JUNK = st.one_of(_JUNK_BASE, _JSON_OBJECT)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _model_issuer(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value)
    return (isinstance(value, dict) and "@id" not in value and _is_text(value.get("id")))


def _model_contexts(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, (list, tuple)) or not value:
        return False
    if not (isinstance(value[0], str) and value[0] in (VC2, VC1)):
        return False
    return all(isinstance(e, dict) or _is_text(e) for e in value[1:])


_ISSUERS = st.one_of(
    _DID, _JUNK,
    st.builds(lambda i, extra: {**extra, "id": i}, _DID, _JSON_OBJECT),
    st.builds(lambda i, extra, at: {**extra, "id": i, "@id": at}, _DID, _JSON_OBJECT, _JSON),
    st.builds(lambda i, extra: {**extra, "id": i}, _JUNK, _JSON_OBJECT))
_TEXTS = st.one_of(st.none(), st.text(max_size=20), _JUNK)
_CONTEXT_ENTRY = st.one_of(
    st.sampled_from([VC2, VC1, "https://x/ctx"]), st.text(max_size=12), _JSON_OBJECT, _JUNK)
_CONTEXTS = st.one_of(
    st.none(), _JUNK,
    st.builds(lambda first, rest, as_tuple: tuple([first, *rest]) if as_tuple
              else [first, *rest],
              st.sampled_from([VC2, VC1]) | _JUNK, st.lists(_CONTEXT_ENTRY, max_size=3),
              st.booleans()),
    st.lists(_CONTEXT_ENTRY, max_size=3))


@settings(max_examples=300, deadline=None)
@given(issuer=_ISSUERS)
def test_property_credential_issuer_matches_the_rule(issuer):
    if _model_issuer(issuer):
        vc = cred(issuer=issuer)
        json.dumps(vc, allow_nan=False)
        assert vc["issuer"] == issuer
    else:
        refused(lambda: cred_unsigned(issuer=issuer))


@settings(max_examples=300, deadline=None)
@given(subject_id=_TEXTS)
def test_property_subject_id_matches_the_rule(subject_id):
    if subject_id is None or _is_text(subject_id):
        vc = cred(subject_id=subject_id)
        expected = f"{LIST_URL}#list" if subject_id is None else subject_id
        assert vc["credentialSubject"]["id"] == expected
    else:
        refused(lambda: cred_unsigned(subject_id=subject_id))


@settings(max_examples=300, deadline=None)
@given(contexts=_CONTEXTS)
def test_property_contexts_matches_the_rule(contexts):
    if _model_contexts(contexts):
        vc = cred(contexts=contexts)
        json.dumps(vc, allow_nan=False)
        assert vc["@context"] == ([VC2] if contexts is None else list(contexts))
    else:
        refused(lambda: cred_unsigned(contexts=contexts))


@settings(max_examples=200, deadline=None)
@given(value=_TEXTS)
def test_property_entry_id_and_token_issuer_match_the_rule(value):
    if value is None or _is_text(value):
        built = entry(id=value)
        assert ("id" in built) == (value is not None)
        assert ("iss" in claims_of(tok(issuer=value))) == (value is not None)
    else:
        refused(lambda: entry(id=value))
        refused(lambda: tok_unsigned(issuer=value))


# What the builders accept by construction: a DID or an object that names one with ``id``
# (and any JSON members besides), a non-empty subject, a context list that starts with a
# base context. The model properties above cover the refusals; here the point is the
# other half of the contract, that EVERYTHING the builders accept is read by the pipeline.
_EXTRAS = _JSON_OBJECT.map(lambda d: {k: v for k, v in d.items() if k not in ("id", "@id")})
_VALID_ISSUERS = st.one_of(
    _DID, st.builds(lambda i, extra: {**extra, "id": i}, _DID, _EXTRAS))
_VALID_SUBJECTS = st.one_of(st.none(), st.text(min_size=1, max_size=20))
_VALID_CONTEXTS = st.one_of(
    st.none(),
    st.builds(lambda first, rest, as_tuple: tuple([first, *rest]) if as_tuple
              else [first, *rest],
              st.sampled_from([VC2, VC1]),
              st.lists(st.one_of(st.text(min_size=1, max_size=12), _JSON_OBJECT), max_size=3),
              st.booleans()))


@pytest.mark.parametrize("lane", ["vc-jwt", "eddsa-jcs-2022"])
@settings(max_examples=100, deadline=None)
@given(issuer=_VALID_ISSUERS, subject_id=_VALID_SUBJECTS, contexts=_VALID_CONTEXTS)
def test_property_whatever_the_builder_accepts_the_pipeline_accepts(
        lane, issuer, subject_id, contexts):
    """Built => JSON-serialisable AND accepted by the pipeline on a lane that reads no
    context (through ``default_status_list_resolver``, with a registry that serves the key
    for any DID). The issuer's own DID is the key's ``kid``, so an object issuer is checked
    against the ``iss`` it signs."""
    assert _model_issuer(issuer) and _model_contexts(contexts)
    did = issuer if isinstance(issuer, str) else issuer["id"]
    key = Ed25519SigningKey(PRIV, f"{did}#0")
    vc = cred(issuer=issuer, subject_id=subject_id, contexts=contexts)
    json.dumps(vc, allow_nan=False)
    if lane == "vc-jwt":
        wire = VcJwtProofSuite().sign(vc, signing_key=key)
    else:
        wire = json.dumps(EddsaJcsProofSuite().add_proof(
            vc, signing_key=key, verification_method=f"{did}#0"))
    got = default_status_list_resolver(resolver=_AnyDid(), fetch=lambda u: wire)(LIST_URL)
    assert got["credentialSubject"]["id"] == vc["credentialSubject"]["id"]
    assert got["@context"] == vc["@context"]


@settings(max_examples=100, deadline=None)
@given(issuer=st.one_of(st.none(), _DID))
def test_property_the_token_issuer_is_what_the_default_resolver_needs(issuer):
    token = build_status_list_token(
        signing_key=Ed25519SigningKey(PRIV, f"{issuer}#0"), uri=TOKEN_URI, status_list=LST,
        issuer=issuer)
    resolve = default_status_list_token_resolver(resolver=_AnyDid(), fetch=lambda u: token)
    if issuer is None:
        refused(lambda: resolve(TOKEN_URI), names="iss")
    else:
        assert resolve(TOKEN_URI)["iss"] == issuer
