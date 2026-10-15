"""
tests/test_ecdsa_sd_issuer_context_typed.py — ``ecdsa-sd-2023`` ``add_base_proof`` and
``derive_proof`` fail typed when the credential cannot be canonicalized (#281).

``verify`` always had the arm: an ``@context`` that ``pyld`` cannot process (an unknown
URL, a typo'd one, a value that is not an array or a string, an inline object with a bad
term definition) was ``ProofMalformed``. The issuer and holder sides never did::

    add_base_proof(credential with @context [v2, "https://example.org/unknown"])
                                                  -> bare pyld.jsonld.JsonLdError
    derive_proof(base proof whose @context is swapped for the same)
                                                  -> bare pyld.jsonld.JsonLdError

Neither is an ``OpenvcError``, so an ``except OpenvcError`` around issuance or derivation
missed it, and ``derive_proof`` reads a credential a third-party issuer chose. Both now
raise ``ProofMalformed`` with the prefix ``could not canonicalize the credential``, the
class ``verify`` and ``_utf8_nquads`` already use. Only the canonicalization is guarded:
a signing-backend error (an HSM or Vault failure) surfaces as itself, and a ``ProofError``
raised inside the guarded block (a bad pointer, a ``validate_document`` refusal) keeps its
own class and message. The pyld text in the message is cut at 500 characters in the three
arms (``verify`` included), because pyld quotes the context it refused and a 1 MB
``@context`` made a 1 MB message.

Every negative asserts the EXACT class (``type(exc) is ProofMalformed``) and the message
prefix, so it cannot pass on a different failure; the issuer is a resolvable ``did:key``
and the subject is a named node (a blank node's statement is hashed inside the guarded
``normalize``, so only a named one reaches the later encode). The controls must pass
before and after: the round trip, the refusals that keep their own message, a context
served through ``extra_contexts``, the verify side, and the RDF siblings. Helpers are
self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import asyncio
import copy
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

pytest.importorskip("pyld")              # ecdsa-sd-2023 canonicalizes with pyld

from openvc import (  # noqa: E402
    VerificationPolicy,
    verify_credential,
    verify_many,
    verify_many_async,
)
from openvc.keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from openvc.multibase import encode_multibase  # noqa: E402
from openvc.proof import ecdsa_sd  # noqa: E402
from openvc.proof.contexts import DocumentLoaderError  # noqa: E402
from openvc.proof.data_integrity import DataIntegrityError, DataIntegrityProofSuite  # noqa: E402
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdError, EcdsaSdProofSuite  # noqa: E402
from openvc.proof.errors import ProofMalformed  # noqa: E402

V2 = "https://www.w3.org/ns/credentials/v2"
_PREFIX = "could not canonicalize the credential"
_DERIVED_PREFIX = "could not canonicalize the derived credential"

SUITE = EcdsaSdProofSuite()
_PRIVATE = ec.generate_private_key(ec.SECP256R1())
_RAW = P256SigningKey(_PRIVATE, kid="tmp").public_key_raw()
DID = "did:key:" + encode_multibase(bytes((0x80, 0x24)) + _RAW)      # multicodec p256-pub
VM = f"{DID}#{DID[len('did:key:'):]}"
SK = P256SigningKey(_PRIVATE, kid=VM)
MANDATORY = ["/issuer"]
SELECTIVE = ["/credentialSubject/name"]

# The ten @context values the issue measured: all ten escaped as a bare JsonLdError from
# add_base_proof and from derive_proof, and all ten are ProofMalformed from verify.
CASES = [
    ("unknown-url", [V2, "https://example.org/unknown"]),
    ("v2-typo", [V2, V2 + "X"]),
    ("v2-surrogate", [V2, V2 + "\ud800"]),
    ("bare-string-typo", V2 + "X"),
    ("int", 5),
    ("null-entry", [V2, None]),
    ("int-entry", [V2, 5]),
    ("vocab-int", [V2, {"@vocab": 5}]),
    ("version-int", [V2, {"@version": 2}]),
    ("term-id-int", [V2, {"x": {"@id": 5}}]),
]
CONTEXTS = [pytest.param(value, id=name) for name, value in CASES]


def credential(context: Any = None, **overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "@context": [V2] if context is None else context,
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
    }
    doc.update(overrides)
    return doc


def issue(doc: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("signing_key", SK)
    kwargs.setdefault("mandatory_pointers", MANDATORY)
    return SUITE.add_base_proof(
        doc if doc is not None else credential(), verification_method=VM, **kwargs)


BASE = issue()
DERIVED = SUITE.derive_proof(BASE, selective_pointers=SELECTIVE)


def with_context(doc: dict[str, Any], context: Any) -> dict[str, Any]:
    out = copy.deepcopy(doc)
    out["@context"] = context
    return out


def refused(call: Callable[[], Any], *, prefix: str = _PREFIX) -> ProofMalformed:
    """Run *call*, which must raise EXACTLY ProofMalformed whose text starts with
    *prefix*, and return the exception."""
    with pytest.raises(Exception) as caught:
        call()
    exc = caught.value
    assert type(exc) is ProofMalformed, f"{type(exc).__module__}.{type(exc).__name__}: {exc}"
    assert str(exc).startswith(prefix), str(exc)
    return exc


# --------------------------------------------------------------------------- #
# The negatives: what used to escape as a bare pyld JsonLdError
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("context", CONTEXTS)
def test_add_base_proof_types_a_context_pyld_refuses(context):
    exc = refused(lambda: issue(credential(context)))
    assert exc.__cause__ is not None, "the pyld error is chained, not dropped"


@pytest.mark.parametrize("context", CONTEXTS)
def test_derive_proof_types_a_context_pyld_refuses(context):
    exc = refused(lambda: SUITE.derive_proof(
        with_context(BASE, context), selective_pointers=SELECTIVE))
    assert exc.__cause__ is not None


def _type_int(held: dict[str, Any]) -> None:
    held["type"] = ["VerifiableCredential", 5]


def _subject_id_int(held: dict[str, Any]) -> None:
    held["credentialSubject"]["id"] = 5


def _subject_at_id_int(held: dict[str, Any]) -> None:
    held["credentialSubject"]["@id"] = 5


@pytest.mark.parametrize("damage", [
    pytest.param(_type_int, id="type-int"),
    pytest.param(_subject_id_int, id="subject-id-int"),
    pytest.param(_subject_at_id_int, id="subject-at-id-int"),
])
def test_derive_proof_types_a_body_pyld_refuses(damage):
    # the holder's input is a credential a third party issued: its body is not trusted
    held = copy.deepcopy(BASE)
    damage(held)
    refused(lambda: SUITE.derive_proof(held, selective_pointers=SELECTIVE))


def test_derive_proof_types_a_body_that_expands_but_does_not_compact():
    # `@reverse` expands, then JSON-LD refuses to compact it: the bare error came from the
    # second pyld call of _transform. Needs a vocab so that `knows` is a term.
    vocab = [V2, {"@vocab": "https://vocab.example/"}]
    base = issue(credential(vocab))
    SUITE.derive_proof(copy.deepcopy(base), selective_pointers=SELECTIVE)         # control
    held = copy.deepcopy(base)
    held["credentialSubject"]["@reverse"] = {"knows": {"id": "did:example:bob"}}
    refused(lambda: SUITE.derive_proof(held, selective_pointers=SELECTIVE))


def test_derive_proof_types_a_holder_view_it_cannot_build():
    # _reveal_view is the last step of the guarded block: a nested node spelled like a
    # skolem id (urn:bnid:c14n0) ended in a bare KeyError there before the guard
    vocab = [V2, {"@vocab": "https://vocab.example/"}]
    nested = issue(credential(vocab, credentialSubject={
        "id": "did:example:alice", "name": "Alice", "address": {"city": "X", "zip": "1"}}))
    nested["credentialSubject"]["address"]["@id"] = "urn:bnid:c14n0"
    refused(lambda: SUITE.derive_proof(nested, selective_pointers=["/credentialSubject/address"]))


def test_the_guard_covers_the_last_step_of_derive_proof(monkeypatch):
    # the same boundary without depending on which input reaches it
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise KeyError("a label the full document never had")

    monkeypatch.setattr(EcdsaSdProofSuite, "_reveal_view", broken)
    refused(lambda: SUITE.derive_proof(copy.deepcopy(BASE), selective_pointers=SELECTIVE))


# --------------------------------------------------------------------------- #
# Controls: what must not change
# --------------------------------------------------------------------------- #

def test_round_trip_still_verifies():
    verified = SUITE.verify(DERIVED, public_key_jwk=SK.public_jwk())
    assert verified.credential["credentialSubject"]["name"] == "Alice"
    result = verify_credential(
        copy.deepcopy(DERIVED), policy=VerificationPolicy(require_status=False))
    assert result.issuer == DID


def test_a_validate_document_refusal_keeps_its_own_message():
    # a ProofError raised inside the guarded block passes through: not re-worded
    with pytest.raises(ProofMalformed, match="may only carry @vocab") as caught:
        issue(credential([V2, {"x": "https://example.org/x"}]))
    assert type(caught.value) is ProofMalformed
    assert not str(caught.value).startswith(_PREFIX)
    with pytest.raises(ProofMalformed, match="non-empty array") as caught:
        issue(credential([]))
    assert type(caught.value) is ProofMalformed
    assert not str(caught.value).startswith(_PREFIX)


@pytest.mark.parametrize("damage", [
    pytest.param({"type": ["VerifiableCredential", 5]}, id="type-int"),
    pytest.param({"credentialSubject": {"id": 5, "name": "Alice"}}, id="subject-id-int"),
])
def test_add_base_proof_keeps_the_body_refusal_it_already_had(damage):
    with pytest.raises(ProofMalformed, match="cannot validate the document's JSON-LD form") as c:
        issue(credential(**damage))
    assert type(c.value) is ProofMalformed
    assert not str(c.value).startswith(_PREFIX)


class _Backend(Exception):
    """What an HSM or Vault backend raises: not an OpenvcError."""


class _FailingKey:
    alg = "ES256"
    kid = VM

    def sign(self, signing_input: bytes) -> bytes:
        raise _Backend("the signing backend is down")

    def public_jwk(self) -> dict[str, Any]:
        return SK.public_jwk()


def test_a_signing_backend_error_surfaces_as_itself():
    # the try covers canonicalization only; widening it over `sign` would turn an HSM
    # failure into "could not canonicalize the credential"
    with pytest.raises(_Backend, match="backend is down"):
        issue(signing_key=_FailingKey())


def test_an_ephemeral_key_error_surfaces_as_itself(monkeypatch):
    class _BrokenEphemeral(P256SigningKey):
        def sign(self, signing_input: bytes) -> bytes:
            raise _Backend("ephemeral signing failed")

    monkeypatch.setattr(ecdsa_sd, "P256SigningKey", _BrokenEphemeral)
    with pytest.raises(_Backend, match="ephemeral signing failed"):
        issue()


def test_a_bad_mandatory_pointer_stays_an_ecdsa_sd_error():
    with pytest.raises(EcdsaSdError, match="must start with '/'") as caught:
        issue(mandatory_pointers=["issuer"])
    assert type(caught.value) is EcdsaSdError


def test_a_pointer_that_does_not_resolve_stays_an_ecdsa_sd_error_on_derive():
    with pytest.raises(EcdsaSdError, match="does not resolve") as caught:
        SUITE.derive_proof(copy.deepcopy(BASE), selective_pointers=["/credentialSubject/nope"])
    assert type(caught.value) is EcdsaSdError


_NICK_URL = "https://example.org/ctx/nickname"
_NICK_EXTRA = {_NICK_URL: {"@context": {"nickname": "https://example.org/vocab#nickname"}}}


def _nickname_credential() -> dict[str, Any]:
    doc = credential([V2, _NICK_URL])
    doc["credentialSubject"]["nickname"] = "Al"
    return doc


def test_a_context_served_through_extra_contexts_still_issues():
    base = issue(_nickname_credential(), extra_contexts=_NICK_EXTRA)
    derived = SUITE.derive_proof(
        base, selective_pointers=["/credentialSubject/nickname"], extra_contexts=_NICK_EXTRA)
    SUITE.verify(derived, public_key_jwk=SK.public_jwk(), extra_contexts=_NICK_EXTRA)


def test_the_same_context_not_served_is_the_typed_refusal():
    # a missing extra_contexts is the realistic trigger: the message names the pyld failure
    refused(lambda: issue(_nickname_credential()))
    base = issue(_nickname_credential(), extra_contexts=_NICK_EXTRA)
    refused(lambda: SUITE.derive_proof(base, selective_pointers=["/credentialSubject/nickname"]))


# -- the verify side, which already had the arm ------------------------------ #

@pytest.mark.parametrize("context", CONTEXTS)
def test_verify_side_is_typed_and_keeps_its_own_prefix(context):
    shown = with_context(DERIVED, context)
    refused(lambda: SUITE.verify(shown, public_key_jwk=SK.public_jwk()),
            prefix=_DERIVED_PREFIX)
    refused(lambda: verify_credential(
        copy.deepcopy(shown), policy=VerificationPolicy(require_status=False)),
        prefix=_DERIVED_PREFIX)


@pytest.mark.parametrize("context", CONTEXTS)
def test_verify_many_returns_both_items(context):
    batch = [copy.deepcopy(DERIVED), with_context(DERIVED, context)]
    policy = VerificationPolicy(require_status=False)
    sync = verify_many(batch, policy=policy)
    parallel = asyncio.run(verify_many_async(copy.deepcopy(batch), policy=policy))
    for out in (sync, parallel):
        assert [r.index for r in out] == [0, 1]
        assert out[0].ok
        assert not out[1].ok and type(out[1].error) is ProofMalformed
        assert str(out[1].error).startswith(_DERIVED_PREFIX)


# -- the RDF siblings are unchanged ------------------------------------------ #

_LOADER_REFUSALS = {"unknown-url", "v2-typo", "v2-surrogate", "bare-string-typo"}


@pytest.mark.parametrize("sibling", ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"])
@pytest.mark.parametrize("name, context", [pytest.param(n, v, id=n) for n, v in CASES])
def test_the_rdf_siblings_keep_their_classes(sibling, name, context):
    if sibling == "eddsa-rdfc-2022":
        suite: Any = DataIntegrityProofSuite()
        key: Any = Ed25519SigningKey.generate(kid=VM)
    else:
        suite, key = EcdsaRdfcProofSuite(), SK
    expected = DocumentLoaderError if name in _LOADER_REFUSALS else DataIntegrityError
    with pytest.raises(expected) as caught:
        suite.add_proof(credential(context), signing_key=key, verification_method=VM)
    assert type(caught.value) is expected


# -- the message quotes the canonicalizer's text, cut ------------------------- #
#
# pyld puts the context it refused into its error text, so a 1 MB @context made a 1 MB
# ProofMalformed (derive_proof and verify read a credential a third party chose). All
# three arms now quote at most 500 characters and show the full length; the pyld error is
# the __cause__, whole. The cap is written out here, not imported, so a change to it shows
# up as a failing test.

_CAP = 500
_BIG = 1_000_000


def _call_add() -> Any:
    return issue()


def _call_derive() -> Any:
    return SUITE.derive_proof(copy.deepcopy(BASE), selective_pointers=SELECTIVE)


def _call_verify() -> Any:
    return SUITE.verify(copy.deepcopy(DERIVED), public_key_jwk=SK.public_jwk())


# (the first canonicalizing call inside each arm's guard, the call, the message prefix)
ARMS = [
    pytest.param("_proof_config_hash", _call_add, _PREFIX, id="add_base_proof"),
    pytest.param("_transform", _call_derive, _PREFIX, id="derive_proof"),
    pytest.param("_to_nquads", _call_verify, _DERIVED_PREFIX, id="verify"),
]


def _text(size: int) -> str:
    return ("0123456789" * (size // 10 + 1))[:size]


def _raising(error: Exception) -> Callable[..., Any]:
    def raiser(*args: Any, **kwargs: Any) -> Any:
        raise error
    return raiser


@pytest.mark.parametrize("target, call, prefix", ARMS)
@pytest.mark.parametrize("size", [0, 1, 499, _CAP])
def test_a_canonicalizer_text_up_to_the_cap_is_quoted_whole(
        monkeypatch, target, call, prefix, size):
    original = ValueError(_text(size))
    monkeypatch.setattr(ecdsa_sd, target, _raising(original))
    exc = refused(call, prefix=prefix)
    assert str(exc) == f"{prefix}: {_text(size)}"
    assert exc.__cause__ is original


@pytest.mark.parametrize("target, call, prefix", ARMS)
@pytest.mark.parametrize("size", [_CAP + 1, 5_000, _BIG])
def test_a_longer_canonicalizer_text_is_cut_and_its_length_shown(
        monkeypatch, target, call, prefix, size):
    original = ValueError(_text(size))
    monkeypatch.setattr(ecdsa_sd, target, _raising(original))
    exc = refused(call, prefix=prefix)
    assert str(exc) == f"{prefix}: {_text(_CAP)}... ({size} chars)"
    assert exc.__cause__ is original
    assert len(str(exc.__cause__)) == size, "the cause keeps the whole text"


def _cut(exc: ProofMalformed, prefix: str) -> None:
    assert len(str(exc)) <= len(prefix) + len(": ") + _CAP + len("... (1000000 chars)")
    assert exc.__cause__ is not None
    # the premise: pyld really did quote the oversized context, so a pass is not vacuous
    assert len(str(exc.__cause__)) > _BIG * 9 // 10


def test_add_base_proof_cuts_a_pyld_message_quoting_a_huge_context():
    exc = refused(lambda: issue(credential("x" * _BIG)))
    _cut(exc, _PREFIX)


def test_derive_proof_cuts_a_pyld_message_quoting_a_huge_context():
    for context in ("x" * _BIG, [V2, "https://example.org/" + "a" * _BIG]):
        exc = refused(lambda: SUITE.derive_proof(
            with_context(BASE, context), selective_pointers=SELECTIVE))
        _cut(exc, _PREFIX)


def test_verify_cuts_a_pyld_message_quoting_a_huge_context():
    exc = refused(lambda: SUITE.verify(
        with_context(DERIVED, "x" * _BIG), public_key_jwk=SK.public_jwk()),
        prefix=_DERIVED_PREFIX)
    _cut(exc, _DERIVED_PREFIX)


def test_an_ordinary_pyld_refusal_is_quoted_whole_by_every_arm():
    # the cap leaves the usual 130 to 470 character refusal alone: the text after the
    # prefix is exactly what pyld said, and the three arms agree on it
    for call, prefix in (
            (lambda: SUITE.derive_proof(with_context(BASE, [V2, 5]),
                                        selective_pointers=SELECTIVE), _PREFIX),
            (lambda: SUITE.verify(with_context(DERIVED, [V2, 5]),
                                  public_key_jwk=SK.public_jwk()), _DERIVED_PREFIX),
            (lambda: issue(credential([V2, 5])), _PREFIX)):
        exc = refused(call, prefix=prefix)
        cause_text = str(exc.__cause__)
        assert len(cause_text) <= _CAP
        assert str(exc) == f"{prefix}: {cause_text}"
