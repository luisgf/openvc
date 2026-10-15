"""
tests/test_key_resolution_error_family.py — one key-resolution error family across the JOSE
and the Data Integrity lanes, sync and async (#283).

The same failed key resolution used to be reported as one of two unrelated classes, by lane:
``KeyResolutionFailed(VerificationError)`` from the JOSE lanes, and
``KeyResolutionError(ProofError)`` from every Data Integrity suite. The async Data Integrity
lane raised both: ``aio._preresolved_di_resolver`` turned a ``DidResolutionError`` into
``KeyResolutionFailed`` before the suite ran, while everything the suite itself decided stayed
``KeyResolutionError``. A malformed ``did:key``, checked where the registry has no ``did:key``
resolver, raised a bare ``DidResolutionError`` (neither a ``ProofError`` nor a
``VerificationError``).

The rule now:

* ``KeyResolutionError`` is also a ``KeyResolutionFailed`` (hence a ``VerificationError``):
  ``class KeyResolutionError(ProofError, KeyResolutionFailed)``. The two classes it extends are
  defined in ``openvc.errors`` (``openvc.proof`` cannot import ``openvc.verify``) and
  re-exported from ``openvc.verify``, still reporting ``openvc.verify`` as their
  ``__module__``;
* the JOSE lanes raise the plain ``KeyResolutionFailed``, which is not a ``ProofError``;
* every Data Integrity entry point, sync and async, raises exactly ``KeyResolutionError`` for
  the same failure, including the offline ``did:key`` fallback.

Every row uses a credential that is really signed and a document that is really served: the
control of each row is the same credential against the good document, so a negative cannot
pass on a failure other than the resolution. Every assertion is on the exact class
(``type(exc) is …``) and on ``type(exc.__cause__)``.

Scenarios (the issue's letters): (a1) the fetch raises ``DidResolutionError``; (a2) the issuer
DID method has no resolver in the registry (``did:example``); (b) a document of the wrong
shape (``verificationMethod: null``, #219); (c) a valid document that does not hold the key
the credential names.

``openvc.verify`` is the only place the two moved classes are imported from at module level, so
this module collects on a tree where ``openvc.errors`` does not define them yet; the
``openvc.errors`` identity is asserted inside the tests that need it.

tests/ is not a package: nothing is imported from another test module.
"""
from __future__ import annotations

import asyncio
import pickle
import traceback
from typing import Any, Callable
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import openvc
import openvc.errors
import openvc.verify
from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
    verify_vp_token,
)
from openvc.did.base import (
    AsyncDidResolverRegistry,
    DidError,
    DidResolutionError,
    DidResolverRegistry,
    UnsupportedDidMethod,
    as_async_resolver,
    parse_did_document,
)
from openvc.did.did_key import DidKeyResolver
from openvc.did.did_web import AsyncDidWebResolver, DidWebResolver
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite
from openvc.proof.errors import KeyResolutionError, ProofError, ProofPurposeMismatch
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.verify import KeyResolutionFailed, VerificationError

try:
    import pyld  # noqa: F401
    _HAS_PYLD = True
except ImportError:                                    # pragma: no cover
    _HAS_PYLD = False

needs_pyld = pytest.mark.skipif(not _HAS_PYLD, reason="the RDF-canonicalized suites need pyld")

V2 = "https://www.w3.org/ns/credentials/v2"
POLICY = VerificationPolicy(require_status=False)
NONCE = "n-283"
DOMAIN = "x509_san_dns:verifier.example"
SUBJECT = "did:example:alice"
SCENARIOS = ("a1", "a2", "b", "c")
ENTRY_POINTS = ("verify_credential", "verify_credential_async", "verify_many",
                "verify_many_async")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

class _Static:
    """A sync resolver for one DID that has no fetch (``did:example``)."""
    def __init__(self, did: str, raw: dict) -> None:
        self._did, self._doc = did, parse_did_document(raw)

    def supports(self, did: str) -> bool:
        return did == self._did

    def resolve(self, did: str):
        return self._doc


class _AsyncStatic(_Static):
    async def resolve(self, did: str):                          # type: ignore[override]
        return self._doc


class World:
    """An issuer (or holder) in one of the scenarios, with its key.

    ``served(failing)`` is what the ``did:web`` fetch yields for it: the good document, or the
    scenario's bad one (an exception instance is raised by the fetch). In scenario a2 the DID
    is ``did:example:…``, which no ``did:web`` resolver handles: the control registers a
    static resolver for it, the failing registry has none.
    """
    def __init__(self, scenario: str, name: str = "issuer", *, curve: str = "ed25519") -> None:
        self.scenario = scenario
        self.host = f"{name}.example"
        self.did = f"did:example:{name}" if scenario == "a2" else f"did:web:{self.host}"
        self.kid = f"{self.did}#k"
        self.subject = SUBJECT                    # who credentials this world issues are about
        make = Ed25519SigningKey if curve == "ed25519" else P256SigningKey
        self.key = make.generate(kid=self.kid)

    def method(self, vm_id: str | None = None) -> dict:
        return {"id": vm_id or self.kid, "type": "JsonWebKey2020", "controller": self.did,
                "publicKeyJwk": self.key.public_jwk()}

    def good_doc(self) -> dict:
        return {"id": self.did, "verificationMethod": [self.method()],
                "assertionMethod": [self.kid], "authentication": [self.kid]}

    def served(self, failing: bool) -> Any:
        if not failing:
            return self.good_doc()
        if self.scenario == "a1":
            return DidResolutionError("issuer is down")
        if self.scenario == "b":
            return {"id": self.did, "verificationMethod": None}
        # c (and a2, whose did:web fetch is never reached): a valid document without the key
        return {**self.good_doc(), "verificationMethod": [self.method(self.did + "#other")],
                "assertionMethod": [self.did + "#other"], "authentication": [self.did + "#other"]}

    def credential(self) -> dict:
        return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": self.did,
                "credentialSubject": {"id": self.subject}}


def _registries(*placed: tuple[World, bool]) -> tuple[DidResolverRegistry,
                                                      AsyncDidResolverRegistry]:
    """A (sync, async) registry pair serving each ``(world, failing)``, plus did:key; the
    did:web fetch is one function dispatching on the host."""
    served: dict[str, Any] = {}
    statics: list[World] = []
    for world, failing in placed:
        if world.scenario == "a2":
            if not failing:
                statics.append(world)
            continue
        served[world.host] = world.served(failing)

    def fetch(url: str) -> dict:
        doc = served[urlparse(url).hostname]
        if isinstance(doc, Exception):
            raise doc
        return doc

    async def afetch(url: str) -> dict:
        return fetch(url)

    sync = [_Static(w.did, w.good_doc()) for w in statics]
    asyn = [_AsyncStatic(w.did, w.good_doc()) for w in statics]
    return (DidResolverRegistry([*sync, DidWebResolver(fetch=fetch), DidKeyResolver()]),
            AsyncDidResolverRegistry([*asyn, AsyncDidWebResolver(fetch=afetch),
                                      as_async_resolver(DidKeyResolver())]))


def _vc_jwt(world: World) -> str:
    return VcJwtProofSuite().sign(world.credential(), signing_key=world.key)


def _sd_jwt(world: World) -> str:
    return SdJwtVcProofSuite().issue(
        {"iss": world.did, "sub": world.subject}, signing_key=world.key,
        vct="https://example.com/vct")


def _di_jcs(world: World) -> dict:
    return EddsaJcsProofSuite().add_proof(world.credential(), signing_key=world.key,
                                          verification_method=world.kid)


def _di_suite(name: str) -> Any:
    if name == "eddsa-rdfc-2022":
        from openvc.proof.data_integrity import DataIntegrityProofSuite
        return DataIntegrityProofSuite()
    return EddsaJcsProofSuite()


def _di_rdfc(world: World) -> dict:
    return _di_suite("eddsa-rdfc-2022").add_proof(world.credential(), signing_key=world.key,
                                                  verification_method=world.kid)


# the two Data Integrity suites an Ed25519 key can use, with the one that needs pyld marked
DI_SUITES = ["eddsa-jcs-2022", pytest.param("eddsa-rdfc-2022", marks=needs_pyld)]


# lane -> (family, builder). "jose" lanes raise KeyResolutionFailed, "di" lanes KeyResolutionError
LANES: dict[str, tuple[str, Callable[[World], Any]]] = {
    "vc-jwt": ("jose", _vc_jwt),
    "sd-jwt-vc": ("jose", _sd_jwt),
    "eddsa-jcs-2022": ("di", _di_jcs),
    "eddsa-rdfc-2022": ("di", _di_rdfc),
}
LANE_PARAMS = [pytest.param(name, marks=needs_pyld) if name == "eddsa-rdfc-2022" else name
               for name in LANES]
EXACT = {"jose": KeyResolutionFailed, "di": KeyResolutionError}

# type(exc.__cause__) per (family, scenario). A method that is not in a document, and a DID
# method with no resolver on the Data Integrity lane, have no cause; the JOSE lanes carry the
# UnsupportedDidMethod the registry raised.
CAUSE = {
    ("jose", "a1"): DidResolutionError, ("jose", "a2"): UnsupportedDidMethod,
    ("jose", "b"): DidResolutionError, ("jose", "c"): type(None),
    ("di", "a1"): DidResolutionError, ("di", "a2"): type(None),
    ("di", "b"): DidResolutionError, ("di", "c"): type(None),
}


def _outcome(entry: str, credential: Any, registries: tuple) -> Any:
    """What *entry* gives for *credential*: the raised exception, ``BatchResult.error`` for a
    batch, or the ``VerificationResult``."""
    sync, asyn = registries
    try:
        if entry == "verify_credential":
            return verify_credential(credential, resolver=sync, policy=POLICY)
        if entry == "verify_credential_async":
            return asyncio.run(verify_credential_async(credential, resolver=asyn, policy=POLICY))
        if entry == "verify_many":
            (item,) = verify_many([credential], resolver=sync, policy=POLICY)
        else:
            (item,) = asyncio.run(verify_many_async([credential], resolver=asyn, policy=POLICY))
        return item.error if item.error is not None else item.result
    except Exception as exc:                          # noqa: BLE001 - the point is the class
        return exc


def _caught(handler: type | tuple, call: Callable[[], Any]) -> bool:
    """Whether ``except handler`` catches what *call* raises (it must raise something)."""
    try:
        try:
            call()
        except handler:
            return True
    except Exception:                                 # noqa: BLE001
        return False
    raise AssertionError("the call did not raise")


# --------------------------------------------------------------------------- #
# 1. the map: the exact class and cause per lane, entry point and scenario
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("lane", LANE_PARAMS)
def test_every_entry_point_raises_the_lanes_exact_class(lane, entry, scenario):
    family, build = LANES[lane]
    world = World(scenario)
    credential = build(world)

    # control: the same credential, signed by the same key, verifies against the good
    # document, so the resolution is the only thing the negative below changes
    ok = _outcome(entry, credential, _registries((world, False)))
    assert not isinstance(ok, BaseException), repr(ok)
    assert ok.issuer == world.did

    got = _outcome(entry, credential, _registries((world, True)))
    assert type(got) is EXACT[family], repr(got)
    assert type(got.__cause__) is CAUSE[(family, scenario)]


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("lane", LANE_PARAMS)
def test_every_failure_is_a_key_resolution_failed_and_only_the_di_ones_a_proof_error(
        lane, entry, scenario):
    family, build = LANES[lane]
    world = World(scenario)
    got = _outcome(entry, build(world), _registries((world, True)))
    assert isinstance(got, BaseException), repr(got)
    # one family: every lane's failure is a KeyResolutionFailed and a VerificationError ...
    assert isinstance(got, KeyResolutionFailed) and isinstance(got, VerificationError)
    # ... and only the Data Integrity lanes' is also a ProofError / KeyResolutionError
    assert isinstance(got, ProofError) is (family == "di")
    assert isinstance(got, KeyResolutionError) is (family == "di")


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("suite_name", DI_SUITES)
def test_a_data_integrity_suite_verify_with_a_resolver_raises_the_same_class(
        suite_name, scenario):
    suite = _di_suite(suite_name)
    world = World(scenario)
    credential = suite.add_proof(world.credential(), signing_key=world.key,
                                 verification_method=world.kid)
    sync_ok, _ = _registries((world, False))
    assert suite.verify(credential, resolver=sync_ok).proof["verificationMethod"] == world.kid

    sync_bad, _ = _registries((world, True))
    with pytest.raises(KeyResolutionError) as exc:
        suite.verify(credential, resolver=sync_bad)
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is CAUSE[("di", scenario)]


def _signed_for(cryptosuite: str, world: World) -> tuple[Any, dict]:
    """(suite, secured credential) for *cryptosuite*; the world's key is P-256 for ecdsa."""
    if cryptosuite == "ecdsa-jcs-2019":
        suite = EcdsaJcsProofSuite()
    elif cryptosuite == "ecdsa-rdfc-2019":
        from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
        suite = EcdsaRdfcProofSuite()
    else:
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        suite = EcdsaSdProofSuite()
        base = suite.add_base_proof(world.credential(), signing_key=world.key,
                                    verification_method=world.kid, mandatory_pointers=["/issuer"])
        return suite, suite.derive_proof(base, selective_pointers=[])
    return suite, suite.add_proof(world.credential(), signing_key=world.key,
                                  verification_method=world.kid)


@pytest.mark.parametrize("scenario", ["a1", "b", "c"])
@pytest.mark.parametrize("cryptosuite", [
    "ecdsa-jcs-2019",
    pytest.param("ecdsa-rdfc-2019", marks=needs_pyld),
    "ecdsa-sd-2023",
])
def test_the_ecdsa_suites_raise_the_same_class_sync_and_async(cryptosuite, scenario):
    # the three suites the issue read from the source rather than ran: same function, same class
    world = World(scenario, curve="p256")
    suite, credential = _signed_for(cryptosuite, world)
    assert suite.verify(credential, resolver=_registries((world, False))[0]).proof

    registries = _registries((world, True))
    with pytest.raises(KeyResolutionError) as exc:
        suite.verify(credential, resolver=registries[0])
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is CAUSE[("di", scenario)]
    for entry in ENTRY_POINTS:
        got = _outcome(entry, credential, registries)
        assert type(got) is KeyResolutionError, (entry, repr(got))
        assert type(got.__cause__) is CAUSE[("di", scenario)]


# --------------------------------------------------------------------------- #
# 2. the handlers a caller writes
# --------------------------------------------------------------------------- #

CATCHES = {
    # except clause -> caught by a (JOSE failure, Data Integrity failure)
    KeyResolutionFailed: (True, True),
    VerificationError: (True, True),
    KeyResolutionError: (False, True),
    ProofError: (False, True),
}


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("lane", LANE_PARAMS)
def test_each_except_clause_catches_what_the_family_rule_says(lane, scenario):
    family, build = LANES[lane]
    world = World(scenario)
    credential = build(world)
    sync, asyn = _registries((world, True))
    calls = {
        "sync": lambda: verify_credential(credential, resolver=sync, policy=POLICY),
        "async": lambda: asyncio.run(
            verify_credential_async(credential, resolver=asyn, policy=POLICY)),
    }
    for name, call in calls.items():
        for handler, (jose, di) in CATCHES.items():
            expected = di if family == "di" else jose
            assert _caught(handler, call) is expected, (name, handler.__name__)


@pytest.mark.parametrize("scenario", ["a1", "b"])      # the async cells that changed class
def test_an_ordered_handler_routes_a_data_integrity_failure_to_the_first_matching_branch(scenario):
    # The SemVer note of #283: a failure moves between branches of an ordered handler. A
    # Data Integrity failure was a ProofError only (and, on the async lane for a1 and b, a
    # plain KeyResolutionFailed); it is now both, so the first matching branch wins on both
    # API styles. A JOSE failure never reaches a ProofError branch.
    world = World(scenario)
    di, jose = _di_jcs(world), _vc_jwt(world)
    sync, asyn = _registries((world, True))

    def branch(call, order):
        try:
            call()
        except order[0][1]:
            return order[0][0]
        except order[1][1]:
            return order[1][0]
        raise AssertionError("not caught")

    proof_first = [("proof", ProofError), ("resolution", KeyResolutionFailed)]
    verification_first = [("verification", VerificationError), ("proof", ProofError)]
    for call in (lambda: verify_credential(di, resolver=sync, policy=POLICY),
                 lambda: asyncio.run(verify_credential_async(di, resolver=asyn, policy=POLICY))):
        assert branch(call, proof_first) == "proof"
        assert branch(call, verification_first) == "verification"
    for call in (lambda: verify_credential(jose, resolver=sync, policy=POLICY),
                 lambda: asyncio.run(verify_credential_async(jose, resolver=asyn, policy=POLICY))):
        assert branch(call, proof_first) == "resolution"
        assert branch(call, verification_first) == "verification"


# --------------------------------------------------------------------------- #
# 3. the hierarchy, and where the two moved classes live
# --------------------------------------------------------------------------- #

def test_the_mro_of_the_data_integrity_class():
    assert KeyResolutionError.__mro__[:5] == (
        KeyResolutionError, ProofError, KeyResolutionFailed, VerificationError,
        openvc.errors.OpenvcError)
    assert issubclass(KeyResolutionError, KeyResolutionFailed)
    assert issubclass(KeyResolutionError, VerificationError)
    assert issubclass(KeyResolutionError, ProofError)


def test_the_jose_class_is_not_a_proof_error_and_the_narrowing_stays_closed():
    assert not issubclass(KeyResolutionFailed, ProofError)
    assert not issubclass(KeyResolutionFailed, KeyResolutionError)
    assert KeyResolutionFailed.__mro__[:3] == (
        KeyResolutionFailed, VerificationError, openvc.errors.OpenvcError)
    # the other pipeline errors are untouched siblings, not key-resolution failures
    for name in ("UnknownCredentialFormat", "TypeMismatch", "IssuerBindingError",
                 "StatusUnavailable", "StatusListIssuerUntrusted"):
        cls = getattr(openvc.verify, name)
        assert issubclass(cls, VerificationError)
        assert not issubclass(cls, KeyResolutionFailed) and not issubclass(cls, ProofError)


def test_the_two_classes_live_in_openvc_errors_and_every_old_path_is_the_same_object():
    import openvc.aio
    import openvc.errors
    assert openvc.verify.KeyResolutionFailed is openvc.errors.KeyResolutionFailed
    assert openvc.verify.VerificationError is openvc.errors.VerificationError
    assert openvc.VerificationError is openvc.errors.VerificationError
    assert openvc.aio.KeyResolutionFailed is openvc.errors.KeyResolutionFailed
    for name in ("KeyResolutionFailed", "VerificationError"):
        assert name in openvc.verify.__all__
        assert name in openvc.errors.__all__
    # the Data Integrity class keeps its homes
    from openvc.proof import data_integrity, ecdsa_sd, errors
    assert errors.KeyResolutionError is KeyResolutionError
    assert data_integrity.KeyResolutionError is KeyResolutionError
    assert ecdsa_sd.KeyResolutionError is KeyResolutionError
    assert "KeyResolutionError" in errors.__all__


def test_the_moved_classes_still_report_openvc_verify_as_their_module():
    # tracebacks, repr and pickle name the class exactly as before the move
    assert KeyResolutionFailed.__module__ == "openvc.verify"
    assert VerificationError.__module__ == "openvc.verify"
    assert KeyResolutionError.__module__ == "openvc.proof.errors"
    assert openvc.verify.UnknownCredentialFormat.__module__ == "openvc.verify"
    exc = KeyResolutionFailed("no key")
    assert traceback.format_exception_only(type(exc), exc) == [
        "openvc.verify.KeyResolutionFailed: no key\n"]
    exc = VerificationError("bad")
    assert traceback.format_exception_only(type(exc), exc) == [
        "openvc.verify.VerificationError: bad\n"]
    for original in (KeyResolutionFailed("no key"), KeyResolutionError("no key")):
        clone = pickle.loads(pickle.dumps(original))
        assert type(clone) is type(original) and str(clone) == "no key"


def test_a_real_failure_reads_as_the_old_class_name_in_a_traceback():
    world = World("b")
    sync, _ = _registries((world, True))
    with pytest.raises(KeyResolutionFailed) as jose:
        verify_credential(_vc_jwt(world), resolver=sync, policy=POLICY)
    assert traceback.format_exception_only(type(jose.value), jose.value)[0].startswith(
        "openvc.verify.KeyResolutionFailed: ")
    with pytest.raises(KeyResolutionError) as di:
        verify_credential(_di_jcs(world), resolver=sync, policy=POLICY)
    assert traceback.format_exception_only(type(di.value), di.value)[0].startswith(
        "openvc.proof.errors.KeyResolutionError: ")


# --------------------------------------------------------------------------- #
# 4. the third class: a malformed did:key where the registry has no did:key resolver
# --------------------------------------------------------------------------- #

BAD_KEY_DID = "did:key:zNOTAKEY"                  # 'O' is not in the base58 alphabet
BAD_KEY_VM = f"{BAD_KEY_DID}#zNOTAKEY"


def _bad_key_credential(suite: Any, key: Any) -> dict:
    return suite.add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": BAD_KEY_DID,
         "credentialSubject": {"id": SUBJECT}},
        signing_key=key, verification_method=BAD_KEY_VM)


def _no_did_key_registries() -> tuple[DidResolverRegistry, AsyncDidResolverRegistry]:
    async def afetch(url):
        raise AssertionError("the did:web fetch must not be reached")

    def fetch(url):
        raise AssertionError("the did:web fetch must not be reached")
    return (DidResolverRegistry([DidWebResolver(fetch=fetch)]),
            AsyncDidResolverRegistry([AsyncDidWebResolver(fetch=afetch)]))


def test_the_bad_did_key_is_a_resolution_error_of_the_did_key_resolver():
    # the cause the cases below must carry, and the reason it is a DidResolutionError
    with pytest.raises(DidResolutionError, match="invalid base58 character") as exc:
        DidKeyResolver().resolve(BAD_KEY_DID)
    assert type(exc.value) is DidResolutionError


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_a_malformed_did_key_without_a_did_key_resolver_is_a_key_resolution_error(entry):
    key = Ed25519SigningKey.generate(kid=BAD_KEY_VM)
    credential = _bad_key_credential(EddsaJcsProofSuite(), key)
    got = _outcome(entry, credential, _no_did_key_registries())
    assert type(got) is KeyResolutionError, repr(got)
    assert type(got.__cause__) is DidResolutionError


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_a_malformed_did_key_is_no_longer_a_did_error_but_its_cause_still_is(entry):
    # the one place an ``except`` clause stops matching (CHANGELOG 1.35.0, a recorded
    # maintainer exception to the versioning rule): the bare DidResolutionError was a
    # DidError; the KeyResolutionError that replaces it is not, and keeps the original.
    key = Ed25519SigningKey.generate(kid=BAD_KEY_VM)
    credential = _bad_key_credential(EddsaJcsProofSuite(), key)
    got = _outcome(entry, credential, _no_did_key_registries())
    assert type(got) is KeyResolutionError, repr(got)
    assert not isinstance(got, DidError)
    assert type(got.__cause__) is DidResolutionError
    assert isinstance(got.__cause__, DidError)


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_the_same_credential_with_a_did_key_resolver_is_a_key_resolution_error(entry):
    # control: the registry path was typed before #283 for the sync entry points, and the
    # default pipeline has a did:key resolver. The async ones went through
    # aio._preresolved_di_resolver and gave KeyResolutionFailed until the same edit.
    key = Ed25519SigningKey.generate(kid=BAD_KEY_VM)
    credential = _bad_key_credential(EddsaJcsProofSuite(), key)
    got = _outcome(entry, credential, (
        DidResolverRegistry([DidKeyResolver()]),
        AsyncDidResolverRegistry([as_async_resolver(DidKeyResolver())])))
    assert type(got) is KeyResolutionError, repr(got)
    assert type(got.__cause__) is DidResolutionError


def test_the_default_pipeline_gives_the_same_class_for_a_malformed_did_key():
    key = Ed25519SigningKey.generate(kid=BAD_KEY_VM)
    credential = _bad_key_credential(EddsaJcsProofSuite(), key)
    with pytest.raises(KeyResolutionError) as exc:
        verify_credential(credential, policy=POLICY)
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is DidResolutionError


@pytest.mark.parametrize("suite_name", DI_SUITES)
@pytest.mark.parametrize("resolver", [None, "registry-without-did-key"])
def test_a_suite_verify_with_no_resolver_or_no_did_key_resolver_is_typed(
        suite_name, resolver):
    suite = _di_suite(suite_name)
    key = Ed25519SigningKey.generate(kid=BAD_KEY_VM)
    credential = _bad_key_credential(suite, key)
    if resolver is not None:
        resolver = _no_did_key_registries()[0]
    with pytest.raises(KeyResolutionError) as exc:
        suite.verify(credential, resolver=resolver)
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is DidResolutionError


# --------------------------------------------------------------------------- #
# 5. the new try reaches only the did:key resolver call
# --------------------------------------------------------------------------- #

def _did_key(key: Ed25519SigningKey) -> tuple[str, str]:
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())
    return f"did:key:{mb}", f"did:key:{mb}#{mb}"


def _did_key_signer() -> tuple[Ed25519SigningKey, str, str]:
    """(a key whose ``kid`` is its own did:key URL, the did:key, that URL)."""
    private = ed25519.Ed25519PrivateKey.generate()
    did, vm = _did_key(Ed25519SigningKey(private, kid="_"))
    return Ed25519SigningKey(private, kid=vm), did, vm


def _did_key_credential(vm_override: str | None = None) -> tuple[dict, str]:
    key, did, vm = _did_key_signer()
    credential = EddsaJcsProofSuite().add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": SUBJECT}},
        signing_key=key, verification_method=vm_override.format(did=did) if vm_override else vm)
    return credential, did


def test_a_resolvable_did_key_verifies():
    credential, did = _did_key_credential()
    assert EddsaJcsProofSuite().verify(credential, resolver=None).proof
    assert verify_credential(credential, policy=POLICY).issuer == did


def test_a_did_key_method_that_is_not_in_the_document_is_not_a_resolution_error_of_the_resolver():
    # the resolver succeeded: the refusal is the document's lookup, so there is no
    # DidResolutionError to carry as a cause
    credential, did = _did_key_credential("{did}#not-the-key")
    for resolver in (None, DidResolverRegistry([DidKeyResolver()])):
        with pytest.raises(KeyResolutionError, match="not in the DID document") as exc:
            EddsaJcsProofSuite().verify(credential, resolver=resolver)
        assert type(exc.value) is KeyResolutionError
        assert exc.value.__cause__ is None
    with pytest.raises(KeyResolutionError, match="not in the DID document") as exc:
        verify_credential(credential, policy=POLICY)
    assert type(exc.value) is KeyResolutionError and exc.value.__cause__ is None


def test_a_did_key_method_that_is_not_authorized_for_the_purpose_stays_a_purpose_mismatch(
        monkeypatch):
    # did:key's own document grants its key assertionMethod and authentication, so a document
    # that withholds the relationship stands in for it. The resolver succeeds; what follows is
    # the purpose check, which must not be swept into the resolution error.
    credential, _ = _did_key_credential()
    original = DidKeyResolver.resolve

    def withholding(self, did):
        return parse_did_document({**original(self, did).raw, "assertionMethod": []})

    monkeypatch.setattr(DidKeyResolver, "resolve", withholding)
    with pytest.raises(ProofPurposeMismatch) as exc:
        EddsaJcsProofSuite().verify(credential, resolver=None)
    assert type(exc.value) is ProofPurposeMismatch
    assert not isinstance(exc.value, KeyResolutionFailed)


def test_only_a_did_resolution_error_from_the_did_key_resolver_is_retyped(monkeypatch):
    # A DidError that is not a DidResolutionError (and anything else) is not this change's to
    # swallow: it propagates as itself, exactly as before.
    credential, _ = _did_key_credential()

    def refusing(self, did):
        raise UnsupportedDidMethod("not a did:key after all")

    monkeypatch.setattr(DidKeyResolver, "resolve", refusing)
    with pytest.raises(UnsupportedDidMethod) as exc:
        EddsaJcsProofSuite().verify(credential, resolver=None)
    assert type(exc.value) is UnsupportedDidMethod
    assert not isinstance(exc.value, KeyResolutionFailed)


# --------------------------------------------------------------------------- #
# 6. batch isolation: the hostile item carries the typed error, the good one verifies
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("lane", LANE_PARAMS)
def test_verify_many_isolates_the_hostile_item_in_both_apis(lane, scenario):
    family, build = LANES[lane]
    world = World(scenario)
    hostile = build(world)
    good, good_did = _did_key_item(family)
    sync, asyn = _registries((world, True))

    for results in (verify_many([hostile, good], resolver=sync, policy=POLICY),
                    asyncio.run(verify_many_async([hostile, good], resolver=asyn,
                                                  policy=POLICY))):
        assert len(results) == 2
        assert type(results[0].error) is EXACT[family] and results[0].result is None
        assert type(results[0].error.__cause__) is CAUSE[(family, scenario)]
        assert results[1].ok and results[1].error is None
        assert results[1].result.issuer == good_did


def _did_key_item(family: str) -> tuple[Any, str]:
    """A good credential of the lane's family from a fresh ``did:key`` issuer."""
    key, did, vm = _did_key_signer()
    credential = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
                  "credentialSubject": {"id": SUBJECT}}
    if family == "di":
        return EddsaJcsProofSuite().add_proof(credential, signing_key=key,
                                              verification_method=vm), did
    return VcJwtProofSuite().sign(credential, signing_key=key), did


# --------------------------------------------------------------------------- #
# 7. verify_vp_token with an ldp_vc presentation
# --------------------------------------------------------------------------- #

LDP_QUERY = {"credentials": [{"id": "c1", "format": "ldp_vc"}]}


def _presentation(holder: World, embedded: list) -> dict:
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": holder.did,
          "verifiableCredential": embedded}
    return EddsaJcsProofSuite().add_proof(
        vp, signing_key=holder.key, verification_method=holder.kid,
        proof_purpose="authentication", challenge=NONCE, domain=DOMAIN)


def _verify_vp(vp: dict, registries: tuple):
    return verify_vp_token({"c1": [vp]}, dcql_query=LDP_QUERY, nonce=NONCE, client_id=DOMAIN,
                           resolver=registries[0])


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_the_ldp_vc_holder_proof_raises_the_data_integrity_class(scenario):
    holder, issuer = World(scenario, "holder"), World("c", "issuer")
    issuer.subject = holder.did             # the query requires holder binding
    vp = _presentation(holder, [_di_jcs(issuer)])
    control = _verify_vp(vp, _registries((holder, False), (issuer, False)))
    assert control.presentations[0].holder == holder.did

    with pytest.raises(KeyResolutionError) as exc:
        _verify_vp(vp, _registries((holder, True), (issuer, False)))
    assert type(exc.value) is KeyResolutionError
    assert type(exc.value.__cause__) is CAUSE[("di", scenario)]


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("lane", ["vc-jwt", "eddsa-jcs-2022"])
def test_an_embedded_credential_keeps_its_own_lanes_class(lane, scenario):
    family, build = LANES[lane]
    holder, issuer = World("c", "holder"), World(scenario, "issuer")
    issuer.subject = holder.did             # the query requires holder binding
    vp = _presentation(holder, [build(issuer)])
    control = _verify_vp(vp, _registries((holder, False), (issuer, False)))
    assert control.presentations[0].credentials[0].issuer == issuer.did

    with pytest.raises(EXACT[family]) as exc:
        _verify_vp(vp, _registries((holder, False), (issuer, True)))
    assert type(exc.value) is EXACT[family]
    assert type(exc.value.__cause__) is CAUSE[(family, scenario)]
