"""#427: under ``require_status=True`` a ``credentialStatus`` entry of a type openvc cannot
check fails closed even when another entry of the credential is recognised, before any
resolver is called. ``require_status=False`` and the direct ``check_credential_status``
API keep skipping it. Sync and async pipelines, VC-JWT and Data Integrity (JCS)."""
from __future__ import annotations

import asyncio
import time

import pytest

from openvc import VerificationPolicy, verify_credential, verify_credential_async
from openvc.did.base import DidResolverRegistry
from openvc.did.did_key import DidKeyResolver
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof._jws import sign_compact
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.status import (
    CredentialRevoked,
    CredentialSuspended,
    StatusListError,
    check_credential_status,
    parse_status_entries,
    unrecognised_status_entries,
)
from openvc.status.bitstring import encode_bitstring, new_bitstring, set_status_bit
from openvc.verify import StatusUnavailable

V2 = "https://www.w3.org/ns/credentials/v2"
URL = "https://status.example/lists/1"


def _key():
    raw = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + raw.public_key_raw())
    did = f"did:key:{mb}"
    return Ed25519SigningKey(raw._sk, kid=f"{did}#{mb}"), did


KEY, ISS = _key()
REG = DidResolverRegistry([DidKeyResolver()])

KNOWN = {"id": URL + "#7", "type": "BitstringStatusListEntry", "statusPurpose": "suspension",
         "statusListIndex": "7", "statusListCredential": URL}
UNKNOWN = {"id": "https://status.example/rl/3#9", "type": "RevocationList2020Status",
           "revocationListIndex": "9", "revocationListCredential": "https://status.example/rl/3"}
UNKNOWN2 = {"id": "https://status.example/other", "type": "SomeFutureStatusEntry2030"}


def _list(*, set_bit=None, purpose="suspension"):
    bits = new_bitstring(64)
    if set_bit is not None:
        set_status_bit(bits, set_bit, 1)
    return {"@context": [V2], "id": URL,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"], "issuer": ISS,
            "credentialSubject": {"id": URL + "#list", "type": "BitstringStatusList",
                                  "statusPurpose": purpose,
                                  "encodedList": encode_bitstring(bits)}}


def _vc(status):
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": ISS,
            "credentialSubject": {"id": "did:example:s"}, "credentialStatus": status}


def _jwt(status):
    now = int(time.time())
    claims = {"iss": ISS, "sub": "did:example:s", "nbf": now, "iat": now, "vc": _vc(status)}
    return sign_compact({"alg": KEY.alg, "typ": "JWT", "kid": KEY.kid}, claims,
                        signing_key=KEY)


def _di(status):
    return EddsaJcsProofSuite().add_proof(
        _vc(status), signing_key=KEY, verification_method=KEY.kid)


LANES = {"vc-jwt": _jwt, "di-jcs": _di}


class _Resolver:
    def __init__(self, doc):
        self.doc, self.calls = doc, 0

    def __call__(self, url):
        self.calls += 1
        return self.doc


def _run(mode, token, resolver, policy=None):
    kw = {"resolver": REG, "resolve_status_list": resolver}
    if policy is not None:
        kw["policy"] = policy
    if mode == "sync":
        return verify_credential(token, **kw)

    async def aresolver(url):
        return resolver(url)

    class _AsyncRegistry:
        async def resolve(self, did):
            return REG.resolve(did)

        def supports(self, did):
            return DidKeyResolver().supports(did)
    kw["resolve_status_list"] = aresolver
    kw["resolver"] = _AsyncRegistry()
    return asyncio.run(verify_credential_async(token, **kw))


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


@pytest.fixture(params=sorted(LANES))
def build(request):
    return LANES[request.param]


# -- the rows of the issue ----------------------------------------------------- #

def test_only_unrecognised_entry_refused_control(mode, build):
    with pytest.raises(StatusUnavailable):
        _run(mode, build(UNKNOWN), _Resolver(_list()))


def test_only_unrecognised_entry_in_array_refused_control(mode, build):
    with pytest.raises(StatusUnavailable):
        _run(mode, build([UNKNOWN]), _Resolver(_list()))


@pytest.mark.parametrize("entries", [[KNOWN, UNKNOWN], [UNKNOWN2, KNOWN],
                                     [UNKNOWN, KNOWN, UNKNOWN2]])
def test_recognised_plus_unrecognised_refused_without_fetch(mode, build, entries):
    resolver = _Resolver(_list())
    with pytest.raises(StatusUnavailable, match="unrecognised type"):
        _run(mode, build(entries), resolver)
    assert resolver.calls == 0            # refused before any resolver is called


def test_message_counts_the_entries(mode, build):
    with pytest.raises(StatusUnavailable, match="2 credentialStatus entries"):
        _run(mode, build([UNKNOWN, KNOWN, UNKNOWN2]), _Resolver(_list()))


def test_revoked_recognised_plus_unrecognised_is_unavailable_not_revoked(mode, build):
    resolver = _Resolver(_list(set_bit=7))
    with pytest.raises(StatusUnavailable):
        _run(mode, build([KNOWN, UNKNOWN]), resolver)
    assert resolver.calls == 0


def test_opt_out_still_checks_the_recognised_entry(mode, build):
    policy = VerificationPolicy(require_status=False)
    ok = _run(mode, build([KNOWN, UNKNOWN]), _Resolver(_list()), policy)
    assert ok.status is not None and not ok.status.revoked and not ok.status.suspended
    with pytest.raises(CredentialSuspended):   # the recognised entry is still enforced
        _run(mode, build([KNOWN, UNKNOWN]), _Resolver(_list(set_bit=7)), policy)


# -- controls: nothing else changes -------------------------------------------- #

def test_recognised_entries_only_still_pass(mode, build):
    ok = _run(mode, build([KNOWN]), _Resolver(_list()))
    assert ok.status is not None and not ok.status.revoked


def test_recognised_revoked_still_revoked(mode, build):
    revocation = dict(KNOWN, statusPurpose="revocation")
    with pytest.raises(CredentialRevoked):
        _run(mode, build(revocation), _Resolver(_list(set_bit=7, purpose="revocation")))


# -- the status layer ---------------------------------------------------------- #

def test_helper_counts_and_direct_api_keeps_skipping():
    cred = _vc([KNOWN, UNKNOWN, UNKNOWN2])
    assert unrecognised_status_entries(cred) == 2
    assert len(parse_status_entries(cred)) == 1
    assert unrecognised_status_entries(_vc([KNOWN])) == 0
    assert unrecognised_status_entries({}) == 0
    assert unrecognised_status_entries(_vc(UNKNOWN)) == 1
    result = check_credential_status(cred, resolve_status_list=lambda u: _list())
    assert not result.revoked


@pytest.mark.parametrize("status", [[KNOWN, {"id": "x"}], [UNKNOWN, ["nested"]], "ref"])
def test_helper_shares_the_parsers_shape_errors(status):
    with pytest.raises(StatusListError):
        unrecognised_status_entries(_vc(status))
    with pytest.raises(StatusListError):
        parse_status_entries(_vc(status))
