"""
tests/test_leeway_validation.py — one ``leeway_s`` contract across the library
(issues #228 and #232).

``leeway_s`` is the clock-skew tolerance every verify lane adds to its temporal checks.
Before v1.35.0 each lane read a bad value its own way. ``NaN`` (every comparison is
``False``), ``Infinity`` and anything wider than the checks could add switched expiry
off on VC-JWT (classic and ML-DSA), VP-JWT, the status-list token and Data Integrity; a
string or ``None`` escaped ``OpenvcError`` as a bare ``TypeError`` and aborted
``verify_many``; a float, a negative and a ``bool`` meant whatever the lane made of them.

The contract now: a whole number of seconds from 0 to ``MAX_LEEWAY_S`` (one day), as an
``int`` that is not a ``bool``, validated **once, up front**, at every entry point, with
the entry point's own typed error. A negative leeway, a float and a ``bool`` are refused
on every lane (some lanes used to clamp or accept them), and ``NaN`` / ``Infinity`` /
``10**12`` can no longer switch an expiry check off.

Every refusal below asserts the **exact** error class, never a bare exception, and that
an expired item is never accepted. The function entry points are fed garbage everywhere
else (an unreadable token, an empty nonce, no trust anchors), so the match on
``leeway_s`` proves the check runs before anything else is read. Helpers are
self-contained: ``tests/`` is not a package, so nothing is imported from another test.
"""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import time
from decimal import Decimal
from fractions import Fraction
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openvc import (
    InvalidPolicy,
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.keys import (
    Ed25519SigningKey,
    MLDSASigningKey,
    P256KeyAgreementKey,
    P256SigningKey,
    mldsa_available,
)
from openvc.mdoc import MdocError, verify_device_response, verify_issuer_signed
from openvc.multibase import encode_multibase
from openvc.openid4vci import CredentialRequestMalformed, verify_credential_request_proofs
from openvc.openid4vp import OpenID4VPError, verify_encrypted_vp_response, verify_vp_token
from openvc.proof._jws import sign_compact
from openvc.proof._verify_common import (
    DEFAULT_LEEWAY_S,
    MAX_LEEWAY_S,
    check_iat_freshness,
    check_jwt_temporal,
    check_validity_window,
    leeway_seconds,
    utc_window,
)
from openvc.proof.data_integrity import DataIntegrityProofSuite
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
from openvc.proof.errors import ClaimsInvalid, CredentialExpired, ProofError
from openvc.proof.sd_jwt import SdJwtError, SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.resolvers import (
    default_status_list_resolver,
    default_status_list_resolver_async,
    default_status_list_token_resolver,
    default_status_list_token_resolver_async,
)
from openvc.rp_registration import RpRegistrationError, verify_rp_registration_certificate
from openvc.status import StatusListError, verify_status_list_token
from openvc.status.issue import build_status_list_token
from openvc.status.token_status_list import new_status_list
from openvc.verify import default_resolver

# Only for the helper tests, which pass it as `now=` themselves. The builders read the
# clock when they run: a CI run is minutes long, and an import-time instant goes stale.
NOW = int(time.time())
VC2 = "https://www.w3.org/ns/credentials/v2"
VCT = "https://credentials.example/membership"
STATUS_URI = "https://status.example/1"


# --------------------------------------------------------------------------- #
# The value matrix
# --------------------------------------------------------------------------- #

class _FloatSub(float):
    """A float subclass (a numpy ``float64`` is one)."""


class _IndexOnly:
    """What a numpy ``int64`` looks like to Python: ``__index__``, but not an ``int``."""

    def __index__(self) -> int:
        return 60


class _LyingInt(int):
    """An int subclass whose comparisons say whatever the attacker wants."""

    def __lt__(self, other): return False
    def __le__(self, other): return True
    def __gt__(self, other): return False
    def __ge__(self, other): return True
    def __index__(self): return 5


class _ClaimsToBeInt:
    """Not an ``int``, but ``isinstance(x, int)`` says it is: ``__class__`` is honoured by
    ``isinstance`` and ignored by ``type``."""

    __class__ = property(lambda self: int)


# Every value a lane used to take for something: all are refused now.
BAD = [
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="inf"),
    pytest.param(float("-inf"), id="-inf"),
    pytest.param(-1, id="minus-1"),
    pytest.param(-60, id="minus-60"),
    pytest.param(True, id="True"),
    pytest.param(False, id="False"),
    pytest.param("60", id="str"),
    pytest.param(None, id="None"),
    pytest.param([], id="list"),
    pytest.param(b"60", id="bytes"),
    pytest.param(1j, id="complex"),
    pytest.param(60.0, id="float-60.0"),
    pytest.param(60.5, id="float-60.5"),
    pytest.param(1.5, id="float-1.5"),
    pytest.param(10 ** 12, id="10**12"),
    pytest.param(10 ** 400, id="10**400"),
    pytest.param(MAX_LEEWAY_S + 1, id="max+1"),
    pytest.param(Decimal(60), id="Decimal"),
    pytest.param(Fraction(60), id="Fraction"),
    pytest.param(_FloatSub(60), id="float-subclass"),
    pytest.param(_FloatSub("nan"), id="float-subclass-nan"),
    pytest.param(_IndexOnly(), id="index-only"),
    pytest.param(_LyingInt(10 ** 12), id="lying-int-out-of-range"),
    # isinstance() believes these are ints, then int.__index__ raises a bare TypeError
    pytest.param(_ClaimsToBeInt(), id="class-claims-int"),
    pytest.param(mock.Mock(spec=int), id="mock-spec-int"),
    pytest.param(mock.MagicMock(spec=int), id="magicmock-spec-int"),
]
# The ones that used to switch an expiry check off or escape as a bare exception.
FAIL_OPEN = [
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="inf"),
    pytest.param("60", id="str"),
    pytest.param(None, id="None"),
    pytest.param(10 ** 12, id="10**12"),
    pytest.param(10 ** 400, id="10**400"),
]
GOOD = [0, 1, 60, DEFAULT_LEEWAY_S, 300, 3600, MAX_LEEWAY_S]


# --------------------------------------------------------------------------- #
# Builders (copied, not imported: tests/ is not a package)
# --------------------------------------------------------------------------- #

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _did_jwk_key() -> tuple[P256SigningKey, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    did = "did:jwk:" + _b64(json.dumps(P256SigningKey(private, kid="-").public_jwk()).encode())
    return P256SigningKey(private, kid=f"{did}#0"), did


KEY, DID = _did_jwk_key()
CRED = {"@context": [VC2], "type": ["VerifiableCredential"], "issuer": DID,
        "credentialSubject": {"id": "did:example:alice"}}


def _vc_jwt(exp_in_s: int | None = None, *, nbf_in_s: int | None = None) -> str:
    """A VC-JWT from the did:jwk issuer; *exp_in_s* is relative to now (negative: lapsed)."""
    if nbf_in_s is not None:
        now = int(time.time())
        payload = {"iss": DID, "vc": CRED, "iat": now, "nbf": now + nbf_in_s}
        return sign_compact({"alg": "ES256", "typ": "JWT", "kid": KEY.kid}, payload,
                            signing_key=KEY)
    return VcJwtProofSuite().sign(CRED, signing_key=KEY, expires_in_s=exp_in_s)


def _sd_jwt(exp_in_s: int) -> str:
    return SdJwtVcProofSuite().issue(
        {"iss": DID, "name": "Ada"}, signing_key=KEY, vct=VCT, expires_in_s=exp_in_s)


def _vp_jwt(exp_in_s: int) -> str:
    return VpJwtProofSuite().sign([], holder_key=KEY, audience="aud", nonce="n",
                                  expires_in_s=exp_in_s)


def _status_token(exp_in_s: int) -> str:
    now = int(time.time())
    return build_status_list_token(
        signing_key=KEY, uri=STATUS_URI, status_list=new_status_list(8),
        issued_at=now - 7200, expires=now + exp_in_s)


def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _di_jcs(valid_until: str) -> dict:
    """An eddsa-jcs-2022 credential from a fresh did:key (no network, no pyld)."""
    private = ed25519.Ed25519PrivateKey.generate()
    raw = base64.urlsafe_b64decode(Ed25519SigningKey(private, kid="t").public_jwk()["x"] + "==")
    did = "did:key:" + encode_multibase(_leb128(0xED) + raw)
    vm = f"{did}#{did[len('did:key:'):]}"
    credential = {"@context": [VC2], "type": ["VerifiableCredential"], "issuer": did,
                  "validFrom": "2020-01-01T00:00:00Z", "validUntil": valid_until,
                  "credentialSubject": {"id": "did:example:alice"}}
    return EddsaJcsProofSuite().add_proof(
        credential, signing_key=Ed25519SigningKey(private, kid=vm), verification_method=vm)


def _iso(delta_s: int) -> str:
    # isoformat, never strftime("%Y"): glibc does not pad a year below 1000
    from datetime import datetime, timedelta, timezone
    moment = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=delta_s)
    return moment.isoformat().replace("+00:00", "Z")


def _corrupt(leeway) -> VerificationPolicy:
    """A policy holding *leeway* although ``VerificationPolicy`` refuses to be built with
    it: the way to reach the per-suite check, as a caller's monkeypatch, a duck-typed
    policy or a ``frozen`` bypass would."""
    policy = VerificationPolicy(require_status=False)
    object.__setattr__(policy, "leeway_s", leeway)
    return policy


# --------------------------------------------------------------------------- #
# The validator
# --------------------------------------------------------------------------- #

class _LaneError(Exception):
    """Stands in for a lane's own error class."""


def test_the_cap_is_one_day_and_the_default_is_inside_it():
    assert MAX_LEEWAY_S == 86_400
    assert 0 <= DEFAULT_LEEWAY_S <= MAX_LEEWAY_S


@pytest.mark.parametrize("bad", BAD)
def test_leeway_seconds_refuses_every_bad_value_with_the_given_error(bad):
    with pytest.raises(_LaneError, match="leeway_s") as info:
        leeway_seconds(bad, error=_LaneError)
    assert type(info.value) is _LaneError


@pytest.mark.parametrize("bad", BAD)
def test_leeway_seconds_defaults_to_proof_error(bad):
    with pytest.raises(ProofError) as info:
        leeway_seconds(bad)
    assert type(info.value) is ProofError


@pytest.mark.parametrize("good", GOOD)
def test_leeway_seconds_returns_the_value_as_a_plain_int(good):
    got = leeway_seconds(good)
    assert got == good and type(got) is int


def test_leeway_seconds_accepts_the_boundaries_and_refuses_one_past_them():
    assert leeway_seconds(0) == 0 and leeway_seconds(MAX_LEEWAY_S) == MAX_LEEWAY_S
    for out in (-1, MAX_LEEWAY_S + 1):
        with pytest.raises(_LaneError):
            leeway_seconds(out, error=_LaneError)


def test_leeway_seconds_reads_an_int_subclass_as_the_integer_it_holds():
    # An overridden comparison or __index__ must not move the verdict either way.
    assert type(leeway_seconds(_LyingInt(60))) is int
    assert leeway_seconds(_LyingInt(60)) == 60
    with pytest.raises(_LaneError):
        leeway_seconds(_LyingInt(MAX_LEEWAY_S + 1), error=_LaneError)


def test_leeway_seconds_names_the_value_in_the_message():
    with pytest.raises(_LaneError, match=r"max_skew must be a whole number of seconds"):
        leeway_seconds(-5, name="max_skew", error=_LaneError)


@pytest.mark.parametrize("bad", [
    pytest.param("x" * 100_000, id="long-str"),
    pytest.param(10 ** 400, id="huge-int"),
    pytest.param([1] * 100_000, id="long-list"),
    pytest.param("\u0000" * 5_000, id="nul-str"),
])
def test_the_message_is_bounded(bad):
    # safe_repr cuts a string and names a container or a bignum by type, so the message
    # does not grow with the input. The ceiling follows safe_repr's _SHOWN_MAX: if that
    # constant changes, move it with it.
    with pytest.raises(_LaneError) as info:
        leeway_seconds(bad, error=_LaneError)
    assert len(str(info.value)) < 1_000


# --------------------------------------------------------------------------- #
# Every suite, constructed: the lane's own error class, exactly
# --------------------------------------------------------------------------- #

SUITES = [
    pytest.param(lambda v: VcJwtProofSuite(leeway_s=v), ProofError, id="vc-jwt"),
    pytest.param(lambda v: VcJwtProofSuite(allow_pq=True, leeway_s=v), ProofError,
                 id="vc-jwt-ml-dsa"),
    pytest.param(lambda v: VpJwtProofSuite(leeway_s=v), ProofError, id="vp-jwt"),
    pytest.param(lambda v: SdJwtVcProofSuite(leeway_s=v), SdJwtError, id="sd-jwt-vc"),
    pytest.param(lambda v: SdJwtVcProofSuite(leeway_s=v, allow_pq=True), SdJwtError,
                 id="sd-jwt-vc-ml-dsa"),
    pytest.param(lambda v: DataIntegrityProofSuite(leeway_s=v), ProofError,
                 id="eddsa-rdfc-2022"),
    pytest.param(lambda v: EcdsaRdfcProofSuite(leeway_s=v), ProofError, id="ecdsa-rdfc-2019"),
    pytest.param(lambda v: EddsaJcsProofSuite(leeway_s=v), ProofError, id="eddsa-jcs-2022"),
    pytest.param(lambda v: EcdsaJcsProofSuite(leeway_s=v), ProofError, id="ecdsa-jcs-2019"),
    pytest.param(lambda v: EcdsaSdProofSuite(leeway_s=v), ProofError, id="ecdsa-sd-2023"),
]


@pytest.mark.parametrize("bad", BAD)
@pytest.mark.parametrize("build, error", SUITES)
def test_a_suite_refuses_a_bad_leeway_when_built(build, error, bad):
    with pytest.raises(error, match="leeway_s") as info:
        build(bad)
    assert type(info.value) is error


@pytest.mark.parametrize("good", [0, 60, MAX_LEEWAY_S])
@pytest.mark.parametrize("build, error", SUITES)
def test_a_suite_accepts_the_range(build, error, good):
    assert build(good)._leeway == good


@pytest.mark.parametrize("build, error", SUITES)
def test_a_suite_keeps_a_plain_int(build, error):
    leeway = build(_LyingInt(60))._leeway
    assert leeway == 60 and type(leeway) is int


def test_a_suite_built_with_no_leeway_uses_a_default_inside_the_range():
    for suite in (VcJwtProofSuite(), VpJwtProofSuite(), SdJwtVcProofSuite(),
                  DataIntegrityProofSuite(), EcdsaRdfcProofSuite(), EddsaJcsProofSuite(),
                  EcdsaJcsProofSuite(), EcdsaSdProofSuite()):
        assert 0 <= suite._leeway <= MAX_LEEWAY_S
    assert VerificationPolicy().leeway_s == DEFAULT_LEEWAY_S


# --------------------------------------------------------------------------- #
# The fail-open rows: an expired item is never accepted under a bad leeway
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_an_expired_vc_jwt_never_verifies_under_a_bad_leeway(bad):
    token = _vc_jwt(-3600)
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite(leeway_s=bad).verify(token, public_key_jwk=KEY.public_jwk())
    assert type(info.value) is ProofError


@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_a_not_yet_valid_vc_jwt_never_verifies_under_a_bad_leeway(bad):
    token = _vc_jwt(nbf_in_s=30 * 86400)
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite(leeway_s=bad).verify(token, public_key_jwk=KEY.public_jwk())
    assert type(info.value) is ProofError


@pytest.mark.skipif(not mldsa_available(), reason="ML-DSA needs a backend")
@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_an_expired_ml_dsa_vc_jwt_never_verifies_under_a_bad_leeway(bad):
    key = MLDSASigningKey.generate(kid="k", alg="ML-DSA-65")
    token = VcJwtProofSuite(allow_pq=True).sign(CRED, signing_key=key, expires_in_s=-3600)
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite(allow_pq=True, leeway_s=bad).verify(
            token, public_key_jwk=key.public_jwk())
    assert type(info.value) is ProofError
    with pytest.raises(ClaimsInvalid, match="expired"):               # the control
        VcJwtProofSuite(allow_pq=True).verify(token, public_key_jwk=key.public_jwk())


@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_an_expired_vp_jwt_never_verifies_under_a_bad_leeway(bad):
    token = _vp_jwt(-3600)
    with pytest.raises(ProofError) as info:
        VpJwtProofSuite(leeway_s=bad).verify(
            token, audience="aud", nonce="n", holder_key_jwk=KEY.public_jwk(),
            resolver=default_resolver())
    assert type(info.value) is ProofError


@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_an_expired_sd_jwt_never_verifies_under_a_bad_leeway(bad):
    token = _sd_jwt(-3600)
    with pytest.raises(SdJwtError) as info:
        SdJwtVcProofSuite(leeway_s=bad).verify(token, public_key_jwk=KEY.public_jwk())
    assert type(info.value) is SdJwtError


@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_an_expired_status_token_never_verifies_under_a_bad_leeway(bad):
    token = _status_token(-3600)
    with pytest.raises(StatusListError, match="leeway_s") as info:
        verify_status_list_token(token, public_key_jwk=KEY.public_jwk(), leeway_s=bad)
    assert type(info.value) is StatusListError


@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_a_lapsed_data_integrity_credential_never_verifies_under_a_bad_leeway(bad):
    credential = _di_jcs(_iso(-3600))
    with pytest.raises(ProofError) as info:
        EddsaJcsProofSuite(leeway_s=bad).verify(credential)
    assert type(info.value) is ProofError


@pytest.mark.parametrize("bad", FAIL_OPEN)
def test_the_jose_and_freshness_helpers_fail_closed_on_a_bad_leeway(bad):
    # The backstop under the entry points: PyJWT never sees these, and the helpers do not
    # read NaN as "never expires" nor a string as a bare TypeError.
    with pytest.raises(ClaimsInvalid, match="leeway_s") as info:
        check_jwt_temporal({"exp": NOW - 3600}, leeway_s=bad, now=NOW)
    assert type(info.value) is ClaimsInvalid
    with pytest.raises(ClaimsInvalid, match="leeway_s") as info:
        check_iat_freshness(NOW - 86400, max_age_s=300, leeway_s=bad, current=NOW,
                            subject="key proof")
    assert type(info.value) is ClaimsInvalid
    with pytest.raises(ProofError, match="leeway_s") as info:
        check_validity_window({"validUntil": _iso(-3600)}, {}, now=None, leeway_s=bad)
    assert type(info.value) is ProofError
    with pytest.raises(ProofError, match="leeway_s") as info:
        utc_window(None, bad)
    assert type(info.value) is ProofError


# --------------------------------------------------------------------------- #
# Function entry points: checked first, before anything else is read
# --------------------------------------------------------------------------- #

def test_the_status_token_check_runs_before_the_token_is_read():
    for bad in (float("nan"), "60", None, -1, True, 60.5, 10 ** 12):
        with pytest.raises(StatusListError, match="leeway_s") as info:
            verify_status_list_token("not-a-token", public_key_jwk={}, leeway_s=bad)
        assert type(info.value) is StatusListError


@pytest.mark.parametrize("bad", BAD)
@pytest.mark.parametrize("factory", [
    default_status_list_resolver, default_status_list_token_resolver,
    default_status_list_resolver_async, default_status_list_token_resolver_async,
], ids=lambda f: f.__name__)
def test_a_status_resolver_factory_refuses_a_bad_leeway_when_built(factory, bad):
    with pytest.raises(StatusListError, match="leeway_s") as info:
        factory(leeway_s=bad)
    assert type(info.value) is StatusListError


@pytest.mark.parametrize("factory", [
    default_status_list_resolver, default_status_list_token_resolver,
    default_status_list_resolver_async, default_status_list_token_resolver_async,
], ids=lambda f: f.__name__)
def test_a_status_resolver_factory_still_builds_with_the_range(factory):
    for good in (0, 60, MAX_LEEWAY_S):
        assert callable(factory(leeway_s=good))
    assert callable(factory())


@pytest.mark.parametrize("bad", BAD)
def test_verify_vp_token_checks_the_leeway_first(bad):
    with pytest.raises(OpenID4VPError, match="leeway_s") as info:
        verify_vp_token("garbage", dcql_query={}, nonce="", leeway_s=bad)
    assert type(info.value) is OpenID4VPError


@pytest.mark.parametrize("bad", BAD)
def test_verify_encrypted_vp_response_checks_the_leeway_before_decrypting(bad):
    key = P256KeyAgreementKey.generate(kid="enc")
    with pytest.raises(OpenID4VPError, match="leeway_s") as info:
        verify_encrypted_vp_response("not.a.jwe", key=key, dcql_query={}, nonce="n",
                                     leeway_s=bad)
    assert type(info.value) is OpenID4VPError


@pytest.mark.parametrize("bad", BAD)
def test_the_openid4vci_key_proof_check_runs_before_the_request_is_read(bad):
    with pytest.raises(CredentialRequestMalformed, match="leeway_s") as info:
        verify_credential_request_proofs("garbage", credential_issuer="", leeway_s=bad)
    assert type(info.value) is CredentialRequestMalformed


@pytest.mark.parametrize("bad", BAD)
def test_mdoc_checks_the_leeway_before_the_response_is_read(bad):
    with pytest.raises(MdocError, match="leeway_s") as info:
        verify_device_response(b"", trust_anchors=[], session_transcript=b"", leeway_s=bad)
    assert type(info.value) is MdocError
    with pytest.raises(MdocError, match="leeway_s") as info:
        verify_issuer_signed(object(), trust_anchors=[], leeway_s=bad)
    assert type(info.value) is MdocError


@pytest.mark.parametrize("bad", BAD)
def test_wrprc_checks_the_leeway_before_anything_else(bad):
    with pytest.raises(RpRegistrationError, match="leeway_s") as info:
        verify_rp_registration_certificate("garbage", trust_anchors=[], leeway_s=bad)
    assert type(info.value) is RpRegistrationError


# --------------------------------------------------------------------------- #
# VerificationPolicy: refused where it is built
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", BAD)
def test_a_policy_cannot_be_built_with_a_bad_leeway(bad):
    with pytest.raises(InvalidPolicy, match="leeway_s") as info:
        VerificationPolicy(leeway_s=bad)
    assert type(info.value) is InvalidPolicy


@pytest.mark.parametrize("bad", BAD)
def test_replace_re_validates_the_leeway(bad):
    with pytest.raises(InvalidPolicy, match="leeway_s"):
        dataclasses.replace(VerificationPolicy(), leeway_s=bad)


@pytest.mark.parametrize("good", GOOD)
def test_a_policy_takes_the_range(good):
    assert VerificationPolicy(leeway_s=good).leeway_s == good


@pytest.mark.parametrize("bad", [
    float("nan"), float("inf"), -1, True, "300", None, 1.5,
    _ClaimsToBeInt(), mock.Mock(spec=int), mock.MagicMock(spec=int),
    _LyingInt(-1),
])
def test_a_policy_cannot_be_built_with_a_bad_kb_max_age(bad):
    with pytest.raises(InvalidPolicy, match="kb_max_age_s") as info:
        VerificationPolicy(kb_max_age_s=bad)
    assert type(info.value) is InvalidPolicy


@pytest.mark.parametrize("bad", [
    pytest.param("x" * 100_000, id="long-str"),
    pytest.param(-(10 ** 400), id="huge-negative-int"),
    pytest.param([1] * 100_000, id="long-list"),
    pytest.param("\u0000" * 5_000, id="nul-str"),
])
def test_the_kb_max_age_message_is_bounded(bad):
    # the policy's kb_max_age_s message goes through safe_repr as the leeway one does
    with pytest.raises(InvalidPolicy, match="kb_max_age_s") as info:
        VerificationPolicy(kb_max_age_s=bad)
    assert len(str(info.value)) < 1_000


def test_a_policy_still_takes_a_wide_kb_max_age_and_a_zero_one():
    # kb_max_age_s has no upper bound: only the leeway is capped (#228)
    for age in (0, 300, 10 ** 8):
        assert VerificationPolicy(kb_max_age_s=age).kb_max_age_s == age


def test_invalid_policy_is_a_proof_error_exported_from_the_package():
    import openvc
    assert issubclass(InvalidPolicy, ProofError) and openvc.InvalidPolicy is InvalidPolicy
    assert "InvalidPolicy" in openvc.__all__


# --------------------------------------------------------------------------- #
# The pipeline: a bad leeway fails each item typed and never aborts the batch
# --------------------------------------------------------------------------- #

LANES = [
    pytest.param(lambda: _vc_jwt(-3600), ProofError, id="vc-jwt"),
    pytest.param(lambda: _sd_jwt(-3600), SdJwtError, id="sd-jwt-vc"),
    pytest.param(lambda: _di_jcs(_iso(-3600)), ProofError, id="data-integrity"),
]
PIPELINE_BAD = [
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="inf"),
    pytest.param("60", id="str"),
    pytest.param(None, id="None"),
    pytest.param(-1, id="minus-1"),
    pytest.param(True, id="True"),
    pytest.param(60.5, id="float"),
    pytest.param(10 ** 12, id="10**12"),
    pytest.param(_ClaimsToBeInt(), id="class-claims-int"),
    pytest.param(mock.Mock(spec=int), id="mock-spec-int"),
]


@pytest.mark.parametrize("bad", PIPELINE_BAD)
@pytest.mark.parametrize("make, error", LANES)
def test_verify_credential_fails_typed_under_a_bad_leeway(make, error, bad):
    credential = make()
    with pytest.raises(error, match="leeway_s") as info:
        verify_credential(credential, policy=_corrupt(bad))
    assert type(info.value) is error
    with pytest.raises(error, match="leeway_s") as info:
        asyncio.run(verify_credential_async(credential, policy=_corrupt(bad)))
    assert type(info.value) is error


@pytest.mark.parametrize("bad", PIPELINE_BAD)
def test_verify_many_never_aborts_and_never_accepts_under_a_bad_leeway(bad):
    batch = [lane.values[0]() for lane in LANES]
    expected = [lane.values[1] for lane in LANES]
    policy = _corrupt(bad)
    for results in (verify_many(batch, policy=policy),
                    asyncio.run(verify_many_async(batch, policy=policy))):
        assert [r.index for r in results] == [0, 1, 2]            # the batch is intact
        assert [r.ok for r in results] == [False, False, False]   # none accepted
        assert [type(r.error) for r in results] == expected       # each typed, lane's own
        assert all("leeway_s" in str(r.error) for r in results)


def test_verify_many_with_a_good_leeway_still_isolates_items():
    good = _vc_jwt(+3600)
    lapsed = _vc_jwt(-3600)
    results = verify_many([good, lapsed, good])
    assert [r.ok for r in results] == [True, False, True]
    assert type(results[1].error) is ClaimsInvalid


# --------------------------------------------------------------------------- #
# Valid values behave: 0 and 60 reject a lapse, a leeway absorbs a recent one
# --------------------------------------------------------------------------- #

def _vc_jwt_check(token, leeway):
    return VcJwtProofSuite(leeway_s=leeway).verify(token, public_key_jwk=KEY.public_jwk())


def _vp_jwt_check(token, leeway):
    return VpJwtProofSuite(leeway_s=leeway).verify(
        token, audience="aud", nonce="n", holder_key_jwk=KEY.public_jwk(),
        resolver=default_resolver())


def _sd_jwt_check(token, leeway):
    return SdJwtVcProofSuite(leeway_s=leeway).verify(token, public_key_jwk=KEY.public_jwk())


def _status_check(token, leeway):
    return verify_status_list_token(token, public_key_jwk=KEY.public_jwk(), leeway_s=leeway)


JOSE_LANES = [
    pytest.param(_vc_jwt, _vc_jwt_check, ClaimsInvalid, id="vc-jwt"),
    pytest.param(_vp_jwt, _vp_jwt_check, ClaimsInvalid, id="vp-jwt"),
    pytest.param(_sd_jwt, _sd_jwt_check, ClaimsInvalid, id="sd-jwt-vc"),
    pytest.param(_status_token, _status_check, StatusListError, id="status-token"),
]


@pytest.mark.parametrize("leeway", [0, 60])
@pytest.mark.parametrize("make, check, error", JOSE_LANES)
def test_zero_and_the_default_reject_an_item_that_lapsed_an_hour_ago(make, check, error, leeway):
    with pytest.raises(error, match="expired") as info:
        check(make(-3600), leeway)
    assert type(info.value) is error


@pytest.mark.parametrize("make, check, error", JOSE_LANES)
def test_a_leeway_of_sixty_absorbs_a_lapse_thirty_seconds_ago(make, check, error):
    check(make(-30), 60)                       # accepted: inside the leeway
    with pytest.raises(error, match="expired"):
        check(make(-30), 0)                    # and the same item is out at 0


@pytest.mark.parametrize("make, check, error", JOSE_LANES)
def test_the_widest_leeway_absorbs_an_hour_but_not_a_day_and_an_hour(make, check, error):
    check(make(-3600), MAX_LEEWAY_S)
    with pytest.raises(error, match="expired"):
        check(make(-(MAX_LEEWAY_S + 3600)), MAX_LEEWAY_S)


def test_data_integrity_applies_the_range_to_validuntil():
    recent, old = _di_jcs(_iso(-30)), _di_jcs(_iso(-3600))
    EddsaJcsProofSuite(leeway_s=60).verify(recent)
    with pytest.raises(CredentialExpired):
        EddsaJcsProofSuite(leeway_s=0).verify(recent)
    with pytest.raises(CredentialExpired):
        EddsaJcsProofSuite(leeway_s=60).verify(old)
    EddsaJcsProofSuite(leeway_s=MAX_LEEWAY_S).verify(old)


def test_the_pipeline_policy_leeway_reaches_the_lane():
    token = _vc_jwt(-30)
    with pytest.raises(ClaimsInvalid, match="expired"):
        verify_credential(token, policy=VerificationPolicy(require_status=False, leeway_s=0))
    result = verify_credential(token, policy=VerificationPolicy(require_status=False))
    assert result.issuer == DID                                  # the default, 60 s, absorbs it
