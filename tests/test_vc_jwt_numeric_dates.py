"""VC-JWT ``exp`` / ``nbf`` / ``iat`` must be NumericDates, whatever the expiry policy.

Through v1.29.2 the VC-JWT lane handed these claims to PyJWT, which casts them with
``int()`` and catches only ``ValueError``. A signed ``"nbf": null``, ``"iat": []`` or
``"exp": {}`` therefore escaped as a bare ``TypeError``. That is outside the typed
``OpenvcError`` family, so ``verify_many`` / ``verify_many_async``, which catch only
``OpenvcError`` per item, aborted the whole batch. Anyone can mint such a token: a
self-issued ``did:jwk`` is enough. Under ``require_not_expired=False`` PyJWT skipped
``exp`` altogether, so ``NaN``, ``Infinity``, ``"abc"`` or ``1e400`` verified. A
numeric string or a bool was silently ``int()``-cast and accepted.

openvc now checks the three claims' shapes before PyJWT reads them, so each value
below fails as a typed ``ClaimsInvalid`` through every entry point. In a batch, the
good items around it still verify. Helpers are self-contained (tests/ is not a
package, so no cross-imports). ``asyncio.run`` drives the coroutines.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.keys import P256SigningKey, mldsa_available
from openvc.proof import vc_jwt
from openvc.proof._verify_common import check_numeric_dates
from openvc.proof.errors import ClaimsInvalid, MalformedToken, ProofError, UnsupportedAlgorithm
from openvc.proof.vc_jwt import VcJwtProofSuite

WAIVED = VerificationPolicy(require_not_expired=False)
POLICIES = [pytest.param(None, id="default"), pytest.param(WAIVED, id="waived")]
NOW = int(time.time())

# Raw JSON text, spliced into the payload unparsed, so NaN / Infinity / 1e400 / a bignum
# reach the verifier exactly as an attacker writes them (json.dumps cannot emit 1e400).
HOSTILE = {
    "null": "null",
    "list": "[]",
    "object": "{}",
    "nan": "NaN",
    "inf": "Infinity",
    "neg-inf": "-Infinity",
    "string": '"abc"',
    "numeric-string": '"1700000000"',   # PyJWT int()-cast and accepted this
    "float-overflow": "1e400",          # json.loads -> inf
    "bignum": "1" + "0" * 400,          # no float holds it: read as not finite
    "true": "true",                     # int(True) == 1
    "false": "false",
}
CASES = [
    pytest.param(claim, raw, id=f"{claim}-{name}")
    for claim in ("exp", "nbf", "iat") for name, raw in HOSTILE.items()
]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _did_jwk_issuer() -> tuple[P256SigningKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = P256SigningKey(priv, kid="tmp").public_jwk()
    did = "did:jwk:" + _b64(json.dumps(jwk, separators=(",", ":")).encode())
    return P256SigningKey(priv, kid=f"{did}#0"), did


KEY, DID = _did_jwk_issuer()


def _mint(extra: dict[str, str] | None = None, *, key=KEY, iss=DID, alg="ES256") -> str:
    """A signed VC-JWT from a self-issued did:jwk. *extra* maps claim name -> raw JSON."""
    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": iss,
        "credentialSubject": {"id": "did:example:alice"},
    }
    members = [f'"iss": {json.dumps(iss)}', f'"vc": {json.dumps(vc)}']
    members += [f"{json.dumps(name)}: {raw}" for name, raw in (extra or {}).items()]
    header = _b64(json.dumps({"alg": alg, "typ": "JWT", "kid": key.kid}).encode())
    payload = _b64(("{" + ", ".join(members) + "}").encode())
    signature = key.sign(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{_b64(signature)}"


def _good() -> str:
    return _mint({"iat": str(NOW), "nbf": str(NOW), "exp": str(NOW + 3600)})


# -- every entry point: typed ClaimsInvalid, never a bare exception -------------- #

@pytest.mark.parametrize("check_temporal", [True, False], ids=["temporal", "waived"])
@pytest.mark.parametrize("claim,raw", CASES)
def test_suite_rejects_malformed_numeric_date(claim, raw, check_temporal):
    with pytest.raises(ClaimsInvalid, match=f"{claim} must be a finite numeric timestamp"):
        VcJwtProofSuite().verify(
            _mint({claim: raw}), public_key_jwk=KEY.public_jwk(),
            check_temporal=check_temporal)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", CASES)
def test_verify_credential_rejects_malformed_numeric_date(claim, raw, policy):
    with pytest.raises(ClaimsInvalid):
        verify_credential(_mint({claim: raw}), policy=policy)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", CASES)
def test_verify_credential_async_rejects_malformed_numeric_date(claim, raw, policy):
    with pytest.raises(ClaimsInvalid):
        asyncio.run(verify_credential_async(_mint({claim: raw}), policy=policy))


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", CASES)
def test_verify_many_isolates_malformed_numeric_date(claim, raw, policy):
    results = verify_many([_good(), _mint({claim: raw}), _good()], policy=policy)
    assert [r.ok for r in results] == [True, False, True]
    assert isinstance(results[1].error, ClaimsInvalid)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", CASES)
def test_verify_many_async_isolates_malformed_numeric_date(claim, raw, policy):
    results = asyncio.run(
        verify_many_async([_good(), _mint({claim: raw}), _good()], policy=policy))
    assert [r.ok for r in results] == [True, False, True]
    assert isinstance(results[1].error, ClaimsInvalid)


# -- well-formed dates keep their meaning ---------------------------------------- #

@pytest.mark.parametrize("policy", POLICIES)
def test_well_formed_numeric_dates_still_verify(policy):
    # ints and finite floats are both NumericDates (RFC 7519 §2 allows fractions)
    token = _mint({"iat": f"{NOW}.25", "nbf": str(NOW - 10), "exp": f"{NOW + 3600}.5"})
    assert verify_credential(token, policy=policy).issuer == DID


def test_waiver_still_accepts_a_well_formed_expired_exp():
    expired = _mint({"exp": str(NOW - 3600)})
    with pytest.raises(ProofError):
        verify_credential(expired)
    assert verify_credential(expired, policy=WAIVED).issuer == DID


def test_absent_numeric_dates_are_not_required():
    assert verify_credential(_mint()).issuer == DID


# -- ordering, the PQ lane, and the PyJWT backstop -------------------------------- #

def test_header_gates_precede_the_shape_gate():
    # A token wrong twice keeps raising the header error: the alg allow-list and the
    # crit gate both run before the payload is read.
    payload = _b64(b'{"iss": "did:example:i", "vc": {}, "exp": null}')
    rs256 = f'{_b64(json.dumps({"alg": "RS256"}).encode())}.{payload}.AAAA'
    with pytest.raises(UnsupportedAlgorithm):
        VcJwtProofSuite().verify(rs256, public_key_jwk=KEY.public_jwk())
    crit = f'{_b64(json.dumps({"alg": "ES256", "crit": ["b64"]}).encode())}.{payload}.AAAA'
    with pytest.raises(MalformedToken, match="crit"):
        VcJwtProofSuite().verify(crit, public_key_jwk=KEY.public_jwk())


@pytest.mark.skipif(
    not mldsa_available(), reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")
@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
@pytest.mark.parametrize("raw", ["null", "[]", '"1"', "true"])
def test_mldsa_lane_rejects_malformed_numeric_date(claim, raw):
    # The shape gate runs before the ALLOWED_ALGS_PQ branch, so the experimental lane
    # rejects the same shapes. Before, it read null as absent and never looked at iat.
    from openvc.keys import MLDSASigningKey
    key = MLDSASigningKey.generate(kid="did:example:pq#k", alg="ML-DSA-65")
    token = _mint({claim: raw}, key=key, iss="did:example:pq", alg="ML-DSA-65")
    for check_temporal in (True, False):
        with pytest.raises(ClaimsInvalid, match=f"{claim} must be a finite"):
            VcJwtProofSuite(allow_pq=True).verify(
                token, public_key_jwk=key.public_jwk(), check_temporal=check_temporal)


@pytest.mark.parametrize(
    "exc", [TypeError("int() argument"), ValueError("bad"), RecursionError("depth")])
def test_pyjwt_errors_stay_typed(monkeypatch, exc):
    # Whatever PyJWT raises from attacker bytes past the shape gate (a cast, its own
    # json.loads running out of depth) surfaces as ClaimsInvalid, never bare.
    def _raise(*_args, **_kwargs):
        raise exc
    monkeypatch.setattr(vc_jwt._JWT, "decode", _raise)
    with pytest.raises(ClaimsInvalid):
        VcJwtProofSuite().verify(_good(), public_key_jwk=KEY.public_jwk())


@pytest.mark.parametrize("batch", ["sync", "async"])
def test_nesting_depth_ladder_never_aborts_a_batch(batch):
    # Found by the adversarial review of this fix. On Python <= 3.11 the json depth
    # limit shrinks with stack depth, and PyJWT parses the payload a few frames deeper
    # than openvc does. Some nesting depth therefore passes openvc's parse and raised a
    # bare RecursionError inside PyJWT, after the signature verified. That depth moves
    # with the caller's stack but the band is narrow, so one batch carrying a ladder of
    # depths always hits it. On 3.12+ there is no band; the ladder must pass there too.
    deep = [_mint({"x": "[" * n + "]" * n}) for n in range(600, 1000)]
    credentials = [_good(), *deep, _good()]
    if batch == "sync":
        results = verify_many(credentials)
    else:
        results = asyncio.run(verify_many_async(credentials))
    assert results[0].ok and results[-1].ok
    assert all(r.ok or isinstance(r.error, ProofError) for r in results)


@pytest.mark.parametrize("where", ["header", "signature"])
def test_non_ascii_token_is_malformed(where):
    # PyJWT UTF-8-encodes the token before decoding it, so a lone surrogate in the
    # signature segment (the one openvc never parses itself) raised a bare
    # UnicodeEncodeError. A compact JWS is ASCII; anything else is MalformedToken.
    header, payload, signature = _good().split(".")
    if where == "header":
        header = "é" + header
    else:
        signature = signature + "\ud800"
    token = f"{header}.{payload}.{signature}"
    with pytest.raises(MalformedToken, match="non-ASCII"):
        VcJwtProofSuite().verify(token, public_key_jwk=KEY.public_jwk())
    results = verify_many([_good(), token, _good()])
    assert [r.ok for r in results] == [True, False, True]
    assert isinstance(results[1].error, MalformedToken)


# -- the helper itself ------------------------------------------------------------ #

def test_check_numeric_dates_reads_presence_not_truthiness():
    check_numeric_dates({}, "exp", "nbf", "iat")                    # absent: fine
    check_numeric_dates({"exp": 0, "nbf": 1.5, "iat": -1}, "exp", "nbf", "iat")
    check_numeric_dates({"exp": None}, "nbf")                       # only *names* checked
    with pytest.raises(ClaimsInvalid, match="token exp must be"):
        check_numeric_dates({"exp": None}, "exp")                   # null is present
    with pytest.raises(ClaimsInvalid, match="presentation iat must be"):
        check_numeric_dates({"iat": "1"}, "iat", subject="presentation")
