"""One NumericDate rule for every JOSE lane: ``exp`` / ``nbf`` / ``iat``.

#195 made the VC-JWT lane reject any **present** ``exp``/``nbf``/``iat`` that is not a
finite JSON number (RFC 7519 §2), ``null`` included, whatever the expiry waiver. Its
adversarial review found the other JOSE lanes still disagreed, all reproduced on
v1.28.2:

* the status-list token accepted an ``exp`` of ``NaN``, ``Infinity`` or ``1e400`` (a list
  that never goes stale), although its comment said it failed closed;
* the SD-JWT VC issuer JWT never shape-checked ``iat`` (``null``, ``[]``, ``"abc"``,
  ``true``, ``NaN``, ``1e400`` and a bignum all verified), and it and the VP-JWT read
  ``exp``/``nbf: null`` as absent;
* the VP-JWT never looked at ``iat`` at all;
* the VC-JWT ML-DSA lane accepted a future ``iat`` and a non-string ``sub``/``jti``, all of
  which PyJWT rejects on the classic lane.

``check_jwt_temporal`` now single-sources the rule: shape first (``null`` rejected), then
``exp`` (the only comparison the waiver switches off), ``nbf``, and a future ``iat``. Each
lane is tested under the default policy and ``require_not_expired=False``. Helpers are
self-contained (tests/ is not a package, so no cross-imports).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

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
from openvc.proof._verify_common import check_jwt_temporal
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.status import StatusListError, verify_status_list_token

WAIVED = VerificationPolicy(require_not_expired=False)
POLICIES = [pytest.param(None, id="default"), pytest.param(WAIVED, id="waived")]
TEMPORAL = pytest.mark.parametrize("check_temporal", [True, False], ids=["temporal", "waived"])
NOW = int(time.time())
LEEWAY = 60                              # every suite's default
FUTURE = NOW + 3600                      # far past the leeway
VCT = "https://credentials.example.com/identity_credential"

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
    "numeric-string": '"1999999999"',
    "float-overflow": "1e400",           # json.loads -> inf
    "bignum": "1" + "0" * 400,           # no float holds it: read as not finite
    "true": "true",
    "false": "false",
}
CASES = [
    pytest.param(claim, raw, id=f"{claim}-{name}")
    for claim in ("exp", "nbf", "iat") for name, raw in HOSTILE.items()
]
# The values the lanes newly reject: every hostile iat, and a null exp/nbf. (A
# non-null malformed exp/nbf was already rejected; it stays in CASES as a guard.)
NEW_CASES = [
    pytest.param(claim, raw, id=f"{claim}-{name}")
    for claim in ("exp", "nbf", "iat") for name, raw in HOSTILE.items()
    if claim == "iat" or name == "null"
]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _did_jwk_key() -> tuple[P256SigningKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = P256SigningKey(priv, kid="tmp").public_jwk()
    did = "did:jwk:" + _b64(json.dumps(jwk, separators=(",", ":")).encode())
    return P256SigningKey(priv, kid=f"{did}#0"), did


ISSUER, ISSUER_DID = _did_jwk_key()
HOLDER, HOLDER_DID = _did_jwk_key()


def _jws(header: dict, members: list[str], key: P256SigningKey) -> str:
    """A compact JWS whose payload is the raw JSON *members*, signed by *key*."""
    h = _b64(json.dumps(header).encode())
    p = _b64(("{" + ", ".join(members) + "}").encode())
    return f"{h}.{p}.{_b64(key.sign(f'{h}.{p}'.encode()))}"


# -- the helper ------------------------------------------------------------------- #

@TEMPORAL
@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
def test_helper_rejects_null_whatever_the_waiver(claim, check_temporal):
    with pytest.raises(ClaimsInvalid, match=f"token {claim} must be a finite"):
        check_jwt_temporal({claim: None}, leeway_s=LEEWAY, check_temporal=check_temporal)


@TEMPORAL
def test_helper_bounds_a_future_iat_whatever_the_waiver(check_temporal):
    check_jwt_temporal({"iat": NOW + LEEWAY}, leeway_s=LEEWAY, now=NOW,
                       check_temporal=check_temporal)              # edge: inside leeway
    with pytest.raises(ClaimsInvalid, match="token iat is in the future"):
        check_jwt_temporal({"iat": NOW + LEEWAY + 1}, leeway_s=LEEWAY, now=NOW,
                           check_temporal=check_temporal)


def test_helper_leaves_iat_optional_and_unbounded_in_age():
    check_jwt_temporal({}, leeway_s=LEEWAY)
    check_jwt_temporal({"iat": 0}, leeway_s=LEEWAY)                # 1970: old, not stale


def test_helper_waiver_switches_off_only_the_exp_comparison():
    expired = {"exp": NOW - 3600}
    with pytest.raises(ClaimsInvalid, match="has expired"):
        check_jwt_temporal(expired, leeway_s=LEEWAY, now=NOW)
    check_jwt_temporal(expired, leeway_s=LEEWAY, now=NOW, check_temporal=False)
    with pytest.raises(ClaimsInvalid, match="not yet valid"):
        check_jwt_temporal({"nbf": FUTURE}, leeway_s=LEEWAY, now=NOW, check_temporal=False)


# -- status-list token ------------------------------------------------------------ #

_LST = "eNrbuRgAAhcBXQ"                  # a valid 1-bit list


def _status_token(extra: dict[str, str]) -> str:
    members = ['"sub": "https://status.example/1"',
               f'"status_list": {{"bits": 1, "lst": "{_LST}"}}']
    members += [f"{json.dumps(k)}: {v}" for k, v in extra.items()]
    return _jws({"alg": "ES256", "typ": "statuslist+jwt"}, members, ISSUER)


@pytest.mark.parametrize("claim,raw", CASES)
def test_status_token_rejects_malformed_numeric_date(claim, raw):
    # exp NaN / Infinity / 1e400 used to verify: every comparison against them is
    # False, so the list never went stale.
    with pytest.raises(StatusListError, match=f"{claim} must be a finite"):
        verify_status_list_token(_status_token({claim: raw}),
                                 public_key_jwk=ISSUER.public_jwk())


def test_status_token_well_formed_dates_still_verify():
    token = _status_token({"iat": str(NOW), "exp": f"{NOW + 3600}.5"})
    claims = verify_status_list_token(token, public_key_jwk=ISSUER.public_jwk())
    assert claims["status_list"]["bits"] == 1


def test_status_token_now_pin_before_iat_still_verifies():
    # Only exp is compared. A verifier re-checking an archived credential pins `now`
    # to its receipt time, and the list it fetches today is newer than that pin. A
    # future-iat or nbf comparison would reject every such re-check.
    token = _status_token({"iat": str(NOW), "nbf": str(NOW), "exp": str(NOW + 3600)})
    pin = datetime.fromtimestamp(NOW, timezone.utc) - timedelta(days=30)
    verify_status_list_token(token, public_key_jwk=ISSUER.public_jwk(), now=pin)


def test_status_token_expiry_unchanged():
    token = _status_token({"exp": str(NOW - 3600)})
    with pytest.raises(StatusListError, match="expired"):
        verify_status_list_token(token, public_key_jwk=ISSUER.public_jwk())


# -- SD-JWT VC issuer JWT --------------------------------------------------------- #

def _sd_jwt(extra: dict[str, str] | None = None, *, disclosures: list[str] = ()) -> str:
    """A self-issued SD-JWT VC (did:jwk) with no KB-JWT. *extra* maps claim -> raw
    JSON in the issuer-JWT body; each disclosure is a raw JSON array."""
    encoded = [_b64(d.encode()) for d in disclosures]
    members = [f'"iss": {json.dumps(ISSUER_DID)}', f'"vct": {json.dumps(VCT)}']
    if encoded:
        digests = [_b64(hashlib.sha256(d.encode()).digest()) for d in encoded]
        members += [f'"_sd": {json.dumps(digests)}', '"_sd_alg": "sha-256"']
    members += [f"{json.dumps(k)}: {v}" for k, v in (extra or {}).items()]
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": ISSUER.kid}
    return _jws(header, members, ISSUER) + "~" + "".join(d + "~" for d in encoded)


def _sd_good() -> str:
    return _sd_jwt({"iat": str(NOW), "nbf": str(NOW), "exp": str(NOW + 3600)})


@TEMPORAL
@pytest.mark.parametrize("claim,raw", CASES)
def test_sd_jwt_suite_rejects_malformed_numeric_date(claim, raw, check_temporal):
    with pytest.raises(ClaimsInvalid, match=f"{claim} must be a finite"):
        SdJwtVcProofSuite().verify(_sd_jwt({claim: raw}),
                                   public_key_jwk=ISSUER.public_jwk(),
                                   check_temporal=check_temporal)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", NEW_CASES)
def test_sd_jwt_verify_credential_rejects_malformed_numeric_date(claim, raw, policy):
    with pytest.raises(ClaimsInvalid):
        verify_credential(_sd_jwt({claim: raw}), policy=policy)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", NEW_CASES)
def test_sd_jwt_verify_credential_async_rejects_malformed_numeric_date(claim, raw, policy):
    with pytest.raises(ClaimsInvalid):
        asyncio.run(verify_credential_async(_sd_jwt({claim: raw}), policy=policy))


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", NEW_CASES)
def test_sd_jwt_verify_many_isolates_malformed_numeric_date(claim, raw, policy):
    results = verify_many([_sd_good(), _sd_jwt({claim: raw}), _sd_good()], policy=policy)
    assert [r.ok for r in results] == [True, False, True]
    assert isinstance(results[1].error, ClaimsInvalid)
    results = asyncio.run(verify_many_async(
        [_sd_good(), _sd_jwt({claim: raw}), _sd_good()], policy=policy))
    assert [r.ok for r in results] == [True, False, True]


@TEMPORAL
@pytest.mark.parametrize("raw", ["null", "NaN", "1e400", '"abc"', "true"])
def test_sd_jwt_rejects_a_malformed_disclosed_iat(raw, check_temporal):
    # SD-JWT VC lets iat be selectively disclosed; it first appears after unpacking,
    # and the processed payload goes through the same rule.
    token = _sd_jwt(disclosures=[f'["salt-iat", "iat", {raw}]'])
    with pytest.raises(ClaimsInvalid, match="iat must be a finite"):
        SdJwtVcProofSuite().verify(token, public_key_jwk=ISSUER.public_jwk(),
                                   check_temporal=check_temporal)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("where", ["body", "disclosed"])
def test_sd_jwt_rejects_a_future_iat(where, policy):
    if where == "body":
        token = _sd_jwt({"iat": str(FUTURE)})
    else:
        token = _sd_jwt(disclosures=[f'["salt-iat", "iat", {FUTURE}]'])
    with pytest.raises(ClaimsInvalid, match="iat is in the future"):
        verify_credential(token, policy=policy)


@pytest.mark.parametrize("policy", POLICIES)
def test_sd_jwt_well_formed_dates_still_verify(policy):
    token = _sd_jwt({"iat": f"{NOW - 86400}.5", "nbf": str(NOW - 10)},
                    disclosures=['["salt", "given_name", "Ada"]'])
    result = verify_credential(token, policy=policy)
    assert result.issuer == ISSUER_DID and result.credential["given_name"] == "Ada"


def test_sd_jwt_waiver_still_accepts_a_well_formed_expired_exp():
    expired = _sd_jwt({"exp": str(NOW - 3600)})
    with pytest.raises(ClaimsInvalid, match="expired"):
        verify_credential(expired)
    assert verify_credential(expired, policy=WAIVED).expired is True


# -- VP-JWT ----------------------------------------------------------------------- #

AUD, NONCE = "https://verifier.example", "n-0S6_WzA2Mj"


def _vp(extra: dict[str, str] | None = None) -> str:
    """A self-signed VP-JWT from a did:jwk holder, carrying no credentials."""
    vp = {"@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiablePresentation"], "holder": HOLDER_DID}
    members = [f'"iss": {json.dumps(HOLDER_DID)}', f'"aud": {json.dumps(AUD)}',
               f'"nonce": {json.dumps(NONCE)}', f'"vp": {json.dumps(vp)}']
    members += [f"{json.dumps(k)}: {v}" for k, v in (extra or {}).items()]
    return _jws({"alg": "ES256", "typ": "JWT", "kid": HOLDER.kid}, members, HOLDER)


def _verify_vp(token: str, policy: VerificationPolicy | None):
    kwargs = {} if policy is None else {"policy": policy}
    return VpJwtProofSuite().verify(token, audience=AUD, nonce=NONCE, **kwargs)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("claim,raw", CASES)
def test_vp_jwt_rejects_malformed_numeric_date(claim, raw, policy):
    # The policy reaches only the embedded credentials; the VP's own dates have no
    # waiver, and their shape never had one either.
    with pytest.raises(ClaimsInvalid, match=f"presentation {claim} must be a finite"):
        _verify_vp(_vp({claim: raw}), policy)


@pytest.mark.parametrize("policy", POLICIES)
def test_vp_jwt_rejects_a_future_iat(policy):
    with pytest.raises(ClaimsInvalid, match="presentation iat is in the future"):
        _verify_vp(_vp({"iat": str(FUTURE)}), policy)


@pytest.mark.parametrize("policy", POLICIES)
def test_vp_jwt_well_formed_dates_still_verify(policy):
    token = _vp({"iat": str(NOW), "nbf": str(NOW), "exp": f"{NOW + 300}.5"})
    assert _verify_vp(token, policy).holder == HOLDER_DID


# -- VC-JWT: the ML-DSA lane matches the classic one ------------------------------ #

def _vc_jwt(extra: dict[str, str], *, key, iss: str, alg: str) -> str:
    vc = {"@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiableCredential"], "issuer": iss,
          "credentialSubject": {"id": "did:example:alice"}}
    members = [f'"iss": {json.dumps(iss)}', f'"vc": {json.dumps(vc)}']
    members += [f"{json.dumps(k)}: {v}" for k, v in extra.items()]
    return _jws({"alg": alg, "typ": "JWT", "kid": key.kid}, members, key)


def _lanes():
    lanes = [pytest.param("classic", id="classic")]
    lanes.append(pytest.param("mldsa", id="mldsa", marks=pytest.mark.skipif(
        not mldsa_available(),
        reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5")))
    return lanes


def _lane(name: str):
    """(suite, key, iss, alg) for a VC-JWT lane."""
    if name == "classic":
        return VcJwtProofSuite(), ISSUER, ISSUER_DID, "ES256"
    from openvc.keys import MLDSASigningKey
    key = MLDSASigningKey.generate(kid="did:example:pq#k", alg="ML-DSA-65")
    return VcJwtProofSuite(allow_pq=True), key, "did:example:pq", "ML-DSA-65"


@TEMPORAL
@pytest.mark.parametrize("lane", _lanes())
def test_vc_jwt_lanes_reject_a_future_iat(lane, check_temporal):
    # PyJWT (classic) raises ImmatureSignatureError for iat > now + leeway, waiver or
    # not; the ML-DSA lane accepted it.
    suite, key, iss, alg = _lane(lane)
    token = _vc_jwt({"iat": str(FUTURE)}, key=key, iss=iss, alg=alg)
    with pytest.raises(ClaimsInvalid, match="iat"):
        suite.verify(token, public_key_jwk=key.public_jwk(), check_temporal=check_temporal)


@TEMPORAL
@pytest.mark.parametrize("lane", _lanes())
def test_vc_jwt_lanes_accept_an_iat_inside_the_leeway(lane, check_temporal):
    suite, key, iss, alg = _lane(lane)
    token = _vc_jwt({"iat": str(NOW + LEEWAY // 2)}, key=key, iss=iss, alg=alg)
    suite.verify(token, public_key_jwk=key.public_jwk(), check_temporal=check_temporal)


@TEMPORAL
@pytest.mark.parametrize("lane", _lanes())
@pytest.mark.parametrize("claim", ["sub", "jti"])
@pytest.mark.parametrize("raw", ["null", "5", "true", "[]", '{"id": "x"}'])
def test_vc_jwt_lanes_require_string_sub_and_jti(lane, claim, raw, check_temporal):
    # RFC 7519 §4.1.2/§4.1.7: StringOrURI / case-sensitive string. PyJWT's
    # verify_sub/verify_jti enforce it on the classic lane; ML-DSA now matches.
    suite, key, iss, alg = _lane(lane)
    token = _vc_jwt({claim: raw}, key=key, iss=iss, alg=alg)
    with pytest.raises(ClaimsInvalid):
        suite.verify(token, public_key_jwk=key.public_jwk(), check_temporal=check_temporal)
