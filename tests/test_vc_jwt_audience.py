"""VC-JWT ``aud`` — RFC 7519 §4.1.3, on both lanes (ADR-0008).

"If the principal processing the claim does not identify itself with a value in the
``aud`` claim when this claim is present, then the JWT MUST be rejected." Through
v1.28.2 openvc passed PyJWT ``verify_aud=False`` whenever the caller gave no audience,
and the ML-DSA lane only looked at ``aud`` when one was given. A VC-JWT addressed to
``https://other-rp`` therefore verified for anyone who held it.

Now ``check_jwt_audience`` runs on both lanes after the signature: a present ``aud``
must be a string or an array of strings, and the caller's audience must be in it, so no
audience means no audience-restricted token. A token without ``aud`` keeps verifying
when no audience is given, and keeps failing when one is. The expiry waiver has nothing
to do with it. Helpers are self-contained (tests/ is not a package).
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
from openvc.proof._verify_common import check_jwt_audience
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite

RP = "https://rp.example"
OTHER = "https://other-rp.example"
WAIVED = VerificationPolicy(require_not_expired=False)
POLICIES = [pytest.param(None, id="default"), pytest.param(WAIVED, id="waived")]
TEMPORAL = pytest.mark.parametrize("check_temporal", [True, False], ids=["temporal", "waived"])
NOW = int(time.time())
MALFORMED = {"null": "null", "number": "5", "object": "{}", "true": "true",
             "mixed-array": f'["{RP}", 5]', "nested-array": f'[["{RP}"]]'}


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _did_jwk_issuer() -> tuple[P256SigningKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = P256SigningKey(priv, kid="tmp").public_jwk()
    did = "did:jwk:" + _b64(json.dumps(jwk, separators=(",", ":")).encode())
    return P256SigningKey(priv, kid=f"{did}#0"), did


KEY, DID = _did_jwk_issuer()


def _mint(aud: str | None = None, *, key=KEY, iss=DID, alg="ES256") -> str:
    """A signed VC-JWT; *aud* is raw JSON for the claim, or None to leave it out."""
    vc = {"@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiableCredential"], "issuer": iss,
          "credentialSubject": {"id": "did:example:alice"}}
    members = [f'"iss": {json.dumps(iss)}', f'"vc": {json.dumps(vc)}', f'"iat": {NOW}']
    if aud is not None:
        members.append(f'"aud": {aud}')
    header = _b64(json.dumps({"alg": alg, "typ": "JWT", "kid": key.kid}).encode())
    payload = _b64(("{" + ", ".join(members) + "}").encode())
    return f"{header}.{payload}.{_b64(key.sign(f'{header}.{payload}'.encode()))}"


def _lanes():
    return [pytest.param("classic", id="classic"),
            pytest.param("mldsa", id="mldsa", marks=pytest.mark.skipif(
                not mldsa_available(),
                reason="ML-DSA needs cryptography>=48 built against OpenSSL>=3.5"))]


def _lane(name: str):
    if name == "classic":
        return VcJwtProofSuite(), KEY, DID, "ES256"
    from openvc.keys import MLDSASigningKey
    key = MLDSASigningKey.generate(kid="did:example:pq#k", alg="ML-DSA-65")
    return VcJwtProofSuite(allow_pq=True), key, "did:example:pq", "ML-DSA-65"


def _verify(lane: str, aud: str | None, audience: str | None, check_temporal: bool = True):
    suite, key, iss, alg = _lane(lane)
    return suite.verify(_mint(aud, key=key, iss=iss, alg=alg),
                        public_key_jwk=key.public_jwk(), audience=audience,
                        check_temporal=check_temporal)


# -- the finding: an audience-restricted token, no audience given ----------------- #

@TEMPORAL
@pytest.mark.parametrize("lane", _lanes())
@pytest.mark.parametrize("aud", [f'"{OTHER}"', f'["{OTHER}"]', f'["{OTHER}", "{RP}"]',
                                 '""', "[]"])
def test_aud_without_an_audience_is_rejected(lane, aud, check_temporal):
    with pytest.raises(ClaimsInvalid, match="RFC 7519 §4.1.3"):
        _verify(lane, aud, None, check_temporal)


@pytest.mark.parametrize("policy", POLICIES)
def test_pipeline_rejects_aud_without_an_audience(policy):
    token = _mint(f'"{OTHER}"')
    with pytest.raises(ClaimsInvalid, match="§4.1.3"):
        verify_credential(token, policy=policy)
    with pytest.raises(ClaimsInvalid, match="§4.1.3"):
        asyncio.run(verify_credential_async(token, policy=policy))


@pytest.mark.parametrize("policy", POLICIES)
def test_batch_isolates_an_audience_restricted_token(policy):
    batch = [_mint(), _mint(f'"{OTHER}"'), _mint()]
    for results in (verify_many(batch, policy=policy),
                    asyncio.run(verify_many_async(batch, policy=policy))):
        assert [r.ok for r in results] == [True, False, True]
        assert isinstance(results[1].error, ClaimsInvalid)


# -- with an audience -------------------------------------------------------------- #

@pytest.mark.parametrize("lane", _lanes())
@pytest.mark.parametrize("aud", [f'"{RP}"', f'["{OTHER}", "{RP}"]'])
def test_aud_naming_the_audience_verifies(lane, aud):
    assert _verify(lane, aud, RP).claims["iss"]


def test_pipeline_audience_from_the_policy():
    policy = VerificationPolicy(audience=RP)
    assert verify_credential(_mint(f'["{RP}"]'), policy=policy).issuer == DID
    with pytest.raises(ClaimsInvalid):
        verify_credential(_mint(f'"{OTHER}"'), policy=policy)


@pytest.mark.parametrize("lane", _lanes())
@pytest.mark.parametrize("aud", [f'"{OTHER}"', f'["{OTHER}"]', "[]", '""'])
def test_aud_not_naming_the_audience_is_rejected(lane, aud):
    with pytest.raises(ClaimsInvalid):
        _verify(lane, aud, RP)


@pytest.mark.parametrize("lane", _lanes())
@pytest.mark.parametrize("audience", [None, RP])
@pytest.mark.parametrize("name,aud", list(MALFORMED.items()), ids=list(MALFORMED))
def test_malformed_aud_is_rejected(lane, audience, name, aud):
    with pytest.raises(ClaimsInvalid):
        _verify(lane, aud, audience)


@pytest.mark.parametrize("lane", _lanes())
@pytest.mark.parametrize("audience", [[RP], (RP,), {RP}, "", 5],
                         ids=["list", "tuple", "set", "empty", "int"])
def test_audience_must_be_a_non_empty_string(lane, audience):
    # Found by the adversarial review. PyJWT matched an iterable audience on the
    # classic lane only, and an empty audience matched an empty aud on the ML-DSA lane
    # only. Both lanes now refuse anything but None or a non-empty string, clearly.
    with pytest.raises(ClaimsInvalid, match="non-empty string"):
        _verify(lane, f'"{RP}"', audience)


# -- unchanged: a token without aud ------------------------------------------------ #

@pytest.mark.parametrize("lane", _lanes())
def test_no_aud_and_no_audience_still_verifies(lane):
    assert _verify(lane, None, None).claims["iss"]


@pytest.mark.parametrize("lane", _lanes())
def test_no_aud_with_an_audience_is_still_rejected(lane):
    with pytest.raises(ClaimsInvalid):
        _verify(lane, None, RP)


# -- the helper -------------------------------------------------------------------- #

def test_helper_contract():
    check_jwt_audience({}, None)
    check_jwt_audience({"aud": RP}, RP)
    check_jwt_audience({"aud": [OTHER, RP]}, RP)
    with pytest.raises(ClaimsInvalid, match="no aud claim"):
        check_jwt_audience({}, RP)
    with pytest.raises(ClaimsInvalid, match="§4.1.3"):
        check_jwt_audience({"aud": OTHER}, None)
    with pytest.raises(ClaimsInvalid, match="does not include"):
        check_jwt_audience({"aud": [OTHER]}, RP)
    with pytest.raises(ClaimsInvalid, match="string or an array of strings"):
        check_jwt_audience({"aud": None}, None)
