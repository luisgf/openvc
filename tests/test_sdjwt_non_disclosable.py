"""
#229 — the claims a verifier needs to judge an SD-JWT VC's validity are never disclosable.

A holder may withhold any disclosure, and a withheld one is indistinguishable from a decoy
(RFC 9901 §9.7). So an issuer that makes ``exp`` or ``status`` disclosable lets the holder
present an expired or revoked credential as one that never expires and has no status.
draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 lists the claims that, "including any of their
sub-claims", MUST NOT be disclosed: ``iss nbf exp cnf vct vct#integrity aka_vcts status``.
openvc adds ``credentialStatus`` (the pipeline enforces it on SD-JWT too) and ``@context``
(it switches the VCDM rules on), and — on a VCDM payload — the VCDM validity window.

* **Issuer side (the fix).** ``SdJwtVcProofSuite.issue`` refuses such a ``disclosable``
  name with ``SdJwtError`` before anything is signed.
* **Verifier side (defence in depth).** A presentation that *presents* such a disclosure,
  at the top level or anywhere under one of those claims, fails with ``SdJwtError`` on every
  entry point — a non-conformant third-party issuer fails visibly.
* **The limit, pinned so nobody mistakes it for coverage:** a *withheld* disclosure is still
  undetectable, except for ``vct`` — REQUIRED, so a ``dc+sd-jwt`` without one now fails.

Helpers are self-contained (tests/ is not a package — no cross-import). The issuer is a
``did:jwk`` so the pipelines resolve its key and reach the suite.
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
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
from openvc.keys import P256SigningKey
from openvc.proof.errors import ClaimsInvalid, MalformedToken
from openvc.proof.sd_jwt import (
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_array_disclosure,
    make_object_disclosure,
)

V2 = "https://www.w3.org/ns/credentials/v2"
VCT = "https://credentials.example/identity"
STATUS_URI = "https://status.example/1"
FUTURE = int(time.time()) + 86400 * 365
PAST = int(time.time()) - 3600


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _did_jwk_key() -> tuple[P256SigningKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    did = "did:jwk:" + _b64(json.dumps(P256SigningKey(priv, kid="x").public_jwk(),
                                       separators=(",", ":")).encode())
    return P256SigningKey(priv, kid=f"{did}#0"), did


KEY, DID = _did_jwk_key()
HOLDER, _ = _did_jwk_key()
JWK = KEY.public_jwk()
SUITE = SdJwtVcProofSuite()


class _CountingKey:
    """A SigningKey that records every signature — to show a refused issue signs nothing."""

    def __init__(self, inner: P256SigningKey) -> None:
        self._inner, self.calls = inner, 0
        self.alg, self.kid = inner.alg, inner.kid

    def sign(self, data: bytes) -> bytes:
        self.calls += 1
        return self._inner.sign(data)

    def public_jwk(self) -> dict:
        return self._inner.public_jwk()


# --------------------------------------------------------------------------- #
# a hand-made SD-JWT: issue() refuses the shapes these tests need
# --------------------------------------------------------------------------- #

def _obj(name, value):
    disclosure = make_object_disclosure(_b64(secrets.token_bytes(16)), name, value)
    return disclosure, disclosure_digest(disclosure)


def _arr(value):
    disclosure = make_array_disclosure(_b64(secrets.token_bytes(16)), value)
    return disclosure, disclosure_digest(disclosure)


def _sign(body, disclosures=(), *, typ="dc+sd-jwt") -> str:
    header = {"alg": KEY.alg, "typ": typ, "kid": KEY.kid}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    jws = f"{signing_input}.{_b64(KEY.sign(signing_input.encode('ascii')))}"
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _mint(claims, *, disclose=(), typ="dc+sd-jwt") -> str:
    """Sign *claims*, moving the top-level *disclose* names into presented disclosures."""
    body, disclosures = dict(claims), []
    for name in disclose:
        disclosure, _ = _obj(name, body.pop(name))
        disclosures.append(disclosure)
    if disclosures:
        body["_sd"] = sorted(disclosure_digest(d) for d in disclosures)
    return _sign(body, disclosures, typ=typ)


def _withheld(sd_jwt: str) -> str:
    """The same issuer JWT with every disclosure withheld."""
    return sd_jwt.split("~", 1)[0] + "~"


def _ietf(**extra):
    claims = {"iss": DID, "vct": VCT, "sub": "did:example:alice", "given_name": "Ada"}
    claims.update(extra)
    return claims


def _vcdm(**extra):
    doc = {"@context": [V2], "iss": DID, "issuer": DID, "id": "urn:uuid:cred-1",
           "type": ["VerifiableCredential"], "validFrom": "2020-01-01T00:00:00Z",
           "credentialSubject": {"id": "did:example:alice"}}
    doc.update(extra)
    return doc


GOOD = _mint(_ietf(), disclose=["given_name"])

# Each refused top-level claim with a value that would otherwise verify, so the only reason
# to fail is the disclosure itself. (`iss` cannot reach this check — see its own test.)
REFUSED_VALUES = {
    "nbf": PAST,
    "exp": FUTURE,
    "cnf": {"jwk": HOLDER.public_jwk()},
    "vct": VCT,
    "vct#integrity": "sha256-WRL5ca_xGgX3c1VLmXfh-9cLlJNXN-TsMk-PmKjZ5t0",
    "aka_vcts": ["urn:example:alias"],
    "status": {"status_list": {"idx": 3, "uri": STATUS_URI}},
    "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
                         "statusListIndex": "3", "statusListCredential": STATUS_URI},
    "@context": [V2],
}


def _disclosing(name):
    claims = {k: v for k, v in _ietf().items() if k != name}
    claims[name] = REFUSED_VALUES[name]
    return _mint(claims, disclose=[name])


# --------------------------------------------------------------------------- #
# the four entry points, and a mixed batch
# --------------------------------------------------------------------------- #

def _suite(token):
    return SUITE.verify(token, public_key_jwk=JWK)


def _sync(token):
    return verify_credential(token, policy=VerificationPolicy())


def _async(token):
    return asyncio.run(verify_credential_async(token, policy=VerificationPolicy()))


def _batch(token):
    results = verify_many([GOOD, token, GOOD], policy=VerificationPolicy())
    assert results[0].ok and results[2].ok, "a refused item must not take its neighbours down"
    if results[1].error is not None:
        raise results[1].error
    return results[1].result


def _batch_async(token):
    results = asyncio.run(verify_many_async([GOOD, token, GOOD], policy=VerificationPolicy()))
    assert results[0].ok and results[2].ok, "a refused item must not take its neighbours down"
    if results[1].error is not None:
        raise results[1].error
    return results[1].result


ENTRY_POINTS = {"suite": _suite, "sync": _sync, "async": _async,
                "verify_many": _batch, "verify_many_async": _batch_async}


@pytest.fixture(params=sorted(ENTRY_POINTS))
def run(request):
    return ENTRY_POINTS[request.param]


# =========================================================================== #
# issue(): refused before anything is signed
# =========================================================================== #

ISSUE_CLAIMS = {**_ietf(), **{k: v for k, v in REFUSED_VALUES.items() if k != "vct"}}


@pytest.mark.parametrize("name", ["iss", *REFUSED_VALUES])
def test_issue_refuses_a_disclosable_validity_claim(name):
    key = _CountingKey(KEY)
    with pytest.raises(SdJwtError, match=f"{name!r} must not be selectively disclosable"):
        SUITE.issue(dict(ISSUE_CLAIMS), signing_key=key, disclosable=[name])
    assert key.calls == 0


@pytest.mark.parametrize("name", ["iss", *REFUSED_VALUES])
def test_issue_refuses_it_mixed_with_allowed_names(name):
    key = _CountingKey(KEY)
    with pytest.raises(SdJwtError, match=repr(name)):
        SUITE.issue(dict(ISSUE_CLAIMS), signing_key=key,
                    disclosable=["given_name", name, "sub"])
    assert key.calls == 0


def test_issue_refuses_the_synthesised_exp_and_cnf():
    # `exp` from expires_in_s and `cnf` from holder_jwk are refused like literal claims.
    for disclosable, extra in ((["exp"], {"expires_in_s": 60}),
                               (["cnf"], {"holder_jwk": HOLDER.public_jwk()})):
        key = _CountingKey(KEY)
        with pytest.raises(SdJwtError, match=repr(disclosable[0])):
            SUITE.issue(_ietf(), signing_key=key, disclosable=disclosable, **extra)
        assert key.calls == 0


@pytest.mark.parametrize("name", ["validFrom", "validUntil", "issuanceDate", "expirationDate"])
def test_issue_refuses_the_vcdm_window_on_a_vcdm_payload(name):
    claims = _ietf(**{"@context": [V2], name: "2030-01-01T00:00:00Z"})
    key = _CountingKey(KEY)
    with pytest.raises(SdJwtError, match="VCDM validity window"):
        SUITE.issue(claims, signing_key=key, disclosable=[name])
    assert key.calls == 0


@pytest.mark.parametrize("context", [(V2,), [V2], V2], ids=["tuple", "list", "string"])
def test_issue_judges_vcdm_on_the_payload_as_signed(context):
    # Adversarial review of #229: a tuple `@context` is not a list to _declares_vcdm, so
    # issue() saw an IETF payload and signed a disclosable validUntil — but it is a JSON
    # array once serialized, so the verifier read VCDM and a withheld expiry verified.
    claims = _ietf(**{"@context": context, "validUntil": "2021-01-01T00:00:00Z"})
    key = _CountingKey(KEY)
    with pytest.raises(SdJwtError, match="VCDM validity window"):
        SUITE.issue(claims, signing_key=key, disclosable=["validUntil"])
    assert key.calls == 0


@pytest.mark.parametrize("vct", [["urn:x"], 1, {"a": 1}, True, ""])
def test_issue_requires_the_string_vct_the_verifier_requires(vct):
    # Adversarial review of #229: issue() took any truthy vct, and verify() now rejects
    # a dc+sd-jwt without a non-empty string one — openvc would mint what it refuses.
    key = _CountingKey(KEY)
    with pytest.raises(SdJwtError, match="vct"):
        SUITE.issue({"iss": DID}, signing_key=key, vct=vct)
    assert key.calls == 0


@pytest.mark.parametrize("name", ["validFrom", "validUntil", "issuanceDate", "expirationDate"])
def test_issue_allows_vcdm_named_claims_on_an_ietf_payload(name):
    # On an IETF SD-JWT VC these names mean nothing and are never read as a validity bound.
    issued = SUITE.issue(_ietf(**{name: "2000-01-01T00:00:00Z"}), signing_key=KEY,
                         disclosable=[name])
    assert _suite(issued).claims[name] == "2000-01-01T00:00:00Z"


def test_issue_still_allows_sub_iat_and_ordinary_claims():
    issued = SUITE.issue(_ietf(iat=1_700_000_000), signing_key=KEY,
                         disclosable=["sub", "iat", "given_name"],
                         expires_in_s=3600, holder_jwk=HOLDER.public_jwk())
    _, body = issued.split("~")[0].split(".")[:2]
    plaintext = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert {"iss", "vct", "exp", "cnf"} <= set(plaintext)
    assert not {"sub", "iat", "given_name"} & set(plaintext)
    verified = _suite(issued)
    assert verified.claims["sub"] == "did:example:alice"
    assert verified.claims["iat"] == 1_700_000_000
    assert verified.claims["given_name"] == "Ada"


# =========================================================================== #
# verify(): a presented disclosure of a refused claim fails typed, everywhere
# =========================================================================== #

@pytest.mark.parametrize("name", list(REFUSED_VALUES))
def test_a_presented_refused_disclosure_is_rejected(run, name):
    with pytest.raises(SdJwtError, match=f"claim {name!r} is selectively disclosed"):
        run(_disclosing(name))


def test_a_disclosed_expired_exp_is_refused_not_read_as_expired(run):
    # The refusal runs before the processed-payload temporal check: the error names the
    # non-conformance, not a (correct but misleading) "expired".
    claims = _ietf(exp=PAST)
    with pytest.raises(SdJwtError, match="'exp' is selectively disclosed"):
        run(_mint(claims, disclose=["exp"]))


@pytest.mark.parametrize("claims, disclose, typ", [
    (_ietf(exp=PAST), ["exp"], "dc+sd-jwt"),
    (_vcdm(validUntil="2021-01-01T00:00:00Z"), ["validUntil"], "vc+sd-jwt"),
], ids=["exp", "validUntil"])
def test_the_expiry_waiver_does_not_admit_a_disclosed_expiry(claims, disclose, typ):
    # Before #229 a disclosed expired exp / validUntil verified under the waiver with
    # expired=True. The shape itself is refused now, waiver or not.
    token = _mint(claims, disclose=disclose, typ=typ)
    with pytest.raises(SdJwtError, match="is selectively disclosed"):
        SUITE.verify(token, public_key_jwk=JWK, check_temporal=False)
    with pytest.raises(SdJwtError, match="is selectively disclosed"):
        verify_credential(token, policy=VerificationPolicy(require_not_expired=False))


def test_a_disclosed_iss_fails_typed(run):
    # Without a plaintext `iss` the issuer key cannot even be chosen: typed, before the
    # profile check. (The pipelines peek it; the bare suite reads it after the signature.)
    token = _mint(_ietf(), disclose=["iss"])
    expected = ClaimsInvalid if run is _suite else MalformedToken
    with pytest.raises(expected, match="iss"):
        run(token)


@pytest.mark.parametrize("name", ["validFrom", "validUntil", "issuanceDate", "expirationDate"])
def test_a_presented_vcdm_window_disclosure_is_rejected(run, name):
    doc = _vcdm(**{name: "2030-01-01T00:00:00Z"})
    with pytest.raises(SdJwtError, match="VCDM validity window"):
        run(_mint(doc, disclose=[name], typ="vc+sd-jwt"))


@pytest.mark.parametrize("name", ["validFrom", "validUntil"])
def test_vcdm_named_disclosures_on_an_ietf_payload_still_verify(run, name):
    result = run(_mint(_ietf(**{name: "2000-01-01T00:00:00Z"}), disclose=[name]))
    assert result.claims[name] == "2000-01-01T00:00:00Z"


# -- sub-claims: "including any of their sub-claims" (draft-19 §2.2.2.3) ---- #

def _sub_claim_under_cnf():
    disclosure, digest = _obj("jwk", HOLDER.public_jwk())
    return _sign({**_ietf(), "cnf": {"_sd": [digest]}}, [disclosure])


def _sub_claim_under_status():
    disclosure, digest = _obj("status_list", {"idx": 3, "uri": STATUS_URI})
    return _sign({**_ietf(), "status": {"_sd": [digest]}}, [disclosure])


def _deep_sub_claim_under_status():
    disclosure, digest = _obj("idx", 3)
    return _sign({**_ietf(), "status": {"status_list": {"uri": STATUS_URI, "_sd": [digest]}}},
                 [disclosure])


def _element_of_aka_vcts():
    disclosure, digest = _arr("urn:example:alias")
    return _sign({**_ietf(), "aka_vcts": ["urn:example:other", {"...": digest}]},
                 [disclosure])


def _element_of_credential_status():
    disclosure, digest = _arr(REFUSED_VALUES["credentialStatus"])
    return _sign({**_ietf(), "credentialStatus": [{"...": digest}]}, [disclosure])


SUB_CLAIMS = {
    "cnf.jwk": (_sub_claim_under_cnf, "cnf"),
    "status.status_list": (_sub_claim_under_status, "status"),
    "status.status_list.idx": (_deep_sub_claim_under_status, "status"),
    "aka_vcts[1]": (_element_of_aka_vcts, "aka_vcts"),
    "credentialStatus[0]": (_element_of_credential_status, "credentialStatus"),
}


@pytest.mark.parametrize("case", list(SUB_CLAIMS))
def test_a_presented_sub_claim_disclosure_is_rejected(run, case):
    build, top = SUB_CLAIMS[case]
    with pytest.raises(SdJwtError, match=f"a sub-claim of {top!r} is selectively disclosed"):
        run(build())


def test_a_nested_claim_merely_named_exp_is_not_the_registered_claim(run):
    # Only the top-level registered claims are refused: `address.exp` is ordinary data.
    disclosure, digest = _obj("exp", PAST)
    result = run(_sign({**_ietf(), "address": {"locality": "Paris", "_sd": [digest]}},
                       [disclosure]))
    assert result.claims["address"] == {"locality": "Paris", "exp": PAST}


# =========================================================================== #
# the limit: a WITHHELD disclosure stays undetectable (except vct)
# =========================================================================== #

def test_limitation_a_withheld_expired_exp_still_verifies(run):
    # NOT coverage: decoys make a withheld digest indistinguishable from noise (RFC 9901
    # §9.7). Only the issuer-side refusal closes this; a third-party issuer that ignores
    # the profile still produces credentials that verify as never-expiring.
    result = run(_withheld(_mint(_ietf(exp=PAST), disclose=["exp"])))
    assert "exp" not in result.claims


def test_limitation_a_withheld_status_still_verifies(run):
    # NOT coverage, as above: the revocation pointer is simply absent.
    status = REFUSED_VALUES["status"]
    result = run(_withheld(_mint(_ietf(status=status), disclose=["status"])))
    assert "status" not in result.claims


def test_a_withheld_vct_is_detected_because_vct_is_required(run):
    # The one detectable case: an IETF SD-JWT VC (dc+sd-jwt) with no vct is non-conformant
    # whether the issuer omitted it or the holder withheld it.
    with pytest.raises(ClaimsInvalid, match="vct"):
        run(_withheld(_mint(_ietf(), disclose=["vct"])))


def test_a_dc_sd_jwt_with_no_vct_at_all_is_rejected(run):
    claims = {k: v for k, v in _ietf().items() if k != "vct"}
    with pytest.raises(ClaimsInvalid, match="vct"):
        run(_mint(claims))


def _raw(result):
    # the VerifiedSdJwt itself: the suite returns it, the pipelines carry it as `.raw`
    return getattr(result, "raw", result)


def test_a_vc_sd_jwt_vcdm_payload_needs_no_vct(run):
    # A W3C VCDM credential secured as `vc+sd-jwt` is typed by `type`, not by `vct`.
    result = run(_mint(_vcdm(), typ="vc+sd-jwt"))
    assert result.claims["type"] == ["VerifiableCredential"]
    assert _raw(result).vcdm is True
    assert _raw(result).vct is None


def test_a_dc_sd_jwt_needs_a_vct_even_with_a_vcdm_context(run):
    # #272: `dc+sd-jwt` means the payload follows the SD-JWT VC rules (draft-19 §2.2.1),
    # and §2.2.2.3 makes `vct` REQUIRED there. A VCDM @context does not waive it.
    with pytest.raises(ClaimsInvalid, match="needs a non-empty string vct"):
        run(_mint(_vcdm(), typ="dc+sd-jwt"))


def test_a_dc_sd_jwt_vcdm_payload_with_a_vct_verifies_as_vcdm(run):
    # The vct satisfies the IETF rule; the VCDM @context still switches the VCDM rules on.
    result = run(_mint(_vcdm(vct=VCT), typ="dc+sd-jwt"))
    assert _raw(result).vcdm is True
    assert _raw(result).vct == VCT
    assert _raw(result).typ == "dc+sd-jwt"
