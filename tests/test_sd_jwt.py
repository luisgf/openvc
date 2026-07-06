"""
tests/test_sd_jwt.py — SD-JWT VC proof suite: issuance, holder key binding,
verification, and the selective-disclosure security properties. All offline.
"""
from __future__ import annotations

import base64
import json
import time

import pytest

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof.sd_jwt import (
    SdJwtError,
    SdJwtVcProofSuite,
    disclosure_digest,
    make_array_disclosure,
    make_object_disclosure,
)
from openvc.proof.vc_jwt import (
    ClaimsInvalid,
    SignatureInvalid,
    UnsupportedAlgorithm,
)

ISSUER = "did:web:issuer.example"
VCT = "https://credentials.example/identity"
suite = SdJwtVcProofSuite()


def _issuer_key():
    return Ed25519SigningKey.generate(kid=f"{ISSUER}#key-1")


def _base_claims():
    return {"iss": ISSUER, "vct": VCT, "sub": "did:key:zHolder",
            "given_name": "Ada", "family_name": "Lovelace", "age": 36}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _issuer_payload(sd_jwt: str) -> dict:
    payload_b64 = sd_jwt.split("~", 1)[0].split(".")[1]
    return json.loads(_b64url_decode(payload_b64))


# --------------------------------------------------------------------------- #
# issuance + verification roundtrip
# --------------------------------------------------------------------------- #

def test_roundtrip_all_claims_recovered():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key,
                         disclosable=["given_name", "family_name", "age"])
    result = suite.verify(sd_jwt, public_key_jwk=key.public_jwk())
    assert result.issuer == ISSUER and result.vct == VCT
    assert result.claims["given_name"] == "Ada"
    assert result.claims["family_name"] == "Lovelace"
    assert result.claims["age"] == 36
    assert result.claims["sub"] == "did:key:zHolder"        # non-disclosable claim
    assert "_sd" not in result.claims and "_sd_alg" not in result.claims
    assert result.key_bound is False


def test_disclosable_claims_absent_from_issuer_jwt():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["given_name", "age"])
    payload = _issuer_payload(sd_jwt)
    assert "given_name" not in payload and "age" not in payload   # only digests remain
    assert payload["family_name"] == "Lovelace"    # not disclosable -> stays cleartext
    assert payload["sub"] == "did:key:zHolder"
    assert len(payload["_sd"]) == 2 and payload["_sd_alg"] == "sha-256"


def test_holder_may_drop_disclosures():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key,
                         disclosable=["given_name", "family_name", "age"])
    issuer_jwt, *rest = sd_jwt.split("~")
    disclosures = [d for d in rest if d]
    # Keep only the disclosure for "age" (drop the two name disclosures).
    kept = [d for d in disclosures
            if json.loads(_b64url_decode(d))[1] == "age"]
    minimal = issuer_jwt + "~" + "".join(d + "~" for d in kept)
    result = suite.verify(minimal, public_key_jwk=key.public_jwk())
    assert result.claims["age"] == 36
    assert "given_name" not in result.claims and "family_name" not in result.claims


def test_decoys_are_ignored():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key,
                         disclosable=["given_name"], decoys=3)
    payload = _issuer_payload(sd_jwt)
    assert len(payload["_sd"]) == 4                     # 1 real + 3 decoys
    result = suite.verify(sd_jwt, public_key_jwk=key.public_jwk())
    assert result.claims["given_name"] == "Ada"


# --------------------------------------------------------------------------- #
# selective-disclosure security properties
# --------------------------------------------------------------------------- #

def test_unreferenced_disclosure_is_rejected():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["given_name"])
    # A holder tries to smuggle in a claim the issuer never signed a digest for.
    forged = make_object_disclosure(_b64url_encode(b"0" * 16), "is_admin", True)
    tampered = sd_jwt + forged + "~"
    with pytest.raises(SdJwtError):
        suite.verify(tampered, public_key_jwk=key.public_jwk())


def test_forged_disclosure_value_is_rejected():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["age"])
    issuer_jwt, *rest = sd_jwt.split("~")
    salt = json.loads(_b64url_decode([d for d in rest if d][0]))[0]
    forged = make_object_disclosure(salt, "age", 21)           # changed 36 -> 21
    tampered = issuer_jwt + "~" + forged + "~"
    with pytest.raises(SdJwtError):
        suite.verify(tampered, public_key_jwk=key.public_jwk())


def test_duplicate_disclosure_is_rejected():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["given_name"])
    issuer_jwt, *rest = sd_jwt.split("~")
    disclosure = [d for d in rest if d][0]
    doubled = issuer_jwt + "~" + disclosure + "~" + disclosure + "~"
    with pytest.raises(SdJwtError):
        suite.verify(doubled, public_key_jwk=key.public_jwk())


def test_disclosure_cannot_overwrite_a_cleartext_claim():
    key = _issuer_key()
    disclosure = make_object_disclosure(_b64url_encode(b"s" * 16), "sub", "did:key:zEvil")
    payload = {"iss": ISSUER, "vct": VCT, "sub": "did:key:zHonest", "iat": int(time.time()),
               "_sd": [disclosure_digest(disclosure)], "_sd_alg": "sha-256"}
    header = {"typ": "dc+sd-jwt", "alg": key.alg, "kid": key.kid}
    issuer_jwt = SdJwtVcProofSuite._sign_compact(header, payload, key)
    presentation = issuer_jwt + "~" + disclosure + "~"
    with pytest.raises(SdJwtError):
        suite.verify(presentation, public_key_jwk=key.public_jwk())


def test_wrong_issuer_key_is_rejected():
    key = _issuer_key()
    other = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["age"])
    with pytest.raises(SignatureInvalid):
        suite.verify(sd_jwt, public_key_jwk=other.public_jwk())


def test_algorithm_allow_list_before_crypto():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["age"])
    issuer_jwt, sep, tail = sd_jwt.partition("~")
    h_b64, p_b64, s_b64 = issuer_jwt.split(".")
    header = json.loads(_b64url_decode(h_b64))
    header["alg"] = "none"
    forged_jwt = _b64url_encode(json.dumps(header).encode()) + f".{p_b64}.{s_b64}"
    with pytest.raises(UnsupportedAlgorithm):
        suite.verify(forged_jwt + sep + tail, public_key_jwk=key.public_jwk())


def test_expired_token_is_rejected():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key,
                         disclosable=["age"], expires_in_s=-3600)
    with pytest.raises(ClaimsInvalid):
        suite.verify(sd_jwt, public_key_jwk=key.public_jwk())


def test_expected_vct_mismatch_is_rejected():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["age"])
    with pytest.raises(ClaimsInvalid):
        suite.verify(sd_jwt, public_key_jwk=key.public_jwk(),
                     expected_vct="https://credentials.example/other")


# --------------------------------------------------------------------------- #
# nested + array-element disclosure (verifier must handle both)
# --------------------------------------------------------------------------- #

def test_nested_object_disclosure():
    key = _issuer_key()
    street = make_object_disclosure(_b64url_encode(b"a" * 16), "street", "Main St")
    payload = {
        "iss": ISSUER, "vct": VCT, "iat": int(time.time()),
        "address": {"country": "ES", "_sd": [disclosure_digest(street)]},
        "_sd_alg": "sha-256",
    }
    header = {"typ": "dc+sd-jwt", "alg": key.alg, "kid": key.kid}
    issuer_jwt = SdJwtVcProofSuite._sign_compact(header, payload, key)
    result = suite.verify(issuer_jwt + "~" + street + "~", public_key_jwk=key.public_jwk())
    assert result.claims["address"] == {"country": "ES", "street": "Main St"}


def test_array_element_disclosure_present_and_absent():
    key = _issuer_key()
    fr = make_array_disclosure(_b64url_encode(b"b" * 16), "FR")
    payload = {
        "iss": ISSUER, "vct": VCT, "iat": int(time.time()),
        "nationalities": ["ES", {"...": disclosure_digest(fr)}],
        "_sd_alg": "sha-256",
    }
    header = {"typ": "dc+sd-jwt", "alg": key.alg, "kid": key.kid}
    issuer_jwt = SdJwtVcProofSuite._sign_compact(header, payload, key)

    disclosed = suite.verify(issuer_jwt + "~" + fr + "~", public_key_jwk=key.public_jwk())
    assert disclosed.claims["nationalities"] == ["ES", "FR"]

    withheld = suite.verify(issuer_jwt + "~", public_key_jwk=key.public_jwk())
    assert withheld.claims["nationalities"] == ["ES"]           # undisclosed element dropped


# --------------------------------------------------------------------------- #
# key binding (holder presentation)
# --------------------------------------------------------------------------- #

def _issue_bound(issuer_key, holder_key):
    return suite.issue(_base_claims(), signing_key=issuer_key,
                       disclosable=["given_name", "age"],
                       holder_jwk=holder_key.public_jwk())


def test_key_binding_roundtrip():
    issuer_key, holder_key = _issuer_key(), _issuer_key()
    sd_jwt = _issue_bound(issuer_key, holder_key)
    presentation = suite.create_presentation(
        sd_jwt, holder_key=holder_key, audience="https://verifier.example", nonce="n-123")
    result = suite.verify(
        presentation, public_key_jwk=issuer_key.public_jwk(),
        audience="https://verifier.example", nonce="n-123", require_key_binding=True)
    assert result.key_bound is True
    assert result.claims["given_name"] == "Ada"
    assert result.confirmation == {"jwk": holder_key.public_jwk()}


def test_key_binding_with_p256_holder():
    issuer_key = _issuer_key()
    holder_key = P256SigningKey.generate(kid="did:key:zP256#0")
    sd_jwt = _issue_bound(issuer_key, holder_key)
    presentation = suite.create_presentation(
        sd_jwt, holder_key=holder_key, audience="aud", nonce="n")
    result = suite.verify(presentation, public_key_jwk=issuer_key.public_jwk(),
                          audience="aud", nonce="n", require_key_binding=True)
    assert result.key_bound is True


def test_key_binding_wrong_audience_or_nonce():
    issuer_key, holder_key = _issuer_key(), _issuer_key()
    sd_jwt = _issue_bound(issuer_key, holder_key)
    presentation = suite.create_presentation(
        sd_jwt, holder_key=holder_key, audience="aud", nonce="n")
    with pytest.raises(ClaimsInvalid):
        suite.verify(presentation, public_key_jwk=issuer_key.public_jwk(),
                     audience="WRONG", nonce="n", require_key_binding=True)
    with pytest.raises(ClaimsInvalid):
        suite.verify(presentation, public_key_jwk=issuer_key.public_jwk(),
                     audience="aud", nonce="WRONG", require_key_binding=True)


def test_key_binding_sd_hash_detects_tampered_disclosures():
    issuer_key, holder_key = _issuer_key(), _issuer_key()
    sd_jwt = _issue_bound(issuer_key, holder_key)
    presentation = suite.create_presentation(
        sd_jwt, holder_key=holder_key, audience="aud", nonce="n")
    # Drop a disclosure after the KB-JWT was computed -> sd_hash no longer matches.
    parts = presentation.split("~")
    tampered = "~".join([parts[0], parts[1], parts[-1]])       # drop parts[2]
    with pytest.raises(ClaimsInvalid):
        suite.verify(tampered, public_key_jwk=issuer_key.public_jwk(),
                     audience="aud", nonce="n", require_key_binding=True)


def test_key_binding_required_but_absent():
    issuer_key, holder_key = _issuer_key(), _issuer_key()
    sd_jwt = _issue_bound(issuer_key, holder_key)          # no KB-JWT attached
    with pytest.raises(ClaimsInvalid):
        suite.verify(sd_jwt, public_key_jwk=issuer_key.public_jwk(),
                     require_key_binding=True)


# --------------------------------------------------------------------------- #
# inspection + status integration
# --------------------------------------------------------------------------- #

def test_peek_issuer():
    key = _issuer_key()
    sd_jwt = suite.issue(_base_claims(), signing_key=key, disclosable=["age"])
    iss, kid = suite.peek_issuer(sd_jwt)
    assert iss == ISSUER and kid == f"{ISSUER}#key-1"


def test_status_claim_checked_via_token_status_list():
    from openvc.status import (
        STATUS_INVALID,
        check_token_status,
        encode_status_list,
        new_status_list,
        set_status,
    )
    key = _issuer_key()
    list_uri = "https://issuer.example/status/1"
    claims = dict(_base_claims(), status={"status_list": {"idx": 7, "uri": list_uri}})
    sd_jwt = suite.issue(claims, signing_key=key, disclosable=["age"])
    result = suite.verify(sd_jwt, public_key_jwk=key.public_jwk())

    data = new_status_list(64, bits=1)
    set_status(data, 7, STATUS_INVALID, bits=1)
    resolve = {list_uri: {"status_list": {"bits": 1, "lst": encode_status_list(bytes(data))}}}
    status = check_token_status(result.claims, resolve_status_list_token=resolve.__getitem__)
    assert status is not None and status.revoked is True


def test_non_numeric_exp_fails_closed():
    # a present-but-non-numeric exp must fail closed, not have its expiry skipped
    from openvc.proof._jws import sign_compact

    sk = _issuer_key()
    header = {"alg": sk.alg, "typ": "dc+sd-jwt", "kid": sk.kid}
    issuer_jwt = sign_compact(
        header, {"iss": ISSUER, "vct": VCT, "exp": "not-a-date"}, signing_key=sk)
    with pytest.raises(ClaimsInvalid, match="numeric"):
        SdJwtVcProofSuite().verify(issuer_jwt + "~", public_key_jwk=sk.public_jwk())
