"""
tests/test_sd_jwt.py — SD-JWT VC proof suite: issuance, holder key binding,
verification, and the selective-disclosure security properties. All offline.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc import VerificationPolicy, verify_credential
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
from openvc.verify import KeyResolutionFailed

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


# --------------------------------------------------------------------------- #
# x5c issuer trust (issue #94): the SD-JWT VC carries an x5c chain, so the
# pipeline anchors the issuer to a trusted list in ONE verify_credential call.
# --------------------------------------------------------------------------- #

_X5C_ISS = "https://sede.uc3m.es"
_X5C_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_X5C_CA_KU = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)


def _x5c_cert(subject, issuer_cn, issuer_key, subject_pub, *, ca, san=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_pub).serial_number(x509.random_serial_number())
        .not_valid_before(_X5C_NOW - dt.timedelta(days=1))
        .not_valid_after(_X5C_NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(_X5C_CA_KU, critical=True)
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _issued_with_x5c(*, san_iss=_X5C_ISS):
    """(sd_jwt issued with an x5c chain, the FNMT-analog root anchor). The document
    signer wraps the SIGNING key and is chained to the root; SAN carries san_iss."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _x5c_cert("FNMT root", "FNMT root", root_key, root_key.public_key(), ca=True)
    signer_priv = ec.generate_private_key(ec.SECP256R1())
    signer = P256SigningKey(signer_priv, kid="uc3m-signer")
    ds = _x5c_cert("UC3M DS", "FNMT root", root_key, signer_priv.public_key(), ca=False,
                   san=[x509.UniformResourceIdentifier(san_iss)])
    x5c = [base64.b64encode(ds.public_bytes(serialization.Encoding.DER)).decode("ascii")]
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": _X5C_ISS, "title": "Grado en Ingeniería Informática"},
        signing_key=signer, vct=VCT, x5c=x5c)
    return sd_jwt, root


def _policy():
    return VerificationPolicy(require_status=False, now=_X5C_NOW)


def test_sd_jwt_vc_with_x5c_verifies_through_pipeline():
    sd_jwt, root = _issued_with_x5c()
    result = verify_credential(sd_jwt, x5c_trust_anchors=[root], policy=_policy())
    assert result.format == "sd-jwt-vc"
    assert result.issuer == _X5C_ISS              # bound via the FNMT-anchored cert SAN
    assert result.claims["title"] == "Grado en Ingeniería Informática"


def test_sd_jwt_vc_x5c_header_present():
    sd_jwt, _ = _issued_with_x5c()
    header = json.loads(base64.urlsafe_b64decode(
        sd_jwt.split("~", 1)[0].split(".")[0] + "=="))
    assert isinstance(header["x5c"], list) and header["x5c"]


def test_sd_jwt_vc_x5c_untrusted_anchor_rejected():
    sd_jwt, _ = _issued_with_x5c()
    stranger_key = ec.generate_private_key(ec.SECP256R1())
    stranger = _x5c_cert("other", "other", stranger_key, stranger_key.public_key(), ca=True)
    with pytest.raises(KeyResolutionFailed):
        verify_credential(sd_jwt, x5c_trust_anchors=[stranger], policy=_policy())


def test_sd_jwt_vc_x5c_iss_not_in_san_rejected():
    # the cert SAN names a different host than iss -> the issuer binding fails closed
    sd_jwt, root = _issued_with_x5c(san_iss="https://attacker.example")
    with pytest.raises(KeyResolutionFailed):
        verify_credential(sd_jwt, x5c_trust_anchors=[root], policy=_policy())


@pytest.mark.parametrize("bad", [[], [""], [123]], ids=["empty", "blank", "non-str"])
def test_issue_rejects_malformed_x5c(bad):
    with pytest.raises(SdJwtError, match="x5c"):
        SdJwtVcProofSuite().issue(
            {"iss": _X5C_ISS}, signing_key=P256SigningKey.generate(kid="k"),
            vct=VCT, x5c=bad)
