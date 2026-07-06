"""
tests/test_status_issue.py — issuer-side status-list construction (Etapa 6).

Building and signing the two status-list artifacts and round-tripping them back
through the check side:

* W3C Bitstring: build the status-list credential + the credentialStatus entry,
  sign the credential (VC-JWT and Data Integrity), and confirm the check reads the
  revoked bit.
* IETF: build + sign the status-list token, verify it, and confirm the referenced
  token's status resolves to revoked.

Plus the shared compact-JWS helper the token path reuses from the VC-JWT suite.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof._jws import parse_compact, sign_compact, verify_compact
from openvc.proof.vc_jwt import (
    MalformedToken,
    SignatureInvalid,
    UnsupportedAlgorithm,
    VcJwtProofSuite,
)
from openvc.status import (
    STATUS_INVALID,
    STATUS_LIST_JWT_TYP,
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    build_status_list_token,
    build_token_status_reference,
    check_credential_status,
    check_token_status,
    encode_status_list,
    new_bitstring,
    new_status_list,
    set_status,
    set_status_bit,
    verify_status_list_token,
)

UTC = timezone.utc
LIST_URL = "https://issuer.example/status/1"
ISSUER = "did:example:issuer"


# --------------------------------------------------------------------------- #
# W3C Bitstring — build the list credential + entry, check the bit
# --------------------------------------------------------------------------- #

def _bitstring_status_vc(revoked_index: int, *, size: int = 256, purpose: str = "revocation"):
    bits = new_bitstring(size)
    set_status_bit(bits, revoked_index, 1)
    return build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=bits, status_purpose=purpose)


def _entry(index: int, purpose: str = "revocation"):
    return {"credentialStatus": build_status_list_entry(
        status_list_credential=LIST_URL, index=index, status_purpose=purpose)}


def test_bitstring_build_and_check_roundtrip():
    status_vc = _bitstring_status_vc(42)
    assert status_vc["type"] == ["VerifiableCredential", "BitstringStatusListCredential"]
    assert status_vc["@context"] == ["https://www.w3.org/ns/credentials/v2"]
    assert status_vc["credentialSubject"]["id"] == f"{LIST_URL}#list"
    assert status_vc["credentialSubject"]["statusPurpose"] == "revocation"

    revoked = check_credential_status(_entry(42), resolve_status_list=lambda u: status_vc)
    assert revoked.revoked is True and revoked.entries[0].is_set is True
    clean = check_credential_status(_entry(7), resolve_status_list=lambda u: status_vc)
    assert clean.revoked is False


def test_bitstring_suspension_purpose():
    status_vc = _bitstring_status_vc(3, purpose="suspension")
    result = check_credential_status(
        _entry(3, "suspension"), resolve_status_list=lambda u: status_vc)
    assert result.suspended is True and result.revoked is False


def test_bitstring_signed_as_vc_jwt_then_checked():
    sk = Ed25519SigningKey.generate(kid="did:key:zStatus#zStatus")
    status_vc = _bitstring_status_vc(100)
    suite = VcJwtProofSuite()
    token = suite.sign(status_vc, signing_key=sk)

    # the resolver fetches + verifies the signed list, returning the VC object
    def resolve(_url):
        return suite.verify(token, public_key_jwk=sk.public_jwk()).credential

    result = check_credential_status(_entry(100), resolve_status_list=resolve)
    assert result.revoked is True


def test_bitstring_signed_as_data_integrity_then_checked():
    pytest.importorskip("pyld")
    from openvc.proof.data_integrity import DataIntegrityProofSuite

    sk = Ed25519SigningKey.generate(kid="did:key:zStatus#zStatus")
    status_vc = _bitstring_status_vc(5)
    suite = DataIntegrityProofSuite()
    signed = suite.add_proof(status_vc, signing_key=sk, verification_method=sk.kid)

    def resolve(_url):
        return suite.verify(signed, public_key_jwk=sk.public_jwk()).credential

    result = check_credential_status(_entry(5), resolve_status_list=resolve)
    assert result.revoked is True


def test_bitstring_credential_carries_optional_metadata():
    bits = new_bitstring(128)
    vc = build_status_list_credential(
        id=LIST_URL, issuer=ISSUER, bitstring=bits,
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_until=datetime(2027, 1, 1, tzinfo=UTC), ttl=300)
    assert vc["validFrom"] == "2026-01-01T00:00:00Z"
    assert vc["validUntil"] == "2027-01-01T00:00:00Z"
    assert vc["credentialSubject"]["ttl"] == 300


# --------------------------------------------------------------------------- #
# IETF Token Status List — build + sign + verify the token, check the reference
# --------------------------------------------------------------------------- #

def test_token_build_verify_and_check_roundtrip():
    sk = P256SigningKey.generate(kid="did:key:zTok#zTok")          # ES256
    data = new_status_list(64, bits=2)
    set_status(data, 9, STATUS_INVALID, bits=2)
    token = build_status_list_token(signing_key=sk, uri=LIST_URL, status_list=data, bits=2)

    claims = verify_status_list_token(
        token, public_key_jwk=sk.public_jwk(), expected_uri=LIST_URL)
    assert claims["sub"] == LIST_URL and claims["status_list"]["bits"] == 2

    revoked = check_token_status(
        build_token_status_reference(uri=LIST_URL, index=9),
        resolve_status_list_token=lambda u: verify_status_list_token(
            token, public_key_jwk=sk.public_jwk(), expected_uri=u))
    assert revoked is not None and revoked.revoked is True

    clean = check_token_status(
        build_token_status_reference(uri=LIST_URL, index=0),
        resolve_status_list_token=lambda u: verify_status_list_token(
            token, public_key_jwk=sk.public_jwk()))
    assert clean is not None and clean.revoked is False and clean.status == 0


def test_token_verify_rejects_wrong_key():
    sk = Ed25519SigningKey.generate(kid="k")
    other = Ed25519SigningKey.generate(kid="k")
    token = build_status_list_token(
        signing_key=sk, uri=LIST_URL, status_list=new_status_list(8, bits=1))
    with pytest.raises(SignatureInvalid):
        verify_status_list_token(token, public_key_jwk=other.public_jwk())


def test_token_verify_requires_statuslist_typ():
    # a VC-JWT (typ=JWT) must not pass as a status-list token even if well-signed
    sk = Ed25519SigningKey.generate(kid="k")
    vc_jwt = VcJwtProofSuite().sign(
        {"issuer": ISSUER, "credentialSubject": {}}, signing_key=sk)
    with pytest.raises(StatusListError, match="typ"):
        verify_status_list_token(vc_jwt, public_key_jwk=sk.public_jwk())


def test_token_verify_rejects_sub_mismatch():
    sk = Ed25519SigningKey.generate(kid="k")
    token = build_status_list_token(
        signing_key=sk, uri=LIST_URL, status_list=new_status_list(8, bits=1))
    with pytest.raises(StatusListError, match="sub"):
        verify_status_list_token(
            token, public_key_jwk=sk.public_jwk(), expected_uri="https://evil.example/other")


def test_token_verify_enforces_exp_with_now_pin():
    sk = Ed25519SigningKey.generate(kid="k")
    token = build_status_list_token(
        signing_key=sk, uri=LIST_URL, status_list=new_status_list(8, bits=1),
        issued_at=datetime(2019, 1, 1, tzinfo=UTC), expires=datetime(2020, 1, 1, tzinfo=UTC))
    with pytest.raises(StatusListError, match="expired"):
        verify_status_list_token(token, public_key_jwk=sk.public_jwk())      # now = today
    # valid when evaluated 'as of' a time inside the window
    claims = verify_status_list_token(
        token, public_key_jwk=sk.public_jwk(), now=datetime(2019, 6, 1, tzinfo=UTC))
    assert "status_list" in claims


def test_token_verify_rejects_non_numeric_exp_fails_closed():
    # a signed token whose exp is the wrong JSON type must fail closed, not have
    # its expiry silently skipped (that would let a stale list be accepted)
    sk = Ed25519SigningKey.generate(kid="k")
    payload = {
        "sub": LIST_URL,
        "iat": 1,
        "exp": "2020-01-01T00:00:00Z",             # a string, not a NumericDate
        "status_list": {"bits": 1, "lst": encode_status_list(bytes(new_status_list(8)))},
    }
    header = {"typ": STATUS_LIST_JWT_TYP, "alg": sk.alg, "kid": sk.kid}
    forged = sign_compact(header, payload, signing_key=sk)
    with pytest.raises(StatusListError, match="numeric"):
        verify_status_list_token(forged, public_key_jwk=sk.public_jwk())


# --------------------------------------------------------------------------- #
# Shared compact-JWS helper (also exercised indirectly by the token path)
# --------------------------------------------------------------------------- #

class _BadAlgKey:
    alg = "RS256"
    kid = "k"

    def sign(self, signing_input: bytes) -> bytes:
        return b"unused"


def test_sign_and_verify_compact_roundtrip():
    sk = Ed25519SigningKey.generate(kid="k1")
    token = sign_compact(
        {"alg": sk.alg, "typ": "example+jwt", "kid": sk.kid},
        {"hello": "world"}, signing_key=sk)
    header, payload = verify_compact(token, public_key_jwk=sk.public_jwk())
    assert header["typ"] == "example+jwt" and payload["hello"] == "world"


def test_sign_compact_rejects_non_allowlisted_alg():
    with pytest.raises(UnsupportedAlgorithm):
        sign_compact({"alg": "RS256"}, {}, signing_key=_BadAlgKey())


def test_verify_compact_detects_tampered_payload():
    sk = Ed25519SigningKey.generate(kid="k")
    token = sign_compact({"alg": sk.alg, "kid": sk.kid}, {"a": 1}, signing_key=sk)
    head, _, sig = token.split(".")
    forged = base64.urlsafe_b64encode(json.dumps({"a": 2}).encode()).rstrip(b"=").decode()
    with pytest.raises(SignatureInvalid):
        verify_compact(f"{head}.{forged}.{sig}", public_key_jwk=sk.public_jwk())


def test_parse_compact_rejects_malformed():
    with pytest.raises(MalformedToken):
        parse_compact("only-one-part")
    with pytest.raises(MalformedToken):
        parse_compact("too.many.parts.here")
