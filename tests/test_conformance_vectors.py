"""
tests/test_conformance_vectors.py — a wire-format drift alarm for the two IETF
formats openvc implements that are still pre-RFC (issue #13).

TRACKED DRAFT VERSIONS (review + re-pin when either advances):
  * SD-JWT VC          — draft-ietf-oauth-sd-jwt-vc-16   (base SD-JWT = RFC 9901)
  * Token Status List  — draft-ietf-oauth-status-list-21

Late drafts still shift small normative details (the ``typ`` header, claim names,
the reference shape, status values). This test pins the wire details openvc emits
and accepts, plus the module constants that carry them, so a change — in openvc, or
one a new draft requires openvc to make — fails loudly and prompts a review. It is a
regression/drift alarm on the wire contract; it is not a cross-implementation interop
suite (that would vendor another implementation's signed vectors — a larger follow-up).
"""
from __future__ import annotations

from openvc.proof._jws import parse_compact
from openvc.proof.sd_jwt import (
    _ACCEPTED_ISSUER_TYP,
    _ISSUER_TYP,
    _KB_TYP,
    SdJwtVcProofSuite,
)
from openvc.status import (
    STATUS_INVALID,
    STATUS_LIST_JWT_TYP,
    STATUS_SUSPENDED,
    STATUS_VALID,
    build_status_list_token,
    build_token_status_reference,
    check_token_status,
    new_status_list,
    parse_token_status_ref,
    set_status,
    verify_status_list_token,
)

TOKEN_URI = "https://issuer.example/statuslist/1"


def _p256(kid="did:example:issuer#k"):
    from openvc.keys import P256SigningKey
    return P256SigningKey.generate(kid=kid)


# --------------------------------------------------------------------------- #
# SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-16)
# --------------------------------------------------------------------------- #

def test_sd_jwt_vc_wire_constants_match_the_draft():
    assert _ISSUER_TYP == "dc+sd-jwt"                     # current draft media type
    assert "vc+sd-jwt" in _ACCEPTED_ISSUER_TYP            # older draft still accepted
    assert _KB_TYP == "kb+jwt"


def test_sd_jwt_vc_issued_vector_conforms_and_verifies():
    key = _p256()
    claims = {"iss": "did:example:issuer", "sub": "did:example:alice",
              "given_name": "Ada", "email": "a@b.com"}
    sd_jwt = SdJwtVcProofSuite().issue(
        claims, signing_key=key, vct="https://example.com/ExampleCredential",
        disclosable=["given_name"])

    assert "~" in sd_jwt                                  # issuer-jwt ~ disclosures ~ [kb]
    issuer_jwt = sd_jwt.split("~", 1)[0]
    header, payload, _, _ = parse_compact(issuer_jwt)
    assert header["typ"] == "dc+sd-jwt"                   # draft typ header
    assert header["alg"] == "ES256"
    assert "_sd_alg" in payload and payload["_sd_alg"] == "sha-256"
    assert "_sd" in payload                               # selective-disclosure digests
    assert "vct" in payload                               # SD-JWT VC type claim

    verified = SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=key.public_jwk())
    assert verified.claims["given_name"] == "Ada"         # the disclosed claim is recovered


# --------------------------------------------------------------------------- #
# IETF Token Status List (draft-ietf-oauth-status-list-21)
# --------------------------------------------------------------------------- #

def test_status_list_wire_constants_match_the_draft():
    assert STATUS_LIST_JWT_TYP == "statuslist+jwt"
    assert (STATUS_VALID, STATUS_INVALID, STATUS_SUSPENDED) == (0x00, 0x01, 0x02)


def test_status_list_reference_shape_conforms():
    ref = build_token_status_reference(uri=TOKEN_URI, index=7)
    # a referenced token carries: status.status_list.{idx, uri}
    assert ref == {"status": {"status_list": {"idx": 7, "uri": TOKEN_URI}}}
    parsed = parse_token_status_ref(ref)
    assert parsed is not None and parsed.index == 7 and parsed.uri == TOKEN_URI


def test_status_list_token_vector_conforms_and_verifies():
    key = _p256()
    lst = new_status_list(64, bits=2)
    set_status(lst, 3, STATUS_INVALID, bits=2)
    token = build_status_list_token(
        signing_key=key, uri=TOKEN_URI, status_list=lst, bits=2, issuer="did:example:issuer")

    header, payload, _, _ = parse_compact(token)
    assert header["typ"] == "statuslist+jwt"             # draft typ header
    assert payload["sub"] == TOKEN_URI                   # sub == the list URI (anti-swap)
    sl = payload["status_list"]
    assert sl["bits"] == 2 and isinstance(sl["lst"], str)  # {bits, lst} member

    claims = verify_status_list_token(
        token, public_key_jwk=key.public_jwk(), expected_uri=TOKEN_URI)
    result = check_token_status(
        {"status": {"status_list": {"idx": 3, "uri": TOKEN_URI}}},
        resolve_status_list_token=lambda _uri: claims)
    assert result is not None and result.revoked          # index 3 -> INVALID -> revoked
