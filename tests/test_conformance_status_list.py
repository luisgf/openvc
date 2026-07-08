"""
tests/test_conformance_status_list.py — conformance / drift alarm for the IETF Token
Status List codec and wire contract (issue #60).

Pins the two byte-exact worked examples from **draft-ietf-oauth-status-list-21 §4.1**
(the 1-bit and 2-bit lists) and the token/reference wire contract. As of 2026-07-08 the
document is IESG-approved and in the RFC Editor queue (intended Proposed Standard) — it
has **no RFC number yet**. When it publishes, re-pin these vectors against the RFC's
examples and update the citations in ``openvc.status.token_status_list`` /
``openvc.status.issue``; if the wire format drifts between the draft and the RFC, this
alarm fires first.

The underlying SD-JWT mechanism these credentials use is now **RFC 9901** (Nov 2025,
formerly draft-ietf-oauth-selective-disclosure-jwt); the SD-JWT VC profile
(``draft-ietf-oauth-sd-jwt-vc``) remains a draft that builds on it.
"""
from __future__ import annotations

import pytest

from openvc.keys import P256SigningKey
from openvc.status import new_status_list
from openvc.status.issue import (
    STATUS_LIST_JWT_TYP,
    build_status_list_token,
    build_token_status_reference,
    verify_status_list_token,
)
from openvc.status.token_status_list import (
    STATUS_INVALID,
    STATUS_SUSPENDED,
    STATUS_VALID,
    decode_status_list,
    encode_status_list,
    get_status,
    parse_token_status_ref,
    set_status,
)

# draft-ietf-oauth-status-list-21 §4.1 — the two published worked examples.
# (statuses, bits, lst-base64url, packed-bytes)
VECTOR_1BIT = ([1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1], 1,
               "eNrbuRgAAhcBXQ", bytes([0xB9, 0xA3]))
VECTOR_2BIT = ([1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3], 2,
               "eNo76fITAAPfAgc", bytes([0xC9, 0x44, 0xF9]))


@pytest.mark.parametrize("statuses,bits,lst,packed",
                         [VECTOR_1BIT, VECTOR_2BIT], ids=["1bit", "2bit"])
def test_draft21_vectors_decode_byte_exact(statuses, bits, lst, packed):
    # Decoding the published `lst` yields the exact packed bytes and, per index, the
    # exact status array — the compression-level-independent interop guarantee.
    data = decode_status_list(lst)
    assert data == packed
    assert [get_status(data, i, bits=bits) for i in range(len(statuses))] == statuses


@pytest.mark.parametrize("statuses,bits,lst,packed",
                         [VECTOR_1BIT, VECTOR_2BIT], ids=["1bit", "2bit"])
def test_draft21_vectors_encode_reproduces_lst(statuses, bits, lst, packed):
    # openvc's encoder reproduces the draft's exact `lst` string (level-9 DEFLATE).
    assert encode_status_list(packed) == lst
    built = new_status_list(len(statuses), bits=bits)
    for i, s in enumerate(statuses):
        set_status(built, i, s, bits=bits)
    assert bytes(built) == packed
    assert encode_status_list(bytes(built)) == lst


def test_status_type_values_match_draft():
    # §7.1 Status Types: VALID=0x00, INVALID=0x01, SUSPENDED=0x02 (0x03–0x0F are
    # permanently reserved as application-specific — exposed raw, not mapped).
    assert (STATUS_VALID, STATUS_INVALID, STATUS_SUSPENDED) == (0x00, 0x01, 0x02)


def test_token_and_reference_wire_contract():
    # typ header = statuslist+jwt; token payload carries status_list{bits,lst};
    # a referenced token points via status.status_list{uri,idx}.
    assert STATUS_LIST_JWT_TYP == "statuslist+jwt"
    sk = P256SigningKey.generate(kid="did:example:issuer#k")
    uri = "https://issuer.example/statuslists/1"

    data = new_status_list(32, bits=1)
    set_status(data, 7, STATUS_INVALID, bits=1)
    token = build_status_list_token(signing_key=sk, uri=uri, status_list=data)
    claims = verify_status_list_token(token, public_key_jwk=sk.public_jwk(),
                                      expected_uri=uri)
    assert set(claims["status_list"]) >= {"bits", "lst"}
    assert claims["sub"] == uri

    ref = build_token_status_reference(uri=uri, index=7)
    parsed = parse_token_status_ref(ref)
    assert parsed is not None and parsed.uri == uri and parsed.index == 7
    # the reference lives under status.status_list with uri + idx
    assert ref["status"]["status_list"] == {"uri": uri, "idx": 7}
