"""An SD-JWT never has an empty disclosure segment (RFC 9901 §4 ABNF).

``SD-JWT = JWT "~" *(DISCLOSURE "~")`` and ``DISCLOSURE = BASE64URL`` (``1*(...)``):
a ``~~`` is not part of the grammar. ``_split`` used to drop empty segments, and the KB-JWT
``sd_hash`` is computed over the re-joined, normalised form, so one presentation had many
accepted spellings. An empty segment between the issuer JWT and the last segment is now a
``MalformedToken``; the last segment keeps its meaning (empty = no KB-JWT).

Every lane that reads the ``~`` structure is exercised: ``verify_credential``, its async twin,
``verify_vp_token`` (``dc+sd-jwt`` and nested in a VP-JWT) and the suite itself. The issuer is
a real did:key, so a refusal here is the segment check and not a key-resolution failure.
"""
from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import VerificationPolicy, verify_credential, verify_credential_async
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import verify_vp_token
from openvc.proof.errors import MalformedToken
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite

CLIENT_ID = "x509_san_dns:client.example.org"
NONCE = "n-0S6_WzA2Mj"
VCT = "https://credentials.example.com/identity_credential"
DC_DCQL = {"credentials": [{"id": "q", "format": "dc+sd-jwt"}]}


def _did_key_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def parties():
    return _did_key_p256(), _did_key_p256()


@pytest.fixture(scope="module")
def issued(parties):
    """(issuer-jwt, d1, d2) of a holder-bound SD-JWT VC with two disclosures."""
    (issuer_key, issuer_did), (holder_key, holder_did) = parties
    sd = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "sub": holder_did, "given": "A", "family": "B"},
        signing_key=issuer_key, vct=VCT, disclosable=["given", "family"],
        holder_jwk=holder_key.public_jwk())
    jwt, d1, d2, tail = sd.split("~")
    assert tail == "" and d1 and d2          # issue() emits the canonical form
    return jwt, d1, d2


@pytest.fixture(scope="module")
def presented(parties, issued):
    """The same credential with a KB-JWT, as create_presentation() emits it."""
    holder_key = parties[1][0]
    jwt, d1, d2 = issued
    sd = SdJwtVcProofSuite().create_presentation(
        f"{jwt}~{d1}~{d2}~", holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)
    head, kb = sd.rsplit("~", 1)
    assert head == f"{jwt}~{d1}~{d2}" and kb.count(".") == 2   # canonical, KB-JWT last
    return jwt, d1, d2, kb


def _spellings(jwt, d1, d2, kb=""):
    """(id, string) — the canonical control first, then every hostile re-spelling."""
    return [
        ("canonical", f"{jwt}~{d1}~{d2}~{kb}", True),
        ("doubled-between", f"{jwt}~{d1}~~{d2}~{kb}", False),
        ("leading", f"{jwt}~~{d1}~{d2}~{kb}", False),
        ("doubled-before-last", f"{jwt}~{d1}~{d2}~~{kb}", False),
        ("tripled-before-last", f"{jwt}~{d1}~{d2}~~~{kb}", False),
    ]


def _cases(jwt, d1, d2, kb=""):
    return [pytest.param(text, ok, id=name) for name, text, ok in _spellings(jwt, d1, d2, kb)]


def _policy(with_kb):
    return VerificationPolicy(
        audience=CLIENT_ID if with_kb else None, nonce=NONCE if with_kb else None,
        require_key_binding=with_kb)


# --------------------------------------------------------------------------- #
# verify_credential / verify_credential_async
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("with_kb", [False, True], ids=["no-kb", "kb"])
@pytest.mark.parametrize("lane", ["sync", "async"])
def test_pipeline_refuses_empty_segments(issued, presented, lane, with_kb):
    jwt, d1, d2, kb = presented if with_kb else (*issued, "")

    def run(text):
        if lane == "sync":
            return verify_credential(text, policy=_policy(with_kb))
        return asyncio.run(verify_credential_async(text, policy=_policy(with_kb)))

    for name, text, ok in _spellings(jwt, d1, d2, kb):
        if ok:
            assert run(text).key_bound is with_kb, name
        else:
            with pytest.raises(MalformedToken, match="disclosure segment is empty"):
                run(text)


@pytest.mark.parametrize("text_of", [
    lambda j, d1, d2: f"{j}~~",
    lambda j, d1, d2: f"{j}~~~",
], ids=["jwt~~", "jwt~~~"])
@pytest.mark.parametrize("lane", ["sync", "async"])
def test_pipeline_refuses_no_disclosure_forms(issued, lane, text_of):
    text = text_of(*issued)
    with pytest.raises(MalformedToken):
        if lane == "sync":
            verify_credential(text, policy=_policy(False))
        else:
            asyncio.run(verify_credential_async(text, policy=_policy(False)))


def test_a_jwt_with_no_disclosure_is_still_accepted_in_its_one_canonical_form(parties):
    """Control: ``<jwt>~`` (no disclosure at all) is the grammar's zero-repeat case."""
    (issuer_key, issuer_did), _ = parties
    sd = SdJwtVcProofSuite().issue({"iss": issuer_did, "given": "A"}, signing_key=issuer_key,
                                   vct=VCT)
    assert sd.endswith("~") and sd.count("~") == 1
    assert verify_credential(sd, policy=_policy(False)).credential["given"] == "A"


def test_no_trailing_tilde_stays_refused(issued):
    jwt, d1, d2 = issued
    with pytest.raises(MalformedToken):
        verify_credential(f"{jwt}~{d1}~{d2}", policy=_policy(False))


def test_kb_jwt_over_the_normalised_form_does_not_survive_a_respelling(presented):
    """The reviewed case: the sd_hash covers the normalised string, so the re-spelled
    presentation used to verify with key_bound=True. It is refused now, not re-bound."""
    jwt, d1, d2, kb = presented
    for text in (f"{jwt}~{d1}~~{d2}~{kb}", f"{jwt}~~{d1}~{d2}~{kb}",
                 f"{jwt}~{d1}~{d2}~~{kb}"):
        with pytest.raises(MalformedToken):
            verify_credential(text, policy=_policy(True))


# --------------------------------------------------------------------------- #
# the suite and the holder side
# --------------------------------------------------------------------------- #

def test_suite_verify_refuses_empty_segments(parties, issued):
    (issuer_key, _), _ = parties
    jwk = issuer_key.public_jwk()
    jwt, d1, d2 = issued
    suite = SdJwtVcProofSuite()
    assert suite.verify(f"{jwt}~{d1}~{d2}~", public_key_jwk=jwk).claims["given"] == "A"
    for text in (f"{jwt}~{d1}~~{d2}~", f"{jwt}~~{d1}~{d2}~", f"{jwt}~~"):
        with pytest.raises(MalformedToken):
            suite.verify(text, public_key_jwk=jwk)


def test_create_presentation_refuses_empty_segments(parties, issued):
    holder_key = parties[1][0]
    jwt, d1, d2 = issued
    with pytest.raises(MalformedToken):
        SdJwtVcProofSuite().create_presentation(
            f"{jwt}~{d1}~~{d2}~", holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)


def test_issue_and_create_presentation_emit_no_empty_segment(presented, issued):
    jwt, d1, d2, kb = presented
    for text in (f"{issued[0]}~{issued[1]}~{issued[2]}~", f"{jwt}~{d1}~{d2}~{kb}"):
        assert all(text.split("~")[:-1])            # no empty segment before the last


# --------------------------------------------------------------------------- #
# verify_vp_token
# --------------------------------------------------------------------------- #

def _dc(text):
    return verify_vp_token({"q": [text]}, dcql_query=DC_DCQL, nonce=NONCE,
                           client_id=CLIENT_ID).for_query("q")[0]


def test_vp_token_dc_sd_jwt_refuses_empty_segments(issued, presented):
    jwt, d1, d2, kb = presented
    for name, text, ok in _spellings(jwt, d1, d2, kb):
        if ok:
            assert _dc(text).credentials[0].key_bound is True
        else:
            with pytest.raises(MalformedToken, match="disclosure segment is empty"):
                _dc(text)


def test_vp_token_dc_sd_jwt_without_kb_refuses_empty_segments(issued):
    jwt, d1, d2 = issued
    dcql = {"credentials": [{"id": "q", "format": "dc+sd-jwt",
                             "require_cryptographic_holder_binding": False}]}

    def run(text):
        return verify_vp_token({"q": [text]}, dcql_query=dcql, nonce=NONCE,
                               client_id=CLIENT_ID).for_query("q")[0]

    assert run(f"{jwt}~{d1}~{d2}~").credentials[0].key_bound is False
    for text in (f"{jwt}~{d1}~~{d2}~", f"{jwt}~~{d1}~{d2}~", f"{jwt}~{d1}~{d2}~~", f"{jwt}~~"):
        with pytest.raises(MalformedToken, match="disclosure segment is empty"):
            run(text)


@pytest.mark.parametrize("with_kb", [False, True], ids=["no-kb", "kb"])
def test_vp_jwt_nested_sd_jwt_refuses_empty_segments(parties, issued, presented, with_kb):
    jwt, d1, d2, kb = presented if with_kb else (*issued, "")
    holder_key = parties[1][0]
    dcql = {"credentials": [{"id": "q", "format": "jwt_vc_json",
                             "require_cryptographic_holder_binding": with_kb}]}

    def run(text):
        vp = VpJwtProofSuite().sign([text], holder_key=holder_key, audience=CLIENT_ID,
                                    nonce=NONCE)
        return verify_vp_token({"q": [vp]}, dcql_query=dcql, nonce=NONCE,
                               client_id=CLIENT_ID).for_query("q")[0]

    assert run(f"{jwt}~{d1}~{d2}~{kb}").credentials[0].key_bound is with_kb
    for name, text, ok in _spellings(jwt, d1, d2, kb):
        if not ok:
            with pytest.raises(MalformedToken, match="disclosure segment is empty"):
                run(text)
