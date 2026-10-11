"""
tests/test_nested_sd_jwt_kb_binding.py — an SD-JWT VC nested in a W3C presentation.

A ``jwt_vc_json`` VP-JWT or an ``ldp_vc`` Data Integrity VP may embed an SD-JWT VC
(bare, or in an ``EnvelopedVerifiableCredential``) that carries its own Key Binding
JWT. Until this fix the cascade verified that KB-JWT's signature and ``sd_hash`` but
never its ``aud`` / ``nonce`` — the nested policy had none to give — and reported
``key_bound=True`` for a KB-JWT minted for **another verifier**. RFC 9901 §7.3 step 5.6
is what makes a KB-JWT a binding ("bound to the current transaction and was created
for this Verifier"); a ``key_bound=True`` that skipped it vouched for a holder proof
made for someone else.

The semantics pinned here: a nested KB-JWT, when present, must be bound to the **same**
audience + nonce as the enclosing presentation, or the whole presentation fails closed;
a nested SD-JWT with no KB-JWT stays valid with ``key_bound=False`` (the VP proof is the
holder binding). The binding is scoped to the KB-JWT — a nested VC-JWT's own ``aud`` is
never pinned to the verifier.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import verify_vp_token
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import VerificationPolicy

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
OTHER_AUD = "x509_san_dns:other-verifier.example"
OTHER_NONCE = "other-nonce"
VCT = "https://credentials.example.com/identity_credential"
JWT_VC_DCQL = {"credentials": [{"id": "q", "format": "jwt_vc_json"}]}
LDP_VC_DCQL = {"credentials": [{"id": "q", "format": "ldp_vc"}]}

# (KB-JWT aud, KB-JWT nonce) pairs that are NOT this exchange's binding.
BOUND_ELSEWHERE = [
    pytest.param(OTHER_AUD, OTHER_NONCE, id="other-verifier"),
    pytest.param(CLIENT_ID, OTHER_NONCE, id="right-aud-wrong-nonce"),
    pytest.param(OTHER_AUD, NONCE, id="wrong-aud-right-nonce"),
    pytest.param("client.example.org", NONCE, id="bare-host-aud"),
]


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_ed25519():
    key = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())   # ed25519-pub
    return Ed25519SigningKey(key._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _did_key_p256()


@pytest.fixture(scope="module")
def holder():
    return _did_key_p256()


def _sd_jwt(issuer, holder, kb=None):
    """An SD-JWT VC bound (cnf) to *holder*; with a KB-JWT over *kb* = (aud, nonce)."""
    issuer_key, issuer_did = issuer
    holder_key, holder_did = holder
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "given_name": "Ada", "sub": holder_did},
        signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
        holder_jwk=holder_key.public_jwk())
    if kb is None:
        return issued
    return SdJwtVcProofSuite().create_presentation(
        issued, holder_key=holder_key, audience=kb[0], nonce=kb[1])


def _vc_jwt(issuer, holder):
    issuer_key, issuer_did = issuer
    return VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer_did,
         "credentialSubject": {"id": holder[1]}},
        signing_key=issuer_key)


def _enveloped(sd_jwt, media="application/dc+sd-jwt"):
    return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
            "id": f"data:{media},{sd_jwt}"}


def _vp_jwt(holder, entries, *, audience=CLIENT_ID, nonce=NONCE):
    return VpJwtProofSuite().sign(
        list(entries), holder_key=holder[0], audience=audience, nonce=nonce)


def _ldp_vp(entries, *, domain=CLIENT_ID, challenge=NONCE):
    vp_key, vp_did = _did_key_ed25519()
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": vp_did,
          "verifiableCredential": list(entries)}
    return EddsaJcsProofSuite().add_proof(
        vp, signing_key=vp_key, verification_method=vp_key.kid,
        proof_purpose="authentication", challenge=challenge, domain=domain)


def _jwt_vc_json(vp, **kw):
    return verify_vp_token({"q": [vp]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                           client_id=CLIENT_ID, **kw).for_query("q")[0]


def _ldp_vc(vp):
    return verify_vp_token({"q": [vp]}, dcql_query=LDP_VC_DCQL, nonce=NONCE,
                           client_id=CLIENT_ID).for_query("q")[0]


# --------------------------------------------------------------------------- #
# jwt_vc_json — a VP-JWT embedding an SD-JWT VC
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kb_aud,kb_nonce", BOUND_ELSEWHERE)
def test_jwt_vc_json_rejects_nested_kb_bound_elsewhere(issuer, holder, kb_aud, kb_nonce):
    # The repro: the VP-JWT itself is bound to this verifier, so before the fix the
    # response verified and the nested credential reported key_bound=True.
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(kb_aud, kb_nonce))])
    with pytest.raises(ClaimsInvalid, match=r"KB-JWT (aud|nonce) does not match"):
        _jwt_vc_json(vp)


@pytest.mark.parametrize("kb_aud,kb_nonce", BOUND_ELSEWHERE)
def test_jwt_vc_json_rejects_enveloped_nested_kb_bound_elsewhere(
        issuer, holder, kb_aud, kb_nonce):
    vp = _vp_jwt(holder, [_enveloped(_sd_jwt(issuer, holder, kb=(kb_aud, kb_nonce)))])
    with pytest.raises(ClaimsInvalid, match=r"KB-JWT (aud|nonce) does not match"):
        _jwt_vc_json(vp)


def test_jwt_vc_json_nested_kb_bound_here_is_key_bound(issuer, holder):
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))])
    (cred,) = _jwt_vc_json(vp).credentials
    assert cred.key_bound is True
    assert cred.credential["given_name"] == "Ada"


def test_jwt_vc_json_nested_sd_jwt_without_kb_is_not_key_bound(issuer, holder):
    # No KB-JWT is legitimate inside a VP — the VP signature is the holder binding —
    # and is reported honestly as not key-bound.
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder)])
    (cred,) = _jwt_vc_json(vp).credentials
    assert cred.key_bound is False


def test_one_nested_kb_bound_elsewhere_fails_the_whole_presentation(issuer, holder):
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE)),
                          _sd_jwt(issuer, holder, kb=(OTHER_AUD, OTHER_NONCE))])
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _jwt_vc_json(vp)


def test_binding_does_not_pin_a_nested_vc_jwt_aud(issuer, holder):
    # The binding is scoped to the KB-JWT. A nested VC-JWT carries no `aud` (it is a
    # credential, not a presentation) and must still verify next to a bound SD-JWT.
    vp = _vp_jwt(holder, [_vc_jwt(issuer, holder),
                          _sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))])
    vc, sd = _jwt_vc_json(vp).credentials
    assert "aud" not in vc.claims
    assert vc.key_bound is None and sd.key_bound is True


def test_double_enveloped_nested_kb_keeps_the_binding(issuer, holder):
    # The envelope is transparent at every depth the pipeline unwraps (2): the SD-JWT
    # reached through two envelopes is still held to this exchange.
    import base64
    import json

    def wrap_json(doc):
        b64 = base64.b64encode(json.dumps(doc).encode()).decode()
        return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
                "id": f"data:application/vc+ld+json;base64,{b64}"}

    bad = wrap_json(_enveloped(_sd_jwt(issuer, holder, kb=(OTHER_AUD, OTHER_NONCE))))
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _jwt_vc_json(_vp_jwt(holder, [bad]))
    good = wrap_json(_enveloped(_sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))))
    (cred,) = _jwt_vc_json(_vp_jwt(holder, [good])).credentials
    assert cred.key_bound is True


# --------------------------------------------------------------------------- #
# ldp_vc — a Data Integrity VP embedding an SD-JWT VC (domain = aud, challenge = nonce)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("envelope", [False, True], ids=["bare", "enveloped"])
@pytest.mark.parametrize("kb_aud,kb_nonce", BOUND_ELSEWHERE)
def test_ldp_vc_rejects_nested_kb_bound_elsewhere(issuer, holder, kb_aud, kb_nonce, envelope):
    nested = _sd_jwt(issuer, holder, kb=(kb_aud, kb_nonce))
    vp = _ldp_vp([_enveloped(nested) if envelope else nested])
    with pytest.raises(ClaimsInvalid, match=r"KB-JWT (aud|nonce) does not match"):
        _ldp_vc(vp)


@pytest.mark.parametrize("envelope", [False, True], ids=["bare", "enveloped"])
def test_ldp_vc_nested_kb_bound_here_is_key_bound(issuer, holder, envelope):
    nested = _sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))
    (cred,) = _ldp_vc(_ldp_vp([_enveloped(nested) if envelope else nested])).credentials
    assert cred.key_bound is True


def test_ldp_vc_nested_sd_jwt_without_kb_is_not_key_bound(issuer, holder):
    (cred,) = _ldp_vc(_ldp_vp([_sd_jwt(issuer, holder)])).credentials
    assert cred.key_bound is False


def test_ldp_vc_binding_does_not_pin_a_nested_vc_jwt_aud(issuer, holder):
    vp = _ldp_vp([_vc_jwt(issuer, holder), _sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))])
    vc, sd = _ldp_vc(vp).credentials
    assert vc.key_bound is None and sd.key_bound is True


# --------------------------------------------------------------------------- #
# W3C Digital Credentials API — the binding is the presentation's own origin
# --------------------------------------------------------------------------- #

ORIGINS = ["https://verifier.example", "https://second.example"]


def _dc_api(vp):
    return verify_vp_token({"q": [vp]}, dcql_query=JWT_VC_DCQL, nonce=NONCE,
                           expected_origins=ORIGINS).for_query("q")[0]


def test_dc_api_nested_kb_bound_to_the_vp_origin_is_key_bound(issuer, holder):
    aud = "origin:https://verifier.example"
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(aud, NONCE))], audience=aud)
    (cred,) = _dc_api(vp).credentials
    assert cred.key_bound is True


@pytest.mark.parametrize("kb_aud", [
    pytest.param("origin:https://second.example", id="another-expected-origin"),
    pytest.param(CLIENT_ID, id="client-id-not-origin"),
])
def test_dc_api_nested_kb_must_match_the_vp_origin_exactly(issuer, holder, kb_aud):
    # Being one of expected_origins is not enough: the nested KB-JWT must be bound to
    # the origin THIS presentation is bound to — the same exchange.
    aud = "origin:https://verifier.example"
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(kb_aud, NONCE))], audience=aud)
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _dc_api(vp)


# --------------------------------------------------------------------------- #
# VpJwtProofSuite.verify — the public suite carries the same binding
# --------------------------------------------------------------------------- #

def _suite_verify(vp, **kw):
    kw.setdefault("policy", VerificationPolicy(require_status=False))
    return VpJwtProofSuite().verify(vp, audience=CLIENT_ID, nonce=NONCE, **kw)


@pytest.mark.parametrize("kb_aud,kb_nonce", BOUND_ELSEWHERE)
def test_suite_rejects_nested_kb_bound_elsewhere(issuer, holder, kb_aud, kb_nonce):
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(kb_aud, kb_nonce))])
    with pytest.raises(ClaimsInvalid, match=r"KB-JWT (aud|nonce) does not match"):
        _suite_verify(vp)


def test_suite_binding_wins_over_the_policy_audience_and_nonce(issuer, holder):
    # A caller's policy cannot re-point the nested KB-JWT at another exchange: the
    # presentation's own audience + nonce are what it must be bound to.
    policy = VerificationPolicy(require_status=False, audience=OTHER_AUD, nonce=OTHER_NONCE)
    elsewhere = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(OTHER_AUD, OTHER_NONCE))])
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _suite_verify(elsewhere, policy=policy)
    here = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))])
    (cred,) = _suite_verify(here, policy=policy).credentials
    assert cred.key_bound is True


@pytest.mark.parametrize("override", [None, (OTHER_AUD, OTHER_NONCE)], ids=["none", "other"])
def test_suite_binding_cannot_be_widened_through_the_kwargs(issuer, holder, override):
    # verify() forwards **credential_verify_kwargs to the cascade; the internal binding
    # is set after them, so passing it cannot switch the check off or re-point it.
    vp = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(OTHER_AUD, OTHER_NONCE))])
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _suite_verify(vp, _kb_binding=override)


def test_suite_require_key_binding_is_now_satisfiable_for_nested(issuer, holder):
    # Requiring key binding on the cascade used to fail for want of an aud/nonce to bind
    # against; the presentation now supplies them, so the requirement is enforceable.
    policy = VerificationPolicy(require_status=False, require_key_binding=True)
    bound = _vp_jwt(holder, [_sd_jwt(issuer, holder, kb=(CLIENT_ID, NONCE))])
    (cred,) = _suite_verify(bound, policy=policy).credentials
    assert cred.key_bound is True
    unbound = _vp_jwt(holder, [_sd_jwt(issuer, holder)])
    with pytest.raises(ClaimsInvalid, match="no KB-JWT present"):
        _suite_verify(unbound, policy=policy)
