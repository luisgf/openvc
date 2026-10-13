"""
tests/test_openid4vp_w3c_holder_binding.py — DCQL ``require_cryptographic_holder_binding``
on the W3C presentation formats (``jwt_vc_json`` / ``ldp_vc``), issue #196.

The flag (OpenID4VP 1.0 §6.1, default **true**) used to be read only on the
``dc+sd-jwt`` lane. On the W3C lanes a VP proved that *someone* signed for this
exchange, and nothing tied that signer to the credentials it carried. A malicious
verifier M that had received a victim's credential could re-wrap it in M's own VP,
correctly bound to an honest verifier, and the response verified: a stripped SD-JWT
(KB-JWT dropped, ``key_bound=False``), a VC-JWT or a Data Integrity VC issued to the
victim.

The semantics pinned here, when the query requires cryptographic holder binding:

* a nested **SD-JWT VC** (bare or enveloped) must carry a KB-JWT bound to this exchange
  (``key_bound=True``) — the VP signer never stands in for the ``cnf`` key;
* every other embedded credential (**VC-JWT**, **Data Integrity**) must name the
  **authenticated** VP signer as its subject;

or the whole response is rejected. With the flag ``false`` the lanes accept what they
did before (a nested KB-JWT that *is* present is still bound here, #190), and an
explicit ``require_holder_binding=True`` keeps its stricter meaning.
"""
from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import VpTokenMalformed, _check_holder_bound, verify_vp_token
from openvc.proof._jws import sign_compact
from openvc.proof.di_jcs import EcdsaJcsProofSuite
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import FORMAT_SD_JWT_VC, FORMAT_VC_JWT, VerificationResult

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
M_AUD = "x509_san_dns:malicious.example"        # where the victim presented first
M_NONCE = "m-nonce"
ORIGIN = "https://verifier.example"
VCT = "https://credentials.example.com/identity_credential"

ABSENT = object()                                # the flag left out: default true
REQUIRED = [pytest.param(ABSENT, id="flag-default"), pytest.param(True, id="flag-true")]
LANES = ["jwt_vc_json", "ldp_vc"]

NO_KB = "key binding required but no KB-JWT present"
NOT_HOLDER = "is not the authenticated holder"
SUBJECT_ARRAY = "credentialSubject array"


def _party():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline, and usable
    both as a VP-JWT holder (ES256) and as an ``ecdsa-jcs-2019`` VP signer."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _party()


@pytest.fixture(scope="module")
def victim():
    return _party()


@pytest.fixture(scope="module")
def attacker():
    return _party()


# -- credentials ------------------------------------------------------------- #

def _sd_jwt(issuer, subject, *, kb=None, cnf=True):
    """An SD-JWT VC about *subject*, bound (``cnf``) to its key unless *cnf* is False,
    with a KB-JWT over *kb* = (aud, nonce) signed by that key."""
    issuer_key, issuer_did = issuer
    subject_key, subject_did = subject
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer_did, "given_name": "Ada", "sub": subject_did},
        signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
        holder_jwk=subject_key.public_jwk() if cnf else None)
    if kb is None:
        return issued
    return SdJwtVcProofSuite().create_presentation(
        issued, holder_key=subject_key, audience=kb[0], nonce=kb[1])


def _stripped(issuer, victim):
    """The victim's SD-JWT + KB-JWT (made for M) with the KB-JWT dropped."""
    presented = _sd_jwt(issuer, victim, kb=(M_AUD, M_NONCE))
    return presented.rsplit("~", 1)[0] + "~"


def _vc_jwt(issuer, subject=None, *, credential_subject=None):
    issuer_key, issuer_did = issuer
    cs = credential_subject if credential_subject is not None else (
        {"id": subject} if subject else {"role": "member"})
    return VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer_did,
         "credentialSubject": cs},
        signing_key=issuer_key)


def _di_vc(issuer, subject=None):
    issuer_key, issuer_did = issuer
    cs = {"id": subject, "role": "member"} if subject else {"role": "member"}
    return EcdsaJcsProofSuite().add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer_did,
         "credentialSubject": cs},
        signing_key=issuer_key, verification_method=issuer_key.kid,
        proof_purpose="assertionMethod")


def _raw_jws(signer, payload):
    """A compact JWS over an arbitrary *payload*, for shapes the suites never sign."""
    signer_key, _ = signer
    return sign_compact({"alg": signer_key.alg, "typ": "JWT", "kid": signer_key.kid},
                        payload, signing_key=signer_key)


def _raw_vp_jwt(signer, vp):
    now = int(time.time())
    return _raw_jws(signer, {"iss": signer[1], "aud": CLIENT_ID, "nonce": NONCE,
                             "iat": now, "nbf": now, "exp": now + 300, "vp": vp})


def _enveloped(sd_jwt):
    return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
            "id": f"data:application/dc+sd-jwt,{sd_jwt}"}


def _double_enveloped(sd_jwt):
    b64 = base64.b64encode(json.dumps(_enveloped(sd_jwt)).encode()).decode()
    return {"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
            "id": f"data:application/vc+ld+json;base64,{b64}"}


# -- presentations ----------------------------------------------------------- #

def _present(lane, signer, entries, *, aud=CLIENT_ID):
    signer_key, signer_did = signer
    if lane == "jwt_vc_json":
        return VpJwtProofSuite().sign(
            list(entries), holder_key=signer_key, audience=aud, nonce=NONCE)
    vp = {"@context": [V2], "type": ["VerifiablePresentation"], "holder": signer_did,
          "verifiableCredential": list(entries)}
    return EcdsaJcsProofSuite().add_proof(
        vp, signing_key=signer_key, verification_method=signer_key.kid,
        proof_purpose="authentication", challenge=NONCE, domain=aud)


def _query(lane, flag=ABSENT):
    q = {"id": "q", "format": lane}
    if flag is not ABSENT:
        q["require_cryptographic_holder_binding"] = flag
    return {"credentials": [q]}


def _verify(lane, vp, flag=ABSENT, **kw):
    kw.setdefault("client_id", CLIENT_ID)
    return verify_vp_token({"q": [vp]}, dcql_query=_query(lane, flag), nonce=NONCE,
                           **kw).for_query("q")[0]


# --------------------------------------------------------------------------- #
# The repro: M re-wraps a victim's credential in its own, correctly bound VP
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("flag", REQUIRED)
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("wrap", [
    pytest.param(lambda s: s, id="bare"),
    pytest.param(_enveloped, id="enveloped"),
    pytest.param(_double_enveloped, id="double-enveloped"),
])
def test_rewrapped_stripped_sd_jwt_rejected(issuer, victim, attacker, lane, flag, wrap):
    vp = _present(lane, attacker, [wrap(_stripped(issuer, victim))])
    with pytest.raises(ClaimsInvalid, match=NO_KB):
        _verify(lane, vp, flag)


@pytest.mark.parametrize("flag", REQUIRED)
@pytest.mark.parametrize("lane", LANES)
def test_rewrapped_vc_jwt_rejected(issuer, victim, attacker, lane, flag):
    vp = _present(lane, attacker, [_vc_jwt(issuer, victim[1])])
    with pytest.raises(ClaimsInvalid, match=NOT_HOLDER):
        _verify(lane, vp, flag)


@pytest.mark.parametrize("flag", REQUIRED)
@pytest.mark.parametrize("lane", LANES)
def test_rewrapped_data_integrity_vc_rejected(issuer, victim, attacker, lane, flag):
    vp = _present(lane, attacker, [_di_vc(issuer, victim[1])])
    with pytest.raises(ClaimsInvalid, match=NOT_HOLDER):
        _verify(lane, vp, flag)


@pytest.mark.parametrize("lane", LANES)
def test_rewrap_rejected_over_the_dc_api(issuer, victim, attacker, lane):
    aud = "origin:" + ORIGIN
    for entry, match in ((_stripped(issuer, victim), NO_KB),
                         (_vc_jwt(issuer, victim[1]), NOT_HOLDER)):
        vp = _present(lane, attacker, [entry], aud=aud)
        with pytest.raises(ClaimsInvalid, match=match):
            _verify(lane, vp, client_id=None, expected_origins=[ORIGIN])


# --------------------------------------------------------------------------- #
# What the binding requires, even from an honest presenter
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("lane", LANES)
def test_vp_signer_never_stands_in_for_the_cnf_key(issuer, victim, lane):
    # The holder signs the VP with the very key the SD-JWT is bound to, but sends no
    # KB-JWT. SD-JWT key binding is the KB-JWT (RFC 9901), so this is not bound.
    vp = _present(lane, victim, [_sd_jwt(issuer, victim)])
    with pytest.raises(ClaimsInvalid, match=NO_KB):
        _verify(lane, vp)


@pytest.mark.parametrize("lane", LANES)
def test_sd_jwt_without_cnf_rejected(issuer, victim, lane):
    # OpenID4VP §B.3: an SD-JWT with no cnf cannot satisfy holder binding.
    vp = _present(lane, victim, [_sd_jwt(issuer, victim, cnf=False)])
    with pytest.raises(ClaimsInvalid, match=NO_KB):
        _verify(lane, vp)
    with_kb = _sd_jwt(issuer, victim, cnf=False, kb=(CLIENT_ID, NONCE))
    with pytest.raises(ClaimsInvalid, match="no cnf.jwk"):
        _verify(lane, _present(lane, victim, [with_kb]))


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("make", [
    pytest.param(lambda i: _vc_jwt(i), id="vc-jwt"),
    pytest.param(lambda i: _di_vc(i), id="data-integrity"),
])
def test_bearer_credential_rejected(issuer, victim, lane, make):
    # No subject id: nothing binds the credential to the presenter.
    with pytest.raises(ClaimsInvalid, match=NOT_HOLDER):
        _verify(lane, _present(lane, victim, [make(issuer)]))


@pytest.mark.parametrize("lane", LANES)
def test_multi_subject_credential_rejected(issuer, victim, lane):
    # A credentialSubject array has no single subject to bind — fail closed, even when
    # the presenter is one of the subjects.
    vc = _vc_jwt(issuer, credential_subject=[{"id": victim[1]}, {"id": "did:example:bob"}])
    with pytest.raises(ClaimsInvalid, match=SUBJECT_ARRAY):
        _verify(lane, _present(lane, victim, [vc]))


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("subjects", [
    pytest.param(["holder", "did:example:bob"], id="holder-and-bob"),
    pytest.param(["did:example:bob"], id="bob-only"),
    pytest.param(["holder"], id="one-element"),
])
def test_subject_array_rejected_even_with_an_issuer_signed_sub(
        issuer, victim, lane, subjects):
    # Review finding (#201): VcJwtProofSuite reports the JWT `sub` as the subject whenever
    # it is a string, and only reconciles it with a credentialSubject *object*. With an
    # array, `sub` = holder satisfied the subject rule even when the array named someone
    # else. Holder binding needs a single subject, so any array fails closed.
    cs = [{"id": victim[1] if s == "holder" else s} for s in subjects]
    vc = _raw_jws(issuer, {"iss": issuer[1], "sub": victim[1], "vc": {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer[1],
        "credentialSubject": cs}})
    with pytest.raises(ClaimsInvalid, match=SUBJECT_ARRAY):
        _verify(lane, _present(lane, victim, [vc]))
    p = _verify(lane, _present(lane, victim, [vc]), False)          # opted out: accepted
    assert p.credentials[0].subject == victim[1]


@pytest.mark.parametrize("flag", [*REQUIRED, pytest.param(False, id="flag-false")])
@pytest.mark.parametrize("vp", [
    pytest.param({"verifiableCredential": []}, id="empty-list"),
    pytest.param({}, id="no-verifiableCredential"),
])
def test_jwt_vc_json_presentation_without_credentials_rejected(attacker, vp, flag):
    # A VP-JWT carrying no credential would meet "every embedded credential is bound"
    # vacuously. #194 (1.28.2) rejects it; pinned here across the flag values too.
    signed = _raw_vp_jwt(attacker, {"@context": [V2], "type": ["VerifiablePresentation"],
                                    **vp})
    with pytest.raises(VpTokenMalformed, match="embeds no verifiableCredential"):
        _verify("jwt_vc_json", signed, flag)


@pytest.mark.parametrize("lane", LANES)
def test_one_unbound_credential_rejects_the_response(issuer, victim, attacker, lane):
    own = _vc_jwt(issuer, victim[1])
    vp = _present(lane, victim, [own, _vc_jwt(issuer, attacker[1])])
    with pytest.raises(ClaimsInvalid, match=NOT_HOLDER):
        _verify(lane, vp)
    vp = _present(lane, victim, [own, _sd_jwt(issuer, victim)])
    with pytest.raises(ClaimsInvalid, match=NO_KB):
        _verify(lane, vp)


@pytest.mark.parametrize("value", [None, "false", "true", 0, 1, [], {}])
@pytest.mark.parametrize("fmt", ["jwt_vc_json", "ldp_vc", "dc+sd-jwt", "mso_mdoc"])
def test_non_boolean_flag_is_malformed(value, fmt):
    # bool(None) / bool(0) would silently opt the query out of holder binding.
    dcql = {"credentials": [{"id": "q", "format": fmt,
                             "require_cryptographic_holder_binding": value}]}
    with pytest.raises(VpTokenMalformed, match="must be a boolean"):
        verify_vp_token({"q": ["x"]}, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID)


def test_non_boolean_flag_on_an_unanswered_query_is_malformed(issuer, victim):
    # Validated with the rest of the query's shape, not only when a lane reads it.
    dcql = {"credentials": [
        {"id": "q", "format": "jwt_vc_json"},
        {"id": "unused", "format": "ldp_vc", "require_cryptographic_holder_binding": None}],
        "credential_sets": [{"options": [["q"], ["unused"]]}]}
    vp = _present("jwt_vc_json", victim, [_vc_jwt(issuer, victim[1])])
    with pytest.raises(VpTokenMalformed, match="must be a boolean"):
        verify_vp_token({"q": [vp]}, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID)


@pytest.mark.parametrize("result, holder, match", [
    # The policy's require_key_binding rejects a KB-less nested SD-JWT first; this is the
    # backstop if a pipeline change ever let one through with key_bound False / None.
    pytest.param(VerificationResult(format=FORMAT_SD_JWT_VC, credential={}, issuer="did:i",
                                    subject="did:h", key_bound=False),
                 "did:h", "no Key Binding JWT", id="sd-jwt-not-key-bound"),
    pytest.param(VerificationResult(format=FORMAT_SD_JWT_VC, credential={}, issuer="did:i",
                                    subject="did:h"),
                 "did:h", "no Key Binding JWT", id="sd-jwt-key-bound-none"),
    # No authenticated holder and no subject must not compare equal (None == None).
    pytest.param(VerificationResult(format=FORMAT_VC_JWT, credential={}, issuer="did:i",
                                    subject=None),
                 None, NOT_HOLDER, id="no-holder-no-subject"),
    # An unforeseen format takes the subject rule, never the SD-JWT one.
    pytest.param(VerificationResult(format="mystery", credential={}, issuer="did:i",
                                    subject="did:x", key_bound=True),
                 "did:h", NOT_HOLDER, id="unknown-format"),
])
def test_binding_backstop_fails_closed(result, holder, match):
    with pytest.raises(ClaimsInvalid, match=match):
        _check_holder_bound("q", [result], holder)


@pytest.mark.parametrize("lane", LANES)
def test_require_holder_binding_is_not_weakened_by_the_flag(issuer, victim, attacker, lane):
    # The query opted out, but the caller's explicit require_holder_binding=True still
    # binds every credential's subject to the signer — SD-JWTs included.
    vp = _present(lane, attacker, [_vc_jwt(issuer, victim[1])])
    with pytest.raises(ClaimsInvalid):
        _verify(lane, vp, False, require_holder_binding=True)
    bound_here = _sd_jwt(issuer, victim, kb=(CLIENT_ID, NONCE))
    with pytest.raises(ClaimsInvalid):
        _verify(lane, _present(lane, attacker, [bound_here]), require_holder_binding=True)


@pytest.mark.parametrize("lane", LANES)
def test_nested_kb_bound_elsewhere_still_rejected_when_opted_out(issuer, victim, lane):
    # Opting out of holder binding does not switch off #190: a KB-JWT that IS present
    # must still be bound to this exchange.
    vp = _present(lane, victim, [_sd_jwt(issuer, victim, kb=(M_AUD, M_NONCE))])
    with pytest.raises(ClaimsInvalid, match="KB-JWT aud does not match"):
        _verify(lane, vp, False)


# --------------------------------------------------------------------------- #
# Positive controls
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("flag", REQUIRED)
@pytest.mark.parametrize("lane", LANES)
def test_credentials_issued_to_the_signer_verify(issuer, victim, lane, flag):
    vp = _present(lane, victim, [_vc_jwt(issuer, victim[1]), _di_vc(issuer, victim[1])])
    p = _verify(lane, vp, flag)
    assert p.holder == victim[1]
    assert [c.subject for c in p.credentials] == [victim[1], victim[1]]


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("wrap", [
    pytest.param(lambda s: s, id="bare"),
    pytest.param(_enveloped, id="enveloped"),
    pytest.param(_double_enveloped, id="double-enveloped"),
])
def test_nested_sd_jwt_with_kb_bound_here_verifies(issuer, victim, lane, wrap):
    vp = _present(lane, victim, [wrap(_sd_jwt(issuer, victim, kb=(CLIENT_ID, NONCE)))])
    (cred,) = _verify(lane, vp).credentials
    assert cred.key_bound is True and cred.subject == victim[1]


@pytest.mark.parametrize("lane", LANES)
def test_nested_kb_jwt_is_the_binding_whoever_signs_the_vp(issuer, victim, attacker, lane):
    # The KB-JWT proves the cnf key holder presented to THIS verifier and nonce — the
    # same guarantee as the dc+sd-jwt lane, so the outer VP signer does not matter.
    vp = _present(lane, attacker, [_sd_jwt(issuer, victim, kb=(CLIENT_ID, NONCE))])
    p = _verify(lane, vp)
    assert p.holder == attacker[1] and p.credentials[0].key_bound is True


@pytest.mark.parametrize("lane", LANES)
def test_dc_api_binding_verifies(issuer, victim, lane):
    aud = "origin:" + ORIGIN
    vp = _present(lane, victim, [_vc_jwt(issuer, victim[1]),
                                 _sd_jwt(issuer, victim, kb=(aud, NONCE))], aud=aud)
    p = _verify(lane, vp, client_id=None, expected_origins=[ORIGIN])
    assert p.holder == victim[1] and p.credentials[1].key_bound is True


@pytest.mark.parametrize("lane", LANES)
def test_query_can_opt_out(issuer, victim, attacker, lane):
    # §5.3 / §14.1.1: with the flag false the verifier accepts that the presenter may
    # not be the subject — the pre-#196 behaviour, now only on request.
    entries = [_stripped(issuer, victim), _vc_jwt(issuer, victim[1]),
               _di_vc(issuer, victim[1]), _vc_jwt(issuer)]
    p = _verify(lane, _present(lane, attacker, entries), False)
    assert p.holder == attacker[1]
    assert p.credentials[0].key_bound is False
    assert [c.subject for c in p.credentials[1:]] == [victim[1], victim[1], None]
