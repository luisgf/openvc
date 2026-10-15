"""
tests/test_openid4vp_bare_w3c_vc.py — a bare W3C Verifiable Credential answers a
``jwt_vc_json`` / ``ldp_vc`` query that opted out of holder binding, issue #204.

OpenID4VP 1.0 §B.1: "If ``require_cryptographic_holder_binding`` is set to true in the
Credential Query, the Wallet MUST return a Verifiable Presentation of a Verifiable
Credential. Otherwise, a Verifiable Credential without Holder Binding MUST be returned."
``verify_vp_token`` used to require a presentation on both W3C lanes, so a verifier that set
the flag to ``false`` (the documented way to accept a bearer ticket, a delegated or a
claims-bound credential, #196) got an error from a conformant wallet.

The rules pinned here, set by the maintainer on 2026-10-15:

* with the flag ``false`` a lane accepts a bare credential **or** a presentation (a VP is
  what it accepted before, so this is purely additive);
* with the flag ``true`` or absent a bare credential is still rejected, on both lanes, and
  never reaches the VP-JWT suite as if it were a presentation;
* the routing is pinned: a bare value under ``jwt_vc_json`` verifies as a VC-JWT and never
  as an SD-JWT or a VP-JWT; under ``ldp_vc`` it is a Data Integrity credential with no
  ``VerifiablePresentation`` type; an ``EnvelopedVerifiableCredential`` is not accepted;
* "bare" is decided fail-closed: for a JWT by its payload claim (``vc`` object, no ``vp``),
  with the JOSE ``typ`` as a cross-check; for a JSON object by its ``type``. Anything
  positively ambiguous is refused, anything that is not positively a credential is left to
  the VP lane and its own typed error;
* the result is ``VerifiedPresentation(holder=None, credentials=(result,))``: nothing
  authenticates a holder, and ``require_holder_binding=True`` cannot be met.

Helpers are self-contained (tests/ is not a package, no cross-import). Every issuer is a
``did:key`` the default resolver answers offline, so a hostile value cannot pass on a
resolution failure, and the assertions name the exact exception class.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import openvc.openid4vp as openid4vp
import openvc.verify as verify_module
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import (
    VpTokenMalformed,
    _check_bare_format,
    _w3c_shape,
    verify_vp_token,
)
from openvc.proof._jws import sign_compact
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite
from openvc.proof.errors import (
    ClaimsInvalid,
    MalformedToken,
    PresentationBindingError,
    ProofPurposeMismatch,
    SignatureInvalid,
)
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import (
    FORMAT_DI_ECDSA_JCS,
    FORMAT_DI_ECDSA_RDFC,
    FORMAT_DI_ECDSA_SD,
    FORMAT_DI_EDDSA,
    FORMAT_DI_EDDSA_JCS,
    FORMAT_ENVELOPED,
    FORMAT_SD_JWT_VC,
    FORMAT_VC_JWT,
    IssuerBindingError,
    VerificationResult,
)

try:
    import pyld  # noqa: F401
    _HAS_PYLD = True
except ImportError:                                    # pragma: no cover
    _HAS_PYLD = False

needs_pyld = pytest.mark.skipif(not _HAS_PYLD, reason="needs the [data-integrity] extra")

V2 = "https://www.w3.org/ns/credentials/v2"
VC_IRI = "https://www.w3.org/2018/credentials#VerifiableCredential"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
ORIGIN = "https://verifier.example"
LANES = ["jwt_vc_json", "ldp_vc"]
ABSENT = object()                                # the flag left out: default true
REQUIRED = [pytest.param(ABSENT, id="flag-absent"), pytest.param(True, id="flag-true")]
REFUSES = "requires cryptographic holder binding"


# -- parties and credentials ------------------------------------------------- #

def _p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)               # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _ed25519():
    key = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + key.public_key_raw())   # multicodec ed25519-pub
    return Ed25519SigningKey(key._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _p256()


@pytest.fixture(scope="module")
def holder():
    return _p256()


@pytest.fixture(scope="module")
def other():
    return _p256()


def _body(issuer, subject=None, *, types=("VerifiableCredential",)):
    cs = {"id": subject, "role": "member"} if subject else {"role": "member"}
    return {"@context": [V2], "type": list(types), "issuer": issuer[1],
            "credentialSubject": cs}


def _vc_jwt(issuer, subject=None):
    return VcJwtProofSuite().sign(_body(issuer, subject), signing_key=issuer[0])


def _di_vc(issuer, subject=None, *, purpose="assertionMethod", types=("VerifiableCredential",),
           suite=None, **extra):
    suite = suite or EcdsaJcsProofSuite()
    return suite.add_proof(
        _body(issuer, subject, types=types), signing_key=issuer[0],
        verification_method=issuer[0].kid, proof_purpose=purpose, **extra)


def _jws(signer, payload, **header):
    """A compact JWS over an arbitrary *payload*; a header value of ``None`` drops it."""
    key, _ = signer
    merged = {"alg": key.alg, "typ": "JWT", "kid": key.kid, **header}
    merged = {k: v for k, v in merged.items() if v is not None}
    return sign_compact(merged, payload, signing_key=key)


def _claims(signer, **extra):
    now = int(time.time())
    return {"iss": signer[1], "iat": now, "nbf": now, **extra}


def _vc_jwt_claims(issuer, subject=None, **extra):
    return _claims(issuer, vc=_body(issuer, subject), **extra)


def _vp_jwt(signer, entries, **header):
    now = int(time.time())
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],
          "verifiableCredential": list(entries), "holder": signer[1]}
    return _jws(signer, {"iss": signer[1], "aud": CLIENT_ID, "nonce": NONCE, "iat": now,
                         "nbf": now, "exp": now + 300, "vp": vp}, **header)


def _ldp_vp(signer, entries, *, domain=CLIENT_ID, challenge=NONCE,
            types=("VerifiablePresentation",)):
    vp = {"@context": [V2], "type": list(types), "holder": signer[1],
          "verifiableCredential": list(entries)}
    return EcdsaJcsProofSuite().add_proof(
        vp, signing_key=signer[0], verification_method=signer[0].kid,
        proof_purpose="authentication", challenge=challenge, domain=domain)


def _bare(lane, issuer, subject=None):
    return _vc_jwt(issuer, subject) if lane == "jwt_vc_json" else _di_vc(issuer, subject)


def _vp(lane, signer, entries):
    return _vp_jwt(signer, entries) if lane == "jwt_vc_json" else _ldp_vp(signer, entries)


# -- verification ------------------------------------------------------------- #

def _query(lane, flag=False, **extra):
    q = {"id": "q", "format": lane, **extra}
    if flag is not ABSENT:
        q["require_cryptographic_holder_binding"] = flag
    return {"credentials": [q]}


def _verify(lane, value, flag=False, query_extra=None, **kw):
    kw.setdefault("client_id", CLIENT_ID)
    return verify_vp_token({"q": [value]}, dcql_query=_query(lane, flag, **(query_extra or {})),
                           nonce=NONCE, **kw).for_query("q")[0]


def _bare_lane_unreachable(monkeypatch):
    """After this, reaching the bare-credential verifier fails the test loudly."""
    def boom(*args, **kwargs):
        raise AssertionError("the bare-credential verifier was reached")
    monkeypatch.setattr(openid4vp, "_verify_bare_w3c_vc", boom)


def _vp_lane_unreachable(monkeypatch):
    """After this, reaching the VP-JWT suite fails the test loudly."""
    def boom(*args, **kwargs):
        raise AssertionError("the VP-JWT suite was reached")
    monkeypatch.setattr(VpJwtProofSuite, "verify", boom)


def _pipeline_unreachable(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("verify_credential was reached")
    monkeypatch.setattr(verify_module, "verify_credential", boom)


# =========================================================================== #
# A. The positive cases: a bare credential with the flag false
# =========================================================================== #

def test_bare_vc_jwt_verifies_under_jwt_vc_json(issuer, holder):
    p = _verify("jwt_vc_json", _vc_jwt(issuer, holder[1]))
    assert p.query_id == "q" and p.format == "jwt_vc_json"
    assert p.holder is None                          # nothing authenticates a holder
    (cred,) = p.credentials
    assert cred.format == FORMAT_VC_JWT
    assert cred.issuer == issuer[1] and cred.subject == holder[1]
    assert cred.key_bound is None
    assert p.raw is cred.raw                         # the suite's own result, as dc+sd-jwt


@pytest.mark.parametrize("make, fmt", [
    pytest.param(lambda i: _di_vc(i, "did:example:alice"), FORMAT_DI_ECDSA_JCS, id="ecdsa-jcs"),
    pytest.param(lambda i: _di_vc(i, "did:example:alice", suite=EddsaJcsProofSuite()),
                 FORMAT_DI_EDDSA_JCS, id="eddsa-jcs"),
])
def test_bare_data_integrity_vc_verifies_under_ldp_vc(make, fmt):
    ed = fmt == FORMAT_DI_EDDSA_JCS
    signer = _ed25519() if ed else _p256()
    p = _verify("ldp_vc", make(signer))
    assert p.format == "ldp_vc" and p.holder is None
    (cred,) = p.credentials
    assert cred.format == fmt and cred.issuer == signer[1]
    assert cred.subject == "did:example:alice"
    assert p.raw is cred.raw


@needs_pyld
def test_bare_rdfc_data_integrity_vc_verifies_under_ldp_vc(issuer):
    from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
    vc = EcdsaRdfcProofSuite().add_proof(      # the RDF suites accept only terms a context defines
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer[1],
         "credentialSubject": {"id": "did:example:alice"}},
        signing_key=issuer[0], verification_method=issuer[0].kid,
        proof_purpose="assertionMethod")
    p = _verify("ldp_vc", vc)
    assert p.credentials[0].format == FORMAT_DI_ECDSA_RDFC and p.holder is None


@needs_pyld
def test_a_bare_selectively_disclosed_credential_verifies(issuer):
    # ecdsa-sd-2023 is no holder-proof suite (it is excluded from the presentation lane), but
    # a derived credential is exactly what a wallet may return when binding is waived.
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        {"@context": [V2, {"@vocab": "https://vocab.example/"}],
         "type": ["VerifiableCredential"], "issuer": issuer[1],
         "validFrom": "2026-01-01T00:00:00Z",
         "credentialSubject": {"id": "did:example:subject", "name": "Ada Lovelace",
                               "birthDate": "1815-12-10"}},
        signing_key=issuer[0], verification_method=issuer[0].kid,
        mandatory_pointers=["/issuer", "/validFrom"])
    derived = suite.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    p = _verify("ldp_vc", derived)
    (cred,) = p.credentials
    assert cred.format == FORMAT_DI_ECDSA_SD and p.holder is None
    assert cred.credential["credentialSubject"]["name"] == "Ada Lovelace"
    assert "birthDate" not in cred.credential["credentialSubject"]


@pytest.mark.parametrize("lane", LANES)
def test_a_bearer_bare_credential_verifies(issuer, lane):
    # No subject id at all: the use case of the opt-out (a ticket).
    p = _verify(lane, _bare(lane, issuer))
    assert p.credentials[0].subject is None and p.holder is None


@pytest.mark.parametrize("lane", LANES)
def test_a_presentation_is_still_accepted_with_the_flag_false(issuer, holder, other, lane):
    # Purely additive: the VP shape verified before and verifies now, bound to its signer,
    # and still carries another party's credential (§14.1.1).
    p = _verify(lane, _vp(lane, holder, [_bare(lane, issuer, other[1])]))
    assert p.holder == holder[1]
    assert p.credentials[0].subject == other[1]


@pytest.mark.parametrize("lane", LANES)
def test_bare_credential_and_presentation_share_a_multiple_query(issuer, holder, lane):
    dcql = _query(lane, False, multiple=True)
    token = {"q": [_bare(lane, issuer, holder[1]), _vp(lane, holder, [_bare(lane, issuer)])]}
    ps = verify_vp_token(token, dcql_query=dcql, nonce=NONCE, client_id=CLIENT_ID).presentations
    assert [p.holder for p in ps] == [None, holder[1]]


@pytest.mark.parametrize("typ", [
    pytest.param("JWT", id="JWT"), pytest.param(None, id="no-typ"),
    pytest.param("vc+jwt", id="vc+jwt"), pytest.param("application/vc+jwt", id="application/"),
    pytest.param("VC+JWT", id="case"), pytest.param("example+jwt", id="unknown"),
    pytest.param(7, id="non-string"),
])
def test_the_typ_of_a_bare_vc_jwt_is_a_cross_check_only(issuer, typ):
    # VC-JOSE-COSE says SHOULD vc+jwt, and openvc itself signs JWT: not the signal.
    token = _jws(issuer, _vc_jwt_claims(issuer), typ=typ)
    assert _verify("jwt_vc_json", token).credentials[0].format == FORMAT_VC_JWT


# -- the Digital Credentials API ----------------------------------------------- #

@pytest.mark.parametrize("lane", LANES)
def test_a_bare_credential_verifies_over_the_dc_api(issuer, lane):
    # A bare credential carries no aud / domain to match an origin against, so the shape
    # must be decided before the audience is read.
    p = _verify(lane, _bare(lane, issuer, "did:example:alice"),
                client_id=None, expected_origins=[ORIGIN])
    assert p.holder is None and p.credentials[0].subject == "did:example:alice"


@pytest.mark.parametrize("flag", REQUIRED)
@pytest.mark.parametrize("lane", LANES)
def test_a_bare_credential_is_rejected_over_the_dc_api_when_binding_is_required(
        issuer, lane, flag):
    with pytest.raises(VpTokenMalformed, match=REFUSES):
        _verify(lane, _bare(lane, issuer), flag, client_id=None, expected_origins=[ORIGIN])


@pytest.mark.parametrize("lane", LANES)
def test_a_presentation_over_the_dc_api_still_needs_its_origin(issuer, holder, lane):
    # The VP route is unchanged: its audience is read, and must be one of the origins.
    with pytest.raises(ClaimsInvalid, match="not one of the expected origins"):
        _verify(lane, _vp(lane, holder, [_bare(lane, issuer)]),
                client_id=None, expected_origins=[ORIGIN])


# =========================================================================== #
# B. With the flag true or absent, a bare credential stays rejected
# =========================================================================== #

@pytest.mark.parametrize("flag", REQUIRED)
@pytest.mark.parametrize("lane", LANES)
def test_a_bare_credential_is_rejected_when_holder_binding_is_required(
        issuer, holder, lane, flag, monkeypatch):
    # Whoever holds a copy of a bound credential could replay it: refused, with an error
    # that names the flag, and (for a JWT) without ever reaching the VP-JWT suite, which
    # used to fail it on the missing `aud` instead.
    _vp_lane_unreachable(monkeypatch)
    _bare_lane_unreachable(monkeypatch)
    with pytest.raises(VpTokenMalformed, match=REFUSES) as info:
        _verify(lane, _bare(lane, issuer, holder[1]), flag)
    assert type(info.value) is VpTokenMalformed


@pytest.mark.parametrize("flag", REQUIRED)
def test_a_bare_credential_is_not_verified_before_it_is_refused(issuer, flag, monkeypatch):
    _pipeline_unreachable(monkeypatch)
    with pytest.raises(VpTokenMalformed, match=REFUSES):
        _verify("jwt_vc_json", _vc_jwt(issuer), flag)


# =========================================================================== #
# C. Routing: nothing is verified as the wrong kind
# =========================================================================== #

def _sd_jwt_with_kb(issuer, holder):
    issued = SdJwtVcProofSuite().issue(
        {"iss": issuer[1], "given_name": "Ada", "sub": holder[1]}, signing_key=issuer[0],
        vct="https://credentials.example.com/identity_credential",
        disclosable=["given_name"], holder_jwk=holder[0].public_jwk())
    return SdJwtVcProofSuite().create_presentation(
        issued, holder_key=holder[0], audience=CLIENT_ID, nonce=NONCE)


@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_a_bare_sd_jwt_is_not_routed_under_jwt_vc_json(issuer, holder, flag, monkeypatch):
    _bare_lane_unreachable(monkeypatch)
    _pipeline_unreachable(monkeypatch)
    for token in (_sd_jwt_with_kb(issuer, holder),
                  _jws(issuer, _vc_jwt_claims(issuer), typ="dc+sd-jwt") + "~"):
        with pytest.raises(MalformedToken, match="not a valid compact JWS") as info:
            _verify("jwt_vc_json", token, flag)
        assert type(info.value) is MalformedToken


@pytest.mark.parametrize("claims, match", [
    pytest.param({"vc": {"_sd": ["x"]}}, "SD-JWT markers", id="marker-in-vc"),
    pytest.param({"_sd_alg": "sha-256"}, "SD-JWT markers", id="sd-alg"),
])
def test_a_tail_dropped_sd_jwt_issuer_jwt_is_not_a_bare_vc_jwt(issuer, claims, match):
    # Its `~` tail dropped, an SD-JWT issuer JWT with a `vc` object reaches the bare
    # route; the VC-JWT lane's own fence (#189, #291) still refuses it before the signature.
    body = _body(issuer)
    payload = _claims(issuer, vc={**body, **claims.get("vc", {})},
                      **{k: v for k, v in claims.items() if k != "vc"})
    with pytest.raises(MalformedToken, match=match) as info:
        _verify("jwt_vc_json", _jws(issuer, payload, typ=None))
    assert type(info.value) is MalformedToken
    typed = _jws(issuer, _vc_jwt_claims(issuer), typ="dc+sd-jwt")
    with pytest.raises(MalformedToken, match="is not a VC-JWT") as info:
        _verify("jwt_vc_json", typed)
    assert type(info.value) is MalformedToken


def test_the_documented_sd_jwt_residual_reaches_the_bare_route(issuer, holder):
    # THE RESIDUAL OF #291, pinned, not fixed. A zero-disclosure SD-JWT issuer JWT with no
    # `typ`, a `vc` object and a `cnf` carries none of the SD-JWT markers, so nothing tells
    # it from a VC-JWT that carries a `cnf`, and the VC-JWT lane never enforces `cnf`. With
    # its `~` tail dropped it used to die on the missing `aud` under jwt_vc_json; with the
    # flag false it now verifies as a bare VC-JWT: format `vc-jwt`, `key_bound` None,
    # `holder` None. The query waived the binding it lacks, as `dc+sd-jwt` already allows,
    # and it takes an issuer who signed the hybrid. Whoever closes the gap changes this test.
    claims = _vc_jwt_claims(issuer, holder[1], cnf={"jwk": holder[0].public_jwk()})
    token = _jws(issuer, claims, typ=None)
    p = _verify("jwt_vc_json", token)
    (cred,) = p.credentials
    assert cred.format == FORMAT_VC_JWT and cred.key_bound is None and p.holder is None
    with pytest.raises(VpTokenMalformed, match=REFUSES):          # the default query refuses it
        _verify("jwt_vc_json", token, ABSENT)


@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_a_vp_jwt_is_never_verified_as_a_bare_credential(issuer, holder, flag, monkeypatch):
    # A VP-JWT is routed to the VP lane, whatever the flag, so its aud + nonce still bind.
    _bare_lane_unreachable(monkeypatch)
    assert _verify("jwt_vc_json", _vp_jwt(holder, [_vc_jwt(issuer, holder[1])]),
                   flag).holder == holder[1]


@pytest.mark.parametrize("lane", LANES)
def test_a_presentation_keeps_its_binding_with_the_flag_false(issuer, holder, lane):
    # Opting out of holder binding is not opting out of the request binding: a VP bound
    # to another exchange is rejected, so a wrong-nonce VP cannot ride in as "bare".
    if lane == "jwt_vc_json":
        now = int(time.time())
        vp = {"@context": [V2], "type": ["VerifiablePresentation"],
              "verifiableCredential": [_vc_jwt(issuer)]}
        stale = _jws(holder, {"iss": holder[1], "aud": CLIENT_ID, "nonce": "other", "iat": now,
                              "nbf": now, "vp": vp})
        expected = ClaimsInvalid
    else:
        stale = _ldp_vp(holder, [_di_vc(issuer)], challenge="other")
        expected = PresentationBindingError
    with pytest.raises(expected) as info:
        _verify(lane, stale)
    assert type(info.value) is expected


def test_a_vp_typed_object_is_not_a_bare_credential(issuer, holder, monkeypatch):
    # No proof at all: it fails as a presentation, never as a credential.
    _bare_lane_unreachable(monkeypatch)
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],
          "verifiableCredential": [_vc_jwt(issuer)]}
    with pytest.raises(VpTokenMalformed, match="no Data Integrity holder proof") as info:
        _verify("ldp_vc", vp)
    assert type(info.value) is VpTokenMalformed


def test_a_vp_proof_on_a_vc_typed_object_is_not_accepted_as_a_credential(issuer):
    # A credential-typed object whose proof is an `authentication` (presentation) proof
    # is routed bare and held to the credential's `assertionMethod` purpose.
    with pytest.raises(ProofPurposeMismatch, match="authentication"):
        _verify("ldp_vc", _di_vc(issuer, purpose="authentication", challenge=NONCE,
                                 domain=CLIENT_ID))


@pytest.mark.parametrize("lane", LANES)
def test_each_lane_keeps_to_its_own_encoding(issuer, lane):
    # A VC-JWT is not an ldp_vc answer and a Data Integrity object is not a jwt_vc_json one.
    wrong = _bare("ldp_vc" if lane == "jwt_vc_json" else "jwt_vc_json", issuer)
    with pytest.raises(VpTokenMalformed, match="must be a (JSON object|compact JWT string)"):
        _verify(lane, wrong)


@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_an_enveloped_credential_is_not_accepted_under_ldp_vc(issuer, flag, monkeypatch):
    # Not mentioned for these formats in OpenID4VP §B.1: left out of this change.
    _bare_lane_unreachable(monkeypatch)
    inner = _vc_jwt(issuer)
    for types in (["EnvelopedVerifiableCredential"],
                  ["VerifiableCredential", "EnvelopedVerifiableCredential"]):
        env = {"@context": [V2], "type": types, "id": f"data:application/vc+jwt,{inner}"}
        with pytest.raises(VpTokenMalformed, match="EnvelopedVerifiableCredential") as info:
            _verify("ldp_vc", env, flag)
        assert type(info.value) is VpTokenMalformed


# =========================================================================== #
# D. Fail-closed detection: ambiguity is refused
# =========================================================================== #

@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_a_jwt_carrying_both_vp_and_vc_is_refused(issuer, holder, flag):
    # A well-formed, correctly bound VP-JWT with a stray top-level `vc` verified before
    # (the VP suite ignores it). It is now refused: this layer does not guess which it is.
    now = int(time.time())
    vp = {"@context": [V2], "type": ["VerifiablePresentation"],
          "verifiableCredential": [_vc_jwt(issuer, holder[1])]}
    both = _jws(holder, {"iss": holder[1], "aud": CLIENT_ID, "nonce": NONCE, "iat": now,
                         "nbf": now, "vp": vp, "vc": _body(issuer, holder[1])})
    with pytest.raises(VpTokenMalformed, match="both a `vp` and a `vc` claim") as info:
        _verify("jwt_vc_json", both, flag)
    assert type(info.value) is VpTokenMalformed


@pytest.mark.parametrize("typ", ["vp+jwt", "application/vp+jwt", "VP+JWT"])
def test_a_vc_claim_typed_as_a_presentation_is_refused(issuer, typ):
    with pytest.raises(VpTokenMalformed, match="but carries a `vc` claim") as info:
        _verify("jwt_vc_json", _jws(issuer, _vc_jwt_claims(issuer), typ=typ))
    assert type(info.value) is VpTokenMalformed


@pytest.mark.parametrize("typ", ["vc+jwt", "application/vc+jwt", "VC+JWT"])
@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_a_vp_claim_typed_as_a_credential_is_refused(issuer, holder, typ, flag):
    with pytest.raises(VpTokenMalformed, match="but carries a `vp` claim") as info:
        _verify("jwt_vc_json", _vp_jwt(holder, [_vc_jwt(issuer)], typ=typ), flag)
    assert type(info.value) is VpTokenMalformed


def test_a_matching_presentation_typ_is_accepted(issuer, holder):
    for typ in ("vp+jwt", "application/vp+jwt", "JWT"):
        token = _vp_jwt(holder, [_vc_jwt(issuer, holder[1])], typ=typ)
        assert _verify("jwt_vc_json", token).holder == holder[1]


@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_a_data_integrity_object_typed_both_is_refused(issuer, holder, flag):
    # Correctly signed as a credential, and also typed a presentation: ambiguous. So is a
    # correctly bound presentation that is also typed a credential, which verified as a VP
    # before: the VP lane ignored the extra type.
    types = ("VerifiableCredential", "VerifiablePresentation")
    for both in (_di_vc(issuer, types=types),
                 _ldp_vp(holder, [_di_vc(issuer)], types=types)):
        with pytest.raises(VpTokenMalformed, match="typed both VerifiablePresentation") as info:
            _verify("ldp_vc", both, flag)
        assert type(info.value) is VpTokenMalformed


@pytest.mark.parametrize("make", [
    pytest.param(lambda i, p: {k: v for k, v in _di_vc(i).items() if k != "proof"}, id="no-proof"),
    pytest.param(lambda i, p: {**_di_vc(i), "proof": [_di_vc(i)["proof"]] * 2}, id="two-proofs"),
])
def test_a_bare_data_integrity_credential_needs_exactly_one_proof(issuer, holder, make):
    from openvc.verify import UnknownCredentialFormat
    with pytest.raises(UnknownCredentialFormat) as info:
        _verify("ldp_vc", make(issuer, holder))
    assert type(info.value) is UnknownCredentialFormat


# What is NOT positively a credential is left to the VP lane, whose errors are unchanged.

@pytest.mark.parametrize("flag", [False, *REQUIRED])
@pytest.mark.parametrize("token", [
    pytest.param("not-a-jwt", id="garbage"),
    pytest.param("a.b.c", id="not-base64-json"),
    pytest.param("é.é.é", id="non-ascii"),
    pytest.param("\ud800.\ud800.\ud800", id="lone-surrogate"),
    pytest.param("e30.W10.AAAA", id="array-payload"),
    pytest.param("e30." + "W" * 3 + "." + "A" * 4, id="not-json"),
])
def test_what_does_not_parse_is_left_to_the_vp_lane(token, flag, monkeypatch):
    _bare_lane_unreachable(monkeypatch)
    with pytest.raises(MalformedToken) as info:
        _verify("jwt_vc_json", token, flag)
    assert type(info.value) is MalformedToken


@pytest.mark.parametrize("flag", [False, *REQUIRED])
def test_a_token_with_more_than_three_segments_is_left_to_the_vp_lane(
        issuer, flag, monkeypatch):
    # The first two segments of a correct VC-JWT parse, the string is still no compact JWS.
    _bare_lane_unreachable(monkeypatch)
    with pytest.raises(MalformedToken) as info:
        _verify("jwt_vc_json", _vc_jwt(issuer) + ".AAAA", flag)
    assert type(info.value) is MalformedToken


def test_a_hostile_deep_payload_is_left_to_the_vp_lane(monkeypatch):
    import base64
    _bare_lane_unreachable(monkeypatch)
    seg = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()    # noqa: E731
    deep = seg(b"[" * 300 + b"]" * 300)
    with pytest.raises(MalformedToken) as info:
        _verify("jwt_vc_json", f"{seg(b'{}')}.{deep}.AAAA")
    assert type(info.value) is MalformedToken


@pytest.mark.parametrize("claims", [
    pytest.param({}, id="neither-claim"),
    pytest.param({"vc": "x"}, id="vc-is-a-string"),
    pytest.param({"vc": ["x"]}, id="vc-is-an-array"),
    pytest.param({"vc": None}, id="vc-is-null"),
])
def test_a_jwt_without_a_vc_object_is_left_to_the_vp_lane(issuer, claims, monkeypatch):
    _bare_lane_unreachable(monkeypatch)
    with pytest.raises(ClaimsInvalid, match="aud None != expected verifier") as info:
        _verify("jwt_vc_json", _jws(issuer, _claims(issuer, **claims)))
    assert type(info.value) is ClaimsInvalid


@pytest.mark.parametrize("value", [
    pytest.param(7, id="number"), pytest.param(None, id="null"), pytest.param([], id="array"),
    pytest.param({"type": []}, id="empty-type"),
    pytest.param({"type": "Other"}, id="other-type"),
    pytest.param({"type": {"VerifiableCredential": 1}}, id="type-is-an-object"),
])
def test_a_non_credential_object_is_left_to_the_ldp_lane(value, monkeypatch):
    _bare_lane_unreachable(monkeypatch)
    with pytest.raises(VpTokenMalformed, match="must be a") as info:
        _verify("ldp_vc", value)
    assert type(info.value) is VpTokenMalformed


@pytest.mark.parametrize("fmt, value, shape", [
    ("jwt_vc_json", None, "vp"),
    ("ldp_vc", None, "vp"),
    ("ldp_vc", {"type": "VerifiableCredential"}, "vc"),            # a bare string type
    ("ldp_vc", {"type": ["VerifiableCredential", "Other"]}, "vc"),
    ("ldp_vc", {"type": ["VerifiablePresentation"]}, "vp"),
    ("ldp_vc", {"type": "VerifiablePresentation"}, "vp"),
    ("ldp_vc", {"type": ["Other"]}, "vp"),
])
def test_the_shape_table(fmt, value, shape):
    assert _w3c_shape("q", fmt, value) == shape


def test_the_jwt_shape_table(issuer):
    assert _w3c_shape("q", "jwt_vc_json", _vc_jwt(issuer)) == "vc"
    assert _w3c_shape("q", "jwt_vc_json", _vp_jwt(issuer, [])) == "vp"
    assert _w3c_shape("q", "jwt_vc_json", _jws(issuer, _claims(issuer))) == "vp"


# =========================================================================== #
# E. The bare credential is verified in full, as it is anywhere else
# =========================================================================== #

def _tampered_vc_jwt(issuer):
    import base64
    import json
    head, payload, sig = _vc_jwt(issuer, "did:example:alice").split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["vc"]["credentialSubject"]["role"] = "admin"
    forged = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
    return f"{head}.{forged.rstrip(b'=').decode()}.{sig}"


def test_a_tampered_bare_vc_jwt_fails_closed(issuer):
    with pytest.raises(SignatureInvalid) as info:
        _verify("jwt_vc_json", _tampered_vc_jwt(issuer))
    assert type(info.value) is SignatureInvalid


def test_a_bare_vc_jwt_signed_by_another_key_fails_closed(issuer, other):
    # `iss` names the issuer; the signature is the attacker's.
    token = _jws(other, _vc_jwt_claims(issuer), kid=issuer[0].kid)
    with pytest.raises(SignatureInvalid) as info:
        _verify("jwt_vc_json", token)
    assert type(info.value) is SignatureInvalid


def test_a_tampered_bare_data_integrity_credential_fails_closed(issuer):
    forged = _di_vc(issuer, "did:example:alice")
    forged["credentialSubject"] = {**forged["credentialSubject"], "role": "admin"}
    with pytest.raises(SignatureInvalid) as info:
        _verify("ldp_vc", forged)
    assert type(info.value) is SignatureInvalid


def test_a_bare_data_integrity_credential_is_bound_to_its_issuer(issuer, other):
    # Signed by `other`, naming `issuer`: the pipeline's issuer binding still applies.
    forged = EcdsaJcsProofSuite().add_proof(
        _body(issuer), signing_key=other[0], verification_method=other[0].kid,
        proof_purpose="assertionMethod")
    with pytest.raises(IssuerBindingError) as info:
        _verify("ldp_vc", forged)
    assert type(info.value) is IssuerBindingError


def test_an_expired_bare_vc_jwt_is_rejected(issuer):
    now = int(time.time())
    token = _jws(issuer, _vc_jwt_claims(issuer, exp=now - 500, iat=now - 1000, nbf=now - 1000))
    with pytest.raises(ClaimsInvalid, match="expired") as info:
        _verify("jwt_vc_json", token)
    assert type(info.value) is ClaimsInvalid


def test_a_bare_vc_jwt_restricted_to_an_audience_is_rejected(issuer):
    # RFC 7519 §4.1.3: a bare credential names no verifier, so none can identify itself in
    # a present `aud`. Fail closed rather than accept what is addressed to someone else.
    for aud in ("https://other.example", CLIENT_ID, [CLIENT_ID]):
        with pytest.raises(ClaimsInvalid, match="restricted to an audience") as info:
            _verify("jwt_vc_json", _jws(issuer, _vc_jwt_claims(issuer, aud=aud)))
        assert type(info.value) is ClaimsInvalid


def test_a_nonce_in_a_bare_vc_jwt_is_not_a_binding(issuer):
    # Nothing is bound to this exchange, and the response carries no nonce (§5.3): a
    # `nonce` claim is not read, matching or not.
    for nonce in (NONCE, "other"):
        _verify("jwt_vc_json", _jws(issuer, _vc_jwt_claims(issuer, nonce=nonce)))


@pytest.mark.parametrize("lane", LANES)
def test_require_holder_binding_cannot_be_met_by_a_bare_credential(issuer, holder, lane):
    # The caller's stricter switch ignores the query: every credential's subject must be
    # the authenticated holder, and a bare credential has none.
    with pytest.raises(ClaimsInvalid, match="cannot meet require_holder_binding") as info:
        _verify(lane, _bare(lane, issuer, holder[1]), require_holder_binding=True)
    assert type(info.value) is ClaimsInvalid
    assert _verify(lane, _bare(lane, issuer, holder[1])).holder is None     # the control


@pytest.mark.parametrize("lane", LANES)
def test_a_presentation_still_meets_require_holder_binding(issuer, holder, lane):
    p = _verify(lane, _vp(lane, holder, [_bare(lane, issuer, holder[1])]),
                require_holder_binding=True)
    assert p.holder == holder[1]


def test_status_is_checked_for_a_bare_credential(issuer):
    # The policy reaches the pipeline: a declared status with no resolver is rejected when
    # require_status is set, as for an embedded credential.
    from openvc.verify import StatusUnavailable
    body = {**_body(issuer), "credentialStatus": {
        "id": "https://status.example/1#5", "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation", "statusListIndex": "5",
        "statusListCredential": "https://status.example/1"}}
    token = VcJwtProofSuite().sign(body, signing_key=issuer[0])
    with pytest.raises(StatusUnavailable):
        _verify("jwt_vc_json", token, require_status=True)
    assert _verify("jwt_vc_json", token).credentials[0].status is None     # skipped by default


# -- meta.type_values --------------------------------------------------------- #

@needs_pyld
@pytest.mark.parametrize("lane", LANES)
def test_type_values_apply_to_a_bare_credential(issuer, lane):
    token = _bare(lane, issuer)
    assert _verify(lane, token, query_extra={"meta": {"type_values": [[VC_IRI]]}}).holder is None
    with pytest.raises(ClaimsInvalid, match="none of the requested type_values") as info:
        _verify(lane, token, query_extra={"meta": {"type_values": [["https://x.example#T"]]}})
    assert type(info.value) is ClaimsInvalid


# =========================================================================== #
# F. The format pin is a backstop
# =========================================================================== #

def _result(fmt):
    return VerificationResult(format=fmt, credential={}, issuer="did:i", subject=None)


@pytest.mark.parametrize("fmt, accepted", [
    ("jwt_vc_json", [FORMAT_VC_JWT]),
    ("ldp_vc", [FORMAT_DI_EDDSA, FORMAT_DI_EDDSA_JCS, FORMAT_DI_ECDSA_RDFC,
                FORMAT_DI_ECDSA_JCS, FORMAT_DI_ECDSA_SD]),
])
def test_the_format_pin_accepts_only_its_own_formats(fmt, accepted):
    every = [FORMAT_VC_JWT, FORMAT_SD_JWT_VC, FORMAT_ENVELOPED, FORMAT_DI_EDDSA,
             FORMAT_DI_EDDSA_JCS, FORMAT_DI_ECDSA_RDFC, FORMAT_DI_ECDSA_JCS,
             FORMAT_DI_ECDSA_SD, "mystery"]
    for candidate in every:
        if candidate in accepted:
            _check_bare_format("q", fmt, _result(candidate))
        else:
            with pytest.raises(VpTokenMalformed, match="did not verify as a") as info:
                _check_bare_format("q", fmt, _result(candidate))
            assert type(info.value) is VpTokenMalformed
