"""
tests/test_openid4vci.py — OpenID4VCI 1.0 key-proof verification (issue #141).

Pins the App. F.1 contract and, above all, the adversarial corpus ADR-0007 D5 names:

  * the `typ` pin — a KB-JWT / VP-JWT / status-list token must not be replayable as a
    key proof;
  * the alg allow-list *before* any crypto, and the (kty, crv) binding between the
    header alg and the key it points at;
  * **exactly one** of jwk/kid/x5c/trust_chain — two present is a key-substitution
    vector, zero means there is no key;
  * `aud` bound to this Credential Issuer, multi-valued rejected;
  * `iat` freshness in BOTH directions, including the NaN fail-open trap;
  * the batch invariants that only exist in the plural — one shared nonce, consumed
    exactly once, no two proofs on the same key;
  * nonce replay surfacing as a distinct ProofReplayed;
  * the App. D key-attestation binding (issue #150) — the proof key must be one of the
    attestation's `attested_keys`, no error may escape the module's own taxonomy, and
    the attestation's signature is never checked, which is the point rather than a gap.

Proofs are minted locally with offline keys; wire shapes follow OID4VCI 1.0 §8.2.
"""

import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey, jwk_thumbprint
from openvc.openid4vci import (
    CredentialRequest,
    CredentialRequestMalformed,
    ProofKeyContext,
    ProofReplayed,
    UnsupportedProofType,
    UnverifiedKeyAttestation,
    parse_credential_request,
    peek_key_attestation,
    peek_proof_header,
    verify_credential_request_proofs,
)
from openvc.proof._jws import sign_compact
from openvc.proof.errors import ClaimsInvalid, MalformedToken, UnsupportedAlgorithm

ISSUER = "https://issuer.example"
NONCE = "c-nonce-abc123"
NOW = dt.datetime(2026, 7, 24, 12, 0, tzinfo=dt.timezone.utc)
NOW_TS = int(NOW.timestamp())


# --------------------------------------------------------------------------- helpers #

_UNSET = object()   # distinguishes "not given" from an explicit None/"" under test


def _proof(
    key, *, aud=ISSUER, nonce=NONCE, iat=NOW_TS, typ="openid4vci-proof+jwt",
    alg=_UNSET, key_param="jwk", jwk=None, header_extra=None, claims_extra=None,
):
    header = {"typ": typ, "alg": key.alg if alg is _UNSET else alg}
    if key_param == "jwk":
        header["jwk"] = key.public_jwk() if jwk is None else jwk
    elif key_param == "kid":
        header["kid"] = "wallet-key-1"
    elif key_param is not None:
        header[key_param] = jwk
    header.update(header_extra or {})
    claims = {"aud": aud}
    if iat is not None:
        claims["iat"] = iat
    if nonce is not None:
        claims["nonce"] = nonce
    claims.update(claims_extra or {})
    return sign_compact(header, claims, signing_key=key)


def _attestation(*jwks, typ="key-attestation+jwt", iat=NOW_TS, exp=NOW_TS + 3600,
                 attested_keys=_UNSET, claims_extra=None):
    """A key attestation JWT (App. D), signed by a key nothing will ever look at.

    The signer is a throwaway on purpose: openvc never checks this signature, and a
    test that used the wallet's own key could hide that.
    """
    claims = {"iss": "https://wallet-provider.example"}
    if iat is not None:
        claims["iat"] = iat
    if exp is not None:
        claims["exp"] = exp
    claims["attested_keys"] = (
        [key.public_jwk() if hasattr(key, "public_jwk") else key for key in jwks]
        if attested_keys is _UNSET else attested_keys)
    claims.update(claims_extra or {})
    provider = P256SigningKey.generate(kid="wallet-provider")
    return sign_compact({"typ": typ, "alg": provider.alg}, claims, signing_key=provider)


def _request(*proofs, config_id="UniversityDegree", proof_type="jwt"):
    return {"credential_configuration_id": config_id, "proofs": {proof_type: list(proofs)}}


def _verify(body, **kw):
    kw.setdefault("credential_issuer", ISSUER)
    kw.setdefault("check_nonce", lambda n: True)
    kw.setdefault("now", NOW)
    return verify_credential_request_proofs(body, **kw)


def _cert(subject, issuer, issuer_key, *, ca, subject_key=None, curve=ec.SECP256R1()):
    subject_key = subject_key or ec.generate_private_key(curve)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=365))
        .not_valid_after(NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def _wallet_chain():
    """(x5c list [leaf, inter], root cert, a SigningKey holding the leaf key)."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root, _ = _cert("root", "root", root_key, ca=True, subject_key=root_key)
    inter, inter_key = _cert("inter", "root", root_key, ca=True)
    leaf, leaf_key = _cert("wallet", "inter", inter_key, ca=False)
    der = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii")
           for c in (leaf, inter)]
    return der, root, P256SigningKey(leaf_key, kid="wallet")


# ------------------------------------------------------------------------ happy path #

@pytest.mark.parametrize("factory", [
    lambda: P256SigningKey.generate(kid="w"),
    lambda: P384SigningKey.generate(kid="w"),
    lambda: Ed25519SigningKey.generate(kid="w"),
    lambda: Ed25519SigningKey.generate(kid="w", alg="Ed25519"),
])
def test_a_valid_proof_returns_the_wallet_key(factory):
    key = factory()
    proofs = _verify(_request(_proof(key)))
    assert len(proofs) == 1
    assert proofs[0].public_jwk == key.public_jwk()
    assert proofs[0].thumbprint == jwk_thumbprint(key.public_jwk())
    assert proofs[0].alg == key.alg
    assert proofs[0].key_source == "jwk"
    assert proofs[0].nonce == NONCE
    assert proofs[0].issued_at == NOW_TS


def test_the_returned_key_is_what_sd_jwt_issue_binds_to():
    """The whole point: VerifiedProof.public_jwk feeds straight into issue()."""
    from openvc.proof.sd_jwt import SdJwtVcProofSuite

    wallet = P256SigningKey.generate(kid="w")
    issuer = Ed25519SigningKey.generate(kid=f"{ISSUER}#key-1")
    proof, = _verify(_request(_proof(wallet)))

    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": ISSUER, "given_name": "Ada"}, signing_key=issuer,
        holder_jwk=proof.public_jwk, vct="https://credentials.example/id")
    result = SdJwtVcProofSuite().verify(sd_jwt, public_key_jwk=issuer.public_jwk())
    assert result.confirmation == {"jwk": wallet.public_jwk()}


def test_both_media_type_spellings_of_typ_are_accepted():
    key = P256SigningKey.generate(kid="w")
    assert _verify(_request(_proof(key, typ="application/openid4vci-proof+jwt")))


def test_accepts_a_credential_identifier_instead_of_a_configuration_id():
    key = P256SigningKey.generate(kid="w")
    body = {"credential_identifier": "degree-1", "proofs": {"jwt": [_proof(key)]}}
    assert _verify(body)


def test_a_prevalidated_request_object_can_be_passed_through():
    key = P256SigningKey.generate(kid="w")
    request = parse_credential_request(_request(_proof(key)))
    assert isinstance(request, CredentialRequest)
    assert _verify(request)


# ---------------------------------------------------------------------- the typ pin #

@pytest.mark.parametrize("typ", [
    "kb+jwt",                      # an SD-JWT Key Binding JWT
    "JWT",                         # a plain JWT / ID token
    "statuslist+jwt",              # a status-list token
    "dc+sd-jwt",                   # an SD-JWT VC issuer JWT
    "openid4vci-proof+JWT",        # case games
    "",
    None,
])
def test_a_foreign_typ_is_not_replayable_as_a_key_proof(typ):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="typ must be openid4vci-proof"):
        _verify(_request(_proof(key, typ=typ)))


# ------------------------------------------------------------------- the allow-list #

@pytest.mark.parametrize("alg", ["none", "HS256", "RS256", "PS256", "ES512", "", None])
def test_a_non_allow_listed_alg_is_rejected_before_any_crypto(alg):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(UnsupportedAlgorithm):
        _verify(_request(_proof(key, alg=alg)))


def test_the_allow_list_can_be_narrowed_by_the_caller():
    key = Ed25519SigningKey.generate(kid="w")
    with pytest.raises(UnsupportedAlgorithm):
        _verify(_request(_proof(key)), allowed_algs=frozenset({"ES256"}))


def test_unknown_crit_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(MalformedToken):
        _verify(_request(_proof(key, header_extra={"crit": ["exp"]})))


def test_header_alg_must_bind_to_the_key_it_names():
    """`alg: ES256` over an Ed25519 JWK must die here, not inside the backend."""
    signer = Ed25519SigningKey.generate(kid="w")
    proof = _proof(signer, alg="EdDSA", jwk=signer.public_jwk())
    # Forge the header alg while keeping the Ed25519 key.
    header, payload, sig = proof.split(".")
    forged = base64.urlsafe_b64encode(
        b'{"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":'
        + base64.urlsafe_b64decode(header + "==").split(b'"jwk":')[1]
    ).rstrip(b"=").decode()
    with pytest.raises(ClaimsInvalid, match="needs a kty"):
        _verify(_request(f"{forged}.{payload}.{sig}"))


@pytest.mark.parametrize("bad_jwk", [
    {"kty": "EC", "crv": "P-384", "x": "AA", "y": "BB"},   # right kty, wrong curve
    {"kty": "OKP", "crv": "Ed25519", "x": "AA"},           # wrong kty entirely
    {"kty": "RSA", "n": "AA", "e": "AQAB"},
    {"kty": "EC", "x": "AA", "y": "BB"},                   # no crv at all
    {},
])
def test_es256_over_a_mismatched_key_is_rejected(bad_jwk):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="needs a kty"):
        _verify(_request(_proof(key, jwk=bad_jwk)))


# ------------------------------------------------------------ the key parameter set #

def test_two_key_parameters_are_rejected():
    """A `kid` naming an honest key paired with an attacker's `jwk`."""
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="exactly one of"):
        _verify(_request(_proof(key, header_extra={"kid": "honest-key"})))


def test_no_key_parameter_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="exactly one of"):
        _verify(_request(_proof(key, key_param=None)))


def test_trust_chain_is_typed_not_silently_ignored():
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, key_param="trust_chain", jwk=["chain"])
    with pytest.raises(UnsupportedProofType, match="trust_chain"):
        _verify(_request(proof))


@pytest.mark.parametrize("member", ["d", "k", "p", "q", "dp", "dq", "qi"])
def test_a_jwk_carrying_private_members_is_rejected(member):
    key = P256SigningKey.generate(kid="w")
    leaky = dict(key.public_jwk(), **{member: "c2VjcmV0"})
    with pytest.raises(ClaimsInvalid, match="private members"):
        _verify(_request(_proof(key, jwk=leaky)))


def test_a_non_object_jwk_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="must be an object"):
        _verify(_request(_proof(key, jwk="not-an-object")))


# ---------------------------------------------------------------------------- x5c #

def test_an_anchored_x5c_chain_resolves_the_wallet_key():
    x5c, root, leaf_key = _wallet_chain()
    proof = _proof(leaf_key, key_param="x5c", jwk=x5c)
    verified, = _verify(_request(proof), trust_anchors=[root])
    assert verified.key_source == "x5c"
    assert verified.public_jwk["crv"] == "P-256"


def test_x5c_without_trust_anchors_is_rejected():
    """An unanchored chain is decoration, not trust."""
    x5c, _, leaf_key = _wallet_chain()
    proof = _proof(leaf_key, key_param="x5c", jwk=x5c)
    with pytest.raises(ClaimsInvalid, match="no trust_anchors"):
        _verify(_request(proof))


def test_an_expired_wallet_certificate_is_rejected_against_the_pinned_clock():
    """`now` must reach the chain's validity window, not just the proof's iat —
    otherwise a frozen-clock verification path-validates against the wall clock."""
    from openvc.x5c import X5cError

    x5c, root, leaf_key = _wallet_chain()          # valid NOW-365d .. NOW+365d
    later = NOW + dt.timedelta(days=400)
    proof = _proof(leaf_key, key_param="x5c", jwk=x5c, iat=int(later.timestamp()))
    with pytest.raises(X5cError):
        _verify(_request(proof), trust_anchors=[root], now=later)


def test_an_x5c_chain_to_a_foreign_root_is_rejected():
    from openvc.x5c import X5cError

    x5c, _, leaf_key = _wallet_chain()
    _, other_root, _ = _wallet_chain()
    proof = _proof(leaf_key, key_param="x5c", jwk=x5c)
    with pytest.raises(X5cError):
        _verify(_request(proof), trust_anchors=[other_root])


# ---------------------------------------------------------------------------- kid #

def test_kid_resolves_through_the_injected_callable():
    key = P256SigningKey.generate(kid="w")
    verified, = _verify(
        _request(_proof(key, key_param="kid")),
        resolve_proof_key=lambda kid: key.public_jwk())
    assert verified.key_source == "kid"


def test_kid_without_a_resolver_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="no resolve_proof_key"):
        _verify(_request(_proof(key, key_param="kid")))


def test_a_resolver_returning_a_non_jwk_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="did not return a JWK"):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: "nope")


def test_a_resolver_returning_the_wrong_key_fails_the_signature():
    from openvc.proof.errors import SignatureInvalid

    key = P256SigningKey.generate(kid="w")
    other = P256SigningKey.generate(kid="other")
    with pytest.raises(SignatureInvalid):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: other.public_jwk())


# ---------------------------------------------------------------------- signature #

def test_a_tampered_payload_fails_the_signature():
    from openvc.proof.errors import SignatureInvalid

    key = P256SigningKey.generate(kid="w")
    header, _, sig = _proof(key).split(".")
    forged = base64.urlsafe_b64encode(
        b'{"aud":"%s","iat":%d,"nonce":"%s"}' % (ISSUER.encode(), NOW_TS, b"other")
    ).rstrip(b"=").decode()
    with pytest.raises(SignatureInvalid):
        _verify(_request(f"{header}.{forged}.{sig}"))


@pytest.mark.parametrize("junk", ["a.b", "a.b.c.d", "not-a-jws", "..", "a.b.!!"])
def test_structurally_broken_proofs_are_typed(junk):
    """An empty string is not here: the shape validator rejects it before parsing."""
    with pytest.raises(MalformedToken):
        _verify(_request(junk))


# --------------------------------------------------------------------------- aud #

def test_a_proof_for_another_issuer_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="is not this Credential Issuer"):
        _verify(_request(_proof(key, aud="https://other-issuer.example")))


def test_a_single_element_aud_array_is_accepted():
    key = P256SigningKey.generate(kid="w")
    assert _verify(_request(_proof(key, aud=[ISSUER])))


def test_a_multi_valued_aud_is_rejected_as_a_cross_issuer_replay_vector():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="exactly one audience"):
        _verify(_request(_proof(key, aud=[ISSUER, "https://other.example"])))


@pytest.mark.parametrize("aud", [None, 42, {"a": 1}, []])
def test_a_missing_or_malformed_aud_is_rejected(aud):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid):
        _verify(_request(_proof(key, aud=aud)))


# ------------------------------------------------------------------ iat freshness #

def test_a_stale_proof_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="too old"):
        _verify(_request(_proof(key, iat=NOW_TS - 3600)))


def test_a_future_dated_proof_is_rejected():
    """Without this a wallet signs once with iat=now+10y and never goes stale."""
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="in the future"):
        _verify(_request(_proof(key, iat=NOW_TS + 10 * 365 * 24 * 3600)))


def test_a_missing_iat_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="missing the required iat"):
        _verify(_request(_proof(key, iat=None)))


@pytest.mark.parametrize("iat", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_iat_cannot_make_a_proof_never_stale(iat):
    """json.loads accepts NaN, and every comparison against it is False."""
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="finite numeric"):
        _verify(_request(_proof(key, iat=iat)))


@pytest.mark.parametrize("iat", [True, "1753358400", None])
def test_a_non_numeric_iat_is_rejected(iat):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid):
        _verify(_request(_proof(key, iat=iat)))


def test_leeway_absorbs_modest_clock_skew_in_both_directions():
    key = P256SigningKey.generate(kid="w")
    assert _verify(_request(_proof(key, iat=NOW_TS + 30)), leeway_s=60)
    assert _verify(_request(_proof(key, iat=NOW_TS - 330)), leeway_s=60)


def test_max_age_is_configurable():
    key = P256SigningKey.generate(kid="w")
    assert _verify(_request(_proof(key, iat=NOW_TS - 3600)), max_age_s=7200)


def test_an_expired_proof_is_rejected_through_the_shared_temporal_check():
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, claims_extra={"exp": NOW_TS - 600})
    with pytest.raises(ClaimsInvalid, match="expired"):
        _verify(_request(proof))


# ------------------------------------------------------------------- iss / client #

def test_iss_is_pinned_when_an_expected_client_is_given():
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, claims_extra={"iss": "wallet-client-1"})
    assert _verify(_request(proof), expected_client_id="wallet-client-1")
    with pytest.raises(ClaimsInvalid, match="does not match the authenticated client"):
        _verify(_request(proof), expected_client_id="someone-else")


def test_a_missing_iss_fails_a_pinned_client():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="does not match"):
        _verify(_request(_proof(key)), expected_client_id="wallet-client-1")


# --------------------------------------------------------------- nonce and replay #

def test_the_nonce_is_consumed_exactly_once():
    key = P256SigningKey.generate(kid="w")
    seen = []
    _verify(_request(_proof(key)), check_nonce=lambda n: seen.append(n) or True)
    assert seen == [NONCE]


def test_a_replayed_nonce_raises_the_distinct_error():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ProofReplayed, match="already consumed"):
        _verify(_request(_proof(key)), check_nonce=lambda n: False)


def test_requiring_a_nonce_without_a_store_fails_closed():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="no check_nonce"):
        verify_credential_request_proofs(
            _request(_proof(key)), credential_issuer=ISSUER, now=NOW)


def test_a_missing_nonce_is_rejected_by_default():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="missing the required nonce"):
        _verify(_request(_proof(key, nonce=None)))


def test_nonce_can_be_opted_out_of_explicitly():
    key = P256SigningKey.generate(kid="w")
    verified, = verify_credential_request_proofs(
        _request(_proof(key, nonce=None)), credential_issuer=ISSUER,
        require_nonce=False, now=NOW)
    assert verified.nonce is None


def test_the_store_is_never_called_when_a_signature_fails():
    """Consume-after-verify: garbage must not let an attacker burn nonces."""
    from openvc.proof.errors import SignatureInvalid

    key = P256SigningKey.generate(kid="w")
    other = P256SigningKey.generate(kid="other")
    proof = _proof(key, jwk=other.public_jwk())
    calls = []
    with pytest.raises(SignatureInvalid):
        _verify(_request(proof), check_nonce=lambda n: calls.append(n) or True)
    assert calls == []


@pytest.mark.parametrize("nonce", ["", 42, [], {}])
def test_a_malformed_nonce_claim_is_rejected(nonce):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid):
        _verify(_request(_proof(key, nonce=nonce)))


# ------------------------------------------------------------- batch invariants #

def test_a_batch_is_rejected_unless_the_issuer_advertised_one():
    a, b = P256SigningKey.generate(kid="a"), P256SigningKey.generate(kid="b")
    with pytest.raises(CredentialRequestMalformed, match="batch limit is 1"):
        _verify(_request(_proof(a), _proof(b)))


def test_a_permitted_batch_returns_one_result_per_proof():
    a, b = P256SigningKey.generate(kid="a"), P256SigningKey.generate(kid="b")
    verified = _verify(_request(_proof(a), _proof(b)), batch_size=2)
    assert [v.public_jwk for v in verified] == [a.public_jwk(), b.public_jwk()]


def test_the_nonce_is_still_consumed_only_once_for_a_batch():
    a, b = P256SigningKey.generate(kid="a"), P256SigningKey.generate(kid="b")
    seen = []
    _verify(_request(_proof(a), _proof(b)), batch_size=2,
            check_nonce=lambda n: seen.append(n) or True)
    assert seen == [NONCE]


def test_proofs_with_divergent_nonces_are_rejected():
    a, b = P256SigningKey.generate(kid="a"), P256SigningKey.generate(kid="b")
    with pytest.raises(ClaimsInvalid, match="same nonce"):
        _verify(_request(_proof(a), _proof(b, nonce="other-nonce")), batch_size=2)


def test_two_proofs_on_the_same_key_are_rejected():
    """N credentials must mean N keys, not N copies bound to one."""
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="same key"):
        _verify(_request(_proof(key), _proof(key)), batch_size=2)


def test_one_bad_proof_rejects_the_whole_batch():
    """There is no partial issuance."""
    good, bad = P256SigningKey.generate(kid="a"), P256SigningKey.generate(kid="b")
    with pytest.raises(ClaimsInvalid):
        _verify(_request(_proof(good), _proof(bad, aud="https://other.example")),
                batch_size=2)


# --------------------------------------------------------------- request shape #

def test_proofs_must_carry_exactly_one_proof_type():
    key = P256SigningKey.generate(kid="w")
    body = {"credential_configuration_id": "X",
            "proofs": {"jwt": [_proof(key)], "di_vp": [{}]}}
    with pytest.raises(CredentialRequestMalformed, match="exactly one proof type"):
        _verify(body)


def test_an_unsupported_proof_type_is_typed():
    body = {"credential_configuration_id": "X", "proofs": {"di_vp": ["x"]}}
    with pytest.raises(UnsupportedProofType, match="di_vp"):
        _verify(body)


@pytest.mark.parametrize("body", [
    {"proofs": {"jwt": ["x"]}},                                        # neither id
    {"credential_configuration_id": "X", "credential_identifier": "Y",
     "proofs": {"jwt": ["x"]}},                                        # both ids
    {"credential_configuration_id": "", "proofs": {"jwt": ["x"]}},      # empty id
    {"credential_configuration_id": 42, "proofs": {"jwt": ["x"]}},      # non-string id
])
def test_the_credential_identifier_contract_is_enforced(body):
    with pytest.raises(CredentialRequestMalformed):
        _verify(body)


@pytest.mark.parametrize("proofs", [
    None, {}, {"jwt": []}, {"jwt": "not-an-array"}, {"jwt": [""]}, {"jwt": [42]},
    {"": ["x"]}, "not-an-object",
])
def test_a_malformed_proofs_member_is_rejected(proofs):
    with pytest.raises(CredentialRequestMalformed):
        _verify({"credential_configuration_id": "X", "proofs": proofs})


def test_configuration_ids_can_be_pinned_to_what_the_issuer_offers():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(CredentialRequestMalformed, match="unsupported credential_conf"):
        parse_credential_request(
            _request(_proof(key)), supported_configuration_ids=["SomethingElse"])
    assert parse_credential_request(
        _request(_proof(key)), supported_configuration_ids=["UniversityDegree"])


def test_an_oversized_proof_is_capped_before_parsing():
    body = {"credential_configuration_id": "X", "proofs": {"jwt": ["a" * 20_000]}}
    with pytest.raises(CredentialRequestMalformed, match="exceeds"):
        _verify(body)


def test_a_json_string_body_is_accepted():
    key = P256SigningKey.generate(kid="w")
    import json as _json
    assert _verify(_json.dumps(_request(_proof(key))))


@pytest.mark.parametrize("body", ["not json", "[]", '"a string"', "null", "123"])
def test_a_non_object_body_is_rejected(body):
    with pytest.raises(CredentialRequestMalformed):
        _verify(body)


def test_hostile_deeply_nested_json_fails_closed():
    body = '{"credential_configuration_id":"X","proofs":' + '[' * 5000 + ']' * 5000 + '}'
    with pytest.raises(CredentialRequestMalformed):
        _verify(body)


def test_response_encryption_must_be_an_object_when_present():
    key = P256SigningKey.generate(kid="w")
    body = dict(_request(_proof(key)), credential_response_encryption="nope")
    with pytest.raises(CredentialRequestMalformed, match="must be an object"):
        _verify(body)


# ------------------------------------------------------------- caller contract #

def test_an_empty_credential_issuer_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(CredentialRequestMalformed, match="credential_issuer"):
        _verify(_request(_proof(key)), credential_issuer="")


@pytest.mark.parametrize("kw", [{"max_age_s": -1}, {"leeway_s": -1}])
def test_negative_time_windows_are_rejected(kw):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(CredentialRequestMalformed, match="must not be negative"):
        _verify(_request(_proof(key)), **kw)


def test_a_zero_batch_size_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(CredentialRequestMalformed, match="at least 1"):
        _verify(_request(_proof(key)), batch_size=0)


# ------------------------------------------------------- key attestations (#150) #

def test_key_attestation_is_captured_but_not_verified():
    """The attestation is signed by a key nobody knows, and that is not an error."""
    key = P256SigningKey.generate(kid="w")
    attestation = _attestation(key)
    verified, = _verify(_request(_proof(key, header_extra={"key_attestation": attestation})))
    assert verified.key_attestation == attestation           # verbatim, unverified
    assert peek_key_attestation(verified.key_attestation).attested_keys == (key.public_jwk(),)


def test_a_proof_signed_by_an_attested_key_is_accepted():
    """The form the wallets emit: the signing key is in the header, under a `kid`."""
    key = P256SigningKey.generate(kid="w")
    other = P256SigningKey.generate(kid="other")
    attestation = _attestation(other, key)                   # `kid` is an index here
    proof = _proof(key, key_param=None,
                   header_extra={"kid": "1", "key_attestation": attestation})

    verified, = _verify(
        _request(proof),
        resolve_proof_key_in_context=lambda ctx: ctx.key_attestation.attested_keys[int(ctx.kid)])
    assert verified.key_source == "kid"
    assert verified.public_jwk == key.public_jwk()


@pytest.mark.parametrize("key_param", ["jwk", "kid", "x5c"])
def test_a_proof_signed_by_a_key_absent_from_the_attestation_is_rejected(key_param):
    """App. D's MUST, on every key source — not just the one that reads the header."""
    stranger = P256SigningKey.generate(kid="stranger")
    kw = {}
    if key_param == "x5c":
        x5c, root, key = _wallet_chain()
        proof_kw, kw = {"key_param": "x5c", "jwk": x5c}, {"trust_anchors": [root]}
    else:
        key = P256SigningKey.generate(kid="w")
        proof_kw = {"key_param": key_param}
        if key_param == "kid":
            kw = {"resolve_proof_key": lambda kid: key.public_jwk()}

    attestation = _attestation(stranger)
    proof = _proof(key, header_extra={"key_attestation": attestation}, **proof_kw)
    with pytest.raises(ClaimsInvalid, match="not among the key attestation"):
        _verify(_request(proof), **kw)


def test_a_non_fixed_width_attested_key_is_rejected_and_the_message_says_why():
    """RFC 7638 digests the coordinates as given: same key, other encoding, other hash.

    Non-conformant per RFC 7518 §6.2.1.2, rare enough to pass every test and surface in
    production — so the rejection names the cause instead of just saying "not found".
    """
    key = P256SigningKey.generate(kid="w")
    sloppy = dict(key.public_jwk())
    sloppy["x"] = base64.urlsafe_b64encode(
        b"\x00" + base64.urlsafe_b64decode(sloppy["x"] + "==")).decode().rstrip("=")

    proof = _proof(key, header_extra={"key_attestation": _attestation(sloppy)})
    with pytest.raises(ClaimsInvalid, match="RFC 7518"):
        _verify(_request(proof))


def test_a_non_string_key_attestation_is_rejected_before_the_signature():
    """Structure before crypto: the bad header wins over the bad signature."""
    key, other = P256SigningKey.generate(kid="w"), P256SigningKey.generate(kid="o")
    proof = _proof(key, key_param="jwk", jwk=other.public_jwk(),
                   header_extra={"key_attestation": {"not": "a string"}})
    with pytest.raises(ClaimsInvalid, match="key_attestation header must be a string"):
        _verify(_request(proof))


@pytest.mark.parametrize("attested_keys", [
    None, [], "x", 42, [42], [{}], [{"kty": "EC"}], [{"kty": "XX", "x": "a"}],
])
def test_a_malformed_attestation_never_escapes_the_documented_taxonomy(attested_keys):
    """`InvalidKey` is a key-backend error, not a ProofError — it must not reach out."""
    key = P256SigningKey.generate(kid="w")
    attestation = _attestation(attested_keys=attested_keys)
    proof = _proof(key, header_extra={"key_attestation": attestation})
    with pytest.raises(ClaimsInvalid):
        _verify(_request(proof))


def test_a_key_that_cannot_be_thumbprinted_is_typed_not_leaked():
    """The other half: a resolver's own key can trip RFC 7638 too."""
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="cannot be thumbprinted"):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: {"kty": "EC", "crv": "P-256", "x": 123, "y": "a"})


def test_an_attestation_that_is_not_a_jws_is_a_malformed_token():
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, header_extra={"key_attestation": "ey.unverified.token"})
    with pytest.raises(MalformedToken):
        _verify(_request(proof))


def test_a_key_attestation_is_not_a_key_parameter():
    """`{typ, alg, key_attestation}` is spec-legal and still rejected, deliberately.

    Picking a key out of `attested_keys` means letting an unverified blob say which key
    signed the proof, and App. F.1 fixes no rule for how a `kid` names one.
    """
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, key_param=None,
                   header_extra={"key_attestation": _attestation(key)})
    with pytest.raises(ClaimsInvalid, match="exactly one of"):
        _verify(_request(proof))


# ---------------------------------------------------------- resolver context #

def test_the_context_resolver_sees_the_kid_alg_header_and_parsed_attestation():
    key = P256SigningKey.generate(kid="w")
    attestation = _attestation(key)
    proof = _proof(key, key_param="kid", header_extra={"key_attestation": attestation})
    seen = []

    verified, = _verify(
        _request(proof),
        resolve_proof_key_in_context=lambda ctx: (seen.append(ctx), key.public_jwk())[1])

    ctx, = seen
    assert isinstance(ctx, ProofKeyContext)
    assert (ctx.kid, ctx.alg, ctx.credential_issuer, ctx.index) == (
        "wallet-key-1", "ES256", ISSUER, 0)
    assert ctx.header["key_attestation"] == attestation
    assert isinstance(ctx.key_attestation, UnverifiedKeyAttestation)
    assert ctx.key_attestation.attested_keys == (key.public_jwk(),)
    assert ctx.key_attestation.expires_at == NOW_TS + 3600
    assert verified.public_jwk == key.public_jwk()


def test_the_context_header_cannot_be_edited_by_the_resolver():
    """Otherwise a resolver could delete the attestation it is about to be bound to."""
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, key_param="kid",
                   header_extra={"key_attestation": _attestation(key)})

    def resolve(ctx):
        with pytest.raises(TypeError):
            ctx.header["key_attestation"] = None
        return key.public_jwk()

    assert _verify(_request(proof), resolve_proof_key_in_context=resolve)


def test_the_context_resolver_gets_the_index_of_each_proof_in_the_batch():
    keys = [P256SigningKey.generate(kid=f"w{n}") for n in range(2)]
    request = _request(*(_proof(k, key_param="kid") for k in keys))
    seen = {}

    _verify(request, batch_size=2, resolve_proof_key_in_context=lambda ctx: (
        seen.setdefault(ctx.index, keys[ctx.index].public_jwk())))
    assert sorted(seen) == [0, 1]


def test_a_context_resolver_returning_a_non_jwk_is_rejected():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="resolve_proof_key_in_context did not return"):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key_in_context=lambda ctx: "nope")


def test_passing_both_resolvers_is_a_caller_error():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(CredentialRequestMalformed, match="not both"):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: key.public_jwk(),
                resolve_proof_key_in_context=lambda ctx: key.public_jwk())


def test_the_kid_resolvers_are_named_in_the_fail_closed_message():
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid, match="resolve_proof_key_in_context"):
        _verify(_request(_proof(key, key_param="kid")))


# ------------------------------------------------------------ peek_* doctrine #

def test_peek_proof_header_agrees_with_the_verified_header():
    """One notion of what a header is. A caller's own decoder is a second one."""
    key = P256SigningKey.generate(kid="w")
    proof = _proof(key, header_extra={"key_attestation": _attestation(key)})
    verified, = _verify(_request(proof))
    assert dict(peek_proof_header(proof)) == dict(verified.header)


def test_peek_key_attestation_reads_a_token_whose_signature_is_worthless():
    key = P256SigningKey.generate(kid="w")
    attestation = _attestation(key, claims_extra={
        "key_storage": ["iso_18045_high"], "user_authentication": ["iso_18045_moderate"],
        "certification": "https://wallet-provider.example/cert", "nonce": NONCE,
        "status": {"status_list": {"idx": 3}}})

    peeked = peek_key_attestation(attestation.replace(attestation[-6:], "AAAAAA"))
    assert peeked.attested_keys == (key.public_jwk(),)
    assert peeked.key_storage == ("iso_18045_high",)
    assert peeked.user_authentication == ("iso_18045_moderate",)
    assert peeked.certification == "https://wallet-provider.example/cert"
    assert (peeked.nonce, peeked.issued_at, peeked.expires_at) == (NONCE, NOW_TS, NOW_TS + 3600)
    assert peeked.status == {"status_list": {"idx": 3}}
    assert peeked.header["typ"] == "key-attestation+jwt"


def test_peeked_objects_are_read_only():
    key = P256SigningKey.generate(kid="w")
    peeked = peek_key_attestation(_attestation(key))
    for mapping in (peeked.header, peeked.claims, peeked.attested_keys[0]):
        with pytest.raises(TypeError):
            mapping["injected"] = True


@pytest.mark.parametrize("bad", [
    "not-a-jws", "", 42, None, "a.b.c",
])
def test_peek_key_attestation_fails_closed_on_junk(bad):
    with pytest.raises((MalformedToken, ClaimsInvalid)):
        peek_key_attestation(bad)


@pytest.mark.parametrize("peek", [peek_proof_header, peek_key_attestation])
def test_the_peek_entry_points_are_capped(peek):
    with pytest.raises(MalformedToken, match="exceeds"):
        peek("x" * (16 * 1024 + 1))


@pytest.mark.parametrize("claims_extra", [
    {"key_storage": "iso_18045_high"}, {"key_storage": []}, {"user_authentication": [1]},
    {"certification": 42}, {"nonce": 42}, {"status": "revoked"}, {"iat": "yesterday"},
    {"exp": float("nan")},
])
def test_peek_key_attestation_pins_the_shape_of_every_app_d_member(claims_extra):
    key = P256SigningKey.generate(kid="w")
    with pytest.raises(ClaimsInvalid):
        peek_key_attestation(_attestation(key, claims_extra=claims_extra))


def test_peek_key_attestation_does_not_enforce_a_verifiers_rules():
    """`typ` and `exp` are left on the object, not judged: that is downstream's call."""
    key = P256SigningKey.generate(kid="w")
    peeked = peek_key_attestation(_attestation(key, typ="nonsense+jwt", exp=None))
    assert peeked.header["typ"] == "nonsense+jwt"
    assert peeked.expires_at is None


def test_verified_proof_is_frozen():
    key = P256SigningKey.generate(kid="w")
    verified, = _verify(_request(_proof(key)))
    with pytest.raises(Exception):
        verified.public_jwk = {}
