"""
tests/test_rp_registration.py — EUDI relying-party **registration** certificate
(WRPRC, ETSI TS 119 475 V1.2.1 clause 5.2) parsing, verification and scope cross-checks
(``openvc.rp_registration``, issue #89).

No official *signed* WRPRC vectors exist: the ETSI deliverable ships one informative,
unsigned JSON example (Annex C), the 2026 EAA Plugtests covered TS 119 472-1 rather than
119 475, and CIR (EU) 2025/848 — under whose Art. 8 registration certificates are
*optional per Member State* — only applies from 2026-12-24. So these pin the **Annex C
payload verbatim** and otherwise build WRPRCs in both profiled forms over the library's
own JOSE and COSE machinery. Recording a real third-party artifact stays a separate,
gated follow-up.

The emphasis is the negative space: a token that is not shaped like a WRPRC, one signed
under an algorithm or a chain that was not authorized, one whose scope does not cover
what is being asked for, and the binding hole that would let a valid-but-unrelated
registration be paired with a request.
"""
from __future__ import annotations

import base64
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from openvc import cbor
from openvc.keys import P256SigningKey
from openvc.rp_registration import (
    RpRegistrationError,
    check_matches_access_certificate,
    check_request_within_registration,
    parse_rp_registration_certificate,
    verify_rp_registration_certificate,
)

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_AT = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)        # a pinned evaluation instant
_IAT = int(_AT.timestamp()) - 3600
_EXP = int(_AT.timestamp()) + 86400
ENTITLEMENT = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
REGISTRAR_EKU = "0.4.0.19475.2.1"     # a placeholder registrar EKU (the real one is caller-gated)


# --------------------------------------------------------------------------- #
# fixtures — a registrar CA, a signing leaf, and both WRPRC forms
# --------------------------------------------------------------------------- #

def _ku(**kw: bool) -> x509.KeyUsage:
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(kw)
    return x509.KeyUsage(**base)


def _cert(subject, issuer, subject_key, signer_key, exts, *, before=None, after=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(before or _NOW - dt.timedelta(days=1))
         .not_valid_after(after or _NOW + dt.timedelta(days=3650)))
    for ext, crit in exts:
        b = b.add_extension(ext, crit)
    return b.sign(signer_key, hashes.SHA256())


def _ca(cn="Test Registrar Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = _cert(name, name, key, key,
                 [(x509.BasicConstraints(True, None), True),
                  (_ku(key_cert_sign=True, crl_sign=True), True)])
    return cert, key, name


def _signer(ca_key, ca_name, *, key=None, eku=REGISTRAR_EKU, cn="Registrar Signing Key"):
    """A registration-certificate signing leaf under the registrar CA."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    exts = [(x509.BasicConstraints(False, None), True)]
    if eku is not None:
        exts.append((x509.ExtendedKeyUsage([ObjectIdentifier(eku)]), False))
    return _cert(subject, ca_name, key, ca_key, exts), key


def _b64(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def claims(**overrides) -> dict:
    """A WRPRC claim set keyed by the clause-5.2.4 claim names. One relying party, one
    intended use (the payload is flat — clause 5.2.4 carries no ``intended_use``
    container), two requestable credentials."""
    base = {
        "sub": "VATES-B12345678",
        "name": "Acme Age Check",
        "sub_ln": "Acme Servicios Digitales SL",
        "country": "ES",
        "registry_uri": "https://registrar.example/ES",
        "policy_id": ["0.4.0.19475.3.1"],
        "certificate_policy": "https://registrar.example/cp",
        "iat": _IAT,
        "exp": _EXP,
        "entitlements": [ENTITLEMENT],
        "intended_use_id": "age-verification",
        "purpose": [{"lang": "en-US", "value": "Checking the minimum age"}],
        "srv_description": [[{"lang": "en-US", "value": "Acme Age Check"}]],
        "credentials": [
            {
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claim": [{"path": ["age_equal_or_over", "18"]}, {"path": ["address"]}],
            },
            {
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claim": [{"path": ["org.iso.18013.5.1", "age_over_18"]}],
            },
        ],
        "supervisory_authority": {
            "email": "supervisory@aepd.es", "phone": "+34 900 000 000",
            "uri": "https://aepd.es/supervisory-authority",
        },
        "status": {"status_list": {"uri": "https://registrar.example/sl/1", "idx": 7}},
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not _ABSENT}


_ABSENT = object()


def jwt_wrprc(payload, chain, key, *, typ="rc-wrp+jwt", alg="ES256", header=None) -> str:
    """A signed compact-JWS WRPRC (the clause-5.2.2 Table 5 shape: typ + alg + x5c)."""
    head = {"typ": typ, "alg": alg, "x5c": [_b64(c) for c in chain]}
    head.update(header or {})
    signing_input = (
        f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}")
    sig = P256SigningKey(key, "registrar").sign(signing_input.encode())
    return f"{signing_input}.{_b64url(sig)}"


# RFC 8392 registered CWT claim keys, so the CWT form exercises the integer-key path.
_CWT_KEYS = {"sub": 2, "exp": 4, "nbf": 5, "iat": 6}


def cwt_wrprc(payload, chain, key, *, typ="rc-wrp+cwt", alg=-7, protected=None,
              detached=False) -> bytes:
    """A signed COSE_Sign1 WRPRC, registered claims carried under their integer keys."""
    body = cbor.encode({_CWT_KEYS.get(k, k): v for k, v in payload.items()})
    prot = {1: alg, 16: typ, 33: [c.public_bytes(serialization.Encoding.DER) for c in chain]}
    prot.update(protected or {})
    prot_bytes = cbor.encode(prot)
    sig = P256SigningKey(key, "registrar").sign(
        cbor.encode(["Signature1", prot_bytes, b"", body]))
    return cbor.encode([prot_bytes, {}, None if detached else body, sig])


@pytest.fixture()
def registrar():
    """(root_cert, signing_chain, signing_private_key) for a well-formed registrar."""
    root, root_key, root_name = _ca()
    leaf, leaf_key = _signer(root_key, root_name)
    return root, [leaf], leaf_key


# --------------------------------------------------------------------------- #
# parse — the claim view
# --------------------------------------------------------------------------- #

def test_parse_reads_the_clause_5_2_4_claim_set(registrar):
    root, chain, key = registrar
    reg = parse_rp_registration_certificate(jwt_wrprc(claims(), chain, key))
    assert reg.form == "jwt"
    assert reg.subject_identifier == "VATES-B12345678"        # `sub` — the semantic id
    assert reg.trade_name == "Acme Age Check"                 # `name`
    assert reg.legal_name == "Acme Servicios Digitales SL"    # `sub_ln`
    assert reg.country == "ES"
    assert reg.entitlements == (ENTITLEMENT,)
    assert reg.policy_ids == ("0.4.0.19475.3.1",)             # an ARRAY of OIDs
    assert reg.intended_use_id == "age-verification"
    assert reg.issued_at == dt.datetime.fromtimestamp(_IAT, tz=dt.timezone.utc)
    assert reg.status == {"status_list": {"uri": "https://registrar.example/sl/1", "idx": 7}}
    assert reg.supervisory_authority is not None
    assert reg.supervisory_authority["email"] == "supervisory@aepd.es"
    # `srv_description` is an array *of arrays* while `purpose` is flat; both normalise.
    assert reg.purpose[0]["value"] == "Checking the minimum age"
    assert reg.service_description[0]["value"] == "Acme Age Check"
    assert len(reg.credentials) == 2
    assert reg.credentials[0].format == "dc+sd-jwt"
    assert reg.credentials[0].claim_paths == (("age_equal_or_over", "18"), ("address",))


def test_parse_reads_the_cwt_form_into_the_same_shape(registrar):
    root, chain, key = registrar
    reg = parse_rp_registration_certificate(cwt_wrprc(claims(), chain, key))
    assert reg.form == "cwt"
    assert reg.subject_identifier == "VATES-B12345678"        # integer key 2 -> sub
    assert reg.issued_at == dt.datetime.fromtimestamp(_IAT, tz=dt.timezone.utc)
    assert reg.entitlements == (ENTITLEMENT,)                 # text key, as it must be
    assert len(reg.credentials) == 2


def test_parse_pins_the_annex_c_example(registrar):
    """The one artifact ETSI publishes: TS 119 475 V1.2.1 Annex C, verbatim.

    It is informative and unsigned (and as printed, not even valid JSON — a trailing
    comma and a stray brace in the header), so it is pinned as the *payload* under a
    signature of our own. It is the only third-party statement of the claim shape, and
    it disagrees with the normative tables in two documented places: `intermediary`
    carries `name` where Table 10 says `sname`, and it omits `exp`/`intended_use_id`.
    """
    annex_c = {
        "name": "Example Company",
        "sub_ln": "Example Company GmbH",
        "sub": "LEIXG-529900T8BM49AURSDO55",
        "country": "DE",
        "registry_uri": "https://registrar.com",
        "srv_description": [[
            {"lang": "en-US", "value": "Awesome Service by Example Company"},
            {"lang": "de-DE", "value": "Super Dienst von Example Company"},
        ]],
        "entitlements": ["https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"],
        "privacy_policy": "https://example.com/privacy-policy",
        "info_uri": "https://example.com/info",
        "support_uri": "https://example.com/support",
        "supervisory_authority": {
            "email": "supervisory@dpa.com",
            "phone": "+49 123 4567890",
            "uri": "https://dpa.com/supervisory-authority",
        },
        "policy_id": ["0.4.0.19475.3.1"],
        "certificate_policy": "https://registrar.com/certificate-policy",
        "iat": 1683000000,
        "status": {"status_list": {"idx": 0, "uri": "https://example.com/statuslists/1"}},
        "purpose": [
            {"lang": "en-US", "value": "Required for checking the minimum age"},
            {"lang": "de-DE", "value": "Benötigt für die Überprüfung des Mindestalters"},
        ],
        "credentials": [
            {"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
             "claim": [{"path": ["age_equal_or_over", "18"]}]},
            {"format": "mso_mdoc", "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
             "claim": [{"path": ["eu.europa.ec.eudi.pid.1", "age_over_18"]}]},
        ],
        "provides_attestations": [
            {"format": "dc+sd-jwt",
             "meta": {"vct_values": ["https://example.com/attestations/age_over_18"]}},
        ],
        "intermediary": {"sub": "LEIXG-INTERMEDIARY-1234567890",
                         "name": "Intermediary Services Ltd."},
    }
    root, chain, key = registrar
    reg = parse_rp_registration_certificate(jwt_wrprc(annex_c, chain, key))
    assert reg.subject_identifier == "LEIXG-529900T8BM49AURSDO55"
    assert reg.trade_name == "Example Company"
    assert reg.country == "DE"
    assert reg.entitlements == (
        "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider",)
    assert reg.policy_ids == ("0.4.0.19475.3.1",)
    assert reg.expires_at is None                    # Annex C carries no `exp` — conformant
    assert reg.intended_use_id is None               # nor `intended_use_id`
    assert len(reg.service_description) == 2         # the doubly-nested array flattens
    assert len(reg.purpose) == 2
    assert len(reg.provides_attestations) == 1
    assert reg.intermediary_identifier == "LEIXG-INTERMEDIARY-1234567890"
    assert reg.intermediary_name == "Intermediary Services Ltd."   # Annex C spells it `name`
    # ...and the request the example registers is inside its own scope.
    check_request_within_registration(reg, {"credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
        "claims": [{"path": ["age_equal_or_over", "18"]}]}]})


def test_intermediary_name_also_reads_the_normative_sname_spelling(registrar):
    # Table 10 says `sname`; Annex C says `name`. Both are accepted.
    root, chain, key = registrar
    reg = parse_rp_registration_certificate(jwt_wrprc(
        claims(intermediary={"sub": "VATDE-INT1", "sname": "Intermediary GmbH"}), chain, key))
    assert reg.intermediary_name == "Intermediary GmbH"
    assert reg.intermediary_identifier == "VATDE-INT1"


def test_intermediary_identifier_also_reads_the_act_sub_spelling(registrar):
    # GEN-5.2.4-09 names the field `act.sub`, which appears nowhere else in the spec.
    root, chain, key = registrar
    reg = parse_rp_registration_certificate(jwt_wrprc(
        claims(act={"sub": "VATDE-INT2"}), chain, key))
    assert reg.intermediary_identifier == "VATDE-INT2"


# --------------------------------------------------------------------------- #
# parse — the signed-header profile, without trust
# --------------------------------------------------------------------------- #

def test_parse_rejects_a_token_that_is_not_shaped_like_a_wrprc(registrar):
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="typ"):
        parse_rp_registration_certificate(jwt_wrprc(claims(), chain, key, typ="JWT"))
    with pytest.raises(RpRegistrationError, match="typ"):
        parse_rp_registration_certificate(cwt_wrprc(claims(), chain, key, typ="application/cwt"))


def test_parse_names_and_refuses_the_german_bmi_profile(registrar):
    # `rc-rp+jwt` is the BMI Architekturkonzept's registration certificate: a different
    # profile with different claim names. Half-parsing it would apply the wrong
    # semantics to `sub`, `purpose` and the credential sets.
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="BMI"):
        parse_rp_registration_certificate(jwt_wrprc(claims(), chain, key, typ="rc-rp+jwt"))


@pytest.mark.parametrize("alg", ["RS256", "HS256", "none", "ES512", None, 7])
def test_parse_rejects_algorithms_outside_the_allow_list(registrar, alg):
    # The allow-list runs before any crypto — an RS*/HS*/none header never reaches a
    # verify call, the invariant the whole library keeps.
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="alg"):
        parse_rp_registration_certificate(jwt_wrprc(claims(), chain, key, alg=alg))


@pytest.mark.parametrize("bad", [b"not cbor", "not.a.jws", "", 42, None, [], b""])
def test_parse_rejects_malformed_input_as_typed_error(bad):
    with pytest.raises(RpRegistrationError):
        parse_rp_registration_certificate(bad)


# --------------------------------------------------------------------------- #
# crit — the JAdES wrinkle
# --------------------------------------------------------------------------- #

def test_crit_accepts_a_jades_parameter_this_verifier_processes(registrar):
    # JAdES V1.1.1-era producers listed their non-registered header parameters in
    # `crit`; the header `iat` (TS 119 182-1 clause 5.1.11) is the live example.
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key, header={"crit": ["iat"], "iat": _IAT})
    assert parse_rp_registration_certificate(token).form == "jwt"


def test_crit_rejects_a_parameter_this_verifier_does_not_process(registrar):
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key,
                      header={"crit": ["sigD"], "sigD": {"pars": ["x"]}})
    with pytest.raises(RpRegistrationError, match="critical"):
        parse_rp_registration_certificate(token)


def test_crit_rejects_a_named_parameter_that_is_absent(registrar):
    # RFC 7515 §4.1.11: every name in `crit` must actually be present in the header.
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key, header={"crit": ["iat"]})
    with pytest.raises(RpRegistrationError, match="not present"):
        parse_rp_registration_certificate(token)


@pytest.mark.parametrize("crit", [[], "iat", [1], {}, None])
def test_crit_rejects_malformed_shapes(registrar, crit):
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key, header={"crit": crit, "iat": _IAT})
    with pytest.raises(RpRegistrationError):
        parse_rp_registration_certificate(token)


def test_a_header_iat_does_not_displace_the_payload_iat(registrar):
    # JAdES puts a claimed signing time in the *header* `iat`; TS 119 475 puts issuance
    # in the *payload* `iat`. They are different fields and must not be collapsed —
    # GEN-5.2.4-08's 12-month ceiling is anchored to the payload's.
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key, header={"iat": _IAT - 999999})
    reg = verify_rp_registration_certificate(token, trust_anchors=[root], now=_AT)
    assert reg.issued_at == dt.datetime.fromtimestamp(_IAT, tz=dt.timezone.utc)
    assert reg.header["iat"] == _IAT - 999999


# --------------------------------------------------------------------------- #
# verify — chain, signature, temporal
# --------------------------------------------------------------------------- #

def test_verify_accepts_a_wrprc_signed_under_the_registrar_anchor(registrar):
    root, chain, key = registrar
    for token in (jwt_wrprc(claims(), chain, key), cwt_wrprc(claims(), chain, key)):
        reg = verify_rp_registration_certificate(token, trust_anchors=[root], now=_AT)
        assert reg.subject_identifier == "VATES-B12345678"


def test_verify_rejects_a_tampered_payload(registrar):
    root, chain, key = registrar
    head, _, sig = jwt_wrprc(claims(), chain, key).split(".")
    forged = claims(entitlements=["https://uri.etsi.org/19475/Entitlement/PID_Provider"])
    swapped = f"{head}.{_b64url(json.dumps(forged, separators=(',', ':')).encode())}.{sig}"
    with pytest.raises(RpRegistrationError, match="signature"):
        verify_rp_registration_certificate(swapped, trust_anchors=[root], now=_AT)


def test_verify_rejects_a_tampered_cwt_payload(registrar):
    root, chain, key = registrar
    prot, unprot, _, sig = cbor.decode(cwt_wrprc(claims(), chain, key))
    forged = cbor.encode({_CWT_KEYS.get(k, k): v for k, v in claims(
        entitlements=["https://uri.etsi.org/19475/Entitlement/PID_Provider"]).items()})
    with pytest.raises(RpRegistrationError, match="signature"):
        verify_rp_registration_certificate(
            cbor.encode([prot, unprot, forged, sig]), trust_anchors=[root], now=_AT)


def test_verify_rejects_a_chain_under_a_different_anchor(registrar):
    root, chain, key = registrar
    other, _, _ = _ca(cn="Some Other Root")
    with pytest.raises(RpRegistrationError, match="trust anchor"):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), chain, key), trust_anchors=[other], now=_AT)


def test_verify_rejects_a_self_signed_registrar(registrar):
    # The classic forgery: an attacker mints their own CA + leaf and signs a WRPRC
    # granting themselves every entitlement. It must not validate to the real anchor.
    root, _, _ = registrar
    rogue_ca, rogue_key, rogue_name = _ca(cn="Rogue Registrar")
    rogue_leaf, rogue_leaf_key = _signer(rogue_key, rogue_name)
    with pytest.raises(RpRegistrationError, match="trust anchor"):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), [rogue_leaf], rogue_leaf_key), trust_anchors=[root], now=_AT)


def test_verify_requires_at_least_one_anchor(registrar):
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="anchor"):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), chain, key), trust_anchors=[], now=_AT)


def test_verify_rejects_mistyped_trust_params(registrar):
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key)
    with pytest.raises(RpRegistrationError):
        verify_rp_registration_certificate(token, trust_anchors=root, now=_AT)
    with pytest.raises(RpRegistrationError):
        verify_rp_registration_certificate(
            token, trust_anchors=[root], intermediates=root, now=_AT)
    with pytest.raises(RpRegistrationError):
        verify_rp_registration_certificate(token, trust_anchors=[root], now="2026-06-01")
    with pytest.raises(RpRegistrationError):
        verify_rp_registration_certificate(token, trust_anchors=[b"not a cert"], now=_AT)


def test_verify_accepts_anchors_in_any_certificate_form(registrar):
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key)
    der = root.public_bytes(serialization.Encoding.DER)
    for anchor in (root, der, root.public_bytes(serialization.Encoding.PEM),
                   base64.b64encode(der).decode()):
        assert verify_rp_registration_certificate(
            token, trust_anchors=[anchor], now=_AT).country == "ES"


def test_verify_refuses_non_ca_intermediate_smuggling():
    # A non-CA certificate must not pass as a signing link (basicConstraints is enforced).
    root, root_key, root_name = _ca()
    imp_key = ec.generate_private_key(ec.SECP256R1())
    imp_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Not A CA")])
    impostor = _cert(imp_name, root_name, imp_key, root_key,
                     [(x509.BasicConstraints(False, None), True)])
    leaf, leaf_key = _signer(imp_key, imp_name)
    with pytest.raises(RpRegistrationError, match="trust anchor"):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), [leaf, impostor], leaf_key), trust_anchors=[root], now=_AT)


def test_verify_requires_a_signing_certificate_chain(registrar):
    root, chain, key = registrar
    signing_input = (
        f"{_b64url(json.dumps({'typ': 'rc-wrp+jwt', 'alg': 'ES256'}).encode())}."
        f"{_b64url(json.dumps(claims()).encode())}")
    sig = P256SigningKey(key, "registrar").sign(signing_input.encode())
    with pytest.raises(RpRegistrationError, match="x5c"):
        verify_rp_registration_certificate(
            f"{signing_input}.{_b64url(sig)}", trust_anchors=[root], now=_AT)


def test_verify_rejects_an_empty_x5c(registrar):
    # Annex C prints `"x5c": []`. Taken literally that anchors nothing.
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="x5c"):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), chain, key, header={"x5c": []}),
            trust_anchors=[root], now=_AT)


def test_verify_enforces_required_eku(registrar):
    root, chain, key = registrar
    token = jwt_wrprc(claims(), chain, key)
    verify_rp_registration_certificate(
        token, trust_anchors=[root], required_eku=REGISTRAR_EKU, now=_AT)     # ok
    with pytest.raises(RpRegistrationError, match="extendedKeyUsage"):
        verify_rp_registration_certificate(
            token, trust_anchors=[root], required_eku="2.9.9.9.9", now=_AT)


def test_verify_rejects_a_signer_with_no_eku_when_one_is_required():
    root, root_key, root_name = _ca()
    leaf, leaf_key = _signer(root_key, root_name, eku=None)
    with pytest.raises(RpRegistrationError, match="extendedKeyUsage"):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), [leaf], leaf_key), trust_anchors=[root],
            required_eku=REGISTRAR_EKU, now=_AT)


def test_verify_rejects_an_rsa_signer_key():
    # An RSA leaf produces no allow-listed JWK: it must fail closed, not crash untyped.
    root, root_key, root_name = _ca()
    leaf, _ = _signer(root_key, root_name, key=rsa.generate_private_key(
        public_exponent=65537, key_size=2048))
    with pytest.raises(RpRegistrationError):
        verify_rp_registration_certificate(
            jwt_wrprc(claims(), [leaf], ec.generate_private_key(ec.SECP256R1())),
            trust_anchors=[root], now=_AT)


def test_verify_enforces_the_temporal_claims(registrar):
    root, chain, key = registrar
    expired = jwt_wrprc(claims(exp=int(_AT.timestamp()) - 7200), chain, key)
    with pytest.raises(RpRegistrationError, match="expired"):
        verify_rp_registration_certificate(expired, trust_anchors=[root], now=_AT)

    future = jwt_wrprc(claims(iat=int(_AT.timestamp()) + 7200,
                              exp=int(_AT.timestamp()) + 90000), chain, key)
    with pytest.raises(RpRegistrationError, match="not valid before"):
        verify_rp_registration_certificate(future, trust_anchors=[root], now=_AT)


def test_an_absent_expiry_is_conformant_but_can_be_refused_by_policy(registrar):
    # `exp` is OPTIONAL (Table 10): revocation runs through `status`. Accept by default,
    # and let a stricter caller demand one.
    root, chain, key = registrar
    token = jwt_wrprc(claims(exp=_ABSENT), chain, key)
    assert verify_rp_registration_certificate(
        token, trust_anchors=[root], now=_AT).expires_at is None
    with pytest.raises(RpRegistrationError, match="exp"):
        verify_rp_registration_certificate(
            token, trust_anchors=[root], now=_AT, require_expiry=True)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_verify_rejects_a_non_finite_expiry(registrar, literal):
    # NaN/Infinity survive json.loads and make every comparison False — i.e. never
    # expires. A present-but-unusable bound must fail closed, not be dropped.
    root, chain, key = registrar
    head, _, sig = jwt_wrprc(claims(), chain, key).split(".")
    raw = json.dumps(claims()).replace(f'"exp": {_EXP}', f'"exp": {literal}')
    with pytest.raises(RpRegistrationError, match="exp"):
        parse_rp_registration_certificate(f"{head}.{_b64url(raw.encode())}.{sig}")


@pytest.mark.parametrize("bad_exp", [True, "soon", [], {}])
def test_verify_rejects_a_non_numeric_expiry(registrar, bad_exp):
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="exp"):
        parse_rp_registration_certificate(jwt_wrprc(claims(exp=bad_exp), chain, key))


def test_verify_rejects_a_validity_longer_than_twelve_months(registrar):
    # GEN-5.2.4-08 caps `exp` at 12 months after the payload `iat`.
    root, chain, key = registrar
    long_lived = jwt_wrprc(claims(iat=_IAT, exp=_IAT + 400 * 86400), chain, key)
    with pytest.raises(RpRegistrationError, match="exceeds"):
        verify_rp_registration_certificate(long_lived, trust_anchors=[root], now=_AT)
    # ...and the ceiling is opt-out-able for a profile that legitimately differs.
    assert verify_rp_registration_certificate(
        long_lived, trust_anchors=[root], now=_AT, max_validity=None).country == "ES"


def test_verify_requires_at_least_one_entitlement(registrar):
    # GEN-5.2.4-03. A WRPRC with no entitlement authorizes nothing.
    root, chain, key = registrar
    token = jwt_wrprc(claims(entitlements=[]), chain, key)
    with pytest.raises(RpRegistrationError, match="entitlement"):
        verify_rp_registration_certificate(token, trust_anchors=[root], now=_AT)
    assert verify_rp_registration_certificate(
        token, trust_anchors=[root], now=_AT, require_entitlement=False).entitlements == ()


def test_a_scalar_entitlement_string_does_not_become_a_grant(registrar):
    # A malformed `entitlements` must not silently collapse into a one-element grant.
    root, chain, key = registrar
    reg = parse_rp_registration_certificate(
        jwt_wrprc(claims(entitlements=ENTITLEMENT), chain, key))
    assert reg.entitlements == ()


# --------------------------------------------------------------------------- #
# CWT-specific fail-closed paths
# --------------------------------------------------------------------------- #

def test_cwt_rejects_a_claim_carried_under_both_an_integer_and_a_text_key(registrar):
    # Two spellings of one claim is a parser-differential wedge: whoever reads the other
    # spelling sees a different token. Fail closed rather than pick a winner.
    root, chain, key = registrar
    body = cbor.encode({**{_CWT_KEYS.get(k, k): v for k, v in claims().items()},
                        "exp": _EXP + 999999})
    prot = cbor.encode({1: -7, 16: "rc-wrp+cwt",
                        33: [c.public_bytes(serialization.Encoding.DER) for c in chain]})
    sig = P256SigningKey(key, "registrar").sign(
        cbor.encode(["Signature1", prot, b"", body]))
    with pytest.raises(RpRegistrationError, match="twice"):
        verify_rp_registration_certificate(
            cbor.encode([prot, {}, body, sig]), trust_anchors=[root], now=_AT)


def test_cwt_rejects_a_detached_payload(registrar):
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="detached"):
        parse_rp_registration_certificate(cwt_wrprc(claims(), chain, key, detached=True))


def test_cwt_rejects_an_algorithm_outside_the_allow_list(registrar):
    root, chain, key = registrar
    with pytest.raises(RpRegistrationError, match="alg"):
        parse_rp_registration_certificate(cwt_wrprc(claims(), chain, key, alg=-257))  # RS256


def test_cwt_reads_alg_from_the_protected_header_only(registrar):
    # An `alg` in the unprotected header is not covered by the signature; honouring it
    # would let an attacker choose the verification algorithm on an unsigned field.
    root, chain, key = registrar
    body = cbor.encode({_CWT_KEYS.get(k, k): v for k, v in claims().items()})
    prot = cbor.encode({16: "rc-wrp+cwt",
                        33: [c.public_bytes(serialization.Encoding.DER) for c in chain]})
    sig = P256SigningKey(key, "registrar").sign(
        cbor.encode(["Signature1", prot, b"", body]))
    with pytest.raises(RpRegistrationError, match="alg"):
        parse_rp_registration_certificate(cbor.encode([prot, {1: -7}, body, sig]))


# --------------------------------------------------------------------------- #
# cross-check 1 — binding the WRPRC to the WRPAC that authenticated the caller
# --------------------------------------------------------------------------- #

class _Wrpac:
    """Stand-in for openvc.rp_cert.RelyingPartyAccessCertificate."""

    def __init__(self, entity_identifier=None, trade_name=None):
        self.entity_identifier = entity_identifier
        self.trade_name = trade_name


def _reg(**overrides):
    root, root_key, root_name = _ca()
    leaf, leaf_key = _signer(root_key, root_name)
    return parse_rp_registration_certificate(
        jwt_wrprc(claims(**overrides), [leaf], leaf_key))


def test_binding_accepts_the_same_relying_party():
    check_matches_access_certificate(_reg(), _Wrpac("VATES-B12345678", "Acme Age Check"))


def test_binding_rejects_a_different_entity():
    # The attack: present your own valid WRPAC alongside someone else's valid WRPRC and
    # inherit their registered scope.
    with pytest.raises(RpRegistrationError, match="different relying parties"):
        check_matches_access_certificate(_reg(), _Wrpac("VATES-ATTACKER01"))


@pytest.mark.parametrize("wrpac,overrides", [
    (_Wrpac(None), {}),                             # missing on the WRPAC
    (_Wrpac("VATES-B12345678"), {"sub": None}),     # missing on the WRPRC
    (_Wrpac(None), {"sub": None}),                  # missing on both
    (_Wrpac("   "), {}),                            # blank on the WRPAC
    (_Wrpac("VATES-B12345678"), {"sub": "   "}),    # blank on the WRPRC
])
def test_binding_never_matches_on_absent_identifiers(wrpac, overrides):
    # `None == None` would be a successful bind — a fail-open hole exactly where the
    # check exists to close one. A blank string must not satisfy it either.
    with pytest.raises(RpRegistrationError, match="missing"):
        check_matches_access_certificate(_reg(**overrides), wrpac)


def test_binding_can_additionally_compare_trade_names():
    check_matches_access_certificate(
        _reg(), _Wrpac("VATES-B12345678", "Acme Age Check"), match_trade_name=True)
    with pytest.raises(RpRegistrationError, match="trade name"):
        check_matches_access_certificate(
            _reg(), _Wrpac("VATES-B12345678", "Acme S.L."), match_trade_name=True)


def test_binding_accepts_a_real_wrpac_object():
    # The documented pairing: openvc.rp_cert's own parsed object, not just a stand-in.
    from openvc.rp_cert import parse_rp_access_certificate

    ca, ca_key, ca_name = _ca(cn="ACA Root")
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, "VATES-B12345678"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Acme Age Check"),
    ])
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    wrpac = parse_rp_access_certificate(
        _cert(subject, ca_name, leaf_key, ca_key, [(x509.BasicConstraints(False, None), True)]))
    check_matches_access_certificate(_reg(), wrpac, match_trade_name=True)


# --------------------------------------------------------------------------- #
# cross-check 2 — the request must fall inside the registered scope
# --------------------------------------------------------------------------- #

def _dcql(*credentials):
    return {"credentials": list(credentials)}


_PID = {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}}


def test_request_within_the_registered_scope_passes():
    check_request_within_registration(
        _reg(), _dcql({**_PID, "claims": [{"path": ["age_equal_or_over", "18"]}]}),
        intended_use_id="age-verification")


def test_the_intended_use_assertion_must_match():
    with pytest.raises(RpRegistrationError, match="intended use"):
        check_request_within_registration(
            _reg(), _dcql({**_PID, "claims": [{"path": ["address"]}]}),
            intended_use_id="profiling")


def test_request_for_an_unregistered_format_is_refused():
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(_reg(), _dcql({
            "id": "x", "format": "ldp_vc", "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["address"]}]}))


def test_request_for_an_unregistered_claim_is_refused():
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(
            _reg(), _dcql({**_PID, "claims": [{"path": ["nationality"]}]}))


def test_a_registered_container_covers_its_members():
    # Registering ["address"] covers ["address","locality"] — a DCQL selection of the
    # container already returns the whole object, so this is not a widening.
    check_request_within_registration(
        _reg(), _dcql({**_PID, "claims": [{"path": ["address", "locality"]}]}))


def test_a_registered_member_does_not_cover_its_container():
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(
            _reg(), _dcql({**_PID, "claims": [{"path": ["age_equal_or_over"]}]}))


def test_a_registered_index_does_not_grant_the_array_wildcard():
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {},
                             "claim": [{"path": ["degrees", 0, "name"]}]}])
    check_request_within_registration(reg, _dcql({
        "id": "d", "format": "dc+sd-jwt", "claims": [{"path": ["degrees", 0, "name"]}]}))
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(reg, _dcql({
            "id": "d", "format": "dc+sd-jwt",
            "claims": [{"path": ["degrees", None, "name"]}]}))


def test_a_registered_wildcard_covers_any_index():
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {},
                             "claim": [{"path": ["degrees", None, "name"]}]}])
    check_request_within_registration(reg, _dcql({
        "id": "d", "format": "dc+sd-jwt", "claims": [{"path": ["degrees", 3, "name"]}]}))


def test_a_boolean_does_not_match_an_integer_index():
    # `True == 1` in Python; without a type guard a registered index 1 would cover a
    # requested `True` (and a registered `True` would cover index 1).
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {},
                             "claim": [{"path": ["a", 1]}]}])
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(reg, _dcql({
            "id": "d", "format": "dc+sd-jwt", "claims": [{"path": ["a", True]}]}))


def test_meta_must_be_covered_not_merely_present():
    # Registered for urn:eudi:pid:1 — asking under a different vct is a scope escalation.
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(_reg(), _dcql({
            "id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:bank-account:1"]},
            "claims": [{"path": ["address"]}]}))


@pytest.mark.parametrize("value", [[{"a": 1}], [["x"]], [{"a": 1}, "b"]])
def test_unhashable_meta_values_fail_closed_not_with_a_bare_typeerror(value):
    # `meta` is attacker-influenced JSON. Subset-testing it by building sets raised a
    # bare TypeError ("unhashable type: 'dict'") straight past the OpenvcError family —
    # found by adversarial review. Equality containment has no such edge.
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {"vct_values": value},
                             "claim": [{"path": ["a"]}]}])
    check_request_within_registration(reg, _dcql({
        "id": "d", "format": "dc+sd-jwt", "meta": {"vct_values": value},
        "claims": [{"path": ["a"]}]}))
    with pytest.raises(RpRegistrationError):
        check_request_within_registration(reg, _dcql({
            "id": "d", "format": "dc+sd-jwt", "meta": {"vct_values": [{"other": 2}]},
            "claims": [{"path": ["a"]}]}))


def test_an_unconstrained_request_does_not_inherit_a_constrained_registration():
    # No `meta` means "any credential of this format"; the registration is narrower.
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(_reg(), _dcql({
            "id": "pid", "format": "dc+sd-jwt", "claims": [{"path": ["address"]}]}))


def test_a_request_naming_no_claims_is_refused_against_an_enumerated_registration():
    # An absent `claims` asks for every attribute — it cannot be inside an explicit list.
    with pytest.raises(RpRegistrationError, match="every attribute"):
        check_request_within_registration(_reg(), _dcql(_PID))


def test_an_entry_registering_no_claim_paths_grants_nothing():
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {"vct_values": ["v"]}}])
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(reg, _dcql({
            "id": "d", "format": "dc+sd-jwt", "meta": {"vct_values": ["v"]},
            "claims": [{"path": ["anything"]}]}))


def test_scope_is_not_unioned_across_differently_scoped_entries():
    # Registered: vct A grants `name`, vct B grants `age`. Asking for A.age must fail —
    # unioning claim paths across entries of the same format would escalate scope.
    reg = _reg(credentials=[
        {"format": "dc+sd-jwt", "meta": {"vct_values": ["A"]}, "claim": [{"path": ["name"]}]},
        {"format": "dc+sd-jwt", "meta": {"vct_values": ["B"]}, "claim": [{"path": ["age"]}]},
    ])
    check_request_within_registration(reg, _dcql({
        "id": "a", "format": "dc+sd-jwt", "meta": {"vct_values": ["A"]},
        "claims": [{"path": ["name"]}]}))
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(reg, _dcql({
            "id": "a", "format": "dc+sd-jwt", "meta": {"vct_values": ["A"]},
            "claims": [{"path": ["age"]}]}))


def test_a_request_spelling_claims_either_way_is_read(registrar):
    # The registration side says `claim`, DCQL says `claims`. A query using the spec's
    # singular spelling must not be under-read into looking like "no claims requested".
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(
            _reg(), _dcql({**_PID, "claim": [{"path": ["nationality"]}]}))


@pytest.mark.parametrize("query", [{}, {"credentials": []}, {"credentials": "x"},
                                   {"credentials": ["not an object"]}, "not a query", None])
def test_malformed_dcql_queries_are_typed_errors(query):
    with pytest.raises(RpRegistrationError):
        check_request_within_registration(_reg(), query)


# --------------------------------------------------------------------------- #
# adversarial-review regressions (issue #89)
# --------------------------------------------------------------------------- #

def test_a_decoy_claim_key_cannot_narrow_a_request():
    # CRITICAL. `_claim_paths` read `claim` first and fell back to `claims`. That is
    # right for the registration side (the spec's spelling), but applied to a *request*
    # it let a relying party put a narrow decoy in `claim` and the real, broader ask in
    # `claims`: openvc authorized the decoy while the wallet — which follows DCQL —
    # answers `claims`. Unknown query members are ignored downstream, so the escalating
    # query stayed valid end to end. The request side now takes the union of both.
    with pytest.raises(RpRegistrationError, match="birth_date"):
        check_request_within_registration(_reg(), _dcql({
            **_PID,
            "claim": [{"path": ["age_equal_or_over", "18"]}],        # the decoy
            "claims": [{"path": ["birth_date"]}, {"path": ["family_name"]}]}))


def test_a_request_using_only_the_spec_spelling_is_still_read():
    # The union must not lose the singular spelling either.
    check_request_within_registration(
        _reg(), _dcql({**_PID, "claim": [{"path": ["address"]}]}))
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(
            _reg(), _dcql({**_PID, "claim": [{"path": ["nationality"]}]}))


def test_a_registration_grant_is_not_widened_by_a_second_spelling():
    # Precedence on the registration side is the fail-closed direction: one list, never
    # the union, so a second spelling cannot add to a grant.
    reg = _reg(credentials=[{
        "format": "dc+sd-jwt", "meta": {},
        "claim": [{"path": ["name"]}],
        "claims": [{"path": ["ssn"]}]}])
    with pytest.raises(RpRegistrationError, match="claim path"):
        check_request_within_registration(reg, _dcql({
            "id": "d", "format": "dc+sd-jwt", "claims": [{"path": ["ssn"]}]}))


@pytest.mark.parametrize("field", ["iat", "exp", "nbf"])
def test_a_bignum_numericdate_is_a_typed_error_not_an_overflow(registrar, field):
    # HIGH. `math.isfinite` casts to float, so a `10**400` literal — which json.loads
    # happily yields — raised a bare OverflowError straight past the OpenvcError family.
    root, chain, key = registrar
    token = jwt_wrprc(claims(**{field: 10 ** 400}), chain, key)
    with pytest.raises(RpRegistrationError, match=field):
        verify_rp_registration_certificate(token, trust_anchors=[root], now=_AT)


def test_an_empty_registered_path_grants_nothing():
    # MEDIUM. An empty tuple is a prefix of every path, so `{"path": []}` silently
    # became a blanket grant over the whole credential.
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {"vct_values": ["v"]},
                             "claim": [{"path": []}]}])
    for wanted in (["ssn"], ["biometric_template"], ["address", "locality"]):
        with pytest.raises(RpRegistrationError, match="claim path"):
            check_request_within_registration(reg, _dcql({
                "id": "d", "format": "dc+sd-jwt", "meta": {"vct_values": ["v"]},
                "claims": [{"path": wanted}]}))


@pytest.mark.parametrize("bad_meta", ["urn:eudi:pid:1", 42, ["urn:eudi:pid:1"], True])
def test_a_malformed_meta_matches_nothing_rather_than_everything(bad_meta):
    # MEDIUM. Coercing a non-object `meta` to `{}` turned a malformed *constraint* into
    # *no* constraint — the entry then matched the broadest possible request (no `meta`
    # at all = any credential of that format) while denying the one it plainly meant.
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": bad_meta,
                             "claim": [{"path": ["address"]}]}])
    assert reg.credentials[0].meta is None
    for query in ({"id": "p", "format": "dc+sd-jwt", "claims": [{"path": ["address"]}]},
                  {"id": "p", "format": "dc+sd-jwt", "meta": {"vct_values": ["x"]},
                   "claims": [{"path": ["address"]}]}):
        with pytest.raises(RpRegistrationError, match="does not register"):
            check_request_within_registration(reg, _dcql(query))


def test_an_absent_meta_still_means_unconstrained():
    # ...and the distinction is preserved: absent `meta` is not malformed `meta`.
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "claim": [{"path": ["address"]}]}])
    assert reg.credentials[0].meta == {}
    check_request_within_registration(reg, _dcql({
        "id": "p", "format": "dc+sd-jwt", "claims": [{"path": ["address"]}]}))


def test_meta_does_not_conflate_booleans_with_integers():
    # LOW. `True == 1` in Python; `_meta_covered` lacked the guard `_path_covered` has.
    reg = _reg(credentials=[{"format": "dc+sd-jwt", "meta": {"k": [1]},
                             "claim": [{"path": ["a"]}]}])
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(reg, _dcql({
            "id": "d", "format": "dc+sd-jwt", "meta": {"k": [True]},
            "claims": [{"path": ["a"]}]}))


def test_the_entitlement_floor_checks_the_etsi_namespace(registrar):
    # LOW. The floor was "≥1 non-empty string", so any junk URI satisfied it while
    # ENTITLEMENT_URI_PREFIX sat exported-but-unused, reading like a check that existed.
    # GEN-5.2.4-03 requires one from clause A.2.
    root, chain, key = registrar
    token = jwt_wrprc(claims(entitlements=["urn:attacker:whatever"]), chain, key)
    with pytest.raises(RpRegistrationError, match="ENTITLEMENT|uri.etsi.org"):
        verify_rp_registration_certificate(token, trust_anchors=[root], now=_AT)
    assert verify_rp_registration_certificate(
        token, trust_anchors=[root], now=_AT, require_entitlement=False,
    ).entitlements == ("urn:attacker:whatever",)
