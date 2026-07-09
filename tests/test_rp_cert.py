"""
tests/test_rp_cert.py — EUDI relying-party access certificate (WRPAC) parsing +
validation (``openvc.rp_cert``, issue #67).

No real WRPACs exist to record yet (EUDI relying-party PKI launches with the wallets),
so these build certificates with ``cryptography`` that carry the WRPAC-relevant shape —
the eIDAS ``organizationIdentifier`` subject field, an EKU, a certificatePolicies OID,
and a Subject Information Access URL pointing at the registration record — and exercise
the parse + fail-closed path validation to caller-provided ACA anchors.
"""
from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from openvc.rp_cert import (
    RpCertError,
    parse_rp_access_certificate,
    verify_rp_access_certificate,
)

RP_EKU = "0.4.0.19411.8.1"          # a placeholder EUDI-RP EKU OID (real one is caller-gated)
_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_AT = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)          # a pinned evaluation instant


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


def _ca(cn="Test ACA Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = _cert(name, name, key, key,
                 [(x509.BasicConstraints(True, None), True),
                  (_ku(key_cert_sign=True, crl_sign=True), True)])
    return cert, key, name


def _wrpac(ca_key, ca_name, *, key=None, org_id="VATES-B12345678", eku=RP_EKU,
           sia="https://registry.example/rp/acme", before=None, after=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, org_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme SA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Acme Verifier Service"),
    ])
    exts = [
        (x509.ExtendedKeyUsage([ObjectIdentifier(eku)]), False),
        (x509.CertificatePolicies(
            [x509.PolicyInformation(ObjectIdentifier("1.2.3.4.5"), None)]), False),
        (x509.SubjectInformationAccess([x509.AccessDescription(
            ObjectIdentifier("1.3.6.1.5.5.7.48.5"),
            x509.UniformResourceIdentifier(sia))]), False),
    ]
    return _cert(subject, ca_name, key, ca_key, exts, before=before, after=after)


def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- #
# parse — untrusted attribute extraction
# --------------------------------------------------------------------------- #

def test_parse_extracts_the_wrpac_attribute_set():
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name)
    rp = parse_rp_access_certificate(_der(leaf))
    assert rp.entity_identifier == "VATES-B12345678"          # organizationIdentifier
    assert rp.trade_name == "Acme Verifier Service"           # commonName
    assert rp.organization_name == "Acme SA"
    assert rp.country == "ES"
    assert rp.extended_key_usages == (RP_EKU,)
    assert rp.certificate_policies == ("1.2.3.4.5",)
    assert rp.registration_records == ("https://registry.example/rp/acme",)
    assert rp.public_jwk == {"kty": "EC", "crv": "P-256", "x": rp.public_jwk["x"],
                             "y": rp.public_jwk["y"]}


def test_parse_accepts_der_pem_and_base64_forms():
    import base64
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name)
    der = _der(leaf)
    pem = leaf.public_bytes(serialization.Encoding.PEM)
    b64 = base64.b64encode(der).decode()
    for form in (leaf, der, pem, b64):
        assert parse_rp_access_certificate(form).entity_identifier == "VATES-B12345678"


def test_parse_rsa_leaf_has_no_ec_jwk_but_still_parses():
    ca, ca_key, ca_name = _ca()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _wrpac(ca_key, ca_name, key=rsa_key)
    rp = parse_rp_access_certificate(leaf)
    assert rp.public_jwk is None                              # not EC — no JWK, but identity parsed
    assert rp.entity_identifier == "VATES-B12345678"


@pytest.mark.parametrize("bad", [b"not a certificate", "!!!not-base64!!!", 42, None, b""])
def test_parse_rejects_malformed_input_as_typed_error(bad):
    with pytest.raises(RpCertError):
        parse_rp_access_certificate(bad)


# --------------------------------------------------------------------------- #
# verify — fail-closed path validation to ACA anchors
# --------------------------------------------------------------------------- #

def test_verify_validates_to_the_aca_anchor():
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name)
    rp = verify_rp_access_certificate(leaf, trust_anchors=[ca], now=_AT)
    assert rp.entity_identifier == "VATES-B12345678"


def test_verify_rejects_a_leaf_under_a_different_anchor():
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name)
    other_ca, _, _ = _ca(cn="Some Other Root")
    with pytest.raises(RpCertError):
        verify_rp_access_certificate(leaf, trust_anchors=[other_ca], now=_AT)


def test_verify_requires_at_least_one_anchor():
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name)
    with pytest.raises(RpCertError):
        verify_rp_access_certificate(leaf, trust_anchors=[])


def test_verify_rejects_expired_certificate():
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name,
                  before=_NOW - dt.timedelta(days=800), after=_NOW - dt.timedelta(days=400))
    with pytest.raises(RpCertError):
        verify_rp_access_certificate(leaf, trust_anchors=[ca], now=_AT)


def test_verify_enforces_required_eku():
    ca, ca_key, ca_name = _ca()
    leaf = _wrpac(ca_key, ca_name, eku=RP_EKU)
    verify_rp_access_certificate(leaf, trust_anchors=[ca], required_eku=RP_EKU, now=_AT)  # ok
    with pytest.raises(RpCertError):
        verify_rp_access_certificate(leaf, trust_anchors=[ca],
                                     required_eku="2.9.9.9.9", now=_AT)


def test_verify_refuses_non_ca_intermediate_smuggling():
    # A non-CA certificate (basicConstraints CA=false) must not pass as an intermediate:
    # cryptography's webpki CA policy enforces basicConstraints, so a smuggled EE cert
    # cannot become a signing link. Build root -> real-CA-key-but-EE-constraints -> leaf.
    root, root_key, root_name = _ca()
    # an "intermediate" that is actually an end-entity (CA=false), signed by the root
    imp_key = ec.generate_private_key(ec.SECP256R1())
    imp_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Not A CA")])
    impostor = _cert(imp_name, root_name, imp_key, root_key,
                     [(x509.BasicConstraints(False, None), True)])
    leaf = _wrpac(imp_key, imp_name)                    # signed by the non-CA impostor
    with pytest.raises(RpCertError):
        verify_rp_access_certificate(leaf, trust_anchors=[root],
                                     intermediates=[impostor], now=_AT)
