"""
tests/test_x5c.py — JOSE x5c certificate-chain validation and issuer binding
(Etapa 8). All offline: a self-signed root -> intermediate -> leaf chain is built
in-test, so no PKI and no network.
"""
from __future__ import annotations

import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc.x5c import X5cError, resolve_x5c_key

ISS = "https://issuer.example"
NOW = dt.datetime(2026, 7, 6, tzinfo=dt.timezone.utc)
_PAST = NOW - dt.timedelta(days=3650)
_FUTURE = NOW + dt.timedelta(days=3650)
_CA_KU = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, issuer_key, *, ca, curve=ec.SECP256R1(), not_after=_FUTURE,
          san=None, subject_key=None):
    subject_key = subject_key or ec.generate_private_key(curve)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_PAST).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(_CA_KU, critical=True)
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def _der_b64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _chain(*, leaf_curve=ec.SECP256R1(), leaf_not_after=_FUTURE, leaf_san=None):
    """(x5c list [leaf, inter], root_cert). leaf_san defaults to a URI matching ISS."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root, _ = _cert("root", "root", root_key, ca=True, subject_key=root_key)
    inter, inter_key = _cert("inter", "root", root_key, ca=True)
    san = leaf_san if leaf_san is not None else [x509.UniformResourceIdentifier(ISS)]
    leaf, _ = _cert("leaf", "inter", inter_key, ca=False, curve=leaf_curve,
                    not_after=leaf_not_after, san=san)
    return [_der_b64(leaf), _der_b64(inter)], root


# --------------------------------------------------------------------------- #

def test_valid_chain_returns_leaf_p256_jwk():
    x5c, root = _chain()
    jwk = resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    assert "x" in jwk and "y" in jwk


def test_dns_san_binding_accepted():
    x5c, root = _chain(leaf_san=[x509.DNSName("issuer.example")])
    jwk = resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)   # host matches DNS SAN
    assert jwk["crv"] == "P-256"


def test_unrelated_anchor_rejected():
    x5c, _ = _chain()
    other_root, _ = _cert("other", "other", ec.generate_private_key(ec.SECP256R1()),
                          ca=True, subject_key=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(X5cError, match="validate"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[other_root], now=NOW)


def test_expired_leaf_rejected():
    x5c, root = _chain(leaf_not_after=NOW - dt.timedelta(days=1))
    with pytest.raises(X5cError, match="validate"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)


def test_naive_now_treated_as_utc_not_host_local():
    # a tz-naive now one hour AFTER expiry (in UTC terms) must reject on ANY host
    # timezone — it is taken as UTC, never reinterpreted as the host's local time
    x5c, root = _chain(leaf_not_after=NOW - dt.timedelta(hours=1))
    naive_after_expiry = dt.datetime(2026, 7, 6, 0, 0, 0)     # == NOW, but tz-naive
    with pytest.raises(X5cError, match="validate"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=naive_after_expiry)


def test_issuer_not_in_san_rejected():
    x5c, root = _chain(leaf_san=[x509.UniformResourceIdentifier("https://other.example")])
    with pytest.raises(X5cError, match="not bound|SAN"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)


def test_leaf_without_san_rejected():
    x5c, root = _chain(leaf_san=[])   # empty SAN extension -> no binding
    with pytest.raises(X5cError):
        resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)


def test_non_ca_intermediate_rejected():
    # a non-CA cert (basicConstraints CA:FALSE) presented as an intermediate must
    # be refused — the verifier enforces basicConstraints
    root_key = ec.generate_private_key(ec.SECP256R1())
    root, _ = _cert("root", "root", root_key, ca=True, subject_key=root_key)
    fake_inter, fake_key = _cert("fake", "root", root_key, ca=False)     # NOT a CA
    leaf, _ = _cert("leaf", "fake", fake_key, ca=False,
                    san=[x509.UniformResourceIdentifier(ISS)])
    x5c = [_der_b64(leaf), _der_b64(fake_inter)]
    with pytest.raises(X5cError, match="validate"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)


def test_non_p256_leaf_rejected():
    x5c, root = _chain(leaf_curve=ec.SECP384R1())
    with pytest.raises(X5cError, match="P-256"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[root], now=NOW)


def test_malformed_and_no_anchors():
    x5c, root = _chain()
    with pytest.raises(X5cError, match="anchor"):
        resolve_x5c_key(x5c, ISS, trust_anchors=[], now=NOW)
    with pytest.raises(X5cError, match="empty|missing"):
        resolve_x5c_key([], ISS, trust_anchors=[root], now=NOW)
    with pytest.raises(X5cError, match="certificate"):
        resolve_x5c_key(["not-a-cert"], ISS, trust_anchors=[root], now=NOW)


# --------------------------------------------------------------------------- #
# pipeline integration (opt-in via x5c_trust_anchors)
# --------------------------------------------------------------------------- #

def _vc_jwt_with_x5c(leaf_key, x5c):
    import time

    from openvc.keys import P256SigningKey
    from openvc.proof._jws import sign_compact

    signer = P256SigningKey(leaf_key, kid="leaf")
    ts = int(time.time())
    header = {"alg": "ES256", "typ": "JWT", "kid": "leaf", "x5c": list(x5c)}
    payload = {
        "iss": ISS, "nbf": ts, "iat": ts,
        "vc": {"@context": ["https://www.w3.org/ns/credentials/v2"], "id": "urn:uuid:1",
               "type": ["VerifiableCredential"], "issuer": ISS,
               "credentialSubject": {"id": "did:example:subject"}},
    }
    return sign_compact(header, payload, signing_key=signer)


def _chain_with_leaf_key():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root, _ = _cert("root", "root", root_key, ca=True, subject_key=root_key)
    inter, inter_key = _cert("inter", "root", root_key, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    _cert("leaf", "inter", inter_key, ca=False, subject_key=leaf_key,
          san=[x509.UniformResourceIdentifier(ISS)])
    leaf, _ = _cert("leaf", "inter", inter_key, ca=False, subject_key=leaf_key,
                    san=[x509.UniformResourceIdentifier(ISS)])
    return [_der_b64(leaf), _der_b64(inter)], root, leaf_key


def test_pipeline_verifies_vc_jwt_with_x5c():
    from openvc import VerificationPolicy, verify_credential

    x5c, root, leaf_key = _chain_with_leaf_key()
    token = _vc_jwt_with_x5c(leaf_key, x5c)
    result = verify_credential(token, x5c_trust_anchors=[root],
                               policy=VerificationPolicy(require_status=False))
    assert result.format == "vc-jwt" and result.issuer == ISS


def test_pipeline_x5c_untrusted_anchor_rejected():
    from openvc import VerificationPolicy, verify_credential
    from openvc.verify import KeyResolutionFailed

    x5c, _, leaf_key = _chain_with_leaf_key()
    token = _vc_jwt_with_x5c(leaf_key, x5c)
    other_root, _ = _cert("other", "other", ec.generate_private_key(ec.SECP256R1()),
                          ca=True, subject_key=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(KeyResolutionFailed):
        verify_credential(token, x5c_trust_anchors=[other_root],
                          policy=VerificationPolicy(require_status=False))
