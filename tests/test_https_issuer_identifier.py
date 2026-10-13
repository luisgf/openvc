"""
tests/test_https_issuer_identifier.py — an https ``iss`` names one host to everyone
(#236).

An https issuer identifier is attacker-controlled, and openvc derives a host from it
twice: to fetch the JWT VC Issuer Metadata, and to bind the iss to an x5c leaf's
``dNSName``. ``https://trusted.example\\@attacker.example`` names ``attacker.example``
to Python's ``urlparse`` and ``trusted.example`` to a WHATWG parser (a browser, a JS
front-end). openvc fetched the keys from, or bound the certificate of,
``attacker.example`` while a consumer that showed the issuer's host read
``trusted.example``.

Every form that lets the two parsers name different hosts or paths is now refused:
userinfo, a backslash, a control character or whitespace, params, a query and a
fragment (even empty), a non-ASCII host, a percent-encoded host, port 0 and a dot
segment. openid4vci's ``credential_issuer`` refuses the same forms.
"""
from __future__ import annotations

import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc.jwt_vc_issuer import JwtVcIssuerError, jwt_vc_issuer_metadata_url
from openvc.keys import P256SigningKey
from openvc.openid4vci import CredentialOfferMalformed, parse_credential_offer
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.verify import KeyResolutionFailed, verify_many
from openvc.x5c import X5cError, resolve_x5c_key

V2 = "https://www.w3.org/ns/credentials/v2"
WELL_KNOWN = "/.well-known/jwt-vc-issuer"

HOSTILE_ISS = [
    "https://trusted.example\\@attacker.example",   # WHATWG: trusted.example
    "https://trusted.example@attacker.example",     # userinfo
    "https://user:pass@attacker.example",
    "https://attacker.example\\.trusted.example",   # WHATWG reads \ as /
    "https://issuer.example/tenant\\1",
    "https://issuer.ex\tample",                     # urlparse drops \t silently
    "https://issuer.ex\nample",
    "https://issuer.example /x",                    # whitespace
    "https://issuer.example\x00",
    "https://attacker.example#@trusted.example",    # a fragment
    "https://issuer.example?tenant=1",              # a query
    "https://issuer.example/tenant;v=1",            # params: the URL dropped them
    "https://:443",                                 # no host
    "https://.",
    # From this change's adversarial review: the hosts below are one domain to
    # Python (IDNA2003, raw %) and another to a browser (UTS 46, decoded %).
    "https://fa\u00df.de",                         # Python fass.de, WHATWG xn--fa-hia.de
    "https://\u1e9e.example",                      # capital sharp s
    "https://\u03c2.example",                      # final sigma
    "https://m\u00fcller.de",                      # any IDN: send its xn-- A-label
    "https://%74rusted.example",                    # WHATWG decodes it to trusted.example
    "https://h.example/attacker/%2e%2e/victim",     # WHATWG resolves it to /victim
    "https://h.example/a/../victim",
    "https://h.example/./x",
    "https://issuer.example/t;",                    # empty params, query and fragment:
    "https://issuer.example/t?",                    # the metadata URL dropped them
    "https://issuer.example/t#",
    "https://issuer.example:0",                     # WHATWG keeps 0, the fetch used 443
]


@pytest.mark.parametrize("iss", HOSTILE_ISS)
def test_metadata_url_rejects_ambiguous_iss(iss):
    with pytest.raises(JwtVcIssuerError):
        jwt_vc_issuer_metadata_url(iss)


@pytest.mark.parametrize("iss,url", [
    ("https://issuer.example", f"https://issuer.example{WELL_KNOWN}"),
    ("https://issuer.example/", f"https://issuer.example{WELL_KNOWN}"),
    ("https://issuer.example:8443/tenant/1",
     f"https://issuer.example:8443{WELL_KNOWN}/tenant/1"),
])
def test_metadata_url_keeps_clean_iss(iss, url):
    assert jwt_vc_issuer_metadata_url(iss) == url


@pytest.mark.parametrize("iss", [None, 5, b"https://issuer.example", ["x"]])
def test_metadata_url_types_a_non_string_iss(iss):
    with pytest.raises(JwtVcIssuerError):
        jwt_vc_issuer_metadata_url(iss)


# openid4vci's credential_issuer is the same kind of identifier, so it refuses the
# same forms (it already refused userinfo, whitespace, a query and a fragment).
@pytest.mark.parametrize("issuer", [
    "https://trusted.example\\.attacker.example",  # WHATWG: trusted.example
    "https://fa\u00df.de",
    "https://%74rusted.example",
    "https://h.example/a/%2e%2e/b",
    "https://issuer.example:0",
    "https://issuer.example/t?",
])
def test_credential_offer_refuses_the_same_forms(issuer):
    with pytest.raises(CredentialOfferMalformed):
        parse_credential_offer(
            {"credential_issuer": issuer, "credential_configuration_ids": ["c"]})


def _did_key_vc() -> str:
    sk = P256SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0x80, 0x24]) + sk.public_key_raw(compressed=True))
    key = P256SigningKey(sk._sk, kid=f"did:key:{mb}#{mb}")
    return _vc(f"did:key:{mb}", key)


def _vc(issuer: str, key) -> str:
    return VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer,
         "credentialSubject": {"id": "did:example:holder"}},
        signing_key=key)


@pytest.mark.parametrize("iss", [
    "https://trusted.example\\@attacker.example",
    "https://fa\u00df.de",
])
def test_pipeline_never_fetches_for_an_ambiguous_iss(iss):
    # Before #236 the metadata and the JWKS came from attacker.example (or fass.de)
    # and the credential verified, reporting the ambiguous iss as its issuer.
    fetched: list[str] = []

    def _fetch(url):
        fetched.append(url)
        raise AssertionError(f"fetch called with {url!r}")
    hostile = _vc(iss, P256SigningKey.generate(kid="k1"))
    good, bad = verify_many([_did_key_vc(), hostile], jwt_vc_issuer_fetch=_fetch)
    assert good.ok is True
    assert isinstance(bad.error, KeyResolutionFailed)
    assert fetched == []


# --------------------------------------------------------------------------- #
# x5c: a dNSName binds only a clean https issuer
# --------------------------------------------------------------------------- #

NOW = dt.datetime(2026, 10, 13, tzinfo=dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


_CA_KU = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)


def _builder(subject, issuer, public_key):
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=365)))


@pytest.fixture(scope="module")
def attacker_chain():
    """A leaf for attacker.example (dNSName) under a pinned root: what any party
    with a certificate from a trusted CA holds."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        _builder("root", "root", root_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_CA_KU, critical=True)
        .sign(root_key, hashes.SHA256()))
    leaf = (
        _builder("leaf", "root", ec.generate_private_key(ec.SECP256R1()).public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("attacker.example")]),
                       critical=False)
        .sign(root_key, hashes.SHA256()))
    der = leaf.public_bytes(serialization.Encoding.DER)
    return [base64.b64encode(der).decode("ascii")], root


@pytest.mark.parametrize("iss", [
    "https://trusted.example\\@attacker.example",
    "https://trusted.example@attacker.example",
    "https://attacker.example#@trusted.example",
    "http://attacker.example",                      # a dNSName binds https only
])
def test_x5c_dns_san_does_not_bind_an_ambiguous_iss(attacker_chain, iss):
    x5c, root = attacker_chain
    with pytest.raises(X5cError, match="not bound"):
        resolve_x5c_key(x5c, iss, trust_anchors=[root], now=NOW)


def test_x5c_types_a_non_string_iss(attacker_chain):
    x5c, root = attacker_chain
    with pytest.raises(X5cError, match="not bound"):
        resolve_x5c_key(x5c, None, trust_anchors=[root], now=NOW)


def test_x5c_dns_san_still_binds_a_clean_iss(attacker_chain):
    x5c, root = attacker_chain
    jwk = resolve_x5c_key(x5c, "https://attacker.example", trust_anchors=[root], now=NOW)
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
