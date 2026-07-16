"""
tests/test_trustlist_xades.py — the reference XAdES verifier behind the
``[trustlist]`` extra (``openvc.trustlist.verify_xades_enveloped``).

The whole file ``importorskip``s ``signxml`` (the extra). Authenticity is proven by
**round-trips**: build an ETSI-shaped TL, sign it with ``signxml`` under a
self-signed EC cert (plain enveloped XML-DSig *and* real XAdES with its
``SignedProperties``), and verify it back — plus the fail-closed negatives (wrong
cert, tampered body, unsigned, DTD, oversize, unexpected signed references) and a
full ``walk_lotl`` over signed LOTL + national TL. The **real Commission-signed
goldens** (EU LOTL + ES TL) live in ``test_trustlist_xades_real.py``.
Self-contained (tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import base64
import datetime
import sys

import pytest

pytest.importorskip("signxml")

from lxml import etree                                         # noqa: E402  (after importorskip)
from cryptography import x509                                  # noqa: E402
from cryptography.hazmat.primitives import hashes              # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec       # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID                      # noqa: E402

from openvc.trustlist import (                                 # noqa: E402
    ServiceStatus,
    TrustListSignatureBackendUnavailable,
    TrustListSignatureError,
    consume_trust_list,
    verify_xades_enveloped,
    walk_lotl,
)

TSL = "http://uri.etsi.org/02231/v2#"
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _cert(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    return key, cert


def _el(parent, tag, text=None):
    e = etree.SubElement(parent, f"{{{TSL}}}{tag}")
    if text is not None:
        e.text = text
    return e


def _x509_el(parent, der):
    _el(parent, "X509Certificate", base64.b64encode(der).decode())


def _national_tl(ca_cert_der, *, next_update="2099-01-01T00:00:00Z",
                 status=ServiceStatus.GRANTED):
    root = etree.Element(f"{{{TSL}}}TrustServiceStatusList")
    si = _el(root, "SchemeInformation")
    _el(si, "TSLType", "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric")
    _el(si, "SchemeTerritory", "DE")
    _el(_el(si, "NextUpdate"), "dateTime", next_update)
    tsp = _el(_el(root, "TrustServiceProviderList"), "TrustServiceProvider")
    name = _el(_el(_el(tsp, "TSPInformation"), "TSPName"), "Name", "Example TSP DE")
    name.set(XML_LANG, "en")
    info = _el(_el(_el(tsp, "TSPServices"), "TSPService"), "ServiceInformation")
    _el(info, "ServiceTypeIdentifier", "http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
    _x509_el(_el(_el(info, "ServiceDigitalIdentity"), "DigitalId"), ca_cert_der)
    _el(info, "ServiceStatus", status)
    return root


def _lotl(national_url, national_signer_der):
    root = etree.Element(f"{{{TSL}}}TrustServiceStatusList")
    si = _el(root, "SchemeInformation")
    _el(si, "TSLType", "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists")
    _el(si, "SchemeTerritory", "EU")
    _el(_el(si, "NextUpdate"), "dateTime", "2099-01-01T00:00:00Z")
    op = _el(_el(si, "PointersToOtherTSL"), "OtherTSLPointer")
    sdi = _el(_el(_el(op, "ServiceDigitalIdentities"), "ServiceDigitalIdentity"), "DigitalId")
    _x509_el(sdi, national_signer_der)
    _el(op, "TSLLocation", national_url)
    add = _el(op, "AdditionalInformation")
    _el(_el(add, "OtherInformation"), "SchemeTerritory", "DE")
    _el(_el(add, "OtherInformation"), "TSLType",
        "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric")
    return root


def _sign(root, key, cert):
    from signxml import XMLSigner
    pem = cert.public_bytes(Encoding.PEM).decode()
    signed = XMLSigner(signature_algorithm="ecdsa-sha256", digest_algorithm="sha256").sign(
        root, key=key, cert=[pem])
    return etree.tostring(signed)


# --------------------------------------------------------------------------- #
# verify_xades_enveloped — round-trip + fail-closed negatives
# --------------------------------------------------------------------------- #

def test_verify_roundtrip_passes():
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    assert verify_xades_enveloped(signed, [cert_n]) is None    # authentic -> returns None


def test_verify_wrong_cert_rejected():
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    _, other = _cert("Someone Else")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(signed, [other])


def test_verify_tampered_body_rejected():
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    tampered = signed.replace(b"<ns0:SchemeTerritory>DE", b"<ns0:SchemeTerritory>FR")
    assert tampered != signed
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(tampered, [cert_n])


def test_verify_unsigned_rejected():
    _, ca = _cert("CA QC")
    unsigned = etree.tostring(_national_tl(ca.public_bytes(Encoding.DER)))
    _, cert = _cert("TL Signer")
    with pytest.raises(TrustListSignatureError):        # no ds:Signature to verify
        verify_xades_enveloped(unsigned, [cert])


def test_verify_multiple_certs_finds_the_signer():
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    _, decoy = _cert("Decoy")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    # a rollover set: the real signer is not first -> still found
    assert verify_xades_enveloped(signed, [decoy, cert_n]) is None


def test_verify_empty_signer_certs_rejected():
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(signed, [])


def test_verify_dtd_rejected():
    _, cert = _cert("TL Signer")
    dtd = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "x">]>'
           b'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">&a;'
           b'</TrustServiceStatusList>')
    with pytest.raises(TrustListSignatureError):        # signxml forbids DTDs
        verify_xades_enveloped(dtd, [cert])


def test_verify_oversize_rejected():
    _, cert = _cert("TL Signer")
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(b"<x/>" * 100, [cert], max_bytes=10)


def test_verify_backend_unavailable(monkeypatch):
    # simulate the [trustlist] extra not being installed
    _, cert = _cert("TL Signer")
    monkeypatch.setitem(sys.modules, "signxml", None)
    with pytest.raises(TrustListSignatureBackendUnavailable):
        verify_xades_enveloped(b"<x/>", [cert])


def test_verify_xades_roundtrip_with_signed_properties():
    # A REAL XAdES signature (what actual EU trusted lists carry) references the
    # document root, its own SignedProperties and — with signxml's XAdES signer — a
    # co-signed KeyInfo. All accepted; the v1.20.0 1-reference pin rejected this.
    from signxml.xades import XAdESSigner
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    pem = cert_n.public_bytes(Encoding.PEM).decode()
    signed = etree.tostring(
        XAdESSigner(signature_algorithm="ecdsa-sha256", digest_algorithm="sha256").sign(
            _national_tl(ca.public_bytes(Encoding.DER)), key=key_n, cert=[pem]))
    assert signed.count(b"SignedProperties>") > 0
    assert verify_xades_enveloped(signed, [cert_n]) is None


def test_verify_xades_roundtrip_tampered_rejected():
    from signxml.xades import XAdESSigner
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    pem = cert_n.public_bytes(Encoding.PEM).decode()
    signed = etree.tostring(
        XAdESSigner(signature_algorithm="ecdsa-sha256", digest_algorithm="sha256").sign(
            _national_tl(ca.public_bytes(Encoding.DER)), key=key_n, cert=[pem]))
    tampered = signed.replace(b"Example TSP DE", b"Evil TSP DE")
    assert tampered != signed
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(tampered, [cert_n])


# --------------------------------------------------------------------------- #
# XML-Signature-Wrapping — the by-Id relocation attack the URI="" anchor defeats
# --------------------------------------------------------------------------- #

def _sign_by_id(root, key, cert, ref_id):
    """Sign with an enveloped BY-ID reference (URI="#id") — a spec-valid XML-DSig
    shape (not what real EU TLs use) that a tag-only coverage check would accept
    under wrapping."""
    from signxml import XMLSigner, methods
    root.set("Id", ref_id)
    pem = cert.public_bytes(Encoding.PEM).decode()
    signed = XMLSigner(method=methods.enveloped, signature_algorithm="ecdsa-sha256",
                       digest_algorithm="sha256").sign(
        root, key=key, cert=[pem], reference_uri="#" + ref_id)
    return etree.tostring(signed)


def test_verify_rejects_by_id_signature_wrapping():
    # A no-key attacker relocates a legitimately-signed same-tag element under a new
    # attacker root: signxml re-resolves URI="#id" to the moved subtree (digest still
    # matches, tag still == root), but the enveloped URI="" anchor is absent -> rejected.
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    legit = _sign_by_id(_national_tl(ca.public_bytes(Encoding.DER), ), key_n, cert_n, "tsl-root")

    outer = _national_tl(ca.public_bytes(Encoding.DER))
    outer.find(f"{{{TSL}}}TrustServiceProviderList/{{{TSL}}}TrustServiceProvider"
               f"/{{{TSL}}}TSPInformation/{{{TSL}}}TSPName/{{{TSL}}}Name").text = "ROGUE TSP"
    dp = _el(outer, "DistributionPoints")
    dp.append(etree.fromstring(legit))
    forged = etree.tostring(outer)

    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(forged, [cert_n])
    # and the same attack is fail-closed through the one-call consume path
    with pytest.raises(TrustListSignatureError):
        consume_trust_list(forged, verify_signature=verify_xades_enveloped,
                           expected_signer_certs=[cert_n])


def test_verify_accepts_legit_by_id_when_not_wrapped():
    # A by-Id signature that is NOT wrapped still fails closed here: coverage is anchored
    # on the enveloped URI="" reference, which a pure by-Id signature lacks. Real EU TLs
    # (and signxml's default signer) use URI="", so this rejects only the non-standard shape.
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    by_id = _sign_by_id(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n, "tsl-root")
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(by_id, [cert_n])


# --------------------------------------------------------------------------- #
# _check_signed_references — the structural XSW guard, unit-tested directly
# (a validly-signed document with an arbitrary extra Reference cannot be built
# without the signer's key, so the guard's negatives are exercised here)
# --------------------------------------------------------------------------- #

def _refs(*pairs):
    """Each pair is (uri, tag) -> a fake VerifyResult + its SignedInfo URI."""
    from types import SimpleNamespace
    results, uris = [], []
    for uri, tag in pairs:
        el = None if tag is None else etree.Element(tag)
        results.append(SimpleNamespace(signed_xml=el))
        uris.append(uri)
    return results, uris


ROOT = f"{{{TSL}}}TrustServiceStatusList"
SIGNED_PROPS = "{http://uri.etsi.org/01903/v1.3.2#}SignedProperties"
KEY_INFO = "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"


def _check(*pairs):
    from openvc.trustlist.xades import _check_signed_references
    results, uris = _refs(*pairs)
    return _check_signed_references(results, uris, ROOT)


def test_check_refs_accepts_the_legitimate_shapes():
    # enveloped doc reference (URI="") + optional SignedProperties / KeyInfo fragments
    assert _check(("", ROOT)) is None
    assert _check(("", ROOT), ("#sp", SIGNED_PROPS)) is None
    assert _check(("", ROOT), ("#sp", SIGNED_PROPS), ("#ki", KEY_INFO)) is None


def test_check_refs_by_id_root_reference_rejected():
    # the wrapping core: a root-tag element reached by URI="#x", not the enveloped URI=""
    with pytest.raises(TrustListSignatureError):
        _check(("#tsl-root", ROOT))


def test_check_refs_missing_enveloped_reference_rejected():
    with pytest.raises(TrustListSignatureError):        # only a fragment ref
        _check(("#sp", SIGNED_PROPS))
    with pytest.raises(TrustListSignatureError):        # nothing verified at all
        from openvc.trustlist.xades import _check_signed_references
        _check_signed_references([], [], ROOT)


def test_check_refs_duplicate_enveloped_reference_rejected():
    with pytest.raises(TrustListSignatureError):
        _check(("", ROOT), ("", ROOT))


def test_check_refs_enveloped_reference_not_root_rejected():
    # URI="" but resolving to a non-root element (a wrapping variant) is rejected
    with pytest.raises(TrustListSignatureError):
        _check(("", SIGNED_PROPS))


def test_check_refs_smuggled_extra_reference_rejected():
    smuggled = f"{{{TSL}}}TrustServiceProvider"
    with pytest.raises(TrustListSignatureError):
        _check(("", ROOT), ("#x", smuggled))


def test_check_refs_uri_result_length_mismatch_rejected():
    from openvc.trustlist.xades import _check_signed_references
    results, _ = _refs(("", ROOT), ("#sp", SIGNED_PROPS))
    with pytest.raises(TrustListSignatureError):        # fewer URIs than results
        _check_signed_references(results, [""], ROOT)


def test_check_refs_unresolved_reference_rejected():
    with pytest.raises(TrustListSignatureError):        # signed_xml=None (raw/binary ref)
        _check(("", ROOT), ("#x", None))


# --------------------------------------------------------------------------- #
# Integration: consume + full walk over signed LOTL / national TL
# --------------------------------------------------------------------------- #

def test_consume_with_xades_verifier():
    _, ca = _cert("CA QC")
    key_n, cert_n = _cert("TL Signer")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    tl = consume_trust_list(signed, verify_signature=verify_xades_enveloped,
                            expected_signer_certs=[cert_n])
    assert tl.territory == "DE" and len(tl.providers) == 1

    _, wrong = _cert("Wrong")
    with pytest.raises(TrustListSignatureError):
        consume_trust_list(signed, verify_signature=verify_xades_enveloped,
                           expected_signer_certs=[wrong])


def test_walk_lotl_end_to_end_with_real_signatures():
    key_c, cert_c = _cert("EU Commission")          # LOTL signer (caller-pinned root)
    key_n, cert_n = _cert("DE TL Signer")           # national TL signer
    _, ca = _cert("DE Qualified CA")                # the anchor the TL publishes

    national_url = "https://tl.example.de/de-tl.xml"
    national_signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    lotl_signed = _sign(_lotl(national_url, cert_n.public_bytes(Encoding.DER)), key_c, cert_c)
    lotl_url = "https://ec.example/eu-lotl.xml"
    store = {lotl_url: lotl_signed, national_url: national_signed}

    res = walk_lotl(
        lotl_url, lotl_signer_certs=[cert_c],
        verify_signature=verify_xades_enveloped,
        fetch=lambda u: store[u])
    assert res.problems == ()
    assert len(res.anchors) == 1
    assert res.anchors[0].sha256 == __import__("hashlib").sha256(
        ca.public_bytes(Encoding.DER)).hexdigest()      # the published CA is the anchor


def test_walk_lotl_forged_national_tl_is_fail_closed():
    key_c, cert_c = _cert("EU Commission")
    _, cert_n = _cert("DE TL Signer")               # the cert the LOTL vouches for
    key_a, cert_a = _cert("Attacker")               # signs a forged TL with its OWN key
    _, ca = _cert("DE Qualified CA")

    national_url = "https://tl.example.de/de-tl.xml"
    forged = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_a, cert_a)   # not cert_n
    lotl_signed = _sign(_lotl(national_url, cert_n.public_bytes(Encoding.DER)), key_c, cert_c)
    lotl_url = "https://ec.example/eu-lotl.xml"
    store = {lotl_url: lotl_signed, national_url: forged}

    res = walk_lotl(lotl_url, lotl_signer_certs=[cert_c],
                    verify_signature=verify_xades_enveloped, fetch=lambda u: store[u])
    assert res.anchors == ()                        # forged TL (unvouched signer) -> no anchors
    assert len(res.problems) == 1 and res.problems[0].stage == "signature"
