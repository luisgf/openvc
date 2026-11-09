"""
tests/test_mdoc_iaca_country.py — ISO/IEC 18013-5 §9.3.3: the mdoc document signer and the
IACA anchor its chain validates to share the subject ``countryName`` (mandatory on both) and
the ``stateOrProvinceName`` when both carry it; the result exposes both subjects (#383).

Before #383 ``resolve_mdoc_signer_key`` path-validated the ``x5chain`` and required the DS
EKU only, so a verifier trusting several IACAs (every member state's, in an EUDI deployment)
accepted a DS issued under one country's anchor for a document naming another, and
``VerifiedMdoc`` exposed only ``issuer_key``. The certificate builders are copied from
``test_mdoc.py`` with explicit ``C`` / ``ST`` knobs — ``tests/`` is not a package.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc import cbor, mdoc
from openvc.keys import P256SigningKey
from openvc.openid4vp import dcapi_session_transcript, verify_vp_token
from openvc.x5c import X5cError, resolve_mdoc_signer, resolve_mdoc_signer_key

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "mdoc"
DOCTYPE = "org.iso.18013.5.1.mDL"
NS = "org.iso.18013.5.1"
ORIGIN = "https://verifier.example"
NONCE = "abcdefgh-nonce-0123456789"

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_PAST, _FUTURE = NOW - dt.timedelta(days=3650), NOW + dt.timedelta(days=3650)
_CA_KU = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)
_MDOC_DS_EKU = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")])
SESSION_TRANSCRIPT = dcapi_session_transcript(ORIGIN, NONCE)
DER = serialization.Encoding.DER


# --------------------------------------------------------------------------- #
# Certificate builders with explicit subject attributes (test-only)
# --------------------------------------------------------------------------- #

def _name(cn, *, c="UT", st=None, extra=()):
    attrs = []
    if c is not None:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if st is not None:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    attrs.extend(extra)
    return x509.Name(attrs)


def _iaca(*, c="UT", st=None, cn=None, extra=(), path_length=0):
    """A self-signed IACA root. Returns (cert, key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(cn or f"IACA {c or 'nowhere'}", c=c, st=st, extra=extra)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(_CA_KU, critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _sub_ca(issuer, issuer_key, *, c="UT", st=None, cn="sub ca"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn, c=c, st=st)).issuer_name(issuer.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_CA_KU, critical=True)
            .sign(issuer_key, hashes.SHA256()))
    return cert, key


def _ds(issuer, issuer_key, *, c="UT", st=None, cn="utopia ds", extra=()):
    """A document-signer cert issued by *issuer* (an IACA or a sub-CA). Returns (cert, key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn, c=c, st=st, extra=extra)).issuer_name(issuer.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_MDOC_DS_EKU, critical=False)
            .sign(issuer_key, hashes.SHA256()))
    return cert, key


# --------------------------------------------------------------------------- #
# DeviceResponse builder (COSE helpers copied from test_mdoc.py)
# --------------------------------------------------------------------------- #

def _cose_sign1(payload, priv, *, x5chain=None, detached=False):
    signer = P256SigningKey(priv, kid="k")
    protected = cbor.encode({1: -7})
    unprotected = {} if x5chain is None else {33: x5chain}
    tbs = cbor.encode(["Signature1", protected, b"", payload])
    return [protected, unprotected, (None if detached else payload), signer.sign(tbs)]


def _cose_key(pub):
    nums = pub.public_numbers()
    return {1: 2, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}


def _issuer_item_bytes(digest_id, element_id, value):
    item = {"digestID": digest_id, "random": bytes([digest_id % 256]) * 16,
            "elementIdentifier": element_id, "elementValue": value}
    return cbor.encode(cbor.CborTag(24, cbor.encode(item)))


def _tdate(when):
    # isoformat, not strftime: glibc's %Y renders year 1 as "1", not "0001"
    utc = when.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return cbor.CborTag(0, utc.isoformat(timespec="seconds") + "Z")


def _device_response(ds_cert, ds_key, *, intermediates=(), issuing_country="UT",
                     mso_signer=None):
    """A DeviceResponse sealed by *ds_cert* (``x5chain`` = DS [+ intermediates]) and
    device-signed for SESSION_TRANSCRIPT. *mso_signer* lets the MSO be signed by a key other
    than the DS's (a bogus seal)."""
    items = [(0, "family_name", "Doe"), (1, "issuing_country", issuing_country)]
    ns_items, digests = [], {}
    for did, eid, val in items:
        raw = _issuer_item_bytes(did, eid, val)
        ns_items.append(cbor.decode(raw))
        digests[did] = hashlib.sha256(raw).digest()
    device_key = ec.generate_private_key(ec.SECP256R1())
    mso = {
        "version": "1.0", "digestAlgorithm": "SHA-256",
        "valueDigests": {NS: digests},
        "deviceKeyInfo": {"deviceKey": _cose_key(device_key.public_key())},
        "docType": DOCTYPE,
        "validityInfo": {"signed": _tdate(NOW), "validFrom": _tdate(_PAST),
                         "validUntil": _tdate(_FUTURE)},
    }
    ders = [ds_cert.public_bytes(DER)] + [c.public_bytes(DER) for c in intermediates]
    x5chain = ders[0] if len(ders) == 1 else ders
    issuer_auth = _cose_sign1(cbor.encode(cbor.CborTag(24, cbor.encode(mso))),
                              mso_signer or ds_key, x5chain=x5chain)
    device_ns_bytes = cbor.encode(cbor.CborTag(24, cbor.encode({})))
    device_authentication = cbor.encode(
        ["DeviceAuthentication", cbor.CborRaw(SESSION_TRANSCRIPT), DOCTYPE,
         cbor.CborRaw(device_ns_bytes)])
    da_bytes = cbor.encode(cbor.CborTag(24, device_authentication))
    document = {
        "docType": DOCTYPE,
        "issuerSigned": {"nameSpaces": {NS: ns_items}, "issuerAuth": issuer_auth},
        "deviceSigned": {"nameSpaces": cbor.decode(device_ns_bytes),
                         "deviceAuth": {"deviceSignature": _cose_sign1(da_bytes, device_key,
                                                                       detached=True)}},
    }
    return cbor.encode({"version": "1.0", "documents": [document], "status": 0})


def _verify(device_response, anchors):
    return mdoc.verify_device_response(
        device_response, trust_anchors=anchors, session_transcript=SESSION_TRANSCRIPT, now=NOW)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
# Refusals (the point of #383)
# --------------------------------------------------------------------------- #

def test_country_mismatch_under_a_trusted_iaca_is_refused():
    # An EU-style verifier trusts two IACAs. A DS that chains to the UT anchor but claims
    # C=DE was accepted before #383 — the measured gap.
    ut, ut_key = _iaca(c="UT")
    de, _ = _iaca(c="DE")
    ds, ds_key = _ds(ut, ut_key, c="DE")
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"countryName 'DE' is not its IACA anchor's 'UT' "
                             r"\(ISO 18013-5 9\.3\.3\)"):
        _verify(_device_response(ds, ds_key, issuing_country="DE"), [ut, de])


def test_state_mismatch_when_both_carry_it_is_refused():
    ut, ut_key = _iaca(c="UT", st="Utopia-North")
    ds, ds_key = _ds(ut, ut_key, c="UT", st="Elsewhere")
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"stateOrProvinceName 'Elsewhere' is not its IACA anchor's "
                             r"'Utopia-North'"):
        _verify(_device_response(ds, ds_key), [ut])


def test_ds_without_country_is_refused():
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c=None)
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"document-signer certificate subject has no countryName"):
        _verify(_device_response(ds, ds_key), [ut])


def test_iaca_without_country_is_refused():
    # Annex B mandates C on the IACA too; an anchor without it cannot anchor the comparison.
    lab, lab_key = _iaca(c=None, cn="lab iaca")
    ds, ds_key = _ds(lab, lab_key, c="UT")
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"IACA anchor certificate subject has no countryName"):
        _verify(_device_response(ds, ds_key), [lab])


def test_country_on_neither_side_is_refused():
    # The shape of the pre-#383 self-generated fixtures: CN-only subjects everywhere.
    lab, lab_key = _iaca(c=None, cn="lab iaca")
    ds, ds_key = _ds(lab, lab_key, c=None)
    with pytest.raises(mdoc.MdocTrustError, match="has no countryName"):
        _verify(_device_response(ds, ds_key), [lab])


def test_country_comparison_is_exact():
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c="ut")                 # same letters, other case
    with pytest.raises(mdoc.MdocTrustError, match=r"'ut' is not its IACA anchor's 'UT'"):
        _verify(_device_response(ds, ds_key), [ut])


@pytest.mark.parametrize("ds_st", ["utopia-north", "Utopia-North ", "Utopia-North​"],
                         ids=["case", "trailing-space", "zero-width"])
def test_state_comparison_is_exact(ds_st):
    ut, ut_key = _iaca(c="UT", st="Utopia-North")
    ds, ds_key = _ds(ut, ut_key, c="UT", st=ds_st)
    with pytest.raises(mdoc.MdocTrustError, match="stateOrProvinceName"):
        _verify(_device_response(ds, ds_key), [ut])


def test_repeated_country_attribute_is_refused_even_when_one_matches():
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c="UT",
                     extra=[x509.NameAttribute(NameOID.COUNTRY_NAME, "DE")])
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"document-signer certificate subject carries 2 C attributes"):
        _verify(_device_response(ds, ds_key), [ut])


def test_repeated_state_attribute_is_refused_even_when_one_matches():
    ut, ut_key = _iaca(c="UT", st="Utopia-North")
    ds, ds_key = _ds(ut, ut_key, c="UT", st="Utopia-North",
                     extra=[x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Elsewhere")])
    with pytest.raises(mdoc.MdocTrustError, match=r"carries 2 ST attributes"):
        _verify(_device_response(ds, ds_key), [ut])


def test_repeated_attribute_on_the_anchor_is_refused_too():
    ut, ut_key = _iaca(c="UT", extra=[x509.NameAttribute(NameOID.COUNTRY_NAME, "UT")])
    ds, ds_key = _ds(ut, ut_key, c="UT")
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"IACA anchor certificate subject carries 2 C attributes"):
        _verify(_device_response(ds, ds_key), [ut])


def test_an_intermediate_does_not_become_the_comparison_anchor():
    # DS (C=DE) <- sub-CA (C=DE) <- IACA (C=UT): the DS matches the CA that issued it, but
    # §9.3.3 compares against the trust anchor the chain validated to.
    ut, ut_key = _iaca(c="UT", path_length=None)
    sub, sub_key = _sub_ca(ut, ut_key, c="DE")
    ds, ds_key = _ds(sub, sub_key, c="DE")
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"countryName 'DE' is not its IACA anchor's 'UT'"):
        _verify(_device_response(ds, ds_key, intermediates=[sub]), [ut])


def test_mismatch_is_refused_before_the_seal_is_checked():
    # The chain is judged before the MSO signature: a bogus seal under a mismatching DS is
    # a trust refusal, never a signature question — nothing attacker-chosen is verified first.
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c="DE")
    bogus = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(mdoc.MdocTrustError):
        _verify(_device_response(ds, ds_key, mso_signer=bogus), [ut])


def test_refusal_message_is_bounded():
    long_st = "X" * 5000
    ut, ut_key = _iaca(c="UT", st="Utopia-North")
    ds, ds_key = _ds(ut, ut_key, c="UT", st=long_st)
    with pytest.raises(mdoc.MdocTrustError) as excinfo:
        _verify(_device_response(ds, ds_key), [ut])
    message = str(excinfo.value)
    assert long_st not in message and len(message) < 600


def test_the_key_only_entry_point_enforces_the_same_rule():
    ut, ut_key = _iaca(c="UT")
    ds, _ = _ds(ut, ut_key, c="DE")
    with pytest.raises(X5cError, match=r"ISO 18013-5 9\.3\.3"):
        resolve_mdoc_signer_key([ds.public_bytes(DER)], trust_anchors=[ut], now=NOW)
    with pytest.raises(X5cError, match=r"ISO 18013-5 9\.3\.3"):
        resolve_mdoc_signer([ds.public_bytes(DER)], trust_anchors=[ut], now=NOW)


def test_verify_vp_token_refuses_the_mismatch():
    ut, ut_key = _iaca(c="UT")
    de, _ = _iaca(c="DE")
    ds, ds_key = _ds(ut, ut_key, c="DE")
    dcql = {"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}
    with pytest.raises(mdoc.MdocTrustError, match=r"ISO 18013-5 9\.3\.3"):
        verify_vp_token({"mdl": [_b64url(_device_response(ds, ds_key, issuing_country="DE"))]},
                        dcql_query=dcql, nonce=NONCE, expected_origins=[ORIGIN],
                        trust_anchors=[ut, de], now=NOW)


# --------------------------------------------------------------------------- #
# Accepted, and what the result exposes
# --------------------------------------------------------------------------- #

def test_conformant_pair_is_accepted_and_both_subjects_are_exposed():
    ut, ut_key = _iaca(c="UT", st="Utopia-North", cn="utopia iaca")
    de, _ = _iaca(c="DE")
    ds, ds_key = _ds(ut, ut_key, c="UT", st="Utopia-North", cn="utopia ds")
    [doc] = _verify(_device_response(ds, ds_key), [de, ut])      # DE listed first
    assert doc.device_signed is True
    assert doc.ds_subject == {"C": "UT", "ST": "Utopia-North", "CN": "utopia ds"}
    assert doc.anchor_subject == {"C": "UT", "ST": "Utopia-North", "CN": "utopia iaca"}
    # the caller's Table B.1 cross-check, as the wiki shows it
    assert doc.elements(NS)["issuing_country"] == doc.ds_subject["C"]


def test_anchor_subject_is_the_matched_anchor_not_a_same_named_one():
    ut, ut_key = _iaca(c="UT", cn="utopia iaca")
    twin, _ = _iaca(c="DE", cn="utopia iaca")                   # same CN, other country+key
    ds, ds_key = _ds(ut, ut_key, c="UT")
    [doc] = _verify(_device_response(ds, ds_key), [twin, ut])
    assert doc.anchor_subject["C"] == "UT"


@pytest.mark.parametrize("iaca_st,ds_st", [("Utopia-North", None), (None, "Utopia-North")],
                         ids=["iaca-only", "ds-only"])
def test_state_absent_on_one_side_is_no_constraint(iaca_st, ds_st):
    ut, ut_key = _iaca(c="UT", st=iaca_st)
    ds, ds_key = _ds(ut, ut_key, c="UT", st=ds_st)
    [doc] = _verify(_device_response(ds, ds_key), [ut])
    assert ("ST" in doc.anchor_subject) is (iaca_st is not None)
    assert ("ST" in doc.ds_subject) is (ds_st is not None)


def test_single_anchor_deployment_is_unchanged():
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c="UT")
    [doc] = _verify(_device_response(ds, ds_key), [ut])
    assert doc.doc_type == DOCTYPE
    assert doc.ds_subject["C"] == doc.anchor_subject["C"] == "UT"


def test_organization_is_exposed_when_present():
    org = NameOID.ORGANIZATION_NAME
    ut, ut_key = _iaca(c="UT", extra=[x509.NameAttribute(org, "Utopia DMV")])
    ds, ds_key = _ds(ut, ut_key, c="UT", extra=[x509.NameAttribute(org, "Utopia DMV DS")])
    [doc] = _verify(_device_response(ds, ds_key), [ut])
    assert doc.anchor_subject["O"] == "Utopia DMV"
    assert doc.ds_subject["O"] == "Utopia DMV DS"


def test_conformant_intermediate_keeps_the_root_as_anchor_subject():
    ut, ut_key = _iaca(c="UT", cn="utopia iaca", path_length=None)
    sub, sub_key = _sub_ca(ut, ut_key, c="UT", cn="utopia sub ca")
    ds, ds_key = _ds(sub, sub_key, c="UT")
    [doc] = _verify(_device_response(ds, ds_key, intermediates=[sub]), [ut])
    assert doc.anchor_subject["CN"] == "utopia iaca"             # the root, not the sub-CA


def test_issuer_signed_entry_point_exposes_the_subjects_too():
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c="UT")
    document = cbor.decode(_device_response(ds, ds_key))["documents"][0]
    result = mdoc.verify_issuer_signed(document, trust_anchors=[ut], now=NOW)
    assert result.device_signed is False
    assert result.ds_subject["C"] == result.anchor_subject["C"] == "UT"


def test_verify_vp_token_exposes_the_subjects():
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds(ut, ut_key, c="UT")
    dcql = {"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}
    result = verify_vp_token({"mdl": [_b64url(_device_response(ds, ds_key))]},
                             dcql_query=dcql, nonce=NONCE, expected_origins=[ORIGIN],
                             trust_anchors=[ut], now=NOW)
    mdl = result.for_query("mdl")[0].credentials[0]
    assert mdl.elements(NS)["issuing_country"] == mdl.ds_subject["C"] == "UT"


def test_resolve_mdoc_signer_returns_key_and_subjects():
    ut, ut_key = _iaca(c="UT", st="Utopia-North")
    ds, _ = _ds(ut, ut_key, c="UT")
    signer = resolve_mdoc_signer([ds.public_bytes(DER)], trust_anchors=[ut], now=NOW)
    assert signer.public_jwk["crv"] == "P-256"
    assert signer.ds_subject == {"C": "UT", "CN": "utopia ds"}
    assert signer.anchor_subject == {"C": "UT", "ST": "Utopia-North", "CN": "IACA UT"}
    assert resolve_mdoc_signer_key([ds.public_bytes(DER)], trust_anchors=[ut],
                                   now=NOW) == signer.public_jwk


def test_annex_d_golden_still_verifies_and_exposes_its_subjects():
    # The real ISO 18013-5 Annex D vector carries C=US on both sides.
    dr = bytes.fromhex((FIXTURES / "annex_d_device_response.hex").read_text().strip())
    iaca = x509.load_pem_x509_certificate((FIXTURES / "annex_d_iaca_root.pem").read_bytes())
    document = cbor.decode(dr)["documents"][0]
    result = mdoc.verify_issuer_signed(
        document, trust_anchors=[iaca], now=dt.datetime(2020, 12, 1, tzinfo=dt.timezone.utc))
    assert result.ds_subject == {"C": "US", "CN": "utopia ds"}
    assert result.anchor_subject == {"C": "US", "CN": "utopia iaca"}


def test_verified_mdoc_stays_add_only():
    # A pre-#383 positional construction keeps working; the new fields default to empty.
    validity = mdoc.MdocValidity(None, None, None)
    result = mdoc.VerifiedMdoc(DOCTYPE, {}, False, {"kty": "EC"}, validity)
    assert result.ds_subject == {} and result.anchor_subject == {}
