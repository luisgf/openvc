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
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
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
    return _device_response_from_der(ds_cert.public_bytes(DER), ds_key, intermediates=intermediates,
                                     issuing_country=issuing_country, mso_signer=mso_signer)


def _device_response_from_der(ds_der, ds_key, *, intermediates=(), issuing_country="UT",
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
    ders = [ds_der] + [c.public_bytes(DER) for c in intermediates]
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
# DER surgery: patch bytes inside the TBSCertificate and re-sign with the issuer key, so a
# certificate with a subject value no builder would emit is still genuinely path-valid.
# --------------------------------------------------------------------------- #

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _read_tlv(buf, pos):
    tag, first = buf[pos], buf[pos + 1]
    if first < 0x80:
        length, header = first, 2
    else:
        nbytes = first & 0x7F
        length, header = int.from_bytes(buf[pos + 2:pos + 2 + nbytes], "big"), 2 + nbytes
    return tag, pos + header, pos + header + length


def _resign_with_patch(cert_der, old, new, issuer_key, *, count=1):
    """Replace *old* by *new* inside the TBSCertificate of *cert_der* and re-sign the TBS
    with *issuer_key* (ECDSA P-256 / SHA-256). *old* must occur exactly *count* times."""
    tag, start, end = _read_tlv(cert_der, 0)
    assert tag == 0x30 and end == len(cert_der)
    _, _, tbs_end = _read_tlv(cert_der, start)
    tbs = cert_der[start:tbs_end]
    assert tbs.count(old) == count, (tbs.count(old), old)
    tbs = tbs.replace(old, new)
    _, _, alg_end = _read_tlv(cert_der, tbs_end)
    sig_alg = cert_der[tbs_end:alg_end]
    sig = issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    bitstr = b"\x03" + _der_len(len(sig) + 1) + b"\x00" + sig
    body = tbs + sig_alg + bitstr
    return b"\x30" + _der_len(len(body)) + body


# OID 2.5.4.6 (countryName) followed by a UTF8String "UT": the byte pattern the DS below
# carries once (its issuer's C is a PrintableString), so a patch hits only the DS subject.
_UTF8_C_UT = b"\x06\x03\x55\x04\x06\x0c\x02UT"
_MALFORMED_C = [
    ("invalid-utf8", b"\x06\x03\x55\x04\x06\x0c\x02\xff\xfe"),
    ("lone-continuation-byte", b"\x06\x03\x55\x04\x06\x0c\x02\x80U"),
    ("integer-tag", b"\x06\x03\x55\x04\x06\x02\x02UT"),
    ("tag-0x05", b"\x06\x03\x55\x04\x06\x05\x02UT"),
    ("context-tag-0x80", b"\x06\x03\x55\x04\x06\x80\x02UT"),
    ("bit-string", b"\x06\x03\x55\x04\x06\x03\x02\x00U"),
]


def _utf8_c_name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "UT", _type=_ASN1Type.UTF8String),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _unvalidated_c_name(c, cn="x"):
    # cryptography refuses a C that is not 2 characters at build time; the parser does not.
    # (The builders warn about it too — silenced here so a test's own warning capture sees
    # only what the verify path emits.)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, c, _validate=False),
                          x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ds_with_subject(issuer, issuer_key, subject):
    key = ec.generate_private_key(ec.SECP256R1())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")                  # see _unvalidated_c_name
        issuer_name = issuer.subject
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_MDOC_DS_EKU, critical=False)
            .sign(issuer_key, hashes.SHA256()))
    return cert, key


def _iaca_with_subject(subject):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_CA_KU, critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


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


def test_repeated_country_on_the_anchor_is_refused_too():
    ut, ut_key = _iaca(c="UT", extra=[x509.NameAttribute(NameOID.COUNTRY_NAME, "UT")])
    ds, ds_key = _ds(ut, ut_key, c="UT")
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"IACA anchor certificate subject carries 2 C attributes"):
        _verify(_device_response(ds, ds_key), [ut])


# --- malformed subjects: path-valid certificates whose Name the verifier is the first to decode

@pytest.mark.parametrize("patch", [p for _, p in _MALFORMED_C], ids=[n for n, _ in _MALFORMED_C])
def test_malformed_ds_subject_is_a_typed_refusal(patch):
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds_with_subject(ut, ut_key, _utf8_c_name("utopia ds"))
    der = _resign_with_patch(ds.public_bytes(DER), _UTF8_C_UT, patch, ut_key)
    x509.load_der_x509_certificate(der)                  # loads; the Name decodes lazily
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"document-signer certificate subject cannot be decoded") as excinfo:
        _verify(_device_response_from_der(der, ds_key), [ut])
    assert len(str(excinfo.value)) < 200                 # nothing of the attribute is echoed
    with pytest.raises(X5cError, match="cannot be decoded"):
        resolve_mdoc_signer([der], trust_anchors=[ut], now=NOW)


def test_malformed_anchor_subject_is_a_typed_refusal():
    bad_c = _MALFORMED_C[0][1]                           # invalid UTF-8
    root, root_key = _iaca_with_subject(_utf8_c_name("root"))
    root_der = _resign_with_patch(root.public_bytes(DER), _UTF8_C_UT, bad_c, root_key, count=2)
    ds, ds_key = _ds(root, root_key, c="UT")             # its issuer must carry the same bytes
    ds_der = _resign_with_patch(ds.public_bytes(DER), _UTF8_C_UT, bad_c, root_key)
    with pytest.raises(mdoc.MdocTrustError,
                       match=r"IACA anchor certificate subject cannot be decoded"):
        _verify(_device_response_from_der(ds_der, ds_key),
                [x509.load_der_x509_certificate(root_der)])


@pytest.mark.parametrize("c", ["UTX", "UT ", "U", ""],
                         ids=["three", "trailing-space", "one", "empty"])
def test_country_not_two_characters_is_refused_without_a_warning(c):
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds_with_subject(ut, ut_key, _unvalidated_c_name(c))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(mdoc.MdocTrustError,
                           match=r"countryName .* is not a 2-character ISO 3166-1 alpha-2 code"):
            _verify(_device_response(ds, ds_key), [ut])
    assert caught == []                                  # cryptography's UserWarning is silenced


def test_country_length_rule_holds_under_warnings_as_errors():
    # `python -W error` turned the lazy-decode UserWarning into a bare exception; not any more.
    ut, ut_key = _iaca(c="UT")
    ds, ds_key = _ds_with_subject(ut, ut_key, _unvalidated_c_name("UTX"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(mdoc.MdocTrustError, match="alpha-2"):
            _verify(_device_response(ds, ds_key), [ut])


def test_three_letter_country_equal_on_both_sides_is_still_refused():
    # Equality alone would accept 'UTX' == 'UTX'; §9.3.3 compares alpha-2 codes.
    root, root_key = _iaca_with_subject(_unvalidated_c_name("UTX", cn="root"))
    ds, ds_key = _ds_with_subject(root, root_key, _unvalidated_c_name("UTX"))
    with pytest.raises(mdoc.MdocTrustError, match="alpha-2"):
        _verify(_device_response(ds, ds_key), [root])


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


def test_repeated_cn_or_o_is_informational_and_omitted():
    cn, org = NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME
    ut, ut_key = _iaca(c="UT", extra=[x509.NameAttribute(org, "o1"), x509.NameAttribute(org, "o1")])
    ds, ds_key = _ds(ut, ut_key, c="UT", extra=[x509.NameAttribute(cn, "second cn")])
    [doc] = _verify(_device_response(ds, ds_key), [ut])   # accepted: §9.3.3 names C and ST only
    assert "CN" not in doc.ds_subject and doc.ds_subject["C"] == "UT"
    assert "O" not in doc.anchor_subject and doc.anchor_subject["CN"] == "IACA UT"


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
