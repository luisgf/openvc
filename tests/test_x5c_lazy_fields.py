"""
tests/test_x5c_lazy_fields.py — a certificate that chains to a trusted anchor but carries a
malformed EKU / SAN / SPKI is a typed refusal on every lane, never a bare ``cryptography``
exception (#430).

``cryptography`` decodes extension values, SAN name forms and the SubjectPublicKeyInfo on
first access, and path validation (``ee_policy=permit_all``) never touches them on the end
entity. The readers that run after the chain validated — the mdoc DS-EKU check, the
``iss``→SAN binding, the leaf-key-to-JWK step, the WRPRC EKU gate — were outside any ``try``:
the failure escaped ``OpenvcError`` and aborted a ``verify_many`` batch and the origin loop
of ``verify_vp_token``. Certificates here are genuinely path-valid: a malformed field is
either an ``UnrecognizedExtension`` carrying the real OID, or DER patched inside the
TBSCertificate and re-signed with the CA key. ``tests/`` is not a package, so the builders
are local.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc import VerificationPolicy, cbor, mdoc, verify_credential, verify_many
from openvc.keys import P256SigningKey
from openvc.openid4vp import dcapi_session_transcript, verify_vp_token
from openvc.proof._jws import sign_compact
from openvc.rp_registration import RpRegistrationError, verify_rp_registration_certificate
from openvc.verify import KeyResolutionFailed
from openvc.x5c import X5cError, resolve_mdoc_signer, resolve_x5c_key

DOCTYPE = "org.iso.18013.5.1.mDL"
NS = "org.iso.18013.5.1"
ORIGIN = "https://verifier.example"
NONCE = "abcdefgh-nonce-0123456789"
ISS = "https://issuer.example"
DER = serialization.Encoding.DER

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_PAST, _FUTURE = NOW - dt.timedelta(days=3650), NOW + dt.timedelta(days=3650)
SESSION_TRANSCRIPT = dcapi_session_transcript(ORIGIN, NONCE)

EKU_OID = x509.ObjectIdentifier("2.5.29.37")
SAN_OID = x509.ObjectIdentifier("2.5.29.17")
DS_EKU = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")])
GOOD_SAN = x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ISS)])
_CA_KU = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)

# garbage that is not a DER EKU / a SAN holding an x400Address ([3] ORAddress)
BAD_EKU = x509.UnrecognizedExtension(EKU_OID, b"\xff\xff\xff")
X400_SAN = x509.UnrecognizedExtension(SAN_OID, b"\x30\x04\xa3\x02\x30\x00")


# --------------------------------------------------------------------------- #
# Builders (test-only)
# --------------------------------------------------------------------------- #

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "UT"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@pytest.fixture(scope="module")
def ca():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(_name("test IACA")).issuer_name(_name("test IACA"))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_CA_KU, critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _leaf(ca, *extensions):
    """(DER, key): an end entity issued by the test CA carrying *extensions*."""
    ca_cert, ca_key = ca
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder()
               .subject_name(_name("ds")).issuer_name(ca_cert.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(_PAST).not_valid_after(_FUTURE)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(DER), key


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


def _resign_with_patch(cert_der, old, new, ca_key):
    """Replace *old* (exactly once) by *new* inside the TBSCertificate and re-sign the TBS
    with the CA key (ECDSA P-256 / SHA-256): a certificate no builder would emit that still
    chains to the CA."""
    _, start, _ = _read_tlv(cert_der, 0)
    _, _, tbs_end = _read_tlv(cert_der, start)
    tbs = cert_der[start:tbs_end]
    assert tbs.count(old) == 1, (tbs.count(old), old)
    tbs = tbs.replace(old, new)
    _, _, alg_end = _read_tlv(cert_der, tbs_end)
    sig_alg = cert_der[tbs_end:alg_end]
    sig = ca_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    body = tbs + sig_alg + b"\x03" + _der_len(len(sig) + 1) + b"\x00" + sig
    return b"\x30" + _der_len(len(body)) + body


_EC_PUBLIC_KEY_OID = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
_P256_OID = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"


def _spki_unknown_algorithm(ca, *extensions):
    der, key = _leaf(ca, *extensions)
    return _resign_with_patch(
        der, _EC_PUBLIC_KEY_OID, _EC_PUBLIC_KEY_OID[:-1] + b"\x09", ca[1]), key


def _spki_unknown_curve(ca, *extensions):
    der, key = _leaf(ca, *extensions)
    return _resign_with_patch(der, _P256_OID, _P256_OID[:-1] + b"\x08", ca[1]), key


def _spki_off_curve(ca, *extensions):
    der, key = _leaf(ca, *extensions)
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    bad = point[:-1] + bytes([point[-1] ^ 0x01])
    return _resign_with_patch(der, point, bad, ca[1]), key


def _duplicate_extension(ca, *extensions, oid=EKU_OID, value=DS_EKU):
    """A leaf carrying the extension *oid* twice (the second spelled as an unrecognised one
    under a sibling OID and patched to *oid*)."""
    decoy = x509.ObjectIdentifier("2.5.29.99")
    # 06 03 55 1d 63 -> 06 03 55 1d <last arc of oid>
    twin = x509.UnrecognizedExtension(decoy, value.public_bytes() if hasattr(value, "public_bytes")
                                      else b"\x30\x00")
    der, key = _leaf(ca, *extensions, twin)
    arc = oid.dotted_string.rsplit(".", 1)[1]
    return _resign_with_patch(
        der, b"\x06\x03\x55\x1d\x63", b"\x06\x03\x55\x1d" + bytes([int(arc)]), ca[1]), key


# --------------------------------------------------------------------------- #
# mdoc DeviceResponse builder
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
    utc = when.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return cbor.CborTag(0, utc.isoformat(timespec="seconds") + "Z")


def _device_response(ds_der, ds_key):
    raw = _issuer_item_bytes(0, "family_name", "Doe")
    device_key = ec.generate_private_key(ec.SECP256R1())
    mso = {
        "version": "1.0", "digestAlgorithm": "SHA-256",
        "valueDigests": {NS: {0: hashlib.sha256(raw).digest()}},
        "deviceKeyInfo": {"deviceKey": _cose_key(device_key.public_key())},
        "docType": DOCTYPE,
        "validityInfo": {"signed": _tdate(NOW), "validFrom": _tdate(_PAST),
                         "validUntil": _tdate(_FUTURE)},
    }
    issuer_auth = _cose_sign1(cbor.encode(cbor.CborTag(24, cbor.encode(mso))), ds_key,
                              x5chain=ds_der)
    device_ns_bytes = cbor.encode(cbor.CborTag(24, cbor.encode({})))
    device_authentication = cbor.encode(
        ["DeviceAuthentication", cbor.CborRaw(SESSION_TRANSCRIPT), DOCTYPE,
         cbor.CborRaw(device_ns_bytes)])
    da_bytes = cbor.encode(cbor.CborTag(24, device_authentication))
    document = {
        "docType": DOCTYPE,
        "issuerSigned": {"nameSpaces": {NS: [cbor.decode(raw)]}, "issuerAuth": issuer_auth},
        "deviceSigned": {"nameSpaces": cbor.decode(device_ns_bytes),
                         "deviceAuth": {"deviceSignature": _cose_sign1(
                             da_bytes, device_key, detached=True)}},
    }
    return cbor.encode({"version": "1.0", "documents": [document], "status": 0})


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _vp_token(ds_der, ds_key, anchors):
    return verify_vp_token(
        {"mdl": [_b64url(_device_response(ds_der, ds_key))]},
        dcql_query={"credentials": [{"id": "mdl", "format": "mso_mdoc"}]},
        nonce=NONCE, expected_origins=[ORIGIN], trust_anchors=anchors, now=NOW)


# --------------------------------------------------------------------------- #
# VC-JWT builder for the x5c issuer lane
# --------------------------------------------------------------------------- #

def _vc_jwt(leaf_key, leaf_der):
    ts = int(time.time())
    header = {"alg": "ES256", "typ": "JWT", "kid": "leaf",
              "x5c": [base64.b64encode(leaf_der).decode()]}
    payload = {
        "iss": ISS, "nbf": ts, "iat": ts,
        "vc": {"@context": ["https://www.w3.org/ns/credentials/v2"], "id": "urn:uuid:1",
               "type": ["VerifiableCredential"], "issuer": ISS,
               "credentialSubject": {"id": "did:example:subject"}},
    }
    return sign_compact(header, payload, signing_key=P256SigningKey(leaf_key, kid="leaf"))


def _x5c_b64(der):
    return [base64.b64encode(der).decode()]


POLICY = VerificationPolicy(require_status=False)

# the malformed-SPKI leaves, by name (each is built with the extensions a lane needs)
SPKI_CASES = [("unknown-algorithm-oid", _spki_unknown_algorithm),
              ("unknown-curve-oid", _spki_unknown_curve),
              ("off-curve-point", _spki_off_curve)]


# --------------------------------------------------------------------------- #
# mdoc lane -> MdocTrustError
# --------------------------------------------------------------------------- #

def test_mdoc_control_good_ds_is_accepted(ca):
    der, key = _leaf(ca, DS_EKU)
    assert resolve_mdoc_signer([der], trust_anchors=[ca[0]], now=NOW).public_jwk["crv"] == "P-256"
    doc = _vp_token(der, key, [ca[0]]).for_query("mdl")[0].credentials[0]
    assert doc.device_signed is True


def test_mdoc_ds_with_undecodable_eku_is_typed(ca):
    der, key = _leaf(ca, BAD_EKU)
    with pytest.raises(X5cError, match="ExtendedKeyUsage extension cannot be decoded"):
        resolve_mdoc_signer([der], trust_anchors=[ca[0]], now=NOW)
    with pytest.raises(mdoc.MdocTrustError, match="ExtendedKeyUsage extension cannot be decoded"):
        mdoc.verify_device_response(_device_response(der, key), trust_anchors=[ca[0]],
                                    session_transcript=SESSION_TRANSCRIPT, now=NOW)
    with pytest.raises(mdoc.MdocTrustError, match="ExtendedKeyUsage extension cannot be decoded"):
        _vp_token(der, key, [ca[0]])


def test_mdoc_ds_with_a_repeated_eku_is_typed(ca):
    der, key = _duplicate_extension(ca, DS_EKU)
    with pytest.raises(X5cError):
        resolve_mdoc_signer([der], trust_anchors=[ca[0]], now=NOW)
    with pytest.raises(mdoc.MdocTrustError):
        _vp_token(der, key, [ca[0]])


@pytest.mark.parametrize("build", [b for _, b in SPKI_CASES], ids=[n for n, _ in SPKI_CASES])
def test_mdoc_ds_with_an_unusable_key_is_typed(ca, build):
    der, key = build(ca, DS_EKU)
    with pytest.raises(X5cError, match="public key cannot be decoded"):
        resolve_mdoc_signer([der], trust_anchors=[ca[0]], now=NOW)
    with pytest.raises(mdoc.MdocTrustError, match="public key cannot be decoded"):
        _vp_token(der, key, [ca[0]])


def test_mdoc_message_quotes_nothing_from_the_certificate(ca):
    der, _ = _leaf(ca, BAD_EKU)
    with pytest.raises(X5cError) as excinfo:
        resolve_mdoc_signer([der], trust_anchors=[ca[0]], now=NOW)
    assert str(excinfo.value) == "x5c leaf certificate ExtendedKeyUsage extension cannot be decoded"
    assert excinfo.value.__cause__ is not None


def test_mdoc_missing_eku_keeps_its_own_message(ca):
    der, _ = _leaf(ca)
    with pytest.raises(X5cError, match="has no ExtendedKeyUsage"):
        resolve_mdoc_signer([der], trust_anchors=[ca[0]], now=NOW)


# --------------------------------------------------------------------------- #
# JOSE x5c lane -> KeyResolutionFailed
# --------------------------------------------------------------------------- #

def test_x5c_control_good_san_is_accepted(ca):
    der, key = _leaf(ca, GOOD_SAN)
    assert resolve_x5c_key(_x5c_b64(der), ISS, trust_anchors=[ca[0]], now=NOW)["crv"] == "P-256"
    assert verify_credential(_vc_jwt(key, der), x5c_trust_anchors=[ca[0]],
                             policy=POLICY).issuer == ISS


def test_x5c_leaf_with_an_unsupported_san_name_form_is_typed(ca):
    der, key = _leaf(ca, X400_SAN)
    # the path verifier itself decodes the end entity's SAN for its name checks
    with pytest.raises(X5cError, match="extension that cannot be decoded"):
        resolve_x5c_key(_x5c_b64(der), ISS, trust_anchors=[ca[0]], now=NOW)
    token = _vc_jwt(key, der)
    with pytest.raises(KeyResolutionFailed, match="extension that cannot be decoded"):
        verify_credential(token, x5c_trust_anchors=[ca[0]], policy=POLICY)
    # one hostile credential in a batch is that item's error, not the batch's
    good_der, good_key = _leaf(ca, GOOD_SAN)
    out = verify_many([token, _vc_jwt(good_key, good_der), token],
                      x5c_trust_anchors=[ca[0]], policy=POLICY)
    assert [type(r.error) if r.error else None for r in out] == [
        KeyResolutionFailed, None, KeyResolutionFailed]


def test_x5c_leaf_with_a_repeated_san_is_typed(ca):
    der, key = _duplicate_extension(ca, GOOD_SAN, oid=SAN_OID, value=GOOD_SAN)
    with pytest.raises(X5cError):
        resolve_x5c_key(_x5c_b64(der), ISS, trust_anchors=[ca[0]], now=NOW)
    with pytest.raises(KeyResolutionFailed):
        verify_credential(_vc_jwt(key, der), x5c_trust_anchors=[ca[0]], policy=POLICY)


@pytest.mark.parametrize("build", [b for _, b in SPKI_CASES], ids=[n for n, _ in SPKI_CASES])
def test_x5c_leaf_with_an_unusable_key_is_typed(ca, build):
    der, key = build(ca, GOOD_SAN)
    with pytest.raises(X5cError, match="public key cannot be decoded"):
        resolve_x5c_key(_x5c_b64(der), ISS, trust_anchors=[ca[0]], now=NOW)
    token = _vc_jwt(key, der)
    with pytest.raises(KeyResolutionFailed, match="public key cannot be decoded"):
        verify_credential(token, x5c_trust_anchors=[ca[0]], policy=POLICY)
    out = verify_many([token], x5c_trust_anchors=[ca[0]], policy=POLICY)
    assert isinstance(out[0].error, KeyResolutionFailed)


def test_x5c_missing_san_keeps_its_own_message(ca):
    der, _ = _leaf(ca)
    with pytest.raises(X5cError, match="has no Subject Alternative Name"):
        resolve_x5c_key(_x5c_b64(der), ISS, trust_anchors=[ca[0]], now=NOW)


# --------------------------------------------------------------------------- #
# WRPRC lane -> RpRegistrationError
# --------------------------------------------------------------------------- #

def _wrprc(leaf_der, key):
    head = {"typ": "rc-wrp+jwt", "alg": "ES256", "x5c": _x5c_b64(leaf_der)}
    signing_input = (f"{_b64url_json(head)}.{_b64url_json({'sub': 'x'})}")
    sig = P256SigningKey(key, "registrar").sign(signing_input.encode())
    return f"{signing_input}.{_b64url(sig)}"


def _b64url_json(obj):
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


_WRPRC_EKU = "1.3.6.1.5.5.7.3.3"


def test_wrprc_undecodable_eku_is_typed(ca):
    der, key = _leaf(ca, BAD_EKU)
    with pytest.raises(RpRegistrationError,
                       match="WRPRC signing certificate: .*ExtendedKeyUsage extension cannot"):
        verify_rp_registration_certificate(
            _wrprc(der, key), trust_anchors=[ca[0]], now=NOW, required_eku=_WRPRC_EKU)


def test_wrprc_eku_control_and_missing_keep_their_messages(ca):
    der, key = _leaf(ca)
    with pytest.raises(RpRegistrationError, match="has no extendedKeyUsage"):
        verify_rp_registration_certificate(
            _wrprc(der, key), trust_anchors=[ca[0]], now=NOW, required_eku=_WRPRC_EKU)
    der, key = _leaf(ca, DS_EKU)
    with pytest.raises(RpRegistrationError, match="lacks the required extendedKeyUsage"):
        verify_rp_registration_certificate(
            _wrprc(der, key), trust_anchors=[ca[0]], now=NOW, required_eku=_WRPRC_EKU)


@pytest.mark.parametrize("build", [b for _, b in SPKI_CASES], ids=[n for n, _ in SPKI_CASES])
def test_wrprc_unusable_key_is_typed(ca, build):
    der, key = build(ca)
    with pytest.raises(RpRegistrationError, match="public key cannot be decoded"):
        verify_rp_registration_certificate(_wrprc(der, key), trust_anchors=[ca[0]], now=NOW)
