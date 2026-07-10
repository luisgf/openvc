"""
tests/test_mdoc.py — ISO 18013-5 ``mso_mdoc`` DeviceResponse verification (issue #86).

Two evidence sources, per ADR-0005 D8:

* **The real ISO 18013-5 Annex D vector** (``fixtures/mdoc/``) — the byte-exact utopia-mDL
  DeviceResponse from the ISO worked example (via openwallet-foundation/multipaz + the IACA
  root from MinBZK/nl-wallet, joined cryptographically). It proves issuer data
  authentication conformance (COSE_Sign1 + x5chain→IACA + valueDigests) against a third
  party. Its DeviceAuth is a proximity DeviceMac (out of scope), so it exercises
  :func:`verify_issuer_signed`.
* **A self-generated online fixture** (real crypto, controlled) — a full DeviceResponse with
  a DeviceSignature over the OpenID4VP DC-API SessionTranscript, for the end-to-end
  :func:`verify_device_response` path, the OpenID4VP wiring, and every negative path
  (tampered digest, wrong transcript, expired MSO, broken chain, bad signature, …).

Negative paths first: every check must fail closed with its typed MdocError.
"""
from __future__ import annotations

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
from openvc.openid4vp import dcapi_session_transcript

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


# --------------------------------------------------------------------------- #
# The real ISO 18013-5 Annex D golden vector (issuer data authentication)
# --------------------------------------------------------------------------- #

def _annex_d():
    dr = bytes.fromhex((FIXTURES / "annex_d_device_response.hex").read_text().strip())
    iaca = x509.load_pem_x509_certificate((FIXTURES / "annex_d_iaca_root.pem").read_bytes())
    return dr, iaca


ANNEX_D_NOW = dt.datetime(2020, 12, 1, tzinfo=dt.timezone.utc)   # inside 2020-10..2021-10


def test_annex_d_issuer_signed_verifies():
    dr, iaca = _annex_d()
    document = cbor.decode(dr)["documents"][0]
    result = mdoc.verify_issuer_signed(document, trust_anchors=[iaca], now=ANNEX_D_NOW)
    assert result.doc_type == DOCTYPE
    assert result.device_signed is False                 # issuer seal only
    assert result.issuer_key["crv"] == "P-256"
    claims = result.elements(NS)
    assert claims["family_name"] == "Doe"
    assert claims["document_number"] == "123456789"
    assert isinstance(claims["portrait"], bytes) and len(claims["portrait"]) > 500
    assert result.validity.valid_until.year == 2021


def test_annex_d_untrusted_anchor_is_typed_trust_error():
    dr, _ = _annex_d()
    document = cbor.decode(dr)["documents"][0]
    stranger, _ = _self_signed("stranger", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(mdoc.MdocTrustError):
        mdoc.verify_issuer_signed(document, trust_anchors=[stranger], now=ANNEX_D_NOW)


def test_annex_d_stale_response_rejected():
    # Well past the vector's lifetime the response is rejected fail-closed. The utopia DS
    # cert expires 2021-10-01, coincident with the MSO validUntil, so the chain-validity
    # check trips first (MdocTrustError) — the MSO validity window itself is exercised by
    # the self-generated test_expired_mso_rejected, where the cert outlives the MSO.
    dr, iaca = _annex_d()
    document = cbor.decode(dr)["documents"][0]
    with pytest.raises(mdoc.MdocError):
        mdoc.verify_issuer_signed(document, trust_anchors=[iaca],
                                  now=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))


def test_annex_d_tampered_disclosed_item_breaks_digest():
    dr, iaca = _annex_d()
    response = cbor.decode(dr)
    # flip one byte of the first disclosed IssuerSignedItem's bytes -> valueDigest mismatch
    items = response["documents"][0]["issuerSigned"]["nameSpaces"][NS]
    bad = bytearray(items[0].raw)
    bad[-1] ^= 0xFF
    items[0] = cbor.CborTag(24, items[0].value, raw=bytes(bad))
    with pytest.raises(mdoc.MdocError):     # re-encode won't match; digest or parse fails closed
        mdoc.verify_issuer_signed(_reencode(response), trust_anchors=[iaca], now=ANNEX_D_NOW)


# --------------------------------------------------------------------------- #
# Self-generated online fixture: certs + COSE signing helpers (test-only)
# --------------------------------------------------------------------------- #

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _self_signed(cn, key, *, not_after=_FUTURE):
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(_CA_KU, critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _ds_cert(iaca_cn, iaca_key, ds_key, *, not_after=_FUTURE):
    return (x509.CertificateBuilder()
            .subject_name(_name("utopia ds test")).issuer_name(_name(iaca_cn))
            .public_key(ds_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(iaca_key, hashes.SHA256()))


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
    return cbor.CborTag(0, when.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _build_online(
    *, session_transcript, items=None, doc_type=DOCTYPE, mso_doc_type=None,
    digest_alg="SHA-256", valid_from=_PAST, valid_until=_FUTURE, tamper_digest_id=None,
    device_key=None, device_signature=True, wrong_device_key=False,
):
    """A full DeviceResponse with real crypto. Returns (device_response_bytes, iaca_cert)."""
    iaca_key = ec.generate_private_key(ec.SECP256R1())
    iaca, _ = _self_signed("utopia iaca test", iaca_key)
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds_der = _ds_cert("utopia iaca test", iaca_key, ds_key).public_bytes(
        serialization.Encoding.DER)
    device_key = device_key or ec.generate_private_key(ec.SECP256R1())

    items = items or [(0, "family_name", "Doe"), (1, "document_number", "123456789"),
                      (2, "age_over_18", True)]
    hasher = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384}[digest_alg] \
        if digest_alg in ("SHA-256", "SHA-384") else hashlib.sha1
    ns_items, digests = [], {}
    for did, eid, val in items:
        raw = _issuer_item_bytes(did, eid, val)
        ns_items.append(cbor.decode(raw))                 # a CborTag(24, ..., raw=raw)
        digest = hasher(raw).digest()
        if did == tamper_digest_id:
            digest = bytes(b ^ 0xFF for b in digest)
        digests[did] = digest

    signed_key = device_key if not wrong_device_key else ec.generate_private_key(ec.SECP256R1())
    mso = {
        "version": "1.0", "digestAlgorithm": digest_alg,
        "valueDigests": {NS: digests},
        "deviceKeyInfo": {"deviceKey": _cose_key(device_key.public_key())},
        "docType": mso_doc_type or doc_type,
        "validityInfo": {"signed": _tdate(NOW), "validFrom": _tdate(valid_from),
                         "validUntil": _tdate(valid_until)},
    }
    mso_tagged = cbor.encode(cbor.CborTag(24, cbor.encode(mso)))
    issuer_auth = _cose_sign1(mso_tagged, ds_key, x5chain=ds_der)
    issuer_signed = {"nameSpaces": {NS: ns_items}, "issuerAuth": issuer_auth}

    device_ns_bytes = cbor.encode(cbor.CborTag(24, cbor.encode({})))
    device_authentication = cbor.encode(
        ["DeviceAuthentication", cbor.CborRaw(session_transcript), doc_type,
         cbor.CborRaw(device_ns_bytes)])
    da_bytes = cbor.encode(cbor.CborTag(24, device_authentication))
    dev_sig = _cose_sign1(da_bytes, signed_key, detached=True)
    device_signed = {"nameSpaces": cbor.decode(device_ns_bytes),
                     "deviceAuth": {"deviceSignature": dev_sig}}

    document = {"docType": doc_type, "issuerSigned": issuer_signed,
                "deviceSigned": device_signed}
    return cbor.encode({"version": "1.0", "documents": [document], "status": 0}), iaca


def _reencode(obj):
    return cbor.encode(obj)


# --------------------------------------------------------------------------- #
# Self-generated online: the happy path (issuer + device authentication)
# --------------------------------------------------------------------------- #

def test_online_device_response_verifies_end_to_end():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    results = mdoc.verify_device_response(
        dr, trust_anchors=[iaca], session_transcript=st, now=NOW)
    assert len(results) == 1
    doc = results[0]
    assert doc.doc_type == DOCTYPE and doc.device_signed is True
    assert doc.elements(NS) == {"family_name": "Doe", "document_number": "123456789",
                                "age_over_18": True}


def test_online_expected_doc_type_enforced():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    with pytest.raises(mdoc.MdocDocTypeMismatch):
        mdoc.verify_device_response(dr, trust_anchors=[iaca], session_transcript=st,
                                    now=NOW, expected_doc_type="org.iso.18013.5.1.other")


# --------------------------------------------------------------------------- #
# Self-generated online: negative paths (fail closed, typed)
# --------------------------------------------------------------------------- #

def test_wrong_session_transcript_fails_device_auth():
    signed_st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=signed_st)
    other_st = dcapi_session_transcript(ORIGIN, "different-nonce")
    with pytest.raises(mdoc.MdocDeviceAuthError):
        mdoc.verify_device_response(dr, trust_anchors=[iaca],
                                    session_transcript=other_st, now=NOW)


def test_wrong_device_key_fails_device_auth():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st, wrong_device_key=True)
    with pytest.raises(mdoc.MdocDeviceAuthError):
        mdoc.verify_device_response(dr, trust_anchors=[iaca], session_transcript=st, now=NOW)


def test_tampered_value_digest_rejected():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st, tamper_digest_id=0)
    with pytest.raises(mdoc.MdocDigestMismatch):
        mdoc.verify_device_response(dr, trust_anchors=[iaca], session_transcript=st, now=NOW)


def test_expired_mso_rejected():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st, valid_until=NOW - dt.timedelta(days=1))
    with pytest.raises(mdoc.MdocValidityError):
        mdoc.verify_device_response(dr, trust_anchors=[iaca], session_transcript=st, now=NOW)


def test_untrusted_iaca_rejected():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, _ = _build_online(session_transcript=st)
    stranger, _ = _self_signed("stranger", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(mdoc.MdocTrustError):
        mdoc.verify_device_response(dr, trust_anchors=[stranger], session_transcript=st, now=NOW)


def test_mso_doctype_mismatch_rejected():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st, mso_doc_type="org.iso.18013.5.1.evil")
    with pytest.raises(mdoc.MdocDocTypeMismatch):
        mdoc.verify_device_response(dr, trust_anchors=[iaca], session_transcript=st, now=NOW)


def test_unsupported_digest_algorithm_rejected():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st, digest_alg="SHA-1")
    with pytest.raises(mdoc.MdocMalformed):
        mdoc.verify_device_response(dr, trust_anchors=[iaca], session_transcript=st, now=NOW)


def test_tampered_issuer_auth_signature_rejected():
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    response = cbor.decode(dr)
    sig = bytearray(response["documents"][0]["issuerSigned"]["issuerAuth"][3])
    sig[-1] ^= 0xFF
    response["documents"][0]["issuerSigned"]["issuerAuth"][3] = bytes(sig)
    with pytest.raises(mdoc.MdocSignatureInvalid):
        mdoc.verify_device_response(_reencode(response), trust_anchors=[iaca],
                                    session_transcript=st, now=NOW)


@pytest.mark.parametrize("mutate, exc", [
    (lambda r: r.__setitem__("status", 1), mdoc.MdocMalformed),
    (lambda r: r.__setitem__("documents", []), mdoc.MdocMalformed),
    (lambda r: r.pop("status"), mdoc.MdocMalformed),
], ids=["status-not-ok", "no-documents", "no-status"])
def test_malformed_device_response_rejected(mutate, exc):
    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    response = cbor.decode(dr)
    mutate(response)
    with pytest.raises(exc):
        mdoc.verify_device_response(_reencode(response), trust_anchors=[iaca],
                                    session_transcript=st, now=NOW)


def test_non_cbor_device_response_rejected():
    with pytest.raises(mdoc.MdocMalformed):
        mdoc.verify_device_response(b"\xff\xff not cbor", trust_anchors=[],
                                    session_transcript=b"\x80", now=NOW)


# --------------------------------------------------------------------------- #
# OpenID4VP wiring (verify_vp_token over the DC API flow)
# --------------------------------------------------------------------------- #

def _b64url(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_verify_vp_token_mso_mdoc_dc_api():
    from openvc.openid4vp import verify_vp_token

    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    vp_token = {"mdl": [_b64url(dr)]}
    dcql = {"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}
    result = verify_vp_token(
        vp_token, dcql_query=dcql, nonce=NONCE, expected_origins=[ORIGIN],
        trust_anchors=[iaca], now=NOW)
    pres = result.for_query("mdl")[0]
    assert pres.format == "mso_mdoc"
    assert pres.credentials[0].elements(NS)["family_name"] == "Doe"


def test_verify_vp_token_enforces_dcql_doctype_value():
    from openvc.openid4vp import verify_vp_token

    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)          # docType == DOCTYPE (mDL)
    match = {"credentials": [{"id": "mdl", "format": "mso_mdoc",
                              "meta": {"doctype_value": DOCTYPE}}]}
    ok = verify_vp_token({"mdl": [_b64url(dr)]}, dcql_query=match, nonce=NONCE,
                         expected_origins=[ORIGIN], trust_anchors=[iaca], now=NOW)
    assert ok.for_query("mdl")[0].credentials[0].doc_type == DOCTYPE

    # a genuine, IACA-sealed, device-bound mdoc of a DIFFERENT docType than the query asked
    # for must be rejected (the mdoc analogue of SD-JWT vct_values enforcement)
    other = {"credentials": [{"id": "mdl", "format": "mso_mdoc",
                              "meta": {"doctype_value": "org.iso.18013.5.1.PhotoID"}}]}
    with pytest.raises(mdoc.MdocDocTypeMismatch):
        verify_vp_token({"mdl": [_b64url(dr)]}, dcql_query=other, nonce=NONCE,
                        expected_origins=[ORIGIN], trust_anchors=[iaca], now=NOW)


def test_verify_vp_token_tries_each_expected_origin():
    from openvc.openid4vp import verify_vp_token

    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    dcql = {"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}
    # the real origin is second in the list — the verifier must try both and accept it
    result = verify_vp_token(
        {"mdl": [_b64url(dr)]}, dcql_query=dcql, nonce=NONCE,
        expected_origins=["https://wrong.example", ORIGIN], trust_anchors=[iaca], now=NOW)
    assert result.for_query("mdl")[0].credentials[0].device_signed is True


def test_verify_vp_token_mso_mdoc_without_trust_anchors_rejected():
    from openvc.openid4vp import verify_vp_token
    from openvc.proof.errors import ClaimsInvalid

    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, _ = _build_online(session_transcript=st)
    dcql = {"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}
    with pytest.raises(ClaimsInvalid):
        verify_vp_token({"mdl": [_b64url(dr)]}, dcql_query=dcql, nonce=NONCE,
                        expected_origins=[ORIGIN], now=NOW)


def test_verify_vp_token_mso_mdoc_wrong_origin_rejected():
    from openvc.openid4vp import verify_vp_token

    st = dcapi_session_transcript(ORIGIN, NONCE)
    dr, iaca = _build_online(session_transcript=st)
    dcql = {"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}
    with pytest.raises(mdoc.MdocDeviceAuthError):
        verify_vp_token({"mdl": [_b64url(dr)]}, dcql_query=dcql, nonce=NONCE,
                        expected_origins=["https://attacker.example"], trust_anchors=[iaca],
                        now=NOW)
