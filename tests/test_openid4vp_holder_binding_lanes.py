"""
tests/test_openid4vp_holder_binding_lanes.py — ``require_holder_binding`` on the
``dc+sd-jwt`` and ``mso_mdoc`` lanes of ``verify_vp_token`` (#378).

``verify_vp_token(require_holder_binding=True)`` is the caller's own, stricter switch: the
presenter must be bound to what they present, whatever the DCQL query says. It was read on
the W3C lanes only. ``_verify_sd_jwt_vc`` had no such parameter and reported
``holder = sub`` unconditionally, so a ``dc+sd-jwt`` query that waived cryptographic holder
binding (``require_cryptographic_holder_binding: false``), answered with an SD-JWT VC and
no Key Binding JWT, was accepted under the switch with ``holder`` set to an issuer-written
``sub`` nobody had authenticated (``key_bound=False``), where a bare ``jwt_vc_json`` answer
in the same situation raised ``ClaimsInvalid``. The ``mso_mdoc`` branch of ``_verify_one``
returned before the switch was read.

Pinned here (the maintainer's decisions on #378):

  * ``dc+sd-jwt`` — under the switch the SD-JWT VC must carry a KB-JWT bound to this
    exchange (``key_bound=True``), else ``ClaimsInvalid`` with the bare lane's wording;
    without the switch an SD-JWT VC with no KB-JWT is still accepted when the query waived
    binding, but reports ``holder=None``: ``sub`` is the issuer's identifier for the holder,
    not an authenticated presenter. With a KB-JWT verified, ``holder`` is ``sub`` as before.
  * ``mso_mdoc`` — exempt by construction, not fail-closed: ``verify_device_response``
    verifies the ``DeviceAuth`` over the origin-bound ``SessionTranscript`` with the device
    key the issuer sealed in the MSO, for every document, or refuses the response. A
    conformant mdoc is accepted under the switch with ``holder=None`` (an mdoc carries no
    holder identifier) and ``device_signed=True``; one without ``deviceSigned``, or signed
    by another device key, is refused whatever the switch says.

``tests/`` is not a package: the did:key, SD-JWT and mdoc builders are copied from
``test_openid4vp.py`` / ``test_mdoc.py`` (DeviceSignature path only), not imported.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc import cbor
from openvc.keys import P256SigningKey
from openvc.mdoc import MdocDeviceAuthError
from openvc.multibase import encode_multibase
from openvc.openid4vp import (
    FORMAT_JWT_VC,
    FORMAT_MSO_MDOC,
    FORMAT_SD_JWT_VC,
    dcapi_session_transcript,
    verify_vp_token,
)
from openvc.proof.errors import ClaimsInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite

NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:client.example.org"
VCT = "https://credentials.example.com/identity_credential"
VICTIM = "did:example:victim"          # the issuer-written `sub`: an identifier, not a proof
# The bare W3C lane's refusal, which the dc+sd-jwt lane now shares word for word.
NO_AUTHENTICATED_HOLDER = ("has no authenticated holder, so it cannot meet "
                           "require_holder_binding")
_MC_P256 = bytes([0x80, 0x24])        # multicodec p256-pub (0x1200) varint

DEFAULT_SD_JWT_DCQL = {"credentials": [{"id": "q", "format": FORMAT_SD_JWT_VC}]}
WAIVED_SD_JWT_DCQL = {"credentials": [{"id": "q", "format": FORMAT_SD_JWT_VC,
                                       "require_cryptographic_holder_binding": False}]}
WAIVED_JWT_VC_DCQL = {"credentials": [{"id": "q", "format": FORMAT_JWT_VC,
                                       "require_cryptographic_holder_binding": False}]}
MDOC_DCQL = {"credentials": [{"id": "mdl", "format": FORMAT_MSO_MDOC}]}


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(_MC_P256 + raw)
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


@pytest.fixture(scope="module")
def issuer():
    return _did_key_p256()


@pytest.fixture(scope="module")
def holder():
    return _did_key_p256()


def _issued_sd_jwt(issuer, holder, *, sub=VICTIM):
    """An SD-JWT VC bound (cnf) to the holder key, presented with NO KB-JWT (ends in '~')."""
    issuer_key, issuer_did = issuer
    holder_key, _ = holder
    claims = {"iss": issuer_did, "given_name": "Ada"}
    if sub is not None:
        claims["sub"] = sub
    issued = SdJwtVcProofSuite().issue(
        claims, signing_key=issuer_key, vct=VCT, disclosable=["given_name"],
        holder_jwk=holder_key.public_jwk())
    assert issued.endswith("~")
    return issued


def _presented_sd_jwt(issuer, holder, *, audience=CLIENT_ID, nonce=NONCE, sub=VICTIM):
    """The same SD-JWT VC with a KB-JWT bound to *audience* + *nonce*."""
    holder_key, _ = holder
    return SdJwtVcProofSuite().create_presentation(
        _issued_sd_jwt(issuer, holder, sub=sub), holder_key=holder_key,
        audience=audience, nonce=nonce)


def _verify(token, dcql, **kwargs):
    return verify_vp_token({"q": [token]}, dcql_query=dcql, nonce=NONCE,
                           client_id=CLIENT_ID, **kwargs).for_query("q")[0]


# --------------------------------------------------------------------------- #
# dc+sd-jwt: the switch requires the KB-JWT; `holder` is `sub` only once it verified
# --------------------------------------------------------------------------- #

def test_sd_jwt_without_kb_jwt_cannot_meet_require_holder_binding(issuer, holder):
    """The gap: on main this was accepted with holder=VICTIM and key_bound=False."""
    with pytest.raises(ClaimsInvalid, match=NO_AUTHENTICATED_HOLDER) as info:
        _verify(_issued_sd_jwt(issuer, holder), WAIVED_SD_JWT_DCQL,
                require_holder_binding=True)
    assert "'q'" in str(info.value) and FORMAT_SD_JWT_VC in str(info.value)


def test_sd_jwt_without_kb_jwt_reports_no_holder_when_the_query_waived_binding(
        issuer, holder):
    """Accepted, as before — but `holder` is no longer the unauthenticated `sub`."""
    p = _verify(_issued_sd_jwt(issuer, holder), WAIVED_SD_JWT_DCQL)
    assert p.format == FORMAT_SD_JWT_VC
    assert p.credentials[0].key_bound is False
    assert p.credentials[0].subject == VICTIM      # the issuer-signed sub stays readable …
    assert p.holder is None                        # … but nobody authenticated it


def test_sd_jwt_without_kb_jwt_is_still_refused_by_a_default_query(issuer, holder):
    """Control: the query's own flag (default true) refused it before and still does, with
    or without the caller's switch — the suite's own error, raised before the lane's."""
    for switch in (False, True):
        with pytest.raises(ClaimsInvalid, match="no KB-JWT present"):
            _verify(_issued_sd_jwt(issuer, holder), DEFAULT_SD_JWT_DCQL,
                    require_holder_binding=switch)


@pytest.mark.parametrize("dcql", [DEFAULT_SD_JWT_DCQL, WAIVED_SD_JWT_DCQL],
                         ids=["default-query", "waived-query"])
def test_sd_jwt_with_kb_jwt_meets_require_holder_binding(issuer, holder, dcql):
    p = _verify(_presented_sd_jwt(issuer, holder), dcql, require_holder_binding=True)
    assert p.credentials[0].key_bound is True
    assert p.holder == VICTIM                      # sub, vouched for by the KB-JWT


@pytest.mark.parametrize("dcql", [DEFAULT_SD_JWT_DCQL, WAIVED_SD_JWT_DCQL],
                         ids=["default-query", "waived-query"])
def test_sd_jwt_with_kb_jwt_reports_sub_as_before(issuer, holder, dcql):
    p = _verify(_presented_sd_jwt(issuer, holder), dcql)
    assert p.holder == VICTIM and p.credentials[0].key_bound is True


@pytest.mark.parametrize("aud, nonce", [
    pytest.param(CLIENT_ID, "other-nonce", id="right-aud-wrong-nonce"),
    pytest.param("x509_san_dns:other.example", NONCE, id="wrong-aud-right-nonce"),
])
@pytest.mark.parametrize("switch", [False, True], ids=["switch-off", "switch-on"])
def test_kb_jwt_bound_elsewhere_is_refused_whatever_the_switch(
        issuer, holder, aud, nonce, switch):
    """A KB-JWT made for another verifier or nonce is no binding here (RFC 9901 §7.3 step
    5.6, #190): the query's waiver does not switch that check off, so key_bound is never
    True for it and the caller's switch has nothing it could pass."""
    with pytest.raises(ClaimsInvalid):
        _verify(_presented_sd_jwt(issuer, holder, audience=aud, nonce=nonce),
                WAIVED_SD_JWT_DCQL, require_holder_binding=switch)


def test_sd_jwt_with_kb_jwt_but_no_sub_has_no_holder_to_report(issuer, holder):
    """The switch asks for the KB-JWT, not for a `sub`: a presenter authenticated by key
    whose issuer wrote no identifier is accepted and reported as None, as before."""
    p = _verify(_presented_sd_jwt(issuer, holder, sub=None), DEFAULT_SD_JWT_DCQL,
                require_holder_binding=True)
    assert p.credentials[0].key_bound is True and p.credentials[0].subject is None
    assert p.holder is None


def test_sd_jwt_with_kb_jwt_and_an_empty_sub_reports_no_holder(issuer, holder):
    """An empty `sub` is no identifier: with the KB-JWT verified, `holder` is None, as the
    W3C lanes already read an empty subject as absent (adversarial review of #378)."""
    p = _verify(_presented_sd_jwt(issuer, holder, sub=""), DEFAULT_SD_JWT_DCQL,
                require_holder_binding=True)
    assert p.credentials[0].key_bound is True
    assert p.credentials[0].subject == ""          # the claim as the issuer wrote it …
    assert p.holder is None                        # … names nobody


def test_vct_mismatch_is_reported_before_the_switch(issuer, holder):
    """The lane's own pins (format, typ, vct_values) keep coming first."""
    dcql = {"credentials": [{"id": "q", "format": FORMAT_SD_JWT_VC,
                             "meta": {"vct_values": ["https://example.com/OtherType"]},
                             "require_cryptographic_holder_binding": False}]}
    with pytest.raises(ClaimsInvalid) as info:
        _verify(_issued_sd_jwt(issuer, holder), dcql, require_holder_binding=True)
    assert NO_AUTHENTICATED_HOLDER not in str(info.value)
    assert "vct" in str(info.value)


# --------------------------------------------------------------------------- #
# Control: the bare jwt_vc_json lane, whose rule the dc+sd-jwt lane now shares
# --------------------------------------------------------------------------- #

def test_bare_jwt_vc_json_control_is_unchanged(issuer):
    issuer_key, issuer_did = issuer
    vc = VcJwtProofSuite().sign(
        {"@context": ["https://www.w3.org/ns/credentials/v2"],
         "type": ["VerifiableCredential"], "issuer": issuer_did,
         "credentialSubject": {"id": VICTIM}},
        signing_key=issuer_key)
    with pytest.raises(ClaimsInvalid, match=NO_AUTHENTICATED_HOLDER):
        _verify(vc, WAIVED_JWT_VC_DCQL, require_holder_binding=True)
    p = _verify(vc, WAIVED_JWT_VC_DCQL)
    assert p.holder is None and p.credentials[0].subject == VICTIM


# --------------------------------------------------------------------------- #
# mso_mdoc over the Digital Credentials API: exempt by construction
# --------------------------------------------------------------------------- #

DOCTYPE = "org.iso.18013.5.1.mDL"
NS = "org.iso.18013.5.1"
ORIGIN = "https://verifier.example"
MDOC_NONCE = "abcdefgh-nonce-0123456789"
NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_PAST, _FUTURE = NOW - dt.timedelta(days=3650), NOW + dt.timedelta(days=3650)
_CA_KU = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False)
_MDOC_DS_EKU = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")])


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _self_signed(cn, key):
    return (x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(_CA_KU, critical=True)
            .sign(key, hashes.SHA256()))


def _ds_cert(iaca_cn, iaca_key, ds_key):
    return (x509.CertificateBuilder()
            .subject_name(_name("utopia ds test")).issuer_name(_name(iaca_cn))
            .public_key(ds_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_PAST).not_valid_after(_FUTURE)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_MDOC_DS_EKU, critical=False)   # ISO 18013-5 Annex B DS EKU
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
    # isoformat, not strftime: glibc's %Y renders year 1 as "1", not "0001"
    utc = when.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return cbor.CborTag(0, utc.isoformat(timespec="seconds") + "Z")


def _build_online(session_transcript, *, wrong_device_key=False):
    """A DeviceResponse with real crypto — issuer seal plus a DeviceSignature over
    *session_transcript* — returned as ``(device_response_bytes, iaca_certificate)``.
    With *wrong_device_key* the DeviceSignature is made by a key other than the one the
    issuer sealed in the MSO."""
    iaca_key = ec.generate_private_key(ec.SECP256R1())
    iaca = _self_signed("utopia iaca test", iaca_key)
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds_der = _ds_cert("utopia iaca test", iaca_key, ds_key).public_bytes(
        serialization.Encoding.DER)
    device_key = ec.generate_private_key(ec.SECP256R1())

    items = [(0, "family_name", "Doe"), (1, "document_number", "123456789"),
             (2, "age_over_18", True)]
    ns_items, digests = [], {}
    for digest_id, element_id, value in items:
        raw = _issuer_item_bytes(digest_id, element_id, value)
        ns_items.append(cbor.decode(raw))                 # a CborTag(24, ..., raw=raw)
        digests[digest_id] = hashlib.sha256(raw).digest()
    mso = {
        "version": "1.0", "digestAlgorithm": "SHA-256",
        "valueDigests": {NS: digests},
        "deviceKeyInfo": {"deviceKey": _cose_key(device_key.public_key())},
        "docType": DOCTYPE,
        "validityInfo": {"signed": _tdate(NOW), "validFrom": _tdate(_PAST),
                         "validUntil": _tdate(_FUTURE)},
    }
    mso_tagged = cbor.encode(cbor.CborTag(24, cbor.encode(mso)))
    issuer_auth = _cose_sign1(mso_tagged, ds_key, x5chain=ds_der)
    issuer_signed = {"nameSpaces": {NS: ns_items}, "issuerAuth": issuer_auth}

    device_ns_bytes = cbor.encode(cbor.CborTag(24, cbor.encode({})))
    device_authentication = cbor.encode(
        ["DeviceAuthentication", cbor.CborRaw(session_transcript), DOCTYPE,
         cbor.CborRaw(device_ns_bytes)])
    da_bytes = cbor.encode(cbor.CborTag(24, device_authentication))
    signer = ec.generate_private_key(ec.SECP256R1()) if wrong_device_key else device_key
    device_signed = {"nameSpaces": cbor.decode(device_ns_bytes),
                     "deviceAuth": {"deviceSignature": _cose_sign1(da_bytes, signer,
                                                                   detached=True)}}
    document = {"docType": DOCTYPE, "issuerSigned": issuer_signed,
                "deviceSigned": device_signed}
    return cbor.encode({"version": "1.0", "documents": [document], "status": 0}), iaca


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _without_device_signed(device_response):
    """The same response with its holder binding dropped; the issuer seal is intact."""
    response = cbor.decode(device_response)
    del response["documents"][0]["deviceSigned"]
    return cbor.encode(response)


def _verify_mdoc(token, iaca, **kwargs):
    return verify_vp_token({"mdl": [token]}, dcql_query=MDOC_DCQL, nonce=MDOC_NONCE,
                           expected_origins=[ORIGIN], trust_anchors=[iaca], now=NOW, **kwargs)


@pytest.mark.parametrize("switch", [True, False], ids=["switch-on", "switch-off"])
def test_conformant_mdoc_is_accepted_under_the_switch_with_no_holder(switch):
    """The exemption: the DeviceAuth over the origin-bound SessionTranscript, made with
    the device key the issuer sealed in the MSO, is the holder binding — verified on every
    document the lane returns. An mdoc carries no holder identifier, so `holder` is None."""
    st = dcapi_session_transcript(ORIGIN, MDOC_NONCE)
    dr, iaca = _build_online(st)
    (p,) = _verify_mdoc(_b64url(dr), iaca, require_holder_binding=switch).for_query("mdl")
    assert p.format == FORMAT_MSO_MDOC
    assert p.holder is None
    assert p.credentials and all(c.device_signed is True for c in p.credentials)
    assert p.credentials[0].elements(NS)["family_name"] == "Doe"


@pytest.mark.parametrize("switch", [True, False], ids=["switch-on", "switch-off"])
def test_mdoc_without_device_signed_is_refused_whatever_the_switch(switch):
    """Why the exemption is safe: the lane never returns an mdoc whose DeviceAuth it did
    not verify. A response with a valid issuer seal and no deviceSigned is refused."""
    st = dcapi_session_transcript(ORIGIN, MDOC_NONCE)
    dr, iaca = _build_online(st)
    with pytest.raises(MdocDeviceAuthError, match="no deviceSigned"):
        _verify_mdoc(_b64url(_without_device_signed(dr)), iaca, require_holder_binding=switch)


@pytest.mark.parametrize("switch", [True, False], ids=["switch-on", "switch-off"])
def test_mdoc_signed_by_another_device_key_is_refused_whatever_the_switch(switch):
    st = dcapi_session_transcript(ORIGIN, MDOC_NONCE)
    dr, iaca = _build_online(st, wrong_device_key=True)
    with pytest.raises(MdocDeviceAuthError, match="holder binding failed"):
        _verify_mdoc(_b64url(dr), iaca, require_holder_binding=switch)


# --------------------------------------------------------------------------- #
# Both lanes in one DC API response
# --------------------------------------------------------------------------- #

def test_mixed_mdoc_and_kb_bound_sd_jwt_meet_the_switch_over_the_dc_api(issuer, holder):
    """Over the DC API both lanes bind to the calling origin: the mdoc through its
    SessionTranscript, the SD-JWT VC through a KB-JWT whose aud is ``origin:<origin>``.
    Evaluated at the real clock (the KB-JWT is fresh now; the mdoc's window covers it)."""
    st = dcapi_session_transcript(ORIGIN, MDOC_NONCE)
    dr, iaca = _build_online(st)
    bound = _presented_sd_jwt(issuer, holder, audience="origin:" + ORIGIN, nonce=MDOC_NONCE)
    dcql = {"credentials": [{"id": "mdl", "format": FORMAT_MSO_MDOC},
                            {"id": "pid", "format": FORMAT_SD_JWT_VC,
                             "require_cryptographic_holder_binding": False}]}
    result = verify_vp_token(
        {"mdl": [_b64url(dr)], "pid": [bound]}, dcql_query=dcql, nonce=MDOC_NONCE,
        expected_origins=[ORIGIN], trust_anchors=[iaca], require_holder_binding=True)
    assert [(p.query_id, p.holder) for p in result.presentations] == [
        ("mdl", None), ("pid", VICTIM)]
    assert result.for_query("pid")[0].credentials[0].key_bound is True


def test_mixed_response_with_an_unbound_sd_jwt_fails_as_a_whole(issuer, holder):
    """One lane failing rejects the response. (Over the DC API an SD-JWT VC with no KB-JWT
    is refused on its missing ``origin:`` audience before the lane runs, as before.)"""
    st = dcapi_session_transcript(ORIGIN, MDOC_NONCE)
    dr, iaca = _build_online(st)
    dcql = {"credentials": [{"id": "mdl", "format": FORMAT_MSO_MDOC},
                            {"id": "pid", "format": FORMAT_SD_JWT_VC,
                             "require_cryptographic_holder_binding": False}]}
    with pytest.raises(ClaimsInvalid):
        verify_vp_token(
            {"mdl": [_b64url(dr)], "pid": [_issued_sd_jwt(issuer, holder)]}, dcql_query=dcql,
            nonce=MDOC_NONCE, expected_origins=[ORIGIN], trust_anchors=[iaca],
            require_holder_binding=True)
