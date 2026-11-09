"""#388 — the XML declaration's ``encoding`` is outside the XAdES signature (C14N drops it),
so it is attacker-chosen: an exotic label must be a typed ``TrustListParseError`` — through
``parse_trust_list``, ``consume_trust_list`` and as a per-TL problem in ``walk_lotl`` — and
only the allow-listed labels parse."""
from __future__ import annotations

import base64
import datetime
import hashlib

import pytest

pytest.importorskip("signxml")
pytest.importorskip("lxml")

from lxml import etree                                         # noqa: E402
from cryptography import x509                                  # noqa: E402
from cryptography.hazmat.primitives import hashes              # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec       # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID                      # noqa: E402

from openvc.trustlist import (                                 # noqa: E402
    TrustListParseError,
    consume_trust_list,
    parse_trust_list,
    verify_xades_enveloped,
    walk_lotl,
)

TSL = "http://uri.etsi.org/02231/v2#"
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"
NOW = datetime.datetime(2026, 7, 1, tzinfo=datetime.timezone.utc)
LOTL_URL = "https://ec.example/lotl.xml"
DE_URL = "https://tl.example.de/de.xml"
FR_URL = "https://tl.example.fr/fr.xml"
HOSTILE = ["GB2312", "Shift_JIS", "EUC-JP", "big5", "gbk", "latin-9", "x-unknown", "",
           "A" * 10_000]
_IDS = [h if len(h) < 20 else "long-label" for h in HOSTILE]
_IDS[_IDS.index("")] = "empty"


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


def _national_tl(ca_der, territory="DE"):
    root = etree.Element(f"{{{TSL}}}TrustServiceStatusList")
    si = _el(root, "SchemeInformation")
    _el(si, "TSLType", "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric")
    _el(si, "SchemeTerritory", territory)
    _el(_el(si, "NextUpdate"), "dateTime", "2099-01-01T00:00:00Z")
    tsp = _el(_el(root, "TrustServiceProviderList"), "TrustServiceProvider")
    name = _el(_el(_el(tsp, "TSPInformation"), "TSPName"), "Name", "Example TSP")
    name.set(XML_LANG, "en")
    info = _el(_el(_el(tsp, "TSPServices"), "TSPService"), "ServiceInformation")
    _el(info, "ServiceTypeIdentifier", "http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
    _el(_el(_el(info, "ServiceDigitalIdentity"), "DigitalId"), "X509Certificate",
        base64.b64encode(ca_der).decode())
    _el(info, "ServiceStatus", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
    return root


def _lotl(pointers):
    root = etree.Element(f"{{{TSL}}}TrustServiceStatusList")
    si = _el(root, "SchemeInformation")
    _el(si, "TSLType", "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists")
    _el(si, "SchemeTerritory", "EU")
    _el(_el(si, "NextUpdate"), "dateTime", "2099-01-01T00:00:00Z")
    ptrs = _el(si, "PointersToOtherTSL")
    for url, signer_der, territory in pointers:
        op = _el(ptrs, "OtherTSLPointer")
        sdi = _el(_el(_el(op, "ServiceDigitalIdentities"), "ServiceDigitalIdentity"), "DigitalId")
        _el(sdi, "X509Certificate", base64.b64encode(signer_der).decode())
        _el(op, "TSLLocation", url)
        add = _el(op, "AdditionalInformation")
        _el(_el(add, "OtherInformation"), "SchemeTerritory", territory)
        _el(_el(add, "OtherInformation"), "TSLType",
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric")
    return root


def _sign(root, key, cert):
    from signxml import XMLSigner
    pem = cert.public_bytes(Encoding.PEM).decode()
    signed = XMLSigner(signature_algorithm="ecdsa-sha256", digest_algorithm="sha256").sign(
        root, key=key, cert=[pem])
    return etree.tostring(signed)


def _relabel(doc, enc):
    """The unsigned declaration put in front of a signed, pure-ASCII document."""
    assert doc.isascii()
    return b'<?xml version="1.0" encoding="%s"?>' % enc.encode() + doc


@pytest.fixture(scope="module")
def world():
    key_n, cert_n = _cert("DE TL Signer")
    key_c, cert_c = _cert("EU Commission")
    _, ca = _cert("Qualified CA")
    signed = _sign(_national_tl(ca.public_bytes(Encoding.DER)), key_n, cert_n)
    return {"cert_n": cert_n, "key_c": key_c, "cert_c": cert_c, "signed": signed}


# --------------------------------------------------------------------------- #
# Negatives
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("enc", HOSTILE, ids=_IDS)
def test_parse_trust_list_hostile_encoding_is_typed(world, enc):
    with pytest.raises(TrustListParseError) as ei:
        parse_trust_list(_relabel(world["signed"], enc))
    assert len(str(ei.value)) < 400                 # a bounded message, never the whole label


@pytest.mark.parametrize("enc", HOSTILE, ids=_IDS)
def test_consume_trust_list_hostile_encoding_is_typed(world, enc):
    # the signature still verifies for most labels (lxml decodes the ASCII body the same
    # way) — the failure that matters is the parse, and it must be typed either way
    from openvc.trustlist import TrustListError
    # (the class depends on whether libxml2/iconv accepts the label first, so the family)
    with pytest.raises(TrustListError):
        consume_trust_list(_relabel(world["signed"], enc),
                           verify_signature=verify_xades_enveloped,
                           expected_signer_certs=[world["cert_n"]])


def test_walk_lotl_relabelled_tl_is_a_problem_and_the_others_still_anchor(world):
    key_o, cert_o = _cert("FR TL Signer")
    _, ca_fr = _cert("FR Qualified CA")
    fr_signed = _sign(_national_tl(ca_fr.public_bytes(Encoding.DER), "FR"), key_o, cert_o)
    lotl = _sign(_lotl([
        (DE_URL, world["cert_n"].public_bytes(Encoding.DER), "DE"),
        (FR_URL, cert_o.public_bytes(Encoding.DER), "FR"),
    ]), world["key_c"], world["cert_c"])
    for enc in ("GB2312", "latin-9"):
        store = {LOTL_URL: lotl, DE_URL: _relabel(world["signed"], enc), FR_URL: fr_signed}
        res = walk_lotl(LOTL_URL, lotl_signer_certs=[world["cert_c"]],
                        verify_signature=verify_xades_enveloped,
                        fetch=lambda u, s=store: s[u], now=NOW)
        assert [(p.location, p.stage) for p in res.problems] == [(DE_URL, "parse")]
        assert [a.sha256 for a in res.anchors] == [
            hashlib.sha256(ca_fr.public_bytes(Encoding.DER)).hexdigest()]


def test_walk_lotl_hostile_lotl_stops_the_walk_with_one_parse_problem(world):
    lotl = _sign(_lotl([(DE_URL, world["cert_n"].public_bytes(Encoding.DER), "DE")]),
                 world["key_c"], world["cert_c"])
    store = {LOTL_URL: _relabel(lotl, "Shift_JIS"), DE_URL: world["signed"]}
    res = walk_lotl(LOTL_URL, lotl_signer_certs=[world["cert_c"]],
                    verify_signature=verify_xades_enveloped,
                    fetch=lambda u: store[u], now=NOW)
    assert res.anchors == ()
    assert [(p.location, p.stage) for p in res.problems] == [(LOTL_URL, "parse")]


# --------------------------------------------------------------------------- #
# Positives — allow-listed labels parse as before
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("enc", ["UTF-8", "utf-8", "US-ASCII"])
def test_allowed_labels_parse(world, enc):
    tl = parse_trust_list(_relabel(world["signed"], enc))
    assert tl.territory == "DE" and len(tl.providers) == 1


def test_no_declaration_parses(world):
    assert parse_trust_list(world["signed"]).territory == "DE"


def test_utf8_bom_is_accepted(world):
    assert parse_trust_list(b"\xef\xbb\xbf" + world["signed"]).territory == "DE"


@pytest.mark.parametrize("codec,label", [("utf-16", "UTF-16"), ("utf-16-le", "UTF-16LE"),
                                         ("utf-16-be", "UTF-16BE"), ("utf-16", None),
                                         ("utf-16-le", None), ("utf-32", None)])
def test_utf16_and_utf32_are_refused(world, codec, label):
    text = world["signed"].decode("ascii")
    decl = f'<?xml version="1.0" encoding="{label}"?>' if label else ""
    with pytest.raises(TrustListParseError):
        parse_trust_list((decl + text).encode(codec))


def test_bomless_utf16_be_is_refused_before_expat(world):
    text = world["signed"].decode("ascii")
    doc = text.encode("utf-16-be")                  # no BOM, no declaration: starts 00 3C
    assert doc[:1] == b"\x00"
    with pytest.raises(TrustListParseError, match="Annex B.0"):
        parse_trust_list(doc)


def test_nul_first_without_declaration_is_refused_before_expat(world):
    with pytest.raises(TrustListParseError, match="Annex B.0"):
        parse_trust_list(b"\x00" + world["signed"])


@pytest.mark.parametrize("enc", ["ISO-8859-1", "iso-8859-1", "UTF-16", "UTF-16LE"])
def test_wider_labels_are_refused(world, enc):
    with pytest.raises(TrustListParseError, match="unsupported XML encoding"):
        parse_trust_list(_relabel(world["signed"], enc))


def test_bom_relabelled_latin1_is_refused_through_the_walk(world):
    # the review's divergence: libxml2 keeps the BOM-detected UTF-8 and verifies, expat
    # used to obey the label and read Latin-1
    key_o, cert_o = _cert("FR TL Signer")
    _, ca_fr = _cert("FR Qualified CA")
    fr = _sign(_national_tl(ca_fr.public_bytes(Encoding.DER), "FR"), key_o, cert_o)
    lotl = _sign(_lotl([(DE_URL, world["cert_n"].public_bytes(Encoding.DER), "DE"),
                        (FR_URL, cert_o.public_bytes(Encoding.DER), "FR")]),
                 world["key_c"], world["cert_c"])
    bad = b"\xef\xbb\xbf" + _relabel(world["signed"], "ISO-8859-1")
    store = {LOTL_URL: lotl, DE_URL: bad, FR_URL: fr}
    res = walk_lotl(LOTL_URL, lotl_signer_certs=[world["cert_c"]],
                    verify_signature=verify_xades_enveloped,
                    fetch=lambda u: store[u], now=NOW)
    assert [(p.location, p.stage) for p in res.problems] == [(DE_URL, "parse")]
    assert [a.sha256 for a in res.anchors] == [
        hashlib.sha256(ca_fr.public_bytes(Encoding.DER)).hexdigest()]


def test_allowed_relabel_still_verifies_and_consumes(world):
    tl = consume_trust_list(_relabel(world["signed"], "US-ASCII"),
                            verify_signature=verify_xades_enveloped,
                            expected_signer_certs=[world["cert_n"]])
    assert len(tl.providers) == 1


def _past_allow_list(monkeypatch, enc):
    from openvc.trustlist import parse
    monkeypatch.setattr(parse, "_ALLOWED_ENCODINGS", parse._ALLOWED_ENCODINGS | {enc.upper()})


# Defence in depth: were a label ever added to the allow-list, expat's own bare
# ValueError / LookupError would still surface as the typed error. Both labels below fail
# in expat on every interpreter (multi-byte; a codec nobody knows).
@pytest.mark.parametrize("enc", ["GB2312", "x-no-such-codec-9f2a"])
def test_expat_own_failures_are_typed_even_past_the_allow_list(world, enc, monkeypatch):
    _past_allow_list(monkeypatch, enc)
    with pytest.raises(TrustListParseError, match="malformed trust list XML"):
        parse_trust_list(_relabel(world["signed"], enc))


def test_latin9_past_the_allow_list_parses_or_is_typed(world, monkeypatch):
    # an alias of ISO-8859-15: older interpreters raise LookupError, 3.15 resolves it
    _past_allow_list(monkeypatch, "latin-9")
    try:
        parse_trust_list(_relabel(world["signed"], "latin-9"))
    except TrustListParseError:
        pass


@pytest.mark.parametrize("enc", ["hz", "ISO-8859-2", "windows-1252", "UTF-7"])
def test_labels_expat_would_accept_are_still_refused(world, enc):
    # expat decodes these itself (a single-byte table, or an unknown-but-harmless label);
    # the allow-list refuses them anyway — only the XmlDeclHandler can do that
    with pytest.raises(TrustListParseError, match="unsupported XML encoding"):
        parse_trust_list(_relabel(world["signed"], enc))
