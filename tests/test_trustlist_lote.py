"""ETSI TS 119 602 LoTE lane — the JSON trusted-list codec, its JAdES-compact
verification, the EU WRPAC/WRPRC providers-list profiles, and the walk.

Self-made signed vectors (no third-party LoTE artifact exists yet — the
Commission's lists are unpublished; the real-list goldens are gated on their
publication, tracked in the issue). The URIs are pinned byte-for-byte against
TS 119 602 V1.1.1 Annex C / Tables F.1–G.3 — including the ``WRPRCroviders``
StatusDetn typo the spec (and the EUDI reference implementation) carry — so an
erratum shows up as a test failure, not silent drift.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from openvc.keys import P256SigningKey
from openvc.trustlist import (
    EU_WRPAC_PROVIDERS_PROFILE,
    EU_WRPRC_PROVIDERS_PROFILE,
    LoteServiceType,
    LoteType,
    Select,
    TrustListParseError,
    TrustListProfileError,
    TrustListSignatureError,
    consume_lote,
    parse_lote,
    walk_lote,
)

_NOW = dt.datetime(2026, 7, 22, tzinfo=dt.timezone.utc)
_URI = "http://uri.etsi.org/19602"


# --------------------------------------------------------------------------- #
# builders — an operator (list signer), a registrar CA (the anchor), documents
# --------------------------------------------------------------------------- #

def _cert(subject, issuer, subject_key, signer_key, exts, *, before=None, after=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(before or _NOW - dt.timedelta(days=30))
         .not_valid_after(after or _NOW + dt.timedelta(days=3650)))
    for ext, crit in exts:
        b = b.add_extension(ext, crit)
    return b.sign(signer_key, hashes.SHA256())


def _operator(org="European Commission", country="EU", *, key=None,
              before=None, after=None):
    """A scheme-operator list-signing certificate whose DN satisfies clause 6.8."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, "LoTE signer")])
    cert = _cert(name, name, key, key,
                 [(x509.BasicConstraints(False, None), True)],
                 before=before, after=after)
    return cert, key


def _ca(cn="Registrar Root CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = _cert(name, name, key, key,
                 [(x509.BasicConstraints(True, None), True),
                  (x509.KeyUsage(False, False, False, False, False, True, True,
                                 False, False), True)])
    return cert, key, name


def _b64(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _doc(anchor_b64, *, lote_type=LoteType.EU_WRPRC_PROVIDERS,
         svc_type=LoteServiceType.WRPRC_ISSUANCE,
         status_detn=f"{_URI}/WRPRCrovidersList/StatusDetn/EU",
         rules=f"{_URI}/WRPRCProvidersList/schemerules/EU",
         pointers=None) -> dict:
    """A profile-conformant WRPRC providers LoTE document (Tables G.1–G.3)."""
    scheme = {
        "LoTEVersionIdentifier": 1,
        "LoTESequenceNumber": 1,
        "LoTEType": lote_type,
        "SchemeOperatorName": [{"lang": "en", "value": "European Commission"}],
        "StatusDeterminationApproach": status_detn,
        "SchemeTypeCommunityRules": [{"lang": "en", "uriValue": rules}],
        "SchemeTerritory": "EU",
        "ListIssueDateTime": "2026-07-01T00:00:00Z",
        "NextUpdate": "2026-12-01T00:00:00Z",
    }
    if pointers is not None:
        scheme["PointersToOtherLoTE"] = pointers
    return {"LoTE": {
        "ListAndSchemeInformation": scheme,
        "TrustedEntitiesList": [{
            "TrustedEntityInformation": {
                "TEName": [{"lang": "en", "value": "Registrar"}],
                "TEAddress": {
                    "TEPostalAddress": [
                        {"lang": "en", "StreetAddress": "Calle Uno 1", "Country": "ES"}],
                    "TEElectronicAddress": [
                        {"lang": "en", "uriValue": "mailto:registrar@example.es"}]},
                "TEInformationURI": [
                    {"lang": "en", "uriValue": "https://registrar.example.es/info"}]},
            "TrustedEntityServices": [{
                "ServiceInformation": {
                    "ServiceName": [{"lang": "en", "value": "WRPRC issuance"}],
                    "ServiceTypeIdentifier": svc_type,
                    "ServiceDigitalIdentity": {
                        "X509Certificates": [{"val": anchor_b64}]}}}]}],
    }}


def _pointer(location, voucher_cert, *, lote_type=LoteType.EU_WRPRC_PROVIDERS,
             territory=None) -> dict:
    qualifier = {"LoTEType": lote_type,
                 "SchemeOperatorName": [{"lang": "en", "value": "European Commission"}],
                 "MimeType": "application/jose"}
    if territory is not None:
        qualifier["SchemeTerritory"] = territory
    return {"LoTELocation": location,
            "ServiceDigitalIdentities": [
                {"X509Certificates": [{"val": _b64(voucher_cert)}]}],
            "LoTEQualifiers": [qualifier]}


def _sign(doc, key, cert, *, alg="ES256", header=None) -> str:
    head = {"alg": alg, "x5c": [_b64(cert)]}
    head.update(header or {})
    signing_input = (
        f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(doc, separators=(',', ':')).encode())}")
    sig = P256SigningKey(key, "lote-signer").sign(signing_input.encode())
    return f"{signing_input}.{_b64url(sig)}"


@pytest.fixture()
def operator():
    return _operator()


@pytest.fixture()
def registrar_anchor():
    """(ca_cert, ca_key, ca_name) — the registrar CA the list will anchor."""
    return _ca()


@pytest.fixture()
def signed(operator, registrar_anchor):
    """(token, doc, op_cert) — a conformant signed WRPRC providers list."""
    op_cert, op_key = operator
    doc = _doc(_b64(registrar_anchor[0]))
    return _sign(doc, op_key, op_cert), doc, op_cert


# --------------------------------------------------------------------------- #
# envelope + signature — reject before trusting
# --------------------------------------------------------------------------- #

def test_consume_verifies_and_parses_under_the_wrprc_profile(signed, registrar_anchor):
    token, _, op_cert = signed
    tl = consume_lote(token, expected_signer_certs=[op_cert],
                      profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW)
    assert tl.tsl_type == LoteType.EU_WRPRC_PROVIDERS
    assert tl.version == 1 and tl.sequence_number == 1
    assert tl.territory == "EU" and tl.scheme_operator == "European Commission"
    anchors = [s for p in tl.providers for s in p.services]
    assert len(anchors) == 1
    assert anchors[0].service_type == LoteServiceType.WRPRC_ISSUANCE
    assert anchors[0].certificate.public_bytes(serialization.Encoding.DER) == \
        registrar_anchor[0].public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize("alg", ["none", "HS256", "RS256", "ES256K"])
def test_rejects_algorithms_outside_the_allow_list(operator, alg):
    op_cert, op_key = operator
    doc = _doc(_b64(op_cert))
    good = _sign(doc, op_key, op_cert)
    head = {"alg": alg, "x5c": [_b64(op_cert)]}
    parts = good.split(".")
    forged = (f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
              f"{parts[1]}.{parts[2]}")
    with pytest.raises(TrustListSignatureError, match="not permitted"):
        consume_lote(forged, expected_signer_certs=[op_cert], now=_NOW)


def test_crit_accepts_a_processed_jades_parameter(operator, registrar_anchor):
    op_cert, op_key = operator
    doc = _doc(_b64(registrar_anchor[0]))
    token = _sign(doc, op_key, op_cert,
                  header={"iat": int(_NOW.timestamp()), "crit": ["iat"]})
    tl = consume_lote(token, expected_signer_certs=[op_cert], now=_NOW)
    assert tl.sequence_number == 1


@pytest.mark.parametrize("crit,detail", [
    (["exp"], "does not process"),                 # a parameter outside the allow-list
    (["iat"], "not present"),                      # named but absent
    ([], "non-empty"),                             # malformed shapes
    ("iat", "non-empty"),
    ([7], "non-empty"),
])
def test_crit_fails_closed(operator, crit, detail):
    op_cert, op_key = operator
    token = _sign(_doc(_b64(op_cert)), op_key, op_cert, header={"crit": crit})
    with pytest.raises(TrustListSignatureError, match=detail):
        consume_lote(token, expected_signer_certs=[op_cert], now=_NOW)


def test_rejects_a_header_without_x5c(operator):
    op_cert, op_key = operator
    doc = _doc(_b64(op_cert))
    head = {"alg": "ES256"}
    signing_input = (
        f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(doc, separators=(',', ':')).encode())}")
    sig = P256SigningKey(op_key, "k").sign(signing_input.encode())
    with pytest.raises(TrustListSignatureError, match="x5c"):
        consume_lote(f"{signing_input}.{_b64url(sig)}",
                     expected_signer_certs=[op_cert], now=_NOW)


@pytest.mark.parametrize("segment", [1, 2])
def test_rejects_a_tampered_token(signed, segment):
    token, _, op_cert = signed
    parts = token.split(".")
    # flip the FIRST character of the segment — fully significant bits
    flipped = ("A" if parts[segment][0] != "A" else "B") + parts[segment][1:]
    parts[segment] = flipped
    with pytest.raises((TrustListSignatureError, TrustListParseError)):
        consume_lote(".".join(parts), expected_signer_certs=[op_cert], now=_NOW)


def test_rejects_an_unpinned_signer(operator):
    op_cert, op_key = operator
    other_cert, _ = _operator()                     # same DN, different key — not pinned
    token = _sign(_doc(_b64(op_cert)), op_key, op_cert)
    with pytest.raises(TrustListSignatureError, match="not pinned"):
        consume_lote(token, expected_signer_certs=[other_cert], now=_NOW)


def test_no_expected_signer_certs_fails_closed(signed):
    token, _, _ = signed
    with pytest.raises(TrustListSignatureError, match="never trusted unverified"):
        consume_lote(token, expected_signer_certs=[], now=_NOW)


def test_accepts_a_leaf_chaining_to_a_pinned_ca(registrar_anchor):
    ca_cert, ca_key, ca_name = _ca("Operator CA")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "European Commission"),
        x509.NameAttribute(NameOID.COMMON_NAME, "LoTE signer 2026")])
    leaf = _cert(leaf_name, ca_name, leaf_key, ca_key,
                 [(x509.BasicConstraints(False, None), True)])
    doc = _doc(_b64(registrar_anchor[0]))
    head = {"alg": "ES256", "x5c": [_b64(leaf), _b64(ca_cert)]}
    signing_input = (
        f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(doc, separators=(',', ':')).encode())}")
    sig = P256SigningKey(leaf_key, "k").sign(signing_input.encode())
    tl = consume_lote(f"{signing_input}.{_b64url(sig)}",
                      expected_signer_certs=[ca_cert], now=_NOW)
    assert tl.sequence_number == 1


def test_rejects_a_pinned_leaf_outside_its_validity_window(registrar_anchor):
    op_cert, op_key = _operator(
        before=_NOW - dt.timedelta(days=730), after=_NOW - dt.timedelta(days=365))
    token = _sign(_doc(_b64(registrar_anchor[0])), op_key, op_cert)
    with pytest.raises(TrustListSignatureError, match="validity window"):
        consume_lote(token, expected_signer_certs=[op_cert], now=_NOW)


def test_rejects_a_signer_whose_organization_matches_no_operator_name(registrar_anchor):
    op_cert, op_key = _operator(org="Mallory Scheme Op")
    token = _sign(_doc(_b64(registrar_anchor[0])), op_key, op_cert)
    with pytest.raises(TrustListSignatureError, match="organizationName"):
        consume_lote(token, expected_signer_certs=[op_cert], now=_NOW)


def test_rejects_a_signer_country_that_is_not_the_scheme_territory(registrar_anchor):
    op_cert, op_key = _operator(country="ES")       # list says SchemeTerritory EU
    token = _sign(_doc(_b64(registrar_anchor[0])), op_key, op_cert)
    with pytest.raises(TrustListSignatureError, match="countryName"):
        consume_lote(token, expected_signer_certs=[op_cert], now=_NOW)


# --------------------------------------------------------------------------- #
# strict structural parsing
# --------------------------------------------------------------------------- #

def _mutated(signed_fixture, mutate):
    token, doc, op_cert = signed_fixture
    doc = copy.deepcopy(doc)
    mutate(doc)
    return doc


def test_parse_rejects_unknown_members(signed, operator):
    op_cert, op_key = operator
    for mutate, member in [
        (lambda d: d.update({"Extra": 1}), "Extra"),
        (lambda d: d["LoTE"].update({"Extra": 1}), "Extra"),
        (lambda d: d["LoTE"]["ListAndSchemeInformation"].update({"TSLType": "x"}), "TSLType"),
        (lambda d: d["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
            ["ServiceInformation"].update({"ServicePreviousStatus": "x"}),
         "ServicePreviousStatus"),
    ]:
        doc = _mutated(signed, mutate)
        with pytest.raises(TrustListParseError, match="unknown member"):
            parse_lote(doc)


def test_parse_rejects_a_bool_where_an_integer_is_required(signed):
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .update({"LoTEVersionIdentifier": True}))
    with pytest.raises(TrustListParseError, match="integer"):
        parse_lote(doc)


def test_parse_requires_the_utc_z_datetime_form(signed):
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .update({"NextUpdate": "2026-12-01T00:00:00+00:00"}))
    with pytest.raises(TrustListParseError, match="clause 6.1.3"):
        parse_lote(doc)


def test_parse_rejects_missing_required_scheme_members(signed):
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .pop("SchemeOperatorName"))
    with pytest.raises(TrustListParseError, match="missing required"):
        parse_lote(doc)


def test_a_malformed_certificate_blob_is_skipped_never_trusted(signed, registrar_anchor):
    good = _b64(registrar_anchor[0])
    doc = _mutated(signed, lambda d: d["LoTE"]["TrustedEntitiesList"][0]
                   ["TrustedEntityServices"][0]["ServiceInformation"]
                   ["ServiceDigitalIdentity"]["X509Certificates"]
                   .insert(0, {"val": base64.b64encode(b"not-a-cert").decode()}))
    tl = parse_lote(doc)
    anchors = [s for p in tl.providers for s in p.services]
    assert len(anchors) == 1                        # only the good blob became an anchor
    assert anchors[0].certificate.public_bytes(serialization.Encoding.DER) == \
        base64.b64decode(good)


def test_an_unrecognised_critical_extension_rejects_the_list(signed):
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .update({"SchemeExtensions": [{"critical": True, "Weird": 1}]}))
    with pytest.raises(TrustListParseError, match="critical extension"):
        parse_lote(doc)
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .update({"SchemeExtensions": [{"critical": False, "Weird": 1}]}))
    parse_lote(doc)                                 # non-critical: carried opaquely


@pytest.mark.parametrize("mutate", [
    lambda d: d["LoTE"].update({"TrustedEntitiesList": []}),
    lambda d: (d["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
               ["ServiceInformation"]["ServiceDigitalIdentity"]
               .update({"X509Certificates": []})),
    lambda d: d["LoTE"]["ListAndSchemeInformation"].update({"PointersToOtherLoTE": []}),
])
def test_parse_rejects_empty_containers(signed, mutate):
    with pytest.raises(TrustListParseError, match="empty"):
        parse_lote(_mutated(signed, mutate))


def test_a_closed_lote_parses_with_a_null_next_update(signed):
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .update({"NextUpdate": None}))
    assert parse_lote(doc).next_update is None


# --------------------------------------------------------------------------- #
# the EU profiles (Annex F / G)
# --------------------------------------------------------------------------- #

def _consume_mutated(operator, registrar_anchor, mutate, **doc_kw):
    op_cert, op_key = operator
    doc = _doc(_b64(registrar_anchor[0]), **doc_kw)
    mutate(doc)
    token = _sign(doc, op_key, op_cert)
    return consume_lote(token, expected_signer_certs=[op_cert],
                        profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW)


def test_profile_constants_pin_the_spec_uris_byte_for_byte():
    """The drift alarm: Table G.1 spells the StatusDetn URI ``WRPRCroviders``
    (sic) and the reference implementation follows suit — an ETSI erratum (or a
    corrected republication) must surface here, not silently."""
    assert EU_WRPRC_PROVIDERS_PROFILE.status_determination == (
        "http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU",
        "http://uri.etsi.org/19602/WRPRCProvidersList/StatusDetn/EU",
    )
    assert EU_WRPRC_PROVIDERS_PROFILE.lote_type == \
        "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList"
    assert EU_WRPRC_PROVIDERS_PROFILE.scheme_rules == \
        "http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU"
    assert EU_WRPAC_PROVIDERS_PROFILE.status_determination == (
        "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU",)
    assert LoteServiceType.WRPRC_ISSUANCE == \
        "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance"
    assert LoteServiceType.WRPAC_REVOCATION == \
        "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation"


def test_profile_accepts_both_status_detn_spellings(operator, registrar_anchor):
    for spelling in EU_WRPRC_PROVIDERS_PROFILE.status_determination:
        tl = _consume_mutated(operator, registrar_anchor, lambda d: None,
                              status_detn=spelling)
        assert tl.version == 1


@pytest.mark.parametrize("mutate,detail", [
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .update({"LoTEVersionIdentifier": 2}), "LoTEVersionIdentifier"),
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .update({"LoTEType": LoteType.EU_WRPAC_PROVIDERS}), "LoTEType"),
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .pop("StatusDeterminationApproach"), "StatusDeterminationApproach"),
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .update({"SchemeTypeCommunityRules": [
            {"lang": "en", "uriValue": "https://elsewhere.example/rules"}]}),
     "SchemeTypeCommunityRules"),
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .update({"SchemeTerritory": "ES"}), "SchemeTerritory"),
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .update({"HistoricalInformationPeriod": 65535}), "HistoricalInformationPeriod"),
    (lambda d: d["LoTE"]["ListAndSchemeInformation"]
        .update({"NextUpdate": "2027-02-01T00:00:00Z"}), "months"),
    (lambda d: d["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
        ["ServiceInformation"]
        .update({"ServiceStatus": "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"}),
     "ServiceStatus"),
    (lambda d: d["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
        ["ServiceInformation"]
        .update({"StatusStartingTime": "2026-07-01T00:00:00Z"}), "StatusStartingTime"),
    (lambda d: d["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
        ["ServiceInformation"]
        .update({"ServiceTypeIdentifier": LoteServiceType.WRPAC_ISSUANCE}),
     "exclusive"),
])
def test_profile_fails_closed_on_every_annex_g_violation(
        operator, registrar_anchor, mutate, detail):
    # note: the ES-territory mutation also breaks the 6.8 country binding, which
    # fires first — both are the same fail-closed outcome
    with pytest.raises((TrustListProfileError, TrustListSignatureError), match=detail):
        _consume_mutated(operator, registrar_anchor, mutate)


def test_the_signer_dn_territory_check_runs_before_the_profile(operator, registrar_anchor):
    # a list whose territory changed no longer matches the signer C=EU: 6.8 fires
    with pytest.raises(TrustListSignatureError, match="SchemeTerritory"):
        _consume_mutated(
            operator, registrar_anchor,
            lambda d: d["LoTE"]["ListAndSchemeInformation"].update({"SchemeTerritory": "ES"}))


# --------------------------------------------------------------------------- #
# walk — fail-closed accounting, vouched pointers, caps
# --------------------------------------------------------------------------- #

def test_walk_collects_anchors_and_follows_a_vouched_pointer(operator, registrar_anchor):
    op_cert, op_key = operator
    second_cert, second_key = _operator(org="Second Operator", country="EU")
    second_anchor, _, _ = _ca("Second Registrar CA")
    second_doc = _doc(_b64(second_anchor))
    second_doc["LoTE"]["ListAndSchemeInformation"]["SchemeOperatorName"] = [
        {"lang": "en", "value": "Second Operator"}]
    second_tok = _sign(second_doc, second_key, second_cert)

    root_doc = _doc(_b64(registrar_anchor[0]), pointers=[
        _pointer("https://root.example/self.jwt", op_cert),          # self — skipped
        _pointer("https://second.example/lote.jwt", second_cert)])   # vouched hop
    root_tok = _sign(root_doc, op_key, op_cert)

    fetched: list[str] = []

    def fetch(url: str) -> bytes:
        fetched.append(url)
        return (root_tok if url == "https://root.example/self.jwt" else second_tok).encode()

    result = walk_lote(
        "https://root.example/self.jwt", lote_signer_certs=[op_cert],
        profile=EU_WRPRC_PROVIDERS_PROFILE, fetch=fetch, now=_NOW)
    assert not result.problems
    assert len(result.certificates) == 2            # both registrars, deduplicated
    assert fetched == ["https://root.example/self.jwt", "https://second.example/lote.jwt"]


def test_walk_rejects_a_pointed_list_signed_outside_the_vouched_certs(
        operator, registrar_anchor):
    op_cert, op_key = operator
    voucher_cert, _ = _operator(org="Second Operator")   # whom the pointer vouches
    mallory_cert, mallory_key = _operator(org="Second Operator")  # same DN, other key
    pointed = _sign(_doc(_b64(registrar_anchor[0])), mallory_key, mallory_cert)
    root_doc = _doc(_b64(registrar_anchor[0]), pointers=[
        _pointer("https://second.example/lote.jwt", voucher_cert)])
    root_tok = _sign(root_doc, op_key, op_cert)

    result = walk_lote(
        "https://root.example/lote.jwt", lote_signer_certs=[op_cert],
        profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW,
        fetch=lambda u: (root_tok if "root" in u else pointed).encode())
    assert len(result.anchors) == 1                 # the root's own anchor survives
    assert [p.stage for p in result.problems] == ["signature"]


def test_walk_stages_an_expired_root_as_a_problem(operator, registrar_anchor):
    op_cert, op_key = operator
    token = _sign(_doc(_b64(registrar_anchor[0])), op_key, op_cert)
    late = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)
    result = walk_lote("https://root.example/lote.jwt",
                       lote_signer_certs=[op_cert], now=late,
                       fetch=lambda u: token.encode())
    assert result.anchors == () and [p.stage for p in result.problems] == ["expired"]


def test_walk_stages_a_closed_root_as_a_problem(operator, registrar_anchor):
    op_cert, op_key = operator
    doc = _doc(_b64(registrar_anchor[0]))
    doc["LoTE"]["ListAndSchemeInformation"]["NextUpdate"] = None
    token = _sign(doc, op_key, op_cert)
    result = walk_lote("https://root.example/lote.jwt",
                       lote_signer_certs=[op_cert], now=_NOW,
                       fetch=lambda u: token.encode())
    assert result.anchors == ()
    assert [p.stage for p in result.problems] == ["expired"]
    assert "closed" in result.problems[0].detail


def test_walk_stages_a_fetch_failure_without_aborting(operator, registrar_anchor):
    op_cert, op_key = operator
    voucher_cert, _ = _operator(org="Second Operator")
    root_doc = _doc(_b64(registrar_anchor[0]), pointers=[
        _pointer("https://gone.example/lote.jwt", voucher_cert)])
    root_tok = _sign(root_doc, op_key, op_cert)

    def fetch(url: str) -> bytes:
        if "gone" in url:
            raise OSError("connection refused")
        return root_tok.encode()

    result = walk_lote("https://root.example/lote.jwt",
                       lote_signer_certs=[op_cert],
                       profile=EU_WRPRC_PROVIDERS_PROFILE, fetch=fetch, now=_NOW)
    assert len(result.anchors) == 1
    assert [p.stage for p in result.problems] == ["fetch"]


def test_walk_enforces_the_list_cap(operator, registrar_anchor):
    op_cert, op_key = operator
    voucher_cert, _ = _operator(org="Second Operator")
    root_doc = _doc(_b64(registrar_anchor[0]), pointers=[
        _pointer("https://a.example/lote.jwt", voucher_cert),
        _pointer("https://b.example/lote.jwt", voucher_cert)])
    root_tok = _sign(root_doc, op_key, op_cert)
    result = walk_lote("https://root.example/lote.jwt",
                       lote_signer_certs=[op_cert], now=_NOW, max_lists=1,
                       fetch=lambda u: root_tok.encode())
    assert len(result.anchors) == 1
    assert {p.stage for p in result.problems} == {"consume"}
    assert all("cap" in p.detail for p in result.problems)


def test_walk_applies_a_service_type_select(operator, registrar_anchor):
    op_cert, op_key = operator
    token = _sign(_doc(_b64(registrar_anchor[0])), op_key, op_cert)
    result = walk_lote(
        "https://root.example/lote.jwt", lote_signer_certs=[op_cert], now=_NOW,
        fetch=lambda u: token.encode(),
        select=Select(service_types=frozenset({LoteServiceType.WRPRC_REVOCATION})))
    assert result.anchors == () and result.problems == ()


# --------------------------------------------------------------------------- #
# adversarial-review regressions (M1, L1, L2, I2)
# --------------------------------------------------------------------------- #

def _two_service_doc(issuance_b64, revocation_b64):
    doc = _doc(issuance_b64)
    doc["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"].append({
        "ServiceInformation": {
            "ServiceName": [{"lang": "en", "value": "WRPRC status"}],
            "ServiceTypeIdentifier": LoteServiceType.WRPRC_REVOCATION,
            "ServiceDigitalIdentity": {"X509Certificates": [{"val": revocation_b64}]}}})
    return doc


def test_default_profiled_walk_keeps_issuance_anchors_only(operator):
    """M1: a provider's *revocation* service is a legitimate list entry, but its
    certificates must not anchor credential verification by default."""
    op_cert, op_key = operator
    iss_ca, _, _ = _ca("Issuance CA")
    rev_ca, _, _ = _ca("Revocation CA")
    token = _sign(_two_service_doc(_b64(iss_ca), _b64(rev_ca)), op_key, op_cert)

    result = walk_lote("https://ec.example/wrprc.jwt", lote_signer_certs=[op_cert],
                       profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW,
                       fetch=lambda u: token.encode())
    assert [a.service_type for a in result.anchors] == [LoteServiceType.WRPRC_ISSUANCE]

    everything = walk_lote("https://ec.example/wrprc.jwt", lote_signer_certs=[op_cert],
                           profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW, select=None,
                           fetch=lambda u: token.encode())
    assert len(everything.certificates) == 2        # the explicit escape hatch


def test_a_wrprc_signed_under_the_revocation_ca_is_rejected_by_the_default_flow(operator):
    """M1 end to end: the documented walk → .certificates → verify flow must not
    let a revocation-service key validate a WRPRC chain."""
    from openvc.rp_registration import (
        RpRegistrationError, verify_rp_registration_certificate)

    op_cert, op_key = operator
    iss_ca, _, _ = _ca("Issuance CA")
    rev_ca, rev_key, rev_name = _ca("Revocation CA")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Revocation-side leaf")]),
        rev_name, leaf_key, rev_key,
        [(x509.BasicConstraints(False, None), True)])
    token = _sign(_two_service_doc(_b64(iss_ca), _b64(rev_ca)), op_key, op_cert)
    anchors = walk_lote("https://ec.example/wrprc.jwt", lote_signer_certs=[op_cert],
                        profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW,
                        fetch=lambda u: token.encode())

    claims = {"sub": "VATES-B1", "iat": int(_NOW.timestamp()) - 60,
              "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"]}
    head = {"typ": "rc-wrp+jwt", "alg": "ES256", "x5c": [_b64(leaf)]}
    signing_input = (
        f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(claims, separators=(',', ':')).encode())}")
    sig = P256SigningKey(leaf_key, "k").sign(signing_input.encode())
    wrprc = f"{signing_input}.{_b64url(sig)}"

    with pytest.raises(RpRegistrationError, match="did not validate"):
        verify_rp_registration_certificate(
            wrprc, trust_anchors=anchors.certificates, now=_NOW)


def test_a_profiled_walk_does_not_follow_foreign_type_pointers(operator, registrar_anchor):
    """M1, pointer facet: a WRPAC-typed pointer cannot drag its list into a
    WRPRC-profiled walk — not followed, staged as a problem, never fetched."""
    op_cert, op_key = operator
    voucher_cert, _ = _operator(org="Second Operator")
    root_doc = _doc(_b64(registrar_anchor[0]), pointers=[
        _pointer("https://wpac.example/lote.jwt", voucher_cert,
                 lote_type=LoteType.EU_WRPAC_PROVIDERS)])
    root_tok = _sign(root_doc, op_key, op_cert)
    fetched: list[str] = []

    def fetch(url: str) -> bytes:
        fetched.append(url)
        return root_tok.encode()

    result = walk_lote("https://root.example/lote.jwt", lote_signer_certs=[op_cert],
                       profile=EU_WRPRC_PROVIDERS_PROFILE, fetch=fetch, now=_NOW)
    assert len(result.anchors) == 1
    assert [p.stage for p in result.problems] == ["profile"]
    assert fetched == ["https://root.example/lote.jwt"]   # the foreign hop never fetched


def test_a_far_future_issue_date_fails_closed_not_valueerror(operator, registrar_anchor):
    """L1: a year-9999 issue date must land in the typed error family (and the
    walk's problems), not crash with an uncaught ValueError."""
    op_cert, op_key = operator
    doc = _doc(_b64(registrar_anchor[0]))
    doc["LoTE"]["ListAndSchemeInformation"]["ListIssueDateTime"] = "9999-12-01T00:00:00Z"
    doc["LoTE"]["ListAndSchemeInformation"]["NextUpdate"] = "9999-12-30T00:00:00Z"
    token = _sign(doc, op_key, op_cert)
    with pytest.raises(TrustListProfileError, match="update window"):
        consume_lote(token, expected_signer_certs=[op_cert],
                     profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW)
    result = walk_lote("https://root.example/lote.jwt", lote_signer_certs=[op_cert],
                       profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW,
                       fetch=lambda u: token.encode())
    assert result.anchors == ()
    assert [p.stage for p in result.problems] == ["profile"]


def test_profile_rejects_an_empty_string_service_status(operator, registrar_anchor):
    """L2: ``"ServiceStatus": ""`` is *present* — presence is the violation."""
    with pytest.raises(TrustListProfileError, match="ServiceStatus"):
        _consume_mutated(
            operator, registrar_anchor,
            lambda d: d["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
            ["ServiceInformation"].update({"ServiceStatus": ""}))


@pytest.mark.parametrize("form", [
    "2026-07-01 00:00:00Z",                 # space separator
    "2026-07-01T00:00:00.123Z",             # decimal fraction
    "2026-W27-1T00:00:00Z",                 # ISO week-date
])
def test_datetime_fields_require_the_exact_clause_6_1_3_form(signed, form):
    """I2: clause 6.1.3 mandates YYYY-MM-DDThh:mm:ssZ exactly."""
    doc = _mutated(signed, lambda d: d["LoTE"]["ListAndSchemeInformation"]
                   .update({"NextUpdate": form}))
    with pytest.raises(TrustListParseError, match="clause 6.1.3"):
        parse_lote(doc)


# --------------------------------------------------------------------------- #
# integration — LoTE anchors feed the WRPRC verify path
# --------------------------------------------------------------------------- #

def test_lote_anchors_verify_a_wrprc_end_to_end(operator):
    """The Annex G list anchors a registrar CA; a WRPRC signed under that CA
    verifies with the walked ``.certificates`` — the whole point of the lane."""
    from openvc.rp_registration import verify_rp_registration_certificate

    op_cert, op_key = operator
    ca_cert, ca_key, ca_name = _ca()
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Registrar Signing Key")]),
        ca_name, leaf_key, ca_key,
        [(x509.BasicConstraints(False, None), True),
         (x509.ExtendedKeyUsage([ObjectIdentifier("0.4.0.19475.2.1")]), False)])

    lote_token = _sign(_doc(_b64(ca_cert)), op_key, op_cert)
    anchors = walk_lote("https://ec.example/wrprc-providers.jwt",
                        lote_signer_certs=[op_cert],
                        profile=EU_WRPRC_PROVIDERS_PROFILE, now=_NOW,
                        fetch=lambda u: lote_token.encode())
    assert not anchors.problems

    wrprc_claims = {
        "sub": "VATES-B12345678", "name": "Acme Age Check", "country": "ES",
        "registry_uri": "https://registrar.example/ES",
        "iat": int(_NOW.timestamp()) - 3600,
        "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
        "intended_use_id": "age-verification",
        "purpose": [{"lang": "en", "value": "Age check"}],
        "credentials": [{"format": "dc+sd-jwt",
                         "meta": {"vct_values": ["urn:eudi:pid:1"]},
                         "claims": [{"path": ["age_equal_or_over", "18"]}]}],
    }
    head = {"typ": "rc-wrp+jwt", "alg": "ES256", "x5c": [_b64(leaf)]}
    signing_input = (
        f"{_b64url(json.dumps(head, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(wrprc_claims, separators=(',', ':')).encode())}")
    sig = P256SigningKey(leaf_key, "registrar").sign(signing_input.encode())
    wrprc = f"{signing_input}.{_b64url(sig)}"

    reg = verify_rp_registration_certificate(
        wrprc, trust_anchors=anchors.certificates, now=_NOW)
    assert reg.subject_identifier == "VATES-B12345678"
    assert reg.intended_use_id == "age-verification"
