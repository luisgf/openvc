"""
tests/test_trustlist.py — EU Trusted List consumption (``openvc.trustlist``).

Fixtures under tests/fixtures/trustlist/ are ETSI TS 119 612 -**shaped** documents
with self-signed EC P-256 certs (not the live EU LOTL — the real XAdES signature is
the ``[trustlist]`` extra's concern). They pin the parser + fail-closed walk. Tests
are self-contained (tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import hashlib
import pathlib
from datetime import datetime, timezone

import pytest

from openvc.trustlist import (
    DEFAULT_SELECT,
    Select,
    ServiceStatus,
    ServiceType,
    TrustListParseError,
    TrustListSignatureError,
    TrustListSignatureUnavailable,
    consume_trust_list,
    parse_trust_list,
    walk_lotl,
)

_FIX = pathlib.Path(__file__).parent / "fixtures" / "trustlist"
LOTL = (_FIX / "eu-lotl.xml").read_bytes()
DE_TL = (_FIX / "de-tl.xml").read_bytes()

LOTL_URL = "https://ec.example/eu-lotl.xml"
DE_URL = "https://tl.example.de/de-tl.xml"


def _store(**overrides):
    s = {LOTL_URL: LOTL, DE_URL: DE_TL}
    s.update(overrides)
    return s


def _fetch_from(store):
    def _fetch(url):
        if url not in store:
            raise KeyError(f"no such TL {url!r}")
        return store[url]
    return _fetch


def _ok_sig(_xml, _certs):
    """A stub XML-signature verifier that accepts (the real one is the extra's job)."""
    return None


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def test_parse_lotl():
    tl = parse_trust_list(LOTL)
    assert tl.is_lotl is True
    assert tl.territory == "EU"
    assert tl.scheme_operator == "European Commission"
    assert tl.sequence_number == 42
    assert len(tl.pointers) == 2
    de = next(p for p in tl.pointers if p.location == DE_URL)
    assert de.territory == "DE"
    assert de.tsl_type.endswith("EUgeneric")
    assert de.mime_type == "application/vnd.etsi.tsl+xml"
    assert len(de.signer_certs) == 1


def test_parse_national_tl():
    tl = parse_trust_list(DE_TL)
    assert tl.is_lotl is False
    assert tl.territory == "DE"
    assert tl.next_update == datetime(2099, 1, 1, tzinfo=timezone.utc)
    assert len(tl.providers) == 1
    assert tl.version == 6                  # TLv6 (ETSI TS 119 612 v2.4.1)
    prov = tl.providers[0]
    assert prov.name == "Example TSP DE"
    assert len(prov.services) == 4          # 2 CA/QC + EDS/Q + RemoteQSealCDManagement/Q (TLv6)
    granted = next(s for s in prov.services if s.service_type == ServiceType.CA_QC
                   and s.service_status.endswith("granted"))
    assert granted.service_type == ServiceType.CA_QC
    assert granted.tsp_name == "Example TSP DE"
    assert granted.service_name == "QC CA (granted)"
    assert granted.territory == "DE"


def test_anchor_sha256_is_haip_x509_hash():
    tl = parse_trust_list(DE_TL)
    from cryptography.hazmat.primitives.serialization import Encoding
    svc = tl.providers[0].services[0]
    assert svc.sha256 == hashlib.sha256(svc.certificate.public_bytes(Encoding.DER)).hexdigest()


# --------------------------------------------------------------------------- #
# Hardening (the parser sees attacker-influenced bytes)
# --------------------------------------------------------------------------- #

def test_reject_doctype_entity_bomb():
    bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "AAAA">]>'
            b'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">&a;'
            b'</TrustServiceStatusList>')
    with pytest.raises(TrustListParseError):
        parse_trust_list(bomb)


def test_parse_element_count_cap():
    # ADR-0003 D4: a max element count bounds the parse in addition to the byte cap.
    from openvc.trustlist.parse import _hardened_parse
    xml = b"<a><b/><c/><d/><e/></a>"                    # 5 elements
    with pytest.raises(TrustListParseError):
        _hardened_parse(xml, max_bytes=10_000, max_elements=3)
    _hardened_parse(xml, max_bytes=10_000, max_elements=100)   # under the cap: fine


def test_reject_external_entity_xxe():
    xxe = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           b'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">&x;'
           b'</TrustServiceStatusList>')
    with pytest.raises(TrustListParseError):
        parse_trust_list(xxe)


def test_reject_oversize():
    with pytest.raises(TrustListParseError):
        parse_trust_list(LOTL, max_bytes=10)


def test_reject_non_bytes():
    with pytest.raises(TrustListParseError):
        parse_trust_list("not bytes")           # type: ignore[arg-type]


def test_reject_wrong_root():
    with pytest.raises(TrustListParseError):
        parse_trust_list(b'<html xmlns="http://uri.etsi.org/02231/v2#"></html>')


def test_reject_malformed_xml():
    with pytest.raises(TrustListParseError):
        parse_trust_list(b'<TrustServiceStatusList><unclosed>')


# --------------------------------------------------------------------------- #
# consume_trust_list — signature is fail-closed
# --------------------------------------------------------------------------- #

def test_consume_requires_verifier():
    with pytest.raises(TrustListSignatureUnavailable):
        consume_trust_list(DE_TL, verify_signature=None, expected_signer_certs=[])


def test_consume_verifies_before_parsing():
    calls = {}

    def _verify(xml, certs):
        calls["xml"] = xml
        calls["certs"] = certs

    consume_trust_list(DE_TL, verify_signature=_verify, expected_signer_certs=["c1", "c2"])
    assert calls["xml"] == DE_TL                 # raw bytes handed to the verifier
    assert calls["certs"] == ("c1", "c2")        # the expected signer certs, as a tuple


def test_consume_signature_failure_wrapped():
    def _boom(_xml, _certs):
        raise ValueError("bad XAdES")

    with pytest.raises(TrustListSignatureError):
        consume_trust_list(DE_TL, verify_signature=_boom, expected_signer_certs=[])


def test_consume_parse_failure_after_valid_signature():
    # signature OK but body malformed -> still a parse error (not silently trusted)
    with pytest.raises(TrustListParseError):
        consume_trust_list(b'<TrustServiceStatusList></nope>',
                           verify_signature=_ok_sig, expected_signer_certs=[])


# --------------------------------------------------------------------------- #
# walk_lotl — selection + fail-closed aggregation
# --------------------------------------------------------------------------- #

def test_walk_default_select_granted_qc_ca():
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["commission"],
                    verify_signature=_ok_sig, fetch=_fetch_from(_store()))
    assert len(res.anchors) == 1                 # granted CA/QC only (withdrawn + pivot excluded)
    assert res.anchors[0].service_status == ServiceStatus.GRANTED
    assert res.problems == ()
    assert len(res.certificates) == 1


def test_walk_select_none_returns_all_services():
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(_store()), select=None)
    assert len(res.anchors) == 4    # granted + withdrawn CA/QC, granted EDS/Q + RemoteQSealCD


# --------------------------------------------------------------------------- #
# TLv6 (ETSI TS 119 612 v2.4.1, mandatory since 29 Apr 2026) conformance (issue #58)
# --------------------------------------------------------------------------- #

def test_tlv6_version_is_parsed():
    assert parse_trust_list(LOTL).version == 6      # TSLVersionIdentifier
    assert parse_trust_list(DE_TL).version == 6


@pytest.mark.parametrize("svc_type", [
    ServiceType.EDS_Q, ServiceType.REMOTE_QSEALCD_MANAGEMENT_Q])
def test_tlv6_new_service_types_are_selectable(svc_type):
    # The qualified trust services beyond CA/QC that TLv6 national lists carry are
    # selectable by their named ServiceType constant.
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(_store()),
                    select=Select(service_types=frozenset({svc_type}),
                                  statuses=frozenset({ServiceStatus.GRANTED})))
    assert len(res.anchors) == 1 and res.anchors[0].service_type == svc_type


def test_tlv6_service_supply_point_is_tolerated():
    # <ServiceSupplyPoints> is a TLv6 addition the parser must ignore, not choke on:
    # the EDS/Q service in the fixture carries one and still parses + selects.
    tl = parse_trust_list(DE_TL)
    eds = [s for p in tl.providers for s in p.services if s.service_type == ServiceType.EDS_Q]
    assert len(eds) == 1 and eds[0].certificate is not None


def test_arbitrary_eudi_service_type_uri_is_selectable_verbatim():
    # EUDI trust services introduced by v2.4.1 (issuance of QEAA / EAA / PuB-EAA,
    # qualified electronic ledgers) are not yet named constants, but Select matches
    # ServiceTypeIdentifier verbatim — so a caller filters by the raw URI as national
    # lists start carrying it. Proven by injecting an (illustrative) EUDI type.
    qeaa = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
    de_v6 = DE_TL.replace(b"http://uri.etsi.org/TrstSvc/Svctype/EDS/Q", qeaa.encode())
    types = {s.service_type for p in parse_trust_list(de_v6).providers for s in p.services}
    assert qeaa in types
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch={LOTL_URL: LOTL, DE_URL: de_v6}.get,
                    select=Select(service_types=frozenset({qeaa}),
                                  statuses=frozenset({ServiceStatus.GRANTED})))
    assert len(res.anchors) == 1


def test_walk_select_by_status():
    both = Select(service_types=frozenset({ServiceType.CA_QC}),
                  statuses=frozenset({ServiceStatus.GRANTED, ServiceStatus.WITHDRAWN}))
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(_store()), select=both)
    assert len(res.anchors) == 2


def test_walk_national_tl_signer_certs_come_from_the_lotl():
    seen = []

    def _verify(_xml, certs):
        seen.append(certs)

    walk_lotl(LOTL_URL, lotl_signer_certs=["commission"], verify_signature=_verify,
              fetch=_fetch_from(_store()))
    # first call verifies the LOTL against the caller-pinned cert; second verifies the
    # DE TL against the signer cert the LOTL vouched for (parsed from its pointer).
    assert seen[0] == ("commission",)
    lotl = parse_trust_list(LOTL)
    de_pointer = next(p for p in lotl.pointers if p.location == DE_URL)
    assert seen[1] == de_pointer.signer_certs


def test_walk_national_tl_fetch_failure_is_a_problem_not_an_abort():
    store = _store()
    del store[DE_URL]                            # DE TL unreachable
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(store))
    assert res.anchors == ()
    assert len(res.problems) == 1
    assert res.problems[0].location == DE_URL and res.problems[0].stage == "fetch"


def test_walk_national_tl_signature_failure_is_fail_closed():
    def _verify(xml, _certs):
        if xml == DE_TL:                         # the LOTL verifies, the DE TL does not
            raise ValueError("forged DE TL")

    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_verify,
                    fetch=_fetch_from(_store()))
    assert res.anchors == ()                     # a forged TL contributes nothing
    assert len(res.problems) == 1 and res.problems[0].stage == "signature"


def test_walk_expired_lotl_yields_nothing():
    future = datetime(2100, 1, 1, tzinfo=timezone.utc)
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(_store()), now=future)
    assert res.anchors == ()
    assert len(res.problems) == 1 and res.problems[0].stage == "expired"


def test_walk_expired_national_tl_is_skipped_with_problem():
    # a DE TL whose NextUpdate is in the past (LOTL still valid)
    expired_de = DE_TL.replace(b"2099-01-01T00:00:00Z", b"2020-01-01T00:00:00Z")
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(_store(**{DE_URL: expired_de})))
    assert res.anchors == ()
    assert len(res.problems) == 1 and res.problems[0].stage == "expired"


def test_walk_lotl_fetch_failure_yields_only_a_problem():
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from({}))       # LOTL itself unreachable
    assert res.anchors == ()
    assert len(res.problems) == 1
    assert res.problems[0].location == LOTL_URL and res.problems[0].stage == "fetch"


def test_walk_requires_verifier():
    res_problem = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=None,
                            fetch=_fetch_from(_store()))
    # a missing verifier fails the LOTL consume (fail-closed) -> a signature problem
    assert res_problem.anchors == ()
    assert res_problem.problems[0].stage == "signature"


def test_default_select_is_granted_qc_ca():
    assert DEFAULT_SELECT.statuses == frozenset({ServiceStatus.GRANTED})
    assert DEFAULT_SELECT.service_types == frozenset({ServiceType.CA_QC})


# --------------------------------------------------------------------------- #
# The anchors feed the x5c trust-anchor path (integration shape)
# --------------------------------------------------------------------------- #

def test_certificates_feed_x5c_anchor_shape():
    from cryptography import x509
    res = walk_lotl(LOTL_URL, lotl_signer_certs=["c"], verify_signature=_ok_sig,
                    fetch=_fetch_from(_store()), select=None)
    certs = res.certificates
    assert certs and all(isinstance(c, x509.Certificate) for c in certs)
    # x509_hashes (HAIP) has one hex sha256 per distinct anchor
    assert len(res.x509_hashes) == len(certs)
