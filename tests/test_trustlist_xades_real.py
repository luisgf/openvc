"""
tests/test_trustlist_xades_real.py — the XAdES verifier against **real
Commission-signed artifacts** (issue #114).

The round-trip suite (``test_trustlist_xades.py``) signs and verifies with the
same library, so it only proves we agree with ourselves — and that self-referential
gap was real: the 1-reference pin shipped in v1.20.0 rejected every genuine EU
trusted list (XAdES-BASELINE signatures carry the enveloped document **plus** their
own ``SignedProperties``). These goldens pin the fix to actual eIDAS signatures:
the EU LOTL (sequence 388) and the Spanish national TL (sequence 187), recorded
2026-07-16 with their signer certificates — provenance in
``tests/fixtures/trustlist/real/README.md``. Offline, deterministic (``now`` is
pinned to the retrieval date). Self-contained (tests/ is not a package).
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("signxml")

from cryptography import x509                                  # noqa: E402  (after importorskip)

from openvc.trustlist import (                                 # noqa: E402
    TrustListSignatureError,
    consume_trust_list,
    verify_xades_enveloped,
)

REAL = Path(__file__).parent / "fixtures" / "trustlist" / "real"


def _fixture(name):
    return (REAL / name).read_bytes()


def _signer(name):
    return x509.load_pem_x509_certificate((REAL / name).read_bytes())


# --------------------------------------------------------------------------- #
# Positive: the recorded Commission / national signatures verify end to end
# --------------------------------------------------------------------------- #

def test_real_eu_lotl_signature_verifies():
    lotl = _fixture("eu-lotl-seq388.xml")
    assert verify_xades_enveloped(lotl, [_signer("eu-lotl-signer.pem")]) is None


def test_real_es_tl_signature_verifies():
    tl = _fixture("es-tl-seq187.xml")
    assert verify_xades_enveloped(tl, [_signer("es-tl-signer.pem")]) is None


def test_real_eu_lotl_consumes_end_to_end():
    # signature -> parse, in one call, exactly as a caller would use it (expiry is
    # walk_lotl's concern, so no clock pinning is needed here)
    tl = consume_trust_list(
        _fixture("eu-lotl-seq388.xml"),
        verify_signature=verify_xades_enveloped,
        expected_signer_certs=[_signer("eu-lotl-signer.pem")])
    assert tl.territory == "EU"
    assert len(tl.pointers) >= 25          # one per Member State (31 at recording time)


def test_real_es_tl_consumes_end_to_end():
    tl = consume_trust_list(
        _fixture("es-tl-seq187.xml"),
        verify_signature=verify_xades_enveloped,
        expected_signer_certs=[_signer("es-tl-signer.pem")])
    assert tl.territory == "ES"
    assert len(tl.providers) > 0


# --------------------------------------------------------------------------- #
# Negatives: tampered bytes and unvouched signers stay fail-closed
# --------------------------------------------------------------------------- #

def test_real_eu_lotl_tampered_rejected():
    lotl = _fixture("eu-lotl-seq388.xml")
    tampered = lotl.replace(b"<TSLSequenceNumber>388<", b"<TSLSequenceNumber>389<", 1)
    assert tampered != lotl
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(tampered, [_signer("eu-lotl-signer.pem")])


def test_real_es_tl_tampered_rejected():
    tl = _fixture("es-tl-seq187.xml")
    tampered = tl.replace(b"<TSLSequenceNumber>187<", b"<TSLSequenceNumber>188<", 1)
    assert tampered != tl
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(tampered, [_signer("es-tl-signer.pem")])


def test_real_eu_lotl_wrong_signer_rejected():
    # the Spanish operator did not sign the LOTL: authentic-but-unvouched fails
    with pytest.raises(TrustListSignatureError):
        verify_xades_enveloped(
            _fixture("eu-lotl-seq388.xml"), [_signer("es-tl-signer.pem")])
