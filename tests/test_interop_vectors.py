"""
tests/test_interop_vectors.py — conformance pinned against **third-party** artifacts
(issue #115).

The most EUDI-relevant formats were previously pinned only by self-recorded vectors —
openvc verifying what openvc produced. These hold it to artifacts made by *others*:

* SD-JWT VC issued by the IETF standard's own example (RFC 9901 Appendix A.3, verified
  against the published A.5 issuer key) and by the EUDI reference implementation (a real
  PID with the issuer cert in ``x5c``);
* W3C Bitstring Status List ``encodedList`` decode vectors — the v1.0 REC's own example
  and a Digital Bazaar one — both multibase-encoded exactly as the REC mandates.

Fixtures + provenance live in ``tests/fixtures/interop/``. Offline and deterministic:
the SD-JWT VCs carry an ``exp``, so the clock is frozen to the 2026-07-16 retrieval date
(the fixed signed bytes cannot be re-minted with a later expiry). Self-contained
(tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path

import pytest

from openvc.proof import _verify_common
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import SignatureInvalid
from openvc.status import decode_bitstring, get_status_bit

FIX = Path(__file__).parent / "fixtures" / "interop"
SD = FIX / "sd_jwt_vc"
STATUS = FIX / "status"

# Inside both vectors' validity windows (EUDI PID: iat 2026-07-02 → exp 2026-08-01;
# RFC 9901: exp 2029). Freezing keeps the fixed signed bytes verifiable forever.
FROZEN_EPOCH = datetime.datetime(2026, 7, 16, tzinfo=datetime.timezone.utc).timestamp()


@pytest.fixture
def frozen_clock(monkeypatch):
    monkeypatch.setattr(_verify_common.time, "time", lambda: FROZEN_EPOCH)


def _b64u(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def _leaf_public_jwk(pem_path: Path) -> dict:
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
    nums = cert.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _b64u(nums.x), "y": _b64u(nums.y)}


# --------------------------------------------------------------------------- #
# SD-JWT VC — third-party issuers
# --------------------------------------------------------------------------- #

def test_rfc9901_appendix_a3_sd_jwt_vc_verifies(frozen_clock):
    # The IETF SD-JWT standard's own SD-JWT VC example, verified against its published key.
    wire = (SD / "rfc9901-a3-sd-jwt-vc.txt").read_text().strip()
    issuer_jwk = json.loads((SD / "rfc9901-a5-issuer-key.json").read_text())
    res = SdJwtVcProofSuite().verify(
        wire, public_key_jwk=issuer_jwk, expected_vct="urn:eudi:pid:de:1")
    assert res.issuer == "https://pid-issuer.bund.de.example"
    assert res.vct == "urn:eudi:pid:de:1"
    assert res.claims["given_name"] == "Erika"          # a selectively-disclosed claim


def test_rfc9901_vector_wrong_key_rejected(frozen_clock):
    # Same vector, a different (valid) P-256 key -> issuer signature must fail.
    from cryptography.hazmat.primitives.asymmetric import ec
    wire = (SD / "rfc9901-a3-sd-jwt-vc.txt").read_text().strip()
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    bogus = {"kty": "EC", "crv": "P-256", "x": _b64u(other.x), "y": _b64u(other.y)}
    with pytest.raises(SignatureInvalid):
        SdJwtVcProofSuite().verify(wire, public_key_jwk=bogus)


def test_eudi_reference_pid_sd_jwt_vc_verifies(frozen_clock):
    # A real EUDI reference-implementation PID: verify the issuer signature against the
    # key in its own x5c leaf, and confirm the holder key in cnf matches the vendored one.
    wire = (SD / "eudi-pid-sd-jwt-vc.txt").read_text().strip()
    issuer_jwk = _leaf_public_jwk(SD / "eudi-pid-issuer.pem")
    res = SdJwtVcProofSuite().verify(
        wire, public_key_jwk=issuer_jwk, expected_vct="urn:eudi:pid:1")
    assert res.issuer == "https://dev.issuer-backend.eudiw.dev"
    assert res.vct == "urn:eudi:pid:1"
    holder = json.loads((SD / "eudi-pid-holder-key.json").read_text())
    assert res.confirmation["jwk"]["x"] == holder["x"]  # cnf holder key == vendored key


def test_eudi_pid_tampered_disclosure_rejected(frozen_clock):
    # Flip a byte in the issuer-signed JWT -> signature fails closed.
    wire = (SD / "eudi-pid-sd-jwt-vc.txt").read_text().strip()
    issuer_jwk = _leaf_public_jwk(SD / "eudi-pid-issuer.pem")
    head, rest = wire.split(".", 1)
    tampered = head + "." + ("B" if rest[0] != "B" else "C") + rest[1:]
    with pytest.raises(Exception):                      # SignatureInvalid / MalformedToken
        SdJwtVcProofSuite().verify(tampered, public_key_jwk=issuer_jwk)


# --------------------------------------------------------------------------- #
# W3C Bitstring Status List — multibase encodedList decode vectors
# --------------------------------------------------------------------------- #

def test_w3c_rec_example3_encoded_list_decodes():
    # VC Bitstring Status List v1.0 REC, Example 3: 131072 bits (16 KiB), all clear.
    encoded = (STATUS / "w3c-rec-example3-encodedList.txt").read_text().strip()
    assert encoded.startswith("u")                      # multibase, as the REC mandates
    bits = decode_bitstring(encoded)
    assert len(bits) == 16 * 1024
    assert len(bits) * 8 == 131072
    assert all(b == 0 for b in bits)
    assert get_status_bit(bits, 0) == 0
    assert get_status_bit(bits, 131071) == 0


def test_digitalbazaar_100k_encoded_list_decodes():
    # Digital Bazaar's encodedList100KWith50KthRevoked: 100000 bits, exactly one set.
    # Under the REC's MSB-first order the set bit is index 50007 (the name assumes LSB).
    encoded = (STATUS / "digitalbazaar-100k-50k-revoked-encodedList.txt").read_text().strip()
    assert encoded.startswith("u")
    bits = decode_bitstring(encoded)
    assert len(bits) * 8 == 100000
    set_indices = [i for i in range(len(bits) * 8) if get_status_bit(bits, i)]
    assert set_indices == [50007]


def test_decode_bitstring_tolerates_multibase_and_bare():
    # The consume fix: the same list decodes identically whether or not it carries the
    # multibase 'u' prefix (real W3C lists carry it; openvc's own legacy output did not).
    encoded = (STATUS / "w3c-rec-example3-encodedList.txt").read_text().strip()
    assert decode_bitstring(encoded) == decode_bitstring(encoded[1:])
