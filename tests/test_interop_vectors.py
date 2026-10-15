"""
tests/test_interop_vectors.py — conformance pinned against **third-party** artifacts
(issue #115).

The most EUDI-relevant formats were previously pinned only by self-recorded vectors —
openvc verifying what openvc produced. These hold it to artifacts made by *others*:

* SD-JWT VC issued by the IETF standard's own example (RFC 9901 Appendix A.3, verified
  against the published A.5 issuer key) and by the EUDI reference implementation (a real
  PID with the issuer cert in ``x5c``);
* W3C Bitstring Status List ``encodedList`` decode vectors — the v1.0 REC's own example
  and a Digital Bazaar one — both multibase-encoded exactly as the REC mandates;
* an OpenID4VP 1.0 ``vp_token`` that a third-party wallet (eudi-dev) presented to a
  third-party verifier (polaris-oid4vp), captured with provenance — the presentation
  layer (DCQL response, KB-JWT, encrypted ``direct_post.jwt``) made by someone else
  (issue #121).

Fixtures + provenance live in ``tests/fixtures/interop/``. Offline and deterministic:
the SD-JWT VCs carry an ``exp``, so the clock is frozen to the 2026-07-16 retrieval date
(the fixed signed bytes cannot be re-minted with a later expiry); the OpenID4VP capture
pins ``now`` through the API to the instant its verifier recorded. Self-contained
(tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
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


# --------------------------------------------------------------------------- #
# OpenID4VP 1.0 vp_token — a third-party wallet's presentation (issue #121)
# --------------------------------------------------------------------------- #

CAPTURE = FIX / "openid4vp" / "eudi-dev-capture"

# PROVENANCE.md's capture instant: the second polaris-oid4vp reached its verdict — the
# verifier's own receipt time, never a value read from the token. The KB-JWT is only
# fresh then, and the issuer leaf expires 2026-11-09; pinning `now` (not the wall clock)
# keeps the fixed bytes verifiable for good.
CAPTURE_AT = datetime.datetime.fromtimestamp(1791661760, datetime.timezone.utc)

# Byte-for-byte. The seven data files' digests are PROVENANCE.md's own table;
# PROVENANCE.md — the author's attribution and Apache-2.0 statement — is pinned too,
# so it is never edited by accident.
CAPTURE_SHA256 = {
    "presentation.txt": "4a968717cab4bb2a1a68db4b50cea437842c0ed3b5595e39bf6c2b268187fb9b",
    "vp-token.json": "682e0fddf1213e3fe01e69bd71164b50afe54d1743773b7060270257d52b9e14",
    "request.jwt": "ab312d0a48d61e69dc77b986b8bf5fbf7fdff10a156f87ac2a87ad5235baba06",
    "request.json": "94806366b3a6ff619b4207f6c90b2a6e8621383fd0ee8a765e763f1370f718da",
    "issuer-ca.pem": "34edc1bcf6880020e13c1140e4f13657627e5888843d91f2a4ab71ee99778a45",
    "response.jwe": "675469a50f8ac2c7076e52e08d19ec5034360001a395ec0a5b5ed3ffcd3b8654",
    "verifier-decryption-key.test-only.jwk.json":
        "e2516a6e174a68d13b5d5d9d6c17544401c56aafeda2fad8ef311d04b81f6838",
    "PROVENANCE.md": "d44e6ace36742e1edc7b3c1c35b062371e88ae72d9afa128b4508b2ae80b5e5f",
}


def _capture_json(name: str):
    return json.loads((CAPTURE / name).read_text())


def _capture_kwargs(**overrides):
    from cryptography import x509

    req = _capture_json("request.json")
    kwargs = dict(
        dcql_query=req["dcql_query"], nonce=req["nonce"], client_id=req["client_id"],
        x5c_trust_anchors=[
            x509.load_pem_x509_certificate((CAPTURE / "issuer-ca.pem").read_bytes())],
        now=CAPTURE_AT)
    kwargs.update(overrides)
    return kwargs


def _verify_capture(vp_token=None, **overrides):
    from openvc import verify_vp_token

    token = _capture_json("vp-token.json") if vp_token is None else vp_token
    return verify_vp_token(token, **_capture_kwargs(**overrides))


def _flip_first_signature_char(jws: str) -> str:
    # The FIRST character: every one of its bits is significant (the last one can land
    # on base64url padding bits and leave the signature unchanged).
    header, payload, sig = jws.split(".")
    return ".".join([header, payload, ("A" if sig[0] != "A" else "B") + sig[1:]])


def test_eudi_dev_capture_is_byte_exact():
    for name, digest in CAPTURE_SHA256.items():
        assert hashlib.sha256((CAPTURE / name).read_bytes()).hexdigest() == digest, name


def test_eudi_dev_capture_is_internally_consistent():
    # vp-token.json carries presentation.txt verbatim under the DCQL query id, and the
    # assembled request.json repeats the signed request object's own members.
    presentation = (CAPTURE / "presentation.txt").read_text()
    assert _capture_json("vp-token.json") == {"pid": [presentation]}
    payload_b64 = (CAPTURE / "request.jwt").read_text().strip().split(".")[1]
    signed = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    for member, value in _capture_json("request.json").items():
        assert signed[member] == value, member


def test_eudi_dev_vp_token_verifies():
    (p,) = _verify_capture().for_query("pid")
    assert p.raw.issuer == "https://issuer.polaris.test"   # bound via the anchored x5c leaf
    assert p.raw.vct == "urn:eudi:pid:1"
    assert p.raw.key_bound is True
    assert (p.raw.claims["given_name"], p.raw.claims["family_name"]) == ("Jean", "Dupont")


def test_eudi_dev_encrypted_response_verifies():
    # The direct_post.jwt body exactly as the wallet posted it (ECDH-ES + A128GCM).
    from openvc import verify_encrypted_vp_response
    from openvc.keys import P256KeyAgreementKey

    jwk = _capture_json("verifier-decryption-key.test-only.jwk.json")
    result = verify_encrypted_vp_response(
        (CAPTURE / "response.jwe").read_text().strip(),
        key=P256KeyAgreementKey.from_jwk(jwk, kid=jwk.get("kid", "verifier-enc")),
        **_capture_kwargs())
    (p,) = result.for_query("pid")
    assert (p.raw.claims["given_name"], p.raw.claims["family_name"]) == ("Jean", "Dupont")


def test_eudi_dev_capture_an_hour_later_is_stale():
    """The author's stale-clock control, kept as asked: the same presentation an hour
    after the capture. polaris-oid4vp refuses it; openvc accepted it until #186 (v1.28.0)."""
    from openvc.proof.errors import ClaimsInvalid

    with pytest.raises(ClaimsInvalid, match="KB-JWT is too old"):
        _verify_capture(now=CAPTURE_AT + datetime.timedelta(hours=1))


def test_eudi_dev_capture_after_the_issuer_leaf_expires_is_rejected():
    # The pin covers the x5c validity window as well — nothing here reads the wall clock.
    # The wide kb_max_age_s keeps the KB-JWT "fresh", so only the certificate window can
    # refuse. (A leeway is capped at a day, so it cannot do this job: #228.)
    from openvc.verify import KeyResolutionFailed

    with pytest.raises(KeyResolutionFailed):
        _verify_capture(now=datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
                        kb_max_age_s=10 ** 8)


def test_eudi_dev_capture_unrelated_anchor_rejected():
    from cryptography import x509

    from openvc.verify import KeyResolutionFailed

    unrelated = x509.load_pem_x509_certificate((SD / "eudi-pid-issuer.pem").read_bytes())
    with pytest.raises(KeyResolutionFailed):
        _verify_capture(x5c_trust_anchors=[unrelated])


def test_eudi_dev_capture_tampered_signatures_rejected():
    presentation = (CAPTURE / "presentation.txt").read_text()
    parts = presentation.split("~")
    kb_flipped = "~".join(parts[:-1] + [_flip_first_signature_char(parts[-1])])
    issuer_flipped = "~".join([_flip_first_signature_char(parts[0])] + parts[1:])
    for tampered, what in ((kb_flipped, "KB-JWT"), (issuer_flipped, "issuer JWT")):
        with pytest.raises(SignatureInvalid, match=what):
            _verify_capture({"pid": [tampered]})


def test_eudi_dev_capture_binding_mismatches_rejected():
    from openvc.proof.errors import ClaimsInvalid

    req = _capture_json("request.json")
    with pytest.raises(ClaimsInvalid, match="nonce"):
        _verify_capture(nonce="not-the-request-nonce")
    with pytest.raises(ClaimsInvalid, match="aud"):      # the bare hash, prefix dropped
        _verify_capture(client_id=req["client_id"].split(":", 1)[1])
