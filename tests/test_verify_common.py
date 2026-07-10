"""
tests/test_verify_common.py — the cross-suite Data Integrity policy checks
(`openvc.proof._verify_common`): validity-window (temporal) enforcement,
proofPurpose enforcement, and the DID verification-relationship key binding.

Pure unit tests — no pyld, no signing. They pin the policy logic both suites
(eddsa-rdfc-2022, ecdsa-sd-2023) share, so the suite-level tests only need to
prove the wiring, not re-derive the matrix.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from openvc.did.base import DidResolutionError, parse_did_document
from openvc.proof._verify_common import (
    CredentialExpired,
    CredentialNotYetValid,
    KeyResolutionError,
    MalformedTimestamp,
    ProofPurposeMismatch,
    _parse_ts,
    check_proof_purpose,
    check_validity_window,
    resolve_verification_key,
)

UTC = timezone.utc
_NOW = datetime(2025, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Timestamp parsing
# --------------------------------------------------------------------------- #

def test_parse_ts_normalises_z_offset_and_naive():
    assert _parse_ts("2024-01-01T00:00:00Z") == datetime(2024, 1, 1, tzinfo=UTC)
    assert _parse_ts("2024-01-01T00:00:00+00:00") == datetime(2024, 1, 1, tzinfo=UTC)
    # a naive timestamp is assumed UTC (not silently local)
    assert _parse_ts("2024-01-01T00:00:00") == datetime(2024, 1, 1, tzinfo=UTC)
    # an offset time zone is preserved as the same instant
    assert _parse_ts("2024-01-01T02:00:00+02:00") == datetime(2024, 1, 1, tzinfo=UTC)


def test_parse_ts_handles_arbitrary_fractional_seconds():
    # XSD allows any fractional precision; Python's pre-3.11 fromisoformat only
    # accepted exactly 3 or 6 digits. These must all parse (not fail open).
    assert _parse_ts("2024-01-01T00:00:00.5Z") == datetime(2024, 1, 1, 0, 0, 0, 500000, UTC)
    assert _parse_ts("2024-01-01T00:00:00.123Z") == datetime(2024, 1, 1, 0, 0, 0, 123000, UTC)
    assert _parse_ts("2024-01-01T00:00:00.123456789Z") == \
        datetime(2024, 1, 1, 0, 0, 0, 123456, UTC)
    assert _parse_ts("2024-01-01T00:00:00.5+02:00") == \
        datetime(2023, 12, 31, 22, 0, 0, 500000, UTC)


def test_parse_ts_returns_none_for_absent_or_garbage():
    assert _parse_ts(None) is None
    assert _parse_ts("") is None
    assert _parse_ts("not-a-date") is None
    assert _parse_ts(12345) is None


# --------------------------------------------------------------------------- #
# Validity window
# --------------------------------------------------------------------------- #

def test_within_window_passes():
    doc = {"validFrom": "2020-01-01T00:00:00Z", "validUntil": "2030-01-01T00:00:00Z"}
    check_validity_window(doc, {}, now=_NOW, leeway_s=0)          # no raise


def test_no_bounds_is_not_a_violation():
    check_validity_window({}, {}, now=_NOW, leeway_s=0)           # no raise


def test_expired_credential_rejected():
    doc = {"validUntil": "2020-01-01T00:00:00Z"}
    with pytest.raises(CredentialExpired):
        check_validity_window(doc, {}, now=_NOW, leeway_s=0)


def test_not_yet_valid_credential_rejected():
    doc = {"validFrom": "2030-01-01T00:00:00Z"}
    with pytest.raises(CredentialNotYetValid):
        check_validity_window(doc, {}, now=_NOW, leeway_s=0)


def test_proof_expires_rejected():
    with pytest.raises(CredentialExpired):
        check_validity_window({}, {"expires": "2020-01-01T00:00:00Z"},
                              now=_NOW, leeway_s=0)


def test_leeway_tolerates_recent_expiry_and_early_validity():
    just_expired = {"validUntil": "2025-01-01T00:00:00Z"}
    at = datetime(2025, 1, 1, 0, 0, 30, tzinfo=UTC)              # 30 s past expiry
    check_validity_window(just_expired, {}, now=at, leeway_s=60)  # within leeway -> OK
    with pytest.raises(CredentialExpired):
        check_validity_window(just_expired, {}, now=at, leeway_s=0)

    not_quite_valid = {"validFrom": "2025-01-01T00:00:30Z"}
    before = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)          # 30 s early
    check_validity_window(not_quite_valid, {}, now=before, leeway_s=60)
    with pytest.raises(CredentialNotYetValid):
        check_validity_window(not_quite_valid, {}, now=before, leeway_s=0)


def test_vcdm11_issuance_and_expiration_dates_honoured():
    doc = {"issuanceDate": "2020-01-01T00:00:00Z", "expirationDate": "2021-01-01T00:00:00Z"}
    with pytest.raises(CredentialExpired):
        check_validity_window(doc, {}, now=_NOW, leeway_s=0)
    # verifies "as of" inside the window
    check_validity_window(doc, {}, now=datetime(2020, 6, 1, tzinfo=UTC), leeway_s=0)


def test_vcdm2_bounds_take_precedence_over_vcdm11():
    # A v2 credential's validUntil wins; the (contradictory) v1.1 field is ignored.
    doc = {"validUntil": "2030-01-01T00:00:00Z", "expirationDate": "2000-01-01T00:00:00Z"}
    check_validity_window(doc, {}, now=_NOW, leeway_s=0)          # no raise


def test_present_but_unparseable_bound_fails_closed():
    # A signed-but-unreadable timestamp must NOT be silently skipped (that would
    # let an expired credential verify); it fails closed instead.
    with pytest.raises(MalformedTimestamp):
        check_validity_window({"validUntil": "sometime-next-year"}, {},
                              now=_NOW, leeway_s=0)
    with pytest.raises(MalformedTimestamp):
        check_validity_window({"validFrom": "garbage"}, {}, now=_NOW, leeway_s=0)
    with pytest.raises(MalformedTimestamp):
        check_validity_window({}, {"expires": "nope"}, now=_NOW, leeway_s=0)


def test_malformed_primary_bound_does_not_fall_through_to_secondary():
    # validUntil takes precedence; if it is present but garbage we must fail, not
    # silently fall back to a (valid) expirationDate — the primary field is broken.
    doc = {"validUntil": "broken", "expirationDate": "2030-01-01T00:00:00Z"}
    with pytest.raises(MalformedTimestamp):
        check_validity_window(doc, {}, now=_NOW, leeway_s=0)


# --------------------------------------------------------------------------- #
# proofPurpose
# --------------------------------------------------------------------------- #

def test_proof_purpose_match_mismatch_and_missing():
    check_proof_purpose({"proofPurpose": "assertionMethod"}, "assertionMethod")   # OK
    with pytest.raises(ProofPurposeMismatch):
        check_proof_purpose({"proofPurpose": "authentication"}, "assertionMethod")
    with pytest.raises(ProofPurposeMismatch):
        check_proof_purpose({}, "assertionMethod")               # a DI proof must declare one
    check_proof_purpose({"proofPurpose": "anything"}, None)      # None disables the check


# --------------------------------------------------------------------------- #
# Key resolution + verification-relationship binding
# --------------------------------------------------------------------------- #

_DID = "did:web:issuer.example"
_VM = f"{_DID}#key-1"
_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}


class _StubResolver:
    def __init__(self, doc, did=_DID):
        self._doc = doc
        self._did = did

    def supports(self, did: str) -> bool:
        return did == self._did

    def resolve(self, did: str):
        if did != self._did:
            raise DidResolutionError(f"unknown DID {did!r}")
        return self._doc


def _doc(relationships: dict) -> object:
    raw = {
        "id": _DID,
        "verificationMethod": [
            {"id": _VM, "type": "JsonWebKey2020", "controller": _DID, "publicKeyJwk": _JWK}
        ],
        **relationships,
    }
    return parse_did_document(raw)


def test_resolver_binds_key_to_authorized_purpose():
    resolver = _StubResolver(_doc({"assertionMethod": [_VM]}))
    jwk = resolve_verification_key(_VM, proof_purpose="assertionMethod", resolver=resolver)
    assert jwk == _JWK


def test_resolver_rejects_key_not_authorized_for_purpose():
    # key is an authentication key only; a proof claiming assertionMethod must fail
    resolver = _StubResolver(_doc({"authentication": [_VM], "assertionMethod": []}))
    with pytest.raises(ProofPurposeMismatch):
        resolve_verification_key(_VM, proof_purpose="assertionMethod", resolver=resolver)


def test_resolver_lenient_when_relationship_not_declared():
    # a minimal did:web doc that only lists verificationMethod -> binding can't be
    # enforced, so the key is accepted (proofPurpose is still checked elsewhere).
    resolver = _StubResolver(_doc({}))
    jwk = resolve_verification_key(_VM, proof_purpose="assertionMethod", resolver=resolver)
    assert jwk == _JWK


def test_resolver_reports_vm_absent_from_document():
    resolver = _StubResolver(_doc({"assertionMethod": [_VM]}))
    with pytest.raises(KeyResolutionError, match="not in the DID document"):
        resolve_verification_key(f"{_DID}#missing", proof_purpose="assertionMethod",
                                 resolver=resolver)


def test_resolution_failure_is_wrapped():
    class _Boom:
        def supports(self, did): return True
        def resolve(self, did): raise DidResolutionError("registry down")

    with pytest.raises(KeyResolutionError, match="could not resolve"):
        resolve_verification_key(_VM, proof_purpose="assertionMethod", resolver=_Boom())


def test_non_didkey_without_resolver_is_unresolvable():
    with pytest.raises(KeyResolutionError, match="offline"):
        resolve_verification_key(_VM, proof_purpose="assertionMethod")


def test_missing_verification_method_rejected():
    with pytest.raises(KeyResolutionError):
        resolve_verification_key(None, proof_purpose="assertionMethod")


def test_prepare_di_proof_validates_and_decodes():
    # #110: the shared whole-document DI preamble (single-sources the fail-closed guards).
    from openvc.multibase import encode_multibase
    from openvc.proof._verify_common import prepare_di_proof
    from openvc.proof.errors import ProofMalformed, UnsupportedCryptosuite

    good = {"@context": ["c"],
            "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                      "proofValue": encode_multibase(b"\x01\x02"), "verificationMethod": "did:x#k"}}
    proof, proof_config, sig = prepare_di_proof(
        good, proof_type="DataIntegrityProof", cryptosuite="eddsa-rdfc-2022")
    assert sig == b"\x01\x02"
    assert "proofValue" not in proof_config and proof_config["@context"] == ["c"]

    def _bad(proof_obj):
        return {"proof": proof_obj}

    with pytest.raises(ProofMalformed):                          # no proof object
        prepare_di_proof({}, proof_type="DataIntegrityProof", cryptosuite="eddsa-rdfc-2022")
    with pytest.raises(ProofMalformed):                          # wrong type
        prepare_di_proof(_bad({"type": "X", "cryptosuite": "eddsa-rdfc-2022", "proofValue": "z"}),
                         proof_type="DataIntegrityProof", cryptosuite="eddsa-rdfc-2022")
    with pytest.raises(UnsupportedCryptosuite):                  # wrong cryptosuite
        prepare_di_proof(
            _bad({"type": "DataIntegrityProof", "cryptosuite": "other", "proofValue": "z"}),
            proof_type="DataIntegrityProof", cryptosuite="eddsa-rdfc-2022")
    with pytest.raises(ProofMalformed):                          # non-string proofValue
        prepare_di_proof(
            _bad({"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                  "proofValue": 123}),
            proof_type="DataIntegrityProof", cryptosuite="eddsa-rdfc-2022")


def test_bundled_contexts_cached_and_isolated():
    # #110: parsed once and shared read-only, but a fresh top-level dict per call so a
    # caller's .update() cannot pollute the cache.
    from openvc.proof.contexts import bundled_contexts
    url = "https://www.w3.org/ns/credentials/v2"
    a, b = bundled_contexts(), bundled_contexts()
    assert a is not b and a[url] is b[url]
    a["injected"] = {}
    assert "injected" not in bundled_contexts()
