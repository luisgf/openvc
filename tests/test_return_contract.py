"""
tests/test_return_contract.py — the frozen return-object contract (issue #7).

`verify_credential` returns a `VerificationResult`, takes a `VerificationPolicy`, and
each proof suite returns a `Verified*` dataclass. Downstream code (openbadgeslib, EUDI
verifiers) destructures these, so their SHAPE is public API: changing a field is a
breaking change that must be a deliberate, CHANGELOG-noted decision. This test pins
the exact fields so an accidental change fails loudly, and enforces the add-only rule
(new fields must default, so old constructions keep working).
"""
from __future__ import annotations

import dataclasses as dc

import pytest

from openvc.proof.data_integrity import VerifiedDataIntegrity
from openvc.proof.ecdsa_sd import VerifiedSdCredential
from openvc.proof.sd_jwt import VerifiedSdJwt
from openvc.proof.vc_jwt import VerifiedCredential
from openvc.proof.vp_jwt import VerifiedPresentation
from openvc.verify import VerificationPolicy, VerificationResult

# The pinned public shape. To change a line here you must also add a CHANGELOG note —
# that is the point: the field list is frozen API toward 1.0.
CONTRACT = {
    VerificationResult: ["format", "credential", "issuer", "subject", "claims",
                         "key_bound", "status", "schema", "raw"],
    VerificationPolicy: ["leeway_s", "expected_types", "expected_vct", "audience",
                         "nonce", "require_key_binding", "proof_purpose",
                         "require_status", "require_schema", "now"],
    VerifiedCredential: ["credential", "issuer", "subject", "claims"],
    VerifiedDataIntegrity: ["credential", "issuer", "subject", "proof"],
    VerifiedSdCredential: ["credential", "issuer", "subject", "proof"],
    VerifiedSdJwt: ["claims", "issuer", "vct", "key_bound", "confirmation"],
    VerifiedPresentation: ["holder", "credentials", "claims", "vp"],
}


@pytest.mark.parametrize("cls,expected", list(CONTRACT.items()),
                         ids=[c.__name__ for c in CONTRACT])
def test_return_object_shape_is_frozen(cls, expected):
    actual = [f.name for f in dc.fields(cls)]
    assert actual == expected, (
        f"{cls.__name__} return-object shape changed to {actual} — update the pinned "
        "contract AND add a CHANGELOG note (breaking for consumers who destructure it)")
    assert cls.__dataclass_params__.frozen, f"{cls.__name__} must stay frozen (immutable)"


def test_verification_policy_is_add_only():
    # Every VerificationPolicy field must default, so a caller's existing construction
    # keeps working when a new policy knob is added (add-only invariant).
    missing = [f.name for f in dc.fields(VerificationPolicy)
               if f.default is dc.MISSING and f.default_factory is dc.MISSING]
    assert not missing, f"VerificationPolicy fields without a default break add-only: {missing}"


def test_verification_result_optional_outputs_default():
    # The non-core outputs must default so the constructor stays back-compatible as
    # new outputs (like `schema` was) are added.
    optional = {"claims", "key_bound", "status", "schema", "raw"}
    for f in dc.fields(VerificationResult):
        if f.name in optional:
            assert f.default is not dc.MISSING or f.default_factory is not dc.MISSING, \
                f"VerificationResult.{f.name} must have a default"
