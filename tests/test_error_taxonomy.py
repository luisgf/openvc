"""
tests/test_error_taxonomy.py — the 1.0 proof error taxonomy contract (issues #4/#5).

The shared leaves are defined ONCE in openvc.proof.errors and re-exported from each
suite, so `except SignatureInvalid` catches whichever suite raised it; the suite
roots (SdJwtError / EcdsaSdError / DataIntegrityError) stay for suite-specific
failures; and the verb-last codec names remain as deprecated aliases.
"""
from __future__ import annotations

from openvc.errors import OpenvcError
from openvc.proof import errors as proof_errors


def test_shared_leaves_are_one_class_across_suites():
    from openvc.proof import data_integrity, ecdsa_sd, sd_jwt, vc_jwt
    for name in ("SignatureInvalid", "ProofMalformed", "UnsupportedCryptosuite",
                 "UnsupportedAlgorithm", "MalformedToken", "ClaimsInvalid"):
        canonical = getattr(proof_errors, name)
        # every place the name is reachable resolves to the ONE canonical class
        for mod in (vc_jwt, data_integrity, ecdsa_sd, sd_jwt):
            if hasattr(mod, name):
                assert getattr(mod, name) is canonical, f"{mod.__name__}.{name} diverged"


def test_proof_error_moved_out_of_vc_jwt_but_reexported():
    from openvc.proof import vc_jwt
    assert proof_errors.ProofError is vc_jwt.ProofError            # re-export kept
    assert issubclass(proof_errors.ProofError, OpenvcError)
    assert proof_errors.SignatureInvalid.__module__ == "openvc.proof.errors"


def test_suite_roots_kept_under_proof_error():
    from openvc.proof.data_integrity import DataIntegrityError
    from openvc.proof.ecdsa_sd import EcdsaSdError, ProofValueMalformed
    from openvc.proof.sd_jwt import SdJwtError
    for root in (DataIntegrityError, EcdsaSdError, SdJwtError):
        assert issubclass(root, proof_errors.ProofError)
    assert issubclass(ProofValueMalformed, EcdsaSdError)
    # the shared leaves no longer subclass a suite root
    assert not issubclass(proof_errors.SignatureInvalid, DataIntegrityError)


def test_except_signature_invalid_catches_every_suite():
    # a single `except SignatureInvalid` is the fix for the old per-suite collision
    from openvc.proof.data_integrity import SignatureInvalid as di
    from openvc.proof.ecdsa_sd import SignatureInvalid as sd
    from openvc.proof.vc_jwt import SignatureInvalid as jose
    assert di is sd is jose is proof_errors.SignatureInvalid


def test_deprecated_codec_aliases_resolve():
    from openvc.proof import ecdsa_sd as m
    assert m.cbor_encode is m.encode_cbor
    assert m.cbor_decode is m.decode_cbor
    assert m.serialize_base_proof is m.encode_base_proof
    assert m.serialize_derived_proof is m.encode_derived_proof
    assert m.parse_base_proof is m.decode_base_proof
    assert m.parse_derived_proof is m.decode_derived_proof
