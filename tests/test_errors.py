"""
tests/test_errors.py — the library-wide OpenvcError root and the EBSI EbsiError
root. Every error family descends from OpenvcError, so one `except OpenvcError`
catches any openvc failure (the per-area roots still work individually).
"""
from __future__ import annotations

import pytest

from openvc import OpenvcError


def test_every_core_error_family_descends_from_openvc_error():
    from openvc.did.base import DidError, DidResolutionError
    from openvc.jwt_vc_issuer import JwtVcIssuerError
    from openvc.keys import InvalidKey, KeyBackendError
    from openvc.multibase import MultibaseError
    from openvc.proof._verify_common import CredentialExpired, ProofPurposeMismatch
    from openvc.proof.contexts import DocumentLoaderError
    from openvc.proof.vc_jwt import ClaimsInvalid, ProofError, SignatureInvalid
    from openvc.status import CredentialRevoked, CredentialSuspended, StatusListError
    from openvc.verify import KeyResolutionFailed, TypeMismatch, VerificationError
    from openvc.x5c import X5cError

    for exc in (DidError, DidResolutionError, KeyBackendError, InvalidKey,
                MultibaseError, DocumentLoaderError, ProofError, SignatureInvalid,
                ClaimsInvalid, CredentialExpired, ProofPurposeMismatch,
                CredentialRevoked, CredentialSuspended, StatusListError,
                VerificationError, KeyResolutionFailed, TypeMismatch, X5cError,
                JwtVcIssuerError):
        assert issubclass(exc, OpenvcError), exc.__name__


def test_openvc_error_catches_a_raised_family_error():
    from openvc.proof.vc_jwt import SignatureInvalid
    from openvc.x5c import X5cError

    with pytest.raises(OpenvcError):
        raise SignatureInvalid("bad sig")
    with pytest.raises(OpenvcError):
        raise X5cError("bad chain")


def test_ebsi_errors_descend_from_ebsi_error_and_openvc_error():
    pytest.importorskip("httpx")
    from openvc_ebsi.errors import EbsiError
    from openvc_ebsi.http import HttpError, HttpNotFound
    from openvc_ebsi.trust import AccreditationRevoked, TrustChainError
    from openvc_ebsi.verify import EbsiVerificationError, IssuerNotTrusted

    for exc in (HttpError, HttpNotFound, TrustChainError, AccreditationRevoked,
                EbsiVerificationError, IssuerNotTrusted):
        assert issubclass(exc, EbsiError), exc.__name__
        assert issubclass(exc, OpenvcError), exc.__name__
