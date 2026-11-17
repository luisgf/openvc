"""
tests/test_fetch_resolver_errors.py — every resolver failure is a typed error (#425).

``_resolve_public_ips`` used to catch only ``socket.gaierror``. CPython reports some
resolver failures (``EAI_SYSTEM``: ``EMFILE``, ``ENOMEM``, ...) as a plain ``OSError``,
which left ``openvc.fetch`` — and so ``verify_credential`` / ``verify_many`` — as a bare
exception. Only ``socket.getaddrinfo`` is patched; nothing reaches the network.
"""
from __future__ import annotations

import socket
from typing import Any

import pytest

from openvc import VerificationPolicy, verify_credential, verify_many
from openvc.errors import KeyResolutionFailed
from openvc.fetch import UnsafeUrlError, https_json_fetch, https_text_fetch
from openvc.keys import P256SigningKey
from openvc.proof.vc_jwt import VcJwtProofSuite

DID = "did:web:issuer.example"
URL = "https://issuer.example/.well-known/did.json"

RESOLVER_FAILURES = [
    pytest.param(OSError(24, "Too many open files"), id="oserror-emfile"),
    pytest.param(OSError(0, "Error"), id="oserror-zero"),
    pytest.param(socket.gaierror(-2, "Name or service not known"), id="gaierror-control"),
]


def _raise(exc: BaseException) -> Any:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise exc
    return boom


def _token() -> str:
    cred = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "credentialSubject": {"id": "did:example:alice"},
    }
    key = P256SigningKey.generate(kid=f"{DID}#key-1")
    return VcJwtProofSuite().sign(cred, signing_key=key)


@pytest.mark.parametrize("exc", RESOLVER_FAILURES)
@pytest.mark.parametrize("fetch", [https_json_fetch, https_text_fetch])
def test_fetch_types_resolver_failure(monkeypatch, exc, fetch):
    monkeypatch.setattr(socket, "getaddrinfo", _raise(exc))
    with pytest.raises(UnsafeUrlError, match="cannot resolve host"):
        fetch(URL)


@pytest.mark.parametrize("exc", RESOLVER_FAILURES)
def test_verify_credential_did_web_is_key_resolution_failed(monkeypatch, exc):
    monkeypatch.setattr(socket, "getaddrinfo", _raise(exc))
    with pytest.raises(KeyResolutionFailed):
        verify_credential(_token(), policy=VerificationPolicy())


@pytest.mark.parametrize("exc", RESOLVER_FAILURES)
def test_verify_many_fails_one_item_not_the_batch(monkeypatch, exc):
    monkeypatch.setattr(socket, "getaddrinfo", _raise(exc))
    results = verify_many([_token(), _token()], policy=VerificationPolicy())
    assert [r.ok for r in results] == [False, False]
    assert all(type(r.error) is KeyResolutionFailed for r in results)


def test_memory_error_still_propagates_unchanged(monkeypatch):
    """Non-OSError BaseExceptions are deliberately not typed (documented)."""
    monkeypatch.setattr(socket, "getaddrinfo", _raise(MemoryError()))
    with pytest.raises(MemoryError):
        https_json_fetch(URL)
