"""
tests/test_bounded_identifier_echo.py — an attacker-sized identifier is never echoed whole (#431).

Before 1.39.0 the key-resolution errors quoted ``iss``, ``verificationMethod`` and the
fetched URL with a bare ``!r``, before any signature was checked: a credential with a
megabyte-long identifier produced a megabyte-long exception message, and callers log the
message. ``safe_repr`` (200 characters) already bounded most messages; these are the rest.

The credentials are unsigned (a zero signature) on purpose: every refusal here happens
before a signature is looked at. The fetch cases use a local TLS server with a test CA
(self-contained: tests/ is not a package); nothing reaches the network.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import socket
import ssl
import threading
from types import SimpleNamespace
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from openvc import fetch, verify_credential
from openvc.aio import verify_credential_async
from openvc.did.base import (
    AsyncDidResolverRegistry, DidResolutionError, DidResolverRegistry, UnsupportedDidMethod,
)
from openvc.errors import OpenvcError
from openvc.fetch import https_json_fetch, https_json_fetch_async
from openvc.proof.errors import KeyResolutionError
from openvc.verify import (
    IssuerBindingError, KeyResolutionFailed, StatusListIssuerUntrusted, VerificationPolicy,
    _bind_issuer_to_verification_method, _enforce_status_issuer,
)

V2 = "https://www.w3.org/ns/credentials/v2"
BIG = 1_000_000
BOUND = 1000
HOST = "issuer.example"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unsigned_vc_jwt(iss: str) -> str:
    head = _b64u(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": iss + "#0"}).encode())
    body = _b64u(json.dumps({"iss": iss, "vc": {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": iss,
        "credentialSubject": {}}}).encode())
    return f"{head}.{body}.{_b64u(bytes(64))}"


def _unsigned_di(vm: str, issuer: str | None = None) -> dict[str, Any]:
    return {"@context": [V2], "type": ["VerifiableCredential"],
            "issuer": vm.split("#")[0] if issuer is None else issuer,
            "credentialSubject": {},
            "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                      "verificationMethod": vm, "proofPurpose": "assertionMethod",
                      "created": "2026-01-01T00:00:00Z", "proofValue": "z" + "1" * 86}}


def _sync(credential: Any) -> Any:
    return verify_credential(credential)


def _async(credential: Any) -> Any:
    return asyncio.run(verify_credential_async(credential))


# Each case: (id, credential builder taking the hostile string, the exact typed class).
CASES: list[tuple[str, Callable[[str], Any], type[OpenvcError]]] = [
    ("jwt-did-key-control", lambda big: _unsigned_vc_jwt("did:key:z" + "2" * BIG),
     KeyResolutionFailed),
    ("jwt-unknown-method", lambda big: _unsigned_vc_jwt("did:unknown:" + big),
     KeyResolutionFailed),
    ("di-did-key", lambda big: _unsigned_di("did:key:z" + "2" * BIG + "#k"),
     KeyResolutionError),
    ("di-unknown-method", lambda big: _unsigned_di("did:unknown:" + big + "#k"),
     KeyResolutionError),
]


@pytest.mark.parametrize("run", [_sync, _async], ids=["sync", "async"])
@pytest.mark.parametrize("name,build,expected", CASES, ids=[c[0] for c in CASES])
def test_a_megabyte_identifier_is_not_echoed_whole(run, name, build, expected):
    with pytest.raises(OpenvcError) as info:
        run(build("a" * BIG))
    assert type(info.value) is expected
    assert len(str(info.value)) < BOUND


@pytest.mark.parametrize("run", [_sync, _async], ids=["sync", "async"])
def test_an_ordinary_identifier_is_still_quoted_in_full(run):
    iss = "did:unknown:example"
    with pytest.raises(OpenvcError) as info:
        run(_unsigned_vc_jwt(iss))
    assert type(info.value) is KeyResolutionFailed
    assert repr(iss) in str(info.value)


def test_issuer_binding_refusal_is_bounded_and_ordinary_values_stay_whole():
    # reached only after a valid signature, so the helper is driven directly
    def verified(vm: str, issuer: str) -> Any:
        return SimpleNamespace(issuer=issuer, proof={"verificationMethod": vm})

    with pytest.raises(IssuerBindingError) as info:
        _bind_issuer_to_verification_method(verified("did:example:a#k", "did:example:b"))
    assert type(info.value) is IssuerBindingError
    assert "'did:example:a#k'" in str(info.value) and "'did:example:b'" in str(info.value)
    with pytest.raises(IssuerBindingError) as info:
        _bind_issuer_to_verification_method(
            verified("did:example:" + "a" * BIG + "#k", "did:example:" + "b" * BIG))
    assert type(info.value) is IssuerBindingError
    assert len(str(info.value)) < BOUND


def test_status_issuer_refusal_is_bounded_and_ordinary_values_stay_whole():
    policy = VerificationPolicy(require_status_issuer_binding=True)
    with pytest.raises(StatusListIssuerUntrusted) as info:
        _enforce_status_issuer({"issuer": "did:example:s"}, "issuer", "did:example:c", policy)
    assert type(info.value) is StatusListIssuerUntrusted
    assert "'did:example:s'" in str(info.value) and "'did:example:c'" in str(info.value)
    with pytest.raises(StatusListIssuerUntrusted) as info:
        _enforce_status_issuer({"issuer": "did:example:" + "s" * BIG}, "issuer",
                               "did:example:" + "c" * BIG, policy)
    assert type(info.value) is StatusListIssuerUntrusted
    assert len(str(info.value)) < BOUND


def test_registries_bound_the_did_in_no_resolver():
    did = "did:unknown:" + "a" * BIG
    with pytest.raises(UnsupportedDidMethod) as info:
        DidResolverRegistry().resolve(did)
    assert type(info.value) is UnsupportedDidMethod
    assert len(str(info.value)) < BOUND
    with pytest.raises(UnsupportedDidMethod) as info:
        asyncio.run(AsyncDidResolverRegistry().resolve(did))
    assert type(info.value) is UnsupportedDidMethod
    assert len(str(info.value)) < BOUND
    with pytest.raises(UnsupportedDidMethod) as info:
        DidResolverRegistry().resolve("did:unknown:short")
    assert "'did:unknown:short'" in str(info.value)


# --------------------------------------------------------------------------- #
# fetch: the URL and the request target echoed in a failed dereference
# --------------------------------------------------------------------------- #

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, issuer_key: Any, public_key: Any, *, ca: bool,
          san: str | None = None) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name("openvc test CA"))
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True)
    else:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("openvc test CA", ca_key, ca_key.public_key(), ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(HOST, ca_key, leaf_key.public_key(), ca=False, san=HOST)
    folder = tmp_path_factory.mktemp("tls")
    cert_path, key_path = folder / "leaf.pem", folder / "leaf.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(str(cert_path), str(key_path))
    client = ssl.create_default_context(
        cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    return server, client


@pytest.fixture
def pinned(monkeypatch: pytest.MonkeyPatch, tls):
    server_ctx, client_ctx = tls
    monkeypatch.setattr(fetch, "_resolve_public_ips", lambda host, port: ["127.0.0.1"])
    monkeypatch.setattr(fetch.ssl, "create_default_context", lambda *a, **k: client_ctx)
    return server_ctx


def _serve(server_ctx: ssl.SSLContext, answer: bytes) -> int:
    """Accept one TLS connection, read the request head, write *answer*, close."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def run() -> None:
        raw, _ = listener.accept()
        listener.close()
        try:
            conn = server_ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            return
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                head += chunk
            conn.sendall(answer)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
GARBAGE = b"not http at all\r\n\r\n"


def _fetch_sync(url: str) -> Any:
    return https_json_fetch(url, timeout_s=5.0)


def _fetch_async(url: str) -> Any:
    return asyncio.run(https_json_fetch_async(url, timeout_s=5.0))


@pytest.mark.parametrize("run", [_fetch_sync, _fetch_async], ids=["sync", "async"])
@pytest.mark.parametrize("answer", [NOT_FOUND, GARBAGE], ids=["404", "bad-status-line"])
def test_a_long_did_web_path_is_not_echoed_whole(pinned, run, answer):
    port = _serve(pinned, answer)
    url = f"https://{HOST}:{port}/" + "a" * 400_000 + "/did.json"
    with pytest.raises(DidResolutionError) as info:
        run(url)
    assert type(info.value) is DidResolutionError
    assert len(str(info.value)) < BOUND


@pytest.mark.parametrize("run", [_fetch_sync, _fetch_async], ids=["sync", "async"])
@pytest.mark.parametrize("answer,needle", [
    (NOT_FOUND, "unexpected status 404 for "),
    (GARBAGE, "fetch failed for https://"),
], ids=["404", "bad-status-line"])
def test_an_ordinary_url_is_still_quoted_in_full(pinned, run, answer, needle):
    port = _serve(pinned, answer)
    url = f"https://{HOST}:{port}/.well-known/did.json"
    with pytest.raises(DidResolutionError) as info:
        run(url)
    assert type(info.value) is DidResolutionError
    message = str(info.value)
    assert needle in message
    assert "/.well-known/did.json" in message
    assert "chars)" not in message


def test_a_key_resolution_failure_of_a_resolver_error_is_bounded():
    class Failing:
        def supports(self, did: str) -> bool:
            return True

        def resolve(self, did: str):
            raise DidResolutionError("boom")

    big = "did:fail:" + "a" * BIG
    with pytest.raises(KeyResolutionFailed) as info:
        verify_credential(_unsigned_vc_jwt(big), resolver=Failing())
    assert type(info.value) is KeyResolutionFailed
    assert len(str(info.value)) < BOUND
