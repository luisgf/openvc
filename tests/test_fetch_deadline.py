"""
tests/test_fetch_deadline.py — one wall-clock deadline over the whole dereference (#385).

Before 1.39.0 ``_https_get`` started its deadline after ``getresponse()`` returned, so it
bounded only the body: the status line and headers were read one socket operation at a
time, each allowed the full per-socket ``timeout``, and ``getaddrinfo`` had no bound at
all. A server dripping one header byte per operation held a verifier thread for
``timeout_s`` × bytes (measured: a 1 s budget returned OK after 9 s).

A local TLS server, with a test CA generated once per session, stands in for the hostile
issuer host. The hostname is pinned to loopback by stubbing ``_resolve_public_ips`` (the
SSRF guard would otherwise refuse 127.0.0.1) and ``ssl.create_default_context`` is replaced
by a client context that trusts the test CA only. Hostname verification, SNI, the Host
header, the watchdog and the body loop run unmodified. Nothing reaches the network.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import decimal
import socket
import ssl
import threading
import time
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from openvc import fetch
from openvc.did.base import DidResolutionError
from openvc.fetch import UnsafeUrlError, https_json_fetch

HOST = "issuer.example"
TIMEOUT_S = 1.0
# The brief's bound: a refusal must land within timeout_s + 1 s.
BUDGET_S = TIMEOUT_S + 1.0
WATCHDOG = "openvc-fetch-watchdog"
DNS_WORKER = "openvc-fetch-dns"
HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n"


# --------------------------------------------------------------------------- #
# A test CA and a TLS server for it (self-contained: tests/ is not a package)
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


@pytest.fixture(scope="session")
def tls(tmp_path_factory: pytest.TempPathFactory) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """(server context for HOST, client context trusting the test CA only)."""
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


def _listen() -> socket.socket:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return listener


def _serve(server_ctx: ssl.SSLContext, handler: Callable[[ssl.SSLSocket], None],
           seen: dict[str, bytes] | None = None) -> int:
    """Accept ONE TLS connection, read the request head, hand the socket to *handler*.
    Returns the port. The thread ends when the handler returns or the client goes away."""
    listener = _listen()

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
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            if seen is not None:
                seen["head"] = head
            handler(conn)
        except OSError:  # the client hung up: the deadline fired
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


def _drip(conn: ssl.SSLSocket, data: bytes, *, piece: int, pause_s: float) -> None:
    for start in range(0, len(data), piece):
        conn.sendall(data[start:start + piece])
        time.sleep(pause_s)


def _hang(conn: socket.socket, max_s: float = 3.0) -> None:
    """Send nothing until the client goes away (bounded so a failing test ends)."""
    conn.settimeout(max_s)
    try:
        conn.recv(1)
    except OSError:
        pass


def _json_ok(conn: ssl.SSLSocket) -> None:
    conn.sendall(HEAD + b"{}")


def _drip_relay(upstream_port: int, *, piece: int, pause_s: float) -> int:
    """A TCP relay to a real TLS server that drips the server's bytes to the client, so the
    TLS handshake itself arrives *piece* bytes at a time. Returns the port."""
    listener = _listen()

    def run() -> None:
        client, _ = listener.accept()
        listener.close()
        upstream = socket.create_connection(("127.0.0.1", upstream_port))
        stop = threading.Event()

        def client_to_server() -> None:
            try:
                while not stop.is_set():
                    data = client.recv(65536)
                    if not data:
                        break
                    upstream.sendall(data)
            except OSError:
                pass
            finally:
                stop.set()
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        def server_to_client() -> None:
            try:
                while not stop.is_set():
                    data = upstream.recv(piece)
                    if not data:
                        break
                    client.sendall(data)
                    time.sleep(pause_s)
            except OSError:
                pass
            finally:
                stop.set()
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threading.Thread(target=client_to_server, daemon=True).start()
        server_to_client()
        client.close()
        upstream.close()

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def no_watchdog_left():
    """Every exit path of ``_https_get`` cancels and joins its watchdog."""
    yield
    assert [t.name for t in threading.enumerate() if t.name == WATCHDOG] == []


@pytest.fixture
def pinned(monkeypatch: pytest.MonkeyPatch, tls: tuple[ssl.SSLContext, ssl.SSLContext]):
    """Pin HOST to loopback and trust the test CA; returns the server context."""
    server_ctx, client_ctx = tls
    monkeypatch.setattr(fetch, "_resolve_public_ips", lambda host, port: ["127.0.0.1"])
    monkeypatch.setattr(fetch.ssl, "create_default_context", lambda *a, **k: client_ctx)
    return server_ctx


def _url(port: int, path: str = "/.well-known/did.json") -> str:
    return f"https://{HOST}:{port}{path}"


def _new_fetch_threads(before: set[threading.Thread]) -> list[str]:
    """The fetch threads alive now that were not alive at *before* (another test's
    abandoned DNS worker may still be sleeping: only this fetch's threads count)."""
    return [t.name for t in threading.enumerate()
            if t not in before and t.name in (WATCHDOG, DNS_WORKER)]


def _refused(url: str, **kwargs: Any) -> tuple[DidResolutionError, float]:
    """Run the fetch, require the exact typed error, return it with the elapsed time."""
    started = time.monotonic()
    with pytest.raises(DidResolutionError) as info:
        https_json_fetch(url, timeout_s=TIMEOUT_S, **kwargs)
    elapsed = time.monotonic() - started
    assert type(info.value) is DidResolutionError  # not UnsafeUrlError: a deadline, not SSRF
    return info.value, elapsed


# --------------------------------------------------------------------------- #
# Negatives: the deadline holds over every phase
# --------------------------------------------------------------------------- #

def test_hang_before_the_status_line_is_refused_at_the_deadline(pinned):
    port = _serve(pinned, _hang)
    exc, elapsed = _refused(_url(port))
    assert "exceeded the wall-clock deadline during the response head" in str(exc)
    assert elapsed < BUDGET_S


def test_header_drip_is_refused_at_the_deadline(pinned):
    # One byte per 0.15 s: every socket operation completes well inside the 1 s
    # per-operation timeout, while the whole head takes ~6 s. Before the fix this returned
    # OK after the whole drip (9.3 s measured for the audit's head).
    port = _serve(pinned, lambda conn: _drip(conn, HEAD + b"{}", piece=1, pause_s=0.15))
    exc, elapsed = _refused(_url(port))
    assert "exceeded the wall-clock deadline during the response head" in str(exc)
    assert elapsed < BUDGET_S


def test_tls_handshake_drip_is_refused_at_the_deadline(pinned):
    # The server's handshake bytes arrive 32 at a time, 0.2 s apart (several seconds for
    # a TLS 1.3 handshake). CPython already holds one do_handshake() call to the socket
    # timeout as a whole, so this phase was bounded before; now it spends the shared
    # budget (what DNS left) and fails with the deadline error, not a generic timeout.
    upstream = _serve(pinned, _json_ok)
    port = _drip_relay(upstream, piece=32, pause_s=0.2)
    exc, elapsed = _refused(_url(port))
    assert "exceeded the wall-clock deadline during the TLS handshake" in str(exc)
    assert elapsed < BUDGET_S


def test_body_drip_is_still_refused(pinned):
    # The control: the body was already deadline-bounded; it still is, and an EOF the
    # watchdog causes is never returned as a complete body.
    def body_drip(conn: ssl.SSLSocket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n")
        _drip(conn, b"{" * 40, piece=1, pause_s=0.3)
    port = _serve(pinned, body_drip)
    exc, elapsed = _refused(_url(port))
    assert "exceeded the wall-clock deadline during the response body" in str(exc)
    assert elapsed < BUDGET_S


def test_slow_dns_is_refused_at_the_deadline(monkeypatch):
    # getaddrinfo has no timeout of its own; the lookup is waited on only until the
    # deadline. No TCP connection may be attempted meanwhile.
    def slow_dns(host, *args, **kwargs):
        time.sleep(2.0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    def no_tcp(address, *args, **kwargs):
        raise AssertionError(f"TCP connection attempted to {address!r}")
    monkeypatch.setattr(fetch.socket, "getaddrinfo", slow_dns)
    monkeypatch.setattr(fetch.socket, "create_connection", no_tcp)
    exc, elapsed = _refused(_url(443))
    assert str(exc) == f"DNS resolution of {HOST!r} exceeded the {TIMEOUT_S:g}s deadline"
    assert elapsed < BUDGET_S


def test_dns_time_is_spent_from_the_same_budget(pinned, monkeypatch):
    # 0.7 s of lookup leaves 0.3 s for the exchange: the hang is refused at ~1 s in all,
    # not at 0.7 + 1.0 (which is what a deadline restarted after DNS would give).
    def slow_resolve(host, port):
        time.sleep(0.7)
        return ["127.0.0.1"]
    monkeypatch.setattr(fetch, "_resolve_public_ips", slow_resolve)
    port = _serve(pinned, _hang)
    exc, elapsed = _refused(_url(port))
    assert "exceeded the wall-clock deadline" in str(exc)
    assert elapsed < TIMEOUT_S + 0.5


def test_async_path_inherits_the_deadline(pinned):
    port = _serve(pinned, lambda conn: _drip(conn, HEAD + b"{}", piece=1, pause_s=0.15))
    started = time.monotonic()
    with pytest.raises(DidResolutionError) as info:
        asyncio.run(fetch.https_json_fetch_async(_url(port), timeout_s=TIMEOUT_S))
    assert time.monotonic() - started < BUDGET_S
    assert "exceeded the wall-clock deadline" in str(info.value)


@pytest.mark.parametrize("timeout_s", [
    0, -1.0, float("nan"), float("inf"),
    9.3e9, 2 ** 63, 10 ** 400, 86_400.001,  # finite but past the timers (or past the cap)
    None, "5", b"5", decimal.Decimal("2"),  # not an int or float: bare TypeError before
    True,                                   # bool is not a number of seconds
])
def test_a_degenerate_budget_is_refused_up_front(monkeypatch, timeout_s):
    # NaN would make every deadline comparison false; inf and a finite value past ~9.2e9 s
    # overflow the timers (a bare OverflowError before); a non-number was a bare TypeError;
    # a non-positive budget is already spent. All typed, before any lookup.
    monkeypatch.setattr(fetch.socket, "getaddrinfo",
                        lambda *a, **k: pytest.fail("DNS lookup attempted"))
    with pytest.raises(DidResolutionError, match="at most 86400") as info:
        https_json_fetch(_url(443), timeout_s=timeout_s)
    assert type(info.value) is DidResolutionError


def test_the_largest_budget_is_accepted(pinned):
    # The ceiling itself (one day, MAX_TIMEOUT_S) arms a timer that is cancelled and joined.
    port = _serve(pinned, _json_ok)
    assert https_json_fetch(_url(port), timeout_s=fetch.MAX_TIMEOUT_S) == {}


def test_connect_emits_the_stdlib_audit_event(monkeypatch):
    # The connect() override keeps the http.client.connect event the stdlib emits (an audit
    # hook that logs or denies outbound connects must still see openvc's). sys.audit is
    # replaced for the test: a real hook can never be removed from the interpreter.
    events: list[tuple[str, tuple[Any, ...]]] = []
    monkeypatch.setattr(fetch.sys, "audit", lambda event, *args: events.append((event, args)))

    def no_tcp(address, *args, **kwargs):
        raise OSError("stop before any connection")
    monkeypatch.setattr(fetch.socket, "create_connection", no_tcp)
    with pytest.raises(DidResolutionError, match="stop before any connection"):
        fetch._https_get(HOST, "127.0.0.1", 443, "/x", timeout=TIMEOUT_S, max_bytes=10)
    assert [(event, args[1:]) for event, args in events
            if event == "http.client.connect"] == [("http.client.connect", (HOST, 443))]


# --------------------------------------------------------------------------- #
# Positives: the happy path is unchanged and leaves nothing behind
# --------------------------------------------------------------------------- #

def test_happy_path_is_unchanged_and_leaves_no_thread_behind(pinned):
    seen: dict[str, bytes] = {}
    port = _serve(pinned, _json_ok, seen)
    before = set(threading.enumerate())
    assert https_json_fetch(_url(port), timeout_s=TIMEOUT_S) == {}
    # SNI / hostname verification and the Host header still use the name (the server's
    # certificate is for HOST, the socket went to 127.0.0.1).
    assert f"Host: {HOST}:{port}".encode() in seen["head"]
    assert _new_fetch_threads(before) == []


def test_the_ssrf_guard_is_unchanged_under_the_deadline(monkeypatch):
    # The classification still runs as is on the lookup thread: a forbidden address is
    # the same UnsafeUrlError, re-raised on the caller's thread.
    monkeypatch.setattr(fetch.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    before = set(threading.enumerate())
    with pytest.raises(UnsafeUrlError, match="blocked address 10.1.2.3"):
        https_json_fetch(_url(443), timeout_s=TIMEOUT_S)
    assert _new_fetch_threads(before) == []


def test_a_served_oversize_body_is_still_refused(pinned):
    port = _serve(pinned, lambda conn: conn.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n" + b"[" * 20))
    with pytest.raises(DidResolutionError, match="exceeds 10 bytes"):
        https_json_fetch(_url(port), timeout_s=TIMEOUT_S, max_bytes=10)
