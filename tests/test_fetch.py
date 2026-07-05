"""
tests/test_fetch.py — the SSRF-guarded did:web fetch (openvc.fetch).

All offline: IP classification is pure, and the network boundary (getaddrinfo,
the URL opener) is monkeypatched so no real request is ever made.
"""
from __future__ import annotations

import pytest

from openvc import fetch
from openvc.did.base import DidResolutionError
from openvc.did.did_web import DidWebResolver
from openvc.fetch import UnsafeUrlError, https_json_fetch


# --------------------------------------------------------------------------- #
# Pure IP classification
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ip", [
    "10.0.0.5", "172.16.0.1", "192.168.1.1",       # private
    "127.0.0.1", "::1",                            # loopback
    "169.254.169.254", "fe80::1",                  # link-local (cloud metadata!)
    "0.0.0.0", "224.0.0.1",                        # unspecified / multicast
])
def test_forbidden_ips(ip):
    assert fetch._ip_is_forbidden(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::1"])
def test_public_ips_allowed(ip):
    assert fetch._ip_is_forbidden(ip) is False


# --------------------------------------------------------------------------- #
# Scheme + host guards
# --------------------------------------------------------------------------- #

def test_rejects_non_https():
    with pytest.raises(UnsafeUrlError, match="https"):
        https_json_fetch("http://issuer.example/.well-known/did.json")


def test_rejects_url_without_host():
    with pytest.raises(UnsafeUrlError, match="no host"):
        https_json_fetch("https:///did.json")


def test_rejects_host_resolving_to_private(monkeypatch):
    # A hostname that resolves to a private address must be blocked.
    monkeypatch.setattr(
        fetch.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    with pytest.raises(UnsafeUrlError, match="blocked address"):
        https_json_fetch("https://internal.evil.example/.well-known/did.json")


# --------------------------------------------------------------------------- #
# Happy path (transport monkeypatched — no real network)
# --------------------------------------------------------------------------- #

PUBLIC_IP = "93.184.216.34"


def _allow_public(monkeypatch):
    monkeypatch.setattr(
        fetch.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", (PUBLIC_IP, 443))])


def _stub_get(monkeypatch, status: int, body: bytes, *, capture: list | None = None):
    def _fake(hostname, ip, port, target, *, timeout, max_bytes):
        if capture is not None:
            capture.append((hostname, ip, port, target))
        return status, body
    monkeypatch.setattr(fetch, "_https_get", _fake)


def test_refuses_redirects(monkeypatch):
    _allow_public(monkeypatch)
    _stub_get(monkeypatch, 302, b"")
    with pytest.raises(UnsafeUrlError, match="redirect"):
        https_json_fetch("https://issuer.example/.well-known/did.json")


def test_happy_path_returns_json(monkeypatch):
    _allow_public(monkeypatch)
    _stub_get(monkeypatch, 200, b'{"id": "did:web:issuer.example"}')
    doc = https_json_fetch("https://issuer.example/.well-known/did.json")
    assert doc == {"id": "did:web:issuer.example"}


def test_connection_is_pinned_to_validated_ip(monkeypatch):
    # The GET must target the IP we validated, not re-resolve the hostname
    # (this is what closes the DNS-rebinding window).
    _allow_public(monkeypatch)
    seen: list = []
    _stub_get(monkeypatch, 200, b"{}", capture=seen)
    https_json_fetch("https://issuer.example/.well-known/did.json")
    assert seen and seen[0][1] == PUBLIC_IP        # (hostname, ip, port, target)
    assert seen[0][0] == "issuer.example"


def test_unexpected_status_rejected(monkeypatch):
    _allow_public(monkeypatch)
    _stub_get(monkeypatch, 500, b"boom")
    with pytest.raises(DidResolutionError, match="status 500"):
        https_json_fetch("https://issuer.example/.well-known/did.json")


def test_non_json_body_rejected(monkeypatch):
    _allow_public(monkeypatch)
    _stub_get(monkeypatch, 200, b"<html/>")
    with pytest.raises(DidResolutionError, match="not JSON"):
        https_json_fetch("https://issuer.example/.well-known/did.json")


def test_oversize_body_rejected(monkeypatch):
    _allow_public(monkeypatch)
    _stub_get(monkeypatch, 200, b"x" * 50)
    with pytest.raises(DidResolutionError, match="exceeds"):
        https_json_fetch("https://issuer.example/.well-known/did.json", max_bytes=10)


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #

def test_default_did_web_resolver_is_wired(monkeypatch):
    resolver = fetch.default_did_web_resolver()
    assert isinstance(resolver, DidWebResolver)
    assert resolver.supports("did:web:issuer.example")

    _allow_public(monkeypatch)
    _stub_get(monkeypatch, 200,
              b'{"id": "did:web:issuer.example", "verificationMethod": []}')
    doc = resolver.resolve("did:web:issuer.example")
    assert doc.id == "did:web:issuer.example"
