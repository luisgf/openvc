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


def test_refuses_redirects():
    with pytest.raises(UnsafeUrlError, match="redirect"):
        fetch._NoRedirect().redirect_request(
            None, None, 302, "Found", {}, "https://elsewhere.example/")


# --------------------------------------------------------------------------- #
# Happy path (transport monkeypatched — no real network)
# --------------------------------------------------------------------------- #

class _FakeResp:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self, n: int = -1) -> bytes:
        return self._data


class _FakeOpener:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def open(self, req, timeout=None):        # noqa: ANN001 - test double
        return _FakeResp(self._data)


def _allow_public(monkeypatch):
    monkeypatch.setattr(
        fetch.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])


def test_happy_path_returns_json(monkeypatch):
    _allow_public(monkeypatch)
    monkeypatch.setattr(fetch, "_build_opener",
                        lambda: _FakeOpener(b'{"id": "did:web:issuer.example"}'))
    doc = https_json_fetch("https://issuer.example/.well-known/did.json")
    assert doc == {"id": "did:web:issuer.example"}


def test_non_json_body_rejected(monkeypatch):
    _allow_public(monkeypatch)
    monkeypatch.setattr(fetch, "_build_opener", lambda: _FakeOpener(b"<html/>"))
    with pytest.raises(DidResolutionError, match="not JSON"):
        https_json_fetch("https://issuer.example/.well-known/did.json")


def test_oversize_body_rejected(monkeypatch):
    _allow_public(monkeypatch)
    monkeypatch.setattr(fetch, "_build_opener", lambda: _FakeOpener(b"x" * 50))
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
    monkeypatch.setattr(
        fetch, "_build_opener",
        lambda: _FakeOpener(b'{"id": "did:web:issuer.example", "verificationMethod": []}'))
    doc = resolver.resolve("did:web:issuer.example")
    assert doc.id == "did:web:issuer.example"
