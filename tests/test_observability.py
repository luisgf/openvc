"""
tests/test_observability.py — optional logging + tracing hooks (issue #25).

openvc emits stdlib-logging events and optional tracing spans at the resolve / fetch /
status / verify boundaries. Both are off by default (the logger has only a NullHandler; the
span hook is a no-op) and must **never** carry secrets. These tests pin: the default
silence, the injectable span hook (install / fire / reset / observe-exception), that each
boundary emits its event, and that no key/token/proofValue material reaches the logs.
"""
from __future__ import annotations

import base64
import logging
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone

import pytest

from openvc import verify_credential, VerificationPolicy
from openvc.did.did_key import DidKeyResolver
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.observability import logger, set_span_hook, span
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.status import encode_bitstring
from openvc.status.status_list import check_credential_status

UTC = timezone.utc
STATUS_URL = "https://issuer.example/status/1"


@pytest.fixture
def obs():
    """Capture openvc log messages and span calls; reset the span hook afterwards."""
    records: list[tuple[str, str]] = []
    handler = logging.Handler()
    handler.emit = lambda r: records.append((logging.getLevelName(r.levelno), r.getMessage()))
    logger.addHandler(handler)
    old_level = logger.level
    logger.setLevel(logging.DEBUG)

    spans: list[tuple[str, dict]] = []

    @contextmanager
    def hook(name, attrs):
        spans.append((name, dict(attrs)))
        yield

    set_span_hook(hook)
    try:
        yield records, spans
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        set_span_hook(None)


# -- helpers ---------------------------------------------------------------- #

def _leb128(code: int) -> bytes:
    out = bytearray()
    while True:
        byte = code & 0x7F
        code >>= 7
        out.append(byte | (0x80 if code else 0))
        if not code:
            return bytes(out)


def _did_key(key) -> str:
    raw = base64.urlsafe_b64decode(key.public_jwk()["x"] + "==")
    return "did:key:" + encode_multibase(_leb128(0xED) + raw)


def _signed():
    key = Ed25519SigningKey.generate(kid="t")
    did = _did_key(key)
    vm = f"{did}#{did[len('did:key:'):]}"
    cred = EddsaJcsProofSuite().add_proof(
        {"@context": ["https://www.w3.org/ns/credentials/v2"],
         "type": ["VerifiableCredential"], "issuer": did,
         "validFrom": "2020-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:a"}},
        signing_key=key, verification_method=vm)
    return cred, did


def _verify(cred):
    return verify_credential(cred, resolver=DidKeyResolver(),
                             policy=VerificationPolicy(require_status=False,
                                                       now=datetime(2021, 1, 1, tzinfo=UTC)))


# --------------------------------------------------------------------------- #
# defaults: silent logger, no-op span
# --------------------------------------------------------------------------- #

def test_logger_is_the_openvc_logger():
    assert logger is logging.getLogger("openvc")


def test_silent_by_default_via_nullhandler():
    """openvc attaches only a NullHandler and never basicConfig/addHandler(real), so
    records don't reach the root last-resort handler until the app opts in."""
    assert any(isinstance(h, logging.NullHandler) for h in logging.getLogger("openvc").handlers)
    # and every event openvc emits is DEBUG/INFO — below the default root WARNING — so a
    # plain `import openvc; verify(...)` prints nothing without explicit configuration.


def test_span_is_noop_without_a_hook():
    set_span_hook(None)
    with span("openvc.test", attr=1):        # must not raise; returns a real context manager
        pass


def test_span_hook_install_fire_and_reset():
    seen: list[tuple[str, dict]] = []
    set_span_hook(lambda name, attrs: (seen.append((name, attrs)), nullcontext())[1])
    with span("openvc.op", did="did:key:z"):
        pass
    assert seen == [("openvc.op", {"did": "did:key:z"})]
    set_span_hook(None)                       # reset → no-op
    seen.clear()
    with span("openvc.op2"):
        pass
    assert seen == []


def test_suppressing_hook_cannot_cause_fail_open():
    """A hook whose __exit__ returns True must NOT swallow the wrapped operation's
    exception — otherwise a status-resolution failure inside `with span(...)` would be
    suppressed and a fail-closed check would silently pass. The single most important
    isolation property (found in adversarial review)."""
    class _Suppress:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return True                       # tries to suppress the exception

    set_span_hook(lambda name, attrs: _Suppress())
    try:
        with pytest.raises(ValueError):       # the operation's error STILL propagates
            with span("openvc.status"):
                raise ValueError("status list unreachable")
    finally:
        set_span_hook(None)


def _raises_on_call(name, attrs):
    raise RuntimeError("hook factory boom")


def _raises_on_enter(name, attrs):
    class _C:
        def __enter__(self):
            raise RuntimeError("enter boom")

        def __exit__(self, *exc):
            return False
    return _C()


@pytest.mark.parametrize("bad_hook", [
    _raises_on_call,                          # the factory itself raises
    _raises_on_enter,                         # __enter__ raises
    lambda name, attrs: object(),            # not a context manager at all
], ids=["factory-raises", "enter-raises", "not-a-context-manager"])
def test_broken_hook_does_not_break_verification(bad_hook):
    """A broken tracing hook must never break the operation it wraps — verification of a
    good credential still succeeds, and a good credential's error still raises."""
    cred, did = _signed()
    set_span_hook(bad_hook)
    try:
        assert _verify(cred).issuer == did   # good credential still verifies
    finally:
        set_span_hook(None)


def test_broken_hook_is_logged(obs):
    records, _ = obs
    set_span_hook(_raises_on_call)
    try:
        with span("openvc.op"):
            pass
    finally:
        set_span_hook(None)
    assert any(lvl == "WARNING" and "span hook failed" in m for lvl, m in records)


def test_span_hook_observes_exceptions():
    """The hook's context manager is entered around the operation, so it sees an exception
    on exit (an OTel span would record it)."""
    caught = {}

    @contextmanager
    def hook(name, attrs):
        try:
            yield
        except Exception as exc:              # pragma: no branch
            caught["type"] = type(exc).__name__
            raise

    set_span_hook(hook)
    try:
        with pytest.raises(ValueError):
            with span("openvc.op"):
                raise ValueError("boom")
        assert caught["type"] == "ValueError"
    finally:
        set_span_hook(None)


# --------------------------------------------------------------------------- #
# boundary events
# --------------------------------------------------------------------------- #

def test_verify_boundary_emits_logs_and_spans(obs):
    records, spans = obs
    cred, did = _signed()
    _verify(cred)
    msgs = [m for _, m in records]
    assert any(m.startswith("verify: format=data-integrity:eddsa-jcs-2022") for m in msgs)
    assert any(m.startswith("verify ok:") and did in m for m in msgs)
    names = [n for n, _ in spans]
    assert "openvc.verify_credential" in names
    assert "openvc.resolve" in names
    assert ("openvc.resolve", {"did": did}) in spans


def test_verify_failure_is_logged_at_info(obs):
    records, _ = obs
    cred, _ = _signed()
    cred["credentialSubject"]["id"] = "did:example:MALLORY"       # break the signature
    with pytest.raises(Exception):
        _verify(cred)
    assert any(lvl == "INFO" and m.startswith("verify failed:") and "SignatureInvalid" in m
               for lvl, m in records)


def test_status_boundary_emits_event(obs):
    records, spans = obs
    bits = bytearray(32)
    status_vc = {"type": ["VerifiableCredential", "BitstringStatusListCredential"],
                 "credentialSubject": {"statusPurpose": "revocation",
                                       "encodedList": encode_bitstring(bytes(bits))}}
    credential = {"credentialStatus": {
        "type": "BitstringStatusListEntry", "statusPurpose": "revocation",
        "statusListIndex": "3", "statusListCredential": STATUS_URL}}
    check_credential_status(credential, resolve_status_list=lambda url: status_vc)
    assert any(m.startswith("status checked:") for _, m in records)
    assert "openvc.status" in [n for n, _ in spans]


def test_fetch_boundary_emits_event(monkeypatch, obs):
    records, spans = obs
    from openvc import fetch
    monkeypatch.setattr(fetch, "_resolve_public_ips", lambda host, port: ["203.0.113.7"])
    monkeypatch.setattr(fetch, "_https_get", lambda *a, **k: (200, b"{}"))
    fetch.https_json_fetch("https://issuer.example/.well-known/jwt-vc-issuer?x=1")
    # host + path logged, query (a possible secret carrier) is NOT
    assert any(m == "fetch https://issuer.example/.well-known/jwt-vc-issuer" for _, m in records)
    assert not any("x=1" in m for _, m in records)
    assert ("openvc.fetch", {"host": "issuer.example"}) in spans


# --------------------------------------------------------------------------- #
# never log secrets
# --------------------------------------------------------------------------- #

def test_no_secret_material_in_logs(obs):
    records, _ = obs
    cred, _ = _signed()
    _verify(cred)
    blob = "\n".join(m for _, m in records)
    assert cred["proof"]["proofValue"] not in blob         # signature never logged
    assert "proofValue" not in blob
    assert "privateKey" not in blob and "\"d\"" not in blob  # no private-key material
