"""
tests/test_did_web_segments.py — a did:web path segment goes on the wire as written.

did:web maps ``did:web:host:a:b`` to ``https://host/a/b/did.json`` and percent-decodes
only the port's ``%3A``. ``_did_web_url`` used to ``unquote()`` every segment, so an
escaped ``#``, ``?`` or ``/``, a ``..`` segment or an escaped control character changed
the path the guarded fetch requested (``urlparse`` cuts a path at a fragment or a query,
so ``did.json`` was not even asked for), ``%0A`` decoded to a newline ``urlsplit``
strips (two identifiers, one URL) and ``::`` sent ``//``. The trust boundary widened
from ``<path>/did.json`` to any path on the host, and such a DID resolves in no
conformant resolver.

Now the host decodes ``%3A`` alone, every segment is used verbatim, and a segment that
is empty, a dot segment in any spelling, non-ASCII, a control character or whitespace,
a URL delimiter (``/ ? # \\ %``) or a ``%XX`` escape of any of those is a typed
``DidResolutionError`` before any fetch — the caller's own fetch included — on the sync
and the async resolver alike. did:webvh reuses the mapping and inherits the rule. (#384)

All offline: every injected fetch fails the test if it is called, and the pipeline
tests fail it if anything reaches DNS or TCP.
"""
from __future__ import annotations

import asyncio
import time

import pytest

import openvc.did.did_web as did_web
import openvc.jwt_vc_issuer as jwt_vc_issuer
from openvc import fetch
from openvc.did.base import DidResolutionError
from openvc.did.did_web import AsyncDidWebResolver, DidWebResolver, _did_web_url
from openvc.did.did_webvh import (
    AsyncDidWebvhResolver,
    DidWebvhError,
    DidWebvhResolver,
    _did_webvh_url,
)
from openvc.fetch import default_did_web_resolver, default_did_webvh_resolver
from openvc.keys import P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.verify import KeyResolutionFailed, default_resolver, verify_many

V2 = "https://www.w3.org/ns/credentials/v2"

# Each is refused before any fetch. The old mapping decoded them and built a URL whose
# path was not ``<segments>/did.json``.
HOSTILE_SEGMENTS = [
    # an empty segment: the URL would carry "//"
    "did:web:example.com::admin",
    "did:web:example.com:",
    "did:web:example.com:a::b",
    "did:web:example.com%3A8443::admin",
    # a dot segment, in every spelling the https issuer lanes refuse
    "did:web:example.com:.",
    "did:web:example.com:..",
    "did:web:example.com:..:..:other",
    "did:web:example.com:a:..:b",
    "did:web:example.com:%2E%2E:%2E%2E:etc",
    "did:web:example.com:%2e",
    "did:web:example.com:.%2E",
    "did:web:example.com:%2e.",
    "did:web:example.com:%2E%2e",
    # the measured spellings: an escaped delimiter changed the requested path
    "did:web:example.com:api%23x",                # the fragment ate /did.json: GET /api
    "did:web:example.com:api%3Fx=1",              # GET /api?x=1/did.json
    "did:web:example.com:api%3Fformat=json%26",
    "did:web:example.com:a%2Fb",                  # /a/b/did.json
    "did:web:example.com:a%2fb",
    "did:web:example.com:a%5Cb",                  # a WHATWG parser reads \ as /
    "did:web:example.com:a%25b",                  # an escape of an escape
    # a literal delimiter
    "did:web:example.com:a/b",
    "did:web:example.com:a?b",
    "did:web:example.com:a#b",
    "did:web:example.com:a\\b",
    # a % that is not a %XX escape
    "did:web:example.com:c%2",
    "did:web:example.com:a%",
    "did:web:example.com:a%zzb",
    "did:web:example.com:a%4Gb",
    "did:web:example.com:%",
    # a control character or whitespace, literal and escaped (urlsplit strips \t\r\n)
    "did:web:example.com:a b",
    "did:web:example.com:a\tb",
    "did:web:example.com:a\nb",
    "did:web:example.com:a\rb",
    "did:web:example.com:a\x00b",
    "did:web:example.com:a\x1fb",
    "did:web:example.com:a\x7fb",
    "did:web:example.com:a%20b",
    "did:web:example.com:a%09b",
    "did:web:example.com:a%0Ab",
    "did:web:example.com:a%0ab",
    "did:web:example.com:a%0Db",
    "did:web:example.com:a%00b",
    "did:web:example.com:a%1Fb",
    "did:web:example.com:a%7Fb",
    # non-ASCII, literal and escaped: the host's ASCII-only policy, applied to the path
    "did:web:example.com:münchen",
    "did:web:example.com:K",                 # KELVIN SIGN: lower() makes it "k"
    "did:web:example.com:a​b",               # a zero-width space
    "did:web:example.com:m%C3%BCnchen",
    "did:web:example.com:a%80b",
    "did:web:example.com:a%FFb",
    "did:web:example.com:a%E2%80%8Bb",
]

# The host decodes the port's %3A and nothing else: these decoded to a valid host and
# were fetched; now any other % fails the domain-name syntax.
ESCAPED_HOSTS = [
    "did:web:ex%61mple.com",                      # decoded to example.com
    "did:web:example%2Ecom",
    "did:web:example.com%3A%38443",               # decoded to port 8443
]

# Unchanged mappings, and escapes of printable ASCII that are now sent as written.
VERBATIM = [
    ("did:web:example.com", "https://example.com/.well-known/did.json"),
    ("did:web:example.com:user:alice", "https://example.com/user/alice/did.json"),
    ("did:web:example.com%3A8443", "https://example.com:8443/.well-known/did.json"),
    ("did:web:example.com%3a8443", "https://example.com:8443/.well-known/did.json"),
    ("did:web:example.com%3A8443:issuers:physics",
     "https://example.com:8443/issuers/physics/did.json"),
    ("did:web:EXAMPLE.com:Users", "https://EXAMPLE.com/Users/did.json"),
    ("did:web:example.com:~alice", "https://example.com/~alice/did.json"),
    ("did:web:example.com:user+x", "https://example.com/user+x/did.json"),
    ("did:web:example.com:a!b", "https://example.com/a!b/did.json"),
    ("did:web:example.com:a@b", "https://example.com/a@b/did.json"),
    ("did:web:example.com:a=b", "https://example.com/a=b/did.json"),
    ("did:web:example.com:a-b_c.d", "https://example.com/a-b_c.d/did.json"),
    ("did:web:example.com:a%3Ab", "https://example.com/a%3Ab/did.json"),
    ("did:web:example.com:a%41b", "https://example.com/a%41b/did.json"),
    ("did:web:example.com:%40evil", "https://example.com/%40evil/did.json"),
    ("did:web:example.com:a%7Eb", "https://example.com/a%7Eb/did.json"),
    ("did:web:example.com:a%21b", "https://example.com/a%21b/did.json"),
    ("did:web:example.com:a%2eb", "https://example.com/a%2eb/did.json"),
]

# One spelling per refusal, so that removing one check fails a named test.
NAMED_REFUSALS = [
    ("did:web:example.com::admin", "has an empty path segment"),
    ("did:web:example.com:%2E%2E:x", "has a dot path segment '%2E%2E'"),
    ("did:web:example.com:münchen", "is not ASCII"),
    ("did:web:example.com:a\tb", "contains a control character or whitespace"),
    ("did:web:example.com:a b", "contains a control character or whitespace"),
    ("did:web:example.com:a#b", "contains a URL delimiter"),
    ("did:web:example.com:c%2", "has a % that is not a %XX escape"),
    ("did:web:example.com:api%23x", "percent-encodes %23"),
    ("did:web:example.com:a%0Ab", "percent-encodes %0A"),
    ("did:web:example.com:a%C3%BCb", "percent-encodes %C3"),
]

WEBVH_HOSTILE = [
    "did:webvh:QmScid:example.com:api%23x",
    "did:webvh:QmScid:example.com::admin",
    "did:webvh:QmScid:example.com:..:other",
    "did:webvh:QmScid:example.com%3A8443:a%2Fb",
    "did:webvh:QmScid:example.com:a%0Ab",
]


# --------------------------------------------------------------------------- #
# helpers (tests/ is not a package: nothing is imported from another test module)
# --------------------------------------------------------------------------- #

def _never(url: str):
    raise AssertionError(f"fetch called with {url!r}")


async def _never_async(url: str):
    raise AssertionError(f"fetch called with {url!r}")


class _Recording:
    """A fetch that records the URL it is handed and serves a document for *did*."""

    def __init__(self, did: str) -> None:
        self.did, self.calls = did, []

    def __call__(self, url: str) -> dict:
        self.calls.append(url)
        return {"id": self.did}

    async def aio(self, url: str) -> dict:
        self.calls.append(url)
        return {"id": self.did}


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything reaches DNS or opens a TCP connection."""
    def _dns(host, *a, **k):
        raise AssertionError(f"DNS lookup attempted for {host!r}")

    def _tcp(address, *a, **k):
        raise AssertionError(f"TCP connection attempted to {address!r}")
    monkeypatch.setattr(fetch.socket, "getaddrinfo", _dns)
    monkeypatch.setattr(fetch.socket, "create_connection", _tcp)


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    sk = P256SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0x80, 0x24]) + sk.public_key_raw(compressed=True))
    return P256SigningKey(sk._sk, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _vc_jwt(issuer: str, signing_key=None) -> str:
    """A VC-JWT naming *issuer*; signed with a throwaway key unless one is given."""
    key = signing_key or P256SigningKey.generate(kid=f"{issuer}#k")
    return VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer,
         "credentialSubject": {"id": "did:example:holder"}},
        signing_key=key)


def _assert_fast(call, error):
    start = time.perf_counter()
    with pytest.raises(error):
        call()
    assert time.perf_counter() - start < 2.0


# --------------------------------------------------------------------------- #
# a hostile segment is refused, typed, before any fetch
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did", HOSTILE_SEGMENTS)
def test_did_web_url_refuses_a_hostile_segment(did):
    with pytest.raises(DidResolutionError) as info:
        _did_web_url(did)
    assert type(info.value) is DidResolutionError


@pytest.mark.parametrize("did", HOSTILE_SEGMENTS)
def test_did_web_resolver_never_calls_the_fetch(did):
    with pytest.raises(DidResolutionError) as info:
        DidWebResolver(_never).resolve(did)
    assert type(info.value) is DidResolutionError


@pytest.mark.parametrize("did", HOSTILE_SEGMENTS)
def test_async_did_web_resolver_never_calls_the_fetch(did):
    with pytest.raises(DidResolutionError) as info:
        asyncio.run(AsyncDidWebResolver(_never_async).resolve(did))
    assert type(info.value) is DidResolutionError


@pytest.mark.parametrize("did,match", NAMED_REFUSALS)
def test_the_refusal_names_the_rule_and_the_segment(did, match):
    with pytest.raises(DidResolutionError, match=r".*") as info:
        _did_web_url(did)
    assert match in str(info.value)
    assert str(info.value).startswith(f"did:web {did!r}")


# --------------------------------------------------------------------------- #
# the host decodes the port's %3A and nothing else
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did", ESCAPED_HOSTS)
def test_an_escaped_host_is_not_decoded(did):
    with pytest.raises(DidResolutionError) as info:
        _did_web_url(did)
    assert type(info.value) is DidResolutionError
    with pytest.raises(DidResolutionError):
        DidWebResolver(_never).resolve(did)
    with pytest.raises(DidResolutionError):
        asyncio.run(AsyncDidWebResolver(_never_async).resolve(did))


# --------------------------------------------------------------------------- #
# everything else is sent as written
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did,url", VERBATIM)
def test_did_web_url_sends_segments_verbatim(did, url):
    assert _did_web_url(did) == url


@pytest.mark.parametrize("did,url", VERBATIM)
def test_did_web_resolver_hands_the_fetch_the_verbatim_url(did, url):
    recording = _Recording(did)
    assert DidWebResolver(recording).resolve(did).id == did
    assert recording.calls == [url]

    recording = _Recording(did)
    assert asyncio.run(AsyncDidWebResolver(recording.aio).resolve(did)).id == did
    assert recording.calls == [url]


def test_dot_segments_are_the_https_issuer_set():
    # One set of spellings for every lane: did:web reuses the https issuer's, not a copy.
    assert did_web._DOT_SEGMENTS is jwt_vc_issuer._DOT_SEGMENTS
    assert {".", "..", "%2e", "%2e%2e"} <= did_web._DOT_SEGMENTS


# --------------------------------------------------------------------------- #
# bounded work and bounded messages: a segment can be megabytes long
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("segment", [
    "\x01" * 2_000_000,                 # a control character, repeated
    "%2F" * 700_000,                    # an escaped delimiter, repeated
    "%" * 2_000_000,                    # bare percents
    "一" * 2_000_000,               # non-ASCII
])
def test_a_huge_hostile_segment_is_refused_fast_with_a_bounded_message(segment):
    did = "did:web:example.com:" + segment
    _assert_fast(lambda: _did_web_url(did), DidResolutionError)
    with pytest.raises(DidResolutionError) as info:
        _did_web_url(did)
    assert len(str(info.value)) < 4_000


def test_a_huge_valid_segment_is_checked_fast():
    did = "did:web:example.com:" + "%41" * 700_000
    start = time.perf_counter()
    url = _did_web_url(did)
    assert time.perf_counter() - start < 2.0
    assert url == "https://example.com/" + "%41" * 700_000 + "/did.json"


# --------------------------------------------------------------------------- #
# did:webvh reuses the mapping and inherits the refusal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did", WEBVH_HOSTILE)
def test_did_webvh_inherits_the_segment_rule(did):
    with pytest.raises(DidWebvhError) as info:
        _did_webvh_url(did)
    assert type(info.value) is DidWebvhError
    with pytest.raises(DidWebvhError):
        DidWebvhResolver(fetch=_never).resolve(did)
    with pytest.raises(DidWebvhError):
        asyncio.run(AsyncDidWebvhResolver(fetch=_never_async).resolve(did))


def test_the_blessed_webvh_resolver_refuses_before_dns(no_network):
    with pytest.raises(DidWebvhError):
        default_did_webvh_resolver().resolve("did:webvh:QmScid:example.com:api%23x")
    with pytest.raises(DidWebvhError):
        default_resolver().resolve("did:webvh:QmScid:example.com:api%23x")


# --------------------------------------------------------------------------- #
# through the blessed resolver and the pipeline
# --------------------------------------------------------------------------- #

def test_the_blessed_did_web_resolver_refuses_before_dns(no_network):
    with pytest.raises(DidResolutionError):
        default_did_web_resolver().resolve("did:web:example.com:api%23x")
    with pytest.raises(DidResolutionError):
        default_resolver().resolve("did:web:example.com:..:other")


def test_verify_many_isolates_a_hostile_did_web_segment(no_network):
    key, did = _did_key_p256()
    batch = [_vc_jwt(did, key), _vc_jwt("did:web:example.com:api%23x"),
             _vc_jwt("did:web:example.com::admin")]
    good, *bad = verify_many(batch)
    assert good.ok is True
    for result in bad:
        assert result.ok is False
        assert isinstance(result.error, KeyResolutionFailed)
