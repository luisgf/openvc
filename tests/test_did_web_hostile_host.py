"""
tests/test_did_web_hostile_host.py — a hostile issuer host is a typed error.

A ``did:web`` / ``did:webvh`` / https issuer is attacker-controlled. Its host used to
reach ``urlparse``, ``getaddrinfo`` and ``http.client`` unchecked, and each raised its
own bare exception: ``ValueError`` (a port out of range, an unbalanced bracket, a
netloc that NFKC-normalizes into a delimiter), ``UnicodeError`` (an IDNA label over 63
characters) or ``InvalidURL`` (a NUL). None of them is an ``OpenvcError``, so one such
credential aborted a whole ``verify_many`` batch. It always failed closed, before any
TCP connection, so it was never an SSRF.

The fix has two layers, and both are pinned here: ``did:web`` checks the host is a
domain name before any fetch (so the caller's own fetch is covered too), and the
SSRF-guarded fetch maps every parse / IDNA / request-line failure into its typed
errors (so status-list, schema and well-known URLs are covered too).

All offline: ``getaddrinfo`` and ``create_connection`` are monkeypatched to fail the
test if a hostile host ever reaches DNS or TCP.
"""
from __future__ import annotations

import asyncio
import datetime
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc import fetch
from openvc.aio import verify_credential_async, verify_many_async
from openvc.did.base import DidResolutionError
from openvc.did.did_web import AsyncDidWebResolver, DidWebResolver, _did_web_url
from openvc.did.did_webvh import DidWebvhError, _did_webvh_url
from openvc.errors import OpenvcError
from openvc.fetch import (
    UnsafeUrlError,
    https_bytes_fetch,
    https_json_fetch,
    https_json_fetch_async,
    https_text_fetch,
)
from openvc.jwt_vc_issuer import JwtVcIssuerError, jwt_vc_issuer_metadata_url
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.openid4vp import verify_vp_token
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.resolvers import default_status_list_resolver
from openvc.verify import KeyResolutionFailed, default_resolver, verify_many
from openvc.x5c import X5cError, _check_issuer_binding

V2 = "https://www.w3.org/ns/credentials/v2"
NONCE = "n-0S6_WzA2Mj"
CLIENT_ID = "x509_san_dns:verifier.example"

# Each decodes to a host that is not a domain name with an optional port. The first
# six are the shapes that escaped as bare exceptions before the fix.
HOSTILE_DID_WEB = [
    "did:web:example.com%3A99999",              # ValueError: port out of range
    "did:web:%5B",                              # ValueError: invalid IPv6 URL
    "did:web:" + "a" * 64 + ".com",             # UnicodeError: IDNA label too long
    "did:web:ex%E2%84%80mple.com",              # ValueError: NFKC turns U+2100 into a/c
    "did:web:8.8.8.8%00.x",                     # InvalidURL: control character
    "did:web:example.com%3Aabc",                # ValueError: port is not an integer
    "did:web:example.com%3A",                   # an empty port
    "did:web:example.com%3A0",                  # port 0
    "did:web:example.com%3A%D9%A3",             # a non-ASCII digit as the port
    "did:web:evil.com%40example.com",           # userinfo: would fetch from example.com
    "did:web:example.com%2Fx",                  # a path smuggled into the host
    "did:web:example.com%23",                   # a fragment smuggled into the host
    "did:web:exa%20mple.com",                   # whitespace
    "did:web:.example.com",                     # an empty label
    "did:web:example..com",
    "did:web:example.com.",                     # a trailing root dot
    "did:web:-example.com",                     # a label starting with a hyphen
    "did:web:%5B2001%3Adb8%3A%3A1%5D",          # an IP literal (the spec forbids IPs)
    "did:web:" + ".".join(["a" * 63] * 4),      # 255 characters, over the 253 limit
    "did:web:ex%FFample.com",                   # invalid UTF-8 decodes to U+FFFD
    # A Unicode host, even a valid IDN: it must be written as its xn-- A-label (#235).
    # Python's IDNA2003 codec would map each to another domain than IDNA2008 does.
    "did:web:m%C3%BCnchen.de",                  # IDNA2008: xn--mnchen-3ya.de
    "did:web:fa%C3%9F.de",                      # IDNA2003 folds to fass.de
    "did:web:%CE%B1%CF%82.gr",                  # final sigma folds to sigma
    "did:web:%E1%BA%9Eexample.com",             # capital sharp s: lower() gives ss
    "did:web:example.com%EF%B8%93443",          # U+FE13: urlparse NFKC reads a colon
    # An IP address in any form WHATWG reads as one (the last label is a number).
    "did:web:127.0.0.1",
    "did:web:8.8.8.8%3A443",
    "did:web:2130706433",                       # 127.0.0.1 as one decimal number
    "did:web:0x7f.1",                           # hex, shorthand
    "did:web:0177.0.0.1",                       # octal
    "did:web:example.0x",
]


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


def _good_vc_jwt() -> str:
    key, did = _did_key_p256()
    return _vc_jwt(did, key)


# --------------------------------------------------------------------------- #
# Layer 1: did:web / did:webvh reject a malformed host before any fetch
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("did", HOSTILE_DID_WEB)
def test_did_web_url_rejects_hostile_host(did):
    with pytest.raises(DidResolutionError):
        _did_web_url(did)


@pytest.mark.parametrize("did", HOSTILE_DID_WEB)
def test_did_web_resolver_never_calls_the_fetch(did):
    # The caller's own fetch is covered too: it is never handed a malformed URL.
    def _fetch(url):
        raise AssertionError(f"fetch called with {url!r}")
    with pytest.raises(DidResolutionError):
        DidWebResolver(_fetch).resolve(did)


@pytest.mark.parametrize("did,url", [
    ("did:web:example.com", "https://example.com/.well-known/did.json"),
    ("did:web:example.com%3A3000", "https://example.com:3000/.well-known/did.json"),
    ("did:web:example.com%3A65535:a:b", "https://example.com:65535/a/b/did.json"),
    ("did:web:localhost%3A8443", "https://localhost:8443/.well-known/did.json"),
    ("did:web:Sub-1.EXAMPLE.com", "https://Sub-1.EXAMPLE.com/.well-known/did.json"),
    ("did:web:123.example.com", "https://123.example.com/.well-known/did.json"),
    ("did:web:example.x0", "https://example.x0/.well-known/did.json"),
    ("did:web:xn--mnchen-3ya.de", "https://xn--mnchen-3ya.de/.well-known/did.json"),
    ("did:web:" + ".".join(["a" * 63] * 3 + ["a" * 61]),
     "https://" + ".".join(["a" * 63] * 3 + ["a" * 61]) + "/.well-known/did.json"),
])
def test_did_web_url_keeps_valid_hosts(did, url):
    assert _did_web_url(did) == url


@pytest.mark.parametrize("did", [
    "did:webvh:Qm:example.com%3Aabc",           # the reported shape
    "did:webvh:Qm:example.com%3A99999",
    "did:webvh:Qm:%5B",
    "did:webvh:Qm:8.8.8.8%00.x",
])
def test_did_webvh_url_rejects_hostile_host_as_webvh_error(did):
    with pytest.raises(DidWebvhError):
        _did_webvh_url(did)


# --------------------------------------------------------------------------- #
# Layer 2: the SSRF-guarded fetch types every URL it cannot use
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url", [
    "https://example.com:99999/did.json",       # port out of range
    "https://example.com:abc/did.json",         # port not an integer
    "https://[/did.json",                       # unbalanced bracket
    "https://ex℀mple.com/did.json",        # NFKC normalizes into a delimiter
    "https://8.8.8.8\x00.x/did.json",           # NUL: getaddrinfo would truncate it
    "https://exa mple.com/did.json",            # whitespace
    "https://faß.de/did.json",             # Unicode host: IDNA2003 would fetch fass.de
    "https://münchen.de/did.json",         # even a valid IDN: send the xn-- A-label
    "https://" + "a" * 254 + "/did.json",       # over 253 characters
    "https://\u212aexample.com/did.json",       # KELVIN SIGN: lower() makes it ASCII "k"
    "https://example.com/\u00fc/did.json",      # a non-ASCII path cannot be sent either
])
@pytest.mark.parametrize("fetcher", [https_json_fetch, https_text_fetch, https_bytes_fetch])
def test_fetch_rejects_malformed_url_before_dns(no_network, fetcher, url):
    with pytest.raises(UnsafeUrlError):
        fetcher(url)


# --------------------------------------------------------------------------- #
# Bounded work: a huge host is rejected in linear time (#235)
# --------------------------------------------------------------------------- #

# CPython's punycode encoder is quadratic: 50,000 CJK characters took about a minute
# to IDNA-encode, on the event-loop thread for the async resolver. Rejecting on length
# and ASCII first makes it milliseconds; the bound is generous so CI never flakes.
HUGE_HOST = "".join(chr(0x4E00 + i % 20000) for i in range(50_000)) + ".com"


def _assert_fast(call, error):
    start = time.perf_counter()
    with pytest.raises(error):
        call()
    assert time.perf_counter() - start < 2.0


def test_did_web_rejects_a_huge_unicode_host_fast():
    _assert_fast(lambda: _did_web_url("did:web:" + HUGE_HOST), DidResolutionError)


def test_async_did_web_resolver_rejects_a_huge_unicode_host_fast():
    async def _fetch(url):
        raise AssertionError(f"fetch called with {url!r}")
    resolver = AsyncDidWebResolver(_fetch)
    _assert_fast(lambda: asyncio.run(resolver.resolve("did:web:" + HUGE_HOST)),
                 DidResolutionError)


def test_fetch_rejects_combining_marks_fast(no_network):
    # Out-of-order combining marks: CPython <= 3.12 NFKC-sorts them with an insertion
    # sort inside urlparse. 0.5 MB took 25 s there, before any host check ran.
    host = "a" + "\u0301" * 64_000 + "\u0316" * 64_000 + ".com"
    _assert_fast(lambda: https_json_fetch(f"https://{host}/did.json"), UnsafeUrlError)


def test_error_message_is_bounded_for_a_huge_did():
    # The message names the DID through safe_repr, not repr(): a 2 MB DID of control
    # characters used to make a 16 MB error string.
    with pytest.raises(DidResolutionError) as info:
        _did_web_url("did:web:" + "\x01" * 2_000_000)
    assert len(str(info.value)) < 4_000
    with pytest.raises(DidWebvhError) as info:
        _did_webvh_url("did:webvh:Qm:" + "\x01" * 2_000_000)
    assert len(str(info.value)) < 4_000


def test_fetch_rejects_a_huge_unicode_host_fast(no_network):
    _assert_fast(lambda: https_json_fetch(f"https://{HUGE_HOST}/did.json"), UnsafeUrlError)


def test_verify_many_async_isolates_a_huge_unicode_host_fast(no_network):
    batch = [_good_vc_jwt(), _vc_jwt("did:web:" + HUGE_HOST)]
    start = time.perf_counter()
    good, bad = asyncio.run(verify_many_async(batch))
    assert time.perf_counter() - start < 2.0
    assert good.ok is True
    assert isinstance(bad.error, KeyResolutionFailed)


def test_async_fetch_rejects_malformed_url_before_dns(no_network):
    with pytest.raises(UnsafeUrlError):
        asyncio.run(https_json_fetch_async("https://example.com:99999/did.json"))


def test_fetch_types_an_idna_label_too_long():
    # The real getaddrinfo: it IDNA-encodes a str host before the C lookup, and the
    # codec rejects a label over 63 characters, so no DNS query is sent.
    with pytest.raises(UnsafeUrlError, match="cannot resolve") as info:
        https_json_fetch("https://" + "a" * 64 + ".com/did.json")
    assert isinstance(info.value.__cause__, UnicodeError)


def test_https_get_types_a_non_ascii_request_target(no_network):
    # The guarded fetch refuses a non-ASCII URL up front; _https_get still types one:
    # http.client fails to encode the request line, before the TCP connection.
    with pytest.raises(DidResolutionError, match="fetch failed") as info:
        fetch._https_get("example.com", "93.184.216.34", 443, "/\u00fc/did.json",
                         timeout=1.0, max_bytes=10)
    assert isinstance(info.value.__cause__, UnicodeEncodeError)


def test_https_get_types_an_invalid_host_at_construction(no_network):
    # HTTPSConnection rejects a control character in the host as it is built; that
    # now happens inside the try, so it is typed (and conn.close() is not reached).
    with pytest.raises(DidResolutionError, match="fetch failed"):
        fetch._https_get("a\x00b", "93.184.216.34", 443, "/",
                         timeout=1.0, max_bytes=10)


# --------------------------------------------------------------------------- #
# Batch isolation: one hostile issuer is that item's error, the rest verify
# --------------------------------------------------------------------------- #

BATCH_ISSUERS = HOSTILE_DID_WEB[:6] + ["did:webvh:Qm:example.com%3Aabc"]


def test_verify_many_isolates_hostile_did_web_hosts(no_network):
    good = _good_vc_jwt()
    results = verify_many([good] + [_vc_jwt(iss) for iss in BATCH_ISSUERS])
    assert results[0].ok is True
    for result in results[1:]:
        assert result.ok is False
        assert isinstance(result.error, KeyResolutionFailed)


def test_verify_many_async_isolates_hostile_did_web_hosts(no_network):
    good = _good_vc_jwt()
    results = asyncio.run(
        verify_many_async([good] + [_vc_jwt(iss) for iss in BATCH_ISSUERS]))
    assert results[0].ok is True
    for result in results[1:]:
        assert result.ok is False
        assert isinstance(result.error, OpenvcError)


@pytest.mark.parametrize("iss", BATCH_ISSUERS)
def test_verify_credential_async_types_hostile_host(no_network, iss):
    with pytest.raises(OpenvcError):
        asyncio.run(verify_credential_async(_vc_jwt(iss)))


@pytest.mark.parametrize("iss", [
    "https://[",
    "https://example.com:99999",
    "https://ex℀mple.com",
])
def test_https_issuer_lane_types_hostile_host(no_network, iss):
    with pytest.raises(JwtVcIssuerError):
        jwt_vc_issuer_metadata_url(iss)
    results = verify_many([_vc_jwt(iss)], jwt_vc_issuer_fetch=https_json_fetch)
    assert isinstance(results[0].error, KeyResolutionFailed)


def test_status_list_url_with_hostile_host_is_typed(no_network):
    # Status-list URLs are issuer-named too; they share the guarded fetch.
    key, did = _did_key_p256()
    vc = VcJwtProofSuite().sign(
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
         "credentialSubject": {"id": "did:example:holder"},
         "credentialStatus": {
             "type": "BitstringStatusListEntry", "statusPurpose": "revocation",
             "statusListIndex": "0",
             "statusListCredential": "https://example.com:99999/status/1"}},
        signing_key=key)
    results = verify_many(
        [vc, _good_vc_jwt()],
        resolve_status_list=default_status_list_resolver())
    assert isinstance(results[0].error, UnsafeUrlError)
    assert results[1].ok is True


# --------------------------------------------------------------------------- #
# Presentations: the holder key and the cascade
# --------------------------------------------------------------------------- #

def test_vp_jwt_resolver_mode_types_hostile_holder(no_network):
    holder_key = P256SigningKey.generate(kid="did:web:example.com%3A99999#k")
    vp = VpJwtProofSuite().sign([], holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)
    with pytest.raises(OpenvcError):
        VpJwtProofSuite().verify(vp, audience=CLIENT_ID, nonce=NONCE)


def test_vp_jwt_pinned_mode_types_hostile_embedded_issuer(no_network):
    holder_key, _ = _did_key_p256()
    vp = VpJwtProofSuite().sign(
        [_vc_jwt("did:web:%5B")], holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)
    with pytest.raises(OpenvcError):
        VpJwtProofSuite().verify(
            vp, audience=CLIENT_ID, nonce=NONCE,
            holder_key_jwk=holder_key.public_jwk(), resolver=default_resolver())


def test_vp_token_jwt_vc_json_types_hostile_holder_before_signature(no_network):
    # The reported shape: a hostile iss and a broken signature. Resolving the holder
    # key runs first, so it used to raise a bare ValueError before the signature check.
    holder_key = P256SigningKey.generate(kid="did:web:example.com%3A99999#k")
    vp = VpJwtProofSuite().sign(
        [_good_vc_jwt()], holder_key=holder_key, audience=CLIENT_ID, nonce=NONCE)
    head, body, sig = vp.split(".")
    broken = f"{head}.{body}.{'A' * len(sig)}"
    with pytest.raises(OpenvcError):
        verify_vp_token(
            {"q": [broken]}, dcql_query={"credentials": [{"id": "q", "format": "jwt_vc_json"}]},
            nonce=NONCE, client_id=CLIENT_ID)


def test_vp_token_ldp_vc_cascade_types_hostile_issuer(no_network):
    # The VP is soundly signed by a did:key holder; the embedded credential names a
    # hostile did:web verification method, which the cascade must resolve.
    suite = EddsaJcsProofSuite()
    hostile_vm = "did:web:example.com%3A99999#k"
    vc = suite.add_proof(
        {"@context": [V2], "type": ["VerifiableCredential"],
         "issuer": "did:web:example.com%3A99999",
         "credentialSubject": {"id": "did:example:holder"}},
        signing_key=Ed25519SigningKey.generate(kid=hostile_vm),
        verification_method=hostile_vm, proof_purpose="assertionMethod")
    hk = Ed25519SigningKey.generate(kid="_")
    mb = encode_multibase(bytes([0xED, 0x01]) + hk.public_key_raw())
    hdid = f"did:key:{mb}"
    hk = Ed25519SigningKey(hk._sk, kid=f"{hdid}#{mb}")
    vp = suite.add_proof(
        {"@context": [V2], "type": ["VerifiablePresentation"], "holder": hdid,
         "verifiableCredential": [vc]},
        signing_key=hk, verification_method=hk.kid, proof_purpose="authentication",
        challenge=NONCE, domain=CLIENT_ID)
    with pytest.raises(OpenvcError):
        verify_vp_token(
            {"c1": [vp]}, dcql_query={"credentials": [{"id": "c1", "format": "ldp_vc"}]},
            nonce=NONCE, client_id=CLIENT_ID)


# --------------------------------------------------------------------------- #
# x5c: binding a hostile https iss to the leaf SAN
# --------------------------------------------------------------------------- #

def test_x5c_issuer_binding_types_unparseable_iss():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]),
                       critical=False)
        .sign(key, hashes.SHA256()))
    with pytest.raises(X5cError, match="not bound"):
        _check_issuer_binding(leaf, "https://[")
