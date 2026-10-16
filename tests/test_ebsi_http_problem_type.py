"""
tests/test_ebsi_http_problem_type.py — RFC 9457 Problem Details ``type`` on ``HttpError`` (#321).

EBSI Core API v1 answers errors as Problem Details (``application/problem+json``) with a stable
``type`` (``urn:ebsi:problems:<slug>``, or ``about:blank`` on some answers: the recorded 406
carries it). ``HttpError.problem_type`` hands that string to the caller, opaque: ``http.py``
does not know the vocabulary. The same change replaces the drain of a non-200 body
(``resp.read()``: no size cap, no deadline) with a bounded read, because a hostile or flaky
allow-listed host could send an unbounded or dripping error body, and a node's firewall
answers a refused client with a 35 KB ``text/html`` page.

Negatives first. Every case asserts the EXACT exception class and that the status error was
still raised with unchanged messages: a body that cannot be used never replaces the error it
came with. Offline, over ``httpx.MockTransport``; the one test that needs a real socket (a
dropped connection is not observable through a mock) talks to a throwaway local TLS server on
127.0.0.1. The recorded bodies come from ``tests/fixtures/ebsi/core-v1/errors/``; 405 is not
recorded (it needs a non-GET), so its body below is SYNTHETIC and says so.
Self-contained: ``tests/`` is not a package.
"""
from __future__ import annotations

import datetime
import http.server
import json
import ssl
import threading
from pathlib import Path
from typing import Any, Iterator

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

httpx = pytest.importorskip("httpx")

from openvc_ebsi import http as ebsi_http  # noqa: E402
from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    MAX_ERROR_BODY_BYTES,
    EbsiHttpClient,
    HttpError,
    HttpForbiddenHost,
    HttpNotFound,
    HttpTransientExhausted,
    RetryPolicy,
    _problem_type,
)

HOST = "api-preprod.ebsi.grnet.gr"
URL = f"https://{HOST}/v1/did-registry/identifiers/did:ebsi:zmaEptEHQRAmkJnFV6ki3io"
FAST_RETRY = RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)
PROBLEM = "application/problem+json"
ERRORS = Path(__file__).parent / "fixtures" / "ebsi" / "core-v1" / "errors"
MANIFEST = json.loads((ERRORS.parent / "MANIFEST.json").read_bytes())["files"]


def _client(handler: Any, **kwargs: Any) -> EbsiHttpClient:
    c = EbsiHttpClient(allowed_hosts={HOST}, retry=FAST_RETRY, **kwargs)
    c._client = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def _answer(status: int, body: bytes, content_type: str | None = PROBLEM) -> Any:
    headers = {} if content_type is None else {"content-type": content_type}
    return lambda request: httpx.Response(status, content=body, headers=headers)


def _error(status: int, body: bytes, content_type: str | None = PROBLEM) -> HttpError:
    """The error ``get_json`` raises for this answer."""
    with pytest.raises(HttpError) as exc:
        _client(_answer(status, body, content_type)).get_json(URL)
    return exc.value


def _recorded(name: str) -> tuple[int, bytes, str]:
    rel = f"errors/{name}"
    entry = MANIFEST[rel]
    return entry["status"], (ERRORS / name).read_bytes(), entry["content_type"]


# --------------------------------------------------------------------------- #
# The recorded answers
# --------------------------------------------------------------------------- #

def test_the_recorded_error_answers_are_problem_json():
    for name in ("pilot-grnet_404_identifier-not-found.json",
                 "preprod-grnet_400_invalid-contract-address.json",
                 "preprod-grnet_406_unsatisfiable-accept.json"):
        status, body, content_type = _recorded(name)
        assert content_type.split(";")[0] == PROBLEM          # the gate matches what nodes send
        assert json.loads(body)["status"] == status


def test_404_is_not_found_and_carries_the_recorded_type():
    status, body, content_type = _recorded("pilot-grnet_404_identifier-not-found.json")
    err = _error(status, body, content_type)
    assert type(err) is HttpNotFound
    assert err.problem_type == "urn:ebsi:problems:identifier-not-found"
    assert (err.status, err.url, str(err)) == (404, URL, "not found")


def test_400_is_an_http_error_and_carries_the_recorded_type():
    status, body, content_type = _recorded("preprod-grnet_400_invalid-contract-address.json")
    err = _error(status, body, content_type)
    assert type(err) is HttpError
    assert err.problem_type == "urn:ebsi:problems:invalid-contract-address"
    assert (err.status, err.url, str(err)) == (400, URL, "unexpected status 400")


def test_406_is_an_http_error_and_its_recorded_type_is_about_blank():
    # not every Core v1 error has a `urn:ebsi:problems:` slug: this one says `about:blank`
    status, body, content_type = _recorded("preprod-grnet_406_unsatisfiable-accept.json")
    err = _error(status, body, content_type)
    assert type(err) is HttpError
    assert err.problem_type == "about:blank"
    assert (err.status, str(err)) == (406, "unexpected status 406")


def test_405_is_an_http_error_over_a_synthetic_body():
    # SYNTHETIC: 405 is not recorded (it needs a non-GET request to a read path; README of the
    # fixtures). The body only has the Problem Details shape; the type is not a real slug.
    body = json.dumps({"status": 405, "title": "Method Not Allowed",
                       "type": "urn:example:synthetic-405"}).encode()
    err = _error(405, body)
    assert type(err) is HttpError
    assert err.problem_type == "urn:example:synthetic-405"
    assert str(err) == "unexpected status 405"


def test_the_legacy_about_blank_body_is_read_as_about_blank():
    # The v5 body is recorded (tests/fixtures/ebsi/tir_v5_issuer_404_problem.json) but its media
    # type is not, so it is served here under the type the Core v1 nodes use.
    body = (ERRORS.parent.parent / "tir_v5_issuer_404_problem.json").read_bytes()
    err = _error(404, body)
    assert type(err) is HttpNotFound
    assert err.problem_type == "about:blank"


def test_a_plain_error_has_no_problem_type():
    err = _error(403, b"", content_type=None)
    assert type(err) is HttpError and err.problem_type is None
    assert HttpError("m").problem_type is None
    assert HttpForbiddenHost("m", url=URL).problem_type is None
    assert HttpError("m", status=1, url="u").status == 1                    # existing call shape


# --------------------------------------------------------------------------- #
# The gate: only application/problem+json
# --------------------------------------------------------------------------- #

JSON_LOOKALIKE = b'{"type": "urn:ebsi:problems:identifier-not-found", "status": 403}'


def test_a_firewall_html_page_is_never_read_as_problem_details():
    # ADR-0009: a node's WAF answers a refused client with a 35 KB text/html 403
    err = _error(403, JSON_LOOKALIKE, "text/html; charset=utf-8")
    assert type(err) is HttpError and err.problem_type is None
    assert str(err) == "unexpected status 403"
    page = b"<html><body>Web Application Firewall " + b"x" * 35_000 + b"</body></html>"
    err = _error(403, page, "text/html")
    assert type(err) is HttpError and err.problem_type is None


@pytest.mark.parametrize("content_type", [
    None, "", "application/json", "application/json; charset=utf-8", "text/html",
    "text/plain", "application/problem+xml", "application/problem+jsonx",
    "application/problem+json, text/html", "text/html, application/problem+json",
    "application/x-problem+json", "problem+json", "application/problem json",
    "application/problem+js"])
def test_any_other_media_type_gives_no_problem_type(content_type):
    err = _error(400, JSON_LOOKALIKE, content_type)
    assert type(err) is HttpError and err.problem_type is None
    assert err.status == 400 and str(err) == "unexpected status 400"


@pytest.mark.parametrize("content_type", [
    "application/problem+json", "application/problem+json; charset=utf-8",
    "APPLICATION/Problem+JSON", "application/problem+json ; charset=UTF-8",
    "application/problem+json;charset=utf-8", " application/problem+json"])
def test_the_problem_media_type_is_matched_without_parameters_and_case(content_type):
    err = _error(400, JSON_LOOKALIKE, content_type)
    assert err.problem_type == "urn:ebsi:problems:identifier-not-found"


# --------------------------------------------------------------------------- #
# The value: a short visible-ASCII string, else None
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [5, 1.5, True, False, None, [], ["urn:x"], {}, {"a": "b"}])
def test_a_non_string_type_gives_none(value):
    err = _error(400, json.dumps({"type": value}).encode())
    assert type(err) is HttpError and err.problem_type is None


@pytest.mark.parametrize("value", [
    "", "a" * 257, "urn:" + "a" * 300, "urn:café", "urn:١", "urn:‮", "​urn:x",
    "urn:a\x00b", "urn:a\nb", "urn:a\tb", "urn:a\rb", "urn:a\x7fb", "urn:a\x1fb", "urn: x",
    " urn:x", "urn:x ", "urn:a b", "urn:a b", "urn:a\ud800b"])
def test_a_type_that_is_empty_too_long_non_ascii_or_not_visible_gives_none(value):
    # json.dumps writes the control characters and the lone surrogate as \u escapes
    err = _error(400, json.dumps({"type": value}).encode())
    assert type(err) is HttpError and err.problem_type is None
    assert str(err) == "unexpected status 400"


@pytest.mark.parametrize("value", [
    "about:blank", "urn:ebsi:problems:identifier-not-found", "a", "a" * 256,
    "https://example.net/probs/out-of-credit", "urn:x:" + "".join(chr(c) for c in range(0x21, 0x7f)
                                                                  if chr(c) not in '"\\')])
def test_a_visible_ascii_type_up_to_256_characters_is_kept_verbatim(value):
    assert _error(400, json.dumps({"type": value}).encode()).problem_type == value


def test_an_absent_type_is_none_and_title_and_detail_are_never_read():
    body = json.dumps({"title": "urn:ebsi:problems:from-title", "detail": "urn:x:from-detail",
                       "status": 400}).encode()
    err = _error(400, body)
    assert err.problem_type is None
    assert "from-title" not in str(err) and "from-detail" not in str(err)
    assert not any(hasattr(err, name) for name in ("title", "detail"))


# --------------------------------------------------------------------------- #
# A body it cannot use never replaces the status error
# --------------------------------------------------------------------------- #

def _deep(depth: int) -> bytes:
    return b'{"type": "urn:ok", "x": ' + b'{"x": ' * depth + b"1" + b"}" * depth + b"}"


UNUSABLE_BODIES = [
    pytest.param(b"", id="empty"),
    pytest.param(b"{", id="truncated"),
    pytest.param(b'{"type": "urn:ebsi:problems:x"', id="truncated-after-type"),
    pytest.param(b'{"type": "urn:ebsi:problems:x"} trailing', id="trailing-bytes"),
    pytest.param(b"not json at all", id="not-json"),
    pytest.param(b"\xff\xfe\x00{", id="not-utf8"),
    pytest.param(b"[]", id="array"),
    pytest.param(b'[{"type": "urn:x"}]', id="array-of-objects"),
    pytest.param(b"null", id="null"),
    pytest.param(b'"urn:x"', id="string"),
    pytest.param(b"7", id="number"),
    pytest.param(_deep(150), id="over-deep"),
    pytest.param(b"[" * 5000 + b"]" * 5000, id="deeper-than-the-interpreter-parses"),
    pytest.param(b'{"type": "urn:ok", "pad": "' + b"a" * (MAX_ERROR_BODY_BYTES + 100) + b'"}',
                 id="over-the-cap"),
    pytest.param(b'{"type": "urn:ok", "pad": "\\ud800"}', id="lone-surrogate-escape-is-fine"),
]


@pytest.mark.parametrize("body", UNUSABLE_BODIES)
def test_an_unusable_body_leaves_the_status_error_unchanged(body):
    err = _error(400, body)
    assert type(err) is HttpError and (err.status, str(err)) == (400, "unexpected status 400")
    if body.startswith(b'{"type": "urn:ok", "pad": "\\ud800"'):
        assert err.problem_type == "urn:ok"                     # the one usable control
    else:
        assert err.problem_type is None
    err = _error(404, body)
    assert type(err) is HttpNotFound and (err.status, str(err)) == (404, "not found")


def test_the_depth_bound_is_the_loaders_not_the_standard_librarys():
    # the same body parses with json.loads, so only openvc._json.loads can have refused it
    assert json.loads(_deep(150))["type"] == "urn:ok"
    assert _error(400, _deep(150)).problem_type is None
    assert _error(400, _deep(50)).problem_type == "urn:ok"


def test_a_body_at_the_cap_is_still_read():
    pad = MAX_ERROR_BODY_BYTES - len(b'{"type":"urn:ok","p":""}')
    body = b'{"type":"urn:ok","p":"' + b"a" * pad + b'"}'
    assert len(body) == MAX_ERROR_BODY_BYTES
    assert _error(400, body).problem_type == "urn:ok"
    assert _error(400, body + b" ").problem_type is None            # one byte more


# --------------------------------------------------------------------------- #
# The read is bounded
# --------------------------------------------------------------------------- #

class _Stream(httpx.SyncByteStream):
    """A response body of `total` bytes in `chunk`-sized pieces, counting what is pulled."""

    def __init__(self, total: int, chunk: int = 64 * 1024) -> None:
        self.total, self.chunk = total, chunk
        self.pulled = 0
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        while self.pulled < self.total:
            piece = min(self.chunk, self.total - self.pulled)
            self.pulled += piece
            yield b"a" * piece

    def close(self) -> None:
        self.closed = True


def test_a_10_mib_error_body_is_read_only_up_to_the_cap_and_closed():
    stream = _Stream(10 * 1024 * 1024)
    c = _client(lambda request: httpx.Response(
        400, headers={"content-type": PROBLEM}, stream=stream))
    with pytest.raises(HttpError) as exc:
        c.get_json(URL)
    assert type(exc.value) is HttpError
    assert (exc.value.status, str(exc.value), exc.value.problem_type) == (
        400, "unexpected status 400", None)
    # the cap, plus the chunk that crossed it: nowhere near the 10 MiB
    assert MAX_ERROR_BODY_BYTES < stream.pulled <= MAX_ERROR_BODY_BYTES + stream.chunk
    assert stream.closed                                    # the response was closed, not drained


def test_a_small_error_body_is_read_to_the_end():
    stream = _Stream(2_000)
    c = _client(lambda request: httpx.Response(
        400, headers={"content-type": "text/html"}, stream=stream))
    with pytest.raises(HttpError):
        c.get_json(URL)
    assert stream.pulled == 2_000 and stream.closed         # drained (the connection is reusable)


def test_a_transient_status_with_an_oversized_body_is_still_retried_and_exhausted():
    streams = [_Stream(1024 * 1024) for _ in range(3)]
    answers = iter(streams)
    c = _client(lambda request: httpx.Response(
        503, headers={"content-type": PROBLEM}, stream=next(answers)))
    with pytest.raises(HttpTransientExhausted) as exc:
        c.get_json(URL)
    assert type(exc.value) is HttpTransientExhausted
    assert str(exc.value) == "gave up after 3 attempts: transient"
    assert all(s.pulled <= MAX_ERROR_BODY_BYTES + s.chunk and s.closed for s in streams)


def test_a_dripping_error_body_is_given_up_at_the_deadline(monkeypatch):
    clock = iter(float(n) * 100 for n in range(1000))               # 100 s per reading
    monkeypatch.setattr(ebsi_http.time, "monotonic", lambda: next(clock))
    stream = _Stream(1024, chunk=1)                                 # one byte at a time
    c = _client(lambda request: httpx.Response(
        400, headers={"content-type": PROBLEM}, stream=stream), timeout_s=10.0)
    with pytest.raises(HttpError) as exc:
        c.get_json(URL)
    assert type(exc.value) is HttpError and exc.value.problem_type is None
    assert str(exc.value) == "unexpected status 400"
    assert stream.pulled < 5 and stream.closed                      # stopped at the first chunk


# --------------------------------------------------------------------------- #
# What the retry and decode handling still do (#248, ADR-0001)
# --------------------------------------------------------------------------- #

def test_404_is_terminal_and_a_5xx_is_retried_whatever_the_body_says():
    calls = {"n": 0}

    def handler(request: Any) -> Any:
        calls["n"] += 1
        return httpx.Response(404, content=b'{"type": "urn:ebsi:problems:identifier-not-found"}',
                              headers={"content-type": PROBLEM})

    with pytest.raises(HttpNotFound):
        _client(handler).get_json(URL)
    assert calls["n"] == 1
    calls["n"] = 0

    def handler5(request: Any) -> Any:
        calls["n"] += 1
        return httpx.Response(500, content=b'{"type": "urn:ebsi:problems:internal"}',
                              headers={"content-type": PROBLEM})

    with pytest.raises(HttpTransientExhausted) as exc:
        _client(handler5).get_json(URL)
    assert calls["n"] == 3 and type(exc.value) is HttpTransientExhausted
    assert exc.value.problem_type == "urn:ebsi:problems:internal"   # the last attempt's


def test_a_retried_status_that_recovers_returns_the_body():
    answers = iter([httpx.Response(429, content=b'{"type": "urn:x"}',
                                   headers={"content-type": PROBLEM, "Retry-After": "0"}),
                    httpx.Response(200, json={"ok": True})])
    assert _client(lambda request: next(answers)).get_json(URL) == {"ok": True}


@pytest.mark.parametrize("status", [400, 404, 500])
def test_a_corrupt_compressed_problem_body_is_still_a_typed_error(status):
    c = _client(lambda request: httpx.Response(
        status, headers={"content-type": PROBLEM, "content-encoding": "gzip"},
        stream=httpx.ByteStream(b'{"type": "urn:x"}')))             # not gzip
    with pytest.raises(MalformedRegistryResponse) as exc:
        c.get_json(URL)
    assert type(exc.value) is MalformedRegistryResponse
    assert isinstance(exc.value.__cause__, httpx.DecodingError)


def test_a_compressed_problem_body_is_decoded_and_read():
    import gzip
    body = gzip.compress(b'{"type": "urn:ebsi:problems:identifier-not-found"}')
    c = _client(lambda request: httpx.Response(
        404, headers={"content-type": PROBLEM, "content-encoding": "gzip"},
        stream=httpx.ByteStream(body)))
    with pytest.raises(HttpNotFound) as exc:
        c.get_json(URL)
    assert exc.value.problem_type == "urn:ebsi:problems:identifier-not-found"


def test_a_compression_bomb_is_bounded_by_the_decoded_size():
    import gzip
    bomb = gzip.compress(b'{"type": "urn:ok", "pad": "' + b"a" * (50 * 1024 * 1024) + b'"}')
    assert len(bomb) < 200_000
    c = _client(lambda request: httpx.Response(
        400, headers={"content-type": PROBLEM, "content-encoding": "gzip"},
        stream=httpx.ByteStream(bomb)))
    with pytest.raises(HttpError) as exc:
        c.get_json(URL)
    assert type(exc.value) is HttpError and exc.value.problem_type is None


def test_an_error_answer_is_never_cached():
    calls = {"n": 0}

    def handler(request: Any) -> Any:
        calls["n"] += 1
        return httpx.Response(400, content=b'{"type": "urn:x"}', headers={"content-type": PROBLEM})

    c = _client(handler)
    for _ in range(2):
        with pytest.raises(HttpError):
            c.get_json(URL)
    assert calls["n"] == 2


# --------------------------------------------------------------------------- #
# A dropped connection is not observable through a mock: one test against a real socket
# --------------------------------------------------------------------------- #

class _TlsServer:
    """A throwaway HTTPS server on 127.0.0.1 that counts the connections it accepts.
    ``/big`` is a 400 problem+json with a 10 MiB body, ``/small`` a 400 with a small one."""

    BIG = 10 * 1024 * 1024

    def __init__(self, tmp_path: Path) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .sign(key, hashes.SHA256()))
        certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.connections = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                outer.connections += 1
                super().setup()

            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                if self.path == "/big":
                    body_len, chunk = outer.BIG, b"a" * 65536
                else:
                    body_len, chunk = 17, b'{"type": "urn:t"}\n'[:17]
                self.send_response(400)
                self.send_header("Content-Type", PROBLEM)
                self.send_header("Content-Length", str(body_len))
                self.end_headers()
                sent = 0
                try:
                    while sent < body_len:
                        piece = chunk[: body_len - sent]
                        self.wfile.write(piece)
                        sent += len(piece)
                except OSError:                       # the client dropped the connection
                    self.close_connection = True

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certfile), str(keyfile))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_TlsServer":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def test_an_oversized_error_body_drops_the_connection_and_a_small_one_keeps_it(
        tmp_path, monkeypatch):
    # The origin guard admits port 443 only (#318) and this server listens on an ephemeral port;
    # the guard is not what this test is about (tests/test_ebsi_guard_origin.py pins it).
    monkeypatch.setattr(EbsiHttpClient, "_guard_host", lambda self, url: None)
    with _TlsServer(tmp_path) as server:
        client = EbsiHttpClient(allowed_hosts={"127.0.0.1"}, verify_tls=False, retry=FAST_RETRY,
                                timeout_s=10.0)
        base = f"https://127.0.0.1:{server.port}"
        try:
            with pytest.raises(HttpError) as big:
                client.get_json(f"{base}/big")
            assert big.value.status == 400 and big.value.problem_type is None
            assert server.connections == 1
            with pytest.raises(HttpError) as small:         # the dropped connection is not reused
                client.get_json(f"{base}/small")
            assert small.value.status == 400
            assert server.connections == 2
            with pytest.raises(HttpError):                  # a body read to the end is
                client.get_json(f"{base}/small")
            assert server.connections == 2
        finally:
            client.close()


# --------------------------------------------------------------------------- #
# Fuzzing: arbitrary bytes and content types
# --------------------------------------------------------------------------- #

_CT_CHARS = st.characters(min_codepoint=0x20, max_codepoint=0x7e)
_content_type = st.one_of(
    st.none(),
    st.sampled_from([PROBLEM, f"{PROBLEM}; charset=utf-8", "application/json", "text/html"]),
    st.text(_CT_CHARS, max_size=60),
    st.text(_CT_CHARS, max_size=20).map(lambda tail: f"{PROBLEM};{tail}"))
_json_bytes = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=300),
    lambda kids: (st.lists(kids, max_size=3)
                  | st.dictionaries(st.text(max_size=6), kids, max_size=3)),
    max_leaves=8).map(lambda v: json.dumps(v).encode())
_typed_bytes = st.one_of(st.text(max_size=400), st.just("urn:x")).map(
    lambda t: json.dumps({"type": t}).encode())
_body = st.one_of(st.binary(max_size=2000), _json_bytes, _typed_bytes)


def _assert_short_visible_ascii_or_none(value: object) -> None:
    assert value is None or (
        isinstance(value, str) and 1 <= len(value) <= 256
        and all(0x21 <= ord(ch) <= 0x7e for ch in value))


@settings(max_examples=500, deadline=None)
@given(_content_type, _body)
def test_the_pure_reader_never_raises_and_returns_none_or_a_short_visible_string(ct, body):
    _assert_short_visible_ascii_or_none(_problem_type(ct, body))


@settings(max_examples=250, deadline=None)
@given(st.sampled_from([400, 401, 403, 404, 405, 406, 410, 418, 422]), _content_type, _body)
def test_get_json_raises_only_the_http_error_family_for_any_error_body(status, ct, body):
    headers = {} if ct is None else {"content-type": ct}
    c = _client(lambda request: httpx.Response(status, content=body, headers=headers))
    with pytest.raises(HttpError) as exc:
        c.get_json(URL)
    assert type(exc.value) is (HttpNotFound if status == 404 else HttpError)
    assert exc.value.status == status
    assert str(exc.value) == ("not found" if status == 404 else f"unexpected status {status}")
    _assert_short_visible_ascii_or_none(exc.value.problem_type)
