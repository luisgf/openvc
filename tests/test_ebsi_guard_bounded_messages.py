"""
tests/test_ebsi_guard_bounded_messages.py — the EBSI client never echoes an unbounded URL or
host in an error message (#338).

``EbsiHttpClient._guard_host`` put the offending value straight into its exception message:
``host not in allow-list: {host}`` and ``non-https URL rejected: {url}``. The value is the
caller's, and in practice a remote party's (a DID document, a registry link, a Trusted Nodes
List entry), and the repo's rule is that such a value goes through ``safe_repr`` (cut past 200
characters). On ``main`` at cf6d100, with ``allowed_hosts={"api-pilot.ebsi.eu"}``, a 70 000
character host or URL gave a 70 032 or 70 033 character message. Three siblings in
``get_json`` / ``_request`` echoed the URL of a 200 they refused, unbounded too.

Every message of ``http.py`` that echoed a URL or a host of the caller's unbounded on ``main`` is
pinned here, with the bytes path's messages (controls) and the guard rules that echo nothing
variable (redirects are off, so no ``Location`` is ever formatted):

  * the two ``_guard_host`` rules that echo (non-https, host not in the allow-list), from the
    guard, ``get_json`` and ``get_bytes``;
  * the three ``MalformedRegistryResponse`` messages of ``get_json`` (a 200 that is not JSON, a
    200 that is not an object, a body that does not decode);
  * the messages of ``get_bytes`` that already went through ``safe_repr`` (a body that does not
    decode, a truncated stream, bytes after its end, an unsupported ``Content-Encoding``):
    controls, which pass on ``main`` and must keep passing;
  * the guard rules that echo nothing variable (not visible ASCII, does not parse, port,
    userinfo), so "every guard rule" is a test, not a claim.

What is NOT changed is pinned too: the exception class, the leading words of each message (the
existing ``match=`` assertions), and ``.url``, which keeps the whole URL as given (``None`` for
the userinfo rule): the message is bounded, the data is not. The one class that did change is
a ``str`` subclass whose ``__format__`` raises, which escaped as that error from the four
messages that format the URL and is now the typed refusal (``safe_repr`` reads ``str.__str__``):
pinned too. The address guard's messages (``resolves to blocked address``, ``cannot resolve``,
``did not resolve``) already went through ``safe_repr`` and are not repeated here; the first has
its bound pinned in ``test_ebsi_address_guard.py``. The helpers are self-contained (tests/ is
not a package: no cross-import).
"""
from __future__ import annotations

import gzip
import json
from typing import Any

import pytest

httpx = pytest.importorskip("httpx")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402
from openvc_ebsi.http import EbsiHttpClient, HttpForbiddenHost  # noqa: E402

HOST = "api-pilot.ebsi.eu"
LONG = 70_000
MAX_MESSAGE = 300           # "at most a few hundred characters" (the issue's bound)


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

def _client(handler: Any = None) -> EbsiHttpClient:
    c = EbsiHttpClient(allowed_hosts={HOST})
    if handler is not None:
        c._client = httpx.Client(transport=httpx.MockTransport(handler))
    return c


class _Chunks(httpx.SyncByteStream):
    """A body delivered in the given pieces, as a socket may split it."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def __iter__(self):
        yield from self._chunks


def _answer(status: int = 200, *, body: bytes | list[bytes] = b"",
            headers: dict[str, str] | None = None):
    """A handler that answers every request as a socket would: the body is a stream (``iter_raw``,
    which the bytes path reads, refuses a response built from ``content=``)."""
    def handler(request: httpx.Request) -> httpx.Response:
        stream = _Chunks(body) if isinstance(body, list) else httpx.ByteStream(body)
        return httpx.Response(status, headers=headers, stream=stream)
    return handler


def _refusals(client: EbsiHttpClient, url: str) -> list[HttpForbiddenHost]:
    """The refusal of ``url`` by the guard itself and by the two public paths that reach it."""
    out: list[HttpForbiddenHost] = []
    for call in (client._guard_host, client.get_json, client.get_bytes):
        with pytest.raises(HttpForbiddenHost) as exc_info:
            call(url)
        assert type(exc_info.value) is HttpForbiddenHost
        out.append(exc_info.value)
    return out


# --------------------------------------------------------------------------- #
# The guard: every rule, with a 70 000 character component
# --------------------------------------------------------------------------- #

# (url, the leading words of the message, the start of the value the message still shows)
HOSTILE_HOST = "a" * LONG + ".example"

ECHOING = [
    pytest.param("http://" + "b" * LONG + "/x", "non-https URL rejected: ", "http://" + "b" * 50,
                 id="non-https"),
    pytest.param("ftp://" + "b" * LONG, "non-https URL rejected: ", "ftp://" + "b" * 50,
                 id="non-https-ftp"),
    pytest.param("//" + "b" * LONG + "/x", "non-https URL rejected: ", "//" + "b" * 50,
                 id="scheme-relative"),
    pytest.param("c" * LONG, "non-https URL rejected: ", "c" * 50, id="no-scheme"),
    pytest.param("https://" + HOSTILE_HOST + "/x", "host not in allow-list: ",
                 "'" + "a" * 50, id="other-host"),
    pytest.param("https://" + HOSTILE_HOST + ":443/x", "host not in allow-list: ",
                 "'" + "a" * 50, id="other-host-443"),
    pytest.param("https://" + HOSTILE_HOST + ":8443/x", "host not in allow-list: ",
                 "'" + "a" * 50, id="other-host-8443"),
    pytest.param("https://" + "a" * LONG + "." + HOST + "/x", "host not in allow-list: ",
                 "'" + "a" * 50, id="suffix-of-the-listed-host"),
]


@pytest.mark.parametrize("url,leading,shown", ECHOING)
def test_an_echoing_guard_rule_cuts_the_value(url: str, leading: str, shown: str) -> None:
    c = _client()
    try:
        for exc in _refusals(c, url):
            message = str(exc)
            assert message.startswith(leading)
            assert len(message) < MAX_MESSAGE, len(message)
            assert shown in message                       # the start of the value is still shown
            assert url not in message                     # and the value is not shown whole
            assert exc.url == url                         # the data keeps the whole URL
            assert exc.args == (message,)
    finally:
        c.close()


@pytest.mark.parametrize("url,value", [
    pytest.param("http://" + "b" * LONG + "/x", "http://" + "b" * LONG + "/x", id="non-https"),
    pytest.param("https://" + HOSTILE_HOST + "/x", HOSTILE_HOST, id="other-host"),
])
def test_the_message_says_how_long_the_cut_value_was(url: str, value: str) -> None:
    # A reader of a log line needs to know a value was cut, and by how much.
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert f"{len(value)} chars" in str(exc)
    finally:
        c.close()


SILENT = [
    pytest.param("https://" + HOST + "/" + "é" * LONG, "URL rejected: not visible ASCII",
                 id="not-visible-ascii"),
    pytest.param("https://[" + "a" * LONG, "URL rejected: does not parse", id="does-not-parse"),
    pytest.param("https://" + HOST + ":8443/" + "p" * LONG, "port 8443 not allowed",
                 id="port"),
    pytest.param("https://" + HOST + ":0/" + "p" * LONG, "port 0 not allowed", id="port-zero"),
    pytest.param("https://user:" + "s" * LONG + "@" + HOST + "/x",
                 "URL rejected: carries userinfo", id="userinfo"),
]


@pytest.mark.parametrize("url,message", SILENT)
def test_the_other_guard_rules_name_the_rule_and_echo_no_part_of_the_url(
        url: str, message: str) -> None:
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert message in str(exc)
            assert len(str(exc)) < MAX_MESSAGE
            assert "ssssssssss" not in str(exc) and "pppppppppp" not in str(exc)
    finally:
        c.close()


def test_the_userinfo_refusal_still_carries_no_url() -> None:
    # Unchanged by #338, pinned beside the rules it must keep company with: the one refusal whose
    # `.url` is None, so a secret in the URL is nowhere on the exception.
    c = _client()
    try:
        for exc in _refusals(c, "https://user:" + "s" * LONG + "@" + HOST + "/x"):
            assert exc.url is None and exc.args == ("URL rejected: carries userinfo",)
    finally:
        c.close()


def test_a_short_value_is_shown_whole_as_a_quoted_string() -> None:
    # The format of the message for a value that fits: the repr, quoted, as the neighbouring
    # `safe_repr` messages of this module show theirs. The leading words are unchanged.
    c = _client()
    try:
        for exc in _refusals(c, "https://evil.example/x"):
            assert str(exc) == "host not in allow-list: 'evil.example'"
        for exc in _refusals(c, f"http://{HOST}/x"):
            assert str(exc) == f"non-https URL rejected: 'http://{HOST}/x'"
    finally:
        c.close()


@pytest.mark.parametrize("url", [
    pytest.param("https:///x", id="empty-authority"),
    pytest.param("https://:443/x", id="port-only"),
    pytest.param("https:" + HOST + "/x", id="no-slashes"),
    pytest.param("https:///" + "q" * LONG, id="empty-authority-long-path"),
])
def test_a_url_that_names_no_host_still_says_none(url: str) -> None:
    # `host or None`: the empty host is shown as `None`, not as `''`.
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert str(exc) == "host not in allow-list: None"
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# get_json: the three refusals of a 200 that name the URL
# --------------------------------------------------------------------------- #

# Under httpx's 64 KiB URL limit (a longer URL is `httpx.InvalidURL`, a fixed message), and
# still two orders of magnitude over what a message may hold.
PATH = "a" * 50_000
URL = f"https://{HOST}/{PATH}"

GET_JSON_REFUSALS = [
    pytest.param(_answer(body=b"<html>not json</html>"),
                 "registry returned a 200 with a non-JSON body: ", id="not-json"),
    pytest.param(_answer(body=json.dumps([1, 2]).encode()),
                 "registry returned a 200 that is not a JSON object: ", id="array"),
    pytest.param(_answer(body=b"null"),
                 "registry returned a 200 that is not a JSON object: ", id="null"),
    # Since #335 the 200 path decodes with the bounded decoder the bytes path uses, so a body
    # that does not decode is reported in that decoder's words.
    pytest.param(_answer(body=b"this is not gzip", headers={"Content-Encoding": "gzip"}),
                 "response body does not decode: ", id="does-not-decode"),
]


@pytest.mark.parametrize("handler,leading", GET_JSON_REFUSALS)
def test_a_refused_200_cuts_the_url_in_its_message(handler: Any, leading: str) -> None:
    c = _client(handler)
    try:
        with pytest.raises(MalformedRegistryResponse) as exc_info:
            c.get_json(URL)
        exc = exc_info.value
        assert type(exc) is MalformedRegistryResponse
        message = str(exc)
        assert message.startswith(leading)
        assert len(message) < MAX_MESSAGE, len(message)
        assert URL not in message and "a" * 50 in message
        assert f"{len(URL)} chars" in message         # how long the cut URL was
    finally:
        c.close()


def test_a_refused_200_with_a_short_url_shows_it_whole_and_quoted() -> None:
    c = _client(_answer(body=b"not json"))
    try:
        with pytest.raises(MalformedRegistryResponse) as exc_info:
            c.get_json(f"https://{HOST}/x")
        assert str(exc_info.value) == (
            f"registry returned a 200 with a non-JSON body: 'https://{HOST}/x'")
    finally:
        c.close()


def test_a_refused_200_is_not_cached() -> None:
    # The message is the only thing that changed: a refusal still caches nothing.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=b"[1]")
    c = _client(handler)
    try:
        for _ in range(2):
            with pytest.raises(MalformedRegistryResponse):
                c.get_json(f"https://{HOST}/x")
        assert len(calls) == 2
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# get_bytes: the messages that already went through safe_repr (controls)
# --------------------------------------------------------------------------- #

GET_BYTES_REFUSALS = [
    pytest.param([gzip.compress(b"hello"), b"x"], "gzip",
                 "response has bytes after the end of its compressed stream: ",
                 id="bytes-in-a-later-chunk"),
    pytest.param(gzip.compress(b"hello")[:-3], "gzip",
                 "response body is a truncated compressed stream: ", id="truncated"),
    pytest.param(b"this is not gzip", "gzip", "response body does not decode: ",
                 id="does-not-decode"),
    pytest.param(gzip.compress(b"hello") + b"x", "gzip",
                 "response has bytes after the end of its compressed stream: ",
                 id="bytes-after-the-end"),
]


@pytest.mark.parametrize("wire,coding,leading", GET_BYTES_REFUSALS)
def test_the_bytes_path_messages_are_bounded_as_well(
        wire: bytes | list[bytes], coding: str, leading: str) -> None:
    c = _client(_answer(body=wire, headers={"Content-Encoding": coding}))
    try:
        with pytest.raises(MalformedRegistryResponse) as exc_info:
            c.get_bytes(URL)
        message = str(exc_info.value)
        assert message.startswith(leading)
        assert len(message) < MAX_MESSAGE, len(message)
        assert URL not in message
    finally:
        c.close()


def test_the_unsupported_encoding_message_is_bounded_as_well() -> None:
    from openvc_ebsi.http import HttpUnexpectedEncoding
    c = _client(_answer(body=b"x", headers={"Content-Encoding": "x" * LONG}))
    try:
        with pytest.raises(HttpUnexpectedEncoding) as exc_info:
            c.get_bytes(f"https://{HOST}/x")
        assert str(exc_info.value).startswith("unsupported Content-Encoding ")
        assert len(str(exc_info.value)) < MAX_MESSAGE
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# A str subclass: the one case where the class of the exception changed
# --------------------------------------------------------------------------- #

class _RaisesOnFormat(str):
    """A URL whose own ``__format__`` and ``__repr__`` raise: ``f"{url}"`` raised that error
    out of the four messages that format the URL, before #338."""

    def __format__(self, spec: str) -> str:
        raise RuntimeError("format")

    def __repr__(self) -> str:
        raise RuntimeError("repr")


class _LongOnFormat(str):
    """A URL whose own ``__format__`` returns 100 000 characters: ``f"{url}"`` put them all in
    the message before #338."""

    def __format__(self, spec: str) -> str:
        return "x" * 100_000


# (the host rule is not here: `host` is read out of the URL by `urlparse` as a plain `str`, so a
# subclass's methods were never consulted for it)
SUBCLASS_REFUSALS = [
    pytest.param(f"http://{HOST}/x", None, HttpForbiddenHost,
                 "non-https URL rejected: ", id="non-https"),
    pytest.param(f"https://{HOST}/x", _answer(body=b"<html>not json</html>"),
                 MalformedRegistryResponse,
                 "registry returned a 200 with a non-JSON body: ", id="not-json"),
    pytest.param(f"https://{HOST}/x", _answer(body=b"[1]"), MalformedRegistryResponse,
                 "registry returned a 200 that is not a JSON object: ", id="not-an-object"),
    pytest.param(f"https://{HOST}/x",
                 _answer(body=b"this is not gzip", headers={"Content-Encoding": "gzip"}),
                 MalformedRegistryResponse,
                 "response body does not decode: ", id="does-not-decode"),   # since #335
]


@pytest.mark.parametrize("kind", [_RaisesOnFormat, _LongOnFormat])
@pytest.mark.parametrize("url,handler,error,leading", SUBCLASS_REFUSALS)
def test_a_str_subclass_url_is_read_as_the_characters_it_holds(
        kind: type, url: str, handler: Any, error: type, leading: str) -> None:
    # `safe_repr` reads `str.__str__`, never the subclass's methods, so what the subclass
    # overrides can neither raise out of the message nor lengthen it. On `main` the first
    # escaped as a bare RuntimeError and the second put 100 000 characters in the message.
    c = _client(handler)
    try:
        with pytest.raises(error) as exc_info:
            c.get_json(kind(url))
        assert type(exc_info.value) is error
        message = str(exc_info.value)
        assert message == f"{leading}{url!r}"
        assert len(message) < MAX_MESSAGE
    finally:
        c.close()


@pytest.mark.parametrize("kind", [_RaisesOnFormat, _LongOnFormat])
def test_a_str_subclass_url_is_refused_by_the_guard_itself_and_by_get_bytes(kind: type) -> None:
    c = _client()
    try:
        for exc in _refusals(c, kind(f"http://{HOST}/x")):
            assert str(exc) == f"non-https URL rejected: 'http://{HOST}/x'"
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# Property: no refusal of the guard is longer than a few hundred characters
# --------------------------------------------------------------------------- #

_PREFIXES = ["https://", "http://", "ftp://", "//", "", "https:", f"https://{HOST}",
             f"https://{HOST}:", "https://[", "https://u@", f"https://{HOST}.", "HTTPS://"]
_VISIBLE = st.characters(min_codepoint=0x21, max_codepoint=0x7E)


@settings(max_examples=300, deadline=None)
@given(prefix=st.sampled_from(_PREFIXES),
       rest=st.text(alphabet=_VISIBLE, max_size=3_000),
       repeat=st.integers(min_value=1, max_value=40))
def test_property_a_guard_refusal_is_never_longer_than_a_few_hundred_characters(
        prefix: str, rest: str, repeat: int) -> None:
    url = prefix + rest * repeat
    c = EbsiHttpClient(allowed_hosts={HOST})
    try:
        try:
            c._guard_host(url)
        except HttpForbiddenHost as exc:
            assert type(exc) is HttpForbiddenHost
            # 200 shown characters, every one escaped at worst (`\` -> `\\`), plus the fixed words
            assert len(str(exc)) < 500, (len(str(exc)), url[:60])
    finally:
        c.close()
