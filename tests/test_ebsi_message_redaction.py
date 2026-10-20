"""
tests/test_ebsi_message_redaction.py — an EBSI error message withholds the userinfo of the URL it
shows, and bounds the other text of the caller or the wire it echoes (#351).

``EbsiHttpClient._guard_host`` quoted the URL in its ``non-https URL rejected`` message exactly as
given, so ``http://user:s3cret@api-pilot.ebsi.eu/x`` put ``s3cret`` in the message, and so in
every log line that formats the exception. On ``main`` at 3bd9e59 (``allowed_hosts=
{"api-pilot.ebsi.eu"}``) the leak had more doors than that one rule:

  * ``NodeSession.get_json`` (``URL is not on this session's node``), the node client's
    ``not a node of this client's list`` and ``the node policy named a node ...`` messages, and
    the Trusted Nodes List's ``is not a bare https origin`` quoted a URL as given;
  * ``urlparse``'s own ``ValueError``, chained as ``__cause__`` of the ``does not parse``
    refusal, quotes the part of the URL it could not read, and a URL written
    ``user:s3cret%40api-pilot.ebsi.eu`` has its password in the PORT slot: the cause read
    ``Port could not be cast to integer value as 's3cret%40api-pilot.ebsi.eu'`` (70 000 characters
    of it for a port that long);
  * ``HttpTransientExhausted`` formatted the last transport error's own text, whatever its
    length (16 000 characters in, 16 000 out), and ``verify.py`` repeated the credential's type
    list (70 000 characters in, 70 107 out), its issuer and its ``id`` unbounded.

What is NOT changed is pinned too: the exception classes, the leading words of each message (the
existing ``match=`` assertions), and ``.url``, which keeps the whole URL as given (``None`` for
the userinfo rule) as #343 recorded: the caller who passed the URL already holds its password, the
message is what reaches a log. So no assertion here reads ``.url`` for a secret; every one reads
``str()``, ``repr()``, ``.args``, ``__notes__`` and the ``__cause__`` / ``__context__`` chain.

Helpers are self-contained (tests/ is not a package: no cross-import).
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

httpx = pytest.importorskip("httpx")

from openvc.keys import P256SigningKey  # noqa: E402
from openvc.multibase import b58btc_encode  # noqa: E402
from openvc.proof.vc_jwt import VcJwtProofSuite  # noqa: E402
from openvc.status import CredentialRevoked, encode_bitstring, set_status_bit  # noqa: E402
from openvc_ebsi import _message, _url  # noqa: E402
from openvc_ebsi._message import bounded_text, redact_userinfo, url_repr  # noqa: E402
from openvc_ebsi.errors import (  # noqa: E402
    NodeClientConfigError,
    NodeListMalformed,
)
from openvc_ebsi.http import (  # noqa: E402
    EbsiHttpClient,
    HttpForbiddenHost,
    HttpTransientExhausted,
    RetryPolicy,
)
from openvc_ebsi.node_client import for_nodes  # noqa: E402
from openvc_ebsi.nodes import (  # noqa: E402
    Accepted,
    Node,
    VerifiedNodeList,
    check_node_origin,
)
from openvc_ebsi.verify import IssuerNotTrusted, verify_ebsi_badge  # noqa: E402
from openvc_ebsi.versioning import DidEbsiResolver, TirV5  # noqa: E402

HOST = "api-pilot.ebsi.eu"
USER = "zq9user"
SECRET = "s3cretpw"
LONG = 70_000
MAX_MESSAGE = 300


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

def _client(handler: Any = None, **kwargs: Any) -> EbsiHttpClient:
    c = EbsiHttpClient(allowed_hosts={HOST}, **kwargs)
    if handler is not None:
        c._client = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def _chain(exc: BaseException) -> list[BaseException]:
    """*exc* and everything it links to through ``__cause__`` and ``__context__``."""
    seen: list[BaseException] = []
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop()
        if e is None or any(e is s for s in seen):
            continue
        seen.append(e)
        todo += [e.__cause__, e.__context__]
    return seen


def _held(exc: BaseException) -> str:
    """Everything the exception and its chain show: ``str``, ``repr``, ``.args`` and
    ``__notes__``. Not ``.url``: it keeps the whole URL as given, by decision (#343)."""
    parts: list[str] = []
    for e in _chain(exc):
        parts += [str(e), repr(e), repr(e.args), repr(getattr(e, "__notes__", ()))]
    return "\n".join(parts)


def _refusals(client: EbsiHttpClient, url: str) -> list[HttpForbiddenHost]:
    """The refusal of *url* by the guard and by the three public paths that reach it."""
    out: list[HttpForbiddenHost] = []
    for call in (client._guard_host, client.get_json, client.get_bytes, client.probe):
        with pytest.raises(HttpForbiddenHost) as exc_info:
            call(url)
        assert type(exc_info.value) is HttpForbiddenHost
        out.append(exc_info.value)
    return out


# --------------------------------------------------------------------------- #
# The guard: the userinfo of the URL is not in a message
# --------------------------------------------------------------------------- #

# (id, url, the whole message). Rules reached in the guard's order: non-https, host, port.
GUARD = [
    pytest.param(f"http://{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'http://***@{HOST}/x'", id="non-https"),
    pytest.param(f"http://{USER}@{HOST}/x",
                 f"non-https URL rejected: 'http://***@{HOST}/x'", id="non-https-no-password"),
    pytest.param(f"http://@{HOST}/x",
                 f"non-https URL rejected: 'http://***@{HOST}/x'", id="non-https-empty"),
    pytest.param(f"http://:@{HOST}/x",
                 f"non-https URL rejected: 'http://***@{HOST}/x'", id="non-https-empty-user-pw"),
    pytest.param(f"HTTP://{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'HTTP://***@{HOST}/x'", id="non-https-upper-case"),
    pytest.param(f"ftp://{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'ftp://***@{HOST}/x'", id="ftp"),
    pytest.param(f"//{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: '//***@{HOST}/x'", id="scheme-relative"),
    pytest.param(f"{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: '***@{HOST}/x'", id="no-scheme-no-slashes"),
    pytest.param(f"://{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: '://***@{HOST}/x'", id="empty-scheme"),
    pytest.param(f"http:/{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'http:/***@{HOST}/x'", id="one-slash"),
    pytest.param(f"http:///{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'http:///***@{HOST}/x'", id="three-slashes"),
    pytest.param(f"ws:////{USER}:{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'ws:////***@{HOST}/x'", id="four-slashes"),
    pytest.param(f"http://{USER}:p%40ss{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'http://***@{HOST}/x'", id="percent-encoded-at"),
    pytest.param(f"http://{USER}:p@ss{SECRET}@{HOST}/x",
                 f"non-https URL rejected: 'http://***@{HOST}/x'", id="unencoded-at-in-password"),
    pytest.param(f"http://{USER}%3A{SECRET}%40evil.example/x",
                 "non-https URL rejected: 'http://***@evil.example/x'",
                 id="percent-encoded-at-is-the-only-delimiter"),
    pytest.param(f"http://{USER}:{SECRET}@[::1]/x",
                 "non-https URL rejected: 'http://***@[::1]/x'", id="ipv6"),
    pytest.param(f"http://{USER}:{SECRET}@[::1]:8080/x",
                 "non-https URL rejected: 'http://***@[::1]:8080/x'", id="ipv6-with-port"),
    pytest.param(f"http://{HOST}@evil.example/x",
                 "non-https URL rejected: 'http://***@evil.example/x'", id="lookalike"),
    pytest.param(f"https://{USER}:{SECRET}@evil.example/x",
                 "host not in allow-list: 'evil.example'", id="other-host"),
    pytest.param(f"https://{HOST}@evil.example/x",
                 "host not in allow-list: 'evil.example'", id="lookalike-other-host"),
    pytest.param(f"https://{USER}:{SECRET}@[::1]/x",
                 "host not in allow-list: '::1'", id="ipv6-other-host"),
    pytest.param(f"https://{USER}%3A{SECRET}%40evil.example/x",
                 "host not in allow-list: '***@evil.example'",
                 id="other-host-percent-encoded-at-is-the-only-delimiter"),
    pytest.param(f"https://{USER}:{SECRET}@{HOST}:8443/x",
                 "port 8443 not allowed: https port 443 only", id="port"),
    pytest.param(f"https://{USER}:{SECRET}@{HOST}/x",
                 "URL rejected: carries userinfo", id="userinfo"),
]


@pytest.mark.parametrize("url,message", GUARD)
def test_no_guard_rule_shows_the_userinfo_of_the_url(url: str, message: str) -> None:
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert str(exc) == message
            assert exc.args == (message,)
            held = _held(exc)
            assert SECRET not in held and USER not in held
    finally:
        c.close()


@pytest.mark.parametrize("url", [
    pytest.param(f"http://{USER}:{SECRET}@{HOST}/x", id="non-https"),
    pytest.param(f"https://{USER}:{SECRET}@evil.example/x", id="other-host"),
    pytest.param(f"https://{USER}:{SECRET}@{HOST}:8443/x", id="port"),
])
def test_the_url_of_the_exception_is_unchanged(url: str) -> None:
    # The decision of #343, kept: the message is redacted, the data is not.
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert exc.url == url
    finally:
        c.close()


def test_the_userinfo_refusal_still_carries_no_url() -> None:
    c = _client()
    try:
        for exc in _refusals(c, f"https://{USER}:{SECRET}@{HOST}/x"):
            assert exc.url is None and exc.args == ("URL rejected: carries userinfo",)
            assert exc.__cause__ is None and exc.__context__ is None
    finally:
        c.close()


@pytest.mark.parametrize("url", [
    f"http://{HOST}/a@b",
    f"http://{HOST}/?c=d@e",
    f"http://{HOST}/#f@g",
    f"http://{HOST}/a@b?c=d@e#f@g",
    f"http://{HOST}:80/p%40q",
])
def test_an_at_sign_outside_the_authority_is_not_userinfo(url: str) -> None:
    # Shown whole and quoted, as before: it is not a credential.
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert str(exc) == f"non-https URL rejected: {url!r}"
    finally:
        c.close()


def test_a_short_url_without_userinfo_reads_as_before() -> None:
    c = _client()
    try:
        for exc in _refusals(c, f"http://{HOST}/x"):
            assert str(exc) == f"non-https URL rejected: 'http://{HOST}/x'"
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# The userinfo goes before the cut, and the cut still holds
# --------------------------------------------------------------------------- #

def test_the_userinfo_is_withheld_before_the_message_is_cut() -> None:
    # A password of 150 characters ending in the secret: cut at 200 characters FIRST, the
    # message would show `http://zq9user:pppp...` and the start of the password.
    password = "p" * 150 + SECRET
    url = f"http://{USER}:{password}@{HOST}/x"
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert str(exc) == f"non-https URL rejected: 'http://***@{HOST}/x'"
            assert "pppppppppp" not in _held(exc)
    finally:
        c.close()


@pytest.mark.parametrize("url", [
    pytest.param(f"http://{USER}:{SECRET}@" + "a" * 100_000 + "/x", id="long-host"),
    pytest.param(f"http://{USER}:{SECRET}@{HOST}/" + "a" * 100_000, id="long-path"),
    pytest.param("http://" + "u" * LONG + f":{SECRET}@{HOST}/x", id="long-user"),
    pytest.param("http://" + USER + ":" + "p" * LONG + f"{SECRET}@{HOST}/x", id="long-password"),
    pytest.param("http://" + "@" * 100_000 + "/x", id="a-hundred-thousand-delimiters"),
    pytest.param("http://" + "%40" * 50_000 + "/x", id="fifty-thousand-percent-encoded-at"),
])
def test_a_100_000_character_url_gives_a_bounded_message_without_the_secret(url: str) -> None:
    c = _client()
    started = time.perf_counter()
    try:
        for exc in _refusals(c, url):
            assert len(str(exc)) < MAX_MESSAGE, len(str(exc))
            assert SECRET not in _held(exc) and "pppppppppp" not in _held(exc)
            assert exc.url == url
    finally:
        c.close()
    assert time.perf_counter() - started < 5            # linear: not a quadratic scan


# --------------------------------------------------------------------------- #
# urlparse's own error text is not chained
# --------------------------------------------------------------------------- #

DOES_NOT_PARSE = [
    pytest.param(f"https://{USER}:{SECRET}%40{HOST}/x", id="password-in-the-port-slot"),
    pytest.param(f"https://{USER}:{SECRET}@{HOST}:abc/x", id="port-not-a-number"),
    pytest.param(f"https://{USER}:{SECRET}@{HOST}:99999/x", id="port-out-of-range"),
    pytest.param(f"https://{USER}:{SECRET}@[::1/x", id="broken-ipv6"),
    pytest.param(f"https://{USER}:{SECRET}@[zz]/x", id="not-an-ip-in-brackets"),
    pytest.param(f"https://{USER}[{SECRET}]@{HOST}/x", id="brackets-in-the-userinfo"),
    pytest.param(f"https://{USER}:{SECRET}%40{HOST}:443/x", id="password-in-the-port-slot-443"),
    pytest.param(f"https://{USER}:{SECRET}@{HOST}:" + "9" * LONG, id="long-port"),
    pytest.param("https://h:" + SECRET + "a" * LONG, id="long-port-without-userinfo"),
    pytest.param(f"http://{USER}:{SECRET}%40{HOST}/x", id="password-in-the-port-slot-http"),
]


@pytest.mark.parametrize("url", DOES_NOT_PARSE)
def test_the_does_not_parse_refusal_chains_nothing_urlparse_said(url: str) -> None:
    c = _client()
    try:
        for exc in _refusals(c, url):
            assert str(exc) == "URL rejected: does not parse"
            held = _held(exc)
            assert SECRET not in held and USER not in held
            assert len(held) < 2_000, len(held)
            assert type(exc.__cause__) is ValueError            # still a ValueError, as before
            assert str(exc.__cause__) == "the authority is not a valid host and port"
            assert exc.url == url
    finally:
        c.close()


def test_read_origin_raises_the_same_cause_for_every_consumer() -> None:
    # `versioning._origin` reads through the same function, so its chain is clean as well.
    with pytest.raises(_url.UrlDoesNotParse) as exc_info:
        _url.read_origin(f"https://{USER}:{SECRET}%40{HOST}/x")
    assert exc_info.value.__context__ is None
    assert type(exc_info.value.__cause__) is ValueError
    assert SECRET not in _held(exc_info.value)


# --------------------------------------------------------------------------- #
# Past the guard: the messages that name the URL of a refused 200
# --------------------------------------------------------------------------- #

class _Chunks(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def __iter__(self):
        yield from self._chunks


def _answer(status: int = 200, *, body: bytes = b"", headers: dict[str, str] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, stream=_Chunks([body]))
    return handler


@pytest.mark.parametrize("path", ["/a@b", "/x?c=d@e", "/x#f@g"])
def test_an_at_sign_in_the_path_of_a_refused_200_is_shown_whole(path: str) -> None:
    url = f"https://{HOST}{path}"
    c = _client(_answer(body=b"not json"))
    try:
        from openvc_ebsi.errors import MalformedRegistryResponse
        with pytest.raises(MalformedRegistryResponse) as exc_info:
            c.get_json(url)
        assert str(exc_info.value) == f"registry returned a 200 with a non-JSON body: {url!r}"
    finally:
        c.close()


def test_a_url_with_userinfo_never_reaches_the_network() -> None:
    # The reachability argument for the post-guard messages: every request goes through the
    # guard first, and the guard refuses userinfo, so none of those messages can hold any.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=b"{}")
    c = _client(handler)
    try:
        for url in (f"https://{USER}:{SECRET}@{HOST}/x", f"https://{USER}@{HOST}/x",
                    f"https://@{HOST}/x"):
            for call in (c.get_json, c.get_bytes, c.probe):
                with pytest.raises(HttpForbiddenHost):
                    call(url)
        assert calls == []
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# HttpTransientExhausted: the transport error's text is cut
# --------------------------------------------------------------------------- #

FAST_RETRY = RetryPolicy(attempts=2, backoff_base_s=0.0, backoff_max_s=0.0)


def _raising(exc: Exception):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc
    return handler


@pytest.mark.parametrize("make", [
    pytest.param(httpx.RemoteProtocolError, id="RemoteProtocolError"),
    pytest.param(httpx.ConnectError, id="ConnectError"),
    pytest.param(httpx.ReadTimeout, id="ReadTimeout"),
])
@pytest.mark.parametrize("call", ["get_json", "get_bytes"])
def test_a_16_000_character_transport_error_gives_a_bounded_message(make: Any, call: str) -> None:
    text = "w" * 16_000
    c = _client(_raising(make(text)), retry=FAST_RETRY)
    try:
        with pytest.raises(HttpTransientExhausted) as exc_info:
            getattr(c, call)(f"https://{HOST}/x")
        exc = exc_info.value
        assert type(exc) is HttpTransientExhausted
        message = str(exc)
        assert message.startswith("gave up after 2 attempts: ")
        assert len(message) < MAX_MESSAGE, len(message)
        assert "w" * 100 in message                       # the start of the text is still shown
        assert "(16000 chars)" in message                 # how long the cut text was
        assert exc.status is None and exc.url == f"https://{HOST}/x"
    finally:
        c.close()


def test_a_short_transport_error_reads_exactly_as_before() -> None:
    # Cut, not quoted: the message is the text it always was.
    c = _client(_raising(httpx.ConnectError("refused")), retry=FAST_RETRY)
    try:
        with pytest.raises(HttpTransientExhausted) as exc_info:
            c.get_json(f"https://{HOST}/x")
        assert str(exc_info.value) == "gave up after 2 attempts: refused"
    finally:
        c.close()


def test_a_transport_error_of_exactly_200_characters_is_not_cut() -> None:
    c = _client(_raising(httpx.ConnectError("e" * 200)), retry=FAST_RETRY)
    try:
        with pytest.raises(HttpTransientExhausted) as exc_info:
            c.get_json(f"https://{HOST}/x")
        assert str(exc_info.value) == "gave up after 2 attempts: " + "e" * 200
    finally:
        c.close()


class _StrRaises(httpx.ConnectError):
    def __str__(self) -> str:
        raise RuntimeError("str")


def test_a_transport_error_whose_str_raises_is_still_the_typed_exhaustion() -> None:
    c = _client(_raising(_StrRaises("x")), retry=FAST_RETRY)
    try:
        with pytest.raises(HttpTransientExhausted) as exc_info:
            c.get_json(f"https://{HOST}/x")
        assert str(exc_info.value) == "gave up after 2 attempts: an object"
    finally:
        c.close()


def test_the_exhaustion_chains_nothing() -> None:
    c = _client(_raising(httpx.RemoteProtocolError("w" * 16_000)), retry=FAST_RETRY)
    try:
        with pytest.raises(HttpTransientExhausted) as exc_info:
            c.get_json(f"https://{HOST}/x")
        assert exc_info.value.__cause__ is None and exc_info.value.__context__ is None
        assert len(_held(exc_info.value)) < 1_000
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# The node client and the node list
# --------------------------------------------------------------------------- #

UTC = timezone.utc
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
EXPIRES = datetime(2027, 1, 4, 13, 33, 18, tzinfo=UTC)
NODE = "https://api.ebsi.node-a.example"
NODE_B = "https://api.ebsi.node-b.example"


def _result(origins: tuple[str, ...] = (NODE, NODE_B), *, hosts: tuple[str, ...] | None = None,
            ) -> VerifiedNodeList:
    hosts = hosts if hosts is not None else tuple(o[len("https://"):] for o in origins)
    nodes = tuple(Node(o, h, "XX", "Example") for o, h in zip(origins, hosts))
    return VerifiedNodeList(
        environment="prod", version=4, keys_version=1, issued=EXPIRES - timedelta(days=90),
        expires=EXPIRES, nodes=nodes, accepted_list=Accepted(4, "0" * 64),
        accepted_keys=Accepted(1, "0" * 64))


def _node_client(policy: Any = None):
    return for_nodes(
        _result(), clock=lambda: NOW, decode_jwt=VcJwtProofSuite().peek_claims,
        policy=policy or (lambda origins: list(origins)), retry=FAST_RETRY, address_guard=None)


def _node_refusal(exc_type: type, call: Any, *args: Any) -> BaseException:
    with pytest.raises(exc_type) as exc_info:
        call(*args)
    assert type(exc_info.value) is exc_type
    return exc_info.value


@pytest.mark.parametrize("url,message", [
    pytest.param(f"https://{USER}:{SECRET}@evil.example/x",
                 "URL is not on this session's node: 'https://***@evil.example/x'",
                 id="other-host"),
    pytest.param(f"http://{USER}:{SECRET}@api.ebsi.node-a.example/x",
                 "URL is not on this session's node: 'http://***@api.ebsi.node-a.example/x'",
                 id="same-host-other-scheme"),
    pytest.param(f"https://{USER}:{SECRET}@api.ebsi.node-b.example/x",
                 "URL is not on this session's node: 'https://***@api.ebsi.node-b.example/x'",
                 id="the-other-node"),
    pytest.param(f"https://{USER}:{SECRET}@[::1]/x",
                 "URL is not on this session's node: 'https://***@[::1]/x'", id="ipv6"),
    pytest.param(f"https:///{USER}:{SECRET}@api.ebsi.node-a.example/x",
                 "URL is not on this session's node: 'https:///***@api.ebsi.node-a.example/x'",
                 id="three-slashes"),
    pytest.param(f"https:/{USER}:{SECRET}@api.ebsi.node-a.example/x",
                 "URL is not on this session's node: 'https:/***@api.ebsi.node-a.example/x'",
                 id="one-slash"),
    pytest.param(f"https://{USER}:{SECRET}%40evil.example/x", None, id="password-in-the-port"),
])
def test_a_node_session_url_off_its_node_is_shown_without_the_userinfo(
        url: str, message: str | None) -> None:
    client = _node_client()
    try:
        session = client.session(NODE)
        exc = _node_refusal(HttpForbiddenHost, session.get_json, url)
        if message is not None:
            assert str(exc) == message
        held = _held(exc)
        assert SECRET not in held and USER not in held
        assert exc.url == url                       # `.url` is unchanged here too
    finally:
        client.close()


def test_a_node_session_url_with_userinfo_on_its_own_node_is_the_guards_refusal() -> None:
    client = _node_client()
    try:
        exc = _node_refusal(HttpForbiddenHost, client.session(NODE).get_json,
                            f"https://{USER}:{SECRET}@api.ebsi.node-a.example/x")
        assert exc.args == ("URL rejected: carries userinfo",) and exc.url is None
    finally:
        client.close()


def test_a_node_session_url_without_userinfo_reads_as_before() -> None:
    client = _node_client()
    try:
        exc = _node_refusal(HttpForbiddenHost, client.session(NODE).get_json,
                            "https://evil.example/x")
        assert str(exc) == "URL is not on this session's node: 'https://evil.example/x'"
    finally:
        client.close()


def test_a_session_for_an_origin_with_userinfo_is_refused_without_it() -> None:
    client = _node_client()
    try:
        for origin in (f"https://{USER}:{SECRET}@api.ebsi.node-a.example",
                       f"https://{USER}:{SECRET}%40api.ebsi.node-a.example"):
            exc = _node_refusal(NodeClientConfigError, client.session, origin)
            assert str(exc).startswith("not a node of this client's prod list: ")
            assert SECRET not in _held(exc) and USER not in _held(exc)
        exc = _node_refusal(NodeClientConfigError, client.session,
                            f"https://{USER}:{SECRET}@api.ebsi.node-a.example")
        assert str(exc) == ("not a node of this client's prod list: "
                            "'https://***@api.ebsi.node-a.example'")
    finally:
        client.close()


def test_a_policy_that_names_an_origin_with_userinfo_is_refused_without_it() -> None:
    named = f"https://{USER}:{SECRET}@api.ebsi.node-a.example"
    client = _node_client(policy=lambda origins: [named])
    try:
        exc = _node_refusal(NodeClientConfigError, client.run, lambda session: None)
        assert str(exc) == ("the node policy named a node that is not in the list: "
                            "'https://***@api.ebsi.node-a.example'")
        assert SECRET not in _held(exc) and USER not in _held(exc)
    finally:
        client.close()


NODE_MESSAGE = ("nodes[0].origin is not a bare https origin: "
                "'https://***@api.ebsi.node-a.example'")


@pytest.mark.parametrize("origin,message", [
    pytest.param(f"https://{USER}:{SECRET}@api.ebsi.node-a.example",
                 NODE_MESSAGE,
                 id="userinfo"),
    pytest.param(f"https://{USER}:{SECRET}%40api.ebsi.node-a.example",
                 NODE_MESSAGE,
                 id="percent-encoded-at"),
])
def test_a_node_list_entry_with_userinfo_is_refused_without_it(origin: str, message: str) -> None:
    exc = _node_refusal(
        NodeClientConfigError, lambda: for_nodes(
            _result((origin, NODE_B), hosts=("x", "y")), clock=lambda: NOW,
            decode_jwt=VcJwtProofSuite().peek_claims, retry=FAST_RETRY, address_guard=None))
    assert str(exc) == message
    assert SECRET not in _held(exc) and USER not in _held(exc)


@pytest.mark.parametrize("url", [
    f"https://{USER}:{SECRET}@api.ebsi.node-a.example",
    f"https://{USER}:{SECRET}%40api.ebsi.node-a.example",
    f"http://{USER}:{SECRET}@api.ebsi.node-a.example/" + "a" * LONG,
])
def test_check_node_origin_refuses_a_url_with_userinfo_without_showing_it(url: str) -> None:
    exc = _node_refusal(NodeListMalformed, check_node_origin, url, "prod", "tnl.json url")
    assert str(exc).startswith("tnl.json url is not a bare https origin: ")
    assert len(str(exc)) < MAX_MESSAGE
    assert SECRET not in _held(exc) and USER not in _held(exc)


def test_a_node_whose_host_is_not_the_host_of_its_origin_does_not_show_userinfo() -> None:
    exc = _node_refusal(
        NodeClientConfigError, lambda: for_nodes(
            _result((NODE, NODE_B), hosts=(f"{USER}:{SECRET}@evil.example", "y")),
            clock=lambda: NOW, decode_jwt=VcJwtProofSuite().peek_claims,
            retry=FAST_RETRY, address_guard=None))
    assert str(exc) == "nodes[0].host is not the host of its origin: '***@evil.example'"
    assert SECRET not in _held(exc)


# --------------------------------------------------------------------------- #
# verify.py: IssuerNotTrusted and CredentialRevoked
# --------------------------------------------------------------------------- #

def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


ISSUER = _did(0xA1)
BASE = "https://api-pilot.ebsi.eu"
STATUS_URL = "https://issuer.example/status/1"


class _Stub:
    def __init__(self, routes: dict[str, dict]) -> None:
        self.routes = routes

    def __call__(self, url: str) -> dict:
        return self.routes[url]


def _badge(types: list[str], *, cred_id: str = "urn:uuid:badge-1", revoked: bool = False):
    """(token, resolver, suite, resolve_status_list): an issuer with NO accreditation."""
    suite = VcJwtProofSuite()
    sk = P256SigningKey.generate(kid=f"{ISSUER}#key-1")
    credential: dict[str, Any] = {
        "@context": ["https://www.w3.org/2018/credentials/v1"], "id": cred_id, "type": types,
        "issuer": ISSUER,
        "credentialSubject": {"id": "did:key:z6MkSubject", "achievement": {"name": "T"}},
    }
    resolve = None
    if revoked:
        credential["credentialStatus"] = {
            "id": f"{STATUS_URL}#17", "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation", "statusListIndex": "17",
            "statusListCredential": STATUS_URL}
        bits = bytearray(32)
        set_status_bit(bits, 17, 1)
        resolve = {STATUS_URL: {
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": {"statusPurpose": "revocation",
                                  "encodedList": encode_bitstring(bytes(bits))}}}.__getitem__
    token = suite.sign(credential, signing_key=sk)
    routes = {
        f"{BASE}/did-registry/v5/identifiers/{ISSUER}": {"didDocument": {
            "id": ISSUER,
            "verificationMethod": [{"id": f"{ISSUER}#key-1", "type": "JsonWebKey2020",
                                    "controller": ISSUER, "publicKeyJwk": sk.public_jwk()}],
            "assertionMethod": [f"{ISSUER}#key-1"]}},
        f"{BASE}/trusted-issuers-registry/v5/issuers/{ISSUER}": {
            "did": ISSUER, "hasAttributes": False},
    }
    resolver = DidEbsiResolver(_Stub(routes), decode_jwt=suite.peek_claims, tir=TirV5())
    return token, resolver, suite, resolve


def _not_trusted(types: list[str]) -> IssuerNotTrusted:
    token, resolver, suite, _ = _badge(types)
    with pytest.raises(IssuerNotTrusted) as exc_info:
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite)
    assert type(exc_info.value) is IssuerNotTrusted
    return exc_info.value


def test_issuer_not_trusted_reads_as_before_for_a_short_type_list() -> None:
    exc = _not_trusted(["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"])
    assert str(exc) == (
        f"issuer '{ISSUER}' has no valid accreditation for types "
        "['VerifiableCredential', 'VerifiableAttestation', 'OpenBadgeCredential']")


@pytest.mark.parametrize("types", [
    pytest.param(["VerifiableCredential", "T" * LONG], id="one-70000-character-type"),
    pytest.param([f"Type{n}" for n in range(LONG)], id="70000-types"),
    pytest.param(["T" * 1_000] * 300, id="300-types-of-1000-characters"),
])
def test_issuer_not_trusted_bounds_the_credential_type_list(types: list[str]) -> None:
    exc = _not_trusted(types)
    message = str(exc)
    assert message.startswith(f"issuer '{ISSUER}' has no valid accreditation for types [")
    assert len(message) < 500, len(message)
    assert "chars)" in message                         # the cut says how long the list was


def test_credential_revoked_bounds_and_redacts_the_credential_id() -> None:
    for cred_id, expected in [
        ("urn:uuid:badge-1", "credential 'urn:uuid:badge-1' is revoked"),
        (f"https://{USER}:{SECRET}@issuer.example/credentials/1",
         "credential 'https://***@issuer.example/credentials/1' is revoked"),
    ]:
        token, resolver, suite, resolve = _badge(
            ["VerifiableCredential", "OpenBadgeCredential"], cred_id=cred_id, revoked=True)
        with pytest.raises(CredentialRevoked) as exc_info:
            verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                              require_trust=False, resolve_status_list=resolve)
        assert type(exc_info.value) is CredentialRevoked
        assert str(exc_info.value) == expected
        assert SECRET not in _held(exc_info.value)


def test_credential_revoked_cuts_a_70_000_character_id() -> None:
    token, resolver, suite, resolve = _badge(
        ["VerifiableCredential", "OpenBadgeCredential"], cred_id="urn:uuid:" + "i" * LONG,
        revoked=True)
    with pytest.raises(CredentialRevoked) as exc_info:
        verify_ebsi_badge(token, resolver=resolver, proof_suite=suite,
                          require_trust=False, resolve_status_list=resolve)
    assert len(str(exc_info.value)) < MAX_MESSAGE
    assert str(exc_info.value).endswith("chars) is revoked")


# --------------------------------------------------------------------------- #
# Found by the review of this change
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url", [
    f"http:/{USER}:{SECRET}@{HOST}/x",
    f"http:///{USER}:{SECRET}@{HOST}/x",
    f"http:////{USER}:{SECRET}@{HOST}/x",
    f"ws:/\\{USER}:{SECRET}@{HOST}/x",
    f"http:\\/{USER}:{SECRET}@{HOST}/x",
    f"http:\\\\{USER}:{SECRET}@{HOST}/x",
    f"ftp:\\//{USER}:{SECRET}@{HOST}/x",
    f"///{USER}:{SECRET}@{HOST}/x",
    f"http:/{USER}:{SECRET}%40{HOST}/x",
])
def test_slashes_that_a_browser_reads_as_the_authority_do_not_hide_the_userinfo(url: str) -> None:
    # A WHATWG parser (a browser, Node) reads `http:/u:p@h` and `http:///u:p@h` as the
    # credentialed `http://u:p@h`; urllib and httpx do not, and the guard refuses them all as
    # non-https, but the message is what reaches a log.
    c = _client()
    client = _node_client()
    try:
        for exc in _refusals(c, url):
            assert SECRET not in _held(exc) and USER not in _held(exc)
        exc = _node_refusal(HttpForbiddenHost, client.session(NODE).get_json, url)
        assert SECRET not in _held(exc) and USER not in _held(exc)
        exc = _node_refusal(NodeClientConfigError, client.session, url)
        assert SECRET not in _held(exc) and USER not in _held(exc)
    finally:
        c.close()
        client.close()


def test_the_unknown_adapter_name_message_is_bounded() -> None:
    for keyword in ("didr", "tir"):
        for name in ("x" * LONG, "https://" + "u" * LONG + "@h/x"):
            with pytest.raises(NodeClientConfigError) as exc_info:
                for_nodes(_result(), clock=lambda: NOW, decode_jwt=VcJwtProofSuite().peek_claims,
                          retry=FAST_RETRY, address_guard=None, **{keyword: name})
            assert type(exc_info.value) is NodeClientConfigError
            message = str(exc_info.value)
            assert message.startswith("unknown adapter name: ")
            assert len(message) < MAX_MESSAGE, len(message)


def test_the_unknown_adapter_name_message_reads_as_before_for_a_short_name() -> None:
    with pytest.raises(NodeClientConfigError) as exc_info:
        for_nodes(_result(), clock=lambda: NOW, decode_jwt=VcJwtProofSuite().peek_claims,
                  retry=FAST_RETRY, address_guard=None, didr="nope")
    assert str(exc_info.value) == f"unknown adapter name: {exc_info.value.__cause__}"
    assert "nope" in str(exc_info.value)


def test_the_label_of_check_node_origin_is_bounded_in_every_message_that_shows_it() -> None:
    label = "w" * LONG
    for url, environment in [("x", "prod"), ("https://other.example", "prod"),
                             ("https://api.ebsi." + "a" * 64, "prod")]:
        with pytest.raises(NodeListMalformed) as exc_info:
            check_node_origin(url, environment, label)
        assert type(exc_info.value) is NodeListMalformed
        assert len(str(exc_info.value)) < 500, (url, len(str(exc_info.value)))   # + the host
        assert str(exc_info.value).startswith("w" * 100)


def test_the_label_of_check_node_origin_reads_as_before_when_it_is_short() -> None:
    with pytest.raises(NodeListMalformed) as exc_info:
        check_node_origin("x", "prod", "tnl.json url")
    assert str(exc_info.value) == "tnl.json url is not a bare https origin: 'x'"


def test_the_address_guard_path_chains_fixed_words_when_it_cannot_read_a_url() -> None:
    # `_open_stream` reads the URL again after the guard did, and only a `str` subclass that
    # answers differently the second time gets there; its `urlparse` error quotes the port.
    from openvc_ebsi.http import AddressGuard
    c = _client(retry=RetryPolicy(attempts=1),
                address_guard=AddressGuard(resolver=lambda host, port: ["93.184.215.14"]))
    c._client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={})))
    c._guard_host = lambda url: None                          # type: ignore[method-assign]
    try:
        with pytest.raises(HttpForbiddenHost) as exc_info:
            c.get_json(f"https://{HOST}:{SECRET}/x")
        exc = exc_info.value
        assert type(exc) is HttpForbiddenHost and str(exc) == "URL rejected: does not parse"
        assert type(exc.__cause__) is ValueError
        assert str(exc.__cause__) == _url.UNPARSABLE_AUTHORITY
        assert SECRET not in _held(exc)
    finally:
        c.close()


def test_url_repr_of_an_object_that_claims_to_be_a_str_is_an_object() -> None:
    class Liar:
        @property
        def __class__(self) -> type:                          # type: ignore[override]
            return str
    assert isinstance(Liar(), str)
    assert url_repr(Liar()) == "an object"                    # as safe_repr says it


# --------------------------------------------------------------------------- #
# The helpers
# --------------------------------------------------------------------------- #

REDACTION = [
    ("http://u:p@h/x", "http://***@h/x"),
    ("http://u@h/x", "http://***@h/x"),
    ("http://@h/x", "http://***@h/x"),
    ("http://:@h/x", "http://***@h/x"),
    ("http://u:p@ss@h/x", "http://***@h/x"),
    ("http://u:p%40ss@h/x", "http://***@h/x"),
    ("http://u:p%40h/x", "http://***@h/x"),
    ("http://u:p%40H/x", "http://***@H/x"),
    ("http://u:p@[::1]:80/x", "http://***@[::1]:80/x"),
    ("//u:p@h/x", "//***@h/x"),
    ("://u:p@h/x", "://***@h/x"),                           # httpx reads an empty scheme
    # a WHATWG parser reads one slash, or three, after a special scheme as `//`
    ("http:/u:p@h/x", "http:/***@h/x"),
    ("http:///u:p@h/x", "http:///***@h/x"),
    ("http:////u:p@h/x", "http:////***@h/x"),
    ("ws:/\\u:p@h/x", "ws:/\\***@h/x"),
    ("http:\\/u:p@h", "http:\\/***@h"),
    ("///u:p@h/x", "///***@h/x"),
    ("/x@y/z", "/x@y/z"),                                    # a lone slash opens a path
    ("https:/h/a@b", "https:/h/a@b"),
    ("https:///host/a@b", "https:///host/a@b"),
    ("file:///etc/a@b", "file:///etc/a@b"),
    ("u:p@h/x", "***@h/x"),
    ("mailto:a@b.example", "***@b.example"),
    ("HTTP://U:P@H", "HTTP://***@H"),
    (" http://u:p@h", "http://***@h"),                    # urlsplit strips a leading space
    ("http:/\t/u:p@h/x", "http://***@h/x"),                # and a tab anywhere: this is `//`
    ("http://u:p\n@h", "http://***@h"),
    # nothing to withhold: returned as given
    ("", ""),
    ("http://h/x", "http://h/x"),
    ("https://h:443/a", "https://h:443/a"),
    ("http://h/a@b?c=d@e#f@g", "http://h/a@b?c=d@e#f@g"),
    ("http://h?x=u:p@q", "http://h?x=u:p@q"),
    ("http://h#u:p@q", "http://h#u:p@q"),
    ("evil.example:8080/x", "evil.example:8080/x"),
    ("c" * 500, "c" * 500),
]


@pytest.mark.parametrize("url,expected", REDACTION)
def test_redact_userinfo(url: str, expected: str) -> None:
    assert redact_userinfo(url) == expected


@pytest.mark.parametrize("value", [None, 5, b"http://u:p@h", ["http://u:p@h"]])
def test_redact_userinfo_never_returns_what_it_cannot_read(value: Any) -> None:
    assert redact_userinfo(value) == "<url withheld>"


class _Hostile(str):
    def __getattribute__(self, name: str) -> Any:
        raise RuntimeError(name)

    def __repr__(self) -> str:
        raise RuntimeError("repr")


def test_redact_userinfo_reads_a_str_subclass_through_str() -> None:
    assert redact_userinfo(_Hostile("http://u:p@h/x")) == "http://***@h/x"
    assert url_repr(_Hostile("http://u:p@h/x")) == "'http://***@h/x'"


def test_url_repr_redacts_before_it_cuts_and_quotes_like_safe_repr() -> None:
    assert url_repr("http://u:p@h/x") == "'http://***@h/x'"
    assert url_repr("http://h/" + "a" * 300).endswith("... (309 chars)")
    assert url_repr(None) == "None" and url_repr(5) == "5"
    assert url_repr([1]) == "list" and url_repr(object()) == "object"        # as safe_repr does


def test_bounded_text() -> None:
    assert bounded_text("transient") == "transient"
    assert bounded_text(ValueError("boom")) == "boom"
    assert bounded_text("a" * 200) == "a" * 200
    assert bounded_text("a" * 201) == "a" * 200 + "... (201 chars)"
    assert bounded_text(["a", "b"]) == "['a', 'b']"
    assert bounded_text(None) == "None"


def test_bounded_text_reads_a_str_subclass_through_str() -> None:
    class Long(str):
        def __str__(self) -> str:
            return "x" * 100_000
    assert bounded_text(Long("short")) == "x" * 200 + "... (100000 chars)"      # str() asked once

    class Raises:
        def __str__(self) -> str:
            raise RuntimeError("str")
    assert bounded_text(Raises()) == "an object"


def test_the_shown_bound_is_the_one_safe_repr_uses() -> None:
    from openvc.proof._verify_common import _SHOWN_MAX
    assert _message._SHOWN_MAX == _SHOWN_MAX == 200
