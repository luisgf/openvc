"""
tests/test_ebsi_node_client.py — the node-bound EBSI client (#324, ADR-0009 D5).

``for_nodes`` turns the verified Trusted Nodes List (#319) into a client bound to ONE environment:
the allow-list is exactly the list's hosts, the client carries the list's ``expires`` and an
injected wall clock (a read at or after it is ``NodeListExpired`` before any socket), a health
check is one status-aware ``GET /v1/alive``, and a registry walk runs on ONE node from start to
end and restarts on the next when that node fails.

Negatives first. Every refusal asserts the EXACT class (``type(exc) is X``) and, where it matters,
that ZERO requests reached the transport, so none of them can pass on an earlier or a different
failure. Offline: ``httpx.MockTransport`` injected into the ``httpx.Client`` the real constructor
builds (so ``follow_redirects``, headers and the cookie policy are the constructor's own), a fixed
wall clock, a fake ``time`` for sleeps and deadlines. No test depends on the day it runs, so the
suite does not go red when the recorded list expires (2027-01-04): the one test that goes through
the real chain pins ``now`` inside its window, the recorded RootTAO is verified at a pinned
instant, and the synthetic signed chain is signed and verified inside one test.

Synthetic inputs are labelled SYNTHETIC. Recorded ones are the ``/v1/alive`` answers of two
production nodes (``tests/fixtures/ebsi/alive/``), the Trusted Nodes List chain
(``tests/fixtures/ebsi/tnl/``) and the preprod Core v1 registry reads
(``tests/fixtures/ebsi/core-v1/``). Helpers are self-contained (tests/ is not a package).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import json
import logging
import pickle
import threading
import urllib.request
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt.api_jwt
import pytest

httpx = pytest.importorskip("httpx")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import openvc_ebsi.http as ebsi_http  # noqa: E402
from openvc.cache import TtlCache  # noqa: E402
from openvc.errors import OpenvcError  # noqa: E402
from openvc.keys import P256SigningKey  # noqa: E402
from openvc.multibase import b58btc_encode  # noqa: E402
from openvc.proof import _verify_common  # noqa: E402
from openvc.proof.errors import UnsupportedAlgorithm  # noqa: E402
from openvc.proof.vc_jwt import VcJwtProofSuite  # noqa: E402
from openvc_ebsi.errors import (  # noqa: E402
    EbsiError,
    MalformedRegistryResponse,
    NodeClientConfigError,
    NodeListExpired,
)
from openvc_ebsi.http import (  # noqa: E402
    AddressGuard,
    EbsiHttpClient,
    HttpAddressGuardUnavailable,
    HttpError,
    HttpForbiddenAddress,
    HttpForbiddenHost,
    HttpNotFound,
    HttpTransientExhausted,
    HttpUnexpectedEncoding,
    RetryPolicy,
)
from openvc_ebsi.node_client import (  # noqa: E402
    FAILURE_KINDS,
    NODE_RETRY,
    EbsiNodeClient,
    NodeFailure,
    NoHealthyNode,
    classify,
    for_nodes,
    random_order,
)
from openvc_ebsi.nodes import (  # noqa: E402
    EUROPEUM_KEY_LIST_ANCHOR,
    Accepted,
    Node,
    VerifiedNodeList,
    verify_node_list,
)
from openvc_ebsi.trust import (  # noqa: E402
    AccreditationInvalid,
    NoTrustedAnchor,
    TrustChainError,
    verify_trust_chain,
)
from openvc_ebsi.verify import IssuerNotTrusted, verify_ebsi_badge  # noqa: E402
from openvc_ebsi.versioning import (  # noqa: E402
    DidEbsiResolver,
    DidRegistryCoreV1,
    TirAdapter,
    TirCoreV1,
)

UTC = timezone.utc
EXPIRES = datetime(2027, 1, 4, 13, 33, 18, tzinfo=UTC)         # a SYNTHETIC list's expiry
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
TICK = timedelta(microseconds=1)

A, B, C = (f"https://api.ebsi.node-{n}.example" for n in "abc")
ORIGINS = (A, B, C)
ALIVE_JSON = {"content-type": "application/json; charset=utf-8"}
ALIVE_OK_BODY = b'{"health_global":1}'
PEEK = VcJwtProofSuite().peek_claims
_dumps = json.dumps

# Zero backoff so the retry loops do not sleep.
FAST_RETRY = RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)

FIX = Path(__file__).parent / "fixtures" / "ebsi"


def host_of(origin: str) -> str:
    return origin[len("https://"):]


def make_result(origins: tuple[str, ...] = ORIGINS, environment: str = "prod",
                expires: datetime = EXPIRES) -> VerifiedNodeList:
    nodes = tuple(Node(o, host_of(o), "XX", "Example") for o in origins)
    return VerifiedNodeList(
        environment=environment, version=4, keys_version=1,
        issued=expires - timedelta(days=90), expires=expires, nodes=nodes,
        accepted_list=Accepted(4, "0" * 64), accepted_keys=Accepted(1, "0" * 64))


class Clock:
    """The injected wall clock: a settable instant, and a count of readings."""

    def __init__(self, now: datetime = NOW) -> None:
        self.now = now
        self.reads = 0

    def __call__(self) -> datetime:
        self.reads += 1
        return self.now


class FakeTime:
    """Stands in for the ``time`` module of openvc_ebsi.http: a sleep advances both clocks."""

    def __init__(self, wall: Clock | None = None) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []
        self.wall = wall

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        if self.wall is not None:
            self.wall.now += timedelta(seconds=seconds)


# --------------------------------------------------------------------------- #
# The wire: one handler per node, every request recorded
# --------------------------------------------------------------------------- #

def R(status: int = 200, content: bytes = b"", headers: Any = None, json: Any = None,
      stream: Any = None) -> httpx.Response:
    """A response as a socket delivers it: a stream that is read once, not a pre-read body (the
    exact-bytes path reads the raw stream)."""
    if json is not None:
        content = _dumps(json).encode()
    return httpx.Response(
        status, headers=headers, stream=stream if stream is not None else httpx.ByteStream(content))


def respond(status: int = 200, body: bytes = b"", **headers: str):
    def handler(request: httpx.Request) -> httpx.Response:
        return R(status, body, {k.replace("_", "-"): v for k, v in headers.items()})
    return handler


def fail(exc: Exception):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc
    return handler


def tagged(request: httpx.Request) -> httpx.Response:
    """A registry read whose body names the node that served it (by ``Host``: behind the
    address guard the URL names the validated address, the header still names the node)."""
    return R(200, json={"node": request.headers["host"]})


alive_ok = respond(200, ALIVE_OK_BODY, **ALIVE_JSON)


def node(read: Any = tagged, alive: Any = alive_ok):
    """A node: ``/v1/alive`` answers *alive*, every other path answers *read*."""
    def handler(request: httpx.Request) -> httpx.Response:
        return (alive if request.url.path == "/v1/alive" else read)(request)
    return handler


class Net:
    """A MockTransport handler that routes by host and records every request it is handed."""

    def __init__(self, default: Any = None) -> None:
        self.default = node() if default is None else default
        self.hosts: dict[str, Any] = {}
        self.requests: list[httpx.Request] = []
        self._lock = threading.Lock()

    def on(self, origin: str, handler: Any) -> "Net":
        self.hosts[host_of(origin)] = handler
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.requests.append(request)
        return self.hosts.get(request.url.host, self.default)(request)

    def to(self, origin: str, path: str | None = None) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host_of(origin)
                and (path is None or r.url.path == path)]

    def walks(self, origin: str) -> list[httpx.Request]:
        return [r for r in self.to(origin) if r.url.path != "/v1/alive"]

    def alive(self, origin: str) -> list[httpx.Request]:
        return self.to(origin, "/v1/alive")

    @property
    def log(self) -> list[tuple[str, str]]:
        return [(r.url.host, r.url.path) for r in self.requests]


def walk_tagged(session: Any) -> str:
    """The simplest walk: one registry read on the session's node."""
    return session.get_json(f"{session.origin}/v1/walk")["node"]


def in_order(origins: tuple[str, ...]) -> list[str]:
    return list(origins)


def expect(cls: type, fn: Any, *args: Any, **kwargs: Any):
    """Call ``fn`` and require EXACTLY ``cls`` (not a subclass)."""
    with pytest.raises(OpenvcError) as info:
        fn(*args, **kwargs)
    assert type(info.value) is cls, (
        f"expected {cls.__name__}, got {type(info.value).__name__}: {info.value}")
    return info.value


DEFAULT_RESULT = object()


class NoCache:
    """A response cache that never hits, so a repeated walk is a repeated request. The tests
    about the cache itself pass a real ``TtlCache``."""

    def get(self, key: str) -> None:
        return None

    def set(self, key: str, value: Any) -> None:
        pass


class Rig:
    """Builds clients through the real ``for_nodes``, with the transport injected into the
    ``httpx.Client`` the constructor creates. ``built`` counts those clients, so a refusal can
    assert that none existed."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._real = httpx.Client
        self.net: Net | None = None
        self.built = 0
        self.inner: list[httpx.Client] = []
        self.clients: list[EbsiNodeClient] = []
        self.clock = Clock()
        monkeypatch.setattr(httpx, "Client", self._client)

    def _client(self, **kwargs: Any) -> httpx.Client:
        assert self.net is not None, "an httpx.Client was built"
        self.built += 1
        inner = self._real(transport=httpx.MockTransport(self.net), **kwargs)
        self.inner.append(inner)
        return inner

    def build(self, net: Net | None = None, result: Any = DEFAULT_RESULT,
              **kwargs: Any) -> EbsiNodeClient:
        self.net = net if net is not None else Net()
        kwargs.setdefault("clock", self.clock)
        kwargs.setdefault("decode_jwt", PEEK)
        kwargs.setdefault("policy", in_order)
        kwargs.setdefault("retry", FAST_RETRY)
        kwargs.setdefault("address_guard", None)
        kwargs.setdefault("cache", NoCache())
        client = for_nodes(make_result() if result is DEFAULT_RESULT else result, **kwargs)
        self.clients.append(client)
        return client

    def refuse(self, cls: type, result: Any, **kwargs: Any):
        """``for_nodes`` must raise EXACTLY ``cls`` and must not have built an httpx.Client."""
        before = self.built
        exc = expect(cls, self.build, Net(), result, **kwargs)
        assert self.built == before, "an httpx.Client was built before the refusal"
        return exc


@pytest.fixture()
def rig(monkeypatch):
    rig = Rig(monkeypatch)
    yield rig
    for client in rig.clients:
        client.close()
    for inner in rig.inner:
        inner.close()


@pytest.fixture(autouse=True)
def _no_environment_proxy(monkeypatch):
    """A developer machine may have a system proxy (``getproxies`` reads the macOS and Windows
    settings); the address guard, on by default in ``for_nodes``, refuses to be built behind one.
    The proxy test sets its own."""
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})


# --------------------------------------------------------------------------- #
# 1. The allow-list is the list, for one environment
# --------------------------------------------------------------------------- #

def test_the_allow_list_is_exactly_the_hosts_of_the_result_and_every_node_is_admitted(rig):
    net = Net()
    client = rig.build(net)
    assert client.http.allowed_hosts == frozenset(host_of(o) for o in ORIGINS)
    assert client.origins == ORIGINS and client.environment == "prod"
    assert client.expires == EXPIRES and client.http.valid_until == EXPIRES
    for origin in ORIGINS:
        assert client.http.get_json(f"{origin}/v1/x") == {"node": host_of(origin)}
    assert len(net.requests) == 3


@pytest.mark.parametrize("host", [
    "tnl.ebsi.eu", "hub.ebsi.eu", "api.ebsi.eu", "api-pilot.ebsi.eu", "api-conformance.ebsi.eu",
    "api.ebsi.node-d.example",
])
def test_a_host_outside_the_result_is_refused_before_any_socket(rig, host):
    net = Net()
    client = rig.build(net)
    expect(HttpForbiddenHost, client.http.get_json, f"https://{host}/v1/x")
    assert net.requests == []


def test_the_hosts_of_another_environment_are_refused(rig):
    preprod = tuple(f"https://api-preprod.ebsi.node-{n}.example" for n in "ab")
    net = Net()
    client = rig.build(net)                                  # the prod client
    for origin in preprod:
        expect(HttpForbiddenHost, client.http.get_json, f"{origin}/v1/x")
    other = rig.build(net, make_result(preprod, "preprod"))
    expect(HttpForbiddenHost, other.http.get_json, f"{A}/v1/x")
    assert net.requests == []
    assert other.environment == "preprod" and other.origins == preprod


@pytest.mark.parametrize("environment", ["pilot", "preprod", "prod"])
def test_the_legacy_table_is_never_read(rig, environment):
    prefix = {"pilot": "api-pilot", "preprod": "api-preprod", "prod": "api"}[environment]
    origins = (f"https://{prefix}.ebsi.node-a.example",)
    net = Net()
    client = rig.build(net, make_result(origins, environment))
    # the legacy default host and the EBSI_HOSTS names are not on any node client's list
    for host in ("api-pilot.ebsi.eu", "api.ebsi.eu", "api-conformance.ebsi.eu"):
        expect(HttpForbiddenHost, client.http.get_json, f"https://{host}/v1/x")
    assert net.requests == []
    assert client.environment == environment


@pytest.mark.parametrize("kwargs", [
    {"extra_hosts": {"api.ebsi.node-d.example"}}, {"allowed_hosts": {"x.example"}},
    {"verify_tls": False},
], ids=["extra_hosts", "allowed_hosts", "verify_tls"])
def test_no_way_to_widen_the_allow_list_or_weaken_tls(rig, kwargs):
    rig.net = Net()
    with pytest.raises(TypeError):
        for_nodes(make_result(), clock=rig.clock, decode_jwt=PEEK, **kwargs)
    assert rig.built == 0


# --------------------------------------------------------------------------- #
# 2. The result is re-validated before an allow-list is made of it
# --------------------------------------------------------------------------- #

def _with_origin(origin: str, host: str | None = None) -> VerifiedNodeList:
    good = make_result()
    node0 = Node(origin, host if host is not None else host_of(origin), "XX", "Example")
    return replace(good, nodes=(node0, *good.nodes[1:]))


BAD_RESULTS = [
    pytest.param(replace(make_result(), nodes=()), id="no-nodes"),
    pytest.param(replace(make_result(), nodes=list(make_result().nodes)), id="nodes-as-list"),
    pytest.param(replace(make_result(), nodes=(None,)), id="a-node-that-is-None"),
    pytest.param(replace(make_result(), nodes=({"origin": A},)), id="a-node-that-is-a-dict"),
    pytest.param(_with_origin(f"{A}/v1"), id="path"),
    pytest.param(_with_origin(f"{A}:8443"), id="port"),
    pytest.param(_with_origin(f"{A}:443"), id="explicit-default-port"),
    pytest.param(_with_origin(f"https://user@{host_of(A)}"), id="userinfo"),
    pytest.param(_with_origin(f"{A}?x=1"), id="query"),
    pytest.param(_with_origin(f"{A}#f"), id="fragment"),
    pytest.param(_with_origin(f"{A}/"), id="trailing-slash"),
    pytest.param(_with_origin(f"{A}\n"), id="trailing-newline"),
    pytest.param(_with_origin(f"http://{host_of(A)}"), id="http"),
    pytest.param(_with_origin("https://API.EBSI.NODE-A.EXAMPLE"), id="upper-case"),
    pytest.param(_with_origin("https://api.ebsi.nöde.example"), id="non-ascii-host"),
    pytest.param(_with_origin("https://api.ebsi.-node.example"), id="label-leading-hyphen"),
    pytest.param(_with_origin("https://api.ebsi." + "a" * 64 + ".example"), id="label-too-long"),
    pytest.param(_with_origin("https://api-pilot.ebsi.node-a.example"), id="another-environment"),
    pytest.param(_with_origin(A, host="api.ebsi.other.example"), id="host-is-not-the-origins"),
    pytest.param(_with_origin(A, host=f"{host_of(A)}:443"), id="host-with-a-port"),
    pytest.param(replace(make_result(), nodes=(*make_result().nodes, make_result().nodes[0])),
                 id="duplicate"),
    pytest.param(replace(make_result(), environment="production"), id="environment-production"),
    pytest.param(replace(make_result(), environment=""), id="environment-empty"),
    pytest.param(replace(make_result(), environment=None), id="environment-None"),
    pytest.param(replace(make_result(), expires=None), id="expires-None"),
    pytest.param(replace(make_result(), expires="2027-01-04T13:33:18Z"), id="expires-string"),
    pytest.param(replace(make_result(), expires=1798680000), id="expires-int"),
    pytest.param({"environment": "prod", "nodes": ()}, id="a-dict"),
    pytest.param(SimpleNamespace(**vars(make_result())), id="a-namespace-with-the-fields"),
    pytest.param(None, id="None"),
]


@pytest.mark.parametrize("result", BAD_RESULTS)
def test_a_result_that_cannot_be_an_allow_list_is_refused_before_any_client_exists(rig, result):
    exc = rig.refuse(NodeClientConfigError, result)
    assert isinstance(exc, ValueError) and isinstance(exc, EbsiError)


def test_a_result_with_more_nodes_than_a_list_can_hold_is_refused(rig):
    origins = tuple(f"https://api.ebsi.n{i}.example" for i in range(513))
    rig.refuse(NodeClientConfigError, make_result(origins))


@pytest.mark.parametrize("bad", [
    pytest.param(0, id="zero"), pytest.param(-1, id="negative"), pytest.param(True, id="bool"),
    pytest.param(2.0, id="float"), pytest.param("3", id="string"), pytest.param(None, id="None"),
    pytest.param(10**9, id="huge"),
])
def test_max_nodes_is_a_small_positive_int(rig, bad):
    rig.refuse(NodeClientConfigError, make_result(), max_nodes=bad)


@pytest.mark.parametrize("bad", [
    pytest.param(0, id="zero"), pytest.param(-5.0, id="negative"),
    pytest.param(float("nan"), id="nan"), pytest.param(float("inf"), id="inf"),
    pytest.param(True, id="bool"), pytest.param("60", id="string"),
    pytest.param(None, id="None"),
])
def test_health_ttl_s_is_a_finite_positive_number(rig, bad):
    rig.refuse(NodeClientConfigError, make_result(), health_ttl_s=bad)


@pytest.mark.parametrize("kwargs", [
    pytest.param({"didr": "v9"}, id="didr-unknown"), pytest.param({"tir": "v9"}, id="tir-unknown"),
    pytest.param({"didr": ["v5"]}, id="didr-unhashable"),
    pytest.param({"decode_jwt": None}, id="decode_jwt-None"),
    pytest.param({"policy": "random"}, id="policy-not-callable"),
    pytest.param({"clock": None}, id="clock-None"),
])
def test_other_arguments_are_checked_before_any_client_exists(rig, kwargs):
    rig.refuse(NodeClientConfigError, make_result(), **kwargs)


BAD_SECONDS = {
    "negative": -1, "zero": 0, "zero-float": 0.0, "nan": float("nan"), "inf": float("inf"),
    "-inf": float("-inf"), "bool": True, "string": "10", "None": None,
    "huge-int": 10**400, "past-the-cap": 10**10,
}


@pytest.mark.parametrize("name", ["timeout_s", "cache_ttl_s", "health_ttl_s"])
@pytest.mark.parametrize("label", sorted(BAD_SECONDS))
def test_a_duration_that_is_not_a_sane_number_of_seconds_is_a_config_error(rig, name, label):
    # every one of these used to be built, and then reported as an outage (NoHealthyNode) or as
    # a bare OverflowError / TypeError from the middle of a request
    rig.refuse(NodeClientConfigError, make_result(), **{name: BAD_SECONDS[label]})


@pytest.mark.parametrize("bad", [
    pytest.param(0, id="zero"), pytest.param(-5, id="negative"), pytest.param(True, id="bool"),
    pytest.param(1.5, id="float"), pytest.param("1024", id="string"), pytest.param(None, id="None"),
])
def test_max_response_bytes_is_a_positive_int(rig, bad):
    rig.refuse(NodeClientConfigError, make_result(), max_response_bytes=bad)


BAD_RETRIES = [
    pytest.param(5, id="int"), pytest.param("RetryPolicy()", id="string"),
    pytest.param({"attempts": 2}, id="dict"),
    pytest.param(RetryPolicy(attempts=0), id="no-attempt"),
    pytest.param(RetryPolicy(attempts=-1), id="negative-attempts"),
    pytest.param(RetryPolicy(attempts=True), id="bool-attempts"),
    pytest.param(RetryPolicy(attempts=1.5), id="float-attempts"),
    pytest.param(RetryPolicy(backoff_base_s=-1.0), id="negative-backoff"),
    pytest.param(RetryPolicy(backoff_max_s=-1.0), id="negative-backoff-max"),
    pytest.param(RetryPolicy(backoff_base_s=float("nan")), id="nan-backoff"),
    pytest.param(RetryPolicy(backoff_max_s=float("inf")), id="inf-backoff-max"),
    pytest.param(RetryPolicy(backoff_base_s="1"), id="string-backoff"),
    pytest.param(RetryPolicy(retry_statuses=503), id="int-statuses"),
    pytest.param(RetryPolicy(retry_statuses=frozenset({"503"})), id="string-status"),
    pytest.param(RetryPolicy(retry_statuses=frozenset({True})), id="bool-status"),
]


@pytest.mark.parametrize("retry", BAD_RETRIES)
def test_a_retry_policy_the_request_loop_cannot_run_is_a_config_error_not_an_outage(rig, retry):
    # RetryPolicy(attempts=0) made no request at all and was reported as "no healthy node"
    rig.refuse(NodeClientConfigError, make_result(), retry=retry)


@pytest.mark.parametrize("kwargs", [
    pytest.param({"health_clock": 5}, id="health_clock-int"),
    pytest.param({"health_clock": None}, id="health_clock-None"),
    pytest.param({"health_clock": lambda: "x"}, id="health_clock-string"),
    pytest.param({"health_clock": lambda: None}, id="health_clock-None-reading"),
    pytest.param({"health_clock": lambda: True}, id="health_clock-bool"),
    pytest.param({"health_clock": lambda: float("nan")}, id="health_clock-nan"),
    pytest.param({"health_clock": lambda: float("inf")}, id="health_clock-inf"),
    pytest.param({"health_clock": lambda: 10**400}, id="health_clock-huge-int"),
    pytest.param({"health_clock": lambda: (_ for _ in ()).throw(RuntimeError("boom"))},
                 id="health_clock-raises"),
    pytest.param({"user_agent": ""}, id="user_agent-empty"),
    pytest.param({"user_agent": None}, id="user_agent-None"),
    pytest.param({"user_agent": b"openvc"}, id="user_agent-bytes"),
    pytest.param({"user_agent": "openvc\r\nX-Evil: 1"}, id="user_agent-crlf"),
    pytest.param({"user_agent": "openvc\x00"}, id="user_agent-nul"),
    pytest.param({"user_agent": "openvc-\u00e9"}, id="user_agent-non-ascii"),
    pytest.param({"user_agent": "x" * 257}, id="user_agent-too-long"),
    pytest.param({"cache": object()}, id="cache-object"),
    pytest.param({"cache": SimpleNamespace(get=None, set=None)}, id="cache-no-methods"),
    pytest.param({"cache": SimpleNamespace(get=lambda k: None)}, id="cache-no-set"),
    pytest.param({"address_guard": object()}, id="address_guard-object"),
    pytest.param({"address_guard": True}, id="address_guard-bool"),
    pytest.param({"address_guard": "on"}, id="address_guard-string"),
])
def test_every_other_argument_is_checked_before_any_client_exists(rig, kwargs):
    rig.refuse(NodeClientConfigError, make_result(), **kwargs)


def test_the_reasonable_values_of_those_arguments_are_accepted(rig):
    client = rig.build(
        Net(), timeout_s=1, cache_ttl_s=1, max_response_bytes=1024, health_ttl_s=1,
        retry=RetryPolicy(attempts=1, backoff_base_s=0, backoff_max_s=0, retry_statuses=set()),
        health_clock=lambda: 5, user_agent="my-service/1.0 (+https://example.org)",
        cache=NoCache(), address_guard=AddressGuard(resolver=lambda h, p: ["93.184.216.34"]))
    assert client.run(walk_tagged) == host_of(A)
    assert rig.net is not None and len(rig.net.requests) == 2           # the probe and the read


def test_a_health_clock_that_goes_bad_later_is_a_config_error_never_a_bare_exception(rig):
    readings: list[Any] = [5000.0]

    def health_clock() -> Any:
        return readings[-1]
    net = Net()
    client = rig.build(net, health_clock=health_clock)
    assert client.run(walk_tagged) == host_of(A)
    before = len(net.requests)
    for bad in ("x", None, float("nan"), 10**400):
        readings.append(bad)
        expect(NodeClientConfigError, client.run, walk_tagged)
        assert len(net.requests) == before                 # no request on a clock it cannot read
        expect(NodeClientConfigError, client.check_health, A)  # (the verdict cannot be recorded)
        before = len(net.requests)


def test_the_adapters_default_to_the_core_v1_names_and_the_walk_uses_them(rig):
    net = Net()
    client = rig.build(net)
    session = client.session(A)
    assert isinstance(session.resolver, DidEbsiResolver)
    assert session.resolver._base == A
    assert type(session.resolver._didr) is DidRegistryCoreV1
    assert type(session.resolver._tir) is TirCoreV1
    # a fresh resolver per session: nothing is carried over
    assert client.session(A).resolver is not session.resolver


# --------------------------------------------------------------------------- #
# 3. The list's lifetime: NodeListExpired before any socket
# --------------------------------------------------------------------------- #

def test_a_result_already_expired_at_the_clock_is_node_list_expired_at_construction(rig):
    rig.clock.now = EXPIRES
    exc = rig.refuse(NodeListExpired, make_result())
    assert "expired" in str(exc)
    rig.clock.now = EXPIRES + timedelta(days=400)
    rig.refuse(NodeListExpired, make_result())
    rig.clock.now = EXPIRES - TICK
    assert rig.build(Net()).expires == EXPIRES                # one microsecond before: builds


# every way in: (client, a session made while the list was still valid) -> a call
EXPIRED_CALLS = {
    "run": lambda c, s: c.run(walk_tagged),
    "session": lambda c, s: c.session(A),
    "check_health": lambda c, s: c.check_health(A),
    "http.get_json": lambda c, s: c.http.get_json(f"{A}/v1/x"),
    "http.get_bytes": lambda c, s: c.http.get_bytes(f"{A}/v1/x"),
    "http.probe": lambda c, s: c.http.probe(f"{A}/v1/alive"),
    "session.get_json": lambda c, s: s.get_json(f"{A}/v1/x"),
}


@pytest.mark.parametrize("call", sorted(EXPIRED_CALLS))
@pytest.mark.parametrize("moment", [
    pytest.param(EXPIRES, id="at-expires"),
    pytest.param(EXPIRES + TICK, id="a-microsecond-after"),
    pytest.param(EXPIRES + timedelta(days=3650), id="far-past"),
])
def test_at_or_after_expires_every_entry_point_raises_before_any_socket(rig, call, moment):
    net = Net()
    client = rig.build(net)
    session = client.session(A)                            # made while the list was valid
    rig.clock.now = moment
    exc = expect(NodeListExpired, EXPIRED_CALLS[call], client, session)
    assert "expired" in str(exc)
    assert net.requests == []


@pytest.mark.parametrize("call", sorted(EXPIRED_CALLS))
def test_one_microsecond_before_expires_everything_still_works(rig, call):
    net = Net()
    client = rig.build(net)
    session = client.session(A)
    rig.clock.now = EXPIRES - TICK
    EXPIRED_CALLS[call](client, session)                     # does not raise
    assert net.requests != [] or call == "session"


def test_a_cached_success_is_not_served_past_expires(rig):
    net = Net()
    client = rig.build(net, cache=TtlCache(ttl_s=300.0))
    url = f"{A}/v1/x"
    assert client.http.get_json(url) == {"node": host_of(A)}
    assert client.http.get_json(url) == {"node": host_of(A)}      # from the cache
    assert len(net.requests) == 1
    rig.clock.now = EXPIRES
    expect(NodeListExpired, client.http.get_json, url)
    assert len(net.requests) == 1


def test_run_raises_node_list_expired_not_no_healthy_node_and_tries_no_second_node(rig):
    def alive_then_expire(request: httpx.Request) -> httpx.Response:
        rig.clock.now = EXPIRES                              # the list dies while A is probed
        return alive_ok(request)
    net = Net().on(A, node(read=respond(503), alive=alive_then_expire))
    client = rig.build(net)
    expect(NodeListExpired, client.run, walk_tagged)
    assert net.to(B) == [] and net.to(C) == []
    assert [r.url.path for r in net.to(A)] == ["/v1/alive"]       # the walk never started


def test_a_backoff_sleep_that_crosses_expires_is_caught_by_the_next_attempt(rig, monkeypatch):
    fake = FakeTime(wall=rig.clock)
    monkeypatch.setattr(ebsi_http, "time", fake)
    rig.clock.now = EXPIRES - timedelta(seconds=1)
    net = Net().on(A, node(read=respond(503)))
    client = rig.build(net, retry=RetryPolicy(attempts=3, backoff_base_s=4.0, backoff_max_s=4.0))
    expect(NodeListExpired, client.run, walk_tagged)             # never NoHealthyNode
    assert len(net.walks(A)) == 1                                # the second attempt was not sent
    assert fake.sleeps != [] and net.to(B) == []


@pytest.mark.parametrize("bad", [
    pytest.param(lambda: None, id="None"), pytest.param(lambda: 1798680000, id="int"),
    pytest.param(lambda: "2026-10-16T12:00:00Z", id="string"),
    pytest.param(lambda: 1798680000.0, id="float"),
    pytest.param(lambda: NOW.date(), id="date"),
    pytest.param(lambda: (_ for _ in ()).throw(RuntimeError("boom")), id="raises"),
    pytest.param(lambda: (_ for _ in ()).throw(KeyError("k")), id="raises-keyerror"),
])
def test_a_clock_that_is_not_a_clock_is_a_config_error_never_now(rig, bad):
    rig.refuse(NodeClientConfigError, make_result(), clock=bad)             # at construction
    net = Net()
    client = rig.build(net)
    client.http._clock = bad                                                # and later
    expect(NodeClientConfigError, client.run, walk_tagged)
    expect(NodeClientConfigError, client.check_health, A)
    expect(NodeClientConfigError, client.http.get_json, f"{A}/v1/x")
    assert net.requests == []


def test_a_naive_clock_is_read_as_utc(rig):
    rig.clock.now = (EXPIRES - TICK).replace(tzinfo=None)
    net = Net()
    client = rig.build(net)
    assert client.run(walk_tagged) == host_of(A)
    rig.clock.now = EXPIRES.replace(tzinfo=None)
    expect(NodeListExpired, client.run, walk_tagged)


class LyingInstant(datetime):
    """A datetime whose own methods lie: only the fields and ``tzinfo`` it holds are true."""

    def utcoffset(self):
        return timedelta(hours=-12)

    def astimezone(self, tz=None):
        return datetime(1999, 1, 1, tzinfo=UTC)

    def __ge__(self, other):
        return False

    def __lt__(self, other):
        return True


@pytest.mark.parametrize("delta,expired", [(-TICK, False), (timedelta(0), True)])
def test_a_datetime_subclass_cannot_change_the_reading(rig, delta, expired):
    moment = EXPIRES + delta
    client = rig.build(Net())                                  # built while the list is valid
    rig.clock.now = LyingInstant(moment.year, moment.month, moment.day, moment.hour,
                                 moment.minute, moment.second, moment.microsecond, tzinfo=UTC)
    if expired:
        expect(NodeListExpired, client.run, walk_tagged)
    else:
        assert client.run(walk_tagged) == host_of(A)


def test_a_swallowed_expiry_still_reaches_the_caller(rig):
    net = Net()
    client = rig.build(net)

    def walk(session: Any) -> str:
        session.get_json(f"{session.origin}/v1/walk")
        rig.clock.now = EXPIRES
        try:
            session.get_json(f"{session.origin}/v1/walk2")
        except EbsiError:
            return "swallowed"
        return "not reached"
    expect(NodeListExpired, client.run, walk)
    assert len(net.walks(A)) == 1 and net.to(B) == []


def test_run_is_gated_before_its_own_walk_even_when_no_probe_is_due(rig):
    # A fresh healthy verdict means `run` sends no probe, and a walk that reads nothing sends no
    # request, so nothing downstream would ever notice that the list is dead: only run's own
    # gate stops it, and the walk is never called.
    net = Net()
    client = rig.build(net)
    assert client.check_health(A) is True
    sent = len(net.requests)
    rig.clock.now = EXPIRES
    ran: list[Any] = []
    expect(NodeListExpired, client.run, lambda session: ran.append(session) or "value")
    assert ran == [] and len(net.requests) == sent


def test_a_session_read_of_an_off_node_url_after_expiry_is_node_list_expired(rig):
    # The session's own gate runs before its origin pin: an expired list is expired on every
    # node, and a refusal of the URL must not hide that. (The client's gate would not catch it:
    # the pin refuses an off-node URL before the client is asked.)
    net = Net()
    client = rig.build(net)
    session = client.session(A)                       # made while the list was valid
    rig.clock.now = EXPIRES
    expect(NodeListExpired, session.get_json, f"{B}/v1/x")
    expect(NodeListExpired, session.get_json, 5)      # not even a str
    assert net.requests == []


def test_a_config_error_the_walk_swallowed_still_reaches_the_caller(rig):
    # The wall clock goes bad in the middle of a walk, the walk catches the EbsiError that
    # follows and returns a value: run must raise the configuration error, never that value.
    net = Net()
    client = rig.build(net)

    def walk(session: Any) -> str:
        session.get_json(f"{session.origin}/v1/walk")
        rig.clock.now = None                         # the clock goes bad
        try:
            session.get_json(f"{session.origin}/v1/walk2")
        except EbsiError:
            return "sentinel"
        return "not reached"
    expect(NodeClientConfigError, client.run, walk)
    assert len(net.walks(A)) == 1 and net.to(B) == []


# --------------------------------------------------------------------------- #
# 4. The selection policy's output is untrusted
# --------------------------------------------------------------------------- #

class StrSub(str):
    pass


BAD_POLICIES = [
    pytest.param(lambda o: [A, "https://api.ebsi.node-d.example"], id="non-member"),
    pytest.param(lambda o: [A.upper()], id="case-variant"),
    pytest.param(lambda o: [A + "/"], id="trailing-slash"),
    pytest.param(lambda o: [host_of(A)], id="bare-host"),
    pytest.param(lambda o: [A, A], id="duplicate"),
    pytest.param(lambda o: [], id="empty"),
    pytest.param(lambda o: iter(()), id="empty-iterator"),
    pytest.param(lambda o: None, id="None"),
    pytest.param(lambda o: 5, id="int"),
    pytest.param(lambda o: [A, 5], id="int-item"),
    pytest.param(lambda o: [None], id="None-item"),
    pytest.param(lambda o: [StrSub(A)], id="str-subclass"),
    pytest.param(lambda o: [list(o)], id="nested"),
    pytest.param(lambda o: itertools.repeat(A), id="never-ending"),
    # the two that only the bound pins: both are cut at len(origins) + 1 items, and a bound of
    # len(origins) would hand `run` a valid order (the cycle truncated, the stray name unseen)
    pytest.param(lambda o: itertools.cycle(o), id="never-ending-cycle"),
    pytest.param(lambda o: list(o) + ["https://api.ebsi.node-d.example"],
                 id="non-member-after-every-member"),
    pytest.param(lambda o: (_ for _ in ()).throw(RuntimeError("boom")), id="raises"),
]


@pytest.mark.parametrize("policy", BAD_POLICIES)
def test_a_policy_that_names_anything_else_is_a_config_error_before_any_request(rig, policy):
    net = Net()
    client = rig.build(net, policy=policy)
    expect(NodeClientConfigError, client.run, walk_tagged)
    assert net.requests == []


def test_the_policy_decides_the_order_and_sees_the_origins_as_a_tuple(rig):
    seen: list[Any] = []

    def policy(origins):
        seen.append(origins)
        return [C, A]                                         # a subset, in its own order
    net = Net()
    client = rig.build(net, policy=policy)
    assert client.run(walk_tagged) == host_of(C)
    assert seen == [ORIGINS] and type(seen[0]) is tuple
    assert net.to(B) == [] and net.to(A) == []


def test_the_default_policy_orders_every_node_once(rig):
    for _ in range(20):
        order = random_order(ORIGINS)
        assert sorted(order) == sorted(ORIGINS)
    assert {tuple(random_order(ORIGINS)) for _ in range(200)} != {ORIGINS}   # it does shuffle
    net = Net()
    client = rig.build(net, policy=random_order)
    assert client.run(walk_tagged) in {host_of(o) for o in ORIGINS}


@settings(max_examples=60, deadline=None, derandomize=True)
@given(st.lists(st.one_of(st.sampled_from(ORIGINS), st.sampled_from(ORIGINS).map(str.upper),
                          st.text(max_size=8), st.integers(), st.none()), max_size=6))
def test_property_a_policy_gets_members_only_or_a_config_error(items):
    net = Net()
    client = for_nodes(make_result(), clock=Clock(), decode_jwt=PEEK, policy=lambda o: items,
                       retry=FAST_RETRY, address_guard=None)
    client.http._client.close()
    client.http._client = httpx.Client(transport=httpx.MockTransport(net))
    try:
        try:
            client.run(walk_tagged)
        except NodeClientConfigError:
            pass
        else:
            assert all(r.url.host in {host_of(o) for o in ORIGINS} for r in net.requests)
    finally:
        client.close()
    members = [i for i in items if type(i) is str and i in ORIGINS]
    valid = bool(items) and len(members) == len(items) and len(set(items)) == len(items)
    assert valid == (len(net.requests) > 0)


# --------------------------------------------------------------------------- #
# 5. Health
# --------------------------------------------------------------------------- #

def _recorded(name: str) -> tuple[bytes, dict[str, str]]:
    body = (FIX / "alive" / f"{name}.body").read_bytes()
    head = (FIX / "alive" / f"{name}.headers").read_bytes().decode("ascii").split("\r\n")
    assert head[0] == "HTTP/1.1 200 OK"
    fields = dict(line.split(": ", 1) for line in head[1:] if line)
    for transfer in ("Content-Length", "Connection", "content-length"):
        fields.pop(transfer, None)                  # the transport recomputes the framing
    return body, fields


RECORDED_NODES = ["api.ebsi.iti.gr", "api.ebsi.edelivery.lt"]


def test_the_recorded_alive_files_are_the_ones_the_manifest_names():
    manifest = json.loads((FIX / "alive" / "MANIFEST.json").read_text(encoding="utf-8"))
    on_disk = {p.name for p in (FIX / "alive").iterdir()} - {"MANIFEST.json", "README.md"}
    assert on_disk == set(manifest["files"])
    for name, entry in manifest["files"].items():
        data = (FIX / "alive" / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"], name
        assert len(data) == entry["bytes"], name
    for name in RECORDED_NODES:                                  # what the health check reads
        body, _ = _recorded(name)
        assert body == ALIVE_OK_BODY and len(body) == 19


@pytest.mark.parametrize("name", RECORDED_NODES)
def test_golden_a_recorded_healthy_node_is_healthy(rig, name):
    body, fields = _recorded(name)
    origin = f"https://{name}"
    net = Net(default=respond(200, body, **fields))
    client = rig.build(net, make_result((origin,)))
    assert client.check_health(origin) is True
    assert [(r.method, str(r.url)) for r in net.requests] == [("GET", f"{origin}/v1/alive")]
    # the same recorded answer, as a node would repeat it, makes the node a candidate
    healthy = Net(default=node(read=tagged, alive=respond(200, body, **fields)))
    other = rig.build(healthy, make_result((origin,)))
    assert other.run(walk_tagged) == name
    assert len(healthy.alive(origin)) == 1 and len(healthy.walks(origin)) == 1
    assert len(other.http._client.cookies.jar) == 0         # edelivery.lt's SRV_ID is dropped


# SYNTHETIC inputs: the hub documents `{"health_global":0}` with a 503 but no node was seen
# answering it, and the firewall page is third-party HTML (only its measured facts are kept:
# 403, text/html, 35 059 bytes).
FIREWALL_PAGE = b"<html><title>Web Application Firewall</title>" + b"x" * (35_059 - 45)

UNHEALTHY = [
    pytest.param(respond(200, b'{"health_global":0}'), id="200-zero"),
    pytest.param(respond(200, b'{"health_global":true}'), id="true"),
    pytest.param(respond(200, b'{"health_global":1.0}'), id="float-one"),
    pytest.param(respond(200, b'{"health_global":"1"}'), id="string-one"),
    pytest.param(respond(200, b'{"health_global":2}'), id="two"),
    pytest.param(respond(200, b'{"health_global":null}'), id="null"),
    pytest.param(respond(200, b'{"health_global":[1]}'), id="list"),
    pytest.param(respond(200, b'{"alive":1}'), id="key-missing"),
    pytest.param(respond(200, b'{}'), id="empty-object"),
    pytest.param(respond(200, b'[]'), id="array"),
    pytest.param(respond(200, b'[{"health_global":1}]'), id="array-with-the-object"),
    pytest.param(respond(200, b'1'), id="number"),
    pytest.param(respond(200, b'"health_global"'), id="string"),
    pytest.param(respond(200, b'not json'), id="non-json"),
    pytest.param(respond(200, b''), id="empty-body"),
    pytest.param(respond(200, b'\xff\xfe{"health_global":1}'), id="not-utf8"),
    pytest.param(respond(200, b'{"health_global":1,"health_global":0}'), id="duplicate-key"),
    pytest.param(respond(200, b'{"health_global":1}' + b" " * 2000), id="body-past-the-cap"),
    pytest.param(respond(503, b'{"health_global":0}'), id="503-synthetic"),
    pytest.param(respond(503, ALIVE_OK_BODY), id="503-with-a-healthy-body"),
    pytest.param(respond(429, ALIVE_OK_BODY), id="429"),
    pytest.param(respond(500, ALIVE_OK_BODY), id="500"),
    pytest.param(respond(403, FIREWALL_PAGE, content_type="text/html"), id="403-firewall"),
    pytest.param(respond(404, ALIVE_OK_BODY), id="404"),
    pytest.param(respond(204), id="204"),
    pytest.param(respond(206, ALIVE_OK_BODY), id="206"),
    pytest.param(respond(301, ALIVE_OK_BODY, location=f"{A}/v1/alive"), id="301"),
    pytest.param(respond(304), id="304"),
    pytest.param(fail(httpx.ConnectTimeout("t")), id="connect-timeout"),
    pytest.param(fail(httpx.ReadTimeout("t")), id="read-timeout"),
    pytest.param(fail(httpx.ConnectError("refused")), id="connect-error"),
]


@pytest.mark.parametrize("answer", UNHEALTHY)
def test_anything_but_a_200_with_health_global_one_is_unhealthy_in_one_request(
        rig, monkeypatch, answer):
    fake = FakeTime()
    monkeypatch.setattr(ebsi_http, "time", fake)
    net = Net().on(A, answer)
    client = rig.build(net, cache=TtlCache(ttl_s=300.0),
                       retry=RetryPolicy(attempts=5, backoff_base_s=1.0, backoff_max_s=1.0))
    assert client.check_health(A) is False
    assert [(r.method, str(r.url)) for r in net.requests] == [("GET", f"{A}/v1/alive")]
    assert fake.sleeps == []                                 # one attempt: no retry, no backoff
    assert len(client.http._cache) == 0                      # nothing written to the cache


def test_a_healthy_node_with_extra_members_is_healthy(rig):
    net = Net().on(A, respond(200, b'{"health_global":1,"build":"x"}'))
    assert rig.build(net).check_health(A) is True


def test_the_probe_is_never_read_from_nor_written_to_the_response_cache(rig):
    net = Net()
    client = rig.build(net, cache=TtlCache(ttl_s=300.0))
    url = f"{A}/v1/alive"
    client.http._cache.set(url, {"health_global": 1})              # a poisoned cache entry
    net.on(A, respond(503))
    assert client.check_health(A) is False                         # the cache was not consulted
    net.on(A, alive_ok)
    assert client.check_health(A) is True
    assert client.http._cache.get(url) == {"health_global": 1}     # and the entry is untouched
    assert len(net.requests) == 2


def test_check_health_names_a_node_of_the_list_or_is_a_config_error(rig):
    net = Net()
    client = rig.build(net)
    for bad in ("https://api.ebsi.node-d.example", A + "/", A.upper(), host_of(A), None, 5):
        expect(NodeClientConfigError, client.check_health, bad)
        expect(NodeClientConfigError, client.session, bad)
    assert net.requests == []


def test_a_probe_failure_is_not_a_walk_failure_and_run_skips_the_node(rig):
    net = Net().on(A, node(alive=respond(503, b'{"health_global":0}')))
    client = rig.build(net)
    assert client.run(walk_tagged) == host_of(B)
    assert net.walks(A) == [] and len(net.alive(A)) == 1


class Mono:
    """The health memo's monotonic clock."""

    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


def test_the_verdict_is_memoised_for_health_ttl_s(rig):
    mono = Mono()
    net = Net()
    client = rig.build(net, health_ttl_s=60.0, health_clock=mono)
    assert client.run(walk_tagged) == host_of(A)
    assert client.run(walk_tagged) == host_of(A)                 # inside the TTL: no second probe
    assert len(net.alive(A)) == 1 and len(net.walks(A)) == 2
    mono.now += 59.0
    client.run(walk_tagged)
    assert len(net.alive(A)) == 1
    mono.now += 2.0                                              # 61 s: the verdict is stale
    client.run(walk_tagged)
    assert len(net.alive(A)) == 2


def test_a_node_that_failed_a_read_is_skipped_without_a_request_inside_the_ttl(rig):
    mono = Mono()
    net = Net().on(A, node(read=respond(503)))
    client = rig.build(net, health_ttl_s=60.0, health_clock=mono)
    assert client.run(walk_tagged) == host_of(B)
    assert len(net.walks(A)) == FAST_RETRY.attempts
    before = len(net.to(A))
    assert client.run(walk_tagged) == host_of(B)                 # A is known bad: free skip
    assert len(net.to(A)) == before
    mono.now += 61.0
    net.on(A, node())                                            # A recovered
    assert client.run(walk_tagged) == host_of(A)


def test_check_health_always_probes_and_refreshes_the_verdict(rig):
    mono = Mono()
    net = Net().on(A, node(alive=respond(503)))
    client = rig.build(net, health_clock=mono)
    assert client.check_health(A) is False
    net.on(A, node())
    assert client.run(walk_tagged) == host_of(B)                 # the stale-bad verdict stands
    assert client.check_health(A) is True                        # a fresh probe says healthy
    assert client.run(walk_tagged) == host_of(A)                 # and now run uses it
    assert len(net.alive(A)) == 2


@settings(max_examples=120, deadline=None, derandomize=True)
@given(body=st.binary(max_size=64),
       status=st.sampled_from([100, 200, 204, 301, 403, 404, 429, 500, 503, 599]))
def test_property_check_health_gives_a_bool_or_an_ebsi_error(body, status):
    net = Net(default=respond(status, body))
    client = for_nodes(make_result(), clock=Clock(), decode_jwt=PEEK, retry=FAST_RETRY,
                       address_guard=None, policy=in_order)
    client.http._client.close()
    client.http._client = httpx.Client(transport=httpx.MockTransport(net))
    try:
        try:
            out = client.check_health(A)
        except EbsiError:
            return
        assert type(out) is bool
        if out:
            assert status == 200
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# 6. Failover, and what does not fail over
# --------------------------------------------------------------------------- #

PROBLEM = "application/problem+json"
SENTINEL = "SENTINEL-body-7f3a"
EVIL = "https://attacker.example/SENTINEL-location-7f3a"

# (id, how node A answers the walk's read, kind, status, requests to A's walk)
FAILOVER = [
    pytest.param(fail(httpx.ConnectError("refused SENTINEL")), "unreachable", None, 3,
                 id="connect-error"),
    pytest.param(fail(httpx.ConnectTimeout("t")), "unreachable", None, 3, id="connect-timeout"),
    pytest.param(fail(httpx.ReadTimeout("t")), "unreachable", None, 3, id="read-timeout"),
    pytest.param(respond(429), "unavailable", 429, 3, id="429"),
    pytest.param(respond(500), "unavailable", 500, 3, id="500"),
    pytest.param(respond(502), "unavailable", 502, 3, id="502"),
    pytest.param(respond(503), "unavailable", 503, 3, id="503"),
    pytest.param(respond(504), "unavailable", 504, 3, id="504"),
    pytest.param(respond(501), "unavailable", 501, 1, id="501-not-retried"),
    pytest.param(respond(507, f"<{SENTINEL}>".encode()), "unavailable", 507, 1, id="507"),
    pytest.param(respond(403, f"<html>{SENTINEL}</html>".encode(), content_type="text/html"),
                 "forbidden", 403, 1, id="403-html"),
    pytest.param(respond(403, json.dumps({"type": f"urn:ebsi:problems:{SENTINEL}"}).encode(),
                         content_type=PROBLEM), "forbidden", 403, 1, id="403-problem"),
    pytest.param(respond(301, b"", location=EVIL), "redirect", 301, 1, id="301"),
    pytest.param(respond(302, b"", location=EVIL), "redirect", 302, 1, id="302"),
    pytest.param(respond(303, b"", location=EVIL), "redirect", 303, 1, id="303"),
    pytest.param(respond(307, b"", location=EVIL), "redirect", 307, 1, id="307"),
    pytest.param(respond(308, b"", location=EVIL), "redirect", 308, 1, id="308"),
    pytest.param(respond(200, b'{"pad":"' + b"0" * 5000 + b'"}'), "limits", 200, 1,
                 id="body-past-the-cap"),
]


@pytest.mark.parametrize("answer,kind,status,attempts", FAILOVER)
def test_a_node_failure_reruns_the_walk_on_the_next_node(rig, answer, kind, status, attempts):
    net = Net().on(A, node(read=answer))
    client = rig.build(net, max_response_bytes=1024)
    assert client.run(walk_tagged) == host_of(B)                 # the value comes from B
    assert len(net.walks(A)) == attempts
    assert len(net.walks(B)) == 1
    assert net.to(C) == []                                       # and C was never needed
    assert "attacker.example" not in {r.url.host for r in net.requests}


@pytest.mark.parametrize("answer,kind,status,attempts", FAILOVER)
def test_when_every_node_fails_no_healthy_node_lists_one_failure_per_node(
        rig, caplog, answer, kind, status, attempts):
    caplog.set_level(logging.DEBUG, logger="openvc")
    net = Net(default=node(read=answer))
    client = rig.build(net, max_response_bytes=1024)
    exc = expect(NoHealthyNode, client.run, walk_tagged)
    assert exc.failures == tuple(NodeFailure(o, kind, status) for o in ORIGINS)
    assert all(f.kind in FAILURE_KINDS for f in exc.failures)
    # nothing a node wrote is in the error, the failures or the log: not the body, not the
    # problem `type`, not a Location, not a transport message
    texts = [str(exc), repr(exc), *map(repr, exc.failures), *map(str, exc.failures)]
    texts += [r.getMessage() for r in caplog.records] + [str(r.args) for r in caplog.records]
    for text in texts:
        for secret in (SENTINEL, "attacker.example", "SENTINEL", "refused"):
            assert secret not in text
    assert exc.__cause__ is None and exc.__context__ is None
    assert len(caplog.records) == 3                              # one line per failed node
    for record in caplog.records:
        assert record.levelno == logging.WARNING and "kind=" + kind in record.getMessage()


def test_a_redirect_is_never_followed(rig):
    net = Net().on(A, node(read=respond(302, b"", location=EVIL)))
    client = rig.build(net)
    assert client.run(walk_tagged) == host_of(B)
    assert {r.url.host for r in net.requests} <= {host_of(o) for o in ORIGINS}
    assert client.http._client.follow_redirects is False


def test_the_deadline_is_a_failover_row(rig, monkeypatch):
    class Dripping:
        """A 200 whose body arrives one byte per read, each read a minute later."""

        def __iter__(self):
            for _ in range(100):
                fake.now += 60.0
                yield b"x"

        def close(self):
            pass
    fake = FakeTime()
    monkeypatch.setattr(ebsi_http, "time", fake)
    drip = node(read=lambda request: R(200, stream=_Stream(Dripping())))
    net = Net().on(A, drip)
    client = rig.build(net)
    assert client.run(walk_tagged) == host_of(B)
    assert len(net.walks(A)) == 1


class _Stream(httpx.SyncByteStream):
    def __init__(self, chunks: Any) -> None:
        self._chunks = chunks

    def __iter__(self):
        return iter(self._chunks)


NO_FAILOVER = [
    pytest.param(respond(404, b"{}", content_type=PROBLEM), HttpNotFound, 404, id="404"),
    pytest.param(respond(400), HttpError, 400, id="400"),
    pytest.param(respond(401), HttpError, 401, id="401"),
    pytest.param(respond(405), HttpError, 405, id="405"),
    pytest.param(respond(406), HttpError, 406, id="406"),
    pytest.param(respond(410), HttpError, 410, id="410"),
    pytest.param(respond(418), HttpError, 418, id="418"),
    pytest.param(respond(204), HttpError, 204, id="204"),
    pytest.param(respond(200, b"[]"), MalformedRegistryResponse, None, id="200-array"),
    pytest.param(respond(200, b"null"), MalformedRegistryResponse, None, id="200-null"),
    pytest.param(respond(200, b"not json"), MalformedRegistryResponse, None, id="200-non-json"),
]


@pytest.mark.parametrize("answer,cls,status", NO_FAILOVER)
def test_a_node_that_answers_is_not_failed_over_from(rig, answer, cls, status):
    net = Net().on(A, node(read=answer))
    client = rig.build(net)
    exc = expect(cls, client.run, walk_tagged)
    if status is not None:
        assert exc.status == status
    assert len(net.walks(A)) == 1                                # one request, no retry
    assert net.to(B) == [] and net.to(C) == []                   # B's handler is never called


def test_a_404_names_the_node_that_said_it_and_does_not_mark_it_unhealthy(rig):
    net = Net().on(A, node(read=respond(404, b"{}", content_type=PROBLEM)))
    client = rig.build(net)
    exc = expect(HttpNotFound, client.run, walk_tagged)
    assert exc.url == f"{A}/v1/walk"
    net.on(A, node())                                            # the node catches up
    assert client.run(walk_tagged) == host_of(A)                 # still a candidate: no TTL wait
    assert len(net.alive(A)) == 1


@pytest.mark.parametrize("error", [
    AccreditationInvalid("bad"), NoTrustedAnchor("none"), IssuerNotTrusted("no"),
    MalformedRegistryResponse("odd"), TrustChainError("cycle"),
    UnsupportedAlgorithm("'ES256K' is not permitted"),
], ids=lambda e: type(e).__name__)
def test_an_error_about_the_content_propagates_unchanged_and_does_not_fail_over(rig, error):
    net = Net()
    client = rig.build(net)

    def walk(session: Any) -> None:
        session.get_json(f"{session.origin}/v1/walk")
        raise error
    with pytest.raises(OpenvcError) as info:
        client.run(walk)
    assert info.value is error
    assert net.to(B) == [] and len(net.walks(A)) == 1


def test_a_failure_the_walk_caught_does_not_defeat_failover(rig):
    net = Net().on(A, node(read=respond(503)))
    client = rig.build(net)
    sentinel = "swallowed"

    def walk(session: Any) -> str:
        try:
            return session.get_json(f"{session.origin}/v1/walk")["node"]
        except EbsiError:
            return sentinel                                  # the walk hides the node failure
    assert client.run(walk) == host_of(B)                    # the sentinel is discarded
    assert len(net.walks(B)) == 1


def test_a_node_failure_followed_by_another_ebsi_error_still_fails_over(rig):
    net = Net().on(A, node(read=respond(503)))
    client = rig.build(net)

    def walk(session: Any) -> str:
        try:
            return session.get_json(f"{session.origin}/v1/walk")["node"]
        except EbsiError as exc:
            raise NoTrustedAnchor("the 503 became a trust verdict") from exc
    assert client.run(walk) == host_of(B)                    # A's verdict was built on a failure


def test_a_failure_of_the_walks_own_fetch_is_not_blamed_on_the_node(rig):
    # e.g. a status-list lookup through some other client: it looks like a node failure
    # (HttpTransientExhausted), but this session did not see it, so no node is marked bad
    net = Net()
    client = rig.build(net)
    own = HttpTransientExhausted("gave up after 3 attempts: transient", status=503)

    def walk(session: Any) -> None:
        session.get_json(f"{session.origin}/v1/walk")
        raise own
    with pytest.raises(HttpTransientExhausted) as info:
        client.run(walk)
    assert info.value is own
    assert net.to(B) == [] and len(net.alive(A)) == 1
    assert client.run(walk_tagged) == host_of(A)                  # A is still a candidate


def test_a_404_the_walk_caught_is_that_nodes_answer_and_is_returned(rig):
    net = Net().on(A, node(read=respond(404)))
    client = rig.build(net)

    def walk(session: Any) -> str:
        try:
            return session.get_json(f"{session.origin}/v1/walk")["node"]
        except HttpNotFound:
            return "not found here"
    assert client.run(walk) == "not found here"
    assert net.to(B) == []


def test_a_non_ebsi_error_from_the_walk_propagates_and_marks_nothing(rig):
    net = Net()
    client = rig.build(net)

    def walk(session: Any) -> None:
        raise KeyError("a bug in the caller's walk")
    with pytest.raises(KeyError):
        client.run(walk)
    assert net.to(B) == []


def test_each_node_is_tried_at_most_once_per_run_and_max_nodes_is_honoured(rig):
    five = tuple(f"https://api.ebsi.node-{n}.example" for n in "abcde")
    net = Net(default=node(read=respond(503)))
    client = rig.build(net, make_result(five), max_nodes=2)
    exc = expect(NoHealthyNode, client.run, walk_tagged)
    assert [f.origin for f in exc.failures] == list(five[:2])
    assert [len(net.walks(o)) for o in five] == [3, 3, 0, 0, 0]
    assert all(net.to(o) == [] for o in five[2:])            # beyond max_nodes: never contacted
    assert len(net.alive(five[0])) == 1 and len(net.alive(five[1])) == 1


def test_candidates_known_bad_cost_nothing_against_max_nodes(rig):
    mono = Mono()
    five = tuple(f"https://api.ebsi.node-{n}.example" for n in "abcde")
    net = Net(default=node(alive=respond(503)))
    client = rig.build(net, make_result(five), max_nodes=2, health_clock=mono)
    expect(NoHealthyNode, client.run, walk_tagged)              # A and B probed and bad
    net.on(five[2], node())
    assert client.run(walk_tagged) == host_of(five[2])          # A, B free; C is the 1st to cost
    assert len(net.alive(five[0])) == 1 and len(net.alive(five[1])) == 1


def test_when_all_candidates_are_known_bad_the_error_costs_no_request(rig):
    mono = Mono()
    net = Net(default=node(alive=respond(503)))
    client = rig.build(net, health_clock=mono)
    first = expect(NoHealthyNode, client.run, walk_tagged)
    count = len(net.requests)
    second = expect(NoHealthyNode, client.run, walk_tagged)
    assert len(net.requests) == count
    assert second.failures == first.failures == tuple(
        NodeFailure(o, "unhealthy", 503) for o in ORIGINS)


def test_the_error_and_the_failure_are_small_and_picklable():
    failures = (NodeFailure(A, "unreachable"), NodeFailure(B, "forbidden", 403))
    exc = NoHealthyNode(failures)
    again = pickle.loads(pickle.dumps(exc))
    assert type(again) is NoHealthyNode and again.failures == failures
    assert str(exc) == "no healthy node among 2 examined (1 unreachable, 1 forbidden)"
    assert repr(failures[1]) == f"NodeFailure(origin={B!r}, kind='forbidden', status=403)"
    assert isinstance(exc, EbsiError)


# classify() on its own: the table, written against the shipped error shapes ---------------

CLASSIFY = [
    (HttpTransientExhausted("x"), "unreachable"),
    (HttpTransientExhausted("x", status=None), "unreachable"),
    (HttpTransientExhausted("x", status=429), "unavailable"),
    (HttpTransientExhausted("x", status=503), "unavailable"),
    (HttpForbiddenAddress("private"), "unreachable"),
    (HttpError("x", status=403), "forbidden"),
    (HttpError("x", status=301), "redirect"),
    (HttpError("x", status=399), "redirect"),
    (HttpError("x", status=429), "unavailable"),
    (HttpError("x", status=500), "unavailable"),
    (HttpError("x", status=599), "unavailable"),
    (HttpError("x", status=200), "limits"),
    (HttpError("deadline exceeded"), "limits"),
    (HttpNotFound("x", status=404), None),
    (HttpError("x", status=400), None),
    (HttpError("x", status=404), None),
    (HttpError("x", status=204), None),
    (HttpError("x", status=300 - 1), None),
    (HttpError("x", status=400), None),
    (HttpError("x", status=499), None),
    (HttpForbiddenHost("off-list"), None),
    (HttpUnexpectedEncoding("x", status=200), None),
    (MalformedRegistryResponse("x"), None),
    (NodeListExpired("x"), None),
    (NodeClientConfigError("x"), None),
    (AccreditationInvalid("x"), None),
    (KeyError("x"), None),
]


@pytest.mark.parametrize("exc,kind", CLASSIFY, ids=lambda v: type(v).__name__ if
                         isinstance(v, BaseException) else str(v))
def test_classify_is_one_table_over_the_shipped_error_shapes(exc, kind):
    assert classify(exc) == kind


@settings(max_examples=150, deadline=None, derandomize=True)
@given(cls=st.sampled_from([HttpError, HttpNotFound, HttpForbiddenHost, HttpTransientExhausted,
                            HttpUnexpectedEncoding, HttpForbiddenAddress]),
       status=st.one_of(st.none(), st.integers(-5, 700), st.just(True)))
def test_property_classify_gives_a_kind_of_the_closed_set_or_none(cls, status):
    out = classify(cls("x", status=status))
    assert out is None or out in FAILURE_KINDS


# --------------------------------------------------------------------------- #
# 7. A session is one node: the URL pin
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url", [
    pytest.param(f"{B}/v1/x", id="another-node-of-the-set"),
    pytest.param(f"{A}:8443/v1/x", id="own-host-other-port"),
    pytest.param(f"http://{host_of(A)}/v1/x", id="own-host-http"),
    pytest.param("https://api.ebsi.node-d.example/v1/x", id="not-in-the-set"),
    pytest.param(f"https://{host_of(A)}.attacker.example/v1/x", id="suffix-trick"),
    pytest.param(f"https://x@{host_of(B)}/v1/x", id="userinfo-names-another"),
    pytest.param(f"{A}\t/v1/x", id="tab"),
    pytest.param("", id="empty"),
    pytest.param(5, id="not-a-string"),
])
def test_a_session_refuses_a_url_that_is_not_on_its_node_before_any_socket(rig, url):
    net = Net()
    session = rig.build(net).session(A)
    expect(HttpForbiddenHost, session.get_json, url)
    assert net.requests == []


def test_a_session_admits_its_own_node_in_every_spelling_of_the_port(rig):
    net = Net()
    session = rig.build(net).session(A)
    assert session.get_json(f"{A}:443/v1/x") == {"node": host_of(A)}
    assert session.get_json(f"{A}/v1/y") == {"node": host_of(A)}
    assert session.get_json(f"{A}:/v1/z") == {"node": host_of(A)}
    assert session.get_json(f"{A.upper()}/v1/w") == {"node": host_of(A)}      # host case
    assert len(net.requests) == 4


def test_what_is_checked_is_what_is_fetched_a_str_subclass_is_read_as_its_text(rig):
    net = Net()
    client = rig.build(net)
    session = client.session(A)
    seen: list[Any] = []
    real = client.http.get_json
    client.http.get_json = lambda url: (seen.append(url), real(url))[1]     # type: ignore
    assert session.get_json(StrSub(f"{A}/v1/x")) == {"node": host_of(A)}
    assert [type(u) for u in seen] == [str]                  # a plain str reaches the client
    expect(HttpForbiddenHost, session.get_json, StrSub(f"{B}/v1/x"))
    assert len(net.requests) == 1


def test_userinfo_on_the_own_node_is_still_the_clients_refusal(rig):
    net = Net()
    session = rig.build(net).session(A)
    expect(HttpForbiddenHost, session.get_json, f"https://u:p@{host_of(A)}/v1/x")
    assert net.requests == []


class _FollowsAnyHref(TirAdapter):
    """A SYNTHETIC adapter with NO origin pin: it fetches whatever `href` the body names."""
    version = "unpinned"

    def issuer_url(self, base: str, did: str) -> str:
        return f"{base}/v1/issuers-registry/issuers/{did}"

    def parse_issuer(self, raw, *, base, did, fetch, decode):
        fetch(raw["href"])
        raise AssertionError("not reached: the fetch above must have been refused")


DID = "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([0xA1]) * 16)


def test_a_body_served_by_one_node_cannot_steer_a_read_to_another_whatever_the_adapter(rig):
    net = Net(default=node(read=lambda r: R(
        200, json={"did": DID, "href": f"{B}/v1/issuers-registry/issuers/{DID}/attributes"})))
    client = rig.build(net)

    def walk(session: Any) -> None:
        resolver = DidEbsiResolver(session.get_json, PEEK, base=session.origin,
                                   tir=_FollowsAnyHref())
        resolver.issuer_record(DID)
    exc = expect(HttpForbiddenHost, client.run, walk)
    assert "not on this session's node" in str(exc)
    assert net.to(B) == [] and net.alive(B) == []            # node B never saw anything
    assert len(net.walks(A)) == 1                            # the issuer read, nothing after


def test_a_refusal_the_walk_swallowed_still_reaches_the_caller(rig):
    net = Net()
    client = rig.build(net)

    def walk(session: Any) -> str:
        try:
            session.get_json(f"{B}/v1/x")
        except EbsiError:
            return "swallowed"
        return "not reached"
    expect(HttpForbiddenHost, client.run, walk)
    assert net.to(B) == []


def test_a_refusal_the_walk_swallowed_and_then_replaced_by_another_error_still_wins(rig):
    # the walk hides the off-node refusal, then fails with a content error of its own: the
    # caller must still hear about the refusal, not be told "no trusted anchor"
    net = Net().on(A, node(read=respond(503)))
    client = rig.build(net)

    def walk(session: Any) -> None:
        try:
            session.get_json(f"{B}/v1/x")
        except EbsiError:
            pass
        raise NoTrustedAnchor("hides the refusal")
    expect(HttpForbiddenHost, client.run, walk)
    assert net.to(B) == []


def test_the_session_records_the_first_failure_only(rig):
    net = Net().on(A, node(read=lambda r: {
        "/v1/a": R(403), "/v1/b": R(302)}[r.url.path]))
    session = rig.build(net).session(A)
    assert session.failure is None
    expect(HttpError, session.get_json, f"{A}/v1/a")
    expect(HttpError, session.get_json, f"{A}/v1/b")
    assert session.failure == NodeFailure(A, "forbidden", 403)


# --------------------------------------------------------------------------- #
# 8. A walk is one node from start to end: the real trust walk, three hops, signed
# --------------------------------------------------------------------------- #

def _did(seed: int) -> str:
    return "did:ebsi:z" + b58btc_encode(bytes([1]) + bytes([seed]) * 16)


LEAF, MID, ROOT = _did(0xA1), _did(0xB2), _did(0xC3)
TYPES = ["OpenBadgeCredential"]


class Registry:
    """A SYNTHETIC Core API v1 registry: a signed LEAF -> MID -> ROOT chain, served by any node,
    every body tagged with the host that served it (the attribute ``id`` carries it)."""

    def __init__(self) -> None:
        suite = VcJwtProofSuite()
        self.suite = suite
        self.keys = {did: P256SigningKey.generate(kid=f"{did}#key-1")
                     for did in (LEAF, MID, ROOT)}
        badge = {
            "@context": ["https://www.w3.org/2018/credentials/v1"], "id": "urn:uuid:badge-1",
            "type": ["VerifiableCredential", "VerifiableAttestation", "OpenBadgeCredential"],
            "issuer": LEAF, "credentialSubject": {"id": "did:key:z6MkSubject"}}
        self.token = suite.sign(badge, signing_key=self.keys[LEAF])
        self.tokens = {LEAF: self._accreditation(MID, LEAF), MID: self._accreditation(ROOT, MID)}

    def _accreditation(self, by: str, subject: str) -> str:
        # MID accredits (a `…ToAccredit`), LEAF attests (a `…ToAttest`): the kind of the hop (#368)
        kind = ("VerifiableAccreditationToAccredit" if subject == MID
                else "VerifiableAccreditationToAttest")
        return self.suite.sign({
            "id": f"urn:uuid:acc-{subject[-4:]}",
            "type": ["VerifiableCredential", kind],
            "issuer": by,
            "credentialSubject": {"id": subject, "accreditedFor": [{"types": TYPES}]},
        }, signing_key=self.keys[by])

    def read(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        origin = f"https://{host}"
        prefix_d = "/v1/did-registry/identifiers/"
        prefix_i = "/v1/issuers-registry/issuers/"
        if path.startswith(prefix_d):
            did = path[len(prefix_d):]
            return R(200, json={
                "id": did, "verificationMethod": [{
                    "id": f"{did}#key-1", "type": "JsonWebKey2020", "controller": did,
                    "publicKeyJwk": self.keys[did].public_jwk()}],
                "assertionMethod": [f"{did}#key-1"]})
        if path.startswith(prefix_i):
            rest = path[len(prefix_i):].split("/")
            did = rest[0]
            base = f"{origin}{prefix_i}{did}"
            if len(rest) == 1:
                return R(200, json={
                    "did": did, "hasAttributes": True, "attributes": f"{base}/attributes"})
            if len(rest) == 2:
                tag = f"acc-{did[-4:]}"
                return R(200, json={
                    "total": 1, "items": [{"id": f"{tag}@{host}",
                                           "href": f"{base}/attributes/{tag}"}]})
            return R(200, json={"did": did, "attribute": {
                "body": self.tokens[did], "hash": rest[2],
                "issuerType": "TI" if did == LEAF else "TAO",
                "tao": MID if did == LEAF else ROOT, "rootTao": ROOT}})
        return R(404)


@pytest.fixture()
def registry():
    return Registry()


def badge_walk(registry: Registry):
    def walk(session: Any):
        return verify_ebsi_badge(
            registry.token, resolver=session.resolver, proof_suite=registry.suite,
            trust_anchors={ROOT})
    return walk


# the reads one full walk makes, in order, after the health probe
FULL_WALK = [
    f"/v1/did-registry/identifiers/{LEAF}",
    f"/v1/issuers-registry/issuers/{LEAF}",
    f"/v1/issuers-registry/issuers/{LEAF}/attributes",
    f"/v1/issuers-registry/issuers/{LEAF}/attributes/acc-{LEAF[-4:]}",
    f"/v1/did-registry/identifiers/{MID}",
    f"/v1/issuers-registry/issuers/{MID}",
    f"/v1/issuers-registry/issuers/{MID}/attributes",
    f"/v1/issuers-registry/issuers/{MID}/attributes/acc-{MID[-4:]}",
    f"/v1/did-registry/identifiers/{ROOT}",
]


def test_the_control_walk_on_one_healthy_node_reads_the_whole_chain_there(rig, registry):
    net = Net(default=node(read=registry.read))
    client = rig.build(net)
    badge = client.run(badge_walk(registry))
    assert badge.trusted is True and badge.chain is not None and badge.chain.anchor == ROOT
    assert [path for host, path in net.log] == ["/v1/alive", *FULL_WALK]
    assert {host for host, _ in net.log} == {host_of(A)}
    tags = [h.accreditation.attribute_id.split("@")[1] for h in badge.chain.hops]
    assert tags == [host_of(A)] * 2


def test_a_walk_that_loses_its_node_on_hop_two_restarts_on_the_next_from_hop_one(rig, registry):
    def hop_two_is_down(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v1/issuers-registry/issuers/{MID}":
            return R(503)
        return registry.read(request)
    net = Net(default=node(read=registry.read)).on(A, node(read=hop_two_is_down))
    client = rig.build(net)
    badge = client.run(badge_walk(registry))

    hosts_in_order = [host for host, _ in net.log]
    switch = hosts_in_order.index(host_of(B))
    assert set(hosts_in_order[:switch]) == {host_of(A)}      # A first,
    assert set(hosts_in_order[switch:]) == {host_of(B)}      # then B, and never back to A
    on_a = [path for host, path in net.log if host == host_of(A)]
    assert on_a[:1] == ["/v1/alive"] and on_a[1:6] == FULL_WALK[:5]    # A's reads up to the failure
    assert on_a[6:] == [FULL_WALK[5]] * FAST_RETRY.attempts    # and the failing read, retried
    on_b = [path for host, path in net.log if host == host_of(B)]
    assert on_b == ["/v1/alive", *FULL_WALK]                           # B: from hop 1, all of it
    # the result holds B-tagged data only
    assert badge.chain is not None
    tags = {h.accreditation.attribute_id.split("@")[1] for h in badge.chain.hops}
    assert tags == {host_of(B)}


def test_a_run_never_mixes_nodes_inside_an_attempt_under_any_single_failure_point(rig, registry):
    # fail node A at each read of the walk in turn: the attempt that succeeds is B's alone
    for position, path in enumerate(FULL_WALK):
        def down(request: httpx.Request, path=path) -> httpx.Response:
            if request.url.path == path:
                return R(503)
            return registry.read(request)
        net = Net(default=node(read=registry.read)).on(A, node(read=down))
        client = rig.build(net)
        badge = client.run(badge_walk(registry))
        assert badge.trusted is True, position
        reads = [(host, p) for host, p in net.log if p != "/v1/alive"]
        last_a = max(i for i, (h, _) in enumerate(reads) if h == host_of(A))
        assert all(h == host_of(B) for h, _ in reads[last_a + 1:]), position
        assert [p for h, p in reads if h == host_of(B)] == FULL_WALK, position


def test_the_bad_signature_on_one_node_is_a_content_error_not_a_failover(rig, registry):
    evil = Registry()                                       # another set of keys: same shapes
    net = Net(default=node(read=registry.read)).on(A, node(read=evil.read))
    client = rig.build(net)
    with pytest.raises(OpenvcError) as info:
        client.run(badge_walk(registry))
    assert not isinstance(info.value, (HttpError, NoHealthyNode))
    assert net.to(B) == []                                  # no second opinion is sought


# --------------------------------------------------------------------------- #
# 9. The recorded Core v1 chain, with and without the ES256K opt-in
# --------------------------------------------------------------------------- #

CORE = FIX / "core-v1"
GRNET = "https://api-preprod.ebsi.grnet.gr"
INCM = "https://api-preprod.ebsi.incm.pt"
ROOT_DID = "did:ebsi:zmaEptEHQRAmkJnFV6ki3io"                # the preprod RootTAO
FROZEN = dt.datetime(2026, 10, 16, 12, 0, 0, tzinfo=dt.timezone.utc)     # the recording's day


def _recorded_routes(directory: str) -> dict[str, tuple[bytes, str]]:
    manifest = json.loads((CORE / "MANIFEST.json").read_text(encoding="utf-8"))
    routes = {}
    for name, entry in manifest["files"].items():
        if name.startswith(directory + "/") and entry["status"] == 200:
            url = entry["request_url"]
            routes[url] = ((CORE / name).read_bytes(), entry["content_type"])
    return routes


def _serve_recorded(routes: dict[str, tuple[bytes, str]]):
    def read(request: httpx.Request) -> httpx.Response:
        found = routes.get(str(request.url))
        if found is None:
            return R(404)
        return R(200, content=found[0], headers={"content-type": found[1]})
    return read


class _FrozenDatetime(dt.datetime):
    @classmethod
    def now(cls, tz: Any = None) -> Any:                     # type: ignore[override]
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


@pytest.fixture()
def recorded_time(monkeypatch):
    """The recorded RootTAO is valid 2026-09-21 .. 2031-09-20; pin both clocks the VC-JWT lane
    reads so the golden does not depend on the day the suite runs."""
    stamp = FROZEN.timestamp()
    monkeypatch.setattr(jwt.api_jwt, "datetime", _FrozenDatetime)
    monkeypatch.setattr(_verify_common.time, "time", lambda: stamp)


def _preprod_client(rig: Rig):
    net = Net()
    net.on(GRNET, node(read=_serve_recorded(_recorded_routes("preprod-grnet"))))
    net.on(INCM, node(read=_serve_recorded(_recorded_routes("preprod-incm"))))
    return net, rig.build(net, make_result((GRNET, INCM), "preprod"))


def test_golden_recursive_trust_on_a_core_v1_root_needs_the_opt_in_and_does_not_fail_over(
        rig, recorded_time):
    root_token = json.loads((CORE / "preprod-grnet/attribute_0dc6a111.json").read_bytes()
                            )["attribute"]["body"]

    def badge(suite: VcJwtProofSuite):
        return lambda s: verify_ebsi_badge(root_token, resolver=s.resolver, proof_suite=suite,
                                           trust_anchors={ROOT_DID})
    # without the opt-in the ES256K root is refused: a content error that reaches the caller,
    # and the second node is not asked for its opinion
    net, client = _preprod_client(rig)
    expect(UnsupportedAlgorithm, client.run, badge(VcJwtProofSuite()))
    assert net.to(INCM) == [] and net.alive(INCM) == []

    # with it, the recorded root verifies on the first node
    net, client = _preprod_client(rig)
    result = client.run(badge(VcJwtProofSuite(allow_es256k=True)))
    assert result.trusted is True and result.issuer == ROOT_DID
    assert net.to(INCM) == []
    # and through verify_trust_chain: the one recorded hop is the root accrediting itself
    net, client = _preprod_client(rig)
    types = ["VerifiableCredential", "VerifiableAttestation",
             "VerifiableAuthorisationForTrustChain"]
    expect(AccreditationInvalid, client.run, lambda s: verify_trust_chain(
        ROOT_DID, types, resolver=s.resolver, proof_suite=VcJwtProofSuite(),
        anchors={"did:ebsi:zZeKyEJfUTGwajhNyNX928z"}))
    expect(TrustChainError, client.run, lambda s: verify_trust_chain(
        ROOT_DID, types, resolver=s.resolver, proof_suite=VcJwtProofSuite(allow_es256k=True),
        anchors={"did:ebsi:zZeKyEJfUTGwajhNyNX928z"}))              # the cycle, past the signature


def test_golden_two_recorded_nodes_fail_over_with_their_own_hosts_in_every_link(rig):
    # node A (grnet) is down for the registry; B (incm) serves ITS recording, whose links name
    # incm's host: the walk stays there. No ES256K here, so a single-level read.
    incm = node(read=_serve_recorded(_recorded_routes("preprod-incm")))
    net = Net().on(GRNET, node(read=respond(503))).on(INCM, incm)
    client = rig.build(net, make_result((GRNET, INCM), "preprod"))
    record = client.run(lambda s: s.resolver.issuer_record(ROOT_DID))
    assert record.did == ROOT_DID and record.accreditations[0].issuer_type == "RootTAO"
    reads = [str(r.url) for r in net.requests if r.url.path != "/v1/alive"]
    assert all(u.startswith(GRNET) for u in reads[:FAST_RETRY.attempts])
    assert all(u.startswith(INCM) for u in reads[FAST_RETRY.attempts:])
    assert len(reads) == FAST_RETRY.attempts + 3                  # issuer, attributes, attribute


# --------------------------------------------------------------------------- #
# 10. Through the real Trusted Nodes List chain
# --------------------------------------------------------------------------- #

def test_golden_end_to_end_from_the_recorded_list_to_a_run(rig):
    tnl = FIX / "tnl"
    now = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)                 # inside the list's window
    result = verify_node_list(
        tnl=(tnl / "tnl.json").read_bytes(), tnl_sig=(tnl / "tnl.json.sig").read_bytes(),
        keys=(tnl / "trusted-keys.json").read_bytes(),
        keys_sig=(tnl / "trusted-keys.json.sig").read_bytes(), environment="preprod",
        now=now, last_accepted_list=None, last_accepted_keys=None,
        anchor=EUROPEUM_KEY_LIST_ANCHOR)
    assert result.expires == datetime(2027, 1, 4, 13, 33, 18, tzinfo=UTC)
    assert len(result.nodes) == 12 and result.environment == "preprod"
    assert GRNET in {n.origin for n in result.nodes}

    net = Net(default=node(read=lambda r: R(200, json={"node": r.url.host})))
    rig.clock.now = now
    client = rig.build(net, result, policy=lambda os: sorted(os, key=lambda o: o != GRNET))
    assert client.environment == "preprod" and client.expires == result.expires
    assert set(client.origins) == {n.origin for n in result.nodes}
    assert client.check_health(GRNET) is True
    assert client.run(walk_tagged) == host_of(GRNET)
    assert [(r.method, str(r.url)) for r in net.requests] == [
        ("GET", f"{GRNET}/v1/alive"), ("GET", f"{GRNET}/v1/walk")]       # the probe was memoised

    rig.clock.now = result.expires - TICK
    assert client.run(walk_tagged) == host_of(GRNET)
    rig.clock.now = result.expires
    expect(NodeListExpired, client.run, walk_tagged)
    assert len(net.requests) == 3


# --------------------------------------------------------------------------- #
# 11. The resolved-address guard is on by default, and what that means
# --------------------------------------------------------------------------- #

def test_the_address_guard_is_on_by_default_and_can_be_switched_off(rig):
    rig.net = Net()
    on = for_nodes(make_result(), clock=rig.clock, decode_jwt=PEEK)
    off = for_nodes(make_result(), clock=rig.clock, decode_jwt=PEEK, address_guard=None)
    mine = AddressGuard(resolver=lambda host, port: ["93.184.216.34"])
    own = for_nodes(make_result(), clock=rig.clock, decode_jwt=PEEK, address_guard=mine)
    try:
        assert isinstance(on.http._address_guard, AddressGuard)
        assert off.http._address_guard is None and own.http._address_guard is mine
    finally:
        for c in (on, off, own):
            c.close()


def test_behind_an_environment_proxy_the_default_is_refused_not_silently_dropped(
        rig, monkeypatch):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://proxy:3128"})
    rig.net = Net()
    exc = expect(HttpAddressGuardUnavailable, for_nodes, make_result(), clock=rig.clock,
                 decode_jwt=PEEK)
    assert "address_guard" in str(exc)
    assert rig.built == 0
    client = rig.build(Net(), address_guard=None)           # the explicit opt-out works
    assert client.run(walk_tagged) == host_of(A)


def test_a_node_whose_name_points_at_a_private_address_is_failed_over_from(rig):
    answers = {host_of(A): ["10.0.0.5"], host_of(B): ["93.184.216.34"]}
    net = Net(default=node())
    client = rig.build(net, address_guard=AddressGuard(resolver=lambda h, p: answers[h]),
                       policy=lambda o: [A, B])
    assert client.run(walk_tagged) == host_of(B)
    # A resolved to a private address: nothing was sent there, the probe found it unhealthy.
    # B was reached at the validated address, with the name kept as Host.
    assert {r.headers["host"] for r in net.requests} == {host_of(B)}
    assert {r.url.host for r in net.requests} == {"93.184.216.34"}


def test_the_walk_level_address_refusal_is_a_failover_too(rig):
    flips = {"n": 0}

    def resolver(host: str, port: int) -> list[str]:
        if host == host_of(A):
            flips["n"] += 1
            return ["93.184.216.34"] if flips["n"] == 1 else ["127.0.0.1"]   # rebinding
        return ["1.1.1.1"]
    net = Net(default=node())
    client = rig.build(net, address_guard=AddressGuard(resolver=resolver),
                       policy=lambda o: [A, B])
    assert client.run(walk_tagged) == host_of(B)            # A passed the probe, then rebound
    sent = [(r.headers["host"], r.url.host, r.url.path) for r in net.requests]
    assert sent == [(host_of(A), "93.184.216.34", "/v1/alive"),        # A's probe, public
                    (host_of(B), "1.1.1.1", "/v1/alive"),
                    (host_of(B), "1.1.1.1", "/v1/walk")]               # A's walk was refused


def test_the_probe_reaches_only_the_first_validated_address_while_a_read_retries_on(rig):
    # What for_nodes and EbsiHttpClient.probe document: the guard hands out one address per
    # attempt, in the resolver's order, a read has several attempts and a probe has one. A node
    # whose first address cannot be reached is therefore unhealthy for the probe (and for
    # health_ttl_s) although a read reaches its second address. Pinned so that the day it is
    # changed, the three docstrings and the wiki are changed with it.
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "9.9.9.9":
            raise httpx.ConnectTimeout("no route", request=request)
        return node()(request)
    guard = AddressGuard(resolver=lambda h, p: ["9.9.9.9", "1.1.1.1"])
    client = rig.build(Net(default=handler), address_guard=guard, policy=lambda o: [A])
    assert client.check_health(A) is False
    assert seen == ["9.9.9.9"]                          # one attempt: the second address untried
    exc = expect(NoHealthyNode, client.run, walk_tagged)
    assert exc.failures == (NodeFailure(A, "unhealthy", None),) and seen == ["9.9.9.9"]
    session = client.session(A)                         # a read of the same node gets through
    assert session.get_json(f"{A}/v1/walk") == {"node": host_of(A)}
    assert seen == ["9.9.9.9", "9.9.9.9", "1.1.1.1"]


# --------------------------------------------------------------------------- #
# 12. Many threads, one client
# --------------------------------------------------------------------------- #

def test_threads_sharing_a_client_raise_only_documented_errors_and_never_share_a_resolver(rig):
    calls = {"n": 0}
    lock = threading.Lock()

    def flaky(request: httpx.Request) -> httpx.Response:
        with lock:
            calls["n"] += 1
            n = calls["n"]
        return R(503) if n % 3 == 0 else R(
            200, json={"node": request.url.host})
    net = Net(default=node(read=flaky))
    client = rig.build(net, policy=random_order, health_ttl_s=0.001)
    resolvers: list[int] = []
    outcomes: list[Any] = []

    def walk(session: Any) -> str:
        resolvers.append(id(session.resolver))
        return walk_tagged(session)

    def worker() -> None:
        for _ in range(15):
            try:
                outcomes.append(client.run(walk))
            except NoHealthyNode as exc:
                outcomes.append(exc)
            except BaseException as exc:                      # anything else is a failure
                outcomes.append(("unexpected", exc))
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not [o for o in outcomes if isinstance(o, tuple)], outcomes
    assert all(isinstance(o, NoHealthyNode) or o in {host_of(x) for x in ORIGINS}
               for o in outcomes)
    assert len(outcomes) == 8 * 15
    # every attempt builds its own resolver (checked directly: two sessions never share one)
    s1, s2 = client.session(A), client.session(A)
    assert s1.resolver is not s2.resolver and s1 is not s2


# --------------------------------------------------------------------------- #
# 13. What a dead node costs: the measured worst case
# --------------------------------------------------------------------------- #

def _dead_walk_seconds(monkeypatch, rig: Rig, retry: RetryPolicy, *, probe_passes: bool) -> float:
    """Virtual seconds one ``run`` spends when every candidate is dead: each connection attempt
    times out after ``timeout_s`` (10 s) and each backoff sleeps at its ceiling."""
    fake = FakeTime()
    monkeypatch.setattr(ebsi_http, "time", fake)

    def dead(request: httpx.Request) -> httpx.Response:
        fake.now += 10.0                                     # the connect timeout elapses
        raise httpx.ConnectTimeout("timed out")
    read = dead
    alive = alive_ok if probe_passes else dead
    net = Net(default=node(read=read, alive=alive))
    # the jitter is random; pin it at its ceiling so the figure is the worst case
    monkeypatch.setattr(ebsi_http.random, "uniform", lambda a, b: b)
    client = rig.build(net, retry=retry, timeout_s=10.0)
    start = fake.now
    expect(NoHealthyNode, client.run, walk_tagged)
    return fake.now - start


def test_the_worst_case_walk_time_is_bounded_and_recorded(rig, monkeypatch):
    # Every node passes its probe at once and then times out on each attempt of the walk's
    # first read: probe (instant) + attempts * 10 s + the backoff sleeps, per node, times
    # max_nodes (3). A blackholed probe is cheaper: one attempt of 10 s per node, no retry.
    default = _dead_walk_seconds(monkeypatch, rig, RetryPolicy(), probe_passes=True)
    node_default = _dead_walk_seconds(monkeypatch, rig, NODE_RETRY, probe_passes=True)
    blackholed = _dead_walk_seconds(monkeypatch, rig, NODE_RETRY, probe_passes=False)
    # RetryPolicy(): 3 attempts: 30 s + 0.25 + 0.5 = 30.75 s per node -> 92.25 s for three nodes
    assert default == pytest.approx(3 * (3 * 10.0 + 0.25 + 0.5))
    # NODE_RETRY: 2 attempts: 20 s + 0.25 s = 20.25 s per node -> 60.75 s for three nodes
    assert node_default == pytest.approx(3 * (2 * 10.0 + 0.25))
    assert blackholed == pytest.approx(3 * 10.0)
    assert NODE_RETRY.attempts == 2 and RetryPolicy().attempts == 3


def test_for_nodes_defaults_to_two_attempts_and_for_ebsi_is_untouched(rig):
    rig.net = Net()
    client = for_nodes(make_result(), clock=rig.clock, decode_jwt=PEEK, address_guard=None)
    try:
        assert client.http._retry.attempts == 2
    finally:
        client.close()
    plain = EbsiHttpClient(allowed_hosts={host_of(A)})
    try:
        assert plain._retry.attempts == 3
    finally:
        plain.close()


def test_the_context_manager_closes_the_pool(rig):
    client = rig.build()
    with client as same:
        assert same is client
    assert client.http._client.is_closed
