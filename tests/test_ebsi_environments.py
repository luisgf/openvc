"""
tests/test_ebsi_environments.py — the EBSI environment-name table (#325, Part 1).

``for_ebsi(environment)`` seeds the https-only host allow-list of an ``EbsiHttpClient`` from
a name. These tests pin what each name means, what the default is, and how a name the table
does not hold is refused. Nothing here touches the network: a client's transport is replaced
by ``httpx.MockTransport``. No bytes are parsed, so there is no golden fixture and no fuzzing:
``environment`` is caller configuration (it can arrive through ``OPENVC_EBSI_ENV``).

Section A is the baseline, written and green on the code as it stood before #325 (the commit
before the implementation), so a later change to a name, a host or the default is a conscious
edit of a pin. The two baseline pins #325 had to move are marked. Section B is the new
behaviour, refusals first, then the controls.
"""
from __future__ import annotations

import collections
import dataclasses
import enum
import inspect
import os
import subprocess
import sys
import warnings
from types import MappingProxyType

import pytest

httpx = pytest.importorskip("httpx")

from openvc.errors import OpenvcError  # noqa: E402
from openvc_ebsi import environments  # noqa: E402
from openvc_ebsi import http as ebsi_http  # noqa: E402
from openvc_ebsi.environments import (  # noqa: E402
    ENVIRONMENTS,
    LEGACY_PILOT_BASE,
    EbsiEnvironment,
    fixed_hosts,
)
from openvc_ebsi.errors import EbsiError, UnknownEbsiEnvironment  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    EBSI_BASE,
    EBSI_HOSTS,
    HttpForbiddenHost,
    HttpTransientExhausted,
    RetryPolicy,
    for_ebsi,
)
from openvc_ebsi.versioning import DidEbsiResolver  # noqa: E402

PILOT_HOST = "api-pilot.ebsi.eu"
CONFORMANCE_HOST = "api-conformance.ebsi.eu"
PRODUCTION_HOST = "api.ebsi.eu"

# Zero backoff so the retry loop does not sleep.
FAST_RETRY = RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0)


def _ok(request):
    return httpx.Response(200, json={"ok": True})


def _mock(client, handler=_ok):
    """Replace the client's transport: no request leaves the process."""
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


# --------------------------------------------------------------------------- #
# A. The baseline (green before #325)
# --------------------------------------------------------------------------- #

def test_the_host_and_base_tables_hold_exactly_the_current_names():
    # MOVED by #325: the baseline held the first three entries only; ``legacy-pilot`` is the
    # fourth, a conscious edit (dict equality, so any further key is one too).
    assert EBSI_HOSTS == {
        "pilot": PILOT_HOST,
        "conformance": CONFORMANCE_HOST,
        "production": PRODUCTION_HOST,
        "legacy-pilot": PILOT_HOST,
    }
    assert EBSI_BASE == {
        "pilot": f"https://{PILOT_HOST}",
        "conformance": f"https://{CONFORMANCE_HOST}",
        "production": f"https://{PRODUCTION_HOST}",
        "legacy-pilot": f"https://{PILOT_HOST}",
    }
    assert type(EBSI_HOSTS) is dict and type(EBSI_BASE) is dict      # same type as before


@pytest.mark.parametrize("call", [
    pytest.param(lambda **kw: for_ebsi(**kw), id="default"),
    pytest.param(lambda **kw: for_ebsi("pilot", **kw), id="pilot"),
])
def test_the_default_and_pilot_seed_exactly_the_pilot_host(call):
    with call() as http:
        assert http._allowed == {PILOT_HOST}


@pytest.mark.parametrize("name,host", [
    ("pilot", PILOT_HOST),
    ("conformance", CONFORMANCE_HOST),
    ("production", PRODUCTION_HOST),
])
def test_each_name_seeds_exactly_its_own_host(name, host):
    with for_ebsi(name) as http:
        assert http._allowed == {host}


def test_extra_hosts_are_merged_and_lower_cased():
    with for_ebsi("pilot", extra_hosts={"Status.Example.ORG"}) as http:
        assert http._allowed == {PILOT_HOST, "status.example.org"}


@pytest.mark.parametrize("name,other", [
    ("pilot", CONFORMANCE_HOST),
    ("pilot", PRODUCTION_HOST),
    ("conformance", PILOT_HOST),
    ("conformance", PRODUCTION_HOST),
    ("production", PILOT_HOST),
    ("production", CONFORMANCE_HOST),
])
def test_a_host_of_another_environment_is_refused_before_any_io(name, other):
    calls = []

    def handler(request):
        calls.append(request)
        return _ok(request)

    with _mock(for_ebsi(name), handler) as http:
        with pytest.raises(HttpForbiddenHost):
            http.get_json(f"https://{other}/anything")
    assert calls == []


def test_the_resolver_default_base_is_the_pilot_base():
    resolver = DidEbsiResolver(lambda url: {}, lambda token: {})
    assert resolver._base == EBSI_BASE["pilot"] == "https://api-pilot.ebsi.eu"


def test_production_first_request_with_a_connect_error_exhausts_the_retry_budget():
    """MEASURED on d5dd0e5: the name builds a client, and the first request fails closed but
    late, as ``HttpTransientExhausted`` after the whole retry budget (an ``httpx.ConnectError``
    is a ``TransportError``, which ``get_json`` retries). No certificate or connection problem
    is simulated more precisely than that; the real host's behaviour is ADR-0009's."""
    calls = []

    def handler(request):
        calls.append(request.url.host)
        raise httpx.ConnectError("no route to host", request=request)

    with _mock(for_ebsi("production", retry=FAST_RETRY), handler) as http:
        with pytest.raises(HttpTransientExhausted) as info:
            http.get_json(f"https://{PRODUCTION_HOST}/v1/alive")
    assert type(info.value) is HttpTransientExhausted
    assert calls == [PRODUCTION_HOST] * FAST_RETRY.attempts


# --------------------------------------------------------------------------- #
# B. Refusals: a name the table does not hold is UnknownEbsiEnvironment
# --------------------------------------------------------------------------- #

class _RaisingRepr:
    def __repr__(self):
        raise RuntimeError("repr must not be called")

    __str__ = __repr__


class _HostileStr(str):
    """A ``str`` whose hashing, equality and repr all raise: whatever reads it through the
    subclass, rather than as the characters it holds, fails."""

    def __hash__(self):
        raise RuntimeError("hash must not be called")

    def __eq__(self, other):
        raise RuntimeError("eq must not be called")

    def __repr__(self):
        raise RuntimeError("repr must not be called")

    __str__ = __repr__


class _ClaimsToBeStr:
    """Not a ``str``, but its ``__class__`` says it is: ``isinstance(x, str)`` is true for it
    and ``str.__str__(x)`` raises a bare ``TypeError``."""

    @property
    def __class__(self):
        return str


class _StrClaimingToBeInt(str):
    """A real ``str`` whose ``__class__`` lies the other way."""

    @property
    def __class__(self):
        return int


# The seven inputs of the acceptance list, then more shapes of "not a name".
SEVEN = [
    pytest.param("nope", id="unknown"),
    pytest.param("Pilot", id="wrong-case"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
    pytest.param(5, id="int"),
    pytest.param([], id="list-unhashable"),
    pytest.param({}, id="dict-unhashable"),
]
MORE = [
    pytest.param(" pilot", id="leading-space"),
    pytest.param("pilot ", id="trailing-space"),
    pytest.param("PILOT", id="upper"),
    pytest.param("legacy_pilot", id="underscore"),
    pytest.param("Legacy-Pilot", id="legacy-wrong-case"),
    pytest.param("pilot\x00", id="nul"),
    pytest.param(b"pilot", id="bytes"),
    pytest.param(("pilot",), id="tuple"),
    pytest.param(object(), id="object"),
    pytest.param(True, id="bool"),
    pytest.param(1.5, id="float"),
    # Not a `str`, yet it hashes and compares equal to a known name, so the dictionary lookup
    # of v1.36.0 accepted it. The `str` type check refuses it: a recorded behaviour
    # change (pass `str(value)`).
    pytest.param(collections.UserString("pilot"), id="user-string-holding-a-known-name"),
    # `isinstance` honours `__class__`, so it would let this through to a bare TypeError.
    pytest.param(_ClaimsToBeStr(), id="class-claims-str"),
]


@pytest.mark.parametrize("bad", SEVEN + MORE)
def test_a_name_the_table_does_not_hold_is_unknown_ebsi_environment(bad):
    with pytest.raises(Exception) as info:
        for_ebsi(bad)
    exc = info.value
    assert type(exc) is UnknownEbsiEnvironment
    assert isinstance(exc, ValueError)               # what it used to be: `except ValueError` works
    assert isinstance(exc, EbsiError)
    assert isinstance(exc, OpenvcError)
    assert not isinstance(exc, TypeError)
    assert str(exc).startswith("unknown EBSI environment: ")
    for name in ENVIRONMENTS:                         # the message lists what is accepted
        assert name in str(exc)


@pytest.mark.parametrize("bad", SEVEN)
def test_except_value_error_still_catches_a_refused_name(bad):
    caught = None
    try:
        for_ebsi(bad)
    except ValueError as exc:
        caught = exc
    assert type(caught) is UnknownEbsiEnvironment


@pytest.mark.parametrize("bad", SEVEN + MORE)
def test_a_refused_name_builds_no_client(bad, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("an EbsiHttpClient was constructed for a refused name")

    monkeypatch.setattr(ebsi_http, "EbsiHttpClient", boom)
    with pytest.raises(UnknownEbsiEnvironment):
        for_ebsi(bad)


def test_the_message_is_bounded_for_a_huge_string():
    huge = "x" * 10_000
    with pytest.raises(UnknownEbsiEnvironment) as info:
        for_ebsi(huge)
    assert huge not in str(info.value)
    assert "x" * 300 not in str(info.value)
    assert len(str(info.value)) < 600
    assert "10000 chars" in str(info.value)


def test_a_value_whose_repr_raises_does_not_raise_from_the_raise():
    with pytest.raises(UnknownEbsiEnvironment) as info:
        for_ebsi(_RaisingRepr())
    assert type(info.value) is UnknownEbsiEnvironment
    assert str(info.value).startswith("unknown EBSI environment: _RaisingRepr (known: ")


def test_a_str_subclass_is_read_as_its_characters_not_through_its_own_methods():
    # `__hash__` / `__eq__` / `__repr__` of the subclass all raise: a bare RuntimeError would
    # escape if the name were looked up or shown through them.
    with pytest.raises(UnknownEbsiEnvironment) as info:
        for_ebsi(_HostileStr("nope"))
    assert type(info.value) is UnknownEbsiEnvironment
    assert "nope" in str(info.value)


def test_a_str_subclass_holding_a_known_name_is_that_name():
    # What is checked is what is used: the plain characters. Control for the case above.
    with for_ebsi(_HostileStr("pilot")) as http:
        assert http._allowed == {PILOT_HOST}


def test_a_real_str_is_read_as_its_characters_whatever_its_class_property_says():
    # Control for `class-claims-str`: the type is what counts, in both directions.
    with for_ebsi(_StrClaimingToBeInt("legacy-pilot")) as http:
        assert http._allowed == {PILOT_HOST}
    with pytest.raises(UnknownEbsiEnvironment) as info:
        for_ebsi(_StrClaimingToBeInt("nope"))
    assert type(info.value) is UnknownEbsiEnvironment


def test_a_str_enum_member_still_selects_its_environment():
    # A (str, Enum) member is a str subclass callers may already pass: it keeps working.
    class Env(str, enum.Enum):
        LEGACY = "legacy-pilot"
        BOGUS = "bogus"

    with for_ebsi(Env.LEGACY) as http:
        assert http._allowed == {PILOT_HOST}
    with pytest.raises(UnknownEbsiEnvironment):
        for_ebsi(Env.BOGUS)


# --------------------------------------------------------------------------- #
# B. Controls: the new name, the new default, and what stays silent
# --------------------------------------------------------------------------- #

def test_legacy_pilot_seeds_the_same_allow_list_as_pilot():
    with for_ebsi("legacy-pilot") as legacy, for_ebsi("pilot") as pilot, for_ebsi() as default:
        assert legacy._allowed == {PILOT_HOST}
        assert legacy._allowed == pilot._allowed == default._allowed


def test_legacy_pilot_row_and_base():
    assert EBSI_HOSTS["legacy-pilot"] == "api-pilot.ebsi.eu"
    assert EBSI_BASE["legacy-pilot"] == "https://api-pilot.ebsi.eu"
    assert ENVIRONMENTS["legacy-pilot"] == EbsiEnvironment("legacy-pilot", "api-pilot.ebsi.eu")


def test_the_default_environment_is_legacy_pilot():
    # The allow-lists of `pilot` and `legacy-pilot` are identical by design, so no allow-list
    # test can tell the two defaults apart: the signature is what pins the flip.
    assert inspect.signature(for_ebsi).parameters["environment"].default == "legacy-pilot"


def test_legacy_pilot_client_refuses_the_hosts_of_the_other_environments():
    calls = []

    def handler(request):
        calls.append(request)
        return _ok(request)

    with _mock(for_ebsi("legacy-pilot"), handler) as http:
        for other in (CONFORMANCE_HOST, PRODUCTION_HOST, "api-pilot.ebsi.eu.evil.example"):
            with pytest.raises(HttpForbiddenHost):
                http.get_json(f"https://{other}/anything")
        assert http.get_json(f"https://{PILOT_HOST}/did-registry/v5/identifiers/x") == {"ok": True}
    assert [r.url.host for r in calls] == [PILOT_HOST]


def test_legacy_pilot_merges_extra_hosts_like_pilot():
    with for_ebsi("legacy-pilot", extra_hosts={"Status.Example.ORG"}) as http:
        assert http._allowed == {PILOT_HOST, "status.example.org"}


def test_building_a_client_from_any_known_name_is_silent():
    """Pins the compatibility options taken in #325, so a later warning is a conscious edit:
    ``pilot`` is NOT deprecated (switch 2a), and ``conformance`` and ``production`` are kept
    and documented, not warned about (switch 3a). The default and ``legacy-pilot`` are silent."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for call in (
            lambda: for_ebsi(),
            lambda: for_ebsi("legacy-pilot"),
            lambda: for_ebsi("pilot"),
            lambda: for_ebsi("conformance"),
            lambda: for_ebsi("production"),
        ):
            call().close()


def test_the_resolver_default_base_is_the_table_row():
    resolver = DidEbsiResolver(lambda url: {}, lambda token: {})
    assert resolver._base == EBSI_BASE["legacy-pilot"] == ENVIRONMENTS["legacy-pilot"].base
    assert resolver._base == LEGACY_PILOT_BASE == "https://api-pilot.ebsi.eu"
    default = inspect.signature(DidEbsiResolver.__init__).parameters["base"].default
    assert default == LEGACY_PILOT_BASE


# --------------------------------------------------------------------------- #
# B. The table itself
# --------------------------------------------------------------------------- #

def test_the_table_holds_the_four_names_and_is_read_only():
    assert list(ENVIRONMENTS) == ["pilot", "conformance", "production", "legacy-pilot"]
    assert all(name == env.name for name, env in ENVIRONMENTS.items())
    assert ENVIRONMENTS["pilot"].fixed_host == ENVIRONMENTS["legacy-pilot"].fixed_host
    with pytest.raises(TypeError):
        ENVIRONMENTS["staging"] = EbsiEnvironment("staging", "api-staging.example.org")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ENVIRONMENTS["pilot"].fixed_host = "api.evil.example"


def test_every_fixed_host_is_a_bare_lower_case_host_name():
    for env in ENVIRONMENTS.values():
        host = env.fixed_host
        assert host is not None
        assert host == host.lower()
        assert host.endswith(".ebsi.eu")
        assert not any(c in host for c in ":/@?#\\ ")
        assert env.base == f"https://{host}"


def test_a_row_with_no_fixed_host_has_no_base_and_is_not_projected(monkeypatch):
    node = EbsiEnvironment("node-derived", None)
    assert node.base is None
    table = MappingProxyType({**ENVIRONMENTS, "node-derived": node})
    monkeypatch.setattr(environments, "ENVIRONMENTS", table)
    projected = fixed_hosts()
    assert "node-derived" not in projected
    assert projected == dict(EBSI_HOSTS)


def test_the_http_tables_are_the_projection_of_the_environment_table():
    assert EBSI_HOSTS == fixed_hosts()
    assert EBSI_BASE == {name: f"https://{host}" for name, host in EBSI_HOSTS.items()}


# --------------------------------------------------------------------------- #
# B. The names are available without the `ebsi` extra
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("module", ["openvc_ebsi.environments", "openvc_ebsi.errors",
                                    "openvc_ebsi.versioning"])
def test_the_name_table_imports_with_httpx_blocked(module, tmp_path):
    code = (
        "import sys\n"
        "sys.modules['httpx'] = None\n"                  # `import httpx` now raises ImportError
        f"import {module}\n"
        "from openvc_ebsi.environments import ENVIRONMENTS\n"
        "print(','.join(ENVIRONMENTS))\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    done = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "pilot,conformance,production,legacy-pilot"
