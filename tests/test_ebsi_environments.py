"""
tests/test_ebsi_environments.py — the EBSI environment-name table (#325).

``for_ebsi(environment)`` seeds the https-only host allow-list of an ``EbsiHttpClient`` from
a name. These tests pin what each name means, what the default is, and how a name the table
does not hold is refused. Nothing here touches the network: a client's transport is replaced
by ``httpx.MockTransport``. No bytes are parsed, so there is no golden fixture and no fuzzing:
``environment`` is caller configuration (it can arrive through ``OPENVC_EBSI_ENV``).

Section A is the baseline, written and green on the code as it stood before #325, so any
later change to a name, a host or the default is a conscious edit of a pin.
"""
from __future__ import annotations

import pytest

httpx = pytest.importorskip("httpx")

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
    assert EBSI_HOSTS == {
        "pilot": PILOT_HOST,
        "conformance": CONFORMANCE_HOST,
        "production": PRODUCTION_HOST,
    }
    assert EBSI_BASE == {
        "pilot": f"https://{PILOT_HOST}",
        "conformance": f"https://{CONFORMANCE_HOST}",
        "production": f"https://{PRODUCTION_HOST}",
    }


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


@pytest.mark.parametrize("bad", ["nope", "Pilot", "", None, 5])
def test_an_unknown_name_is_a_bare_value_error_today(bad):
    with pytest.raises(ValueError) as info:
        for_ebsi(bad)
    assert type(info.value) is ValueError


@pytest.mark.parametrize("bad", [[], {}])
def test_an_unhashable_name_is_a_bare_type_error_today(bad):
    with pytest.raises(TypeError) as info:
        for_ebsi(bad)
    assert type(info.value) is TypeError


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
