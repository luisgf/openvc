"""
tests/test_ebsi_core_v1.py — EBSI Core API v1 adapters and their recorded vectors (#321).

``DidRegistryCoreV1`` and ``TirCoreV1`` (registered ``"core-v1"``) read the EBSI Core API v1:
``/v1/did-registry/identifiers/{did}`` and ``/v1/issuers-registry/issuers/{did}`` on the
answering node's own origin. The recorded responses live in ``tests/fixtures/ebsi/core-v1/``
(provenance in its README, one ``MANIFEST.json`` entry per file); the legacy pilot (v5)
vectors in ``tests/fixtures/ebsi/*.json`` stay untouched. The Problem Details ``type`` on
``HttpError`` has its own file, ``test_ebsi_http_problem_type.py``.

Order: the vectors are what the nodes sent; the registry names and the URLs; the
``contract_address`` configuration; hostile DIDs and malformed bodies; the origin pin
(per node, and the shared walk's guards for BOTH TIR lanes by parametrisation); the
contract-address walk; the ES256K pin; the goldens; fuzzing.

Negatives first, each asserting the exact class (``type(exc) is X`` or ``match=``) and, where
requests matter, how many were made, so a test cannot pass on an earlier failure. The hostile
cases use a RESOLVABLE issuer (a recorded one served by a stub), never ``did:example``.
Self-contained: ``tests/`` is not a package, so the small stub harness is copied.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

httpx = pytest.importorskip("httpx")

from openvc.did.base import DidResolutionError  # noqa: E402
from openvc.errors import OpenvcError  # noqa: E402
from openvc.proof.errors import UnsupportedAlgorithm  # noqa: E402
from openvc.proof.vc_jwt import VcJwtProofSuite  # noqa: E402
from openvc_ebsi.errors import MalformedRegistryResponse  # noqa: E402
from openvc_ebsi.http import EbsiHttpClient, HttpNotFound  # noqa: E402
from openvc_ebsi.models import IssuerRecord  # noqa: E402
from openvc_ebsi.trust import AccreditationInvalid, verify_trust_chain  # noqa: E402
from openvc_ebsi.verify import evaluate_issuer_trust  # noqa: E402
from openvc_ebsi.versioning import (  # noqa: E402
    DID_REGISTRY_ADAPTERS,
    TIR_ADAPTERS,
    DidEbsiResolver,
    DidRegistryCoreV1,
    DidRegistryV5,
    TirAdapter,
    TirCoreV1,
    TirV5,
    _on_contract_address,
    did_registry_adapter,
    tir_adapter,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi" / "core-v1"
LEGACY_FIXTURES = FIXTURES.parent
# Not recorded responses: the manifest itself and the README that explains it.
NOT_RECORDED = {"MANIFEST.json", "README.md"}
# What EbsiHttpClient sends (ADR-0001 D10), and what every recording that did not override it
# sent. A test below pins the client's string to this one.
CLIENT_ACCEPT = "application/json, application/did+ld+json, */*;q=0.1"

GRNET = "https://api-preprod.ebsi.grnet.gr"
INCM = "https://api-preprod.ebsi.incm.pt"
PROD = "https://api.ebsi.iti.gr"
DID = "did:ebsi:zmaEptEHQRAmkJnFV6ki3io"            # the preprod RootTAO (two nodes recorded)
OTHER_DID = "did:ebsi:zZeKyEJfUTGwajhNyNX928z"      # well-formed, any other (the legacy fixture's)
PROD_DID = "did:ebsi:z262SoSjWAqmXpaGmzqGnJoc"      # the one seeded prod issuer
ATTRIBUTE_ID = "0dc6a11138b6f6df1127006fdd4c2122f2b7f64afada725ae2942ae76faef262"
PROD_ATTRIBUTE_ID = "030c5a3d324c9787cebddae40edd56b320f82306cce0ab23bafeacc6e345d7cc"
# The addresses the preprod node publishes on /<registry>/details (contract-address/).
DID_REGISTRY_ADDRESS = "0xd6ad334a8B230266AA8CDCCd38f42e67Fa5a52De"
ISSUERS_REGISTRY_ADDRESS = "0xF18307A7d81644Ae1478263D697Ec08C65fF70BD"

PEEK = VcJwtProofSuite().peek_claims


def _manifest() -> dict:
    return json.loads((FIXTURES / "MANIFEST.json").read_bytes())


def _read(rel: str) -> bytes:
    return (FIXTURES / rel).read_bytes()


def _rec(rel: str) -> dict:
    """A recorded body, parsed."""
    return json.loads(_read(rel))


def _url(rel: str) -> str:
    """The URL a recorded file was requested at."""
    return _manifest()["files"][rel]["request_url"]


# --------------------------------------------------------------------------- #
# Harness (copied from test_ebsi_origin_default_port.py: tests/ is not a package)
# --------------------------------------------------------------------------- #

class StubFetch:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url: str) -> Any:
        self.calls.append(url)
        try:
            return self.routes[url]
        except KeyError:
            raise HttpNotFound("no stub route", url=url) from None


def _core_resolver(fetch: Callable[[str], Any], base: str, *,
                   didr: DidRegistryCoreV1 | None = None,
                   tir: TirCoreV1 | None = None) -> DidEbsiResolver:
    """A resolver on the Core v1 lane: base, didr and tir are selected together."""
    return DidEbsiResolver(fetch, PEEK, base=base, didr=didr or DidRegistryCoreV1(),
                           tir=tir or TirCoreV1())


# --------------------------------------------------------------------------- #
# The vectors are what the nodes sent
# --------------------------------------------------------------------------- #

def test_every_recorded_file_is_in_the_manifest_and_nothing_else_is():
    on_disk = {p.relative_to(FIXTURES).as_posix()
               for p in FIXTURES.rglob("*") if p.is_file()} - NOT_RECORDED
    assert on_disk == set(_manifest()["files"])


@pytest.mark.parametrize("rel", sorted(_manifest()["files"]))
def test_recorded_file_matches_its_manifest_hash(rel):
    entry = _manifest()["files"][rel]
    data = _read(rel)
    assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    assert len(data) == entry["bytes"]


@pytest.mark.parametrize("rel", sorted(_manifest()["files"]))
def test_manifest_entry_is_complete_and_consistent(rel):
    entry = _manifest()["files"][rel]
    assert set(entry) == {"accept", "bytes", "content_type", "node", "request_url",
                          "retrieved", "sha256", "status", "user_agent"}
    url = urlsplit(entry["request_url"])
    assert url.scheme == "https" and url.hostname == entry["node"]
    assert url.path.startswith("/v1/")                     # Core v1 paths, never a legacy one
    assert isinstance(entry["status"], int) and not isinstance(entry["status"], bool)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["retrieved"])
    assert entry["user_agent"].startswith("openvc-core/")
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    # a body the node sent as JSON is JSON; the bytes are kept exactly as received, so there
    # is no trailing newline of ours either
    assert isinstance(json.loads(_read(rel)), dict)
    assert not _read(rel).endswith(b"\n")


def test_the_clients_accept_is_the_string_the_vectors_were_recorded_with():
    with EbsiHttpClient(allowed_hosts={"api-preprod.ebsi.grnet.gr"}) as client:
        assert client._client.headers["Accept"] == CLIENT_ACCEPT
        assert client._client.headers["User-Agent"].startswith("openvc-core/")
    overridden = {rel for rel, e in _manifest()["files"].items() if e["accept"] != CLIENT_ACCEPT}
    # the two deliberate overrides, and only those (README, "How they were recorded")
    assert overridden == {"negotiation/preprod-grnet_did_document_did+json.json",
                          "errors/preprod-grnet_406_unsatisfiable-accept.json"}


# --------------------------------------------------------------------------- #
# Registry names: "core-v1" and nothing else new; the defaults do not move
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("version", ["v1", "core-v2", "", "CORE-V1", "core-v1 ", "Core-v1", "v6"])
def test_an_unknown_adapter_version_is_a_value_error_on_both_registries(version):
    for factory in (did_registry_adapter, tir_adapter):
        with pytest.raises(ValueError, match="no .* adapter for"):
            factory(version)


def test_the_defaults_stay_the_legacy_lane():
    assert type(did_registry_adapter()) is DidRegistryV5
    assert type(tir_adapter()) is TirV5
    resolver = DidEbsiResolver(StubFetch({}), PEEK)
    assert type(resolver._didr) is DidRegistryV5 and type(resolver._tir) is TirV5
    assert resolver._base == "https://api-pilot.ebsi.eu"


def test_core_v1_is_registered_by_that_name_on_both_registries_and_nowhere_else():
    assert type(did_registry_adapter("core-v1")) is DidRegistryCoreV1
    assert type(tir_adapter("core-v1")) is TirCoreV1
    assert DID_REGISTRY_ADAPTERS["core-v1"] is DidRegistryCoreV1
    assert TIR_ADAPTERS["core-v1"] is TirCoreV1
    assert set(DID_REGISTRY_ADAPTERS) == {"v5", "core-v1"}
    assert set(TIR_ADAPTERS) == {"v4", "v5", "core-v1"}
    assert DidRegistryCoreV1.version == TirCoreV1.version == "core-v1"


def test_the_core_v1_walk_is_shared_not_copied_and_not_inherited_from_v5():
    assert TirCoreV1._iter_attribute_items is TirV5._iter_attribute_items
    assert TirCoreV1.parse_issuer is TirV5.parse_issuer
    assert not issubclass(TirCoreV1, TirV5) and not issubclass(TirV5, TirCoreV1)
    assert not issubclass(DidRegistryCoreV1, DidRegistryV5)


# --------------------------------------------------------------------------- #
# The URLs: /v1, never the registry key
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("base", [GRNET, INCM, PROD, "https://api-preprod.ebsi.grnet.gr:443"])
def test_core_v1_urls_are_the_documented_ones(base):
    didr, tir = DidRegistryCoreV1(), TirCoreV1()
    assert didr.identifiers_url(base, DID) == f"{base}/v1/did-registry/identifiers/{DID}"
    assert tir.issuer_url(base, DID) == f"{base}/v1/issuers-registry/issuers/{DID}"
    # the path segment is `v1`; the registry key `core-v1` is not part of any URL
    assert "core-v1" not in didr.identifiers_url(base, DID)
    assert "core-v1" not in tir.issuer_url(base, DID)


def test_the_legacy_layout_is_not_the_core_layout():
    didr5, tir5 = DidRegistryV5(), TirV5()
    assert didr5.identifiers_url(GRNET, DID) == f"{GRNET}/did-registry/v5/identifiers/{DID}"
    assert tir5.issuer_url(GRNET, DID) == f"{GRNET}/trusted-issuers-registry/v5/issuers/{DID}"


def test_the_recorded_requests_are_the_urls_the_adapters_build():
    for node, base in (("preprod-grnet", GRNET), ("preprod-incm", INCM)):
        assert DidRegistryCoreV1().identifiers_url(base, DID) == _url(f"{node}/did_document.json")
        assert TirCoreV1().issuer_url(base, DID) == _url(f"{node}/issuer.json")
    assert DidRegistryCoreV1().identifiers_url(PROD, PROD_DID) == _url("prod-iti/did_document.json")
    assert TirCoreV1().issuer_url(PROD, PROD_DID) == _url("prod-iti/issuer.json")


# --------------------------------------------------------------------------- #
# contract_address: configuration only, and it cannot reshape the URL
# --------------------------------------------------------------------------- #

BAD_ADDRESSES = [
    "", " ", "   ", "\t", "\n", "0x0\n", "0xabc\n\n",
    "0xab\x00cd", "0xab\x1fcd", "0xab\x7fcd",                 # control characters
    "0x\u00e9", "0x\uff10\uff11", "0x\u202e", "\u0660",       # non-ASCII (incl. digit lookalikes)
    "0xab/cd", "0xab?cd", "0xab#cd", "0xab&cd", "0xab=cd", "0xab%cd", "0xab cd",
    "/", "?", "#", "&", "=", "%", " 0xabc", "0xabc ", "../x", "./",
    "0xab%2fcd", "0xab\\cd", "0xab:cd", "0xab,cd", "0xab;cd", "0xab+cd",
    "a" * 129, "a" * 1000,
]
BAD_ADDRESS_TYPES = [0, 1, 1.5, True, False, b"0xabc", bytearray(b"0xabc"), ["0xabc"],
                     ("0xabc",), {"a": 1}, object(), b""]
# "." and ".." are admitted by the bound but inert: they sit in the QUERY, which httpx never
# resolves as a path, so they cannot reach another route.
GOOD_ADDRESSES = [DID_REGISTRY_ADDRESS, ISSUERS_REGISTRY_ADDRESS, "a", "A.b_c-d", "0x" + "f" * 40,
                  "a" * 128, "0", "a.b", "-", "_", ".", ".."]
ADAPTER_CLASSES = [DidRegistryCoreV1, TirCoreV1]


def _built(cls: type, address: Any) -> str:
    adapter = cls(contract_address=address)
    if cls is DidRegistryCoreV1:
        return adapter.identifiers_url(GRNET, DID)
    return adapter.issuer_url(GRNET, DID)


@pytest.mark.parametrize("cls", ADAPTER_CLASSES)
@pytest.mark.parametrize("value", BAD_ADDRESSES, ids=lambda v: repr(v)[:24])
def test_a_bad_contract_address_is_a_value_error(cls, value):
    with pytest.raises(ValueError, match="contract_address"):
        cls(contract_address=value)


@pytest.mark.parametrize("cls", ADAPTER_CLASSES)
@pytest.mark.parametrize("value", BAD_ADDRESS_TYPES, ids=lambda v: type(v).__name__)
def test_a_non_str_contract_address_is_a_value_error(cls, value):
    with pytest.raises(ValueError, match="contract_address must be a str"):
        cls(contract_address=value)


@pytest.mark.parametrize("cls", ADAPTER_CLASSES)
@pytest.mark.parametrize("value", GOOD_ADDRESSES, ids=lambda v: v[:20])
def test_a_valid_contract_address_is_the_only_query_component(cls, value):
    url = _built(cls, value)
    path = _built(cls, None)
    assert "?" not in path
    assert url == f"{path}?contractAddress={value}"
    assert url.count("?") == 1 and url.count("&") == 0 and url.count("#") == 0


@pytest.mark.parametrize("cls", ADAPTER_CLASSES)
def test_contract_address_is_keyword_only_and_optional(cls):
    with pytest.raises(TypeError):
        cls(DID_REGISTRY_ADDRESS)                                  # type: ignore[misc]
    assert _built(cls, None) == _built(cls, None)
    cls()                                                           # no address: the default


@pytest.mark.parametrize("cls", ADAPTER_CLASSES)
def test_a_str_subclass_is_read_as_its_characters(cls):
    class Sneaky(str):
        def __format__(self, spec: str) -> str:
            return "/../etc"

        def __str__(self) -> str:
            return "/../etc"

    url = _built(cls, Sneaky(DID_REGISTRY_ADDRESS))
    assert url.endswith(f"?contractAddress={DID_REGISTRY_ADDRESS}")
    assert "/../etc" not in url
    with pytest.raises(ValueError, match="contract_address"):
        cls(contract_address=Sneaky("bad/value"))


def test_each_registry_has_its_own_address_and_the_adapters_do_not_share_one():
    didr = DidRegistryCoreV1(contract_address=DID_REGISTRY_ADDRESS)
    tir = TirCoreV1(contract_address=ISSUERS_REGISTRY_ADDRESS)
    assert didr.identifiers_url(GRNET, DID).endswith(f"?contractAddress={DID_REGISTRY_ADDRESS}")
    assert tir.issuer_url(GRNET, DID).endswith(f"?contractAddress={ISSUERS_REGISTRY_ADDRESS}")


def test_the_nodes_published_addresses_are_what_the_tests_use():
    did_details = _rec("contract-address/preprod-grnet_did-registry_details.json")
    issuers_details = _rec("contract-address/preprod-grnet_issuers-registry_details.json")
    assert did_details["contractAddress"] == DID_REGISTRY_ADDRESS
    assert issuers_details["contractAddress"] == ISSUERS_REGISTRY_ADDRESS
    for address in (*did_details.values(), *issuers_details.values()):
        assert re.fullmatch(r"0x[0-9a-fA-F]{40}", address)       # what the nodes serve
        assert DidRegistryCoreV1(contract_address=address)       # and what the bound admits


def test_resolvers_with_different_addresses_never_share_a_cached_document():
    seen: list[str] = []
    other = "0x" + "1" * 40

    def handler(request: Any) -> Any:
        seen.append(str(request.url))
        doc = _rec("preprod-grnet/did_document.json")
        doc["alsoKnownAs"] = [request.url.params.get("contractAddress") or "default"]
        return httpx.Response(200, json=doc, headers={"content-type": "application/did+ld+json"})

    client = EbsiHttpClient(allowed_hosts={"api-preprod.ebsi.grnet.gr"})
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        first = _core_resolver(client.get_json, GRNET,
                               didr=DidRegistryCoreV1(contract_address=DID_REGISTRY_ADDRESS))
        second = _core_resolver(client.get_json, GRNET,
                                didr=DidRegistryCoreV1(contract_address=other))
        bare = _core_resolver(client.get_json, GRNET)
        docs = [first.resolve(DID), second.resolve(DID), bare.resolve(DID)]
        assert [d.raw["alsoKnownAs"] for d in docs] == [
            [DID_REGISTRY_ADDRESS], [other], ["default"]]
        assert len(seen) == 3 and len(set(seen)) == 3
        # the same resolvers again are served from the cache, each from its own entry
        assert [r.resolve(DID).raw["alsoKnownAs"][0] for r in (second, bare, first)] == \
            [other, "default", DID_REGISTRY_ADDRESS]
        assert len(seen) == 3
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# Hostile DIDs and wrong bodies, on the Core v1 pair (#266, #257, #267 are inherited)
# --------------------------------------------------------------------------- #

HOSTILE_DIDS = [
    "..", "did:ebsi:..", "did:ebsi:../x", f"{DID}/attributes", f"{DID}?x=1", f"{DID}#key-1",
    "did:ebsi:%2f%2e%2e", f"{DID}%2f", "https://evil.example/v1/", "did:web:evil.example",
    "did:ebsi:z" + "1" * 60_000, DID + "\n", " " + DID, "", "did:ebsi:", DID.upper(),
]


def _served_core_walk(base: str = GRNET, *, tir: TirCoreV1 | None = None,
                      didr: DidRegistryCoreV1 | None = None) -> tuple[StubFetch, DidEbsiResolver]:
    """The recorded preprod-grnet reads behind a stub, keyed by the URLs the node was asked."""
    routes = {_url(f"preprod-grnet/{name}.json"): _rec(f"preprod-grnet/{name}.json")
              for name in ("did_document", "issuer", "attributes", "attribute_0dc6a111")}
    fetch = StubFetch(routes)
    return fetch, _core_resolver(fetch, base, didr=didr, tir=tir)


def test_control_the_recorded_walk_resolves_on_the_core_lane():
    fetch, resolver = _served_core_walk()
    assert resolver.resolve(DID).id == DID
    assert resolver.issuer_record(DID).did == DID


@pytest.mark.parametrize("hostile", HOSTILE_DIDS, ids=lambda d: repr(d)[:30])
def test_a_hostile_did_is_refused_before_any_request_on_the_core_pair(hostile):
    for address in (None, DID_REGISTRY_ADDRESS):
        fetch, resolver = _served_core_walk(
            didr=DidRegistryCoreV1(contract_address=address),
            tir=TirCoreV1(contract_address=address))
        with pytest.raises(DidResolutionError) as exc:
            resolver.resolve(hostile)
        assert type(exc.value) is DidResolutionError
        with pytest.raises(DidResolutionError) as exc:
            resolver.issuer_record(hostile)
        assert type(exc.value) is DidResolutionError
        assert fetch.calls == []
        assert len(str(exc.value)) < 400                          # bounded, even for 60 KB


def test_a_document_whose_id_is_not_the_requested_did_is_refused():
    other_url = DidRegistryCoreV1().identifiers_url(GRNET, OTHER_DID)
    fetch = StubFetch({other_url: _rec("preprod-grnet/did_document.json")})   # id is DID
    with pytest.raises(DidResolutionError, match="document id") as exc:
        _core_resolver(fetch, GRNET).resolve(OTHER_DID)
    assert type(exc.value) is DidResolutionError
    assert fetch.calls == [other_url]


@pytest.mark.parametrize("named", [OTHER_DID, "", None, 5, ["x"], {"did": DID}, True, DID.upper()],
                         ids=lambda v: repr(v)[:30])
def test_an_issuer_response_naming_another_did_is_malformed_after_one_request(named):
    issuer = _rec("preprod-grnet/issuer.json")
    issuer["did"] = named
    url = TirCoreV1().issuer_url(GRNET, DID)
    fetch = StubFetch({url: issuer})
    with pytest.raises(MalformedRegistryResponse, match="names") as exc:
        _core_resolver(fetch, GRNET).issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls == [url]                      # no attributes page, no revision


def test_an_issuer_response_without_a_did_is_malformed_after_one_request():
    issuer = _rec("preprod-grnet/issuer.json")
    del issuer["did"]
    url = TirCoreV1().issuer_url(GRNET, DID)
    fetch = StubFetch({url: issuer})
    with pytest.raises(MalformedRegistryResponse) as exc:
        _core_resolver(fetch, GRNET).issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls == [url]


NON_OBJECTS = [[], [{"a": 1}], None, "text", "", 7, 1.5, True]


@pytest.mark.parametrize("body", NON_OBJECTS, ids=lambda v: repr(v)[:20])
def test_a_non_object_issuer_is_malformed(body):
    url = TirCoreV1().issuer_url(GRNET, DID)
    fetch = StubFetch({url: body})
    with pytest.raises(MalformedRegistryResponse) as exc:
        _core_resolver(fetch, GRNET).issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls == [url]


@pytest.mark.parametrize("body", NON_OBJECTS, ids=lambda v: repr(v)[:20])
def test_a_non_object_attribute_list_is_malformed(body):
    fetch, resolver = _served_core_walk()
    fetch.routes[_url("preprod-grnet/attributes.json")] = body
    with pytest.raises(MalformedRegistryResponse, match="attributes page") as exc:
        resolver.issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls == [_url("preprod-grnet/issuer.json"), _url("preprod-grnet/attributes.json")]


@pytest.mark.parametrize("body", NON_OBJECTS, ids=lambda v: repr(v)[:20])
def test_a_non_object_attribute_is_malformed(body):
    fetch, resolver = _served_core_walk()
    fetch.routes[_url("preprod-grnet/attribute_0dc6a111.json")] = body
    with pytest.raises(MalformedRegistryResponse, match="attribute revision") as exc:
        resolver.issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls[-1] == _url("preprod-grnet/attribute_0dc6a111.json")


@pytest.mark.parametrize("body", NON_OBJECTS, ids=lambda v: repr(v)[:20])
def test_a_non_object_did_document_is_a_typed_error(body):
    url = DidRegistryCoreV1().identifiers_url(GRNET, DID)
    fetch = StubFetch({url: body})
    with pytest.raises(OpenvcError):
        _core_resolver(fetch, GRNET).resolve(DID)


# --------------------------------------------------------------------------- #
# The origin pin is to the answering node
# --------------------------------------------------------------------------- #

def test_one_nodes_issuer_body_read_through_another_nodes_resolver_is_malformed():
    # grnet's issuer body names grnet's `attributes` URL; a resolver based on incm routes the
    # request to incm and receives it
    incm_issuer = TirCoreV1().issuer_url(INCM, DID)
    grnet_attributes = _url("preprod-grnet/attributes.json")
    fetch = StubFetch({incm_issuer: _rec("preprod-grnet/issuer.json"),
                       grnet_attributes: _rec("preprod-grnet/attributes.json")})
    with pytest.raises(MalformedRegistryResponse, match="off the listing origin") as exc:
        _core_resolver(fetch, INCM).issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert fetch.calls == [incm_issuer]              # exactly one request, nothing followed


def test_one_nodes_attribute_list_served_by_another_node_has_every_href_skipped():
    incm_issuer = TirCoreV1().issuer_url(INCM, DID)
    incm_attributes = _url("preprod-incm/attributes.json")
    grnet_href = _url("preprod-grnet/attribute_0dc6a111.json")
    fetch = StubFetch({
        incm_issuer: _rec("preprod-incm/issuer.json"),
        incm_attributes: _rec("preprod-grnet/attributes.json"),      # grnet's hrefs, incm's route
        grnet_href: _rec("preprod-grnet/attribute_0dc6a111.json"),   # real content: a wrongful
    })                                                               # fetch would show up
    record = _core_resolver(fetch, INCM).issuer_record(DID)
    assert record.accreditations == ()
    assert record.has_attributes is True
    assert fetch.calls == [incm_issuer, incm_attributes]             # the grnet href: never fetched


def test_a_node_not_in_the_recording_cannot_borrow_another_nodes_links():
    # the resolver's base is the third node; the recorded issuer names grnet's `attributes`
    third = "https://api-preprod.ebsi.edelivery.lt"
    third_issuer = TirCoreV1().issuer_url(third, DID)
    fetch = StubFetch({third_issuer: _rec("preprod-grnet/issuer.json")})
    with pytest.raises(MalformedRegistryResponse, match="off the listing origin"):
        _core_resolver(fetch, third).issuer_record(DID)
    assert fetch.calls == [third_issuer]


# --- the shared walk's guards, for BOTH TIR lanes, by parametrisation -------------------- #

@dataclass(frozen=True)
class Lane:
    name: str
    make: Callable[[], TirAdapter]
    issuer_url: Callable[[str, str], str]


LANES = [
    Lane("v5", TirV5, lambda base, did: f"{base}/trusted-issuers-registry/v5/issuers/{did}"),
    Lane("core-v1", TirCoreV1, lambda base, did: f"{base}/v1/issuers-registry/issuers/{did}"),
]
ROOT = "did:ebsi:zYcXJpGw4oxsrGXc5WdR3UA"


def _decode(body: str) -> dict[str, Any]:
    return {"vc": {"credentialSubject": {"accreditedFor": [{"types": ["TestType"]}]}}}


class World:
    """One TIR listing behind a stub, built for a lane, with routes keyed by exact URL."""

    def __init__(self, lane: Lane, base: str = GRNET) -> None:
        self.lane, self.base = lane, base
        self.tir = lane.make()
        self.issuer_url = lane.issuer_url(base, DID)
        self.attributes_url = self.issuer_url + "/attributes"
        self.routes: dict[str, Any] = {
            self.issuer_url: {"did": DID, "hasAttributes": True, "attributes": self.attributes_url}}
        self.calls: list[str] = []

    def fetch(self, url: str) -> Any:
        self.calls.append(url)
        try:
            return self.routes[url]
        except KeyError:
            raise HttpNotFound("no stub route", url=url) from None

    def href(self, n: int, base: str | None = None) -> str:
        return f"{base or self.base}{urlsplit(self.attributes_url).path}/{n:064x}"

    def item(self, n: int, href: str | None = None) -> dict[str, str]:
        return {"id": f"{n:064x}", "href": href or self.href(n)}

    def serve_revision(self, url: str, n: int) -> None:
        self.routes[url] = {"did": DID, "attribute": {
            "body": f"jwt-{n}", "hash": f"hash-{n}", "issuerType": "TI", "tao": ROOT,
            "rootTao": ROOT}}

    def walk(self) -> IssuerRecord:
        resolver = DidEbsiResolver(self.fetch, _decode, base=self.base,
                                   didr=DidRegistryV5(), tir=self.tir)
        return resolver.issuer_record(DID)


def _revisions_fetched(world: World) -> list[str]:
    return [u for u in world.calls if u not in (world.issuer_url, world.attributes_url)
            and "page[after]" not in u]


@pytest.fixture(params=LANES, ids=lambda lane: lane.name)
def lane(request: Any) -> Lane:
    return request.param


def test_control_the_synthetic_walk_reads_every_item(lane):
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1), w.item(2)], "total": 2}
    w.serve_revision(w.href(1), 1)
    w.serve_revision(w.href(2), 2)
    record = w.walk()
    assert [a.attribute_id for a in record.accreditations] == [f"{1:064x}", f"{2:064x}"]
    assert w.calls == [w.issuer_url, w.attributes_url, w.href(1), w.href(2)]


def test_the_walks_caps_are_the_documented_ones(lane):
    tir = lane.make()
    assert tir._MAX_ATTRIBUTE_PAGES == 50 and tir._MAX_ATTRIBUTE_ITEMS == 1000


def test_a_self_referential_next_is_fetched_once(lane):
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 9,
                                  "links": {"next": w.attributes_url}}
    w.serve_revision(w.href(1), 1)
    record = w.walk()
    assert w.calls.count(w.attributes_url) == 1
    assert len(record.accreditations) == 1


def test_an_off_origin_next_is_not_followed_and_keeps_what_was_read(lane):
    w = World(lane)
    evil = "https://evil.example" + urlsplit(w.attributes_url).path + "?page[after]=2"
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 9, "links": {"next": evil}}
    w.routes[evil] = {"items": [w.item(2)], "total": 9}                 # real content
    w.serve_revision(w.href(1), 1)
    w.serve_revision(w.href(2), 2)
    record = w.walk()
    assert evil not in w.calls
    assert len(record.accreditations) == 1


def test_an_off_origin_href_is_skipped_and_never_fetched(lane):
    w = World(lane)
    evil = w.href(1, "https://evil.example")
    w.routes[w.attributes_url] = {"items": [w.item(1, evil)], "total": 1}
    w.serve_revision(evil, 1)                                           # real content
    record = w.walk()
    assert record.accreditations == () and evil not in w.calls
    assert w.calls == [w.issuer_url, w.attributes_url]


def test_an_off_origin_attributes_url_is_malformed_after_one_request(lane):
    w = World(lane)
    evil = "https://evil.example" + urlsplit(w.attributes_url).path
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True, "attributes": evil}
    w.routes[evil] = {"items": [w.item(1)], "total": 1}
    with pytest.raises(MalformedRegistryResponse, match="off the listing origin") as exc:
        w.walk()
    assert type(exc.value) is MalformedRegistryResponse
    assert w.calls == [w.issuer_url]


def test_a_port_only_change_is_off_origin_on_every_hop(lane):
    w = World(lane)
    other_port = w.base + ":8443"
    # attributes: refused
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True,
                              "attributes": w.attributes_url.replace(w.base, other_port)}
    with pytest.raises(MalformedRegistryResponse, match="off the listing origin"):
        w.walk()
    # href and next: skipped and not followed
    w = World(lane)
    href = w.href(1, other_port)
    nxt = w.attributes_url.replace(w.base, other_port) + "?page[after]=2"
    w.routes[w.attributes_url] = {"items": [w.item(1, href)], "total": 9, "links": {"next": nxt}}
    w.serve_revision(href, 1)
    w.routes[nxt] = {"items": [w.item(2)], "total": 9}
    w.serve_revision(w.href(2), 2)
    record = w.walk()
    assert record.accreditations == ()
    assert href not in w.calls and nxt not in w.calls


def test_port_443_is_the_same_origin_as_no_port_on_every_hop(lane):
    w = World(lane)                                                     # base has no port
    on_443 = w.base + ":443"
    attrs = w.attributes_url.replace(w.base, on_443)
    href = w.href(1, on_443)
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True, "attributes": attrs}
    w.routes[attrs] = {"items": [w.item(1, href)], "total": 9,
                       "links": {"next": attrs + "?page[after]=2"}}
    w.routes[attrs + "?page[after]=2"] = {"items": [w.item(2)], "total": 9}
    w.serve_revision(href, 1)
    w.serve_revision(w.href(2), 2)
    record = w.walk()
    assert len(record.accreditations) == 2
    assert w.calls == [w.issuer_url, attrs, href, attrs + "?page[after]=2", w.href(2)]


@pytest.mark.parametrize("junk", ["https://api-preprod.ebsi.grnet.gr:99999/x",
                                  "https://api-preprod.ebsi.grnet.gr:abc/x",
                                  "https://[::1/x", "https://host\u00e9.example/x",
                                  "https://api-preprod.ebsi.grnet.gr/" + "a" * 9000,
                                  "https://api-preprod.ebsi.grnet.gr/a b"])
def test_an_unparseable_url_is_typed_for_attributes_and_skipped_for_href_and_next(lane, junk):
    w = World(lane)
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True, "attributes": junk}
    with pytest.raises(MalformedRegistryResponse) as exc:
        w.walk()
    assert type(exc.value) is MalformedRegistryResponse
    assert w.calls == [w.issuer_url]
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1, junk)], "total": 9, "links": {"next": junk}}
    record = w.walk()
    assert record.accreditations == ()
    assert w.calls == [w.issuer_url, w.attributes_url]


def test_total_true_does_not_read_as_one(lane):
    w = World(lane)
    nxt = w.attributes_url + "?page[after]=2"
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": True, "links": {"next": nxt}}
    w.routes[nxt] = {"items": [w.item(2)], "total": True}
    w.serve_revision(w.href(1), 1)
    w.serve_revision(w.href(2), 2)
    assert len(w.walk().accreditations) == 2                            # `True` is not 1


def test_total_stops_the_walk_when_it_is_reached(lane):
    w = World(lane)
    nxt = w.attributes_url + "?page[after]=2"
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1, "links": {"next": nxt}}
    w.routes[nxt] = {"items": [w.item(2)], "total": 1}
    w.serve_revision(w.href(1), 1)
    w.serve_revision(w.href(2), 2)
    assert len(w.walk().accreditations) == 1 and nxt not in w.calls


def test_the_page_cap_bounds_a_registry_that_never_stops_paginating(lane):
    w = World(lane)
    cap = w.tir._MAX_ATTRIBUTE_PAGES
    pages = [w.attributes_url] + [f"{w.attributes_url}?page[after]={n}" for n in range(2, cap + 20)]
    for n, url in enumerate(pages):
        w.routes[url] = {"items": [w.item(n + 1)],
                         "links": {"next": pages[n + 1] if n + 1 < len(pages) else url}}
        w.serve_revision(w.href(n + 1), n + 1)
    record = w.walk()
    assert len([u for u in w.calls if u in pages]) == cap
    assert len(record.accreditations) == cap


def test_the_item_cap_bounds_one_giant_page(lane):
    w = World(lane)
    w.tir._MAX_ATTRIBUTE_ITEMS = 3                                      # shrink it for the test
    w.routes[w.attributes_url] = {"items": [w.item(n) for n in range(1, 11)], "total": 10}
    for n in range(1, 11):
        w.serve_revision(w.href(n), n)
    record = w.walk()
    assert len(record.accreditations) == 3
    assert len(_revisions_fetched(w)) == 3


def test_a_walk_with_no_attributes_link_builds_it_from_the_issuer_path(lane):
    w = World(lane)
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True}
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1}
    w.serve_revision(w.href(1), 1)
    assert len(w.walk().accreditations) == 1
    assert w.calls[:2] == [w.issuer_url, w.attributes_url]


@pytest.mark.parametrize("body", [5, 1.5, True, False, ["a.b.c"], {"x": 1}, [], {}],
                         ids=lambda v: repr(v)[:16])
def test_a_non_string_attribute_body_is_malformed_not_a_bare_attribute_error(lane, body):
    # `decode` is the proof suite's `peek_claims`, which takes a token: a number, an array or an
    # object used to leave it as a bare AttributeError (`'int' object has no attribute 'isascii'`)
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1}
    w.routes[w.href(1)] = {"attribute": {"body": body, "hash": "h"}}
    resolver = DidEbsiResolver(w.fetch, PEEK, base=w.base, didr=DidRegistryV5(), tir=w.tir)
    with pytest.raises(MalformedRegistryResponse, match="body is not a string") as exc:
        resolver.issuer_record(DID)
    assert type(exc.value) is MalformedRegistryResponse
    assert w.calls[-1] == w.href(1)


@pytest.mark.parametrize("attribute", [None, "text", 7, ["x"], True])
def test_an_attribute_revision_without_an_attribute_object_is_malformed(lane, attribute):
    # not read as an empty attribute: that is an accreditation with no type restriction
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1}
    w.routes[w.href(1)] = {"did": DID, "attribute": attribute}
    with pytest.raises(MalformedRegistryResponse, match="no attribute object") as exc:
        w.walk()
    assert type(exc.value) is MalformedRegistryResponse
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1}
    w.routes[w.href(1)] = {"did": DID}                                    # absent
    with pytest.raises(MalformedRegistryResponse, match="no attribute object"):
        w.walk()


# Every shape carries a live `issuerType`: since #358 an attribute with no role (read as "")
# is set aside by both trust policies before its body is looked at (pinned in
# `test_ebsi_issuer_type_roles.py`), and the point here is the body, not the role.
NO_USABLE_BODY = [
    {"body": None, "issuerType": "TI", "tao": ROOT},
    {"body": "", "issuerType": "TI", "tao": ROOT},
    {"issuerType": "TI", "tao": ROOT},                                    # no body key
    {"hash": "h", "issuerType": "TI", "tao": ROOT},                       # hash only
]


@pytest.mark.parametrize("attribute", NO_USABLE_BODY,
                         ids=["body-none", "body-empty", "no-body-key", "hash-only"])
def test_an_attribute_object_with_no_usable_body_is_still_a_wildcard_by_design(lane, attribute):
    # The missing-`attribute`-object check above is a SHAPE check; it does not remove the
    # wildcard. An attribute OBJECT with nothing to decode is an accreditation with no type
    # restriction, which single-level trust accepts for any credential (its documented policy:
    # that mode trusts the node's list); recursive trust refuses it for lack of a token.
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1}
    w.routes[w.href(1)] = {"attribute": attribute}
    record = w.walk()
    accreditation = record.accreditations[0]
    assert accreditation.credential_jwt == attribute.get("body")
    assert accreditation.credential_types == ()
    assert evaluate_issuer_trust(record, ["AnyCredentialType"]) is accreditation
    resolver = DidEbsiResolver(w.fetch, _decode, base=w.base, didr=DidRegistryV5(), tir=w.tir)
    with pytest.raises(AccreditationInvalid, match="no raw accreditation token") as exc:
        verify_trust_chain(DID, ["AnyCredentialType"], resolver=resolver,
                           proof_suite=VcJwtProofSuite(), anchors={OTHER_DID})
    assert type(exc.value) is AccreditationInvalid


def test_a_body_whose_claims_name_no_accredited_for_is_the_same_wildcard(lane):
    # why rejecting a body-less attribute could not close the wildcard: a body that decodes to
    # claims with no `accreditedFor` reads the same way
    w = World(lane)
    w.routes[w.attributes_url] = {"items": [w.item(1)], "total": 1}
    w.serve_revision(w.href(1), 1)
    resolver = DidEbsiResolver(w.fetch, lambda body: {"vc": {"credentialSubject": {}}},
                               base=w.base, didr=DidRegistryV5(), tir=w.tir)
    record = resolver.issuer_record(DID)
    assert record.accreditations[0].credential_jwt == "jwt-1"
    assert record.accreditations[0].credential_types == ()
    assert evaluate_issuer_trust(record, ["AnyCredentialType"]) is record.accreditations[0]


def test_non_object_listing_items_are_skipped_and_the_valid_one_is_read(lane):
    # a registry's `items` may hold anything: only an object can be an {id, href} entry
    w = World(lane)
    w.routes[w.attributes_url] = {"items": ["abc", 5, 1.5, None, True, [1], ["x", {"id": "y"}],
                                            w.item(1)], "total": 1}
    w.serve_revision(w.href(1), 1)
    record = w.walk()
    assert [a.attribute_id for a in record.accreditations] == [f"{1:064x}"]
    assert w.calls == [w.issuer_url, w.attributes_url, w.href(1)]


def test_a_listing_of_only_non_object_items_reads_no_accreditation(lane):
    w = World(lane)
    w.routes[w.attributes_url] = {"items": ["abc", 5, None, [1]], "total": 4}
    record = w.walk()
    assert record.accreditations == ()
    assert w.calls == [w.issuer_url, w.attributes_url]


# --------------------------------------------------------------------------- #
# A configured contract address stays on every hop of the walk
# --------------------------------------------------------------------------- #

ADDRESS = ISSUERS_REGISTRY_ADDRESS
OTHER_ADDRESS = "0x" + "2" * 40


def _bound_world(*, address: str | None = ADDRESS) -> World:
    w = World(LANES[1])
    w.tir = TirCoreV1(contract_address=address)
    if address is not None:
        w.issuer_url = f"{w.issuer_url}?contractAddress={address}"
    return w


def test_the_recorded_nodes_name_no_address_in_any_link():
    for rel in ("preprod-grnet/issuer.json", "preprod-grnet/attributes.json",
                "preprod-grnet/issuers_page.json",
                "contract-address/preprod-grnet_issuer_with-address.json",
                "contract-address/preprod-grnet_attributes_with-address.json"):
        assert "contractAddress" not in _read(rel).decode()


@pytest.mark.parametrize("pair", [
    ("preprod-grnet/did_document.json",
     "contract-address/preprod-grnet_did_document_with-address.json"),
    ("preprod-grnet/issuer.json", "contract-address/preprod-grnet_issuer_with-address.json"),
    ("preprod-grnet/attributes.json",
     "contract-address/preprod-grnet_attributes_with-address.json"),
    ("preprod-grnet/attribute_0dc6a111.json",
     "contract-address/preprod-grnet_attribute_0dc6a111_with-address.json"),
])
def test_a_read_with_the_address_is_byte_identical_to_the_bare_read(pair):
    bare, bound = pair
    assert _read(bare) == _read(bound)
    assert "contractAddress=" in _url(bound) and "contractAddress" not in _url(bare)


def test_a_configured_address_is_added_to_every_link_the_walk_follows():
    w = _bound_world()
    bare_attrs = w.attributes_url.split("?")[0]
    page2 = bare_attrs + "?page[after]=2&page[size]=1"
    w.routes = {
        w.issuer_url: {"did": DID, "hasAttributes": True, "attributes": bare_attrs},
        f"{bare_attrs}?contractAddress={ADDRESS}": {
            "items": [w.item(1, w.href(1))], "total": 2, "links": {"next": page2}},
        f"{page2}&contractAddress={ADDRESS}": {"items": [w.item(2, w.href(2))], "total": 2},
    }
    w.serve_revision(f"{w.href(1)}?contractAddress={ADDRESS}", 1)
    w.serve_revision(f"{w.href(2)}?contractAddress={ADDRESS}", 2)
    record = w.walk()
    assert len(record.accreditations) == 2
    assert w.calls == [
        w.issuer_url,
        f"{bare_attrs}?contractAddress={ADDRESS}",
        f"{w.href(1)}?contractAddress={ADDRESS}",
        f"{page2}&contractAddress={ADDRESS}",
        f"{w.href(2)}?contractAddress={ADDRESS}",
    ]
    assert all(u.count("contractAddress=") == 1 for u in w.calls)


def test_a_link_that_already_names_the_configured_address_is_left_alone():
    w = _bound_world()
    bound_attrs = f"{w.attributes_url.split('?')[0]}?contractAddress={ADDRESS}"
    href = f"{w.href(1)}?contractAddress={ADDRESS}"
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True, "attributes": bound_attrs}
    w.routes[bound_attrs] = {"items": [w.item(1, href)], "total": 1}
    w.serve_revision(href, 1)
    assert len(w.walk().accreditations) == 1
    assert w.calls == [w.issuer_url, bound_attrs, href]


def test_a_missing_attributes_link_is_built_from_the_path_with_the_query_last():
    w = _bound_world()
    path = urlsplit(w.attributes_url).path
    built = f"{GRNET}{path}?contractAddress={ADDRESS}"
    assert not built.endswith("/attributes") and "?contractAddress=" in built
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True}
    w.routes[built] = {"items": [], "total": 0}
    w.walk()
    assert w.calls == [w.issuer_url, built]
    # without an address the same fallback has no query at all
    plain = _bound_world(address=None)
    plain.routes[plain.issuer_url] = {"did": DID, "hasAttributes": True}
    plain.routes[plain.attributes_url] = {"items": [], "total": 0}
    plain.walk()
    assert plain.calls == [plain.issuer_url, plain.attributes_url]
    assert "?" not in plain.attributes_url


NAMING_ANOTHER = [
    f"?contractAddress={OTHER_ADDRESS}",
    f"?page[after]=1&contractAddress={OTHER_ADDRESS}",
    f"?contractAddress={ADDRESS}&contractAddress={OTHER_ADDRESS}",
    f"?contractAddress={OTHER_ADDRESS}&contractAddress={ADDRESS}",
    f"?contractaddress={ADDRESS}",                    # another spelling of the name is not accepted
    f"?CONTRACTADDRESS={OTHER_ADDRESS}",
    f"?contract%41ddress={OTHER_ADDRESS}",            # percent-decoded before the comparison
    "?contractAddress=",
    f"?contractAddress={ADDRESS.lower()}",            # exact comparison, no case folding
    f"?contractAddress={ADDRESS}%00",
    # a name that CONTAINS the parameter name is refused, not read as some other parameter:
    f"?contractAddress[]={OTHER_ADDRESS}",            # bracket suffix (qs-style array)
    f"?contractAddress%5B%5D={OTHER_ADDRESS}",        # the same, percent-encoded
    f"?contractAddress[0]={OTHER_ADDRESS}",
    f"?contractAddress[]={ADDRESS}",                  # the configured value, in another spelling
    f"?contractAddress.x={OTHER_ADDRESS}",
    f"?contractAddress%20={OTHER_ADDRESS}",           # trailing space
    f"?contractAddress+={OTHER_ADDRESS}",
    f"?%00contractAddress={OTHER_ADDRESS}",
    f"?contractAddressX={OTHER_ADDRESS}",
    "?contractAddressX=1",
    "?contractAddress",                               # no `=`: a blank value
    # a ';' is refused whatever the query names (a server may read it as a separator):
    f"?x=1;contractAddress={OTHER_ADDRESS}",
    f"?x=1;contractAddress={ADDRESS}",
    "?a=1;b=2",
]


@pytest.mark.parametrize("query", NAMING_ANOTHER)
def test_a_link_naming_another_instance_is_malformed_on_every_hop(query):
    bare = urlsplit(_bound_world().attributes_url).path
    # attributes
    w = _bound_world()
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True,
                              "attributes": f"{GRNET}{bare}{query}"}
    with pytest.raises(MalformedRegistryResponse, match="contract address") as exc:
        w.walk()
    assert type(exc.value) is MalformedRegistryResponse
    assert w.calls == [w.issuer_url]
    # href
    w = _bound_world()
    bound = f"{GRNET}{bare}?contractAddress={ADDRESS}"
    href = f"{w.href(1)}{query}"
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True, "attributes": bound}
    w.routes[bound] = {"items": [w.item(1, href)], "total": 1}
    w.routes[href] = {}
    with pytest.raises(MalformedRegistryResponse, match="contract address") as exc:
        w.walk()
    assert type(exc.value) is MalformedRegistryResponse
    assert href not in w.calls
    # next
    w = _bound_world()
    nxt = f"{GRNET}{bare}{query}"
    w.routes[w.issuer_url] = {"did": DID, "hasAttributes": True, "attributes": bound}
    w.routes[bound] = {"items": [w.item(1, f"{w.href(1)}?contractAddress={ADDRESS}")],
                       "total": 9, "links": {"next": nxt}}
    w.serve_revision(f"{w.href(1)}?contractAddress={ADDRESS}", 1)
    w.routes[nxt] = {"items": [], "total": 9}
    with pytest.raises(MalformedRegistryResponse, match="contract address") as exc:
        w.walk()
    assert type(exc.value) is MalformedRegistryResponse
    assert nxt not in w.calls


def test_without_a_configured_address_links_are_followed_as_the_node_wrote_them():
    w = _bound_world(address=None)
    href = f"{w.href(1)}?contractAddress={OTHER_ADDRESS}"
    w.routes[w.attributes_url] = {"items": [w.item(1, href)], "total": 1}
    w.serve_revision(href, 1)
    assert len(w.walk().accreditations) == 1
    assert w.calls == [w.issuer_url, w.attributes_url, href]


@pytest.mark.parametrize("url,expected", [
    ("https://h/p", f"https://h/p?contractAddress={ADDRESS}"),
    ("https://h/p?", f"https://h/p?contractAddress={ADDRESS}"),
    ("https://h/p?page[after]=1&page[size]=10",
     f"https://h/p?page[after]=1&page[size]=10&contractAddress={ADDRESS}"),
    ("https://h/p#frag", f"https://h/p?contractAddress={ADDRESS}#frag"),
    (f"https://h/p?contractAddress={ADDRESS}", f"https://h/p?contractAddress={ADDRESS}"),
    (f"https://h/p?a=1&contractAddress={ADDRESS}&b=2",
     f"https://h/p?a=1&contractAddress={ADDRESS}&b=2"),
    # a percent-encoded ';' is data in every server, so it neither separates nor is refused
    ("https://h/p?x=1%3BcontractAddress=0xOTHER",
     f"https://h/p?x=1%3BcontractAddress=0xOTHER&contractAddress={ADDRESS}"),
    ("https://h/p;a=1?x=1", f"https://h/p;a=1?x=1&contractAddress={ADDRESS}"),   # a path ';'
])
def test_on_contract_address_binds_or_keeps(url, expected):
    assert _on_contract_address(url, ADDRESS) == expected


@pytest.mark.parametrize("query", NAMING_ANOTHER)
def test_on_contract_address_refuses_every_spelling_of_another_instance(query):
    with pytest.raises(MalformedRegistryResponse, match="contract address") as exc:
        _on_contract_address(f"https://h/p{query}", ADDRESS)
    assert type(exc.value) is MalformedRegistryResponse


# --------------------------------------------------------------------------- #
# ES256K: the recorded RootTAO is refused by the DEFAULT suite (#323 added the opt-in)
# --------------------------------------------------------------------------- #

def test_the_recorded_root_tao_is_es256k_and_verification_refuses_it():
    # The preprod and prod RootTAO accreditation JWTs are signed ES256K, which the DEFAULT
    # JOSE allow-list does not admit and keeps refusing. #323 added `allow_es256k=True` on
    # VcJwtProofSuite: the positive verification of this very signature, through the chain
    # and badge verifiers, is tests/test_es256k_ebsi_chain.py. This test pins the default.
    token = _rec("preprod-grnet/attribute_0dc6a111.json")["attribute"]["body"]
    suite = VcJwtProofSuite()
    issuer, kid = suite.peek_issuer(token)
    assert issuer == DID and kid.startswith(DID + "#")
    doc = DidRegistryCoreV1().parse_did_document(_rec("preprod-grnet/did_document.json"))
    method = doc.key_by_kid(kid)
    assert method is not None and method.public_key_jwk["crv"] == "secp256k1"
    with pytest.raises(UnsupportedAlgorithm, match="ES256K") as exc:
        suite.verify(token, public_key_jwk=method.public_key_jwk)
    assert type(exc.value) is UnsupportedAlgorithm
    # what still works on it: reading the claims, building the record, single-level trust
    assert suite.peek_claims(token)["iss"] == DID
    _, resolver = _served_core_walk()
    record = resolver.issuer_record(DID)
    assert len(record.accreditations) == 1
    accreditation = record.accreditations[0]
    assert accreditation.issuer_type == "RootTAO"
    assert "VerifiableAuthorisationForTrustChain" in accreditation.credential_types
    assert evaluate_issuer_trust(record, ["VerifiableAuthorisationForTrustChain"]) is accreditation
    assert evaluate_issuer_trust(record, ["NotAType"]) is None


def test_recursive_trust_fails_closed_on_the_recorded_es256k_root():
    # The chain walk verifies the accreditation against the accreditor's resolved key, and with
    # the DEFAULT suite the ES256K signature cannot be checked: AccreditationInvalid, not a
    # trust grant (the opted-in walk is in test_es256k_ebsi_chain.py). A leaf that is itself an
    # anchor is trusted without a walk, so the anchor here is another DID.
    _, resolver = _served_core_walk()
    with pytest.raises(AccreditationInvalid, match="ES256K") as exc:
        verify_trust_chain(DID, ["VerifiableAuthorisationForTrustChain"], resolver=resolver,
                           proof_suite=VcJwtProofSuite(), anchors={OTHER_DID})
    assert type(exc.value) is AccreditationInvalid


# --------------------------------------------------------------------------- #
# Goldens: the recorded walks
# --------------------------------------------------------------------------- #

NODES = [("preprod-grnet", GRNET), ("preprod-incm", INCM)]
ROOT_TYPES = ("VerifiableCredential", "VerifiableAttestation",
              "VerifiableAuthorisationForTrustChain")


def _recorded_node(directory: str, attribute: str) -> StubFetch:
    names = ("did_document", "issuer", "attributes", attribute)
    return StubFetch({_url(f"{directory}/{n}.json"): _rec(f"{directory}/{n}.json") for n in names})


@pytest.mark.parametrize("directory,base", NODES)
def test_golden_preprod_walk_on_each_node(directory, base):
    fetch = _recorded_node(directory, "attribute_0dc6a111")
    resolver = _core_resolver(fetch, base)
    doc = resolver.resolve(DID)
    record = resolver.issuer_record(DID)

    assert doc.id == DID
    assert len(doc.verification_methods) == 2
    assert sorted(vm.public_key_jwk["crv"] for vm in doc.verification_methods) == \
        ["P-256", "secp256k1"]
    assert [vm.type for vm in doc.verification_methods] == ["JsonWebKey2020"] * 2

    assert record.did == DID and record.has_attributes is True
    assert len(record.accreditations) == 1
    acc = record.accreditations[0]
    assert acc.attribute_id == ATTRIBUTE_ID
    assert acc.issuer_type == "RootTAO"
    assert acc.tao == DID and acc.root_tao == DID
    assert acc.credential_types == ROOT_TYPES
    assert acc.credential_jwt == _rec(f"{directory}/attribute_0dc6a111.json")["attribute"]["body"]
    assert acc.is_revoked is False

    # exactly the recorded requests, in walk order, all on this node's own origin
    assert fetch.calls == [_url(f"{directory}/did_document.json"), _url(f"{directory}/issuer.json"),
                           _url(f"{directory}/attributes.json"),
                           _url(f"{directory}/attribute_0dc6a111.json")]
    assert {urlsplit(u).hostname for u in fetch.calls} == {urlsplit(base).hostname}
    # the credentialSchema.id host inside the JWT is in no node list, and never requested
    assert "api-test.ebsi.eu" in json.dumps(PEEK(acc.credential_jwt))
    assert not any("api-test.ebsi.eu" in u or "api-prod.ebsi.eu" in u for u in fetch.calls)


def test_golden_the_two_preprod_nodes_agree_on_the_host_free_fields():
    results = []
    for directory, base in NODES:
        resolver = _core_resolver(_recorded_node(directory, "attribute_0dc6a111"), base)
        results.append((resolver.resolve(DID), resolver.issuer_record(DID)))
    (doc_a, record_a), (doc_b, record_b) = results
    assert doc_a == doc_b
    assert record_a == record_b


@pytest.mark.parametrize("name", ["did_document", "issuer", "attributes", "attribute_0dc6a111",
                                  "issuers_page"])
def test_golden_the_raw_bodies_are_equal_once_the_node_host_is_replaced(name):
    # the host is replaced in the comparison only, never in the files
    grnet = _read(f"preprod-grnet/{name}.json")
    incm = _read(f"preprod-incm/{name}.json")
    assert grnet.replace(b"api-preprod.ebsi.grnet.gr", b"api-preprod.ebsi.incm.pt") == incm
    if name in ("issuer", "attributes", "issuers_page"):
        assert grnet != incm                                    # the host really is in them
    else:
        assert grnet == incm                                    # and really is not in these


def test_golden_the_nodes_name_their_own_host_in_every_link():
    for directory, base in NODES:
        host = urlsplit(base).hostname
        issuer = _rec(f"{directory}/issuer.json")
        listing = _rec(f"{directory}/attributes.json")
        urls = [issuer["attributes"], listing["self"], *listing["links"].values(),
                *(item["href"] for item in listing["items"])]
        assert {urlsplit(u).hostname for u in urls} == {host}
        assert all(urlsplit(u).path.startswith("/v1/issuers-registry/issuers/") for u in urls)


def test_golden_attribute_id_is_the_list_items_id_and_not_the_attributes_hash():
    for directory, base in NODES:
        listing = _rec(f"{directory}/attributes.json")
        attribute = _rec(f"{directory}/attribute_0dc6a111.json")["attribute"]
        assert listing["items"][0]["id"] == ATTRIBUTE_ID
        assert attribute["hash"] != ATTRIBUTE_ID                # the recorded fact
        record = _core_resolver(_recorded_node(directory, "attribute_0dc6a111"),
                                base).issuer_record(DID)
        assert record.accreditations[0].attribute_id == ATTRIBUTE_ID
        assert record.accreditations[0].attribute_id != attribute["hash"]


def test_golden_the_legacy_adapter_keeps_the_list_id_too():
    # the repo's own v5 recording shows the same: `053e8d31...` (list id) against `bcdbbb24...`
    # (attribute.hash). Until now no test pinned it.
    issuer = json.loads((LEGACY_FIXTURES / "tir_v5_issuer.json").read_text())
    listing = json.loads((LEGACY_FIXTURES / "tir_v5_attributes.json").read_text())
    revisions = json.loads((LEGACY_FIXTURES / "tir_v5_revisions.json").read_text())
    base = "https://api-pilot.ebsi.eu"
    routes: dict[str, Any] = {TirV5().issuer_url(base, issuer["did"]): issuer,
                              issuer["attributes"]: listing}
    routes.update({item["href"]: revisions[item["id"]] for item in listing["items"]})
    resolver = DidEbsiResolver(StubFetch(routes), PEEK, base=base)
    record = resolver.issuer_record(issuer["did"])
    ids = [item["id"] for item in listing["items"]]
    assert [a.attribute_id for a in record.accreditations] == ids
    hashes = [revisions[i]["attribute"]["hash"] for i in ids]
    assert all(a.attribute_id != h for a, h in zip(record.accreditations, hashes))
    assert "053e8d314e60" in ids[1] and hashes[1].startswith("bcdbbb24")


def test_golden_parent_attribute_id_is_recorded_and_nothing_reads_it():
    # Decision 1 (Option 1): the field is kept in the fixtures as evidence only.
    for rel in ("preprod-grnet/attribute_0dc6a111.json", "preprod-incm/attribute_0dc6a111.json",
                "prod-iti/attribute_030c5a3d.json"):
        assert _rec(rel)["attribute"]["parentAttributeId"] == "0" * 64


def test_golden_prod_seed_shape():
    fetch = _recorded_node("prod-iti", "attribute_030c5a3d")
    resolver = _core_resolver(fetch, PROD)
    record = resolver.issuer_record(PROD_DID)
    assert record.did == PROD_DID and record.has_attributes is True
    assert len(record.accreditations) == 1
    acc = record.accreditations[0]
    assert acc.attribute_id == PROD_ATTRIBUTE_ID
    assert acc.attribute_id != _rec("prod-iti/attribute_030c5a3d.json")["attribute"]["hash"]
    assert acc.issuer_type == "RootTAO" and acc.tao == acc.root_tao == PROD_DID
    assert acc.credential_types == ROOT_TYPES
    # the seeded issuer's DID document has no verification method at all
    doc = resolver.resolve(PROD_DID)
    assert doc.id == PROD_DID
    assert doc.verification_methods == []
    _, kid = VcJwtProofSuite().peek_issuer(acc.credential_jwt)
    assert doc.key_by_kid(kid) is None
    assert doc.key_by_kid(None) is None
    assert fetch.calls == [_url("prod-iti/issuer.json"), _url("prod-iti/attributes.json"),
                           _url("prod-iti/attribute_030c5a3d.json"),
                           _url("prod-iti/did_document.json")]


def test_golden_both_recorded_content_negotiation_forms_parse_to_the_same_document():
    didr = DidRegistryCoreV1()
    ld = didr.parse_did_document(_rec("preprod-grnet/did_document.json"))
    plain = didr.parse_did_document(_rec("negotiation/preprod-grnet_did_document_did+json.json"))
    assert "@context" in _rec("preprod-grnet/did_document.json")
    assert "@context" not in _rec("negotiation/preprod-grnet_did_document_did+json.json")
    assert plain.id == ld.id == DID
    assert plain.verification_methods == ld.verification_methods
    assert plain.relationships == ld.relationships
    entries = _manifest()["files"]
    assert entries["preprod-grnet/did_document.json"]["content_type"].startswith(
        "application/did+ld+json")
    negotiated = entries["negotiation/preprod-grnet_did_document_did+json.json"]
    assert negotiated["content_type"].startswith("application/did+json")


def test_golden_a_read_with_the_address_builds_the_recorded_requests():
    didr = DidRegistryCoreV1(contract_address=DID_REGISTRY_ADDRESS)
    tir = TirCoreV1(contract_address=ISSUERS_REGISTRY_ADDRESS)
    bound = "contract-address/preprod-grnet_"
    assert didr.identifiers_url(GRNET, DID) == _url(bound + "did_document_with-address.json")
    assert tir.issuer_url(GRNET, DID) == _url(bound + "issuer_with-address.json")
    names = ("did_document_with-address", "issuer_with-address", "attributes_with-address",
             "attribute_0dc6a111_with-address")
    routes = {_url(f"{bound}{n}.json"): _rec(f"{bound}{n}.json") for n in names}
    fetch = StubFetch(routes)
    resolver = _core_resolver(fetch, GRNET, didr=didr, tir=tir)
    bare = _core_resolver(_recorded_node("preprod-grnet", "attribute_0dc6a111"), GRNET)
    assert resolver.resolve(DID) == bare.resolve(DID)
    assert resolver.issuer_record(DID) == bare.issuer_record(DID)
    assert fetch.calls == [_url(bound + "did_document_with-address.json"),
                           _url(bound + "issuer_with-address.json"),
                           _url(bound + "attributes_with-address.json"),
                           _url(bound + "attribute_0dc6a111_with-address.json")]


# --------------------------------------------------------------------------- #
# Fuzzing: a node's bytes never raise anything but the OpenvcError family
# --------------------------------------------------------------------------- #

_scalar = (st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False)
           | st.text(max_size=24))
_json = st.recursive(
    _scalar,
    lambda kids: (st.lists(kids, max_size=4)
                  | st.dictionaries(st.text(max_size=8), kids, max_size=4)),
    max_leaves=12)


def _keys(*names: str) -> Any:
    return st.dictionaries(st.sampled_from(names), _json, max_size=len(names))


_HREF = TirCoreV1().issuer_url(GRNET, DID) + "/attributes/" + "ab" * 32
_ATTRIBUTES = TirCoreV1().issuer_url(GRNET, DID) + "/attributes"
_issuer = st.one_of(_json, _keys("did", "hasAttributes", "attributes").map(
    lambda d: {**d, "did": DID, "hasAttributes": True, "attributes": _ATTRIBUTES}),
    _keys("hasAttributes", "attributes").map(lambda d: {**d, "did": DID}))
_item = st.fixed_dictionaries({"href": st.one_of(st.just(_HREF), _json), "id": _json})
_listing = st.one_of(_json, st.fixed_dictionaries({
    "items": st.lists(_item, max_size=4), "total": _json,
    "links": st.one_of(_json, st.fixed_dictionaries({"next": _json}))}))
_attribute = st.one_of(_json, st.fixed_dictionaries({
    "attribute": st.one_of(_json, _keys("body", "hash", "issuerType", "tao", "rootTao")),
    "did": _json}))


_ISSUER_URL = TirCoreV1().issuer_url(GRNET, DID)
_GOOD_ISSUER = {"did": DID, "hasAttributes": True, "attributes": _ATTRIBUTES}
_GOOD_LISTING = {"items": [{"id": "ab" * 32, "href": _HREF}], "total": 1}
_GOOD_ATTRIBUTE = {"did": DID, "attribute": {"body": "x", "hash": "h", "issuerType": "TI"}}


def _walk(issuer: Any, listing: Any, attribute: Any) -> None:
    routes = {_ISSUER_URL: issuer, _ATTRIBUTES: listing, _HREF: attribute}
    resolver = _core_resolver(StubFetch(routes), GRNET)
    try:
        record = resolver.issuer_record(DID)
    except OpenvcError:
        return                                                  # typed: fail-closed
    assert isinstance(record, IssuerRecord) and record.did == DID


_FUZZ = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@_FUZZ
@given(_issuer, _listing, _attribute)
def test_arbitrary_registry_json_is_a_result_or_an_openvc_error(issuer, listing, attribute):
    _walk(issuer, listing, attribute)


# The three below hold the earlier hops good so that every example reaches the hop it varies
# (a fully random issuer almost never names the requested DID, so the first test rarely gets
# as far as the attribute).
@_FUZZ
@given(_issuer)
def test_arbitrary_issuer_json_is_a_result_or_an_openvc_error(issuer):
    _walk(issuer, _GOOD_LISTING, _GOOD_ATTRIBUTE)


@_FUZZ
@given(_listing)
def test_arbitrary_attribute_list_json_is_a_result_or_an_openvc_error(listing):
    _walk(_GOOD_ISSUER, listing, _GOOD_ATTRIBUTE)


@_FUZZ
@given(_attribute)
def test_arbitrary_attribute_json_is_a_result_or_an_openvc_error(attribute):
    _walk(_GOOD_ISSUER, _GOOD_LISTING, attribute)


@settings(max_examples=200, deadline=None)
@given(_json)
def test_arbitrary_json_as_a_did_document_is_a_result_or_an_openvc_error(body):
    fetch = StubFetch({DidRegistryCoreV1().identifiers_url(GRNET, DID): body})
    try:
        doc = _core_resolver(fetch, GRNET).resolve(DID)
    except OpenvcError:
        return
    assert doc.id == DID
