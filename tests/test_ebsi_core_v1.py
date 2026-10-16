"""
tests/test_ebsi_core_v1.py — EBSI Core API v1 adapters and their recorded vectors (#321).

The recorded Core v1 responses live in ``tests/fixtures/ebsi/core-v1/`` (provenance in its
README, one ``MANIFEST.json`` entry per file). They are the drift alarm for
``DidRegistryCoreV1`` and ``TirCoreV1``; the legacy pilot (v5) vectors in
``tests/fixtures/ebsi/*.json`` stay untouched.

This file starts with the vectors themselves: nothing below can mean anything if a recorded
body was edited, re-encoded or swapped.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

httpx = pytest.importorskip("httpx")

from openvc_ebsi.http import EbsiHttpClient  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "ebsi" / "core-v1"
# Not recorded responses: the manifest itself and the README that explains it.
NOT_RECORDED = {"MANIFEST.json", "README.md"}
# What EbsiHttpClient sends (ADR-0001 D10), and what every recording that did not override it
# sent. A test below pins the client's string to this one.
CLIENT_ACCEPT = "application/json, application/did+ld+json, */*;q=0.1"


def _manifest() -> dict:
    return json.loads((FIXTURES / "MANIFEST.json").read_bytes())


def _read(rel: str) -> bytes:
    return (FIXTURES / rel).read_bytes()


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
